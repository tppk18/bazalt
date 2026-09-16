use std::{collections::{HashMap, HashSet}, time::Duration};

use anyhow::{Context, Result};
use reqwest::Client;
use serde::de::DeserializeOwned;
use uuid::Uuid;

use crate::model::{ContentIndexRecord, FlowSummary, HttpRecord, MatchRecord, MetadataEvent, TrafficFilter};


#[derive(Debug, Clone, serde::Serialize)]
pub struct ClickHouseTableStats {
    pub table: String,
    pub rows: u64,
    pub bytes_on_disk: u64,
    pub active_parts: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ClickHouseStats {
    pub database: String,
    pub total_rows: u64,
    pub total_bytes_on_disk: u64,
    pub active_parts: u64,
    pub tables: Vec<ClickHouseTableStats>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RetentionDeleteResult {
    pub cutoff: String,
    pub tables_mutated: u64,
}

#[derive(Clone)]
pub struct ClickHouseStore {
    client: Client,
    base: String,
    database: String,
}

impl ClickHouseStore {
    pub fn new(base: &str, database: &str) -> Self {
        Self { client: Client::new(), base: base.trim_end_matches('/').to_owned(), database: database.to_owned() }
    }

    pub async fn init_retry(&self) -> Result<()> {
        let mut last = None;
        for _ in 0..60 {
            match self.init().await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    last = Some(e);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
        Err(last.unwrap_or_else(|| anyhow::anyhow!("clickhouse init failed")))
    }

    async fn init(&self) -> Result<()> {
        self.exec(&format!("CREATE DATABASE IF NOT EXISTS {}", ident(&self.database))).await?;
        let db = ident(&self.database);
        self.exec(&format!(r#"
            CREATE TABLE IF NOT EXISTS {db}.flows (
                flow_id UUID,
                started_at DateTime64(9, 'UTC'),
                ended_at DateTime64(9, 'UTC'),
                src_ip String,
                dst_ip String,
                src_port UInt16,
                dst_port UInt16,
                protocol LowCardinality(String),
                service LowCardinality(Nullable(String)),
                packets_c2s UInt64,
                packets_s2c UInt64,
                bytes_c2s UInt64,
                bytes_s2c UInt64,
                truncated Bool
            ) ENGINE=ReplacingMergeTree ORDER BY (flow_id)
        "#)).await?;
        self.exec(&format!(r#"
            CREATE TABLE IF NOT EXISTS {db}.http_messages (
                id UUID,
                flow_id UUID,
                timestamp DateTime64(9, 'UTC'),
                request Bool,
                method Nullable(String),
                host Nullable(String),
                path Nullable(String),
                status Nullable(UInt16),
                user_agent Nullable(String),
                content_type Nullable(String),
                body_content_id Nullable(UUID)
            ) ENGINE=ReplacingMergeTree ORDER BY (flow_id, id)
        "#)).await?;
        self.exec(&format!(r#"
            CREATE TABLE IF NOT EXISTS {db}.content_index (
                content_id UUID,
                flow_id UUID,
                ts_ns UInt64,
                service LowCardinality(Nullable(String)),
                direction LowCardinality(String),
                view LowCardinality(String),
                stream_offset UInt64,
                payload_len UInt32,
                segment_path String,
                segment_offset UInt64,
                INDEX content_id_bf content_id TYPE bloom_filter(0.01) GRANULARITY 4
            ) ENGINE=ReplacingMergeTree
            ORDER BY (flow_id, ts_ns, stream_offset, content_id)
        "#)).await?;
        self.exec(&format!(r#"
            CREATE TABLE IF NOT EXISTS {db}.matches (
                timestamp DateTime64(9, 'UTC'),
                pattern_id UUID,
                pattern_revision Int64,
                flow_id UUID,
                content_id UUID,
                view LowCardinality(String),
                action LowCardinality(String),
                offset_start UInt64,
                offset_end UInt64,
                historical Bool
            ) ENGINE=ReplacingMergeTree ORDER BY (pattern_id, pattern_revision, content_id, offset_start)
        "#)).await?;
        Ok(())
    }

    pub async fn insert_events(&self, events: &[MetadataEvent]) -> Result<()> {
        let mut flows = String::new();
        let mut http = String::new();
        let mut matches = String::new();
        let mut content_index = String::new();
        for e in events {
            match e {
                MetadataEvent::Flow(v) => { flows.push_str(&serde_json::to_string(&FlowRow::from(v))?); flows.push('\n'); }
                MetadataEvent::Http(v) => { http.push_str(&serde_json::to_string(&HttpRow::from(v))?); http.push('\n'); }
                MetadataEvent::Match(v) => { matches.push_str(&serde_json::to_string(&MatchRow::from(v))?); matches.push('\n'); }
                MetadataEvent::ContentIndex(v) => { content_index.push_str(&serde_json::to_string(&ContentIndexRow::from(v))?); content_index.push('\n'); }
            }
        }
        if !flows.is_empty() { self.insert_json_each_row("flows", flows).await?; }
        if !http.is_empty() { self.insert_json_each_row("http_messages", http).await?; }
        if !matches.is_empty() { self.insert_json_each_row("matches", matches).await?; }
        if !content_index.is_empty() { self.insert_json_each_row("content_index", content_index).await?; }
        Ok(())
    }

    pub async fn query_flows(
        &self,
        filter: &TrafficFilter,
        favorites: &HashSet<Uuid>,
        active_ignores: &[(Uuid, i64)],
    ) -> Result<Vec<FlowSummary>> {
        let limit = filter.limit.unwrap_or(100).min(500);
        let offset = filter.offset.unwrap_or(0);
        let mut where_parts = Vec::<String>::new();
        if !active_ignores.is_empty() {
            let refs = active_ignores.iter()
                .map(|(id, rev)| format!("(toUUID({}), {})", quote(&id.to_string()), rev))
                .collect::<Vec<_>>()
                .join(",");
            where_parts.push(format!(
                "flow_id NOT IN (SELECT flow_id FROM {}.matches FINAL WHERE action = 'ignore' AND (pattern_id, pattern_revision) IN ({}))",
                ident(&self.database), refs
            ));
        }
        if let Some(v) = &filter.service { where_parts.push(format!("service = {}", quote(v))); }
        if let Some(v) = &filter.src_ip { where_parts.push(format!("src_ip = {}", quote(v))); }
        if let Some(v) = &filter.dst_ip { where_parts.push(format!("dst_ip = {}", quote(v))); }
        if let Some(v) = filter.port { where_parts.push(format!("(src_port = {v} OR dst_port = {v})")); }
        if let Some(v) = &filter.protocol { where_parts.push(format!("protocol = {}", quote(&v.to_ascii_lowercase()))); }
        if let Some(v) = filter.from { where_parts.push(format!("started_at >= parseDateTime64BestEffort({})", quote(&v.to_rfc3339()))); }
        if let Some(v) = filter.to { where_parts.push(format!("started_at <= parseDateTime64BestEffort({})", quote(&v.to_rfc3339()))); }
        if let Some(pattern) = filter.pattern_id {
            where_parts.push(format!("flow_id IN (SELECT flow_id FROM {}.matches FINAL WHERE pattern_id = toUUID({}))", ident(&self.database), quote(&pattern.to_string())));
        }
        if let Some(ua) = &filter.user_agent {
            where_parts.push(format!("flow_id IN (SELECT flow_id FROM {}.http_messages FINAL WHERE positionCaseInsensitiveUTF8(ifNull(user_agent,''), {}) > 0)", ident(&self.database), quote(ua)));
        }
        if let Some(ua) = &filter.user_agent_equals {
            where_parts.push(format!("flow_id IN (SELECT flow_id FROM {}.http_messages FINAL WHERE lowerUTF8(ifNull(user_agent,'')) = lowerUTF8({}))", ident(&self.database), quote(ua)));
        }
        if let Some(ua) = &filter.user_agent_not_contains {
            where_parts.push(format!("flow_id NOT IN (SELECT flow_id FROM {}.http_messages FINAL WHERE positionCaseInsensitiveUTF8(ifNull(user_agent,''), {}) > 0)", ident(&self.database), quote(ua)));
        }
        if let Some(re) = &filter.user_agent_regex {
            where_parts.push(format!("flow_id IN (SELECT flow_id FROM {}.http_messages FINAL WHERE match(ifNull(user_agent,''), {}))", ident(&self.database), quote(re)));
        }
        if let Some(fav) = filter.favorite {
            if favorites.is_empty() && fav {
                return Ok(Vec::new());
            }
            if !favorites.is_empty() {
                let ids = favorites.iter().map(|id| format!("toUUID({})", quote(&id.to_string()))).collect::<Vec<_>>().join(",");
                where_parts.push(if fav { format!("flow_id IN ({ids})") } else { format!("flow_id NOT IN ({ids})") });
            }
        }
        let where_sql = if where_parts.is_empty() { String::new() } else { format!("WHERE {}", where_parts.join(" AND ")) };
        let sql = format!(r#"
            SELECT flow_id, started_at, ended_at, src_ip, dst_ip, src_port, dst_port, protocol,
                   service, packets_c2s, packets_s2c, bytes_c2s, bytes_s2c, truncated
            FROM {}.flows FINAL
            {}
            ORDER BY started_at DESC
            LIMIT {} OFFSET {}
            FORMAT JSONEachRow
        "#, ident(&self.database), where_sql, limit, offset);
        let rows: Vec<FlowRow> = self.query_json_rows(&sql).await?;
        rows.into_iter().map(FlowSummary::try_from).collect()
    }

    pub async fn query_pattern_ids_for_flows(&self, ids: &[Uuid]) -> Result<HashMap<Uuid, Vec<Uuid>>> {
        if ids.is_empty() { return Ok(HashMap::new()); }
        let list = ids.iter().map(|id| format!("toUUID({})", quote(&id.to_string()))).collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT flow_id, groupUniqArray(pattern_id) AS pattern_ids FROM {}.matches FINAL WHERE action='find' AND flow_id IN ({}) GROUP BY flow_id FORMAT JSONEachRow",
            ident(&self.database), list
        );
        #[derive(serde::Deserialize)]
        struct Row { flow_id: Uuid, pattern_ids: Vec<Uuid> }
        let rows: Vec<Row> = self.query_json_rows(&sql).await?;
        Ok(rows.into_iter().map(|row| (row.flow_id, row.pattern_ids)).collect())
    }

    pub async fn query_user_agents_for_flows(&self, ids: &[Uuid]) -> Result<HashMap<Uuid, String>> {
        if ids.is_empty() { return Ok(HashMap::new()); }
        let list = ids.iter().map(|id| format!("toUUID({})", quote(&id.to_string()))).collect::<Vec<_>>().join(",");
        let sql = latest_user_agents_sql(&self.database, &list);
        #[derive(serde::Deserialize)]
        struct Row { flow_id: Uuid, latest_user_agent: String }
        let rows: Vec<Row> = self.query_json_rows(&sql).await?;
        Ok(rows.into_iter().map(|row| (row.flow_id, row.latest_user_agent)).collect())
    }

    pub async fn query_service_spm(&self) -> Result<HashMap<String, u64>> {
        let sql = format!(
            "SELECT ifNull(service,'') AS service, count() AS spm FROM {}.flows FINAL WHERE ended_at >= now64(9) - INTERVAL 1 MINUTE GROUP BY service FORMAT JSONEachRow",
            ident(&self.database)
        );
        #[derive(serde::Deserialize)]
        struct Row { service: String, spm: u64 }
        let rows: Vec<Row> = self.query_json_rows(&sql).await?;
        Ok(rows.into_iter().filter(|row| !row.service.is_empty()).map(|row| (row.service, row.spm)).collect())
    }

    pub async fn query_flow(&self, id: Uuid) -> Result<Option<FlowSummary>> {
        let sql = format!(r#"SELECT flow_id, started_at, ended_at, src_ip, dst_ip, src_port, dst_port, protocol, service,
            packets_c2s, packets_s2c, bytes_c2s, bytes_s2c, truncated FROM {}.flows FINAL
            WHERE flow_id=toUUID({}) ORDER BY ended_at DESC LIMIT 1 FORMAT JSONEachRow"#,
            ident(&self.database), quote(&id.to_string()));
        let mut rows: Vec<FlowRow> = self.query_json_rows(&sql).await?;
        match rows.pop() { Some(v) => Ok(Some(v.try_into()?)), None => Ok(None) }
    }

    pub async fn query_http_for_flow(&self, id: Uuid) -> Result<Vec<HttpRecord>> {
        let sql = format!("SELECT * FROM {}.http_messages FINAL WHERE flow_id=toUUID({}) ORDER BY timestamp FORMAT JSONEachRow", ident(&self.database), quote(&id.to_string()));
        let rows: Vec<HttpRow> = self.query_json_rows(&sql).await?;
        rows.into_iter().map(HttpRecord::try_from).collect()
    }

    pub async fn query_matches_for_flow(&self, id: Uuid) -> Result<Vec<MatchRecord>> {
        let sql = format!("SELECT * FROM {}.matches FINAL WHERE flow_id=toUUID({}) ORDER BY timestamp FORMAT JSONEachRow", ident(&self.database), quote(&id.to_string()));
        let rows: Vec<MatchRow> = self.query_json_rows(&sql).await?;
        rows.into_iter().map(MatchRecord::try_from).collect()
    }

    pub async fn query_content_index(&self, id: Uuid) -> Result<Option<ContentIndexRecord>> {
        let sql = format!(
            "SELECT content_id, flow_id, ts_ns, service, direction, view, stream_offset, payload_len, segment_path, segment_offset FROM {}.content_index FINAL WHERE content_id=toUUID({}) LIMIT 1 FORMAT JSONEachRow",
            ident(&self.database), quote(&id.to_string())
        );
        let mut rows: Vec<ContentIndexRow> = self.query_json_rows(&sql).await?;
        match rows.pop() {
            Some(v) => Ok(Some(v.try_into()?)),
            None => Ok(None),
        }
    }

    pub async fn query_content_for_flow(&self, id: Uuid, limit: u32) -> Result<Vec<ContentIndexRecord>> {
        let limit = limit.min(5000);
        let sql = format!(
            "SELECT content_id, flow_id, ts_ns, service, direction, view, stream_offset, payload_len, segment_path, segment_offset FROM {}.content_index FINAL WHERE flow_id=toUUID({}) ORDER BY ts_ns, stream_offset LIMIT {} FORMAT JSONEachRow",
            ident(&self.database), quote(&id.to_string()), limit
        );
        let rows: Vec<ContentIndexRow> = self.query_json_rows(&sql).await?;
        rows.into_iter().map(ContentIndexRecord::try_from).collect()
    }

    pub async fn storage_stats(&self) -> Result<ClickHouseStats> {
        #[derive(serde::Deserialize)]
        struct Row {
            table: String,
            rows: u64,
            bytes_on_disk: u64,
            active_parts: u64,
        }
        let sql = format!(
            "SELECT table, sum(rows) AS rows, sum(bytes_on_disk) AS bytes_on_disk, count() AS active_parts \
             FROM system.parts WHERE active AND database={} GROUP BY table ORDER BY bytes_on_disk DESC FORMAT JSONEachRow",
            quote(&self.database)
        );
        let rows: Vec<Row> = self.query_json_rows(&sql).await?;
        let tables = rows.into_iter().map(|row| ClickHouseTableStats {
            table: row.table,
            rows: row.rows,
            bytes_on_disk: row.bytes_on_disk,
            active_parts: row.active_parts,
        }).collect::<Vec<_>>();
        Ok(ClickHouseStats {
            database: self.database.clone(),
            total_rows: tables.iter().map(|v| v.rows).sum(),
            total_bytes_on_disk: tables.iter().map(|v| v.bytes_on_disk).sum(),
            active_parts: tables.iter().map(|v| v.active_parts).sum(),
            tables,
        })
    }

    /// Delete traffic metadata older than `cutoff`. `mutations_sync=2` waits for
    /// the mutation to finish on replicas before this method returns. Physical
    /// filesystem reclamation can still lag while ClickHouse removes obsolete
    /// parts, so callers should treat the returned storage size as eventually
    /// consistent.
    pub async fn delete_before(&self, cutoff: chrono::DateTime<chrono::Utc>) -> Result<RetentionDeleteResult> {
        let db = ident(&self.database);
        let cutoff_text = cutoff.to_rfc3339();
        let cutoff_ns = cutoff.timestamp_nanos_opt().context("retention cutoff is outside nanosecond timestamp range")?;
        if cutoff_ns < 0 { anyhow::bail!("retention cutoff predates UNIX epoch"); }
        let cutoff_ns = cutoff_ns as u64;
        let cutoff_sql = quote(&cutoff_text);
        let statements = [
            format!("ALTER TABLE {db}.matches DELETE WHERE timestamp < parseDateTime64BestEffort({cutoff_sql}) SETTINGS mutations_sync=2"),
            format!("ALTER TABLE {db}.http_messages DELETE WHERE timestamp < parseDateTime64BestEffort({cutoff_sql}) SETTINGS mutations_sync=2"),
            format!("ALTER TABLE {db}.content_index DELETE WHERE ts_ns < {cutoff_ns} SETTINGS mutations_sync=2"),
            format!("ALTER TABLE {db}.flows DELETE WHERE ended_at < parseDateTime64BestEffort({cutoff_sql}) SETTINGS mutations_sync=2"),
        ];
        for statement in &statements {
            self.exec(statement).await?;
        }
        Ok(RetentionDeleteResult { cutoff: cutoff_text, tables_mutated: statements.len() as u64 })
    }

    async fn insert_json_each_row(&self, table: &str, body: String) -> Result<()> {
        let query = format!("INSERT INTO {}.{} FORMAT JSONEachRow", ident(&self.database), ident(table));
        let resp = self.client.post(&self.base).query(&[("query", query)]).body(body).send().await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() { anyhow::bail!("clickhouse insert {table}: {status}: {text}"); }
        Ok(())
    }

    async fn exec(&self, sql: &str) -> Result<()> {
        let resp = self.client.post(&self.base).body(sql.to_owned()).send().await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() { anyhow::bail!("clickhouse: {status}: {text}"); }
        Ok(())
    }

    async fn query_json_rows<T: DeserializeOwned>(&self, sql: &str) -> Result<Vec<T>> {
        let resp = self.client.post(&self.base).body(sql.to_owned()).send().await?;
        let status = resp.status();
        let text = resp.text().await.context("clickhouse response")?;
        if !status.is_success() { anyhow::bail!("clickhouse query: {status}: {text}"); }
        text.lines().filter(|l| !l.trim().is_empty()).map(|l| serde_json::from_str(l).map_err(Into::into)).collect()
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ContentIndexRow {
    content_id: Uuid,
    flow_id: Uuid,
    ts_ns: u64,
    service: Option<String>,
    direction: String,
    view: String,
    stream_offset: u64,
    payload_len: u32,
    segment_path: String,
    segment_offset: u64,
}
impl From<&ContentIndexRecord> for ContentIndexRow {
    fn from(v: &ContentIndexRecord) -> Self {
        Self {
            content_id: v.content_id,
            flow_id: v.flow_id,
            ts_ns: v.ts_ns,
            service: v.service.clone(),
            direction: match v.direction { crate::model::Direction::AToB => "a_to_b".into(), crate::model::Direction::BToA => "b_to_a".into() },
            view: v.view.as_str().into(),
            stream_offset: v.stream_offset,
            payload_len: v.payload_len,
            segment_path: v.segment_path.clone(),
            segment_offset: v.segment_offset,
        }
    }
}
impl TryFrom<ContentIndexRow> for ContentIndexRecord {
    type Error = anyhow::Error;
    fn try_from(v: ContentIndexRow) -> Result<Self> {
        Ok(Self {
            content_id: v.content_id,
            flow_id: v.flow_id,
            ts_ns: v.ts_ns,
            service: v.service,
            direction: match v.direction.as_str() {
                "a_to_b" => crate::model::Direction::AToB,
                "b_to_a" => crate::model::Direction::BToA,
                _ => anyhow::bail!("bad direction {}", v.direction),
            },
            view: parse_view(&v.view)?,
            stream_offset: v.stream_offset,
            payload_len: v.payload_len,
            segment_path: v.segment_path,
            segment_offset: v.segment_offset,
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct FlowRow {
    flow_id: Uuid,
    started_at: String,
    ended_at: String,
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    protocol: String,
    service: Option<String>,
    packets_c2s: u64,
    packets_s2c: u64,
    bytes_c2s: u64,
    bytes_s2c: u64,
    truncated: bool,
}
impl From<&FlowSummary> for FlowRow { fn from(v:&FlowSummary)->Self{Self{flow_id:v.flow_id,started_at:format_ch_dt(v.started_at),ended_at:format_ch_dt(v.ended_at),src_ip:v.src_ip.clone(),dst_ip:v.dst_ip.clone(),src_port:v.src_port,dst_port:v.dst_port,protocol:format!("{:?}",v.protocol).to_ascii_lowercase(),service:v.service.clone(),packets_c2s:v.packets_c2s,packets_s2c:v.packets_s2c,bytes_c2s:v.bytes_c2s,bytes_s2c:v.bytes_s2c,truncated:v.truncated}}}
impl TryFrom<FlowRow> for FlowSummary { type Error=anyhow::Error; fn try_from(v:FlowRow)->Result<Self>{Ok(Self{flow_id:v.flow_id,started_at:parse_ch_dt(&v.started_at)?,ended_at:parse_ch_dt(&v.ended_at)?,src_ip:v.src_ip,dst_ip:v.dst_ip,src_port:v.src_port,dst_port:v.dst_port,protocol:match v.protocol.as_str(){"tcp"=>crate::model::TransportProtocol::Tcp,"udp"=>crate::model::TransportProtocol::Udp,_=>anyhow::bail!("bad protocol")},service:v.service,packets_c2s:v.packets_c2s,packets_s2c:v.packets_s2c,bytes_c2s:v.bytes_c2s,bytes_s2c:v.bytes_s2c,truncated:v.truncated})}}

#[derive(serde::Serialize, serde::Deserialize)]
struct HttpRow { id:Uuid, flow_id:Uuid, timestamp:String, request:bool, method:Option<String>, host:Option<String>, path:Option<String>, status:Option<u16>, user_agent:Option<String>, content_type:Option<String>, body_content_id:Option<Uuid> }
impl From<&HttpRecord> for HttpRow { fn from(v:&HttpRecord)->Self{Self{id:v.id,flow_id:v.flow_id,timestamp:format_ch_dt(v.timestamp),request:v.request,method:v.method.clone(),host:v.host.clone(),path:v.path.clone(),status:v.status,user_agent:v.user_agent.clone(),content_type:v.content_type.clone(),body_content_id:v.body_content_id}}}
impl TryFrom<HttpRow> for HttpRecord { type Error=anyhow::Error; fn try_from(v:HttpRow)->Result<Self>{Ok(Self{id:v.id,flow_id:v.flow_id,timestamp:parse_ch_dt(&v.timestamp)?,request:v.request,method:v.method,host:v.host,path:v.path,status:v.status,user_agent:v.user_agent,content_type:v.content_type,body_content_id:v.body_content_id})}}

#[derive(serde::Serialize, serde::Deserialize)]
struct MatchRow { timestamp:String, pattern_id:Uuid, pattern_revision:i64, flow_id:Uuid, content_id:Uuid, view:String, action:String, offset_start:u64, offset_end:u64, historical:bool }
impl From<&MatchRecord> for MatchRow { fn from(v:&MatchRecord)->Self{Self{timestamp:format_ch_dt(v.timestamp),pattern_id:v.pattern_id,pattern_revision:v.pattern_revision,flow_id:v.flow_id,content_id:v.content_id,view:v.view.as_str().into(),action:match v.action{crate::model::PatternAction::Find=>"find".into(),crate::model::PatternAction::Ignore=>"ignore".into()},offset_start:v.offset_start,offset_end:v.offset_end,historical:v.historical}}}
impl TryFrom<MatchRow> for MatchRecord { type Error=anyhow::Error; fn try_from(v:MatchRow)->Result<Self>{Ok(Self{timestamp:parse_ch_dt(&v.timestamp)?,pattern_id:v.pattern_id,pattern_revision:v.pattern_revision,flow_id:v.flow_id,content_id:v.content_id,view:parse_view(&v.view)?,action:match v.action.as_str(){"find"=>crate::model::PatternAction::Find,"ignore"=>crate::model::PatternAction::Ignore,_=>anyhow::bail!("bad action")},offset_start:v.offset_start,offset_end:v.offset_end,historical:v.historical})}}

fn latest_user_agents_sql(database: &str, list: &str) -> String {
    // Keep the aggregate alias distinct from the source column name. ClickHouse
    // resolves SELECT aliases in WHERE, so `AS user_agent` made the WHERE
    // expression expand to argMax(...), yielding ILLEGAL_AGGREGATION (Code 184).
    format!(
        "SELECT flow_id, argMaxIf(ifNull(user_agent,''), timestamp, notEmpty(ifNull(user_agent,''))) AS latest_user_agent \
         FROM {}.http_messages FINAL \
         WHERE flow_id IN ({}) \
         GROUP BY flow_id \
         HAVING notEmpty(latest_user_agent) \
         FORMAT JSONEachRow",
        ident(database), list
    )
}

#[cfg(test)]
mod clickhouse_query_tests {
    use super::latest_user_agents_sql;

    #[test]
    fn latest_user_agent_query_does_not_shadow_source_column_with_aggregate_alias() {
        let sql = latest_user_agents_sql("packmate", "toUUID('00000000-0000-0000-0000-000000000001')");
        assert!(sql.contains("AS latest_user_agent"));
        assert!(sql.contains("argMaxIf(ifNull(user_agent,''), timestamp"));
        assert!(sql.contains("HAVING notEmpty(latest_user_agent)"));
        assert!(!sql.contains("AS user_agent"));
    }
}


fn format_ch_dt(v: chrono::DateTime<chrono::Utc>) -> String {
    v.format("%Y-%m-%d %H:%M:%S%.9f").to_string()
}

fn parse_ch_dt(v: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(v) {
        return Ok(dt.with_timezone(&chrono::Utc));
    }
    let naive = chrono::NaiveDateTime::parse_from_str(v, "%Y-%m-%d %H:%M:%S%.f")?;
    Ok(chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(naive, chrono::Utc))
}

fn ident(v:&str)->String{v.chars().filter(|c|c.is_ascii_alphanumeric()||*c=='_').collect()}
fn quote(v:&str)->String{format!("'{}'",v.replace('\\',"\\\\").replace('\'',"\\'"))}
fn parse_view(v:&str)->Result<crate::model::ContentView>{use crate::model::ContentView::*;match v{"tcp_raw"=>Ok(TcpRaw),"http_request_headers"=>Ok(HttpRequestHeaders),"http_request_body"=>Ok(HttpRequestBody),"http_request_decoded_body"=>Ok(HttpRequestDecodedBody),"http_response_headers"=>Ok(HttpResponseHeaders),"http_response_body"=>Ok(HttpResponseBody),"http_response_decoded_body"=>Ok(HttpResponseDecodedBody),_=>anyhow::bail!("bad view {v}")}}
