use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use uuid::Uuid;

use crate::model::{
    ContentView, NewPattern, PatternAction, PatternDirection, PatternKind, PatternRef,
    PatternRevision, ReplayJob, ServiceConfig,
};

#[derive(Clone)]
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    pub async fn connect_retry(url: &str) -> Result<Self> {
        let mut last = None;
        for _ in 0..60 {
            match PgPoolOptions::new().max_connections(8).connect(url).await {
                Ok(pool) => return Ok(Self { pool }),
                Err(e) => {
                    last = Some(e);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
        Err(last
            .map(anyhow::Error::from)
            .unwrap_or_else(|| anyhow::anyhow!("postgres connection failed")))
    }

    pub async fn migrate(&self) -> Result<()> {
        const STATEMENTS: &[&str] = &[
            r#"CREATE TABLE IF NOT EXISTS patterns (
                id UUID NOT NULL,
                revision BIGINT NOT NULL,
                name TEXT NOT NULL,
                expression TEXT NOT NULL,
                kind TEXT NOT NULL,
                action TEXT NOT NULL,
                color TEXT NOT NULL DEFAULT '#FF7474',
                direction_type TEXT NOT NULL DEFAULT 'both',
                service TEXT NULL,
                view TEXT NULL,
                enabled BOOLEAN NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                PRIMARY KEY (id, revision)
            )"#,
            r#"ALTER TABLE patterns ADD COLUMN IF NOT EXISTS color TEXT NOT NULL DEFAULT '#FF7474'"#,
            r#"ALTER TABLE patterns ADD COLUMN IF NOT EXISTS direction_type TEXT NOT NULL DEFAULT 'both'"#,
            r#"CREATE INDEX IF NOT EXISTS patterns_enabled_idx ON patterns(enabled)"#,
            r#"CREATE TABLE IF NOT EXISTS replay_jobs (
                id UUID PRIMARY KEY,
                pattern_ids JSONB NOT NULL,
                pattern_revisions JSONB NOT NULL DEFAULT '[]'::jsonb,
                segment_cutoff TEXT NULL,
                segment_paths JSONB NOT NULL DEFAULT '[]'::jsonb,
                status TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL,
                segments_total BIGINT NOT NULL DEFAULT 0,
                segments_done BIGINT NOT NULL DEFAULT 0,
                bytes_processed BIGINT NOT NULL DEFAULT 0,
                matches_found BIGINT NOT NULL DEFAULT 0,
                error TEXT NULL
            )"#,
            r#"ALTER TABLE replay_jobs ADD COLUMN IF NOT EXISTS pattern_revisions JSONB NOT NULL DEFAULT '[]'::jsonb"#,
            r#"ALTER TABLE replay_jobs ADD COLUMN IF NOT EXISTS segment_cutoff TEXT NULL"#,
            r#"ALTER TABLE replay_jobs ADD COLUMN IF NOT EXISTS segment_paths JSONB NOT NULL DEFAULT '[]'::jsonb"#,
            r#"CREATE INDEX IF NOT EXISTS replay_jobs_status_idx ON replay_jobs(status, updated_at)"#,
            r#"CREATE TABLE IF NOT EXISTS favorites (
                flow_id UUID PRIMARY KEY,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )"#,
            r#"CREATE TABLE IF NOT EXISTS services (
                port INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                http BOOLEAN NOT NULL DEFAULT TRUE,
                urldecode_http_requests BOOLEAN NOT NULL DEFAULT FALSE,
                merge_adjacent_packets BOOLEAN NOT NULL DEFAULT FALSE,
                parse_websockets BOOLEAN NOT NULL DEFAULT FALSE
            )"#,
            r#"ALTER TABLE services ADD COLUMN IF NOT EXISTS http BOOLEAN NOT NULL DEFAULT TRUE"#,
            r#"ALTER TABLE services ADD COLUMN IF NOT EXISTS urldecode_http_requests BOOLEAN NOT NULL DEFAULT FALSE"#,
            r#"ALTER TABLE services ADD COLUMN IF NOT EXISTS merge_adjacent_packets BOOLEAN NOT NULL DEFAULT FALSE"#,
            r#"ALTER TABLE services ADD COLUMN IF NOT EXISTS parse_websockets BOOLEAN NOT NULL DEFAULT FALSE"#,
        ];
        for statement in STATEMENTS {
            sqlx::query(statement)
                .execute(&self.pool)
                .await
                .context("postgres migration")?;
        }
        Ok(())
    }

    pub async fn list_patterns(&self) -> Result<Vec<PatternRevision>> {
        let rows = sqlx::query(
            r#"
            SELECT DISTINCT ON (id)
              id, revision, name, expression, kind, action, color, direction_type, service, view, enabled, created_at
            FROM patterns
            ORDER BY id, revision DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_pattern).collect()
    }

    pub async fn list_enabled_patterns(&self) -> Result<Vec<PatternRevision>> {
        // Filter *after* selecting the latest revision. Filtering enabled rows
        // before DISTINCT ON would resurrect an older enabled revision when the
        // newest revision disables the pattern.
        let rows = sqlx::query(
            r#"
            SELECT id, revision, name, expression, kind, action, color, direction_type, service, view, enabled, created_at
            FROM (
              SELECT DISTINCT ON (id)
                id, revision, name, expression, kind, action, color, direction_type, service, view, enabled, created_at
              FROM patterns
              ORDER BY id, revision DESC
            ) latest
            WHERE enabled = TRUE
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_pattern).collect()
    }

    pub async fn create_pattern(&self, p: NewPattern) -> Result<PatternRevision> {
        let out = PatternRevision {
            id: Uuid::new_v4(),
            revision: 1,
            name: p.name,
            expression: p.expression,
            kind: p.kind,
            action: p.action,
            color: p.color,
            direction_type: p.direction_type,
            service: p.service,
            view: p.view,
            enabled: true,
            created_at: Utc::now(),
        };
        self.insert_pattern_revision(&out).await?;
        Ok(out)
    }

    pub async fn update_pattern(
        &self,
        id: Uuid,
        p: NewPattern,
        enabled: bool,
    ) -> Result<PatternRevision> {
        let revision: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(revision), 0) + 1 FROM patterns WHERE id = $1")
                .bind(id)
                .fetch_one(&self.pool)
                .await?;
        let out = PatternRevision {
            id,
            revision,
            name: p.name,
            expression: p.expression,
            kind: p.kind,
            action: p.action,
            color: p.color,
            direction_type: p.direction_type,
            service: p.service,
            view: p.view,
            enabled,
            created_at: Utc::now(),
        };
        self.insert_pattern_revision(&out).await?;
        Ok(out)
    }

    async fn insert_pattern_revision(&self, p: &PatternRevision) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO patterns
            (id, revision, name, expression, kind, action, color, direction_type, service, view, enabled, created_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)"#,
        )
        .bind(p.id)
        .bind(p.revision)
        .bind(&p.name)
        .bind(&p.expression)
        .bind(kind_str(p.kind))
        .bind(action_str(p.action))
        .bind(&p.color)
        .bind(direction_str(p.direction_type))
        .bind(&p.service)
        .bind(p.view.map(|v| v.as_str().to_owned()))
        .bind(p.enabled)
        .bind(p.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_pattern(&self, id: Uuid) -> Result<bool> {
        // Pattern revisions are referenced by durable replay jobs.  A physical
        // delete made an interrupted job unrecoverable and also erased audit
        // history.  Tombstone the latest revision instead; list_enabled_patterns
        // already selects the latest revision before filtering `enabled`.
        let Some(current) = self.latest_pattern(id).await? else {
            return Ok(false);
        };
        if !current.enabled {
            return Ok(false);
        }
        let tombstone = PatternRevision {
            revision: current.revision + 1,
            enabled: false,
            created_at: Utc::now(),
            ..current
        };
        self.insert_pattern_revision(&tombstone).await?;
        Ok(true)
    }

    pub async fn set_pattern_enabled(&self, id: Uuid, enabled: bool) -> Result<PatternRevision> {
        let current = self
            .latest_pattern(id)
            .await?
            .context("pattern not found")?;
        let next = PatternRevision {
            revision: current.revision + 1,
            enabled,
            created_at: Utc::now(),
            ..current
        };
        self.insert_pattern_revision(&next).await?;
        Ok(next)
    }

    pub async fn latest_pattern(&self, id: Uuid) -> Result<Option<PatternRevision>> {
        let row = sqlx::query(
            r#"SELECT id, revision, name, expression, kind, action, color, direction_type, service, view, enabled, created_at
               FROM patterns WHERE id=$1 ORDER BY revision DESC LIMIT 1"#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_pattern).transpose()
    }

    pub async fn pattern_revision(
        &self,
        id: Uuid,
        revision: i64,
    ) -> Result<Option<PatternRevision>> {
        let row = sqlx::query(
            r#"SELECT id, revision, name, expression, kind, action, color, direction_type, service, view, enabled, created_at
               FROM patterns WHERE id=$1 AND revision=$2 LIMIT 1"#,
        )
        .bind(id)
        .bind(revision)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_pattern).transpose()
    }

    pub async fn create_replay_job(
        &self,
        patterns: &[PatternRevision],
        segment_paths: &[std::path::PathBuf],
    ) -> Result<ReplayJob> {
        let now = Utc::now();
        let pattern_ids = patterns.iter().map(|p| p.id).collect::<Vec<_>>();
        let pattern_revisions = patterns
            .iter()
            .map(|p| PatternRef {
                id: p.id,
                revision: p.revision,
            })
            .collect::<Vec<_>>();
        let segment_cutoff = segment_paths
            .last()
            .map(|p| p.to_string_lossy().into_owned());
        let frozen_paths = segment_paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let job = ReplayJob {
            id: Uuid::new_v4(),
            pattern_ids,
            pattern_revisions,
            segment_cutoff,
            segment_paths: frozen_paths,
            status: "queued".into(),
            created_at: now,
            updated_at: now,
            segments_total: segment_paths.len() as i64,
            segments_done: 0,
            bytes_processed: 0,
            matches_found: 0,
            error: None,
        };
        let pattern_json = serde_json::to_value(&job.pattern_ids)?;
        let revisions_json = serde_json::to_value(&job.pattern_revisions)?;
        let segment_paths_json = serde_json::to_value(&job.segment_paths)?;
        sqlx::query(
            r#"INSERT INTO replay_jobs
               (id, pattern_ids, pattern_revisions, segment_cutoff, segment_paths, status, created_at, updated_at, segments_total, segments_done, bytes_processed, matches_found, error)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)"#,
        )
        .bind(job.id)
        .bind(pattern_json)
        .bind(revisions_json)
        .bind(&job.segment_cutoff)
        .bind(segment_paths_json)
        .bind(&job.status)
        .bind(job.created_at)
        .bind(job.updated_at)
        .bind(job.segments_total)
        .bind(job.segments_done)
        .bind(job.bytes_processed)
        .bind(job.matches_found)
        .bind(&job.error)
        .execute(&self.pool)
        .await?;
        Ok(job)
    }

    pub async fn update_replay_progress(
        &self,
        id: Uuid,
        status: &str,
        segments_done: i64,
        bytes_processed: i64,
        matches_found: i64,
        error: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            r#"UPDATE replay_jobs SET status=$2, updated_at=now(), segments_done=$3,
               bytes_processed=$4, matches_found=$5, error=$6 WHERE id=$1"#,
        )
        .bind(id)
        .bind(status)
        .bind(segments_done)
        .bind(bytes_processed)
        .bind(matches_found)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_replay_jobs(&self, limit: i64) -> Result<Vec<ReplayJob>> {
        let rows = sqlx::query(
            r#"SELECT id, pattern_ids, pattern_revisions, segment_cutoff, segment_paths, status, created_at, updated_at, segments_total,
               segments_done, bytes_processed, matches_found, error
               FROM replay_jobs ORDER BY created_at DESC LIMIT $1"#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::new();
        for row in rows {
            let json: serde_json::Value = row.try_get("pattern_ids")?;
            let pattern_ids: Vec<Uuid> = serde_json::from_value(json)?;
            let refs_json: serde_json::Value = row.try_get("pattern_revisions")?;
            let pattern_revisions: Vec<PatternRef> =
                serde_json::from_value(refs_json).unwrap_or_default();
            let paths_json: serde_json::Value = row.try_get("segment_paths")?;
            let segment_paths: Vec<String> = serde_json::from_value(paths_json).unwrap_or_default();
            out.push(ReplayJob {
                id: row.try_get("id")?,
                pattern_ids,
                pattern_revisions,
                segment_cutoff: row.try_get("segment_cutoff")?,
                segment_paths,
                status: row.try_get("status")?,
                created_at: row.try_get("created_at")?,
                updated_at: row.try_get("updated_at")?,
                segments_total: row.try_get("segments_total")?,
                segments_done: row.try_get("segments_done")?,
                bytes_processed: row.try_get("bytes_processed")?,
                matches_found: row.try_get("matches_found")?,
                error: row.try_get("error")?,
            });
        }
        Ok(out)
    }

    pub async fn set_favorite(&self, flow_id: Uuid, favorite: bool) -> Result<()> {
        if favorite {
            sqlx::query("INSERT INTO favorites(flow_id) VALUES($1) ON CONFLICT DO NOTHING")
                .bind(flow_id)
                .execute(&self.pool)
                .await?;
        } else {
            sqlx::query("DELETE FROM favorites WHERE flow_id=$1")
                .bind(flow_id)
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    pub async fn list_favorites(&self) -> Result<Vec<Uuid>> {
        Ok(sqlx::query_scalar("SELECT flow_id FROM favorites")
            .fetch_all(&self.pool)
            .await?)
    }

    pub async fn upsert_service(&self, service: &ServiceConfig) -> Result<ServiceConfig> {
        let row = sqlx::query(
            r#"
            INSERT INTO services(
                port, name, enabled, http, urldecode_http_requests, merge_adjacent_packets, parse_websockets
            ) VALUES($1,$2,TRUE,$3,$4,$5,$6)
            ON CONFLICT(port) DO UPDATE SET
                name=EXCLUDED.name,
                enabled=TRUE,
                http=EXCLUDED.http,
                urldecode_http_requests=EXCLUDED.urldecode_http_requests,
                merge_adjacent_packets=EXCLUDED.merge_adjacent_packets,
                parse_websockets=EXCLUDED.parse_websockets
            RETURNING port,name,http,urldecode_http_requests,merge_adjacent_packets,parse_websockets
            "#
        )
        .bind(service.port as i32)
        .bind(service.name.trim())
        .bind(service.http)
        .bind(service.urldecode_http_requests)
        .bind(service.merge_adjacent_packets)
        .bind(service.parse_websockets)
        .fetch_one(&self.pool)
        .await?;
        row_to_service(row)
    }

    pub async fn delete_service(&self, port: u16) -> Result<bool> {
        let result = sqlx::query("DELETE FROM services WHERE port=$1")
            .bind(port as i32)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn database_size_bytes(&self) -> Result<u64> {
        let value: i64 = sqlx::query_scalar("SELECT pg_database_size(current_database())::bigint")
            .fetch_one(&self.pool)
            .await?;
        Ok(value.max(0) as u64)
    }

    pub async fn list_services(&self) -> Result<Vec<ServiceConfig>> {
        let rows = sqlx::query(
            "SELECT port,name,http,urldecode_http_requests,merge_adjacent_packets,parse_websockets FROM services WHERE enabled=TRUE ORDER BY port"
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_service).collect()
    }
}

fn row_to_service(row: sqlx::postgres::PgRow) -> Result<ServiceConfig> {
    let port = row.try_get::<i32, _>("port")?;
    if !(1..=65535).contains(&port) {
        anyhow::bail!("invalid service port stored in postgres: {port}");
    }
    Ok(ServiceConfig {
        port: port as u16,
        name: row.try_get("name")?,
        http: row.try_get("http")?,
        urldecode_http_requests: row.try_get("urldecode_http_requests")?,
        merge_adjacent_packets: row.try_get("merge_adjacent_packets")?,
        parse_websockets: row.try_get("parse_websockets")?,
    })
}

fn row_to_pattern(row: sqlx::postgres::PgRow) -> Result<PatternRevision> {
    Ok(PatternRevision {
        id: row.try_get("id")?,
        revision: row.try_get("revision")?,
        name: row.try_get("name")?,
        expression: row.try_get("expression")?,
        kind: parse_kind(&row.try_get::<String, _>("kind")?)?,
        action: parse_action(&row.try_get::<String, _>("action")?)?,
        color: row.try_get("color")?,
        direction_type: parse_direction(&row.try_get::<String, _>("direction_type")?)?,
        service: row.try_get("service")?,
        view: row
            .try_get::<Option<String>, _>("view")?
            .map(|s| parse_view(&s))
            .transpose()?,
        enabled: row.try_get("enabled")?,
        created_at: row.try_get("created_at")?,
    })
}

fn kind_str(v: PatternKind) -> &'static str {
    match v {
        PatternKind::Text => "text",
        PatternKind::Binary => "binary",
        PatternKind::Regex => "regex",
    }
}
fn action_str(v: PatternAction) -> &'static str {
    match v {
        PatternAction::Find => "find",
        PatternAction::Ignore => "ignore",
    }
}
fn direction_str(v: PatternDirection) -> &'static str {
    match v {
        PatternDirection::Both => "both",
        PatternDirection::Input => "input",
        PatternDirection::Output => "output",
    }
}
fn parse_kind(v: &str) -> Result<PatternKind> {
    match v {
        "text" => Ok(PatternKind::Text),
        "binary" => Ok(PatternKind::Binary),
        "regex" => Ok(PatternKind::Regex),
        _ => anyhow::bail!("unknown pattern kind {v}"),
    }
}
fn parse_action(v: &str) -> Result<PatternAction> {
    match v {
        "find" => Ok(PatternAction::Find),
        "ignore" => Ok(PatternAction::Ignore),
        _ => anyhow::bail!("unknown pattern action {v}"),
    }
}
fn parse_direction(v: &str) -> Result<PatternDirection> {
    match v {
        "both" => Ok(PatternDirection::Both),
        "input" => Ok(PatternDirection::Input),
        "output" => Ok(PatternDirection::Output),
        _ => anyhow::bail!("unknown pattern direction {v}"),
    }
}
fn parse_view(v: &str) -> Result<ContentView> {
    match v {
        "tcp_raw" => Ok(ContentView::TcpRaw),
        "http_request_headers" => Ok(ContentView::HttpRequestHeaders),
        "http_request_body" => Ok(ContentView::HttpRequestBody),
        "http_request_decoded_body" => Ok(ContentView::HttpRequestDecodedBody),
        "http_response_headers" => Ok(ContentView::HttpResponseHeaders),
        "http_response_body" => Ok(ContentView::HttpResponseBody),
        "http_response_decoded_body" => Ok(ContentView::HttpResponseDecodedBody),
        _ => anyhow::bail!("unknown content view {v}"),
    }
}
