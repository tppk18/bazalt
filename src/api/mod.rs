use std::{collections::{HashMap, HashSet}, net::SocketAddr, sync::Arc};
use parking_lot::Mutex;

use axum::{
    extract::{ConnectInfo, Path, Query, Request, State, WebSocketUpgrade, ws::{Message, WebSocket}},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get, patch, post, put},
    Json, Router,
};
use base64::Engine;
use futures::StreamExt;
use serde::Deserialize;
use tokio::sync::{broadcast, watch};
use tower_http::{services::ServeDir, trace::TraceLayer};
use uuid::Uuid;

use crate::{
    auth::{AuthManager, LoginError},
    http::ServiceRegistry,
    matching::PatternManager,
    metrics::Metrics,
    model::{LiveEvent, NewPattern, PatternRevision, ServiceConfig, TrafficFilter},
    replay::ReplayHandle,
    storage::{clickhouse::ClickHouseStore, postgres::PostgresStore, segment::SegmentStore, MetadataSink},
};

#[derive(Clone)]
pub struct ApiState {
    pub metrics: Arc<Metrics>,
    pub auth: AuthManager,
    pub metadata: MetadataSink,
    pub maintenance: Arc<tokio::sync::RwLock<()>>,
    pub postgres: PostgresStore,
    pub clickhouse: ClickHouseStore,
    pub segments: Arc<SegmentStore>,
    pub patterns: PatternManager,
    pub replay: ReplayHandle,
    pub services: Arc<ServiceRegistry>,
    pub live_events: broadcast::Sender<LiveEvent>,
    pub missing_segments_warned: Arc<Mutex<HashSet<String>>>,
}

pub async fn serve(
    addr: std::net::SocketAddr,
    state: ApiState,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let protected = Router::new()
        .route("/api/status", get(status))
        .route("/api/resources", get(resource_status))
        .route("/metrics", get(prometheus_metrics))
        .route("/api/flows", get(flows))
        .route("/api/flows/{id}", get(flow_detail))
        .route("/api/flows/{id}/content", get(flow_content))
        .route("/api/flows/{id}/favorite", post(set_favorite))
        .route("/api/content/{id}", get(content))
        .route("/api/patterns", get(list_patterns).post(create_pattern))
        .route("/api/patterns/{id}", put(update_pattern).delete(delete_pattern))
        .route("/api/patterns/{id}/enabled", patch(set_pattern_enabled))
        .route("/api/patterns/{id}/lookback", post(lookback_pattern))
        .route("/api/replay/jobs", get(replay_jobs))
        .route("/api/services", get(list_services).post(create_service))
        .route("/api/services/{port}", put(update_service).delete(delete_service))
        .route("/api/management/storage", get(management_storage))
        .route("/api/management/cleanup", post(management_cleanup))
        .route("/api/live", get(live_ws))
        .route("/api", any(api_not_found))
        .route("/api/{*rest}", any(api_not_found))
        .route("/auth/logout", post(logout));

    // Static UI assets and the login endpoint remain public. Access control is
    // applied at the outer router so *every* /api request (including unknown
    // paths and wrong methods), /metrics and /auth/logout is rejected with 403
    // before any endpoint handler/extractor runs when credentials are missing.
    let app = Router::new()
        .route("/auth/login", post(login))
        .merge(protected)
        .fallback_service(ServeDir::new("frontend").append_index_html_on_directories(true))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn_with_state(state.clone(), access_control))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "HTTP/UI server listening");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async move {
            if *shutdown.borrow() { return; }
            while shutdown.changed().await.is_ok() {
                if *shutdown.borrow() { break; }
            }
        })
        .await?;
    Ok(())
}


#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

async fn login(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(s): State<ApiState>,
    Json(req): Json<LoginRequest>,
) -> Response {
    match s.auth.login(peer.ip(), &req.username, &req.password) {
        Ok(token) => {
            let mut response = Json(serde_json::json!({"ok": true, "auth_enabled": s.auth.enabled()})).into_response();
            if s.auth.enabled() {
                if let Ok(value) = HeaderValue::from_str(&s.auth.set_cookie_header(&token)) {
                    response.headers_mut().insert(header::SET_COOKIE, value);
                }
            }
            response
        }
        Err(LoginError::Forbidden) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "invalid credentials"})),
        ).into_response(),
        Err(LoginError::RateLimited) => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "too many failed login attempts; retry later"})),
        ).into_response(),
    }
}

async fn logout(State(s): State<ApiState>, request: Request) -> Response {
    s.auth.logout(request.headers());
    let mut response = Json(serde_json::json!({"ok": true})).into_response();
    if let Ok(value) = HeaderValue::from_str(&s.auth.clear_cookie_header()) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

async fn access_control(State(s): State<ApiState>, request: Request, next: Next) -> Response {
    let path = request.uri().path();
    let protected = path == "/metrics" || path == "/auth/logout" || path == "/api" || path.starts_with("/api/");
    if !protected || s.auth.is_authorized(request.headers()) {
        return next.run(request).await;
    }
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({"error": "forbidden"})),
    ).into_response()
}

#[derive(Deserialize)]
struct CleanupRequest {
    older_than_seconds: u64,
    confirm: String,
}

async fn management_storage(State(s): State<ApiState>) -> ApiResult<Json<serde_json::Value>> {
    let segments = s.segments.clone();
    let segment_stats = tokio::task::spawn_blocking(move || segments.disk_stats()).await.map_err(anyhow::Error::from)??;
    let (clickhouse, postgres_bytes) = tokio::try_join!(
        s.clickhouse.storage_stats(),
        s.postgres.database_size_bytes(),
    )?;
    let total = clickhouse.total_bytes_on_disk
        .saturating_add(postgres_bytes)
        .saturating_add(segment_stats.bytes);
    Ok(Json(serde_json::json!({
        "auth_enabled": s.auth.enabled(),
        "total_managed_bytes": total,
        "clickhouse": clickhouse,
        "postgres_bytes": postgres_bytes,
        "segments": segment_stats,
    })))
}

async fn management_cleanup(
    State(s): State<ApiState>,
    Json(req): Json<CleanupRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    if req.confirm != "DELETE" {
        return Err(ApiError::bad_request("explicit cleanup confirmation DELETE is required"));
    }
    if req.older_than_seconds == 0 {
        return Err(ApiError::bad_request("older_than_seconds must be greater than zero"));
    }
    let seconds = i64::try_from(req.older_than_seconds)
        .map_err(|_| ApiError::bad_request("retention duration is too large"))?;
    let cutoff = chrono::Utc::now()
        .checked_sub_signed(chrono::Duration::seconds(seconds))
        .ok_or_else(|| ApiError::bad_request("retention cutoff is outside supported range"))?;
    let cutoff_ns = cutoff.timestamp_nanos_opt()
        .filter(|v| *v >= 0)
        .ok_or_else(|| ApiError::bad_request("retention cutoff predates UNIX epoch"))? as u64;

    // Exclude historical replay for the whole seal/mutation/delete sequence.
    let _maintenance_guard = s.maintenance.write().await;

    let segments = s.segments.clone();
    let candidates = tokio::task::spawn_blocking(move || segments.retention_candidates(cutoff_ns)).await.map_err(anyhow::Error::from)??;

    // The segment seal publishes ContentIndex events. Wait until all metadata
    // ordered before this point is in ClickHouse before issuing mutations.
    let metadata = s.metadata.clone();
    tokio::task::spawn_blocking(move || metadata.barrier()).await.map_err(anyhow::Error::from)??;

    let mutation = s.clickhouse.delete_before(cutoff).await?;
    let segments = s.segments.clone();
    let delete_paths = candidates.clone();
    let deleted = tokio::task::spawn_blocking(move || segments.delete_segments(&delete_paths)).await.map_err(anyhow::Error::from)??;

    tracing::warn!(
        cutoff=%mutation.cutoff,
        segment_files=deleted.files,
        segment_bytes=deleted.bytes,
        "traffic retention cleanup completed"
    );

    Ok(Json(serde_json::json!({
        "ok": true,
        "cutoff": mutation.cutoff,
        "tables_mutated": mutation.tables_mutated,
        "segments_deleted": deleted.files,
        "segment_bytes_deleted": deleted.bytes,
        "note": "ClickHouse mutation completed; obsolete part files may be reclaimed asynchronously",
    })))
}

async fn api_not_found() -> Response {
    (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not found"}))).into_response()
}

async fn prometheus_metrics(State(s): State<ApiState>) -> Response {
    ([
        (header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8"),
    ], s.metrics.prometheus()).into_response()
}

async fn status(State(s): State<ApiState>) -> ApiResult<Json<serde_json::Value>> {
    let service_spm = s.clickhouse.query_service_spm().await.unwrap_or_else(|error| {
        tracing::debug!(%error, "cannot query per-service SPM");
        HashMap::new()
    });
    Ok(Json(serde_json::json!({
        "ok": true,
        "version": env!("CARGO_PKG_VERSION"),
        "metrics": s.metrics.snapshot(),
        "live_pressure_pct": s.metrics.live_pressure_pct(),
        "services": s.services.list(),
        "service_spm": service_spm,
    })))
}

async fn resource_status(State(s): State<ApiState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "metrics": s.metrics.snapshot(),
        "resources": crate::resources::snapshot(),
        "live_pressure_pct": s.metrics.live_pressure_pct(),
    }))
}

async fn flows(State(s): State<ApiState>, Query(filter): Query<TrafficFilter>) -> ApiResult<Json<serde_json::Value>> {
    let favorites = s.postgres.list_favorites().await?.into_iter().collect::<HashSet<_>>();
    let active_ignores = s.patterns.active_ignore_revisions();
    let rows = s.clickhouse.query_flows(&filter, &favorites, &active_ignores).await?;
    let ids = rows.iter().map(|row| row.flow_id).collect::<Vec<_>>();
    let pattern_ids = s.clickhouse.query_pattern_ids_for_flows(&ids).await.unwrap_or_else(|error| {
        tracing::warn!(%error, "cannot enrich flow list with pattern ids");
        HashMap::new()
    });
    let user_agents = s.clickhouse.query_user_agents_for_flows(&ids).await.unwrap_or_else(|error| {
        tracing::warn!(%error, "cannot enrich flow list with user agents");
        HashMap::new()
    });
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let flow_id = row.flow_id;
        let mut value = serde_json::to_value(row).map_err(anyhow::Error::from)?;
        if let Some(object) = value.as_object_mut() {
            object.insert("favorite".into(), serde_json::json!(favorites.contains(&flow_id)));
            object.insert("user_agent".into(), serde_json::json!(user_agents.get(&flow_id)));
            object.insert("pattern_ids".into(), serde_json::json!(pattern_ids.get(&flow_id).cloned().unwrap_or_default()));
        }
        items.push(value);
    }
    Ok(Json(serde_json::json!({"items":items,"limit":filter.limit.unwrap_or(100),"offset":filter.offset.unwrap_or(0)})))
}

fn suppress_redundant_tcp_raw(records: Vec<crate::model::ContentRecord>) -> Vec<crate::model::ContentRecord> {
    use crate::model::{ContentView, Direction};

    // HTTP semantic records describe the same reassembled TCP byte range as
    // TcpRaw for normal HTTP/1.x headers and fixed-length bodies. Build a
    // per-direction coverage map and suppress only raw records whose entire
    // stream range is represented semantically. Decoded bodies are excluded:
    // they are a derived representation and do not cover raw TCP bytes.
    let mut coverage = HashMap::<Direction, Vec<(u64, u64)>>::new();
    for record in &records {
        let semantic = matches!(
            record.view,
            ContentView::HttpRequestHeaders
                | ContentView::HttpRequestBody
                | ContentView::HttpResponseHeaders
                | ContentView::HttpResponseBody
        );
        if semantic && !record.data.is_empty() {
            coverage
                .entry(record.direction)
                .or_default()
                .push((record.stream_offset, record.stream_offset.saturating_add(record.data.len() as u64)));
        }
    }

    for ranges in coverage.values_mut() {
        ranges.sort_unstable_by_key(|range| range.0);
        let mut merged = Vec::<(u64, u64)>::with_capacity(ranges.len());
        for (start, end) in ranges.drain(..) {
            if let Some(last) = merged.last_mut() {
                if start <= last.1 {
                    last.1 = last.1.max(end);
                    continue;
                }
            }
            merged.push((start, end));
        }
        *ranges = merged;
    }

    records
        .into_iter()
        .filter(|record| {
            if record.view != ContentView::TcpRaw || record.data.is_empty() {
                return true;
            }
            let start = record.stream_offset;
            let end = start.saturating_add(record.data.len() as u64);
            !coverage
                .get(&record.direction)
                .map(|ranges| ranges.iter().any(|(covered_start, covered_end)| *covered_start <= start && *covered_end >= end))
                .unwrap_or(false)
        })
        .collect()
}

fn is_http_wire_view(view: crate::model::ContentView) -> bool {
    matches!(
        view,
        crate::model::ContentView::HttpRequestHeaders
            | crate::model::ContentView::HttpRequestBody
            | crate::model::ContentView::HttpResponseHeaders
            | crate::model::ContentView::HttpResponseBody
    )
}

fn project_matches_to_visible_content(
    all_records: &[crate::model::ContentRecord],
    visible_records: &[crate::model::ContentRecord],
    matches: Vec<crate::model::MatchRecord>,
) -> HashMap<Uuid, Vec<crate::model::MatchRecord>> {
    let visible_ids = visible_records.iter().map(|record| record.id).collect::<HashSet<_>>();
    let by_id = all_records.iter().map(|record| (record.id, record)).collect::<HashMap<_, _>>();
    let mut out = HashMap::<Uuid, Vec<crate::model::MatchRecord>>::new();

    for hit in matches {
        if visible_ids.contains(&hit.content_id) {
            out.entry(hit.content_id).or_default().push(hit);
            continue;
        }

        let Some(source) = by_id.get(&hit.content_id).copied() else { continue; };
        if source.view != crate::model::ContentView::TcpRaw { continue; }

        // ANYWHERE patterns intentionally scan the canonical reassembled TCP
        // stream once. When that raw record is hidden because HTTP has an
        // equivalent semantic representation, project the hit onto the visible
        // HTTP record instead of rescanning duplicate bytes in the matcher.
        // This preserves highlighting while keeping matcher CPU linear in the
        // canonical byte stream.
        for target in visible_records.iter().filter(|record| {
            record.direction == source.direction && is_http_wire_view(record.view)
        }) {
            let target_start = target.stream_offset;
            let target_end = target_start.saturating_add(target.data.len() as u64);
            if hit.offset_start >= target_end || hit.offset_end <= target_start {
                continue;
            }
            let mut projected = hit.clone();
            projected.content_id = target.id;
            projected.view = target.view;
            let bucket = out.entry(target.id).or_default();
            let duplicate = bucket.iter().any(|existing| {
                existing.pattern_id == projected.pattern_id
                    && existing.pattern_revision == projected.pattern_revision
                    && existing.offset_start == projected.offset_start
                    && existing.offset_end == projected.offset_end
                    && existing.historical == projected.historical
            });
            if !duplicate {
                bucket.push(projected);
            }
        }
    }

    out
}

async fn flow_content(State(s):State<ApiState>,Path(id):Path<Uuid>)->ApiResult<Json<serde_json::Value>>{
    let flow = s.clickhouse.query_flow(id).await?.ok_or_else(|| ApiError::not_found("flow not found"))?;
    let (_, request_direction) = crate::model::FlowKey::canonical(
        flow.src_ip.parse::<std::net::IpAddr>().map_err(anyhow::Error::from)?,
        flow.src_port,
        flow.dst_ip.parse::<std::net::IpAddr>().map_err(anyhow::Error::from)?,
        flow.dst_port,
        flow.protocol,
    );
    let indices = s.clickhouse.query_content_for_flow(id, 2000).await?;
    let matches = s.clickhouse.query_matches_for_flow(id).await?;
    let store = s.segments.clone();
    let missing_segments_warned = s.missing_segments_warned.clone();
    let all_records = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<crate::model::ContentRecord>> {
        // Content for a busy HTTP flow often lives in only a handful of segment
        // files. Group reads by path so one UI refresh does not perform
        // canonicalize()+open() once per ContentRecord.
        let mut groups = HashMap::<String, Vec<(usize, u64, Uuid)>>::new();
        for (slot, idx) in indices.iter().enumerate() {
            groups.entry(idx.segment_path.clone()).or_default()
                .push((slot, idx.segment_offset, idx.content_id));
        }
        let mut ordered = vec![None; indices.len()];
        for (path, mut entries) in groups {
            entries.sort_unstable_by_key(|entry| entry.1);
            let offsets = entries.iter().map(|entry| entry.1).collect::<Vec<_>>();
            match store.read_many_at(std::path::Path::new(&path), &offsets) {
                Ok(results) => {
                    missing_segments_warned.lock().remove(&path);
                    for ((slot, _offset, content_id), (_actual_offset, result)) in entries.into_iter().zip(results) {
                        match result {
                            Ok(record) => ordered[slot] = Some(record),
                            Err(e) => tracing::warn!(%content_id, error=%e, "failed to read indexed content"),
                        }
                    }
                }
                Err(e) => {
                    let first = missing_segments_warned.lock().insert(path.clone());
                    if first {
                        tracing::warn!(segment=%path, error=%e, "indexed segment is unavailable; suppressing repeated warnings until it becomes readable");
                    } else {
                        tracing::debug!(segment=%path, error=%e, "indexed segment remains unavailable");
                    }
                }
            }
        }
        Ok(ordered.into_iter().flatten().collect())
    }).await.map_err(|e| anyhow::anyhow!(e))??;
    let records = suppress_redundant_tcp_raw(all_records.clone());
    let mut matches_by_content = project_matches_to_visible_content(&all_records, &records, matches);
    let items=records.into_iter().map(|r| {
        let request = match r.view {
            crate::model::ContentView::HttpRequestHeaders | crate::model::ContentView::HttpRequestBody | crate::model::ContentView::HttpRequestDecodedBody => true,
            crate::model::ContentView::HttpResponseHeaders | crate::model::ContentView::HttpResponseBody | crate::model::ContentView::HttpResponseDecodedBody => false,
            crate::model::ContentView::TcpRaw => r.direction == request_direction,
        };
        let hits = matches_by_content.remove(&r.id).unwrap_or_default().into_iter().map(|hit| serde_json::json!({
            "pattern_id": hit.pattern_id,
            "offset_start": hit.offset_start,
            "offset_end": hit.offset_end,
            "historical": hit.historical,
        })).collect::<Vec<_>>();
        serde_json::json!({
            "id":r.id,"timestamp_ns":r.ts_ns.to_string(),"direction":r.direction,"request":request,"view":r.view,"offset":r.stream_offset,"len":r.data.len(),
            "preview":String::from_utf8_lossy(&r.data[..r.data.len().min(4096)]),
            "matches":hits,
        })
    }).collect::<Vec<_>>();
    Ok(Json(serde_json::json!({"items":items})))
}

async fn flow_detail(State(s): State<ApiState>, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    let flow = s.clickhouse.query_flow(id).await?.ok_or_else(|| ApiError::not_found("flow not found"))?;
    let http = s.clickhouse.query_http_for_flow(id).await?;
    let matches = s.clickhouse.query_matches_for_flow(id).await?;
    let favorite = s.postgres.list_favorites().await?.contains(&id);
    Ok(Json(serde_json::json!({"flow":flow,"http":http,"matches":matches,"favorite":favorite})))
}

#[derive(Deserialize)]
struct FavoriteRequest { favorite: bool }
async fn set_favorite(State(s):State<ApiState>,Path(id):Path<Uuid>,Json(req):Json<FavoriteRequest>)->ApiResult<Json<serde_json::Value>>{
    s.postgres.set_favorite(id,req.favorite).await?;
    Ok(Json(serde_json::json!({"flow_id":id,"favorite":req.favorite})))
}

#[derive(Deserialize)]
struct ContentQuery { format: Option<String> }
async fn content(State(s):State<ApiState>,Path(id):Path<Uuid>,Query(q):Query<ContentQuery>)->ApiResult<Response>{
    let idx=s.clickhouse.query_content_index(id).await?.ok_or_else(||ApiError::not_found("content not found"))?;
    let store=s.segments.clone();
    let record=tokio::task::spawn_blocking(move || store.read_at(std::path::Path::new(&idx.segment_path),idx.segment_offset))
        .await.map_err(|e| anyhow::anyhow!(e))??;
    match q.format.as_deref() {
        Some("raw") => Ok(([(header::CONTENT_TYPE,"application/octet-stream")],record.data.to_vec()).into_response()),
        Some("hex") => Ok(Json(serde_json::json!({"id":id,"view":record.view,"data":hex::encode(&record.data)})).into_response()),
        Some("text") => Ok(Json(serde_json::json!({"id":id,"view":record.view,"data":String::from_utf8_lossy(&record.data)})).into_response()),
        _ => Ok(Json(serde_json::json!({"id":id,"view":record.view,"data":base64::engine::general_purpose::STANDARD.encode(&record.data)})).into_response()),
    }
}

async fn list_patterns(State(s):State<ApiState>)->ApiResult<Json<Vec<PatternRevision>>>{Ok(Json(s.patterns.list().await?))}
async fn create_pattern(State(s):State<ApiState>,Json(req):Json<NewPattern>)->ApiResult<(StatusCode,Json<PatternRevision>)>{
    let p=s.patterns.create(req).await?;
    s.replay.enqueue(p.clone()).await?;
    Ok((StatusCode::CREATED,Json(p)))
}

#[derive(Deserialize)]
struct UpdatePatternRequest {
    name: String,
    expression: String,
    kind: crate::model::PatternKind,
    action: crate::model::PatternAction,
    #[serde(default = "default_pattern_color_api")]
    color: String,
    #[serde(default)]
    direction_type: crate::model::PatternDirection,
    service: Option<String>,
    view: Option<crate::model::ContentView>,
    enabled: Option<bool>,
}
fn default_pattern_color_api() -> String { "#FF7474".to_owned() }
async fn update_pattern(State(s):State<ApiState>,Path(id):Path<Uuid>,Json(req):Json<UpdatePatternRequest>)->ApiResult<Json<PatternRevision>>{
    let enabled=req.enabled.unwrap_or(true);
    let p=s.patterns.update(id,NewPattern{name:req.name,expression:req.expression,kind:req.kind,action:req.action,color:req.color,direction_type:req.direction_type,service:req.service,view:req.view},enabled).await?;
    if enabled { s.replay.enqueue(p.clone()).await?; }
    Ok(Json(p))
}
#[derive(Deserialize)] struct EnabledRequest{enabled:bool}
async fn set_pattern_enabled(State(s):State<ApiState>,Path(id):Path<Uuid>,Json(req):Json<EnabledRequest>)->ApiResult<Json<PatternRevision>>{
    let p=s.patterns.set_enabled(id,req.enabled).await?;
    if req.enabled { s.replay.enqueue(p.clone()).await?; }
    Ok(Json(p))
}

async fn delete_pattern(State(s):State<ApiState>,Path(id):Path<Uuid>)->ApiResult<StatusCode>{
    if !s.patterns.delete(id).await? {
        return Err(ApiError::not_found("pattern not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn lookback_pattern(State(s):State<ApiState>,Path(id):Path<Uuid>)->ApiResult<(StatusCode,Json<serde_json::Value>)>{
    let p=s.patterns.postgres().latest_pattern(id).await?.ok_or_else(||ApiError::not_found("pattern not found"))?;
    s.replay.enqueue(p.clone()).await?;
    Ok((StatusCode::ACCEPTED,Json(serde_json::json!({"pattern_id":id,"revision":p.revision,"queued":true}))))
}

async fn replay_jobs(State(s):State<ApiState>)->ApiResult<Json<serde_json::Value>>{Ok(Json(serde_json::json!({"items":s.replay.jobs().await?})))}

async fn list_services(State(s): State<ApiState>) -> Json<Vec<ServiceConfig>> {
    Json(s.services.list())
}

#[derive(Debug, Deserialize)]
struct ServiceRequest {
    name: String,
    #[serde(default = "default_service_http")]
    http: bool,
    #[serde(default)]
    urldecode_http_requests: bool,
    #[serde(default)]
    merge_adjacent_packets: bool,
    #[serde(default)]
    parse_websockets: bool,
}

#[derive(Debug, Deserialize)]
struct CreateServiceRequest {
    port: u16,
    #[serde(flatten)]
    service: ServiceRequest,
}

fn default_service_http() -> bool { true }

fn validate_service(port: u16, req: &ServiceRequest) -> ApiResult<()> {
    if port == 0 {
        return Err(ApiError::bad_request("service port must be between 1 and 65535"));
    }
    let name = req.name.trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("service name is empty"));
    }
    if name.len() > 128 {
        return Err(ApiError::bad_request("service name is longer than 128 characters"));
    }
    Ok(())
}

fn service_from_request(port: u16, req: ServiceRequest) -> ServiceConfig {
    ServiceConfig {
        port,
        name: req.name.trim().to_owned(),
        http: req.http,
        urldecode_http_requests: req.urldecode_http_requests,
        merge_adjacent_packets: req.merge_adjacent_packets,
        parse_websockets: req.parse_websockets,
    }
}

async fn create_service(
    State(s): State<ApiState>,
    Json(req): Json<CreateServiceRequest>,
) -> ApiResult<(StatusCode, Json<ServiceConfig>)> {
    validate_service(req.port, &req.service)?;
    if s.services.by_port(req.port).is_some() {
        return Err(ApiError::conflict("a service with this port already exists"));
    }
    let service = service_from_request(req.port, req.service);
    let saved = s.postgres.upsert_service(&service).await?;
    s.services.upsert(saved.clone());
    tracing::info!(port=saved.port, name=%saved.name, "service created");
    Ok((StatusCode::CREATED, Json(saved)))
}

async fn update_service(
    State(s): State<ApiState>,
    Path(port): Path<u16>,
    Json(req): Json<ServiceRequest>,
) -> ApiResult<Json<ServiceConfig>> {
    validate_service(port, &req)?;
    let service = service_from_request(port, req);
    let saved = s.postgres.upsert_service(&service).await?;
    s.services.upsert(saved.clone());
    tracing::info!(port=saved.port, name=%saved.name, "service updated");
    Ok(Json(saved))
}

async fn delete_service(
    State(s): State<ApiState>,
    Path(port): Path<u16>,
) -> ApiResult<StatusCode> {
    if !s.postgres.delete_service(port).await? {
        return Err(ApiError::not_found("service not found"));
    }
    s.services.delete(port);
    tracing::info!(port, "service deleted");
    Ok(StatusCode::NO_CONTENT)
}

async fn live_ws(ws:WebSocketUpgrade,State(s):State<ApiState>)->Response{ws.on_upgrade(move |socket|live_socket(socket,s.live_events.subscribe()))}
async fn live_socket(mut socket:WebSocket,mut rx:broadcast::Receiver<LiveEvent>){
    loop{
        tokio::select!{
            evt=rx.recv()=>match evt{Ok(evt)=>{if let Ok(text)=serde_json::to_string(&evt){if socket.send(Message::Text(text.into())).await.is_err(){break;}}},Err(broadcast::error::RecvError::Lagged(_))=>continue,Err(_)=>break},
            msg=socket.next()=>match msg{Some(Ok(Message::Close(_)))|None=>break,Some(Err(_))=>break,_=>{}}
        }
    }
}

#[cfg(test)]
mod content_dedup_tests {
    use super::{project_matches_to_visible_content, suppress_redundant_tcp_raw};
    use crate::model::{ContentRecord, ContentView, Direction, MatchRecord, PatternAction};
    use bytes::Bytes;
    use uuid::Uuid;

    fn record(view: ContentView, direction: Direction, offset: u64, data: &'static [u8]) -> ContentRecord {
        ContentRecord {
            id: Uuid::new_v4(),
            flow_id: Uuid::nil(),
            ts_ns: 1,
            service: Some("http".into()),
            direction,
            view,
            stream_offset: offset,
            data: Bytes::from_static(data),
        }
    }

    fn hit(content: &ContentRecord, start: u64, end: u64) -> MatchRecord {
        MatchRecord {
            timestamp: chrono::Utc::now(),
            pattern_id: Uuid::new_v4(),
            pattern_revision: 1,
            flow_id: content.flow_id,
            content_id: content.id,
            view: content.view,
            action: PatternAction::Find,
            offset_start: start,
            offset_end: end,
            historical: false,
        }
    }

    #[test]
    fn hides_tcp_raw_fully_covered_by_http_semantics() {
        let request = b"GET / HTTP/1.1\r\nHost: bazalt\r\n\r\n";
        let records = vec![
            record(ContentView::TcpRaw, Direction::AToB, 0, request),
            record(ContentView::HttpRequestHeaders, Direction::AToB, 0, request),
        ];
        let out = suppress_redundant_tcp_raw(records);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].view, ContentView::HttpRequestHeaders);
    }

    #[test]
    fn hides_split_raw_chunks_covered_by_one_http_record() {
        let records = vec![
            record(ContentView::TcpRaw, Direction::AToB, 0, b"GET / HTTP/1.1\r\n"),
            record(ContentView::TcpRaw, Direction::AToB, 16, b"Host: x\r\n\r\n"),
            record(ContentView::HttpRequestHeaders, Direction::AToB, 0, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
        ];
        let out = suppress_redundant_tcp_raw(records);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].view, ContentView::HttpRequestHeaders);
    }

    #[test]
    fn keeps_uncovered_raw_fallback() {
        let records = vec![
            record(ContentView::HttpResponseHeaders, Direction::BToA, 0, b"HTTP/1.1 200 OK\r\n\r\n"),
            record(ContentView::TcpRaw, Direction::BToA, 19, b"4\r\ntest\r\n0\r\n\r\n"),
        ];
        let out = suppress_redundant_tcp_raw(records);
        assert_eq!(out.len(), 2);
        assert!(out.iter().any(|record| record.view == ContentView::TcpRaw));
    }

    #[test]
    fn never_treats_decoded_body_as_raw_coverage() {
        let records = vec![
            record(ContentView::TcpRaw, Direction::BToA, 100, b"compressed"),
            record(ContentView::HttpResponseDecodedBody, Direction::BToA, 100, b"decoded"),
        ];
        let out = suppress_redundant_tcp_raw(records);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn projects_hidden_raw_match_onto_http_record_without_rescanning() {
        let request = b"GET /secret HTTP/1.1\r\nHost: bazalt\r\n\r\n";
        let raw = record(ContentView::TcpRaw, Direction::AToB, 0, request);
        let http = record(ContentView::HttpRequestHeaders, Direction::AToB, 0, request);
        let pattern_start = request.windows(6).position(|w| w == b"secret").unwrap() as u64;
        let match_record = hit(&raw, pattern_start, pattern_start + 6);
        let all = vec![raw.clone(), http.clone()];
        let visible = suppress_redundant_tcp_raw(all.clone());
        let projected = project_matches_to_visible_content(&all, &visible, vec![match_record]);
        assert!(!projected.contains_key(&raw.id));
        let hits = projected.get(&http.id).expect("match should move to visible HTTP record");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].content_id, http.id);
        assert_eq!(hits[0].view, ContentView::HttpRequestHeaders);
        assert_eq!(hits[0].offset_start, pattern_start);
    }

    #[test]
    fn keeps_match_on_visible_raw_fallback() {
        let raw = record(ContentView::TcpRaw, Direction::BToA, 50, b"not-http");
        let match_record = hit(&raw, 50, 58);
        let all = vec![raw.clone()];
        let visible = suppress_redundant_tcp_raw(all.clone());
        let projected = project_matches_to_visible_content(&all, &visible, vec![match_record]);
        assert_eq!(projected.get(&raw.id).map(Vec::len), Some(1));
    }
}

pub type ApiResult<T>=Result<T,ApiError>;
#[derive(Debug)] pub struct ApiError{status:StatusCode,message:String}
impl ApiError{
    fn not_found(m:&str)->Self{Self{status:StatusCode::NOT_FOUND,message:m.into()}}
    fn bad_request(m:&str)->Self{Self{status:StatusCode::BAD_REQUEST,message:m.into()}}
    fn conflict(m:&str)->Self{Self{status:StatusCode::CONFLICT,message:m.into()}}
}
impl From<anyhow::Error> for ApiError{fn from(e:anyhow::Error)->Self{Self{status:StatusCode::INTERNAL_SERVER_ERROR,message:e.to_string()}}}
impl IntoResponse for ApiError{fn into_response(self)->Response{(self.status,Json(serde_json::json!({"error":self.message}))).into_response()}}
