//! The HTTP surface: routes of the Docker Engine API.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use serde::Deserialize;

use super::filters::Filters;
use super::model::{API_VERSION, ENGINE_VERSION, MIN_API_VERSION};
use super::util::{ApiError, ApiResult};
use super::Engine;

type S = State<Arc<Engine>>;
type Q = Query<HashMap<String, String>>;

/// All routes, with Docker's optional `/v1.NN` path prefix accepted.
pub(crate) fn router(engine: Arc<Engine>) -> Router {
    let api = Router::new()
        .route("/_ping", get(ping).head(ping))
        .route("/version", get(version))
        .route("/info", get(info))
        .route("/events", get(events))
        .route("/system/df", get(system_df))
        .route("/auth", post(auth))
        .route("/containers/create", post(container_create))
        .route("/containers/json", get(container_list))
        .route("/containers/prune", post(container_prune))
        .route("/containers/{id}/json", get(container_inspect))
        .route("/containers/{id}/start", post(container_start))
        .route("/containers/{id}/stop", post(container_stop))
        .route("/containers/{id}/restart", post(container_restart))
        .route("/containers/{id}/kill", post(container_kill))
        .route("/containers/{id}/wait", post(container_wait))
        .route("/containers/{id}/rename", post(container_rename))
        .route("/containers/{id}/attach", post(container_attach))
        .route("/containers/{id}/resize", post(container_resize))
        .route("/containers/{id}/logs", get(container_logs))
        .route("/containers/{id}/top", get(container_top))
        .route("/containers/{id}/stats", get(container_stats))
        .route("/containers/{id}/exec", post(exec_create))
        .route("/containers/{id}/update", post(container_update))
        .route("/containers/{id}/pause", post(container_pause))
        .route("/containers/{id}/unpause", post(container_unpause))
        .route(
            "/containers/{id}/archive",
            get(super::archive::get_archive)
                .head(super::archive::head_archive)
                .put(super::archive::put_archive),
        )
        .route("/containers/{id}/export", get(super::archive::export))
        .route("/containers/{id}", axum::routing::delete(container_remove))
        .route("/commit", post(container_commit))
        .route("/exec/{id}/start", post(exec_start))
        .route("/exec/{id}/resize", post(exec_resize))
        .route("/exec/{id}/json", get(exec_inspect))
        .route("/images/create", post(image_pull))
        .route("/images/json", get(image_list))
        .route("/images/prune", post(image_prune))
        .route("/images/load", post(image_load))
        .route("/images/get", get(images_get))
        .route("/images/{*rest}", any(image_dispatch))
        .route("/build", post(super::build::build))
        .route("/build/prune", post(super::build::build_prune))
        .route("/session", post(super::build::session))
        .route("/grpc", post(super::build::session))
        .route("/volumes", get(volume_list))
        .route("/volumes/create", post(volume_create))
        .route("/volumes/prune", post(volume_prune))
        .route("/volumes/{name}", get(volume_inspect).delete(volume_remove))
        .route("/plugins", get(|| async { Json(serde_json::json!([])) }))
        .route("/distribution/{*rest}", get(distribution))
        .merge(super::network::routes())
        .fallback(not_found)
        .with_state(engine);
    let mut outer = Router::new()
        .fallback_service(api)
        .layer(axum::middleware::map_request(strip_version));
    if let Some(path) = std::env::var_os("SMOLVM_ENGINE_RECORD") {
        let recorder = Arc::new(Recorder {
            file: parking_lot::Mutex::new(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .ok(),
            ),
        });
        outer = outer.layer(axum::middleware::from_fn(move |req, next| {
            let recorder = recorder.clone();
            record_request(recorder, req, next)
        }));
    }
    outer
}

/// Appends every request to a file as one JSON line (`SMOLVM_ENGINE_RECORD`),
/// which is how the conformance fixtures were captured from real clients.
struct Recorder {
    file: parking_lot::Mutex<Option<std::fs::File>>,
}

async fn record_request(
    recorder: Arc<Recorder>,
    req: Request,
    next: axum::middleware::Next,
) -> Response {
    use std::io::Write as _;
    let (parts, body) = req.into_parts();
    let content_type = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    // Only a body small enough to hold, and declared so: buffering an upload
    // (an image tar the CLI sends untyped) would cut it off at the limit.
    let small = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok()?.parse::<usize>().ok())
        .is_some_and(|n| n <= 4 << 20);
    let json = small
        && (content_type.contains("json")
            || (content_type.is_empty() && !parts.uri.path().ends_with("/archive")));
    let (body, recorded) = if json && parts.method != Method::GET {
        match axum::body::to_bytes(body, 4 << 20).await {
            Ok(bytes) => {
                let value = serde_json::from_slice::<serde_json::Value>(&bytes)
                    .unwrap_or(serde_json::Value::Null);
                (Body::from(bytes), value)
            }
            Err(_) => (Body::empty(), serde_json::Value::Null),
        }
    } else {
        (body, serde_json::Value::Null)
    };
    let mut line = serde_json::json!({
        "method": parts.method.as_str(),
        "path": parts.uri.path(),
        "query": parts.uri.query().unwrap_or(""),
        "upgrade": parts.headers.contains_key(header::UPGRADE),
        "contentType": content_type,
        "userAgent": parts.headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or(""),
        "body": recorded,
    });
    let response = next.run(Request::from_parts(parts.clone(), body)).await;
    // The answer goes with the request: its status, and its body when it is
    // a complete JSON document rather than a stream.
    use http_body::Body as _;
    let (rparts, rbody) = response.into_parts();
    let complete = rbody.size_hint().exact().is_some();
    let json_answer = rparts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("json"));
    line["status"] = serde_json::json!(rparts.status.as_u16());
    line["streaming"] = serde_json::json!(!complete);
    let rbody = if complete && json_answer {
        match axum::body::to_bytes(rbody, 16 << 20).await {
            Ok(bytes) => {
                line["response"] = serde_json::from_slice::<serde_json::Value>(&bytes)
                    .unwrap_or(serde_json::Value::Null);
                Body::from(bytes)
            }
            Err(_) => Body::empty(),
        }
    } else {
        rbody
    };
    if let Some(file) = recorder.file.lock().as_mut() {
        let _ = writeln!(file, "{line}");
    }
    Response::from_parts(rparts, rbody)
}

/// Drop a `/v1.NN` prefix so every route matches with or without it.
async fn strip_version(mut req: Request) -> Request {
    let path = req.uri().path();
    if let Some(rest) = path.strip_prefix("/v") {
        if let Some(slash) = rest.find('/') {
            let version = &rest[..slash];
            if version
                .split('.')
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
            {
                let new_path = rest[slash..].to_string();
                let pq = match req.uri().query() {
                    Some(q) => format!("{new_path}?{q}"),
                    None => new_path,
                };
                if let Ok(uri) = pq.parse() {
                    *req.uri_mut() = uri;
                }
            }
        }
    }
    req
}

async fn not_found(method: Method, uri: axum::http::Uri) -> ApiError {
    tracing::debug!(%method, %uri, "unhandled engine API request");
    ApiError::not_found("page not found")
}

fn q_bool(q: &HashMap<String, String>, key: &str) -> bool {
    q.get(key)
        .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "True" | "yes"))
}

fn q_i64(q: &HashMap<String, String>, key: &str) -> Option<i64> {
    q.get(key).and_then(|v| v.parse().ok())
}

fn filters(q: &HashMap<String, String>) -> ApiResult<Filters> {
    Filters::parse(q.get("filters").map(String::as_str)).map_err(ApiError::bad_request)
}

fn container(engine: &Engine, id: &str) -> ApiResult<Arc<super::containers::Container>> {
    engine
        .find_container(id)
        .ok_or_else(|| ApiError::no_such_container(id))
}

fn json_body<T: for<'de> Deserialize<'de> + Default>(body: &Bytes) -> ApiResult<T> {
    super::util::parse_body(body)
}

fn no_content() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

fn not_modified() -> Response {
    StatusCode::NOT_MODIFIED.into_response()
}

// ============================================================================
// System
// ============================================================================

async fn ping() -> Response {
    let mut r = Response::new(Body::from("OK"));
    let h = r.headers_mut();
    h.insert("API-Version", HeaderValue::from_static(API_VERSION));
    h.insert("Builder-Version", HeaderValue::from_static("1"));
    h.insert("Docker-Experimental", HeaderValue::from_static("false"));
    h.insert("OSType", HeaderValue::from_static("linux"));
    h.insert("Swarm", HeaderValue::from_static("inactive"));
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-store, must-revalidate"),
    );
    h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    r
}

/// The daemon architecture in Docker's (Go) naming.
fn go_arch() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        other => other,
    }
}

fn kernel_version() -> String {
    format!("smolvm {}", crate::ENGINE_BUILD)
}

async fn version() -> Json<serde_json::Value> {
    let details = serde_json::json!({
        "ApiVersion": API_VERSION,
        "MinAPIVersion": MIN_API_VERSION,
        "Os": "linux",
        "Arch": go_arch(),
        "KernelVersion": kernel_version(),
        "GitCommit": crate::ENGINE_BUILD,
        "GoVersion": "",
        "BuildTime": "",
        "Experimental": "false",
    });
    Json(serde_json::json!({
        "Platform": {"Name": format!("smolvm {}", env!("CARGO_PKG_VERSION"))},
        "Components": [{"Name": "Engine", "Version": ENGINE_VERSION, "Details": details}],
        "Version": ENGINE_VERSION,
        "ApiVersion": API_VERSION,
        "MinAPIVersion": MIN_API_VERSION,
        "GitCommit": crate::ENGINE_BUILD,
        "GoVersion": "",
        "Os": "linux",
        "Arch": go_arch(),
        "KernelVersion": kernel_version(),
        "Experimental": false,
        "BuildTime": "",
    }))
}

async fn info(State(engine): S) -> Json<serde_json::Value> {
    let containers: Vec<_> = engine.containers.read().values().cloned().collect();
    let running = containers.iter().filter(|c| c.is_running()).count();
    let paused = containers
        .iter()
        .filter(|c| c.record().state.status == "paused")
        .count();
    let host = crate::process::host_memory_stats()
        .map(|m| m.total_bytes)
        .or_else(|| crate::data::resources::host_physical_memory_mib().map(|mib| mib << 20))
        .unwrap_or(0);
    let ncpu = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let hostname = std::process::Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let mut info = serde_json::Map::new();
    if let serde_json::Value::Object(part) = serde_json::json!({
        "ID": engine_id(&engine),
        "Containers": containers.len(),
        "ContainersRunning": running - paused.min(running),
        "ContainersPaused": paused,
        "ContainersStopped": containers.len() - running,
        "Images": engine.images.all().len(),
        "Driver": "smolvm",
        "DriverStatus": [["Isolation", "one machine per container"]],
        "Plugins": {
            "Volume": ["local"],
            "Network": ["bridge", "host", "null"],
            "Authorization": null,
            "Log": ["json-file"],
        },
        "MemoryLimit": true,
        "SwapLimit": false,
        "KernelMemoryTCP": false,
    }) {
        info.extend(part);
    }
    if let serde_json::Value::Object(part) = serde_json::json!({
        "CpuCfsPeriod": true,
        "CpuCfsQuota": true,
        "CPUShares": false,
        "CPUSet": false,
        "PidsLimit": false,
        "IPv4Forwarding": true,
        "Debug": false,
        "NFd": 0,
        "OomKillDisable": false,
        "NGoroutines": 0,
        "SystemTime": super::util::now_rfc3339(),
        "LoggingDriver": "json-file",
    }) {
        info.extend(part);
    }
    if let serde_json::Value::Object(part) = serde_json::json!({
        "CgroupDriver": "none",
        "CgroupVersion": "2",
        "NEventsListener": 0,
        "KernelVersion": kernel_version(),
        "OperatingSystem": "smolvm",
        "OSVersion": env!("CARGO_PKG_VERSION"),
        "OSType": "linux",
        "Architecture": std::env::consts::ARCH,
        "IndexServerAddress": "https://index.docker.io/v1/",
        "RegistryConfig": {
            "IndexConfigs": {"docker.io": {"Name": "docker.io", "Mirrors": [], "Secure": true, "Official": true}},
            "InsecureRegistryCIDRs": ["127.0.0.0/8"],
            "Mirrors": [],
        },
        "NCPU": ncpu,
        "MemTotal": host,
    }) {
        info.extend(part);
    }
    if let serde_json::Value::Object(part) = serde_json::json!({
        "GenericResources": null,
        "DockerRootDir": engine.config.root,
        "HttpProxy": std::env::var("HTTP_PROXY").unwrap_or_default(),
        "HttpsProxy": std::env::var("HTTPS_PROXY").unwrap_or_default(),
        "NoProxy": std::env::var("NO_PROXY").unwrap_or_default(),
        "Name": hostname,
        "Labels": [],
        "ExperimentalBuild": false,
        "ServerVersion": ENGINE_VERSION,
        "Runtimes": {"smolvm": {"path": "smolvm"}},
        "DefaultRuntime": "smolvm",
        "Swarm": {
            "NodeID": "", "NodeAddr": "", "LocalNodeState": "inactive",
            "ControlAvailable": false, "Error": "", "RemoteManagers": null,
        },
    }) {
        info.extend(part);
    }
    if let serde_json::Value::Object(part) = serde_json::json!({
        "LiveRestoreEnabled": false,
        "Isolation": "",
        "InitBinary": "",
        "ContainerdCommit": {"ID": ""},
        "RuncCommit": {"ID": ""},
        "InitCommit": {"ID": ""},
        "SecurityOptions": [],
        "Warnings": null,
    }) {
        info.extend(part);
    }
    Json(serde_json::Value::Object(info))
}

fn engine_id(engine: &Engine) -> String {
    let path = engine.config.root.join("engine-id");
    if let Ok(id) = std::fs::read_to_string(&path) {
        return id.trim().to_string();
    }
    let id = super::util::new_id();
    let _ = std::fs::write(&path, &id);
    id
}

async fn auth(body: Bytes) -> ApiResult<Json<serde_json::Value>> {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Login {
        username: String,
        password: String,
        serveraddress: String,
    }
    let login: Login = json_body(&body)?;
    let registry = if login.serveraddress.is_empty() {
        "docker.io".to_string()
    } else {
        login
            .serveraddress
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or("")
            .replace("index.docker.io", "docker.io")
    };
    // Check the credentials by asking the registry for a token, as a pull
    // would; nothing is stored here (the docker CLI keeps them).
    let auth = crate::registry::PullAuth::Basic {
        username: login.username,
        password: login.password,
    };
    let probe = format!("{registry}/library/hello-world:latest");
    match crate::image_store::authorized_digest(&probe, &auth).await {
        Err(e)
            if e.to_string().contains("401")
                || e.to_string().to_lowercase().contains("unauthorized") =>
        {
            Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                format!("login attempt to {registry} failed: unauthorized"),
            ))
        }
        _ => Ok(Json(
            serde_json::json!({"Status": "Login Succeeded", "IdentityToken": ""}),
        )),
    }
}

async fn events(State(engine): S, Query(q): Q) -> ApiResult<Response> {
    let f = filters(&q)?;
    let since = q
        .get("since")
        .and_then(|s| super::util::parse_time_filter(s));
    let until = q
        .get("until")
        .and_then(|s| super::util::parse_time_filter(s));
    let nanos = |t: std::time::SystemTime| {
        t.duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0)
    };
    let until_nanos = until.map(nanos);
    let mut rx = engine.events.subscribe();
    let backlog = since
        .map(|s| engine.events.since(nanos(s)))
        .unwrap_or_default();
    let (tx, body) = super::stream::json_lines();
    tokio::spawn(async move {
        let mut last = 0i64;
        for e in backlog {
            if until_nanos.is_some_and(|u| e.time_nano > u) {
                return;
            }
            last = e.time_nano;
            if super::events::matches(&e, &f)
                && tx
                    .send(serde_json::to_value(&e).unwrap_or_default())
                    .await
                    .is_err()
            {
                return;
            }
        }
        let deadline = until.map(|u| {
            let left = u
                .duration_since(std::time::SystemTime::now())
                .unwrap_or_default();
            tokio::time::Instant::now() + left
        });
        loop {
            let next = async {
                match deadline {
                    Some(d) => tokio::time::timeout_at(d, rx.recv()).await.ok(),
                    None => Some(rx.recv().await),
                }
            };
            match next.await {
                None => return,
                Some(Ok(e)) => {
                    if e.time_nano <= last {
                        continue;
                    }
                    if super::events::matches(&e, &f)
                        && tx
                            .send(serde_json::to_value(&e).unwrap_or_default())
                            .await
                            .is_err()
                    {
                        return;
                    }
                }
                Some(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
                Some(Err(_)) => return,
            }
        }
    });
    let mut r = Response::new(body);
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok(r)
}

async fn system_df(State(engine): S) -> Json<serde_json::Value> {
    let containers: Vec<serde_json::Value> = engine
        .containers
        .read()
        .values()
        .map(|c| super::containers::summary(&engine, c))
        .collect();
    let images: Vec<serde_json::Value> =
        engine.images.all().iter().map(|i| i.summary(-1)).collect();
    let volumes: Vec<serde_json::Value> = engine
        .volumes
        .all()
        .iter()
        .map(|v| engine.volumes.inspect(v))
        .collect();
    Json(serde_json::json!({
        "LayersSize": 0,
        "Images": images,
        "Containers": containers,
        "Volumes": volumes,
        "BuildCache": [],
    }))
}

async fn distribution(
    Path(rest): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let name = rest.strip_suffix("/json").unwrap_or(&rest);
    let reference = super::images::ImageRef::parse(name).map_err(ApiError::bad_request)?;
    let auth =
        super::images::pull_auth(headers.get("X-Registry-Auth").and_then(|h| h.to_str().ok()));
    let meta = super::images::resolve(&reference, &auth, None).await?;
    Ok(Json(serde_json::json!({
        "Descriptor": {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": meta.manifest_digest,
            "size": 0,
        },
        "Platforms": [{
            "architecture": meta.config["architecture"],
            "os": meta.config["os"],
        }],
    })))
}

// ============================================================================
// Containers
// ============================================================================

async fn container_create(State(engine): S, Query(q): Q, body: Bytes) -> ApiResult<Response> {
    let mut raw: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| ApiError::bad_request(format!("invalid JSON: {e}")))?;
    super::util::strip_nulls(&mut raw);
    let req: super::model::CreateRequest = serde_json::from_value(raw.clone())
        .map_err(|e| ApiError::bad_request(format!("invalid container config: {e}")))?;
    if req.config.image.is_empty() {
        return Err(ApiError::bad_request("config.Image is required"));
    }
    let raw_host = raw.get("HostConfig").cloned().unwrap_or_default();
    let (id, warnings) = super::containers::create(
        &engine,
        q.get("name").cloned(),
        req,
        raw_host,
        q.get("platform").cloned(),
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({"Id": id, "Warnings": warnings})),
    )
        .into_response())
}

async fn container_list(State(engine): S, Query(q): Q) -> ApiResult<Json<Vec<serde_json::Value>>> {
    let f = filters(&q)?;
    let all = q_bool(&q, "all");
    let mut containers: Vec<_> = engine.containers.read().values().cloned().collect();
    containers.sort_by_key(|c| std::cmp::Reverse(c.record().created));
    let mut out: Vec<serde_json::Value> = containers
        .iter()
        .filter(|c| all || c.is_running() || f.has("status"))
        .filter(|c| super::containers::matches(&engine, c, &f))
        .map(|c| super::containers::summary(&engine, c))
        .collect();
    if let Some(limit) = q_i64(&q, "limit").filter(|l| *l > 0) {
        out.truncate(limit as usize);
    }
    Ok(Json(out))
}

async fn container_inspect(
    State(engine): S,
    Path(id): Path<String>,
    Query(q): Q,
) -> ApiResult<Json<serde_json::Value>> {
    let c = container(&engine, &id)?;
    Ok(Json(super::containers::inspect(
        &engine,
        &c,
        q_bool(&q, "size"),
    )))
}

async fn container_start(State(engine): S, Path(id): Path<String>) -> ApiResult<Response> {
    let c = container(&engine, &id)?;
    if super::containers::start(&engine, &c).await? {
        Ok(no_content())
    } else {
        Ok(not_modified())
    }
}

async fn container_stop(
    State(engine): S,
    Path(id): Path<String>,
    Query(q): Q,
) -> ApiResult<Response> {
    let c = container(&engine, &id)?;
    let t = q_i64(&q, "t").or_else(|| q_i64(&q, "timeout"));
    if super::containers::stop(&engine, &c, t, q.get("signal").cloned()).await? {
        Ok(no_content())
    } else {
        Ok(not_modified())
    }
}

async fn container_restart(
    State(engine): S,
    Path(id): Path<String>,
    Query(q): Q,
) -> ApiResult<Response> {
    let c = container(&engine, &id)?;
    let t = q_i64(&q, "t").or_else(|| q_i64(&q, "timeout"));
    super::containers::restart(&engine, &c, t, q.get("signal").cloned()).await?;
    Ok(no_content())
}

async fn container_kill(
    State(engine): S,
    Path(id): Path<String>,
    Query(q): Q,
) -> ApiResult<Response> {
    let c = container(&engine, &id)?;
    let signal = q.get("signal").cloned().unwrap_or_else(|| "SIGKILL".into());
    super::containers::kill(&engine, &c, &signal).await?;
    Ok(no_content())
}

async fn container_wait(
    State(engine): S,
    Path(id): Path<String>,
    Query(q): Q,
) -> ApiResult<Response> {
    let c = container(&engine, &id)?;
    let condition = q.get("condition").cloned().unwrap_or_default();
    // Answer the headers at once, as Docker does, so a client that waits
    // before it starts the container can go on to start it.
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(1);
    tokio::spawn(async move {
        let body = match super::containers::wait(&c, &condition).await {
            Ok(code) => serde_json::json!({"StatusCode": code, "Error": null}),
            Err(e) => serde_json::json!({"StatusCode": -1, "Error": {"Message": e.message}}),
        };
        let _ = tx.send(Ok(Bytes::from(body.to_string()))).await;
    });
    let mut r = Response::new(Body::from_stream(
        tokio_stream::wrappers::ReceiverStream::new(rx),
    ));
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok(r)
}

async fn container_rename(
    State(engine): S,
    Path(id): Path<String>,
    Query(q): Q,
) -> ApiResult<Response> {
    let c = container(&engine, &id)?;
    let name = q
        .get("name")
        .ok_or_else(|| ApiError::bad_request("name is required"))?;
    super::containers::rename(&engine, &c, name)?;
    Ok(no_content())
}

async fn container_remove(
    State(engine): S,
    Path(id): Path<String>,
    Query(q): Q,
) -> ApiResult<Response> {
    let c = container(&engine, &id)?;
    super::containers::remove(&engine, &c, q_bool(&q, "force"), q_bool(&q, "v")).await?;
    Ok(no_content())
}

async fn container_prune(State(engine): S, Query(q): Q) -> ApiResult<Json<serde_json::Value>> {
    let f = filters(&q)?;
    let candidates: Vec<_> = engine
        .containers
        .read()
        .values()
        .filter(|c| !c.is_running() && c.record().state.status != "restarting")
        .filter(|c| f.labels_match("label", &c.record().config.labels))
        .cloned()
        .collect();
    let mut deleted = Vec::new();
    for c in candidates {
        let id = c.id();
        if super::containers::remove(&engine, &c, false, false)
            .await
            .is_ok()
        {
            deleted.push(id);
        }
    }
    Ok(Json(
        serde_json::json!({"ContainersDeleted": deleted, "SpaceReclaimed": 0}),
    ))
}

async fn container_attach(
    State(engine): S,
    Path(id): Path<String>,
    Query(q): Q,
    req: Request,
) -> ApiResult<Response> {
    let c = container(&engine, &id)?;
    let record = c.record();
    let tty = record.config.tty;
    let want_stdin = q_bool(&q, "stdin");
    let want_stdout = q_bool(&q, "stdout");
    let want_stderr = q_bool(&q, "stderr");
    let stream = q_bool(&q, "stream");
    let logs = q_bool(&q, "logs");
    // Subscribe before anything else so no output after this point is lost.
    let mut live = c.output.subscribe();
    let content_type = if tty {
        super::stream::RAW
    } else {
        super::stream::MULTIPLEXED
    };
    let (response, session) = super::stream::hijack(req, content_type);
    let eng = engine.clone();
    let c2 = c.clone();
    tokio::spawn(async move {
        let Some(session) = session.await else { return };
        let super::stream::Session { input, mut output } = session;
        let mut attrs = record.event_attributes();
        attrs.remove("__");
        eng.events
            .emit("container", "attach", &record.id, record.event_attributes());
        if let (true, Some(input)) = (want_stdin, input) {
            let c3 = c2.clone();
            let stdin_once = record.config.stdin_once;
            tokio::spawn(async move {
                super::stream::read_input(input, |data| {
                    super::containers::send_input(&c3, super::runtime::Input::Data(data))
                })
                .await;
                if stdin_once {
                    super::containers::send_input(&c3, super::runtime::Input::Eof);
                }
            });
        }
        let query = super::logs::LogQuery {
            stdout: want_stdout,
            stderr: want_stderr,
            ..Default::default()
        };
        if logs {
            let (entries, _) =
                super::logs::read(&super::logs::path(&eng.store, &record.id), &query);
            for e in entries {
                if !output.write(super::logs::encode(&e, &query, tty)).await {
                    return;
                }
            }
        }
        if !stream || (!c2.is_running() && c2.record().state.status != "created") {
            output.close().await;
            return;
        }
        loop {
            match live.recv().await {
                Ok(super::runtime::Output::Data(s, data)) => {
                    if (s == 1 && !want_stdout) || (s == 2 && !want_stderr) {
                        continue;
                    }
                    let bytes = if tty {
                        data.to_vec()
                    } else {
                        super::stream::frame(s, &data)
                    };
                    if !output.write(bytes).await {
                        return;
                    }
                }
                Ok(super::runtime::Output::End) => break,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            }
        }
        output.close().await;
    });
    Ok(response)
}

async fn container_resize(
    State(engine): S,
    Path(id): Path<String>,
    Query(q): Q,
) -> ApiResult<Response> {
    let c = container(&engine, &id)?;
    let h = q_i64(&q, "h").unwrap_or(24).clamp(1, 1000) as u16;
    let w = q_i64(&q, "w").unwrap_or(80).clamp(1, 1000) as u16;
    if !c.is_running() {
        return Err(ApiError::conflict(format!(
            "Container {} is not running",
            c.id()
        )));
    }
    super::containers::send_input(&c, super::runtime::Input::Resize { cols: w, rows: h });
    Ok(StatusCode::OK.into_response())
}

async fn container_logs(
    State(engine): S,
    Path(id): Path<String>,
    Query(q): Q,
) -> ApiResult<Response> {
    let c = container(&engine, &id)?;
    let record = c.record();
    let tty = record.config.tty;
    let mut query = super::logs::LogQuery {
        stdout: q_bool(&q, "stdout"),
        stderr: q_bool(&q, "stderr"),
        since: q
            .get("since")
            .and_then(|s| super::util::parse_time_filter(s))
            .filter(|t| *t > std::time::UNIX_EPOCH),
        until: q
            .get("until")
            .and_then(|s| super::util::parse_time_filter(s))
            .filter(|t| *t > std::time::UNIX_EPOCH),
        timestamps: q_bool(&q, "timestamps"),
        tail: q
            .get("tail")
            .filter(|t| t.as_str() != "all")
            .and_then(|t| t.parse().ok()),
    };
    if !query.stdout && !query.stderr {
        return Err(ApiError::bad_request("You must choose at least one stream"));
    }
    let follow = q_bool(&q, "follow");
    let path = super::logs::path(&engine.store, &record.id);
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(64);
    tokio::spawn(async move {
        let (entries, mut offset) = super::logs::read(&path, &query);
        for e in entries {
            if tx
                .send(Ok(Bytes::from(super::logs::encode(&e, &query, tty))))
                .await
                .is_err()
            {
                return;
            }
        }
        if !follow {
            return;
        }
        query.tail = None;
        loop {
            let notified = c.log_written.notified();
            let (entries, next) = super::logs::read_from(&path, offset, &query);
            offset = next;
            for e in entries {
                if tx
                    .send(Ok(Bytes::from(super::logs::encode(&e, &query, tty))))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            if !c.is_running() && c.record().state.status != "restarting" {
                // One last read for what the exit flushed.
                let (entries, _) = super::logs::read_from(&path, offset, &query);
                for e in entries {
                    let _ = tx
                        .send(Ok(Bytes::from(super::logs::encode(&e, &query, tty))))
                        .await;
                }
                return;
            }
            let _ = tokio::time::timeout(std::time::Duration::from_millis(500), notified).await;
            if tx.is_closed() {
                return;
            }
        }
    });
    let mut r = Response::new(Body::from_stream(
        tokio_stream::wrappers::ReceiverStream::new(rx),
    ));
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(if tty {
            super::stream::RAW
        } else {
            super::stream::MULTIPLEXED
        }),
    );
    Ok(r)
}

async fn container_top(
    State(engine): S,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let c = container(&engine, &id)?;
    let socket = c
        .socket()
        .ok_or_else(|| ApiError::conflict(format!("Container {} is not running", c.id())))?;
    let reply = super::runtime::request(
        &socket,
        &smolvm_protocol::AgentRequest::ContainerTop {
            overlay_id: super::containers::overlay_id(&c.record()),
        },
    )
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    match reply {
        smolvm_protocol::AgentResponse::Ok { data: Some(data) } => Ok(Json(serde_json::json!({
            "Titles": data["titles"],
            "Processes": data["processes"],
        }))),
        other => Err(ApiError::internal(
            super::runtime::error_text(&other).unwrap_or_else(|| "no process list".into()),
        )),
    }
}

async fn container_stats(
    State(engine): S,
    Path(id): Path<String>,
    Query(q): Q,
) -> ApiResult<Response> {
    let c = container(&engine, &id)?;
    let one_shot = q_bool(&q, "one-shot");
    let stream = !q.get("stream").is_some_and(|v| v == "0" || v == "false") && !one_shot;
    let (tx, body) = super::stream::json_lines();
    tokio::spawn(async move {
        let mut prev: Option<serde_json::Value> = None;
        // A single answer carries a second-old sample as its `precpu_stats`,
        // so clients can show a CPU rate from it, unless the client asked for
        // one sample only.
        if !stream && !one_shot && c.is_running() {
            prev = Some(stats_sample(&engine, &c).await);
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        loop {
            let sample = stats_sample(&engine, &c).await;
            let mut out = sample.clone();
            if let Some(p) = prev.take() {
                out["precpu_stats"] = p["cpu_stats"].clone();
                out["preread"] = p["read"].clone();
            }
            if tx.send(out).await.is_err() || !stream {
                return;
            }
            prev = Some(sample);
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    });
    Ok(Response::new(body))
}

async fn stats_sample(
    engine: &Arc<Engine>,
    c: &Arc<super::containers::Container>,
) -> serde_json::Value {
    let record = c.record();
    let ncpu = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1) as u64;
    let (cpu_ns, rss) = if c.is_running() && record.state.pid > 0 {
        crate::process::process_stats(record.state.pid as crate::process::Pid)
            .map(|s| (s.cpu_time_ns, s.rss_bytes))
            .unwrap_or((0, 0))
    } else {
        (0, 0)
    };
    let mut usage = rss;
    let mut limit = crate::process::host_memory_stats()
        .map(|m| m.total_bytes)
        .or_else(|| crate::data::resources::host_physical_memory_mib().map(|mib| mib << 20))
        .unwrap_or(0);
    if let Some(socket) = c.socket() {
        if let Ok(smolvm_protocol::AgentResponse::Ok { data: Some(d) }) =
            super::runtime::request(&socket, &smolvm_protocol::AgentRequest::MemoryStatus).await
        {
            if let Ok(m) = serde_json::from_value::<smolvm_protocol::MemoryStatus>(d) {
                usage = m.used_bytes();
                limit = m.total_bytes;
            }
        }
    }
    if record.host_config.memory > 0 {
        limit = record.host_config.memory as u64;
    }
    let system = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        * ncpu;
    let _ = engine;
    serde_json::json!({
        "read": super::util::now_rfc3339(),
        "preread": super::util::ZERO_TIME,
        "id": record.id,
        "name": format!("/{}", record.name),
        "num_procs": 0,
        "pids_stats": {"current": 0},
        "cpu_stats": {
            "cpu_usage": {"total_usage": cpu_ns, "usage_in_kernelmode": 0, "usage_in_usermode": cpu_ns},
            "system_cpu_usage": system,
            "online_cpus": ncpu,
            "throttling_data": {"periods": 0, "throttled_periods": 0, "throttled_time": 0},
        },
        "precpu_stats": {
            "cpu_usage": {"total_usage": 0, "usage_in_kernelmode": 0, "usage_in_usermode": 0},
            "system_cpu_usage": 0,
            "online_cpus": ncpu,
            "throttling_data": {"periods": 0, "throttled_periods": 0, "throttled_time": 0},
        },
        "memory_stats": {"usage": usage, "limit": limit, "stats": {"rss": rss}},
        "blkio_stats": {"io_service_bytes_recursive": null},
        "networks": {"eth0": {"rx_bytes": 0, "rx_packets": 0, "rx_errors": 0, "rx_dropped": 0, "tx_bytes": 0, "tx_packets": 0, "tx_errors": 0, "tx_dropped": 0}},
    })
}

async fn container_update(
    State(engine): S,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    let c = container(&engine, &id)?;
    #[derive(Deserialize, Default)]
    #[serde(rename_all = "PascalCase", default)]
    struct Update {
        restart_policy: Option<super::model::RestartPolicy>,
    }
    let update: Update = json_body(&body)?;
    let mut warnings = Vec::new();
    if let Some(policy) = update.restart_policy {
        c.update(&engine, |r| {
            r.host_config.restart_policy = policy.clone();
            if let Some(obj) = r.host_config_raw.as_object_mut() {
                obj.insert(
                    "RestartPolicy".into(),
                    serde_json::to_value(&policy).unwrap_or_default(),
                );
            }
        });
    } else {
        warnings.push("only the restart policy can change on a running container".to_string());
    }
    Ok(Json(serde_json::json!({"Warnings": warnings})))
}

async fn container_pause(State(engine): S, Path(id): Path<String>) -> ApiResult<Response> {
    let c = container(&engine, &id)?;
    super::containers::pause(&engine, &c, true).await?;
    Ok(no_content())
}

async fn container_unpause(State(engine): S, Path(id): Path<String>) -> ApiResult<Response> {
    let c = container(&engine, &id)?;
    super::containers::pause(&engine, &c, false).await?;
    Ok(no_content())
}

// ============================================================================
// Exec
// ============================================================================

async fn exec_create(State(engine): S, Path(id): Path<String>, body: Bytes) -> ApiResult<Response> {
    let c = container(&engine, &id)?;
    let req: super::model::ExecCreateRequest = json_body(&body)?;
    let exec_id = super::exec::create(&engine, &c, req)?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({"Id": exec_id})),
    )
        .into_response())
}

fn exec_of(engine: &Engine, id: &str) -> ApiResult<Arc<super::exec::Exec>> {
    engine
        .execs
        .lock()
        .get(id)
        .cloned()
        .ok_or_else(|| ApiError::not_found(format!("No such exec instance: {id}")))
}

async fn exec_start(State(engine): S, Path(id): Path<String>, req: Request) -> ApiResult<Response> {
    let exec = exec_of(&engine, &id)?;
    let (parts, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, 1 << 20)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    let start: super::model::ExecStartRequest = json_body(&bytes)?;
    let req = Request::from_parts(parts, Body::empty());
    super::exec::start(&engine, exec, start, req).await
}

async fn exec_resize(State(engine): S, Path(id): Path<String>, Query(q): Q) -> ApiResult<Response> {
    let exec = exec_of(&engine, &id)?;
    let h = q_i64(&q, "h").unwrap_or(24).clamp(1, 1000) as u16;
    let w = q_i64(&q, "w").unwrap_or(80).clamp(1, 1000) as u16;
    super::exec::resize(&exec, h, w);
    Ok(StatusCode::CREATED.into_response())
}

async fn exec_inspect(
    State(engine): S,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let exec = exec_of(&engine, &id)?;
    Ok(Json(super::exec::inspect(&exec)))
}

// ============================================================================
// Images
// ============================================================================

/// A JSON-lines response, as the image endpoints stream their progress.
fn json_stream(body: axum::body::Body) -> Response {
    let mut r = Response::new(body);
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    r
}

/// Every value a query parameter has (`changes` and `names` repeat).
fn q_all(pairs: &[(String, String)], key: &str) -> Vec<String> {
    pairs
        .iter()
        .filter(|(k, _)| k == key)
        .map(|(_, v)| v.clone())
        .collect()
}

async fn image_pull(
    State(engine): S,
    Query(pairs): Query<Vec<(String, String)>>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<Response> {
    let q: HashMap<String, String> = pairs.iter().cloned().collect();
    if let Some(src) = q.get("fromSrc").filter(|s| !s.is_empty()) {
        let (tx, out) = super::stream::json_lines();
        let src = src.clone();
        let changes = q_all(&pairs, "changes");
        tokio::spawn(async move {
            super::image_ops::import(
                &engine,
                &src,
                q.get("repo").map(String::as_str).unwrap_or(""),
                q.get("tag").map(String::as_str).unwrap_or(""),
                q.get("message").map(String::as_str).unwrap_or(""),
                &changes,
                q.get("platform")
                    .map(String::as_str)
                    .filter(|p| !p.is_empty()),
                body,
                tx,
            )
            .await;
        });
        return Ok(json_stream(out));
    }
    let from = q
        .get("fromImage")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::bad_request("fromImage or fromSrc is required"))?;
    let tag = q.get("tag").cloned().unwrap_or_default();
    let name = if tag.is_empty() {
        from.clone()
    } else if tag.starts_with("sha256:") {
        format!("{from}@{tag}")
    } else {
        format!("{from}:{tag}")
    };
    let reference = super::images::ImageRef::parse(&name).map_err(ApiError::bad_request)?;
    let platform = q.get("platform").cloned().filter(|p| !p.is_empty());
    let auth =
        super::images::pull_auth(headers.get("X-Registry-Auth").and_then(|h| h.to_str().ok()));
    // Resolve before answering, so a missing image is a 404 as clients expect.
    let meta = super::images::resolve(&reference, &auth, platform.as_deref()).await?;
    let (tx, body) = super::stream::json_lines();
    tokio::spawn(super::images::finish_pull(
        engine, reference, meta, auth, tx,
    ));
    let mut r = Response::new(body);
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok(r)
}

/// `GET /images/get?names=`: one archive of every named image.
async fn images_get(
    State(engine): S,
    Query(pairs): Query<Vec<(String, String)>>,
) -> ApiResult<Response> {
    super::image_ops::save(&engine, &q_all(&pairs, "names")).await
}

/// `POST /images/load`: the images of a `docker save` or OCI archive.
async fn image_load(State(engine): S, body: Body) -> ApiResult<Response> {
    let (tx, out) = super::stream::json_lines();
    tokio::spawn(async move { super::image_ops::load(&engine, body, tx).await });
    Ok(json_stream(out))
}

/// `POST /commit`: a new image from a container's changes.
async fn container_commit(
    State(engine): S,
    Query(pairs): Query<Vec<(String, String)>>,
    body: Bytes,
) -> ApiResult<Response> {
    let q: HashMap<String, String> = pairs.iter().cloned().collect();
    let container = q
        .get("container")
        .filter(|c| !c.is_empty())
        .ok_or_else(|| ApiError::bad_request("container is required"))?;
    let config = if body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&body).map_err(|e| ApiError::bad_request(e.to_string()))?
    };
    let req = super::image_ops::CommitRequest {
        repo: q.get("repo").cloned().unwrap_or_default(),
        tag: q.get("tag").cloned().unwrap_or_default(),
        comment: q.get("comment").cloned().unwrap_or_default(),
        author: q.get("author").cloned().unwrap_or_default(),
        changes: q_all(&pairs, "changes"),
        config,
    };
    let image = super::image_ops::commit(&engine, container, req).await?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "Id": image.id })),
    )
        .into_response())
}

async fn image_list(State(engine): S, Query(q): Q) -> ApiResult<Json<Vec<serde_json::Value>>> {
    let f = filters(&q)?;
    let all_containers: Vec<_> = engine
        .containers
        .read()
        .values()
        .map(|c| c.record())
        .collect();
    let mut images = engine.images.all();
    images.sort_by_key(|i| std::cmp::Reverse(i.created()));
    Ok(Json(
        images
            .iter()
            .filter(|i| super::images::matches(i, &f))
            .filter(|i| q_bool(&q, "all") || !i.repo_tags.is_empty() || f.has("dangling"))
            .map(|i| {
                let n = all_containers.iter().filter(|c| c.image_id == i.id).count() as i64;
                i.summary(n)
            })
            .collect(),
    ))
}

async fn image_dispatch(
    State(engine): S,
    Path(rest): Path<String>,
    method: Method,
    Query(q): Q,
    headers: HeaderMap,
) -> ApiResult<Response> {
    if method == Method::GET {
        if let Some(name) = rest.strip_suffix("/json") {
            let img = engine
                .images
                .resolve(name)
                .ok_or_else(|| ApiError::not_found(format!("No such image: {name}")))?;
            return Ok(Json(img.inspect()).into_response());
        }
        if let Some(name) = rest.strip_suffix("/history") {
            let img = engine
                .images
                .resolve(name)
                .ok_or_else(|| ApiError::not_found(format!("No such image: {name}")))?;
            return Ok(Json(img.history()).into_response());
        }
        if let Some(name) = rest.strip_suffix("/get") {
            return super::image_ops::save(&engine, &[name.to_string()]).await;
        }
    }
    if method == Method::POST {
        if let Some(name) = rest.strip_suffix("/tag") {
            let repo = q
                .get("repo")
                .ok_or_else(|| ApiError::bad_request("repo is required"))?;
            engine.images.tag(
                &engine.store,
                name,
                repo,
                q.get("tag").map(String::as_str).unwrap_or(""),
            )?;
            let img = engine.images.resolve(name);
            engine.events.emit(
                "image",
                "tag",
                &img.map(|i| i.id).unwrap_or_default(),
                BTreeMap::from([(
                    "name".to_string(),
                    format!(
                        "{repo}:{}",
                        q.get("tag").map(String::as_str).unwrap_or("latest")
                    ),
                )]),
            );
            return Ok(StatusCode::CREATED.into_response());
        }
        if let Some(name) = rest.strip_suffix("/push") {
            let auth = super::images::pull_auth(
                headers.get("X-Registry-Auth").and_then(|h| h.to_str().ok()),
            );
            let (tx, out) = super::stream::json_lines();
            let (name, tag) = (name.to_string(), q.get("tag").cloned().unwrap_or_default());
            tokio::spawn(async move {
                super::image_ops::push(&engine, &name, &tag, auth, tx).await;
            });
            return Ok(json_stream(out));
        }
    }
    if method == Method::DELETE {
        let containers: Vec<_> = engine
            .containers
            .read()
            .values()
            .map(|c| c.record())
            .collect();
        let out = engine
            .images
            .remove(&engine.store, &rest, q_bool(&q, "force"), |id| {
                containers
                    .iter()
                    .find(|c| c.image_id == id)
                    .map(|c| c.id.clone())
            })?;
        for item in &out {
            if let Some(id) = item.get("Deleted").and_then(|v| v.as_str()) {
                engine.events.emit("image", "delete", id, BTreeMap::new());
            } else if let Some(tag) = item.get("Untagged").and_then(|v| v.as_str()) {
                engine.events.emit(
                    "image",
                    "untag",
                    tag,
                    BTreeMap::from([("name".to_string(), tag.to_string())]),
                );
            }
        }
        return Ok(Json(out).into_response());
    }
    Err(ApiError::not_found("page not found"))
}

async fn image_prune(State(engine): S, Query(q): Q) -> ApiResult<Json<serde_json::Value>> {
    let f = filters(&q)?;
    let dangling_only = !f.get("dangling").iter().any(|v| v == "false" || v == "0");
    let used: std::collections::HashSet<String> = engine
        .containers
        .read()
        .values()
        .map(|c| c.record().image_id)
        .collect();
    let mut deleted = Vec::new();
    for img in engine.images.all() {
        if used.contains(&img.id) || (dangling_only && !img.repo_tags.is_empty()) {
            continue;
        }
        if !f.labels_match("label", &img.labels()) {
            continue;
        }
        if let Ok(out) = engine.images.remove(&engine.store, &img.id, true, |_| None) {
            deleted.extend(out);
        }
    }
    Ok(Json(
        serde_json::json!({"ImagesDeleted": deleted, "SpaceReclaimed": 0}),
    ))
}

// ============================================================================
// Volumes
// ============================================================================

async fn volume_list(State(engine): S, Query(q): Q) -> ApiResult<Json<serde_json::Value>> {
    let f = filters(&q)?;
    let volumes: Vec<serde_json::Value> = engine
        .volumes
        .all()
        .iter()
        .filter(|v| {
            super::volumes::matches(v, &f, super::containers::volume_in_use(&engine, &v.name))
        })
        .map(|v| engine.volumes.inspect(v))
        .collect();
    Ok(Json(
        serde_json::json!({"Volumes": volumes, "Warnings": []}),
    ))
}

async fn volume_create(State(engine): S, body: Bytes) -> ApiResult<Response> {
    let req: super::model::VolumeCreateRequest = json_body(&body)?;
    if !req.driver.is_empty() && req.driver != "local" {
        return Err(ApiError::bad_request(format!(
            "volume driver \"{}\" is not supported (local is)",
            req.driver
        )));
    }
    let (v, created) = engine.volumes.create(
        &engine.store,
        Some(req.name.as_str()),
        req.labels,
        req.driver_opts,
        false,
    )?;
    if created {
        engine.events.emit(
            "volume",
            "create",
            &v.name,
            BTreeMap::from([("driver".to_string(), "local".to_string())]),
        );
    }
    Ok((StatusCode::CREATED, Json(engine.volumes.inspect(&v))).into_response())
}

async fn volume_inspect(
    State(engine): S,
    Path(name): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let v = engine
        .volumes
        .get(&name)
        .ok_or_else(|| ApiError::not_found(format!("get {name}: no such volume")))?;
    Ok(Json(engine.volumes.inspect(&v)))
}

async fn volume_remove(
    State(engine): S,
    Path(name): Path<String>,
    Query(q): Q,
) -> ApiResult<Response> {
    if engine.volumes.get(&name).is_none() {
        if q_bool(&q, "force") {
            return Ok(no_content());
        }
        return Err(ApiError::not_found(format!("get {name}: no such volume")));
    }
    if super::containers::volume_in_use(&engine, &name) {
        return Err(ApiError::conflict(format!(
            "remove {name}: volume is in use"
        )));
    }
    engine.volumes.remove(&engine.store, &name)?;
    engine
        .events
        .emit("volume", "destroy", &name, BTreeMap::new());
    Ok(no_content())
}

async fn volume_prune(State(engine): S, Query(q): Q) -> ApiResult<Json<serde_json::Value>> {
    let f = filters(&q)?;
    let all = f.get("all").iter().any(|v| v == "true" || v == "1");
    let mut deleted = Vec::new();
    for v in engine.volumes.all() {
        if super::containers::volume_in_use(&engine, &v.name) {
            continue;
        }
        if !all && !v.anonymous {
            continue;
        }
        if !f.labels_match("label", &v.labels) {
            continue;
        }
        if engine.volumes.remove(&engine.store, &v.name).is_ok() {
            engine
                .events
                .emit("volume", "destroy", &v.name, BTreeMap::new());
            deleted.push(v.name);
        }
    }
    Ok(Json(
        serde_json::json!({"VolumesDeleted": deleted, "SpaceReclaimed": 0}),
    ))
}
