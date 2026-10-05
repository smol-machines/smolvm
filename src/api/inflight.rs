//! Accounting of the API requests a serve process is working on.
//!
//! A worker roll restarts `serve` while machines keep running, and a restart cuts
//! off whatever request was being served: a long `exec` loses its result even
//! though the command ran. The operator therefore needs to see, without touching
//! the API, whether anything is in flight and how long it has been running, so the
//! restart can wait for a quiet moment while serve keeps serving normally. This
//! module counts every request on the main API router from the moment it arrives
//! until its response body has been sent in full (an SSE `exec/stream` counts
//! until the command exits), and reports the totals on the loopback
//! `GET /inflight` route.
//!
//! Open-ended streams (a followed log, an interactive terminal) are reported apart
//! from the rest: they end only when their client leaves, so a roll cannot wait
//! for them.

use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Instant;

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, Uri};
use axum::middleware::Next;
use axum::response::Response;
use axum::Json;
use serde::Serialize;

/// What a request is, as far as waiting for it goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    /// A command running in a machine (`exec`, `exec/stream`, `run`).
    Exec,
    /// Any other request with a definite end.
    Request,
    /// A stream that ends only when its client disconnects.
    OpenStream,
}

/// Requests being served right now.
#[derive(Debug, Default)]
pub struct InFlight {
    next_id: AtomicU64,
    live: parking_lot::Mutex<BTreeMap<u64, (Instant, RequestKind)>>,
}

/// Keeps one request counted until it is dropped.
#[derive(Debug)]
pub struct InFlightGuard {
    tracker: Arc<InFlight>,
    id: u64,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.tracker.live.lock().remove(&self.id);
    }
}

/// Totals reported by `GET /inflight`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InFlightSnapshot {
    /// Requests a restart now would cut off, open-ended streams excluded.
    pub in_flight: usize,
    /// How many of `in_flight` are commands running in a machine.
    pub execs: usize,
    /// Followed logs and interactive terminals; they end only when their client
    /// leaves, so they are not part of `in_flight`.
    pub open_streams: usize,
    /// Age in milliseconds of the oldest request counted in `in_flight`, 0 when
    /// there is none. A roll that recorded when it began waiting knows every
    /// request older than that has finished once this is below its own wait.
    pub oldest_ms: u64,
}

impl InFlight {
    /// Count a request from now until the returned guard is dropped.
    pub fn begin(self: &Arc<Self>, kind: RequestKind) -> InFlightGuard {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.live.lock().insert(id, (Instant::now(), kind));
        InFlightGuard {
            tracker: Arc::clone(self),
            id,
        }
    }

    /// Current totals.
    pub fn snapshot(&self) -> InFlightSnapshot {
        let now = Instant::now();
        let live = self.live.lock();
        let mut snapshot = InFlightSnapshot {
            in_flight: 0,
            execs: 0,
            open_streams: 0,
            oldest_ms: 0,
        };
        let mut oldest: Option<Instant> = None;
        for (started, kind) in live.values() {
            match kind {
                RequestKind::OpenStream => {
                    snapshot.open_streams += 1;
                    continue;
                }
                RequestKind::Exec => snapshot.execs += 1,
                RequestKind::Request => {}
            }
            snapshot.in_flight += 1;
            if oldest.is_none_or(|o| *started < o) {
                oldest = Some(*started);
            }
        }
        if let Some(started) = oldest {
            snapshot.oldest_ms = now.saturating_duration_since(started).as_millis() as u64;
        }
        snapshot
    }
}

/// The tracker for this process's main API router.
pub fn global() -> Arc<InFlight> {
    static GLOBAL: OnceLock<Arc<InFlight>> = OnceLock::new();
    Arc::clone(GLOBAL.get_or_init(|| Arc::new(InFlight::default())))
}

/// Decide how a request is counted from its path, query and headers.
pub fn classify(uri: &Uri, headers: &HeaderMap) -> RequestKind {
    if headers.contains_key(header::UPGRADE) {
        return RequestKind::OpenStream;
    }
    let path = uri.path();
    if let Some(rest) = path.strip_prefix("/api/v1/machines/") {
        if rest.ends_with("/exec/interactive") {
            return RequestKind::OpenStream;
        }
        if rest.ends_with("/logs") && query_flag(uri.query(), "follow") {
            return RequestKind::OpenStream;
        }
        if rest.ends_with("/exec") || rest.ends_with("/exec/stream") || rest.ends_with("/run") {
            return RequestKind::Exec;
        }
    }
    RequestKind::Request
}

fn query_flag(query: Option<&str>, name: &str) -> bool {
    query
        .unwrap_or_default()
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .any(|(key, value)| key == name && (value == "true" || value == "1"))
}

/// Middleware that counts each request until its response body has been sent.
pub async fn track(State(tracker): State<Arc<InFlight>>, request: Request, next: Next) -> Response {
    let guard = tracker.begin(classify(request.uri(), request.headers()));
    let response = next.run(request).await;
    response.map(|body| {
        Body::new(GuardedBody {
            inner: body,
            _guard: guard,
        })
    })
}

/// A response body that keeps its request counted until it ends or is dropped.
struct GuardedBody {
    inner: Body,
    _guard: InFlightGuard,
}

impl http_body::Body for GuardedBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, axum::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

/// `GET /inflight` on the loopback door: what a restart now would cut off.
pub async fn inflight_status() -> Json<InFlightSnapshot> {
    Json(global().snapshot())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, post};
    use axum::Router;
    use std::time::Duration;
    use tower::ServiceExt;

    fn uri(s: &str) -> Uri {
        s.parse().unwrap()
    }

    #[test]
    fn classifies_execs_streams_and_the_rest() {
        let none = HeaderMap::new();
        for path in [
            "/api/v1/machines/m1/exec",
            "/api/v1/machines/m1/exec/stream",
            "/api/v1/machines/m1/run",
        ] {
            assert_eq!(classify(&uri(path), &none), RequestKind::Exec, "{path}");
        }
        for path in [
            "/api/v1/machines/m1/logs?follow=true",
            "/api/v1/machines/m1/logs?tail=10&follow=1",
            "/api/v1/machines/m1/exec/interactive?cmd=sh",
        ] {
            assert_eq!(
                classify(&uri(path), &none),
                RequestKind::OpenStream,
                "{path}"
            );
        }
        for path in [
            "/api/v1/machines/m1/logs",
            "/api/v1/machines/m1/logs?follow=false",
            "/api/v1/machines/m1/start",
            "/api/v1/machines/m1/checkpoint",
            "/health",
            "/exec",
        ] {
            assert_eq!(classify(&uri(path), &none), RequestKind::Request, "{path}");
        }
        let mut upgrade = HeaderMap::new();
        upgrade.insert(header::UPGRADE, "websocket".parse().unwrap());
        assert_eq!(
            classify(&uri("/anything"), &upgrade),
            RequestKind::OpenStream
        );
    }

    #[test]
    fn snapshot_counts_kinds_and_ages_the_oldest() {
        let tracker = Arc::new(InFlight::default());
        assert_eq!(
            tracker.snapshot(),
            InFlightSnapshot {
                in_flight: 0,
                execs: 0,
                open_streams: 0,
                oldest_ms: 0
            }
        );
        let stream = tracker.begin(RequestKind::OpenStream);
        std::thread::sleep(Duration::from_millis(30));
        let exec = tracker.begin(RequestKind::Exec);
        std::thread::sleep(Duration::from_millis(30));
        let request = tracker.begin(RequestKind::Request);
        let s = tracker.snapshot();
        assert_eq!((s.in_flight, s.execs, s.open_streams), (2, 1, 1));
        // The open stream is older, but it is not what a restart waits for.
        assert!(s.oldest_ms >= 30 && s.oldest_ms < 60_000, "{s:?}");
        drop(exec);
        let s = tracker.snapshot();
        assert_eq!((s.in_flight, s.execs), (1, 0));
        assert!(s.oldest_ms < 30, "{s:?}");
        drop(request);
        drop(stream);
        assert_eq!(
            tracker.snapshot().in_flight + tracker.snapshot().open_streams,
            0
        );
    }

    // A request stays counted while its handler runs and while its streamed body
    // is still being sent, and stops counting once the body has been read.
    #[tokio::test]
    async fn middleware_counts_until_the_body_is_done() {
        let tracker = Arc::new(InFlight::default());
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let release_rx = Arc::new(parking_lot::Mutex::new(Some(release_rx)));
        let app = Router::new()
            .route(
                "/api/v1/machines/m1/exec/stream",
                post(move || {
                    let release_rx = release_rx.lock().take().unwrap();
                    async move {
                        let stream = futures_util::stream::once(async move {
                            let _ = release_rx.await;
                            Ok::<_, std::io::Error>(Bytes::from_static(b"event: exit\n\n"))
                        });
                        Body::from_stream(stream)
                    }
                }),
            )
            .route("/health", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(tracker.clone(), track));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/machines/m1/exec/stream")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Headers are out, the command has not finished: still in flight.
        let s = tracker.snapshot();
        assert_eq!((s.in_flight, s.execs), (1, 1), "{s:?}");

        let short = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let _ = axum::body::to_bytes(short.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(tracker.snapshot().in_flight, 1);

        release_tx.send(()).unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"event: exit\n\n");
        assert_eq!(tracker.snapshot().in_flight, 0);
    }
}
