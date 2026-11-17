//! An inactivity timeout for requests whose work scales with their data.
//!
//! A fixed deadline is wrong for these: a 32 GB cache disk publish needs far
//! longer than a small one, and a total timeout either cuts the large one off
//! mid-upload or leaves a stuck one running for as long as the largest could
//! take. Instead the work touches a [`Progress`] each time it moves data, and
//! [`idle_timeout`] gives up only once nothing has moved for [`IDLE_TIMEOUT`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use super::error::ApiError;

/// How long a request may go without progress before it is abandoned.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// When a request's work last moved data. Cloned freely; every clone shares
/// the same clock. One nothing observes costs only its touches.
#[derive(Clone, Debug)]
pub struct Progress(Arc<AtomicU64>);

impl Default for Progress {
    fn default() -> Self {
        let progress = Self(Arc::new(AtomicU64::new(0)));
        progress.touch();
        progress
    }
}

impl Progress {
    /// Record that the work moved data just now.
    pub fn touch(&self) {
        self.0.store(since_start(), Ordering::Relaxed);
    }

    /// How long ago the work last moved data.
    pub fn idle(&self) -> Duration {
        Duration::from_millis(since_start().saturating_sub(self.0.load(Ordering::Relaxed)))
    }
}

/// Milliseconds since a fixed process-wide instant: a monotonic clock that
/// fits an atomic.
fn since_start() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// Run the request with a [`Progress`] in its extensions, and answer `408`
/// once its work has gone [`IDLE_TIMEOUT`] without touching it. Dropping the
/// handler cancels its work, as a total timeout would.
pub async fn idle_timeout(request: Request, next: Next) -> Response {
    run_until_idle(request, next, IDLE_TIMEOUT).await
}

async fn run_until_idle(mut request: Request, next: Next, limit: Duration) -> Response {
    let progress = Progress::default();
    request.extensions_mut().insert(progress.clone());
    let work = next.run(request);
    tokio::pin!(work);
    loop {
        let wait = limit.saturating_sub(progress.idle());
        tokio::select! {
            response = &mut work => return response,
            _ = tokio::time::sleep(wait) => {
                if progress.idle() >= limit {
                    tracing::warn!(idle_secs = limit.as_secs(), "request made no progress; giving up");
                    return ApiError::Timeout.into_response();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::routing::get;
    use axum::{Extension, Router};
    use tower::ServiceExt;

    const LIMIT: Duration = Duration::from_millis(200);

    fn router() -> Router {
        Router::new()
            .route(
                "/steady",
                // Runs well past the limit, but never idle that long.
                get(|Extension(progress): Extension<Progress>| async move {
                    for _ in 0..10 {
                        tokio::time::sleep(LIMIT / 4).await;
                        progress.touch();
                    }
                    "done"
                }),
            )
            .route(
                "/stuck",
                get(|| async {
                    tokio::time::sleep(LIMIT * 10).await;
                    "never"
                }),
            )
            .layer(axum::middleware::from_fn(|request, next| {
                run_until_idle(request, next, LIMIT)
            }))
    }

    async fn status(path: &str) -> StatusCode {
        router()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn work_that_keeps_moving_outlasts_the_limit() {
        assert_eq!(status("/steady").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn work_that_stops_moving_times_out() {
        let started = Instant::now();
        assert_eq!(status("/stuck").await, StatusCode::REQUEST_TIMEOUT);
        assert!(started.elapsed() < LIMIT * 5);
    }

    #[test]
    fn a_touch_resets_the_idle_clock() {
        let progress = Progress::default();
        std::thread::sleep(Duration::from_millis(30));
        assert!(progress.idle() >= Duration::from_millis(30));
        progress.touch();
        assert!(progress.idle() < Duration::from_millis(30));
    }
}
