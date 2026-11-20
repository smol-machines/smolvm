//! Private app discovery and TCP upgrades, scoped to a running container.
//! This is a Smol extension on the existing Docker socket, not another server.
use super::{
    containers::{Container, ContainerRecord},
    util::{ApiError, ApiResult},
    Engine,
};
use axum::{
    extract::{Path, Query, Request, State},
    http::{header, StatusCode},
    response::Response,
    Json,
};
use serde::{Deserialize, Serialize};
use smolvm_protocol::{AgentRequest, AgentResponse};
use std::{sync::Arc, time::Duration};
use tokio::io::AsyncWriteExt;

#[derive(Serialize)]
pub(super) struct Ports {
    id: String,
    started_at: String,
    ports: Vec<u16>,
    listener_notifications: bool,
}
#[derive(Deserialize)]
pub(super) struct Generation {
    started_at: String,
}

fn running(engine: &Engine, id: &str) -> ApiResult<Arc<Container>> {
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::bad_request(
            "Use the full container ID for app access.",
        ));
    }
    let container = engine
        .find_container(id)
        .ok_or_else(|| ApiError::no_such_container(id))?;
    if container.id() != id || container.record().state.status != "running" {
        return Err(ApiError::conflict(
            "Start the container before opening its app.",
        ));
    }
    Ok(container)
}
fn same_run(container: &Container, before: &ContainerRecord) -> ApiResult<()> {
    let after = container.record();
    if after.state.status != "running"
        || after.state.started_at != before.state.started_at
        || after.state.pid != before.state.pid
        || after.agent_socket != before.agent_socket
    {
        return Err(ApiError::conflict(
            "The container changed while opening its app.",
        ));
    }
    Ok(())
}
fn socket(record: &ContainerRecord) -> ApiResult<&std::path::Path> {
    record
        .agent_socket
        .as_deref()
        .ok_or_else(|| ApiError::conflict("The container's agent is not ready."))
}
fn guest_error(response: AgentResponse) -> ApiError {
    match response {
        AgentResponse::Error { message, code }
            if code.as_deref() == Some(smolvm_protocol::error_codes::INVALID_REQUEST) =>
        {
            ApiError::not_implemented(format!(
                "Restart this container with an updated guest for private app access: {message}"
            ))
        }
        AgentResponse::Error { message, .. } => ApiError::new(StatusCode::BAD_GATEWAY, message),
        _ => ApiError::new(
            StatusCode::BAD_GATEWAY,
            "The guest did not confirm app access.",
        ),
    }
}

pub(super) async fn list(
    State(engine): State<Arc<Engine>>,
    Path(id): Path<String>,
) -> ApiResult<Json<Ports>> {
    let container = running(&engine, &id)?;
    let _operation = container.op_lock().await;
    let record = container.record();
    same_run(&container, &record)?;
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        super::runtime::request(
            socket(&record)?,
            &AgentRequest::ContainerPorts {
                overlay_id: super::containers::overlay_id(&record),
            },
        ),
    )
    .await
    .map_err(|_| ApiError::new(StatusCode::GATEWAY_TIMEOUT, "App discovery timed out."))?
    .map_err(|e| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("App discovery failed: {e}"),
        )
    })?;
    let (ports, listener_notifications) = match response {
        AgentResponse::Ok { data: Some(data) } => {
            let ports: Vec<u16> = serde_json::from_value(data["ports"].clone())
                .map_err(|_| ApiError::internal("The guest returned invalid app ports."))?;
            if ports.len() > 4096 || ports.contains(&0) || ports.windows(2).any(|w| w[0] >= w[1]) {
                return Err(ApiError::internal("The guest returned invalid app ports."));
            }
            (
                ports,
                data["listener_notifications"].as_bool().unwrap_or(false),
            )
        }
        other => return Err(guest_error(other)),
    };
    same_run(&container, &record)?;
    Ok(Json(Ports {
        id,
        started_at: record.state.started_at,
        ports,
        listener_notifications,
    }))
}

pub(super) async fn connect(
    State(engine): State<Arc<Engine>>,
    Path((id, port)): Path<(String, u16)>,
    Query(generation): Query<Generation>,
    request: Request,
) -> ApiResult<Response> {
    if port == 0 || generation.started_at.is_empty() || generation.started_at.len() > 64 {
        return Err(ApiError::bad_request(
            "Supply an app port and the current container start identity.",
        ));
    }
    if !super::stream::wants_upgrade(&request)
        || request
            .headers()
            .get(header::UPGRADE)
            .and_then(|v| v.to_str().ok())
            != Some("tcp")
    {
        return Err(ApiError::bad_request(
            "App connections require a TCP upgrade.",
        ));
    }
    let container = running(&engine, &id)?;
    let operation = container.op_lock().await;
    let record = container.record();
    same_run(&container, &record)?;
    if record.state.started_at != generation.started_at {
        return Err(ApiError::conflict(
            "This app address refers to an earlier container run.",
        ));
    }
    let mut exits = container.subscribe_exits();
    let sequence = exits.borrow_and_update().exits;
    let mut guest = tokio::time::timeout(
        Duration::from_secs(5),
        super::runtime::app_connect(
            socket(&record)?,
            &super::containers::overlay_id(&record),
            port,
        ),
    )
    .await
    .map_err(|_| ApiError::new(StatusCode::GATEWAY_TIMEOUT, "App connection timed out."))??;
    same_run(&container, &record)?;
    if exits.borrow().exits != sequence || exits.borrow().removed {
        return Err(ApiError::conflict(
            "The container stopped while opening its app.",
        ));
    }
    let (response, session) = super::stream::hijack(request, super::stream::RAW);
    drop(operation);
    tokio::spawn(async move {
        let relay = async {
            let Ok(Some(session)) = tokio::time::timeout(Duration::from_secs(5), session).await
            else {
                return;
            };
            let _activity = session._activity;
            let Some(mut input) = session.input else {
                return;
            };
            let super::stream::Sink::Raw(mut output, peer) = session.output else {
                return;
            };
            let (mut read, mut write) = guest.split();
            let (half_closed, eof) = tokio::sync::oneshot::channel();
            let copy = async {
                tokio::try_join!(
                    async {
                        tokio::io::copy(&mut input, &mut write).await?;
                        let _ = half_closed.send(());
                        write.shutdown().await
                    },
                    async {
                        tokio::io::copy(&mut read, &mut output).await?;
                        output.shutdown().await
                    },
                )
            };
            let disconnected = async {
                // An idle open app must not poll the client every 100 ms.
                // Inspect full-close only after read EOF, which can also be
                // an intentional half-close while the app still sends data.
                let _ = eof.await;
                if let Some(peer) = peer {
                    peer.closed().await;
                } else {
                    std::future::pending::<()>().await;
                }
            };
            tokio::select! { _ = copy => {}, _ = disconnected => {} }
        };
        tokio::select! { biased; _ = exits.changed() => {}, _ = relay => {} }
    });
    Ok(response)
}

pub(super) fn confirmed(response: AgentResponse) -> ApiResult<()> {
    match response {
        AgentResponse::Ok { data: Some(data) }
            if data["protocol"].as_str() == Some("smol-app-tcp-v1") =>
        {
            Ok(())
        }
        other => Err(guest_error(other)),
    }
}

#[cfg(test)]
mod tests;

mod watch;
pub(super) use watch::{subscribe, Watch};
