//! Reserve a reviewed workload without pausing it or creating a remote copy.

use super::*;
use crate::db::transfer_admission::preparation::{Phase, Preparation};
use axum::extract::Path as ApiPath;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::engine) struct PrepareRequest {
    operation: String,
    containers: Vec<String>,
    fingerprint: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::engine) struct PreparationStatus {
    operation: String,
    phase: Phase,
    fingerprint: String,
    containers: Vec<String>,
}

fn selection(record: &Preparation) -> ApiResult<Vec<String>> {
    if record.inventory["version"] != 3 {
        return Err(ApiError::conflict(
            "unsupported workload preparation inventory",
        ));
    }
    let selected = record.inventory["selected"]
        .as_array()
        .ok_or_else(|| ApiError::conflict("invalid workload preparation selection"))?;
    selected
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|id| super::super::store::valid_id(id))
                .map(str::to_owned)
                .ok_or_else(|| ApiError::conflict("invalid workload preparation container"))
        })
        .collect()
}

fn response(record: Preparation) -> ApiResult<PreparationStatus> {
    let containers = selection(&record)?;
    Ok(PreparationStatus {
        operation: record.operation,
        phase: record.phase,
        fingerprint: record.fingerprint,
        containers,
    })
}

pub(in crate::engine) async fn prepare(
    State(engine): State<Arc<Engine>>,
    Json(request): Json<PrepareRequest>,
) -> ApiResult<Json<PreparationStatus>> {
    tokio::task::spawn_blocking(move || {
        prepare_with_review(&engine, request, |engine, selected| {
            review_with_inventory(engine, selected, live_shares)
        })
        .and_then(response)
    })
    .await
    .map_err(|error| ApiError::internal(error.to_string()))?
    .map(Json)
}

fn checked(review: &Review, request: &PrepareRequest) -> ApiResult<()> {
    if review.plan.selected != request.containers || review.plan.fingerprint != request.fingerprint
    {
        return Err(ApiError::conflict(
            "workload changed after review; review it again",
        ));
    }
    if !review.plan.additional_containers.is_empty() {
        return Err(ApiError::conflict(
            "select every dependent container before preparing the move",
        ));
    }
    if !review.plan.blockers.is_empty() {
        return Err(ApiError::conflict(
            "resolve the workload's transfer blockers before preparing it",
        ));
    }
    if review.claims.len() != review.plan.machines.len() || review.claims.is_empty() {
        return Err(ApiError::conflict(
            "workload machine records are incomplete",
        ));
    }
    Ok(())
}

fn prepare_with_review(
    engine: &Engine,
    mut request: PrepareRequest,
    mut review: impl FnMut(&Engine, &[String]) -> ApiResult<Review>,
) -> ApiResult<Preparation> {
    request.containers.sort();
    if request.containers.is_empty()
        || request.containers.len() > 1024
        || request
            .containers
            .iter()
            .any(|id| !super::super::store::valid_id(id))
        || request.containers.windows(2).any(|pair| pair[0] == pair[1])
        || !request
            .fingerprint
            .strip_prefix("sha256:")
            .is_some_and(super::super::store::valid_id)
    {
        return Err(ApiError::bad_request(
            "prepare the complete container IDs and fingerprint returned by review",
        ));
    }
    // Status/retry uses the same durable operation, never a fresh anonymous
    // claim. A cancelled operation cannot be reused for a later execution.
    let existing = engine
        .db
        .workload_preparation(&request.operation)
        .map_err(ApiError::mutation)?;
    let reserved = if let Some(existing) = existing {
        if existing.phase == Phase::Cancelled
            || existing.fingerprint != request.fingerprint
            || selection(&existing)? != request.containers
        {
            return Err(ApiError::conflict(
                "this preparation belongs to a different or cancelled review",
            ));
        }
        existing
    } else {
        let reviewed = review(engine, &request.containers)?;
        checked(&reviewed, &request)?;
        engine
            .db
            .reserve_workload_preparation(
                Preparation {
                    version: 1,
                    operation: request.operation.clone(),
                    phase: Phase::Reserved,
                    fingerprint: request.fingerprint.clone(),
                    inventory: reviewed.inventory,
                },
                reviewed.claims,
                &reviewed.roots,
            )
            .map_err(ApiError::mutation)?
    };
    // A metadata mutation may have completed between the first inventory and
    // admission. Re-read after every normal writer is excluded. This still
    // does not freeze guest/device I/O or grant capture authority.
    let rechecked =
        review(engine, &request.containers).and_then(|review| checked(&review, &request));
    if let Err(error) = rechecked {
        engine.db.cancel_workload_preparation(&request.operation).map_err(|_| {
            ApiError::conflict("preparation could not be released; inspect or cancel this operation before retrying")
        })?;
        return Err(error);
    }
    engine
        .db
        .confirm_workload_preparation(&reserved)
        .map_err(ApiError::mutation)
}

pub(in crate::engine) async fn status(
    State(engine): State<Arc<Engine>>,
    ApiPath(operation): ApiPath<String>,
) -> ApiResult<Json<PreparationStatus>> {
    tokio::task::spawn_blocking(move || {
        let record = engine
            .db
            .workload_preparation(&operation)
            .map_err(ApiError::mutation)?
            .ok_or_else(|| ApiError::not_found("No such workload preparation"))?;
        response(record)
    })
    .await
    .map_err(|error| ApiError::internal(error.to_string()))?
    .map(Json)
}

pub(in crate::engine) async fn cancel(
    State(engine): State<Arc<Engine>>,
    ApiPath(operation): ApiPath<String>,
) -> ApiResult<Json<PreparationStatus>> {
    tokio::task::spawn_blocking(move || {
        engine
            .db
            .cancel_workload_preparation(&operation)
            .map_err(ApiError::mutation)
            .and_then(response)
    })
    .await
    .map_err(|error| ApiError::internal(error.to_string()))?
    .map(Json)
}

#[cfg(test)]
mod tests;
