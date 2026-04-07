//! Image management handlers.

use axum::{
    extract::{Path, State},
    Json,
};
use std::sync::Arc;

use crate::api::error::{classify_ensure_running_error, ApiError};
use crate::api::state::{ensure_running_and_persist, with_machine_client, ApiState};
use crate::api::types::{
    ApiErrorResponse, ImageInfo, ListImagesResponse, PullImageRequest, PullImageResponse,
};
use crate::internal::agent::PullOptions;

/// List images in a machine.
#[utoipa::path(
    get,
    path = "/api/v1/machines/{id}/images",
    tag = "Images",
    params(
        ("id" = String, Path, description = "Machine name")
    ),
    responses(
        (status = 200, description = "List of images", body = ListImagesResponse),
        (status = 404, description = "Machine not found", body = ApiErrorResponse)
    )
)]
pub async fn list_images(
    State(state): State<Arc<ApiState>>,
    Path(machine_id): Path<String>,
) -> Result<Json<ListImagesResponse>, ApiError> {
    let entry = state.get_machine(&machine_id)?;

    // Check if machine VM is actually alive, return empty list if not
    {
        let entry = entry.lock();
        if !entry.manager.is_process_alive() {
            return Ok(Json(ListImagesResponse { images: Vec::new() }));
        }
    }

    let images = with_machine_client(&entry, |c| c.list_images()).await?;

    let images = images
        .into_iter()
        .map(|i| ImageInfo {
            reference: i.reference,
            digest: i.digest,
            size: i.size,
            architecture: i.architecture,
            os: i.os,
            layer_count: i.layer_count,
        })
        .collect();

    Ok(Json(ListImagesResponse { images }))
}

/// Pull an image into a machine.
#[utoipa::path(
    post,
    path = "/api/v1/machines/{id}/images/pull",
    tag = "Images",
    params(
        ("id" = String, Path, description = "Machine name")
    ),
    request_body = PullImageRequest,
    responses(
        (status = 200, description = "Image pulled", body = PullImageResponse),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 404, description = "Machine not found", body = ApiErrorResponse),
        (status = 500, description = "Failed to pull image", body = ApiErrorResponse)
    )
)]
pub async fn pull_image(
    State(state): State<Arc<ApiState>>,
    Path(machine_id): Path<String>,
    Json(req): Json<PullImageRequest>,
) -> Result<Json<PullImageResponse>, ApiError> {
    if req.image.is_empty() {
        return Err(ApiError::BadRequest(
            "image reference cannot be empty".into(),
        ));
    }

    let entry = state.get_machine(&machine_id)?;

    // Ensure machine is running and persist state to DB
    ensure_running_and_persist(&state, &machine_id, &entry)
        .await
        .map_err(classify_ensure_running_error)?;

    let image = req.image.clone();
    let oci_platform = req.oci_platform.clone();
    let image_info = with_machine_client(&entry, move |c| {
        let mut opts = PullOptions::new().use_registry_config(true);
        if let Some(p) = oci_platform {
            opts = opts.oci_platform(p);
        }
        c.pull(&image, opts)
    })
    .await?;

    Ok(Json(PullImageResponse {
        image: ImageInfo {
            reference: image_info.reference,
            digest: image_info.digest,
            size: image_info.size,
            architecture: image_info.architecture,
            os: image_info.os,
            layer_count: image_info.layer_count,
        },
    }))
}
