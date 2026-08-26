//! Private descriptor transport between smolvm and a managed rollout sidecar.
//!
//! The public rollout API never exposes CUDA allocation descriptors. It
//! redeems a one-use clone publication itself, then transfers the descriptor
//! to the executor's registered Unix socket. The sidecar acknowledges load and
//! unload so the executor can keep the corresponding policy lifetime tracked.

use crate::api::rollout::RolloutError;
use crate::cuda_daemon::RedeemedTensorBundle;
use serde::Deserialize;
use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

const REQUEST_MAGIC: [u8; 8] = *b"SMVDLH01";
const RESPONSE_MAGIC: [u8; 8] = *b"SMVDHR01";
const HEADER_BYTES: usize = 32;
const RESPONSE_HEADER_BYTES: usize = 16;
const OP_HEALTH: u8 = 0;
const OP_LOAD: u8 = 1;
const OP_UNLOAD: u8 = 2;
const MAX_MODEL_BYTES: usize = 512;
const MAX_METADATA_BYTES: usize = (2 << 20) + 64;
const MAX_RESPONSE_BYTES: usize = 1 << 20;
const MANIFEST_SCHEMA: &str = "smolvm.device-lora.v1";
const MAX_TENSOR_NAME_BYTES: usize = 1024;
const MAX_TENSOR_RANK: usize = 16;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeviceAdapterManifest {
    schema: String,
    adapter_config: serde_json::Value,
    tensors: Vec<DeviceAdapterTensor>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeviceAdapterTensor {
    name: String,
    shape: Vec<u64>,
    dtype: String,
}

#[derive(Clone, Debug)]
pub(crate) struct DeviceHandoffClient {
    path: PathBuf,
    timeout: Duration,
}

impl DeviceHandoffClient {
    pub(crate) fn new(path: &Path, timeout: Duration) -> Result<Self, RolloutError> {
        if !path.is_absolute() {
            return Err(RolloutError::BadRequest(
                "deviceAdapterSocket must be an absolute Unix-socket path".into(),
            ));
        }
        let path = path.canonicalize().map_err(|error| {
            RolloutError::BadRequest(format!("canonicalize deviceAdapterSocket: {error}"))
        })?;
        validate_socket_node(&path)?;
        Ok(Self { path, timeout })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) async fn health(&self) -> Result<(), RolloutError> {
        let path = self.path.clone();
        let timeout = self.timeout.min(Duration::from_secs(10));
        tokio::task::spawn_blocking(move || transact(&path, timeout, OP_HEALTH, "", None))
            .await
            .map_err(|error| {
                RolloutError::Backend(format!("device handoff task failed: {error}"))
            })??;
        Ok(())
    }

    pub(crate) async fn load(
        &self,
        model: &str,
        bundle: RedeemedTensorBundle,
    ) -> Result<(), RolloutError> {
        validate_bundle_metadata(&bundle.metadata, bundle.allocation_size)?;
        validate_model_name(model)?;
        let path = self.path.clone();
        let timeout = self.timeout;
        let model = model.to_string();
        tokio::task::spawn_blocking(move || {
            transact(&path, timeout, OP_LOAD, &model, Some(bundle))
        })
        .await
        .map_err(|error| RolloutError::Backend(format!("device handoff task failed: {error}")))??;
        Ok(())
    }

    pub(crate) async fn unload(&self, model: &str) -> Result<(), RolloutError> {
        validate_model_name(model)?;
        let path = self.path.clone();
        let timeout = self.timeout;
        let model = model.to_string();
        tokio::task::spawn_blocking(move || transact(&path, timeout, OP_UNLOAD, &model, None))
            .await
            .map_err(|error| {
                RolloutError::Backend(format!("device handoff task failed: {error}"))
            })??;
        Ok(())
    }
}

fn validate_socket_node(path: &Path) -> Result<(), RolloutError> {
    let metadata = path.metadata().map_err(|error| {
        RolloutError::BadRequest(format!("inspect deviceAdapterSocket: {error}"))
    })?;
    if !metadata.file_type().is_socket() {
        return Err(RolloutError::BadRequest(
            "deviceAdapterSocket must resolve to a Unix socket".into(),
        ));
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(RolloutError::BadRequest(
            "deviceAdapterSocket must be owned by the smolvm user".into(),
        ));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(RolloutError::BadRequest(
            "deviceAdapterSocket must not grant group or other permissions".into(),
        ));
    }
    Ok(())
}

fn validate_model_name(model: &str) -> Result<(), RolloutError> {
    if model.is_empty() || model.len() > MAX_MODEL_BYTES || model.as_bytes().contains(&0) {
        return Err(RolloutError::BadRequest(
            "invalid device adapter model name".into(),
        ));
    }
    Ok(())
}

fn tensor_dtype_size(dtype: &str) -> Option<u64> {
    match dtype {
        "bool" | "int8" | "uint8" | "float8_e4m3fn" | "float8_e5m2" => Some(1),
        "int16" | "float16" | "bfloat16" => Some(2),
        "int32" | "float32" => Some(4),
        "int64" | "float64" => Some(8),
        _ => None,
    }
}

fn validate_bundle_metadata(metadata: &[u8], allocation_size: u64) -> Result<(), RolloutError> {
    if metadata.len() < 8 || metadata.len() > MAX_METADATA_BYTES {
        return Err(RolloutError::BadRequest(
            "invalid device adapter metadata length".into(),
        ));
    }
    let manifest_len = u32::from_le_bytes(metadata[0..4].try_into().unwrap()) as usize;
    let tensor_count = u32::from_le_bytes(metadata[4..8].try_into().unwrap()) as usize;
    let ranges_offset = 8usize.checked_add(manifest_len).ok_or_else(|| {
        RolloutError::BadRequest("device adapter metadata length overflow".into())
    })?;
    let expected = ranges_offset
        .checked_add(tensor_count.checked_mul(16).ok_or_else(|| {
            RolloutError::BadRequest("device adapter tensor count overflow".into())
        })?)
        .ok_or_else(|| RolloutError::BadRequest("device adapter metadata overflow".into()))?;
    if tensor_count == 0 || expected != metadata.len() {
        return Err(RolloutError::BadRequest(
            "inconsistent device adapter metadata".into(),
        ));
    }
    let manifest: DeviceAdapterManifest = serde_json::from_slice(&metadata[8..ranges_offset])
        .map_err(|error| {
            RolloutError::BadRequest(format!("decode device adapter manifest: {error}"))
        })?;
    if manifest.schema != MANIFEST_SCHEMA {
        return Err(RolloutError::BadRequest(format!(
            "unsupported device adapter schema '{}'",
            manifest.schema
        )));
    }
    if !manifest.adapter_config.is_object() {
        return Err(RolloutError::BadRequest(
            "device adapter config must be a JSON object".into(),
        ));
    }
    if manifest.tensors.len() != tensor_count {
        return Err(RolloutError::BadRequest(
            "device adapter manifest tensor count mismatch".into(),
        ));
    }
    let mut names = HashSet::with_capacity(tensor_count);
    let mut prior_end = 0u64;
    for (tensor, range) in manifest
        .tensors
        .iter()
        .zip(metadata[ranges_offset..].as_chunks::<16>().0.iter())
    {
        if tensor.name.is_empty()
            || tensor.name.len() > MAX_TENSOR_NAME_BYTES
            || tensor.name.as_bytes().contains(&0)
            || !names.insert(&tensor.name)
        {
            return Err(RolloutError::BadRequest(
                "device adapter tensor names must be unique, non-empty, and bounded".into(),
            ));
        }
        if tensor.shape.len() > MAX_TENSOR_RANK || tensor.shape.contains(&0) {
            return Err(RolloutError::BadRequest(
                "invalid device adapter tensor shape".into(),
            ));
        }
        let element_size = tensor_dtype_size(&tensor.dtype).ok_or_else(|| {
            RolloutError::BadRequest(format!(
                "unsupported device adapter dtype '{}'",
                tensor.dtype
            ))
        })?;
        let expected_size = tensor
            .shape
            .iter()
            .try_fold(element_size, |size, dimension| size.checked_mul(*dimension))
            .ok_or_else(|| {
                RolloutError::BadRequest("device adapter tensor size overflow".into())
            })?;
        let offset = u64::from_le_bytes(range[0..8].try_into().unwrap());
        let size = u64::from_le_bytes(range[8..16].try_into().unwrap());
        let end = offset.checked_add(size).ok_or_else(|| {
            RolloutError::BadRequest("device adapter tensor range overflow".into())
        })?;
        if offset != prior_end || size != expected_size || end > allocation_size {
            return Err(RolloutError::BadRequest(
                "device adapter tensor shape does not match its exported range".into(),
            ));
        }
        prior_end = end;
    }
    Ok(())
}

fn transact(
    path: &Path,
    timeout: Duration,
    operation: u8,
    model: &str,
    bundle: Option<RedeemedTensorBundle>,
) -> Result<(), RolloutError> {
    validate_socket_node(path)?;
    let mut stream = UnixStream::connect(path).map_err(|error| {
        RolloutError::Unavailable(format!("connect device adapter sidecar: {error}"))
    })?;
    stream.set_read_timeout(Some(timeout)).map_err(sidecar_io)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(sidecar_io)?;
    validate_peer(&stream)?;

    let metadata_len = bundle.as_ref().map_or(0, |value| value.metadata.len());
    let allocation_size = bundle.as_ref().map_or(0, |value| value.allocation_size);
    let mut header = [0u8; HEADER_BYTES];
    header[..8].copy_from_slice(&REQUEST_MAGIC);
    header[8] = operation;
    header[12..16].copy_from_slice(&(model.len() as u32).to_le_bytes());
    header[16..20].copy_from_slice(&(metadata_len as u32).to_le_bytes());
    header[20..28].copy_from_slice(&allocation_size.to_le_bytes());
    if let Some(bundle) = bundle.as_ref() {
        send_header_with_fd(&mut stream, &header, bundle.allocation.as_raw_fd())?;
    } else {
        stream.write_all(&header).map_err(sidecar_io)?;
    }
    stream.write_all(model.as_bytes()).map_err(sidecar_io)?;
    if let Some(bundle) = bundle.as_ref() {
        stream.write_all(&bundle.metadata).map_err(sidecar_io)?;
    }

    let mut response = [0u8; RESPONSE_HEADER_BYTES];
    stream.read_exact(&mut response).map_err(sidecar_io)?;
    if response[..8] != RESPONSE_MAGIC {
        return Err(RolloutError::Backend(
            "invalid device adapter sidecar response".into(),
        ));
    }
    let status = i32::from_le_bytes(response[8..12].try_into().unwrap());
    let message_len = u32::from_le_bytes(response[12..16].try_into().unwrap()) as usize;
    if message_len > MAX_RESPONSE_BYTES {
        return Err(RolloutError::Backend(
            "device adapter sidecar response is too large".into(),
        ));
    }
    let mut message = vec![0u8; message_len];
    stream.read_exact(&mut message).map_err(sidecar_io)?;
    if status != 0 {
        return Err(RolloutError::Backend(format!(
            "device adapter sidecar rejected request ({status}): {}",
            String::from_utf8_lossy(&message)
        )));
    }
    Ok(())
}

fn sidecar_io(error: io::Error) -> RolloutError {
    if matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        RolloutError::Timeout("device adapter sidecar request timed out".into())
    } else {
        RolloutError::Unavailable(format!("device adapter sidecar I/O failed: {error}"))
    }
}

fn send_header_with_fd(
    stream: &mut UnixStream,
    header: &[u8; HEADER_BYTES],
    fd: RawFd,
) -> Result<(), RolloutError> {
    let mut iov = libc::iovec {
        iov_base: header.as_ptr() as *mut libc::c_void,
        iov_len: header.len(),
    };
    let sent = unsafe {
        let mut control = [0u8; 32];
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = libc::CMSG_SPACE(4) as _;
        let cmsg = libc::CMSG_FIRSTHDR(&message);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(4) as _;
        std::ptr::copy_nonoverlapping((&fd as *const RawFd).cast::<u8>(), libc::CMSG_DATA(cmsg), 4);
        libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL)
    };
    if sent < 0 {
        return Err(sidecar_io(io::Error::last_os_error()));
    }
    let sent = sent as usize;
    if sent < header.len() {
        stream.write_all(&header[sent..]).map_err(sidecar_io)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_peer(stream: &UnixStream) -> Result<(), RolloutError> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if rc != 0 {
        return Err(sidecar_io(io::Error::last_os_error()));
    }
    if credentials.uid != unsafe { libc::geteuid() } {
        return Err(RolloutError::Unavailable(
            "device adapter sidecar peer has a different user identity".into(),
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn validate_peer(_stream: &UnixStream) -> Result<(), RolloutError> {
    Err(RolloutError::Unavailable(
        "device-resident rollout handoff requires Linux".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    fn metadata(manifest: serde_json::Value, ranges: &[(u64, u64)]) -> Vec<u8> {
        let manifest = serde_json::to_vec(&manifest).unwrap();
        let mut metadata = Vec::new();
        metadata.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
        metadata.extend_from_slice(&(ranges.len() as u32).to_le_bytes());
        metadata.extend_from_slice(&manifest);
        for (offset, size) in ranges {
            metadata.extend_from_slice(&offset.to_le_bytes());
            metadata.extend_from_slice(&size.to_le_bytes());
        }
        metadata
    }

    fn receive_request(
        mut stream: UnixStream,
    ) -> (u8, String, Vec<u8>, Option<OwnedFd>, UnixStream) {
        let mut header = [0u8; HEADER_BYTES];
        let mut iov = libc::iovec {
            iov_base: header.as_mut_ptr().cast(),
            iov_len: header.len(),
        };
        let (received, fd) = unsafe {
            let mut control = [0u8; 32];
            let mut message: libc::msghdr = std::mem::zeroed();
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = libc::CMSG_SPACE(4) as _;
            let received = libc::recvmsg(stream.as_raw_fd(), &mut message, 0);
            assert!(received > 0);
            let cmsg = libc::CMSG_FIRSTHDR(&message);
            if cmsg.is_null() {
                (received as usize, None)
            } else {
                assert_eq!((*cmsg).cmsg_level, libc::SOL_SOCKET);
                assert_eq!((*cmsg).cmsg_type, libc::SCM_RIGHTS);
                let mut fd = -1;
                std::ptr::copy_nonoverlapping(
                    libc::CMSG_DATA(cmsg),
                    (&mut fd as *mut RawFd).cast(),
                    4,
                );
                (received as usize, Some(OwnedFd::from_raw_fd(fd)))
            }
        };
        if received < header.len() {
            stream.read_exact(&mut header[received..]).unwrap();
        }
        assert_eq!(header[..8], REQUEST_MAGIC);
        let operation = header[8];
        let model_len = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;
        let metadata_len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
        let mut model = vec![0u8; model_len];
        stream.read_exact(&mut model).unwrap();
        let mut metadata = vec![0u8; metadata_len];
        stream.read_exact(&mut metadata).unwrap();
        (
            operation,
            String::from_utf8(model).unwrap(),
            metadata,
            fd,
            stream,
        )
    }

    fn acknowledge(mut stream: UnixStream) {
        let mut response = [0u8; RESPONSE_HEADER_BYTES];
        response[..8].copy_from_slice(&RESPONSE_MAGIC);
        stream.write_all(&response).unwrap();
    }

    #[test]
    fn manifest_shape_and_exported_ranges_must_agree() {
        let manifest = serde_json::json!({
            "schema": MANIFEST_SCHEMA,
            "adapterConfig": {},
            "tensors": [
                {"name": "q_proj.lora_A.weight", "shape": [2, 4], "dtype": "float16"},
                {"name": "q_proj.lora_B.weight", "shape": [4, 2], "dtype": "float16"}
            ]
        });
        let valid = metadata(manifest.clone(), &[(0, 16), (16, 16)]);
        validate_bundle_metadata(&valid, 64).unwrap();

        let wrong_size = metadata(manifest.clone(), &[(0, 8), (8, 16)]);
        assert!(validate_bundle_metadata(&wrong_size, 64).is_err());
        let duplicate = serde_json::json!({
            "schema": MANIFEST_SCHEMA,
            "adapterConfig": {},
            "tensors": [
                {"name": "same", "shape": [2, 4], "dtype": "float16"},
                {"name": "same", "shape": [4, 2], "dtype": "float16"}
            ]
        });
        assert!(validate_bundle_metadata(&metadata(duplicate, &[(0, 16), (16, 16)]), 64).is_err());
    }

    #[tokio::test]
    async fn descriptor_owner_survives_load_until_unload_acknowledgement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("device-adapter.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let server = std::thread::spawn(move || {
            let (health, _) = listener.accept().unwrap();
            let (operation, model, metadata, fd, health) = receive_request(health);
            assert_eq!(operation, OP_HEALTH);
            assert!(model.is_empty());
            assert!(metadata.is_empty());
            assert!(fd.is_none());
            acknowledge(health);

            let (load, _) = listener.accept().unwrap();
            let (operation, model, metadata, retained, load) = receive_request(load);
            assert_eq!(operation, OP_LOAD);
            assert_eq!(model, "executor-policy-step");
            assert!(!metadata.is_empty());
            let retained = retained.unwrap();
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            assert_eq!(unsafe { libc::fstat(retained.as_raw_fd(), &mut stat) }, 0);
            acknowledge(load);

            let (unload, _) = listener.accept().unwrap();
            let (operation, model, metadata, fd, unload) = receive_request(unload);
            assert_eq!(operation, OP_UNLOAD);
            assert_eq!(model, "executor-policy-step");
            assert!(metadata.is_empty());
            assert!(fd.is_none());
            assert_eq!(unsafe { libc::fstat(retained.as_raw_fd(), &mut stat) }, 0);
            drop(retained);
            acknowledge(unload);
        });

        let client = DeviceHandoffClient::new(&path, Duration::from_secs(2)).unwrap();
        client.health().await.unwrap();
        let manifest = serde_json::json!({
            "schema": MANIFEST_SCHEMA,
            "adapterConfig": {},
            "tensors": [
                {"name": "q_proj.lora_A.weight", "shape": [2, 4], "dtype": "float16"}
            ]
        });
        let allocation: OwnedFd = tempfile::tempfile().unwrap().into();
        let bundle = RedeemedTensorBundle {
            allocation,
            allocation_size: 64,
            metadata: metadata(manifest, &[(0, 16)]),
        };
        client.load("executor-policy-step", bundle).await.unwrap();
        client.unload("executor-policy-step").await.unwrap();
        server.join().unwrap();
    }
}
