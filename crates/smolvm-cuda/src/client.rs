//! Guest-side CUDA-RPC client: marshal `cu*` calls over a byte stream.
//!
//! Transport-agnostic — it takes any [`Read`]/[`Write`], so the guest binary
//! supplies an `AF_VSOCK` stream while tests supply an in-memory pipe. Each
//! method does one request→response round-trip and surfaces a non-zero
//! `CUresult` as [`CudaRpcError::Cuda`].

use crate::proto::{decode_response, encode_request, read_msg, write_msg, Op, Request, Response};
use std::io::{self, Read, Write};

/// A client-side failure: transport error, a CUDA error code from the host, or
/// a protocol mismatch (host returned the wrong response shape).
#[derive(Debug)]
pub enum CudaRpcError {
    Io(io::Error),
    /// Non-zero `CUresult` returned by the host driver.
    Cuda(i32),
    Protocol(&'static str),
}

impl std::fmt::Display for CudaRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CudaRpcError::Io(e) => write!(f, "cuda-rpc io: {e}"),
            CudaRpcError::Cuda(c) => write!(f, "CUDA error {c}"),
            CudaRpcError::Protocol(m) => write!(f, "cuda-rpc protocol: {m}"),
        }
    }
}
impl std::error::Error for CudaRpcError {}
impl From<io::Error> for CudaRpcError {
    fn from(e: io::Error) -> Self {
        CudaRpcError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, CudaRpcError>;

/// A CUDA Driver-API client over one connection to the host server.
pub struct Client<S> {
    stream: S,
}

impl<S: Read + Write> Client<S> {
    pub fn new(stream: S) -> Self {
        Client { stream }
    }

    fn call(&mut self, req: &Request, op: Op) -> Result<Response> {
        write_msg(&mut self.stream, &encode_request(req))?;
        let payload =
            read_msg(&mut self.stream)?.ok_or(CudaRpcError::Protocol("host closed mid-call"))?;
        let (status, resp) = decode_response(op, &payload)?;
        if status != 0 {
            return Err(CudaRpcError::Cuda(status));
        }
        Ok(resp)
    }

    pub fn init(&mut self) -> Result<()> {
        self.call(&Request::Init, Op::Init).map(|_| ())
    }

    pub fn device_get_count(&mut self) -> Result<i32> {
        match self.call(&Request::DeviceGetCount, Op::DeviceGetCount)? {
            Response::Count(n) => Ok(n),
            _ => Err(CudaRpcError::Protocol("expected Count")),
        }
    }

    pub fn device_get_name(&mut self, device: i32) -> Result<String> {
        match self.call(&Request::DeviceGetName { device }, Op::DeviceGetName)? {
            Response::Name(s) => Ok(s),
            _ => Err(CudaRpcError::Protocol("expected Name")),
        }
    }

    pub fn device_total_mem(&mut self, device: i32) -> Result<u64> {
        match self.call(&Request::DeviceTotalMem { device }, Op::DeviceTotalMem)? {
            Response::Bytes(v) => Ok(v),
            _ => Err(CudaRpcError::Protocol("expected Bytes")),
        }
    }

    pub fn ctx_create(&mut self, device: i32) -> Result<u64> {
        match self.call(&Request::CtxCreate { device }, Op::CtxCreate)? {
            Response::Handle(h) => Ok(h),
            _ => Err(CudaRpcError::Protocol("expected Handle")),
        }
    }

    pub fn ctx_destroy(&mut self, ctx: u64) -> Result<()> {
        self.call(&Request::CtxDestroy { ctx }, Op::CtxDestroy)
            .map(|_| ())
    }

    pub fn module_load_data(&mut self, image: &[u8]) -> Result<u64> {
        match self.call(
            &Request::ModuleLoadData {
                image: image.to_vec(),
            },
            Op::ModuleLoadData,
        )? {
            Response::Handle(h) => Ok(h),
            _ => Err(CudaRpcError::Protocol("expected Handle")),
        }
    }

    pub fn module_get_function(&mut self, module: u64, name: &str) -> Result<u64> {
        match self.call(
            &Request::ModuleGetFunction {
                module,
                name: name.to_string(),
            },
            Op::ModuleGetFunction,
        )? {
            Response::Handle(h) => Ok(h),
            _ => Err(CudaRpcError::Protocol("expected Handle")),
        }
    }

    pub fn mem_alloc(&mut self, bytes: u64) -> Result<u64> {
        match self.call(&Request::MemAlloc { bytes }, Op::MemAlloc)? {
            Response::Dptr(d) => Ok(d),
            _ => Err(CudaRpcError::Protocol("expected Dptr")),
        }
    }

    pub fn mem_free(&mut self, dptr: u64) -> Result<()> {
        self.call(&Request::MemFree { dptr }, Op::MemFree)
            .map(|_| ())
    }

    pub fn memcpy_htod(&mut self, dptr: u64, data: &[u8]) -> Result<()> {
        self.call(
            &Request::MemcpyHtoD {
                dptr,
                data: data.to_vec(),
            },
            Op::MemcpyHtoD,
        )
        .map(|_| ())
    }

    pub fn memcpy_dtoh(&mut self, dptr: u64, bytes: u64) -> Result<Vec<u8>> {
        match self.call(&Request::MemcpyDtoH { dptr, bytes }, Op::MemcpyDtoH)? {
            Response::Data(d) => Ok(d),
            _ => Err(CudaRpcError::Protocol("expected Data")),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn launch_kernel(
        &mut self,
        function: u64,
        grid: [u32; 3],
        block: [u32; 3],
        shared_bytes: u32,
        stream: u64,
        params: &[Vec<u8>],
    ) -> Result<()> {
        self.call(
            &Request::LaunchKernel {
                function,
                grid,
                block,
                shared_bytes,
                stream,
                params: params.to_vec(),
            },
            Op::LaunchKernel,
        )
        .map(|_| ())
    }

    pub fn ctx_synchronize(&mut self) -> Result<()> {
        self.call(&Request::CtxSynchronize, Op::CtxSynchronize)
            .map(|_| ())
    }

    pub fn driver_get_version(&mut self) -> Result<i32> {
        match self.call(&Request::DriverGetVersion, Op::DriverGetVersion)? {
            Response::Count(v) => Ok(v),
            _ => Err(CudaRpcError::Protocol("expected Count")),
        }
    }

    pub fn device_get_attribute(&mut self, attrib: i32, device: i32) -> Result<i32> {
        match self.call(
            &Request::DeviceGetAttribute { attrib, device },
            Op::DeviceGetAttribute,
        )? {
            Response::Count(v) => Ok(v),
            _ => Err(CudaRpcError::Protocol("expected Count")),
        }
    }

    pub fn device_get_uuid(&mut self, device: i32) -> Result<[u8; 16]> {
        match self.call(&Request::DeviceGetUuid { device }, Op::DeviceGetUuid)? {
            Response::Data(d) if d.len() == 16 => {
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(&d);
                Ok(uuid)
            }
            _ => Err(CudaRpcError::Protocol("expected 16-byte Data")),
        }
    }

    pub fn primary_ctx_retain(&mut self, device: i32) -> Result<u64> {
        match self.call(&Request::PrimaryCtxRetain { device }, Op::PrimaryCtxRetain)? {
            Response::Handle(h) => Ok(h),
            _ => Err(CudaRpcError::Protocol("expected Handle")),
        }
    }

    pub fn primary_ctx_release(&mut self, device: i32) -> Result<()> {
        self.call(
            &Request::PrimaryCtxRelease { device },
            Op::PrimaryCtxRelease,
        )
        .map(|_| ())
    }

    pub fn module_unload(&mut self, module: u64) -> Result<()> {
        self.call(&Request::ModuleUnload { module }, Op::ModuleUnload)
            .map(|_| ())
    }

    /// Per-parameter byte sizes of the kernel's arguments, in declaration order.
    pub fn func_get_param_info(&mut self, function: u64) -> Result<Vec<u32>> {
        match self.call(
            &Request::FuncGetParamInfo { function },
            Op::FuncGetParamInfo,
        )? {
            Response::Data(d) if d.len() % 4 == 0 => Ok(d
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                .collect()),
            _ => Err(CudaRpcError::Protocol("expected u32-array Data")),
        }
    }

    pub fn memcpy_dtod(&mut self, dst: u64, src: u64, bytes: u64) -> Result<()> {
        self.call(&Request::MemcpyDtoD { dst, src, bytes }, Op::MemcpyDtoD)
            .map(|_| ())
    }

    pub fn memset_d8(&mut self, dptr: u64, value: u8, bytes: u64) -> Result<()> {
        self.call(&Request::MemsetD8 { dptr, value, bytes }, Op::MemsetD8)
            .map(|_| ())
    }

    /// Returns `(free, total)` device memory in bytes.
    pub fn mem_get_info(&mut self) -> Result<(u64, u64)> {
        match self.call(&Request::MemGetInfo, Op::MemGetInfo)? {
            Response::Pair(free, total) => Ok((free, total)),
            _ => Err(CudaRpcError::Protocol("expected Pair")),
        }
    }

    pub fn stream_create(&mut self, flags: u32) -> Result<u64> {
        match self.call(&Request::StreamCreate { flags }, Op::StreamCreate)? {
            Response::Handle(h) => Ok(h),
            _ => Err(CudaRpcError::Protocol("expected Handle")),
        }
    }

    pub fn stream_destroy(&mut self, stream: u64) -> Result<()> {
        self.call(&Request::StreamDestroy { stream }, Op::StreamDestroy)
            .map(|_| ())
    }

    pub fn stream_synchronize(&mut self, stream: u64) -> Result<()> {
        self.call(
            &Request::StreamSynchronize { stream },
            Op::StreamSynchronize,
        )
        .map(|_| ())
    }

    pub fn event_create(&mut self, flags: u32) -> Result<u64> {
        match self.call(&Request::EventCreate { flags }, Op::EventCreate)? {
            Response::Handle(h) => Ok(h),
            _ => Err(CudaRpcError::Protocol("expected Handle")),
        }
    }

    pub fn event_destroy(&mut self, event: u64) -> Result<()> {
        self.call(&Request::EventDestroy { event }, Op::EventDestroy)
            .map(|_| ())
    }

    pub fn event_record(&mut self, event: u64, stream: u64) -> Result<()> {
        self.call(&Request::EventRecord { event, stream }, Op::EventRecord)
            .map(|_| ())
    }

    pub fn event_synchronize(&mut self, event: u64) -> Result<()> {
        self.call(&Request::EventSynchronize { event }, Op::EventSynchronize)
            .map(|_| ())
    }

    pub fn event_elapsed_time(&mut self, start: u64, end: u64) -> Result<f32> {
        match self.call(
            &Request::EventElapsedTime { start, end },
            Op::EventElapsedTime,
        )? {
            Response::Millis(ms) => Ok(ms),
            _ => Err(CudaRpcError::Protocol("expected Millis")),
        }
    }

    /// `(nvcomp_status, temp_bytes)` — nvcomp status is the library's own code.
    pub fn nvcomp_deflate_temp_size(
        &mut self,
        num_chunks: u64,
        max_uncompressed_chunk_bytes: u64,
        max_total_uncompressed_bytes: u64,
    ) -> Result<(i32, u64)> {
        match self.call(
            &Request::NvcompDeflateTempSize {
                num_chunks,
                max_uncompressed_chunk_bytes,
                max_total_uncompressed_bytes,
            },
            Op::NvcompDeflateTempSize,
        )? {
            Response::Pair(st, tb) => Ok((st as i32, tb)),
            _ => Err(CudaRpcError::Protocol("expected Pair")),
        }
    }

    /// Returns the nvcomp status code.
    #[allow(clippy::too_many_arguments)]
    pub fn nvcomp_deflate_decompress(
        &mut self,
        device_compressed_ptrs: u64,
        device_compressed_bytes: u64,
        device_uncompressed_bytes: u64,
        device_actual_uncompressed_bytes: u64,
        batch_size: u64,
        device_temp: u64,
        temp_bytes: u64,
        device_uncompressed_ptrs: u64,
        device_statuses: u64,
        stream: u64,
    ) -> Result<i32> {
        match self.call(
            &Request::NvcompDeflateDecompress {
                device_compressed_ptrs,
                device_compressed_bytes,
                device_uncompressed_bytes,
                device_actual_uncompressed_bytes,
                batch_size,
                device_temp,
                temp_bytes,
                device_uncompressed_ptrs,
                device_statuses,
                stream,
            },
            Op::NvcompDeflateDecompress,
        )? {
            Response::Count(st) => Ok(st),
            _ => Err(CudaRpcError::Protocol("expected Count")),
        }
    }

    pub fn cublas_create(&mut self) -> Result<u64> {
        match self.call(&Request::CublasCreate, Op::CublasCreate)? {
            Response::Handle(h) => Ok(h),
            _ => Err(CudaRpcError::Protocol("expected Handle")),
        }
    }

    pub fn cublas_destroy(&mut self, handle: u64) -> Result<()> {
        self.call(&Request::CublasDestroy { handle }, Op::CublasDestroy)
            .map(|_| ())
    }

    pub fn cublas_set_stream(&mut self, handle: u64, stream: u64) -> Result<()> {
        self.call(
            &Request::CublasSetStream { handle, stream },
            Op::CublasSetStream,
        )
        .map(|_| ())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn cublas_sgemm(
        &mut self,
        handle: u64,
        transa: u32,
        transb: u32,
        m: i32,
        n: i32,
        k: i32,
        alpha: f32,
        a: u64,
        lda: i32,
        b: u64,
        ldb: i32,
        beta: f32,
        c: u64,
        ldc: i32,
    ) -> Result<()> {
        self.call(
            &Request::CublasSgemm {
                handle,
                transa,
                transb,
                m,
                n,
                k,
                alpha_bits: alpha.to_bits(),
                a,
                lda,
                b,
                ldb,
                beta_bits: beta.to_bits(),
                c,
                ldc,
            },
            Op::CublasSgemm,
        )
        .map(|_| ())
    }

    /// Generic forward-to-host-lib call. Returns `(library_status, outputs)`.
    pub fn lib_call(&mut self, lib: u8, func: u16, args: Vec<u8>) -> Result<(i32, Vec<u8>)> {
        match self.call(&Request::LibCall { lib, func, args }, Op::LibCall)? {
            Response::LibResult(status, out) => Ok((status, out)),
            _ => Err(CudaRpcError::Protocol("expected LibResult")),
        }
    }

    /// Zero-copy H2D via the shared region (data already written at `offset`).
    pub fn memcpy_shm_htod(&mut self, dptr: u64, offset: u64, size: u64) -> Result<()> {
        self.call(
            &Request::MemcpyShmHtoD { dptr, offset, size },
            Op::MemcpyShmHtoD,
        )
        .map(|_| ())
    }

    /// Zero-copy D2H via the shared region (host writes into `offset`).
    pub fn memcpy_shm_dtoh(&mut self, offset: u64, dptr: u64, size: u64) -> Result<()> {
        self.call(
            &Request::MemcpyShmDtoH { offset, dptr, size },
            Op::MemcpyShmDtoH,
        )
        .map(|_| ())
    }

    /// Zero-copy H2D from guest RAM: the host gathers `segments` (guest-physical)
    /// and DMAs to `dptr`.
    pub fn memcpy_gpa_htod(&mut self, dptr: u64, segments: Vec<(u64, u64)>) -> Result<()> {
        self.call(
            &Request::MemcpyGpaHtoD { dptr, segments },
            Op::MemcpyGpaHtoD,
        )
        .map(|_| ())
    }

    /// Zero-copy D2H to guest RAM: the host DMAs from `dptr` and scatters into
    /// `segments` (guest-physical).
    pub fn memcpy_gpa_dtoh(&mut self, dptr: u64, segments: Vec<(u64, u64)>) -> Result<()> {
        self.call(
            &Request::MemcpyGpaDtoH { dptr, segments },
            Op::MemcpyGpaDtoH,
        )
        .map(|_| ())
    }
}
