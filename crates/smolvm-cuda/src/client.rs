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
}
