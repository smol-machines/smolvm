//! Host-side CUDA-RPC server: dispatch decoded [`Request`]s to a [`Backend`].
//!
//! The dispatch layer ([`serve`]) owns opaque→raw handle tables for modules,
//! functions and contexts, so the guest only ever sees host-minted ids and
//! cannot forge a host pointer; an unknown id is rejected with
//! `CUDA_ERROR_INVALID_HANDLE`. Device pointers (`CUdeviceptr`) pass through by
//! value because kernel launch parameters embed them — exactly as the Driver
//! API works.
//!
//! Two backends ship: [`GpuBackend`] (the real driver via `nvcuda.dll` /
//! `libcuda.so.1`) and [`CpuBackend`] (emulates a known test kernel so the full
//! protocol + transport can be exercised on a host with no NVIDIA GPU).

use crate::proto::{decode_request, encode_response, read_msg, write_msg, Request, Response};
use std::collections::HashMap;
use std::io::{Read, Write};

/// `Ok(value)` or `Err(CUresult)` — a non-zero CUDA error code.
pub type CuResult<T> = Result<T, i32>;

/// `CUDA_ERROR_INVALID_HANDLE`.
pub const CUDA_ERROR_INVALID_HANDLE: i32 = 400;
/// `CUDA_ERROR_NOT_FOUND`.
pub const CUDA_ERROR_NOT_FOUND: i32 = 500;

/// A CUDA Driver-API implementation. Handles returned here are the backend's
/// own raw values (e.g. real `CUmodule` pointers); [`serve`] hides them behind
/// opaque ids before they reach the guest.
pub trait Backend: Send {
    fn init(&mut self) -> CuResult<()>;
    fn device_get_count(&mut self) -> CuResult<i32>;
    fn device_get_name(&mut self, device: i32) -> CuResult<String>;
    fn device_total_mem(&mut self, device: i32) -> CuResult<u64>;
    fn ctx_create(&mut self, device: i32) -> CuResult<u64>;
    fn ctx_destroy(&mut self, ctx: u64) -> CuResult<()>;
    fn module_load_data(&mut self, image: &[u8]) -> CuResult<u64>;
    fn module_get_function(&mut self, module: u64, name: &str) -> CuResult<u64>;
    fn mem_alloc(&mut self, bytes: u64) -> CuResult<u64>;
    fn mem_free(&mut self, dptr: u64) -> CuResult<()>;
    fn memcpy_htod(&mut self, dptr: u64, data: &[u8]) -> CuResult<()>;
    fn memcpy_dtoh(&mut self, dptr: u64, bytes: u64) -> CuResult<Vec<u8>>;
    fn launch_kernel(
        &mut self,
        function: u64,
        grid: [u32; 3],
        block: [u32; 3],
        shared_bytes: u32,
        stream: u64,
        params: &[Vec<u8>],
    ) -> CuResult<()>;
    fn ctx_synchronize(&mut self) -> CuResult<()>;
}

/// Per-connection opaque→raw handle translation. Ids are dense and monotonic so
/// a stale/forged id from the guest never aliases a live resource.
#[derive(Default)]
struct Session {
    next_id: u64,
    modules: HashMap<u64, u64>,
    functions: HashMap<u64, u64>,
    contexts: HashMap<u64, u64>,
}

impl Session {
    fn mint(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }
}

/// Serve one CUDA-RPC connection to completion (until the peer closes). Each
/// request is dispatched to `backend`; returns on clean EOF.
pub fn serve<S: Read + Write>(mut stream: S, backend: &mut dyn Backend) -> std::io::Result<()> {
    let mut sess = Session::default();
    while let Some(payload) = read_msg(&mut stream)? {
        let req = decode_request(&payload)?;
        let (status, resp) = dispatch(&mut sess, backend, req);
        let out = encode_response(status, &resp);
        write_msg(&mut stream, &out)?;
    }
    Ok(())
}

fn dispatch(sess: &mut Session, b: &mut dyn Backend, req: Request) -> (i32, Response) {
    // Translate an opaque id to the backend's raw handle, or error.
    fn raw(map: &HashMap<u64, u64>, id: u64) -> CuResult<u64> {
        map.get(&id).copied().ok_or(CUDA_ERROR_INVALID_HANDLE)
    }
    let r: CuResult<Response> = (|| match req {
        Request::Init => b.init().map(|_| Response::Ok),
        Request::DeviceGetCount => b.device_get_count().map(Response::Count),
        Request::DeviceGetName { device } => b.device_get_name(device).map(Response::Name),
        Request::DeviceTotalMem { device } => b.device_total_mem(device).map(Response::Bytes),
        Request::CtxCreate { device } => {
            let raw = b.ctx_create(device)?;
            let id = sess.mint();
            sess.contexts.insert(id, raw);
            Ok(Response::Handle(id))
        }
        Request::CtxDestroy { ctx } => {
            let raw = raw(&sess.contexts, ctx)?;
            b.ctx_destroy(raw)?;
            sess.contexts.remove(&ctx);
            Ok(Response::Ok)
        }
        Request::ModuleLoadData { image } => {
            let raw = b.module_load_data(&image)?;
            let id = sess.mint();
            sess.modules.insert(id, raw);
            Ok(Response::Handle(id))
        }
        Request::ModuleGetFunction { module, name } => {
            let raw_mod = raw(&sess.modules, module)?;
            let raw_fn = b.module_get_function(raw_mod, &name)?;
            let id = sess.mint();
            sess.functions.insert(id, raw_fn);
            Ok(Response::Handle(id))
        }
        Request::MemAlloc { bytes } => b.mem_alloc(bytes).map(Response::Dptr),
        Request::MemFree { dptr } => b.mem_free(dptr).map(|_| Response::Ok),
        Request::MemcpyHtoD { dptr, data } => b.memcpy_htod(dptr, &data).map(|_| Response::Ok),
        Request::MemcpyDtoH { dptr, bytes } => b.memcpy_dtoh(dptr, bytes).map(Response::Data),
        Request::LaunchKernel {
            function,
            grid,
            block,
            shared_bytes,
            stream,
            params,
        } => {
            let raw_fn = raw(&sess.functions, function)?;
            b.launch_kernel(raw_fn, grid, block, shared_bytes, stream, &params)
                .map(|_| Response::Ok)
        }
        Request::CtxSynchronize => b.ctx_synchronize().map(|_| Response::Ok),
    })();
    match r {
        Ok(resp) => (0, resp),
        Err(code) => (code, Response::Ok),
    }
}

// ===========================================================================
// CPU emulation backend (for GPU-less verification of the full RPC path)
// ===========================================================================

/// Emulates a small, known set of kernels so the protocol + transport can be
/// exercised end-to-end without an NVIDIA GPU. Device memory is a bump-allocated
/// host buffer keyed by fake `CUdeviceptr`. Recognizes the `vecadd(a,b,c,n)`
/// test kernel by name; unknown kernels return `CUDA_ERROR_NOT_FOUND`.
pub struct CpuBackend {
    next_dptr: u64,
    mem: HashMap<u64, Vec<u8>>,
    fn_names: HashMap<u64, String>,
    next_handle: u64,
}

impl Default for CpuBackend {
    fn default() -> Self {
        CpuBackend {
            next_dptr: 0x1_0000_0000, // distinct from small handle ids
            mem: HashMap::new(),
            fn_names: HashMap::new(),
            next_handle: 1,
        }
    }
}

impl CpuBackend {
    fn handle(&mut self) -> u64 {
        let h = self.next_handle;
        self.next_handle += 1;
        h
    }
}

fn read_u64(p: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(p.get(..8)?.try_into().ok()?))
}
fn read_u32(p: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(p.get(..4)?.try_into().ok()?))
}

impl Backend for CpuBackend {
    fn init(&mut self) -> CuResult<()> {
        Ok(())
    }
    fn device_get_count(&mut self) -> CuResult<i32> {
        Ok(1)
    }
    fn device_get_name(&mut self, _device: i32) -> CuResult<String> {
        Ok("smolvm CPU emulation device".into())
    }
    fn device_total_mem(&mut self, _device: i32) -> CuResult<u64> {
        Ok(1 << 30)
    }
    fn ctx_create(&mut self, _device: i32) -> CuResult<u64> {
        Ok(self.handle())
    }
    fn ctx_destroy(&mut self, _ctx: u64) -> CuResult<()> {
        Ok(())
    }
    fn module_load_data(&mut self, _image: &[u8]) -> CuResult<u64> {
        Ok(self.handle())
    }
    fn module_get_function(&mut self, _module: u64, name: &str) -> CuResult<u64> {
        let h = self.handle();
        self.fn_names.insert(h, name.to_string());
        Ok(h)
    }
    fn mem_alloc(&mut self, bytes: u64) -> CuResult<u64> {
        let dptr = self.next_dptr;
        self.next_dptr += bytes.max(1);
        self.mem.insert(dptr, vec![0u8; bytes as usize]);
        Ok(dptr)
    }
    fn mem_free(&mut self, dptr: u64) -> CuResult<()> {
        self.mem
            .remove(&dptr)
            .map(|_| ())
            .ok_or(CUDA_ERROR_INVALID_HANDLE)
    }
    fn memcpy_htod(&mut self, dptr: u64, data: &[u8]) -> CuResult<()> {
        let buf = self.mem.get_mut(&dptr).ok_or(CUDA_ERROR_INVALID_HANDLE)?;
        if data.len() > buf.len() {
            return Err(CUDA_ERROR_INVALID_HANDLE);
        }
        buf[..data.len()].copy_from_slice(data);
        Ok(())
    }
    fn memcpy_dtoh(&mut self, dptr: u64, bytes: u64) -> CuResult<Vec<u8>> {
        let buf = self.mem.get(&dptr).ok_or(CUDA_ERROR_INVALID_HANDLE)?;
        let n = bytes as usize;
        if n > buf.len() {
            return Err(CUDA_ERROR_INVALID_HANDLE);
        }
        Ok(buf[..n].to_vec())
    }
    fn launch_kernel(
        &mut self,
        function: u64,
        _grid: [u32; 3],
        _block: [u32; 3],
        _shared_bytes: u32,
        _stream: u64,
        params: &[Vec<u8>],
    ) -> CuResult<()> {
        let name = self
            .fn_names
            .get(&function)
            .cloned()
            .ok_or(CUDA_ERROR_INVALID_HANDLE)?;
        match name.as_str() {
            // vecadd(const float* a, const float* b, float* c, int n): c[i]=a[i]+b[i]
            "vecadd" => {
                if params.len() != 4 {
                    return Err(CUDA_ERROR_NOT_FOUND);
                }
                let a = read_u64(&params[0]).ok_or(CUDA_ERROR_NOT_FOUND)?;
                let b = read_u64(&params[1]).ok_or(CUDA_ERROR_NOT_FOUND)?;
                let c = read_u64(&params[2]).ok_or(CUDA_ERROR_NOT_FOUND)?;
                let n = read_u32(&params[3]).ok_or(CUDA_ERROR_NOT_FOUND)? as usize;
                let av = self.mem.get(&a).ok_or(CUDA_ERROR_INVALID_HANDLE)?.clone();
                let bv = self.mem.get(&b).ok_or(CUDA_ERROR_INVALID_HANDLE)?.clone();
                let out = self.mem.get_mut(&c).ok_or(CUDA_ERROR_INVALID_HANDLE)?;
                for i in 0..n {
                    let x = f32::from_le_bytes(av[i * 4..i * 4 + 4].try_into().unwrap());
                    let y = f32::from_le_bytes(bv[i * 4..i * 4 + 4].try_into().unwrap());
                    out[i * 4..i * 4 + 4].copy_from_slice(&(x + y).to_le_bytes());
                }
                Ok(())
            }
            _ => Err(CUDA_ERROR_NOT_FOUND),
        }
    }
    fn ctx_synchronize(&mut self) -> CuResult<()> {
        Ok(())
    }
}

#[cfg(feature = "gpu")]
mod gpu;
#[cfg(feature = "gpu")]
pub use gpu::GpuBackend;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Client;
    use std::io::{Read, Write};

    // Drive the CPU backend through the full encode→dispatch→decode path.
    #[test]
    fn cpu_backend_vecadd_via_dispatch() {
        let mut sess = Session::default();
        let mut b = CpuBackend::default();
        // module + function
        let (_, m) = dispatch(&mut sess, &mut b, Request::ModuleLoadData { image: vec![] });
        let module = match m {
            Response::Handle(h) => h,
            _ => panic!(),
        };
        let (_, f) = dispatch(
            &mut sess,
            &mut b,
            Request::ModuleGetFunction {
                module,
                name: "vecadd".into(),
            },
        );
        let function = match f {
            Response::Handle(h) => h,
            _ => panic!(),
        };
        // alloc a, b, c (4 floats)
        let alloc = |sess: &mut Session, b: &mut CpuBackend| -> u64 {
            match dispatch(sess, b, Request::MemAlloc { bytes: 16 }).1 {
                Response::Dptr(d) => d,
                _ => panic!(),
            }
        };
        let da = alloc(&mut sess, &mut b);
        let db = alloc(&mut sess, &mut b);
        let dc = alloc(&mut sess, &mut b);
        let a: Vec<u8> = [1f32, 2., 3., 4.]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let bb: Vec<u8> = [10f32, 20., 30., 40.]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        dispatch(&mut sess, &mut b, Request::MemcpyHtoD { dptr: da, data: a });
        dispatch(
            &mut sess,
            &mut b,
            Request::MemcpyHtoD { dptr: db, data: bb },
        );
        let params = vec![
            da.to_le_bytes().to_vec(),
            db.to_le_bytes().to_vec(),
            dc.to_le_bytes().to_vec(),
            4u32.to_le_bytes().to_vec(),
        ];
        let (st, _) = dispatch(
            &mut sess,
            &mut b,
            Request::LaunchKernel {
                function,
                grid: [1, 1, 1],
                block: [4, 1, 1],
                shared_bytes: 0,
                stream: 0,
                params,
            },
        );
        assert_eq!(st, 0);
        let out = match dispatch(
            &mut sess,
            &mut b,
            Request::MemcpyDtoH {
                dptr: dc,
                bytes: 16,
            },
        )
        .1
        {
            Response::Data(d) => d,
            _ => panic!(),
        };
        let c: Vec<f32> = out
            .chunks(4)
            .map(|p| f32::from_le_bytes(p.try_into().unwrap()))
            .collect();
        assert_eq!(c, vec![11., 22., 33., 44.]);
    }

    #[test]
    fn unknown_handle_rejected() {
        let mut sess = Session::default();
        let mut b = CpuBackend::default();
        // function id 999 was never minted
        let (st, _) = dispatch(
            &mut sess,
            &mut b,
            Request::LaunchKernel {
                function: 999,
                grid: [1, 1, 1],
                block: [1, 1, 1],
                shared_bytes: 0,
                stream: 0,
                params: vec![],
            },
        );
        assert_eq!(st, CUDA_ERROR_INVALID_HANDLE);
    }

    // Full client↔serve round-trip over an in-process socketpair-like channel.
    #[test]
    fn client_serve_roundtrip() {
        use std::sync::mpsc::{Receiver, Sender};
        // A duplex stream built from two mpsc byte channels.
        struct Chan {
            tx: Sender<u8>,
            rx: Receiver<u8>,
        }
        impl Write for Chan {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                for &x in buf {
                    self.tx
                        .send(x)
                        .map_err(|_| std::io::ErrorKind::BrokenPipe)?;
                }
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl Read for Chan {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                // Block for at least one byte, then drain what's buffered.
                if buf.is_empty() {
                    return Ok(0);
                }
                let mut n = match self.rx.recv() {
                    Ok(b) => {
                        buf[0] = b;
                        1
                    }
                    Err(_) => return Ok(0), // EOF
                };
                while n < buf.len() {
                    match self.rx.try_recv() {
                        Ok(b) => {
                            buf[n] = b;
                            n += 1;
                        }
                        Err(_) => break,
                    }
                }
                Ok(n)
            }
        }
        let (c2s_tx, c2s_rx) = std::sync::mpsc::channel();
        let (s2c_tx, s2c_rx) = std::sync::mpsc::channel();
        let server_side = Chan {
            tx: s2c_tx,
            rx: c2s_rx,
        };
        let client_side = Chan {
            tx: c2s_tx,
            rx: s2c_rx,
        };

        let server = std::thread::spawn(move || {
            let mut b = CpuBackend::default();
            let _ = serve(server_side, &mut b);
        });

        let mut cli = Client::new(client_side);
        cli.init().unwrap();
        assert_eq!(cli.device_get_count().unwrap(), 1);
        let module = cli.module_load_data(b"<ptx>").unwrap();
        let func = cli.module_get_function(module, "vecadd").unwrap();
        let n = 8usize;
        let da = cli.mem_alloc((n * 4) as u64).unwrap();
        let db = cli.mem_alloc((n * 4) as u64).unwrap();
        let dc = cli.mem_alloc((n * 4) as u64).unwrap();
        let a: Vec<u8> = (0..n).flat_map(|i| (i as f32).to_le_bytes()).collect();
        let bb: Vec<u8> = (0..n)
            .flat_map(|i| ((2 * i) as f32).to_le_bytes())
            .collect();
        cli.memcpy_htod(da, &a).unwrap();
        cli.memcpy_htod(db, &bb).unwrap();
        cli.launch_kernel(
            func,
            [1, 1, 1],
            [n as u32, 1, 1],
            0,
            0,
            &[
                da.to_le_bytes().to_vec(),
                db.to_le_bytes().to_vec(),
                dc.to_le_bytes().to_vec(),
                (n as u32).to_le_bytes().to_vec(),
            ],
        )
        .unwrap();
        cli.ctx_synchronize().unwrap();
        let out = cli.memcpy_dtoh(dc, (n * 4) as u64).unwrap();
        let c: Vec<f32> = out
            .chunks(4)
            .map(|p| f32::from_le_bytes(p.try_into().unwrap()))
            .collect();
        let expect: Vec<f32> = (0..n).map(|i| (3 * i) as f32).collect();
        assert_eq!(c, expect);
        drop(cli); // closes client_side → server sees EOF
        server.join().unwrap();
    }
}
