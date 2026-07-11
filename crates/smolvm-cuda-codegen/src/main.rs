//! Forward-to-host-lib marshaling generator.
//!
//! CUDA's library surface is hundreds of functions across cudart, cuBLAS,
//! cuDNN, … Hand-writing the guest stub + host dispatch + (de)serialization for
//! each is unmaintainable. This tool takes a compact per-function spec and emits
//! both sides of the marshaling over the generic `LibCall` transport
//! (`smolvm_cuda::proto::Op::LibCall`), so adding a function is a few lines of
//! spec, not code across five files.
//!
//! Parameter kinds capture the one thing a C signature can't: whether a pointer
//! is an opaque host **Handle**, a **DevPtr** (real device address), or a
//! **HostIn** scalar to read and ship by value. Everything else follows.
//!
//! Emits two files:
//! - `<out>/<lib>_guest.rs` — `extern "C"` stubs, `include!`d by the guest shim.
//! - `<out>/<lib>_host.rs` — dlsym table + `dispatch(func, args)`, `include!`d by
//!   the host backend.
//!
//! This is a spec-driven generator; the specs below are hand-authored today, but
//! nothing stops a future front-end from emitting them from the CUDA headers.

use std::fmt::Write as _;

/// How one parameter is marshaled.
#[derive(Clone, Copy)]
enum Kind {
    /// A machine scalar passed by value. `.0` is the Rust scalar type.
    Scalar(&'static str),
    /// An opaque host handle (cuBLAS/cuDNN handle, stream, …) — pass the pointer
    /// value by reference; the guest never dereferences it.
    Handle,
    /// A real device address — pass by value.
    DevPtr,
    /// A host input scalar behind a pointer (cuBLAS alpha/beta) — read `*p` on
    /// the guest, ship the value, rebuild a pointer to a local on the host.
    HostInScalar(&'static str),
    /// A host output scalar behind a pointer (cuDNN workspace size) — the host
    /// fills a local and ships it back; the guest writes it through `*p`. `.0` is
    /// the wire scalar type; the pointee type comes from the param's `cty`.
    HostOutScalar(&'static str),
}

/// The pointee of a `*mut T` C type (for building a local of the right type).
fn pointee(cty: &str) -> &str {
    cty.strip_prefix("*mut ").unwrap_or(cty)
}

/// Wire size in bytes of a scalar type name.
fn wire_size(t: &str) -> usize {
    match t {
        "i32" | "u32" | "f32" => 4,
        _ => 8,
    }
}

/// One parameter: its name, the Rust type in the `extern "C"` signature, and how
/// to marshal it.
struct P {
    name: &'static str,
    cty: &'static str,
    kind: Kind,
}
const fn p(name: &'static str, cty: &'static str, kind: Kind) -> P {
    P { name, cty, kind }
}

/// One function to generate.
struct Fun {
    /// Exported symbol name (what the guest program links).
    sym: &'static str,
    /// Real host symbol to dlsym (usually the same).
    real: &'static str,
    params: Vec<P>,
}

/// A library: an id (matches the guest shim's `LIB_*` constant) and its
/// functions, indexed in order (the index is the `func` id on the wire).
struct Lib {
    name: &'static str,
    id: u8,
    /// Default soname to dlopen on the host if the env override is unset.
    default_so: &'static str,
    funcs: Vec<Fun>,
}

fn cublas_spec() -> Lib {
    use Kind::*;
    let handle = || p("handle", "*mut c_void", Handle);
    let i = |n| p(n, "c_int", Scalar("i32"));
    // Column-major GEMM shared shape for S/D, differing only in element type.
    let gemm = |sym, real, ety: &'static str| Fun {
        sym,
        real,
        params: vec![
            handle(),
            i("transa"),
            i("transb"),
            i("m"),
            i("n"),
            i("k"),
            p("alpha", leak(format!("*const {ety}")), HostInScalar(ety)),
            p("A", leak(format!("*const {ety}")), DevPtr),
            i("lda"),
            p("B", leak(format!("*const {ety}")), DevPtr),
            i("ldb"),
            p("beta", leak(format!("*const {ety}")), HostInScalar(ety)),
            p("C", leak(format!("*mut {ety}")), DevPtr),
            i("ldc"),
        ],
    };
    // Strided-batched GEMM (PyTorch's `bmm`): same as gemm plus per-operand
    // strides (i64) and a batch count.
    let s64 = |n| p(n, "i64", Scalar("i64"));
    let gemm_strided = |sym, real, ety: &'static str| Fun {
        sym,
        real,
        params: vec![
            handle(),
            i("transa"),
            i("transb"),
            i("m"),
            i("n"),
            i("k"),
            p("alpha", leak(format!("*const {ety}")), HostInScalar(ety)),
            p("A", leak(format!("*const {ety}")), DevPtr),
            i("lda"),
            s64("strideA"),
            p("B", leak(format!("*const {ety}")), DevPtr),
            i("ldb"),
            s64("strideB"),
            p("beta", leak(format!("*const {ety}")), HostInScalar(ety)),
            p("C", leak(format!("*mut {ety}")), DevPtr),
            i("ldc"),
            s64("strideC"),
            i("batchCount"),
        ],
    };
    Lib {
        name: "cublas",
        id: 1,
        default_so: "libcublas.so",
        funcs: vec![
            Fun {
                sym: "cublasCreate_v2",
                real: "cublasCreate_v2",
                params: vec![p("handle_out", "*mut *mut c_void", Handle)], // out-handle: special-cased below
            },
            Fun {
                sym: "cublasDestroy_v2",
                real: "cublasDestroy_v2",
                params: vec![handle()],
            },
            gemm("cublasSgemm_v2", "cublasSgemm_v2", "f32"),
            gemm("cublasDgemm_v2", "cublasDgemm_v2", "f64"),
            gemm_strided(
                "cublasSgemmStridedBatched",
                "cublasSgemmStridedBatched",
                "f32",
            ),
            gemm_strided(
                "cublasDgemmStridedBatched",
                "cublasDgemmStridedBatched",
                "f64",
            ),
            // Stream + config that PyTorch sets up before a matmul.
            Fun {
                sym: "cublasSetStream_v2",
                real: "cublasSetStream_v2",
                params: vec![handle(), p("stream", "*mut c_void", Handle)],
            },
            Fun {
                sym: "cublasSetWorkspace_v2",
                real: "cublasSetWorkspace_v2",
                params: vec![
                    handle(),
                    p("workspace", "*mut c_void", DevPtr),
                    p("size", "usize", Scalar("u64")),
                ],
            },
            Fun {
                sym: "cublasSetMathMode",
                real: "cublasSetMathMode",
                params: vec![handle(), i("mode")],
            },
            Fun {
                sym: "cublasGetMathMode",
                real: "cublasGetMathMode",
                params: vec![handle(), p("mode", "*mut c_int", HostOutScalar("i32"))],
            },
            Fun {
                sym: "cublasGetProperty",
                real: "cublasGetProperty",
                params: vec![
                    i("prop_type"),
                    p("value", "*mut c_int", HostOutScalar("i32")),
                ],
            },
            // cublasGemmEx — PyTorch's general GEMM. alpha/beta are the compute
            // type (f32 for the common CUBLAS_COMPUTE_32F path).
            Fun {
                sym: "cublasGemmEx",
                real: "cublasGemmEx",
                params: vec![
                    handle(),
                    i("transa"),
                    i("transb"),
                    i("m"),
                    i("n"),
                    i("k"),
                    p("alpha", "*const f32", HostInScalar("f32")),
                    p("A", "*const c_void", DevPtr),
                    i("Atype"),
                    i("lda"),
                    p("B", "*const c_void", DevPtr),
                    i("Btype"),
                    i("ldb"),
                    p("beta", "*const f32", HostInScalar("f32")),
                    p("C", "*mut c_void", DevPtr),
                    i("Ctype"),
                    i("ldc"),
                    i("computeType"),
                    i("algo"),
                ],
            },
            // cublasGemmStridedBatchedEx — PyTorch's mixed-precision batched GEMM
            // (fp16/bf16 `bmm`). alpha/beta are the compute type (f32 common path).
            Fun {
                sym: "cublasGemmStridedBatchedEx",
                real: "cublasGemmStridedBatchedEx",
                params: vec![
                    handle(),
                    i("transa"),
                    i("transb"),
                    i("m"),
                    i("n"),
                    i("k"),
                    p("alpha", "*const f32", HostInScalar("f32")),
                    p("A", "*const c_void", DevPtr),
                    i("Atype"),
                    i("lda"),
                    s64("strideA"),
                    p("B", "*const c_void", DevPtr),
                    i("Btype"),
                    i("ldb"),
                    s64("strideB"),
                    p("beta", "*const f32", HostInScalar("f32")),
                    p("C", "*mut c_void", DevPtr),
                    i("Ctype"),
                    i("ldc"),
                    s64("strideC"),
                    i("batchCount"),
                    i("computeType"),
                    i("algo"),
                ],
            },
        ],
    }
}

/// An out-handle constructor (`fn(T* out)`), e.g. `cudnnCreateTensorDescriptor`.
fn create(name: &'static str) -> Fun {
    Fun {
        sym: name,
        real: name,
        params: vec![p("out", "*mut *mut c_void", Kind::Handle)],
    }
}

/// Core cuDNN legacy convolution path — the surface a basic conv forward needs.
/// Descriptors are opaque handles; tensors are device pointers; alpha/beta are
/// host scalars; the workspace size is a host output.
fn cudnn_spec() -> Lib {
    use Kind::*;
    let h = || p("handle", "*mut c_void", Handle);
    let d = |n| p(n, "*mut c_void", Handle);
    let dev = |n| p(n, "*mut c_void", DevPtr);
    let i = |n| p(n, "c_int", Scalar("i32"));
    let f = |sym, params| Fun {
        sym,
        real: sym,
        params,
    };
    Lib {
        name: "cudnn",
        id: 2,
        default_so: "libcudnn.so",
        funcs: vec![
            create("cudnnCreate"),
            f("cudnnDestroy", vec![h()]),
            f(
                "cudnnSetStream",
                vec![h(), p("stream", "*mut c_void", Handle)],
            ),
            create("cudnnCreateTensorDescriptor"),
            f(
                "cudnnSetTensor4dDescriptor",
                vec![d("t"), i("fmt"), i("dtype"), i("n"), i("c"), i("h"), i("w")],
            ),
            f("cudnnDestroyTensorDescriptor", vec![d("t")]),
            create("cudnnCreateFilterDescriptor"),
            f(
                "cudnnSetFilter4dDescriptor",
                vec![d("f"), i("dtype"), i("fmt"), i("k"), i("c"), i("h"), i("w")],
            ),
            f("cudnnDestroyFilterDescriptor", vec![d("f")]),
            create("cudnnCreateConvolutionDescriptor"),
            f(
                "cudnnSetConvolution2dDescriptor",
                vec![
                    d("cv"),
                    i("pad_h"),
                    i("pad_w"),
                    i("u"),
                    i("v"),
                    i("dil_h"),
                    i("dil_w"),
                    i("mode"),
                    i("ctype"),
                ],
            ),
            f("cudnnDestroyConvolutionDescriptor", vec![d("cv")]),
            f(
                "cudnnGetConvolutionForwardWorkspaceSize",
                vec![
                    h(),
                    d("x"),
                    d("w"),
                    d("cv"),
                    d("y"),
                    i("algo"),
                    p("size", "*mut usize", HostOutScalar("u64")),
                ],
            ),
            f(
                "cudnnConvolutionForward",
                vec![
                    h(),
                    p("alpha", "*const f32", HostInScalar("f32")),
                    d("xDesc"),
                    dev("x"),
                    d("wDesc"),
                    dev("w"),
                    d("convDesc"),
                    i("algo"),
                    dev("workspace"),
                    p("wsSize", "usize", Scalar("u64")),
                    p("beta", "*const f32", HostInScalar("f32")),
                    d("yDesc"),
                    dev("y"),
                ],
            ),
        ],
    }
}

/// Leak a String to `&'static str` (generator is short-lived).
fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn main() {
    let out = std::env::args().nth(1).unwrap_or_else(|| ".".into());
    for lib in [cublas_spec(), cudnn_spec()] {
        std::fs::write(format!("{out}/{}_guest.rs", lib.name), gen_guest(&lib)).unwrap();
        std::fs::write(format!("{out}/{}_host.rs", lib.name), gen_host(&lib)).unwrap();
        eprintln!(
            "generated {} functions for lib '{}' (id {})",
            lib.funcs.len(),
            lib.name,
            lib.id
        );
    }
}

/// Is this the create/out-handle special case (first param is `*mut *mut`)?
fn is_create(f: &Fun) -> bool {
    f.params.len() == 1 && f.params[0].cty.starts_with("*mut *mut")
}

fn gen_guest(lib: &Lib) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "// @generated by smolvm-cuda-codegen — do not edit. lib='{}' id={}",
        lib.name, lib.id
    );
    let _ = writeln!(s, "const LIB_ID: u8 = {};", lib.id);
    for (idx, f) in lib.funcs.iter().enumerate() {
        if is_create(f) {
            // out-handle create: no args in; returns a handle (u64) in `out`.
            let _ = writeln!(
                s,
                "#[no_mangle]\npub extern \"C\" fn {}(handle_out: *mut *mut c_void) -> c_int {{\n    \
                 if handle_out.is_null() {{ return 1; }}\n    \
                 match with_client(|c| c.lib_call(LIB_ID, {idx}, Vec::new())) {{\n        \
                 Ok((0, out)) if out.len() >= 8 => {{\n            \
                 let h = u64::from_le_bytes(out[..8].try_into().unwrap());\n            \
                 unsafe {{ *handle_out = h as *mut c_void }};\n            0\n        }}\n        \
                 Ok((st, _)) => st,\n        Err(_) => 1,\n    }}\n}}",
                f.sym
            );
            continue;
        }
        // signature
        let sig = f
            .params
            .iter()
            .map(|p| format!("{}: {}", p.name, p.cty))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            s,
            "#[no_mangle]\npub extern \"C\" fn {}({sig}) -> c_int {{",
            f.sym
        );
        let _ = writeln!(s, "    let mut a: Vec<u8> = Vec::new();");
        for p in &f.params {
            match p.kind {
                Kind::Scalar(t) => {
                    let _ = writeln!(
                        s,
                        "    a.extend_from_slice(&({} as {t}).to_le_bytes());",
                        p.name
                    );
                }
                Kind::Handle | Kind::DevPtr => {
                    let _ = writeln!(
                        s,
                        "    a.extend_from_slice(&({} as u64).to_le_bytes());",
                        p.name
                    );
                }
                Kind::HostInScalar(t) => {
                    let _ = writeln!(
                        s,
                        "    if {n}.is_null() {{ return 1; }}\n    a.extend_from_slice(&(unsafe {{ *{n} }} as {t}).to_le_bytes());",
                        n = p.name
                    );
                }
                Kind::HostOutScalar(_) => {} // output-only: nothing to send
            }
        }
        // Output params (in declaration order) come back in `out`.
        let outs: Vec<(&str, &str)> = f
            .params
            .iter()
            .filter_map(|p| match p.kind {
                Kind::HostOutScalar(t) => Some((p.name, t)),
                _ => None,
            })
            .collect();
        if outs.is_empty() {
            let _ = writeln!(
                s,
                "    match with_client(|c| c.lib_call(LIB_ID, {idx}, a)) {{ Ok((st, _)) => st, Err(_) => 1 }}\n}}"
            );
        } else {
            let _ = writeln!(
                s,
                "    match with_client(|c| c.lib_call(LIB_ID, {idx}, a)) {{\n        Ok((st, out)) => {{ let mut o = 0usize;"
            );
            for (name, t) in &outs {
                let sz = wire_size(t);
                let _ = writeln!(
                    s,
                    "            if !{name}.is_null() && out.len() >= o + {sz} {{ unsafe {{ *{name} = {t}::from_le_bytes(out[o..o + {sz}].try_into().unwrap()) as _ }}; }} o += {sz};"
                );
            }
            let _ = writeln!(
                s,
                "            let _ = o; st }}\n        Err(_) => 1,\n    }}\n}}"
            );
        }
    }
    s
}

fn gen_host(lib: &Lib) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "// @generated by smolvm-cuda-codegen — do not edit. lib='{}' id={}",
        lib.name, lib.id
    );
    // The resolved-symbols struct.
    let _ = writeln!(s, "pub struct GenLib {{ _lib: Library,");
    for f in &lib.funcs {
        let cargs = f
            .params
            .iter()
            .map(|p| p.cty)
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            s,
            "    f_{}: unsafe extern \"C\" fn({cargs}) -> c_int,",
            f.real
        );
    }
    let _ = writeln!(s, "}}");
    // Loader.
    let _ = writeln!(
        s,
        "impl GenLib {{\n    pub fn load() -> Result<GenLib, String> {{\n        let path = std::env::var(\"SMOLVM_{}_LIB\").unwrap_or_else(|_| \"{}\".into());\n        unsafe {{\n            let lib = Library::new(&path).map_err(|e| format!(\"load {{path}}: {{e}}\"))?;\n            Ok(GenLib {{",
        lib.name.to_uppercase(),
        lib.default_so
    );
    for f in &lib.funcs {
        let _ = writeln!(
            s,
            "                f_{r}: sym(&lib, b\"{r}\\0\")?,",
            r = f.real
        );
    }
    let _ = writeln!(
        s,
        "                _lib: lib,\n            }})\n        }}\n    }}"
    );
    // Dispatch.
    let _ = writeln!(
        s,
        "    pub fn dispatch(&self, func: u16, args: &[u8]) -> (i32, Vec<u8>) {{\n        let mut __c = GenCur {{ b: args, p: 0 }};\n        match func {{"
    );
    for (idx, f) in lib.funcs.iter().enumerate() {
        if is_create(f) {
            let _ = writeln!(
                s,
                "            {idx} => {{ let mut h: *mut c_void = std::ptr::null_mut(); let st = unsafe {{ (self.f_{})(&mut h) }}; (st, (h as u64).to_le_bytes().to_vec()) }}",
                f.real
            );
            continue;
        }
        let mut binds = String::new();
        let mut call = Vec::new();
        let mut outs = String::new(); // append out-params after the call
        for p in &f.params {
            match p.kind {
                Kind::Scalar(t) => {
                    let _ = writeln!(binds, "                let {} = __c.{t}();", p.name);
                    call.push(format!("{} as {}", p.name, p.cty));
                }
                Kind::Handle | Kind::DevPtr => {
                    let _ = writeln!(
                        binds,
                        "                let {} = __c.u64() as {};",
                        p.name, p.cty
                    );
                    call.push(p.name.to_string());
                }
                Kind::HostInScalar(t) => {
                    let _ = writeln!(binds, "                let {}_v = __c.{t}();", p.name);
                    call.push(format!("&{}_v", p.name));
                }
                Kind::HostOutScalar(t) => {
                    let pt = pointee(p.cty);
                    let _ = writeln!(
                        binds,
                        "                let mut {}_v: {pt} = 0 as {pt};",
                        p.name
                    );
                    call.push(format!("&mut {}_v", p.name));
                    let _ = writeln!(
                        outs,
                        "                out.extend_from_slice(&({}_v as {t}).to_le_bytes());",
                        p.name
                    );
                }
            }
        }
        let _ = writeln!(
            s,
            "            {idx} => {{\n{binds}                let mut out = Vec::new();\n                let st = unsafe {{ (self.f_{})({}) }};\n{outs}                (st, out)\n            }}",
            f.real,
            call.join(", ")
        );
    }
    let _ = writeln!(
        s,
        "            _ => (super::super::CUDA_ERROR_NOT_FOUND, Vec::new()),\n        }}\n    }}\n}}"
    );
    // A tiny cursor with the scalar readers the generated code uses.
    let _ = writeln!(
        s,
        "struct GenCur<'a> {{ b: &'a [u8], p: usize }}\nimpl GenCur<'_> {{\n    fn take(&mut self, n: usize) -> [u8; 8] {{ let mut o = [0u8; 8]; let end = (self.p + n).min(self.b.len()); o[..end - self.p].copy_from_slice(&self.b[self.p..end]); self.p = end; o }}\n    fn i32(&mut self) -> i32 {{ i32::from_le_bytes(self.take(4)[..4].try_into().unwrap()) }}\n    fn i64(&mut self) -> i64 {{ i64::from_le_bytes(self.take(8)) }}\n    fn u64(&mut self) -> u64 {{ u64::from_le_bytes(self.take(8)) }}\n    fn f32(&mut self) -> f32 {{ f32::from_le_bytes(self.take(4)[..4].try_into().unwrap()) }}\n    fn f64(&mut self) -> f64 {{ f64::from_le_bytes(self.take(8)) }}\n}}"
    );
    s
}
