#!/usr/bin/env python3
"""Prove a smolvm --cuda guest reaches a real GPU, and that data moves.

Run this inside the guest. It uses the CUDA driver API through ctypes, so it
needs no CUDA toolkit, no torch and no nvidia-smi.

Why it is shaped this way. CUDA in smolvm is REMOTED, not passed through: the
guest gets no NVIDIA driver and no /dev/nvidia*, and a compatibility
libcuda.so.1 forwards driver calls over vsock to a host daemon that owns the
device. A program can therefore start, link against libcuda.so.1 and exit zero
without a GPU ever being reached, so an exit code proves nothing. The two
assertions that mean something are a device NAME and a byte-for-byte round trip
through device memory.
"""
import ctypes
import sys

# Load by absolute path rather than by soname. The shim is injected at a fixed
# location in the guest, and relying on the loader path picks up whatever the
# image happens to carry.
SHIM = "/opt/smolvm-cuda/libcuda.so.1"

try:
    lib = ctypes.CDLL(SHIM)
except OSError as exc:
    print(f"load_shim -> FAILED {exc}")
    print("If this says 'not found', the machine was started without --cuda.")
    print("If it names a musl or ld-linux problem, use a glibc image: the shim is glibc,")
    print("so an Alpine guest cannot load it. python:3.12-slim works and has Python already.")
    sys.exit(1)

print(f"load_shim -> ok {SHIM}")

rc = lib.cuInit(0)
print("cuInit ->", rc)

count = ctypes.c_int(-1)
print("cuDeviceGetCount ->", lib.cuDeviceGetCount(ctypes.byref(count)), "count =", count.value)

buf = ctypes.create_string_buffer(128)
print("cuDeviceGetName ->", lib.cuDeviceGetName(buf, 128, 0), "name =", buf.value.decode())

ctx = ctypes.c_void_p()
print("cuCtxCreate ->", lib.cuCtxCreate_v2(ctypes.byref(ctx), 0, 0))

free, total = ctypes.c_size_t(), ctypes.c_size_t()
print("cuMemGetInfo ->", lib.cuMemGetInfo_v2(ctypes.byref(free), ctypes.byref(total)),
      "total MiB =", total.value // (1024 * 1024))

# The assertion that matters: 1 MiB to the device and back, unchanged.
N = 1024 * 1024
src = (ctypes.c_ubyte * N)(*([7] * 16 + [0] * (N - 16)))
dptr = ctypes.c_void_p()
print("cuMemAlloc   ->", lib.cuMemAlloc_v2(ctypes.byref(dptr), ctypes.c_size_t(N)))
print("cuMemcpyHtoD ->", lib.cuMemcpyHtoD_v2(dptr, src, ctypes.c_size_t(N)))
dst = (ctypes.c_ubyte * N)()
print("cuMemcpyDtoH ->", lib.cuMemcpyDtoH_v2(dst, dptr, ctypes.c_size_t(N)))
print("roundtrip first 16 bytes match:", list(dst[:16]) == [7] * 16)
print("cuMemFree    ->", lib.cuMemFree_v2(dptr))
