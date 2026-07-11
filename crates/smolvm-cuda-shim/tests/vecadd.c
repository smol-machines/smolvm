/* Unmodified CUDA Driver-API program — the acceptance test for the smolvm
 * libcuda.so.1 shim. Nothing here is smolvm-specific: it is written exactly as
 * a program against the real driver would be (hand-declared prototypes stand
 * in for cuda.h so no CUDA toolkit is needed to compile it).
 *
 * Exercises: init, device queries, primary context (the cudart pattern),
 * module load from PTX, kernel launch with kernelParams, memcpys, memset,
 * device-to-device copy, streams, events, mem info, error strings — and
 * resolves a second round of entry points through cuGetProcAddress the way
 * the CUDA runtime does.
 *
 * Build:  gcc vecadd.c -o vecadd -L<shimdir> -lcuda -Wl,-rpath,<shimdir>
 * Run:    ./vecadd            (prints SHIM-CUDA-OK on success, exit 0)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int CUresult;
typedef int CUdevice;
typedef void *CUcontext;
typedef void *CUmodule;
typedef void *CUfunction;
typedef void *CUstream;
typedef void *CUevent;
typedef unsigned long long CUdeviceptr;

extern CUresult cuInit(unsigned int flags);
extern CUresult cuDriverGetVersion(int *version);
extern CUresult cuDeviceGetCount(int *count);
extern CUresult cuDeviceGet(CUdevice *dev, int ordinal);
extern CUresult cuDeviceGetName(char *name, int len, CUdevice dev);
extern CUresult cuDeviceTotalMem_v2(size_t *bytes, CUdevice dev);
extern CUresult cuDeviceGetAttribute(int *pi, int attrib, CUdevice dev);
extern CUresult cuDevicePrimaryCtxRetain(CUcontext *pctx, CUdevice dev);
extern CUresult cuDevicePrimaryCtxRelease_v2(CUdevice dev);
extern CUresult cuCtxSetCurrent(CUcontext ctx);
extern CUresult cuCtxGetCurrent(CUcontext *pctx);
extern CUresult cuCtxSynchronize(void);
extern CUresult cuModuleLoadData(CUmodule *module, const void *image);
extern CUresult cuModuleGetFunction(CUfunction *fn, CUmodule module, const char *name);
extern CUresult cuModuleUnload(CUmodule module);
extern CUresult cuMemAlloc_v2(CUdeviceptr *dptr, size_t bytes);
extern CUresult cuMemFree_v2(CUdeviceptr dptr);
extern CUresult cuMemcpyHtoD_v2(CUdeviceptr dst, const void *src, size_t bytes);
extern CUresult cuMemcpyDtoH_v2(void *dst, CUdeviceptr src, size_t bytes);
extern CUresult cuMemcpyDtoD_v2(CUdeviceptr dst, CUdeviceptr src, size_t bytes);
extern CUresult cuMemsetD8_v2(CUdeviceptr dptr, unsigned char value, size_t n);
extern CUresult cuMemGetInfo_v2(size_t *free_b, size_t *total_b);
extern CUresult cuLaunchKernel(CUfunction fn, unsigned gx, unsigned gy, unsigned gz,
                               unsigned bx, unsigned by, unsigned bz,
                               unsigned shared, CUstream stream,
                               void **params, void **extra);
extern CUresult cuStreamCreate(CUstream *stream, unsigned flags);
extern CUresult cuStreamSynchronize(CUstream stream);
extern CUresult cuStreamDestroy_v2(CUstream stream);
extern CUresult cuEventCreate(CUevent *ev, unsigned flags);
extern CUresult cuEventRecord(CUevent ev, CUstream stream);
extern CUresult cuEventSynchronize(CUevent ev);
extern CUresult cuEventElapsedTime(float *ms, CUevent start, CUevent end);
extern CUresult cuEventDestroy_v2(CUevent ev);
extern CUresult cuGetErrorName(CUresult code, const char **pstr);
extern CUresult cuGetProcAddress_v2(const char *symbol, void **pfn, int version,
                                    unsigned long long flags, int *status);

#define CHECK(call)                                                         \
    do {                                                                    \
        CUresult _rc = (call);                                              \
        if (_rc != 0) {                                                     \
            const char *_name = "?";                                        \
            cuGetErrorName(_rc, &_name);                                    \
            fprintf(stderr, "FAIL %s -> %d (%s) at line %d\n", #call, _rc,  \
                    _name, __LINE__);                                       \
            exit(1);                                                        \
        }                                                                   \
    } while (0)

static const char *VECADD_PTX =
    ".version 7.0\n"
    ".target sm_52\n"
    ".address_size 64\n"
    ".visible .entry vecadd(.param .u64 a, .param .u64 b, .param .u64 c, .param .u32 n)\n"
    "{ .reg .pred %p<2>; .reg .f32 %f<4>; .reg .b32 %r<6>; .reg .b64 %rd<11>;\n"
    " ld.param.u64 %rd1,[a]; ld.param.u64 %rd2,[b]; ld.param.u64 %rd3,[c]; ld.param.u32 %r2,[n];\n"
    " mov.u32 %r3,%ntid.x; mov.u32 %r4,%ctaid.x; mov.u32 %r5,%tid.x; mad.lo.s32 %r1,%r4,%r3,%r5;\n"
    " setp.ge.u32 %p1,%r1,%r2; @%p1 bra $E;\n"
    " cvta.to.global.u64 %rd4,%rd1; cvta.to.global.u64 %rd5,%rd2; cvta.to.global.u64 %rd6,%rd3;\n"
    " mul.wide.u32 %rd7,%r1,4; add.s64 %rd8,%rd4,%rd7; add.s64 %rd9,%rd5,%rd7; add.s64 %rd10,%rd6,%rd7;\n"
    " ld.global.f32 %f1,[%rd8]; ld.global.f32 %f2,[%rd9]; add.f32 %f3,%f1,%f2; st.global.f32 [%rd10],%f3;\n"
    "$E: ret; }\n";

enum { N = 4096 };

int main(void) {
    CHECK(cuInit(0));

    int version = 0, count = 0;
    CHECK(cuDriverGetVersion(&version));
    CHECK(cuDeviceGetCount(&count));
    if (count < 1) {
        fprintf(stderr, "FAIL no devices\n");
        return 1;
    }
    CUdevice dev;
    CHECK(cuDeviceGet(&dev, 0));
    char name[256];
    CHECK(cuDeviceGetName(name, sizeof name, dev));
    size_t total = 0;
    CHECK(cuDeviceTotalMem_v2(&total, dev));
    int cc_major = 0;
    CHECK(cuDeviceGetAttribute(&cc_major, /*COMPUTE_CAPABILITY_MAJOR*/ 75, dev));
    printf("device 0: %s (%zu MiB, cc %d.x, driver %d)\n", name,
           total >> 20, cc_major, version);

    /* Primary context, exactly as the CUDA runtime does it. */
    CUcontext ctx = NULL;
    CHECK(cuDevicePrimaryCtxRetain(&ctx, dev));
    CHECK(cuCtxSetCurrent(ctx));
    CUcontext cur = NULL;
    CHECK(cuCtxGetCurrent(&cur));
    if (cur != ctx) {
        fprintf(stderr, "FAIL current ctx mismatch\n");
        return 1;
    }

    CUmodule module;
    CUfunction vecadd;
    CHECK(cuModuleLoadData(&module, VECADD_PTX));
    CHECK(cuModuleGetFunction(&vecadd, module, "vecadd"));

    static float a[N], b[N], c[N];
    for (int i = 0; i < N; i++) {
        a[i] = (float)i;
        b[i] = 2.0f * (float)i;
    }
    CUdeviceptr da, db, dc, dscratch;
    CHECK(cuMemAlloc_v2(&da, sizeof a));
    CHECK(cuMemAlloc_v2(&db, sizeof b));
    CHECK(cuMemAlloc_v2(&dc, sizeof c));
    CHECK(cuMemAlloc_v2(&dscratch, sizeof c));
    CHECK(cuMemcpyHtoD_v2(da, a, sizeof a));
    CHECK(cuMemcpyHtoD_v2(db, b, sizeof b));
    CHECK(cuMemsetD8_v2(dc, 0, sizeof c));

    size_t mem_free = 0, mem_total = 0;
    CHECK(cuMemGetInfo_v2(&mem_free, &mem_total));

    /* Launch on a created stream, timed with events. */
    CUstream stream;
    CUevent ev_start, ev_end;
    CHECK(cuStreamCreate(&stream, 0));
    CHECK(cuEventCreate(&ev_start, 0));
    CHECK(cuEventCreate(&ev_end, 0));

    unsigned block = 256, grid = (N + block - 1) / block;
    unsigned n = N;
    void *params[] = { &da, &db, &dc, &n };
    CHECK(cuEventRecord(ev_start, stream));
    CHECK(cuLaunchKernel(vecadd, grid, 1, 1, block, 1, 1, 0, stream, params, NULL));
    CHECK(cuEventRecord(ev_end, stream));
    CHECK(cuStreamSynchronize(stream));
    CHECK(cuEventSynchronize(ev_end));
    float ms = -1.0f;
    CHECK(cuEventElapsedTime(&ms, ev_start, ev_end));

    /* Round-trip the result through a device-to-device copy. */
    CHECK(cuMemcpyDtoD_v2(dscratch, dc, sizeof c));
    CHECK(cuMemcpyDtoH_v2(c, dscratch, sizeof c));
    for (int i = 0; i < N; i++) {
        float want = a[i] + b[i];
        if (c[i] < want - 1e-2f || c[i] > want + 1e-2f) {
            fprintf(stderr, "FAIL mismatch at %d: got %f want %f\n", i, c[i], want);
            return 1;
        }
    }
    printf("vecadd n=%d verified (kernel %.3f ms, %zu/%zu MiB free)\n", N, ms,
           mem_free >> 20, mem_total >> 20);

    /* Second pass resolving entry points via cuGetProcAddress — the path the
     * CUDA runtime takes for every driver call since 11.3. */
    CUresult (*p_cuCtxSynchronize)(void) = NULL;
    CUresult (*p_cuMemcpyDtoH)(void *, CUdeviceptr, size_t) = NULL;
    int status = -1;
    CHECK(cuGetProcAddress_v2("cuCtxSynchronize", (void **)&p_cuCtxSynchronize,
                              12000, 0, &status));
    CHECK(cuGetProcAddress_v2("cuMemcpyDtoH", (void **)&p_cuMemcpyDtoH,
                              12000, 0, &status));
    if (!p_cuCtxSynchronize || !p_cuMemcpyDtoH) {
        fprintf(stderr, "FAIL cuGetProcAddress returned NULL fn\n");
        return 1;
    }
    CHECK(p_cuCtxSynchronize());
    memset(c, 0, sizeof c);
    CHECK(p_cuMemcpyDtoH(c, dc, sizeof c));
    if (c[N - 1] != a[N - 1] + b[N - 1]) {
        fprintf(stderr, "FAIL proc-address path mismatch\n");
        return 1;
    }

    /* Unknown symbols must be reported, not crash. */
    void *bogus = (void *)1;
    if (cuGetProcAddress_v2("cuDefinitelyNotReal", &bogus, 12000, 0, &status) == 0 ||
        bogus != NULL) {
        fprintf(stderr, "FAIL unknown symbol not rejected\n");
        return 1;
    }

    CHECK(cuEventDestroy_v2(ev_start));
    CHECK(cuEventDestroy_v2(ev_end));
    CHECK(cuStreamDestroy_v2(stream));
    CHECK(cuMemFree_v2(da));
    CHECK(cuMemFree_v2(db));
    CHECK(cuMemFree_v2(dc));
    CHECK(cuMemFree_v2(dscratch));
    CHECK(cuModuleUnload(module));
    CHECK(cuDevicePrimaryCtxRelease_v2(dev));

    printf("SHIM-CUDA-OK: %s\n", name);
    return 0;
}
