#include <cuda.h>
#include <stdio.h>

static int check(CUresult status, const char *operation) {
    if (status == CUDA_SUCCESS) {
        return 0;
    }
    fprintf(stderr, "%s failed: %d\n", operation, (int)status);
    return 1;
}

int main(void) {
    CUdevice device;
    CUcontext context = NULL;
    CUevent event = NULL;

    if (check(cuInit(0), "cuInit") ||
        check(cuDeviceGet(&device, 0), "cuDeviceGet") ||
        check(cuDevicePrimaryCtxRetain(&context, device),
              "cuDevicePrimaryCtxRetain") ||
        check(cuCtxSetCurrent(context), "cuCtxSetCurrent")) {
        return 1;
    }

    CUresult invalid = cuEventQuery(NULL);
    if (invalid == CUDA_SUCCESS) {
        fputs("cuEventQuery accepted a null event\n", stderr);
        return 1;
    }

    if (check(cuEventCreate(&event, CU_EVENT_DISABLE_TIMING),
              "cuEventCreate") ||
        check(cuEventRecord(event, NULL), "cuEventRecord")) {
        return 1;
    }

    CUresult pending = cuEventQuery(event);
    if (pending != CUDA_SUCCESS && pending != CUDA_ERROR_NOT_READY) {
        fprintf(stderr, "cuEventQuery returned unexpected status: %d\n",
                (int)pending);
        return 1;
    }
    if (check(cuEventSynchronize(event), "cuEventSynchronize") ||
        check(cuEventQuery(event), "cuEventQuery(complete)") ||
        check(cuEventDestroy(event), "cuEventDestroy") ||
        check(cuDevicePrimaryCtxRelease(device),
              "cuDevicePrimaryCtxRelease")) {
        return 1;
    }

    printf("DRIVER-EVENT-QUERY-OK initial=%d invalid=%d\n", (int)pending,
           (int)invalid);
    return 0;
}
