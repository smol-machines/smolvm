#include <cuda_runtime_api.h>
#include <stdio.h>

/*
 * Live GPU regression probe for a side stream joining and rejoining one
 * captured graph segment. Link it against native libcudart for the control and
 * against the SmolVM shim while a shim_server is running for the remoted arm.
 */

static int check(cudaError_t status, const char *operation) {
    if (status == cudaSuccess) {
        return 0;
    }
    fprintf(stderr, "%s failed: %s (%d)\n", operation,
            cudaGetErrorString(status), (int)status);
    return 1;
}

int main(void) {
    cudaStream_t root = NULL;
    cudaStream_t side = NULL;
    cudaEvent_t fork_event = NULL;
    cudaEvent_t join_event = NULL;
    cudaGraph_t graph = NULL;
    cudaGraphExec_t graph_exec = NULL;

    if (check(cudaStreamCreate(&root), "cudaStreamCreate(root)") ||
        check(cudaStreamCreate(&side), "cudaStreamCreate(side)") ||
        check(cudaEventCreateWithFlags(&fork_event, cudaEventDisableTiming),
              "cudaEventCreate(fork)") ||
        check(cudaEventCreateWithFlags(&join_event, cudaEventDisableTiming),
              "cudaEventCreate(join)") ||
        check(cudaStreamBeginCapture(root, cudaStreamCaptureModeRelaxed),
              "cudaStreamBeginCapture") ||
        check(cudaEventRecord(fork_event, root), "cudaEventRecord(fork)") ||
        check(cudaStreamWaitEvent(side, fork_event, 0),
              "cudaStreamWaitEvent(side)")) {
        return 1;
    }

    enum cudaStreamCaptureStatus status = cudaStreamCaptureStatusNone;
    enum cudaStreamCaptureStatus is_capturing = cudaStreamCaptureStatusNone;
    unsigned long long capture_id = 0;
    if (check(cudaStreamIsCapturing(side, &is_capturing),
              "cudaStreamIsCapturing(side)")) {
        return 1;
    }
#if CUDART_VERSION >= 13000
    if (check(cudaStreamGetCaptureInfo(side, &status, &capture_id, NULL, NULL,
                                       NULL, NULL),
#else
    if (check(cudaStreamGetCaptureInfo_v2(side, &status, &capture_id, NULL, NULL,
                                          NULL),
#endif
              "cudaStreamGetCaptureInfo(side)")) {
        return 1;
    }
    printf("side_capture_status=%d capture_id=%llu\n", (int)status,
           capture_id);

    if (status == cudaStreamCaptureStatusActive) {
        if (check(cudaEventRecord(join_event, side), "cudaEventRecord(join)") ||
            check(cudaStreamWaitEvent(root, join_event, 0),
                  "cudaStreamWaitEvent(root)")) {
            return 1;
        }
    }

    if (check(cudaStreamEndCapture(root, &graph), "cudaStreamEndCapture")) {
        return 1;
    }
    if (is_capturing != cudaStreamCaptureStatusActive ||
        status != cudaStreamCaptureStatusActive || graph == NULL) {
        fprintf(stderr, "side stream did not join root capture\n");
        return 2;
    }

    if (check(cudaGraphInstantiateWithFlags(&graph_exec, graph, 0),
              "cudaGraphInstantiateWithFlags") ||
        check(cudaGraphLaunch(graph_exec, root), "cudaGraphLaunch") ||
        check(cudaStreamSynchronize(root), "cudaStreamSynchronize")) {
        return 1;
    }

    check(cudaGraphExecDestroy(graph_exec), "cudaGraphExecDestroy");
    check(cudaGraphDestroy(graph), "cudaGraphDestroy");
    check(cudaEventDestroy(join_event), "cudaEventDestroy(join)");
    check(cudaEventDestroy(fork_event), "cudaEventDestroy(fork)");
    check(cudaStreamDestroy(side), "cudaStreamDestroy(side)");
    check(cudaStreamDestroy(root), "cudaStreamDestroy(root)");
    puts("SEGMENTED-CAPTURE-OK");
    return 0;
}
