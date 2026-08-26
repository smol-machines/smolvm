#include <cuda_runtime_api.h>
#include <stdio.h>

/*
 * Live GPU regression probe for two simultaneous capture roots, each with a
 * joined side stream. Their capture IDs must remain distinct and stable across
 * the root/side boundary.
 */

static int check(cudaError_t status, const char *operation) {
    if (status == cudaSuccess) {
        return 0;
    }
    fprintf(stderr, "%s failed: %s (%d)\n", operation,
            cudaGetErrorString(status), (int)status);
    return 1;
}

static int capture_info(cudaStream_t stream, unsigned long long *id) {
    enum cudaStreamCaptureStatus status = cudaStreamCaptureStatusNone;
#if CUDART_VERSION >= 13000
    cudaError_t error = cudaStreamGetCaptureInfo(stream, &status, id, NULL,
                                                 NULL, NULL, NULL);
#else
    cudaError_t error = cudaStreamGetCaptureInfo_v2(stream, &status, id, NULL,
                                                    NULL, NULL);
#endif
    return check(error, "cudaStreamGetCaptureInfo") ||
           status != cudaStreamCaptureStatusActive;
}

int main(void) {
    cudaStream_t roots[2] = {NULL, NULL};
    cudaStream_t sides[2] = {NULL, NULL};
    cudaEvent_t forks[2] = {NULL, NULL};
    cudaEvent_t joins[2] = {NULL, NULL};
    cudaGraph_t graphs[2] = {NULL, NULL};
    cudaGraphExec_t graph_execs[2] = {NULL, NULL};
    unsigned long long root_ids[2] = {0, 0};
    unsigned long long side_ids[2] = {0, 0};

    for (int i = 0; i < 2; ++i) {
        if (check(cudaStreamCreate(&roots[i]), "cudaStreamCreate(root)") ||
            check(cudaStreamCreate(&sides[i]), "cudaStreamCreate(side)") ||
            check(cudaEventCreateWithFlags(&forks[i], cudaEventDisableTiming),
                  "cudaEventCreate(fork)") ||
            check(cudaEventCreateWithFlags(&joins[i], cudaEventDisableTiming),
                  "cudaEventCreate(join)")) {
            return 1;
        }
    }

    for (int i = 0; i < 2; ++i) {
        if (check(cudaStreamBeginCapture(roots[i], cudaStreamCaptureModeRelaxed),
                  "cudaStreamBeginCapture") ||
            check(cudaEventRecord(forks[i], roots[i]),
                  "cudaEventRecord(fork)") ||
            check(cudaStreamWaitEvent(sides[i], forks[i], 0),
                  "cudaStreamWaitEvent(side)")) {
            return 2;
        }
        if (i == 0 &&
            cudaStreamBeginCapture(roots[i], cudaStreamCaptureModeRelaxed) !=
                cudaErrorIllegalState) {
            fprintf(stderr, "duplicate capture did not return illegal state\n");
            return 3;
        }
    }

    for (int i = 0; i < 2; ++i) {
        if (capture_info(roots[i], &root_ids[i]) ||
            capture_info(sides[i], &side_ids[i]) ||
            root_ids[i] != side_ids[i]) {
            return 4;
        }
    }
    if (root_ids[0] == root_ids[1]) {
        fprintf(stderr, "independent captures received one ID\n");
        return 5;
    }

    for (int i = 0; i < 2; ++i) {
        if (check(cudaEventRecord(joins[i], sides[i]),
                  "cudaEventRecord(join)") ||
            check(cudaStreamWaitEvent(roots[i], joins[i], 0),
                  "cudaStreamWaitEvent(root)") ||
            check(cudaStreamEndCapture(roots[i], &graphs[i]),
                  "cudaStreamEndCapture") ||
            check(cudaGraphInstantiateWithFlags(&graph_execs[i], graphs[i], 0),
                  "cudaGraphInstantiateWithFlags") ||
            check(cudaGraphLaunch(graph_execs[i], roots[i]),
                  "cudaGraphLaunch")) {
            return 6;
        }
    }
    if (check(cudaDeviceSynchronize(), "cudaDeviceSynchronize")) {
        return 7;
    }

    printf("root_ids=%llu,%llu side_ids=%llu,%llu\n", root_ids[0],
           root_ids[1], side_ids[0], side_ids[1]);
    for (int i = 0; i < 2; ++i) {
        check(cudaGraphExecDestroy(graph_execs[i]), "cudaGraphExecDestroy");
        check(cudaGraphDestroy(graphs[i]), "cudaGraphDestroy");
        check(cudaEventDestroy(joins[i]), "cudaEventDestroy(join)");
        check(cudaEventDestroy(forks[i]), "cudaEventDestroy(fork)");
        check(cudaStreamDestroy(sides[i]), "cudaStreamDestroy(side)");
        check(cudaStreamDestroy(roots[i]), "cudaStreamDestroy(root)");
    }
    puts("CONCURRENT-SEGMENTED-CAPTURE-OK");
    return 0;
}
