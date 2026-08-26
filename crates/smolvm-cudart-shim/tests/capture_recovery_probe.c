#include <cuda_runtime_api.h>
#include <stdint.h>
#include <stdio.h>

/*
 * Live GPU regression probe for capture invalidation and recovery. Link it
 * against native libcudart for the control and against the SmolVM shim while a
 * shim_server is running for the remoted arm.
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
    cudaStream_t stream = NULL;
    cudaGraph_t graph = NULL;
    cudaGraphExec_t graph_exec = NULL;
    uint32_t *device = NULL;
    uint32_t host = 0;

    cudaGraphExec_t invalid_exec = (cudaGraphExec_t)(uintptr_t)1;
    cudaError_t invalid_instantiate =
        cudaGraphInstantiateWithFlags(&invalid_exec, NULL, 0);
    if (invalid_instantiate == cudaSuccess) {
        fprintf(stderr, "invalid graph instantiated successfully\n");
        return 1;
    }

    if (check(cudaSetDevice(0), "cudaSetDevice") ||
        check(cudaStreamCreate(&stream), "cudaStreamCreate") ||
        check(cudaMalloc((void **)&device, sizeof(*device)), "cudaMalloc")) {
        return 1;
    }

    size_t empty_nodes = 123;
    if (check(cudaStreamBeginCapture(stream, cudaStreamCaptureModeRelaxed),
              "cudaStreamBeginCapture(empty)") ||
        check(cudaStreamEndCapture(stream, &graph),
              "cudaStreamEndCapture(empty)") ||
        check(cudaGraphGetNodes(graph, NULL, &empty_nodes),
              "cudaGraphGetNodes(empty)")) {
        return 1;
    }
    if (empty_nodes != 0) {
        fprintf(stderr, "empty capture reported %zu nodes\n", empty_nodes);
        return 2;
    }
    check(cudaGraphDestroy(graph), "cudaGraphDestroy(empty)");
    graph = NULL;

    if (check(cudaStreamBeginCapture(stream, cudaStreamCaptureModeRelaxed),
              "cudaStreamBeginCapture(invalidated)") ||
        check(cudaMemsetAsync(device, 0x11, sizeof(*device), stream),
              "cudaMemsetAsync(invalidated)")) {
        return 1;
    }

    cudaError_t forbidden =
        cudaMemcpy(&host, device, sizeof(host), cudaMemcpyDeviceToHost);
    graph = (cudaGraph_t)(uintptr_t)1;
    cudaError_t ended = cudaStreamEndCapture(stream, &graph);
    printf("forbidden=%d end=%d graph=%p\n", (int)forbidden, (int)ended,
           (void *)graph);
    if (forbidden == cudaSuccess || ended == cudaSuccess || graph != NULL) {
        fprintf(stderr, "capture was not invalidated\n");
        return 2;
    }
    (void)cudaGetLastError();

    if (check(cudaStreamBeginCapture(stream, cudaStreamCaptureModeRelaxed),
              "cudaStreamBeginCapture(recovery)") ||
        check(cudaMemsetAsync(device, 0x2a, sizeof(*device), stream),
              "cudaMemsetAsync(recovery)") ||
        check(cudaStreamEndCapture(stream, &graph),
              "cudaStreamEndCapture(recovery)") ||
        check(cudaGraphInstantiateWithFlags(&graph_exec, graph, 0),
              "cudaGraphInstantiateWithFlags") ||
        check(cudaGraphLaunch(graph_exec, stream), "cudaGraphLaunch") ||
        check(cudaStreamSynchronize(stream), "cudaStreamSynchronize") ||
        check(cudaMemcpy(&host, device, sizeof(host), cudaMemcpyDeviceToHost),
              "cudaMemcpy(result)")) {
        return 3;
    }
    if (host != 0x2a2a2a2aU) {
        fprintf(stderr, "wrong recovered output: %#x\n", host);
        return 4;
    }

    check(cudaGraphExecDestroy(graph_exec), "cudaGraphExecDestroy");
    check(cudaGraphDestroy(graph), "cudaGraphDestroy");
    check(cudaFree(device), "cudaFree");
    check(cudaStreamDestroy(stream), "cudaStreamDestroy");
    puts("CAPTURE-RECOVERY-OK");
    return 0;
}
