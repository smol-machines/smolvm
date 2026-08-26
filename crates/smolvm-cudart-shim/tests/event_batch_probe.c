#include <cuda_runtime_api.h>
#include <stdint.h>
#include <stdio.h>

enum { EVENT_COUNT = 130 };

static int run_flag(uint32_t flags) {
    cudaEvent_t events[EVENT_COUNT] = {0};

    for (int i = 0; i < EVENT_COUNT; ++i) {
        cudaError_t status = cudaEventCreateWithFlags(&events[i], flags);
        if (status != cudaSuccess || events[i] == NULL) {
            fprintf(stderr, "create[%d] flags=%u failed: %d\n", i, flags,
                    (int)status);
            return 1;
        }
        for (int j = 0; j < i; ++j) {
            if (events[i] == events[j]) {
                fprintf(stderr, "duplicate live event handle at %d/%d\n", i,
                        j);
                return 1;
            }
        }
    }

    for (int i = 0; i < EVENT_COUNT; ++i) {
        cudaError_t status = cudaEventRecord(events[i], NULL);
        if (status != cudaSuccess) {
            fprintf(stderr, "record[%d] flags=%u failed: %d\n", i, flags,
                    (int)status);
            return 1;
        }
    }
    cudaError_t status = cudaEventSynchronize(events[EVENT_COUNT - 1]);
    if (status != cudaSuccess) {
        fprintf(stderr, "synchronize flags=%u failed: %d\n", flags,
                (int)status);
        return 1;
    }

    for (int i = 0; i < EVENT_COUNT; ++i) {
        status = cudaEventDestroy(events[i]);
        if (status != cudaSuccess) {
            fprintf(stderr, "destroy[%d] flags=%u failed: %d\n", i, flags,
                    (int)status);
            return 1;
        }
    }
    return 0;
}

int main(void) {
    if (cudaEventCreate(NULL) != cudaErrorInvalidValue) {
        fputs("null event output was not rejected\n", stderr);
        return 1;
    }
    cudaEvent_t invalid = NULL;
    if (cudaEventCreateWithFlags(&invalid, UINT32_C(0x80000000)) !=
        cudaErrorInvalidValue) {
        fputs("invalid event flags were not rejected\n", stderr);
        return 1;
    }
    if (invalid != NULL) {
        fputs("invalid event creation modified the output\n", stderr);
        return 1;
    }

    if (run_flag(cudaEventDefault) || run_flag(cudaEventDisableTiming)) {
        return 1;
    }
    puts("EVENT-BATCH-OK creates=260 flags=2");
    return 0;
}
