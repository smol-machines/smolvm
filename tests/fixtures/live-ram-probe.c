#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

/* QA helper: retain actual anonymous pages, not a capacity-only assertion. */
static uint64_t *allocate(size_t bytes, uint64_t seed) {
    uint64_t *p = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { perror("mmap"); exit(1); }
    for (size_t i = 0; i < bytes / sizeof(*p); ++i) p[i] = seed ^ i;
    if (mlock(p, bytes)) { perror("mlock: residency not proven"); exit(1); }
    return p;
}

static void verify(uint64_t *p, size_t bytes, uint64_t seed) {
    for (size_t i = 0; i < bytes / sizeof(*p); ++i) {
        if (p[i] != (seed ^ i)) {
            fprintf(stderr, "RAM mismatch at word %zu\n", i);
            exit(2);
        }
    }
}

int main(void) {
    const size_t initial = 64UL << 20, extra = 640UL << 20;
    uint64_t grown_seed = 0xfedcba9876543210ULL;
    uint64_t *base = allocate(initial, 0x123456789abcdef0ULL), *grown = NULL;
    unsigned long sequence = 0;
    for (;;) {
        if (!grown && access("/run/ram-probe-grow", F_OK) == 0)
            grown = allocate(extra, grown_seed);
        if (grown && grown_seed == 0xfedcba9876543210ULL &&
            access("/run/ram-probe-mutate", F_OK) == 0) {
            grown_seed = 0x55aa55aa12345678ULL;
            for (size_t i = 0; i < extra / sizeof(*grown); ++i)
                grown[i] = grown_seed ^ i;
            FILE *done = fopen("/run/ram-probe-mutated", "w");
            if (!done || fclose(done)) { perror("mutation marker"); return 3; }
        }
        verify(base, initial, 0x123456789abcdef0ULL);
        if (grown) verify(grown, extra, grown_seed);
        FILE *out = fopen("/run/ram-probe-status.next", "w");
        if (!out) { perror("status"); return 3; }
        fprintf(out, "%ld %lu %zu\n", (long)getpid(), ++sequence,
                initial + (grown ? extra : 0));
        if (fclose(out) || rename("/run/ram-probe-status.next", "/run/ram-probe-status")) {
            perror("publish status"); return 3;
        }
        sleep(2);
    }
}
