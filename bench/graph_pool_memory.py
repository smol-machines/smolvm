#!/usr/bin/env python3
"""Measure many CUDA graph shapes with shared or isolated allocator pools."""

import argparse
import gc
import json
import math
import time

import torch


MIB = 1024 * 1024


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pool", choices=("shared", "isolated"), required=True)
    parser.add_argument("--shapes", type=int, default=42)
    parser.add_argument("--min-elements", type=int, default=16 * 1024)
    parser.add_argument("--max-elements", type=int, default=1024 * 1024)
    parser.add_argument("--replays", type=int, default=3)
    parser.add_argument("--label", default="")
    return parser.parse_args()


def memory_snapshot():
    free, total = torch.cuda.mem_get_info()
    return {
        "free_mib": free / MIB,
        "total_mib": total / MIB,
        "allocated_mib": torch.cuda.memory_allocated() / MIB,
        "reserved_mib": torch.cuda.memory_reserved() / MIB,
    }


def memory_delta(after, before):
    return {
        "device_used_mib": round(before["free_mib"] - after["free_mib"], 3),
        "allocated_mib": round(after["allocated_mib"] - before["allocated_mib"], 3),
        "reserved_mib": round(after["reserved_mib"] - before["reserved_mib"], 3),
    }


def capture_sizes(count, minimum, maximum):
    if count < 1:
        raise ValueError("--shapes must be positive")
    if minimum < 1 or maximum < minimum:
        raise ValueError("element bounds must satisfy 1 <= minimum <= maximum")
    if count == 1:
        return [maximum]
    ratio = maximum / minimum
    sizes = {
        int(round(minimum * ratio ** (index / (count - 1))))
        for index in range(count)
    }
    # Capturing the maximum first lets smaller, non-concurrent graphs reuse its
    # private allocator reservation, as serving runtimes do for shape buckets.
    return sorted(sizes, reverse=True)


def main():
    args = parse_args()
    torch.set_grad_enabled(False)
    torch.cuda.init()
    capture_stream = torch.cuda.Stream()
    torch.cuda.set_stream(capture_stream)
    torch.cuda.empty_cache()
    torch.cuda.synchronize()
    before = memory_snapshot()

    sizes = capture_sizes(args.shapes, args.min_elements, args.max_elements)
    shared_pool = torch.cuda.graph_pool_handle() if args.pool == "shared" else None
    output = torch.empty(args.max_elements, device="cuda")
    captures = []
    capture_started = time.perf_counter()
    for elements in sizes:
        static_input = torch.linspace(-0.5, 0.5, elements, device="cuda")
        graph = torch.cuda.CUDAGraph()
        for _ in range(3):
            warm = torch.sin(static_input * 1.001 + 0.01)
        torch.cuda.synchronize()
        if shared_pool is None:
            graph.capture_begin(capture_error_mode="relaxed")
        else:
            graph.capture_begin(pool=shared_pool, capture_error_mode="relaxed")
        value = torch.sin(static_input * 1.001 + 0.01)
        value = torch.tanh(value * 0.999 + 0.02)
        output[:elements].copy_(value)
        graph.capture_end()
        captures.append((graph, static_input, elements))
    torch.cuda.synchronize()
    capture_ms = (time.perf_counter() - capture_started) * 1000
    after_capture = memory_snapshot()

    replay_started = time.perf_counter()
    checksum = 0.0
    for replay in range(1, args.replays + 1):
        for graph, static_input, elements in reversed(captures):
            static_input.add_(0.00001)
            graph.replay()
            actual = float(output[elements - 1].item())
            expected = math.tanh(
                math.sin((0.5 + replay * 0.00001) * 1.001 + 0.01) * 0.999
                + 0.02
            )
            if not math.isclose(actual, expected, rel_tol=2e-5, abs_tol=2e-5):
                raise RuntimeError(
                    f"incorrect replay output for {elements} elements: "
                    f"{actual} != {expected}"
                )
            checksum += actual
    torch.cuda.synchronize()
    replay_ms = (time.perf_counter() - replay_started) * 1000

    captures.clear()
    del graph, static_input, output, shared_pool, warm, value, capture_stream
    gc.collect()
    torch.cuda.empty_cache()
    torch.cuda.synchronize()
    after_cleanup = memory_snapshot()

    print(
        json.dumps(
            {
                "label": args.label,
                "pool": args.pool,
                "gpu": torch.cuda.get_device_name(0),
                "torch": torch.__version__,
                "cuda": torch.version.cuda,
                "shape_count": len(sizes),
                "min_elements": min(sizes),
                "max_elements": max(sizes),
                "capture_ms": round(capture_ms, 3),
                "replay_ms": round(replay_ms, 3),
                "checksum": round(checksum, 6),
                "capture_delta": memory_delta(after_capture, before),
                "cleanup_delta": memory_delta(after_cleanup, before),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
