#!/usr/bin/env python3
"""Measure launch-bound eager and CUDA-graph execution with identical math."""

import argparse
import ctypes
import json
import os
import statistics
import time

import torch


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("eager", "full", "segmented", "segmented-side"), required=True)
    parser.add_argument("--iters", type=int, default=1000)
    parser.add_argument("--reps", type=int, default=5)
    parser.add_argument("--warmup", type=int, default=50)
    parser.add_argument("--ops", type=int, default=8)
    parser.add_argument("--elements", type=int, default=1024)
    parser.add_argument("--label", default="")
    return parser.parse_args()


def side_stream_is_capturing(stream):
    shim = os.environ.get("SMOLVM_CUDART_QUERY_LIB")
    if not shim:
        with torch.cuda.stream(stream):
            return torch.cuda.is_current_stream_capturing(), 0

    runtime = ctypes.CDLL(shim)
    query = runtime.cudaStreamGetCaptureInfo_v2
    query.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    query.restype = ctypes.c_int
    status = ctypes.c_int(0)
    capture_id = ctypes.c_uint64(0)
    rc = query(
        ctypes.c_void_p(stream.cuda_stream),
        ctypes.byref(status),
        ctypes.byref(capture_id),
        None,
        None,
        None,
    )
    if rc != 0:
        raise RuntimeError(f"cudaStreamGetCaptureInfo_v2 failed: {rc}")
    return status.value == 1, capture_id.value


def main():
    args = parse_args()
    torch.set_grad_enabled(False)
    torch.cuda.init()
    device = torch.device("cuda")
    root = torch.cuda.Stream()
    side = torch.cuda.Stream()
    input_buffer = torch.linspace(-0.5, 0.5, args.elements, device=device)

    def segment(value):
        for _ in range(args.ops):
            value = value * 1.0001
            value = value + 0.0001
        return value

    def eager_iteration():
        value = segment(input_buffer)
        value = value * 0.999
        value = value + 0.0007
        return segment(value)

    with torch.cuda.stream(root):
        for _ in range(10):
            reference = eager_iteration()
    torch.cuda.synchronize()
    reference = reference.detach().cpu()

    capture_ms = 0.0
    capture_id = 0
    output = None

    if args.mode == "eager":
        def run_once():
            return eager_iteration()

    elif args.mode == "full":
        graph = torch.cuda.CUDAGraph()
        capture_start = time.perf_counter()
        with torch.cuda.stream(root):
            graph.capture_begin(capture_error_mode="relaxed")
            output = eager_iteration()
            graph.capture_end()
        torch.cuda.synchronize()
        capture_ms = (time.perf_counter() - capture_start) * 1000

        def run_once():
            graph.replay()
            return output

    else:
        pool = torch.cuda.graph_pool_handle()
        bridge = torch.empty_like(input_buffer)
        stable_eager_output = torch.empty_like(input_buffer)
        graph1 = torch.cuda.CUDAGraph()
        graph2 = torch.cuda.CUDAGraph()
        capture_start = time.perf_counter()
        with torch.cuda.stream(root):
            graph1.capture_begin(pool=pool, capture_error_mode="relaxed")
            first = segment(input_buffer)
            if args.mode == "segmented-side":
                side.wait_stream(root)
                with torch.cuda.stream(side):
                    bridge.copy_(first)
                active, capture_id = side_stream_is_capturing(side)
                if not active:
                    raise RuntimeError("side stream was not reported as capturing")
                root.wait_stream(side)
            else:
                bridge.copy_(first)
            graph1.capture_end()

            fresh = bridge * 0.999
            fresh = fresh + 0.0007
            stable_eager_output.copy_(fresh)

            graph2.capture_begin(pool=pool, capture_error_mode="relaxed")
            output = segment(stable_eager_output)
            graph2.capture_end()
        torch.cuda.synchronize()
        capture_ms = (time.perf_counter() - capture_start) * 1000

        def run_once():
            graph1.replay()
            fresh_value = bridge * 0.999
            fresh_value = fresh_value + 0.0007
            stable_eager_output.copy_(fresh_value)
            graph2.replay()
            return output

    samples = []
    with torch.cuda.stream(root):
        for _ in range(args.warmup):
            output = run_once()
    torch.cuda.synchronize()

    for _ in range(args.reps):
        torch.cuda.synchronize()
        started = time.perf_counter()
        with torch.cuda.stream(root):
            for _ in range(args.iters):
                output = run_once()
        torch.cuda.synchronize()
        samples.append(time.perf_counter() - started)

    actual = output.detach().cpu()
    torch.testing.assert_close(actual, reference, rtol=2e-5, atol=2e-5)
    median_seconds = statistics.median(samples)
    result = {
        "label": args.label,
        "mode": args.mode,
        "gpu": torch.cuda.get_device_name(0),
        "torch": torch.__version__,
        "cuda": torch.version.cuda,
        "iters": args.iters,
        "ops_per_segment": args.ops,
        "elements": args.elements,
        "capture_ms": round(capture_ms, 3),
        "capture_id": capture_id,
        "median_ms_per_iter": round(median_seconds * 1000 / args.iters, 6),
        "median_iters_per_sec": round(args.iters / median_seconds, 2),
        "min_iters_per_sec": round(args.iters / max(samples), 2),
        "max_iters_per_sec": round(args.iters / min(samples), 2),
        "samples_seconds": [round(sample, 6) for sample in samples],
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
