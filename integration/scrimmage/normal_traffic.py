"""Bounded normal-traffic generator for the two-team L1-L3 demo proxy.

It emits aggregate JSON only. Response bodies, flags, cookies, and headers are never printed.
"""

from __future__ import annotations

import argparse
import json
import random
import time
import urllib.error
import urllib.request


CASES = tuple(
    (f"team{team}.lig.internal", port, path)
    for team in (1, 2)
    for port, path in ((8082, "/health"), (8083, "/health"), (8084, "/health"))
)


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int((len(ordered) - 1) * fraction)))
    return ordered[index]


def run(seed: int, samples_per_route: int, timeout: float, interval: float) -> dict:
    if samples_per_route < 1:
        raise ValueError("samples_per_route must be positive")
    rng = random.Random(seed)
    requests = list(CASES) * samples_per_route
    rng.shuffle(requests)

    latencies: list[float] = []
    status_counts: dict[str, int] = {}
    successes = 0
    failures = 0
    for host, port, path in requests:
        started = time.monotonic()
        status = 0
        try:
            with urllib.request.urlopen(
                f"http://{host}:{port}{path}", timeout=timeout
            ) as response:
                status = int(response.status)
                response.read(1)
        except urllib.error.HTTPError as error:
            status = int(error.code)
        except Exception:
            status = 0
        elapsed_ms = (time.monotonic() - started) * 1000.0
        latencies.append(elapsed_ms)
        status_counts[str(status)] = status_counts.get(str(status), 0) + 1
        if status == 200:
            successes += 1
        else:
            failures += 1
        if interval > 0:
            time.sleep(interval)

    return {
        "seed": seed,
        "requests": len(requests),
        "successes": successes,
        "failures": failures,
        "status_counts": status_counts,
        "latency_ms": {
            "p50": round(percentile(latencies, 0.50), 3),
            "p95": round(percentile(latencies, 0.95), 3),
            "p99": round(percentile(latencies, 0.99), 3),
            "max": round(max(latencies, default=0.0), 3),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--samples-per-route", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--interval", type=float, default=0.05)
    args = parser.parse_args()
    print(json.dumps(run(
        args.seed, args.samples_per_route, args.timeout, args.interval
    ), sort_keys=True))


if __name__ == "__main__":
    main()
