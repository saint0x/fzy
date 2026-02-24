#!/usr/bin/env python3
import argparse
import json
import time
import urllib.request


def req(url: str, method: str = "GET", body: bytes | None = None) -> tuple[int, bytes, float]:
    t0 = time.perf_counter()
    request = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=5) as resp:
        data = resp.read()
        status = resp.status
    return status, data, (time.perf_counter() - t0) * 1000


def main() -> None:
    parser = argparse.ArgumentParser(description="Rack load against live_server")
    parser.add_argument("--base", default="http://127.0.0.1:8080")
    parser.add_argument("--requests", type=int, default=400, help="total HTTP requests")
    parser.add_argument("--prefix", default="rack")
    args = parser.parse_args()

    if args.requests % 2 != 0:
        raise SystemExit("--requests must be even (script sends PUT+GET pairs)")

    pairs = args.requests // 2
    lat = []
    ok = 0
    err = 0

    for i in range(pairs):
        key = f"{args.prefix}_{i}"
        put_body = json.dumps({"value": "v"}).encode("utf-8")
        try:
            status, _, ms = req(f"{args.base}/v1/items/{key}", method="PUT", body=put_body)
            lat.append(ms)
            ok += 1 if status == 200 else 0
            err += 0 if status == 200 else 1

            status, _, ms = req(f"{args.base}/v1/items/{key}", method="GET")
            lat.append(ms)
            ok += 1 if status == 200 else 0
            err += 0 if status == 200 else 1
        except Exception:
            err += 2

    lat.sort()

    def pctl(p: int) -> float:
        if not lat:
            return 0.0
        idx = min(len(lat) - 1, int((p / 100) * len(lat)))
        return lat[idx]

    total_ms = sum(lat)
    rps = (ok / (total_ms / 1000.0)) if total_ms > 0 else 0.0

    print(
        json.dumps(
            {
                "requests": args.requests,
                "ok": ok,
                "err": err,
                "p50_ms": round(pctl(50), 3),
                "p95_ms": round(pctl(95), 3),
                "p99_ms": round(pctl(99), 3),
                "avg_ms": round((total_ms / len(lat)) if lat else 0.0, 3),
                "rps": round(rps, 2),
            }
        )
    )


if __name__ == "__main__":
    main()
