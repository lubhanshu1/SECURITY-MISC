from __future__ import annotations

import argparse
import json
import socket
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(slots=True)
class ServiceResult:
    target: str
    port: int
    reachable: bool
    service: str
    hostname: str | None
    latency_ms: float | None
    error: str | None = None


def lookup_service(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def detect_service(
    target: str,
    port: int,
    timeout: float = 1.0,
) -> ServiceResult:
    started = time.perf_counter()
    hostname = None

    try:
        hostname = socket.gethostbyaddr(target)[0]
    except (socket.herror, socket.gaierror):
        pass

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((target, port))
        latency_ms = round((time.perf_counter() - started) * 1000, 2)

        if result == 0:
            return ServiceResult(
                target=target,
                port=port,
                reachable=True,
                service=lookup_service(port),
                hostname=hostname,
                latency_ms=latency_ms,
            )

        return ServiceResult(
            target=target,
            port=port,
            reachable=False,
            service=lookup_service(port),
            hostname=hostname,
            latency_ms=latency_ms,
        )

    except OSError as exc:
        return ServiceResult(
            target=target,
            port=port,
            reachable=False,
            service=lookup_service(port),
            hostname=hostname,
            latency_ms=round(
                (time.perf_counter() - started) * 1000,
                2,
            ),
            error=str(exc),
        )

    finally:
        sock.close()


def save_result(result: ServiceResult, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "tool": "SECURITY-MISC",
        "module": "service_detector",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "result": asdict(result),
    }

    with output.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inspect a single TCP service on an authorized target."
    )

    parser.add_argument(
        "target",
        nargs="?",
        default="127.0.0.1",
    )

    parser.add_argument(
        "port",
        type=int,
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
    )

    parser.add_argument(
        "--json",
        type=Path,
    )

    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")

    if not 0.1 <= args.timeout <= 10:
        parser.error("timeout must be between 0.1 and 10 seconds")

    try:
        resolved_ip = socket.gethostbyname(args.target)
    except socket.gaierror as exc:
        print(f"[!] Unable to resolve target: {args.target}")
        print(f"    {exc}")
        return 2

    print()
    print("=" * 62)
    print("SECURITY-MISC :: SERVICE DETECTOR")
    print("=" * 62)
    print(f"Target       : {args.target}")
    print(f"Resolved IP  : {resolved_ip}")
    print(f"Port         : {args.port}")
    print(f"Timeout      : {args.timeout:.1f}s")
    print("=" * 62)

    result = detect_service(
        resolved_ip,
        args.port,
        args.timeout,
    )

    if result.reachable:
        print(f"[+] Port      : {result.port}/tcp")
        print("[+] State     : OPEN")
        print(f"[+] Service   : {result.service}")
        print(f"[+] Hostname  : {result.hostname or 'unavailable'}")
        print(f"[+] Latency   : {result.latency_ms:.2f} ms")
    else:
        print(f"[-] Port      : {result.port}/tcp")
        print("[-] State     : NOT REACHABLE")
        print(f"[-] Service   : {result.service}")
        print(f"[-] Latency   : {result.latency_ms:.2f} ms")

        if result.error:
            print(f"[!] Error     : {result.error}")

    print("=" * 62)

    if args.json:
        save_result(result, args.json)
        print(f"[+] Report    : {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())