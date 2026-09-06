from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(slots=True)
class PortResult:
    port: int
    state: str
    service: str
    latency_ms: float | None


def resolve_target(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve target: {target}") from exc


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def check_port(target: str, port: int, timeout: float) -> PortResult:
    started = time.perf_counter()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((target, port))
        latency_ms = round((time.perf_counter() - started) * 1000, 2)

        if result == 0:
            return PortResult(
                port=port,
                state="open",
                service=service_name(port),
                latency_ms=latency_ms,
            )

        return PortResult(
            port=port,
            state="closed_or_filtered",
            service=service_name(port),
            latency_ms=latency_ms,
        )

    except OSError:
        latency_ms = round((time.perf_counter() - started) * 1000, 2)

        return PortResult(
            port=port,
            state="error",
            service=service_name(port),
            latency_ms=latency_ms,
        )

    finally:
        sock.close()


def scan_ports(
    target: str,
    start_port: int,
    end_port: int,
    timeout: float,
    workers: int,
) -> dict:
    if not 1 <= start_port <= 65535:
        raise ValueError("start_port must be between 1 and 65535")

    if not 1 <= end_port <= 65535:
        raise ValueError("end_port must be between 1 and 65535")

    if start_port > end_port:
        raise ValueError("start_port cannot be greater than end_port")

    if not 0.1 <= timeout <= 10:
        raise ValueError("timeout must be between 0.1 and 10 seconds")

    if not 1 <= workers <= 100:
        raise ValueError("workers must be between 1 and 100")

    resolved_ip = resolve_target(target)
    ports = range(start_port, end_port + 1)

    started_at = datetime.now(timezone.utc)
    timer = time.perf_counter()

    print()
    print("=" * 62)
    print("SECURITY-MISC :: TCP PORT ASSESSMENT")
    print("=" * 62)
    print(f"Target       : {target}")
    print(f"Resolved IP  : {resolved_ip}")
    print(f"Port range   : {start_port}-{end_port}")
    print(f"Timeout      : {timeout:.1f}s")
    print(f"Workers      : {workers}")
    print("=" * 62)

    results: list[PortResult] = []

    try:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    check_port,
                    resolved_ip,
                    port,
                    timeout,
                ): port
                for port in ports
            }

            for future in as_completed(futures):
                result = future.result()

                if result.state == "open":
                    results.append(result)
                    print(
                        f"[+] {result.port:5d}/tcp  "
                        f"OPEN   "
                        f"{result.service:<16} "
                        f"{result.latency_ms:>8.2f} ms"
                    )

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        raise

    results.sort(key=lambda item: item.port)

    duration = round(time.perf_counter() - timer, 3)

    report = {
        "tool": "SECURITY-MISC",
        "module": "tcp_port_assessment",
        "started_at": started_at.isoformat(),
        "duration_seconds": duration,
        "target": target,
        "resolved_ip": resolved_ip,
        "port_range": {
            "start": start_port,
            "end": end_port,
        },
        "timeout_seconds": timeout,
        "workers": workers,
        "open_ports": len(results),
        "results": [asdict(item) for item in results],
    }

    print("-" * 62)
    print(f"[+] Scan completed in {duration:.3f}s")
    print(f"[+] Open TCP ports: {len(results)}")
    print("=" * 62)

    return report


def save_report(report: dict, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)

    print(f"[+] Report written to: {output}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SECURITY-MISC TCP port assessment tool."
    )

    parser.add_argument(
        "target",
        nargs="?",
        default="127.0.0.1",
        help="Hostname or IP address to assess (default: 127.0.0.1)",
    )

    parser.add_argument(
        "--start",
        type=int,
        default=1,
        help="First TCP port (default: 1)",
    )

    parser.add_argument(
        "--end",
        type=int,
        default=1024,
        help="Last TCP port (default: 1024)",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="TCP connection timeout in seconds (default: 0.5)",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=32,
        help="Maximum concurrent workers (default: 32)",
    )

    parser.add_argument(
        "--json",
        type=Path,
        help="Write results to a JSON report.",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        report = scan_ports(
            target=args.target,
            start_port=args.start,
            end_port=args.end,
            timeout=args.timeout,
            workers=args.workers,
        )

        if args.json:
            save_report(report, args.json)

        return 0

    except ValueError as exc:
        print(f"[!] Configuration error: {exc}")
        return 2

    except KeyboardInterrupt:
        return 130

    except Exception as exc:
        print(f"[!] Unexpected error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())