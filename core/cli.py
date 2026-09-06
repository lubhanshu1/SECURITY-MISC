from __future__ import annotations

import argparse
import platform
import sys
from datetime import datetime
from pathlib import Path

from core import __version__


BANNER = r"""
 ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗
 ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
 ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝
 ╚════██║██╔══╝  ██║     ██║   ██║██╔═══╝ ██║   ██║     ╚██╔╝
 ███████║███████╗╚██████╗╚██████╔╝██║     ██║   ██║      ██║
 ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝   ╚═╝      ╚═╝

                    SECURITY-MISC
             Security Research Toolkit
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-misc",
        description="Security research and analysis toolkit.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser(
        "info",
        help="Display runtime and project information.",
    )

    subparsers.add_parser(
        "doctor",
        help="Check the local Python environment.",
    )

    network_parser = subparsers.add_parser(
        "network",
        help="Network assessment tools.",
    )

    network_subparsers = network_parser.add_subparsers(
        dest="network_command"
    )

    scan_parser = network_subparsers.add_parser(
        "scan",
        help="Perform a TCP port assessment.",
    )

    scan_parser.add_argument(
        "target",
        nargs="?",
        default="127.0.0.1",
        help="Target hostname or IP.",
    )

    scan_parser.add_argument(
        "--start",
        type=int,
        default=1,
        help="Starting TCP port.",
    )

    scan_parser.add_argument(
        "--end",
        type=int,
        default=1024,
        help="Ending TCP port.",
    )

    scan_parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Connection timeout in seconds.",
    )

    scan_parser.add_argument(
        "--workers",
        type=int,
        default=32,
        help="Maximum concurrent workers.",
    )

    scan_parser.add_argument(
        "--json",
        type=Path,
        help="Write a JSON report.",
    )

    service_parser = network_subparsers.add_parser(
        "service",
        help="Inspect a single TCP service.",
    )

    service_parser.add_argument(
        "target",
        nargs="?",
        default="127.0.0.1",
        help="Target hostname or IP.",
    )

    service_parser.add_argument(
        "port",
        type=int,
        help="TCP port.",
    )

    service_parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds.",
    )

    service_parser.add_argument(
        "--json",
        type=Path,
        help="Write a JSON report.",
    )

    return parser


def command_info() -> int:
    print(BANNER)
    print(f"Version    : {__version__}")
    print(f"Python     : {platform.python_version()}")
    print(f"Platform   : {platform.platform()}")
    print(f"Executable : {sys.executable}")
    print(
        f"Timestamp  : "
        f"{datetime.now().astimezone().isoformat()}"
    )
    return 0


def command_doctor() -> int:
    print("[*] Running SECURITY-MISC environment checks...")

    if sys.version_info < (3, 11):
        print("[!] Python 3.11+ is required.")
        return 1

    print(f"[+] Python {platform.python_version()} detected.")
    print("[+] Python version is supported.")
    print("[+] Core package loaded successfully.")
    print("[+] Environment looks good.")

    return 0


def command_network_scan(args: argparse.Namespace) -> int:
    from network.socket_tools.local_scanner import scan_ports

    try:
        report = scan_ports(
            target=args.target,
            start_port=args.start,
            end_port=args.end,
            timeout=args.timeout,
            workers=args.workers,
        )

        if args.json:
            from network.socket_tools.local_scanner import save_report

            save_report(report, args.json)

        return 0

    except ValueError as exc:
        print(f"[!] Configuration error: {exc}")
        return 2

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted.")
        return 130

    except Exception as exc:
        print(f"[!] Unexpected error: {exc}")
        return 1


def command_network_service(args: argparse.Namespace) -> int:
    from network.socket_tools.service_detector import (
        detect_service,
        save_result,
    )

    try:
        target_ip = __import__("socket").gethostbyname(args.target)
    except __import__("socket").gaierror:
        print(f"[!] Unable to resolve target: {args.target}")
        return 2

    print()
    print("=" * 62)
    print("SECURITY-MISC :: SERVICE DETECTOR")
    print("=" * 62)
    print(f"Target       : {args.target}")
    print(f"Resolved IP  : {target_ip}")
    print(f"Port         : {args.port}")
    print("=" * 62)

    result = detect_service(
        target_ip,
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

    if args.json:
        save_result(result, args.json)
        print(f"[+] Report    : {args.json}")

    print("=" * 62)

    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "info":
        return command_info()

    if args.command == "doctor":
        return command_doctor()

    if args.command == "network":
        if args.network_command == "scan":
            return command_network_scan(args)

        if args.network_command == "service":
            return command_network_service(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())