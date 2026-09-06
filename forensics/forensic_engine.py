from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from forensics.IOC_extraction.ioc_extractor import extract_iocs
from forensics.file_analysis.file_analyzer import analyze_file


def analyze(path: Path) -> dict:
    base_report = analyze_file(path)

    text = path.read_text(
        encoding="utf-8",
        errors="replace",
    )

    iocs = extract_iocs(text)

    base_report["ioc_analysis"] = {
        "total": sum(len(values) for values in iocs.values()),
        "categories": iocs,
    }

    base_report["pipeline"] = {
        "name": "SECURITY-MISC forensic pipeline",
        "version": "0.1.0",
        "completed_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    return base_report


def print_summary(report: dict) -> None:
    print()
    print("=" * 76)
    print("SECURITY-MISC :: FORENSIC ANALYSIS PIPELINE")
    print("=" * 76)

    print(f"File       : {report['name']}")
    print(f"Size       : {report['size_bytes']:,} bytes")
    print(f"Type       : {report['file_type']}")
    print(f"Entropy    : {report['entropy']:.4f}")
    print(
        f"SHA-256    : {report['hashes']['sha256']}"
    )

    ioc_total = report["ioc_analysis"]["total"]

    print()
    print(f"IOC total  : {ioc_total}")

    for category, values in (
        report["ioc_analysis"]["categories"].items()
    ):
        if values:
            print(
                f"  {category:<14}: "
                f"{len(values)}"
            )

    print()
    print("=" * 76)


def save_report(report: dict, output: Path) -> None:
    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output.open(
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            report,
            handle,
            indent=2,
            ensure_ascii=False,
        )

    print(f"[+] Evidence report: {output}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the SECURITY-MISC static "
            "forensic analysis pipeline."
        )
    )

    parser.add_argument(
        "file",
        help="File to analyze.",
    )

    parser.add_argument(
        "--json",
        type=Path,
        help="Write the complete report to JSON.",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    path = Path(args.file).expanduser().resolve()

    if not path.exists():
        print(f"[!] File not found: {path}")
        return 2

    if not path.is_file():
        print(f"[!] Not a regular file: {path}")
        return 2

    try:
        report = analyze(path)
        print_summary(report)

        if args.json:
            save_report(report, args.json)

        return 0

    except PermissionError:
        print(f"[!] Permission denied: {path}")
        return 3

    except OSError as exc:
        print(f"[!] File-system error: {exc}")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())