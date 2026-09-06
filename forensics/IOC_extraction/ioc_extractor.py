from __future__ import annotations

import argparse
import ipaddress
import json
import re
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


VALID_TLDS = {
    "com", "org", "net", "edu", "gov", "mil",
    "io", "ai", "dev", "app", "tech", "info",
    "biz", "me", "co", "uk", "in", "us", "ca",
    "de", "fr", "jp", "au", "xyz", "online",
    "site", "pro", "cloud", "store",
}


PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ),
    "url": re.compile(
        r"https?://[^\s<>'\"`]+",
        re.IGNORECASE,
    ),
    "email": re.compile(
        r"\b[a-zA-Z0-9._%+-]+@"
        r"[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b"
    ),
    "md5": re.compile(
        r"\b[a-fA-F0-9]{32}\b"
    ),
    "sha1": re.compile(
        r"\b[a-fA-F0-9]{40}\b"
    ),
    "sha256": re.compile(
        r"\b[a-fA-F0-9]{64}\b"
    ),
    "windows_path": re.compile(
        r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*"
        r"[^\\/:*?\"<>|\r\n]*"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"([A-Za-z]{2,63})\b"
    ),
}


def deduplicate(values: list[str]) -> list[str]:
    return list(OrderedDict.fromkeys(values))


def clean(value: str) -> str:
    return value.rstrip(".,;:!?)]}>\"'")


def extract_ipv4(text: str) -> list[str]:
    results = []

    for candidate in PATTERNS["ipv4"].findall(text):
        try:
            address = ipaddress.ip_address(candidate)

            if address.version == 4:
                results.append(str(address))
        except ValueError:
            continue

    return deduplicate(results)


def extract_domains(text: str) -> list[str]:
    results = []

    for match in PATTERNS["domain"].finditer(text):
        domain = match.group(0)
        tld = match.group(1).lower()

        # Ignore source-code-style identifiers such as:
        # path.open, md5.update, parser.add_argument
        if tld not in VALID_TLDS:
            continue

        # Ignore domains that are actually part of an email.
        start = match.start()
        if start > 0 and text[start - 1] == "@":
            continue

        results.append(domain.lower())

    return deduplicate(results)


def extract_urls(text: str) -> list[str]:
    return deduplicate(
        [clean(value) for value in PATTERNS["url"].findall(text)]
    )


def extract_emails(text: str) -> list[str]:
    return deduplicate(
        [clean(value) for value in PATTERNS["email"].findall(text)]
    )


def extract_iocs(text: str) -> dict[str, list[str]]:
    return {
        "ipv4": extract_ipv4(text),
        "url": extract_urls(text),
        "email": extract_emails(text),
        "md5": deduplicate(
            PATTERNS["md5"].findall(text)
        ),
        "sha1": deduplicate(
            PATTERNS["sha1"].findall(text)
        ),
        "sha256": deduplicate(
            PATTERNS["sha256"].findall(text)
        ),
        "windows_path": deduplicate(
            PATTERNS["windows_path"].findall(text)
        ),
        "domain": extract_domains(text),
    }


def analyze_file(path: Path) -> dict:
    text = path.read_text(
        encoding="utf-8",
        errors="replace",
    )

    iocs = extract_iocs(text)

    total = sum(len(values) for values in iocs.values())

    return {
        "tool": "SECURITY-MISC",
        "module": "ioc_extractor",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "file": str(path),
        "total_iocs": total,
        "iocs": iocs,
    }


def print_report(report: dict) -> None:
    print()
    print("=" * 72)
    print("SECURITY-MISC :: IOC EXTRACTION")
    print("=" * 72)
    print(f"File         : {report['file']}")
    print(f"Total IOCs   : {report['total_iocs']}")
    print("-" * 72)

    for category, values in report["iocs"].items():
        print(f"\n{category.upper()} ({len(values)})")

        if not values:
            print("  None found")
            continue

        for value in values:
            print(f"  {value}")

    print()
    print("=" * 72)


def save_report(report: dict, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("w", encoding="utf-8") as handle:
        json.dump(
            report,
            handle,
            indent=2,
            ensure_ascii=False,
        )

    print(f"[+] JSON report: {output}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Extract common IOCs from a text file."
    )

    parser.add_argument(
        "file",
        help="Text file to analyze.",
    )

    parser.add_argument(
        "--json",
        type=Path,
        help="Write results to JSON.",
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
        report = analyze_file(path)
        print_report(report)

        if args.json:
            save_report(report, args.json)

        return 0

    except OSError as exc:
        print(f"[!] File error: {exc}")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())