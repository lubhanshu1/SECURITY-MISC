from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


ASCII_RE = re.compile(
    rb"[\x20-\x7E]{4,}"
)

UTF16_RE = re.compile(
    rb"(?:[\x20-\x7E]\x00){4,}"
)

URL_RE = re.compile(
    r"https?://[^\s\"'<>]+",
    re.IGNORECASE,
)

IPV4_RE = re.compile(
    r"\b"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\."
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
    r"\b"
)

EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@"
    r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

WINDOWS_PATH_RE = re.compile(
    r"\b[A-Za-z]:\\"
    r"[^\r\n\t\"<>|]{2,}"
)

UNC_PATH_RE = re.compile(
    r"\\\\[A-Za-z0-9._$ -]+\\"
    r"[^\r\n\t\"<>|]{1,}"
)

REGISTRY_RE = re.compile(
    r"\b"
    r"(?:HKLM|HKCU|HKCR|HKU|HKCC)"
    r"\\[^\r\n\t\"<>]{2,}",
    re.IGNORECASE,
)

POWERSHELL_RE = re.compile(
    r"\b(?:powershell|pwsh|"
    r"-enc|-encodedcommand|"
    r"invoke-expression|"
    r"iex)\b",
    re.IGNORECASE,
)

CMD_RE = re.compile(
    r"\b(?:cmd\.exe|command\.com|"
    r"start-process|rundll32|"
    r"regsvr32|mshta|wscript|cscript)\b",
    re.IGNORECASE,
)

SUSPICIOUS_API_NAMES = {
    "VirtualAlloc",
    "VirtualProtect",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "OpenProcess",
    "NtCreateThreadEx",
    "QueueUserAPC",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "CreateProcessA",
    "CreateProcessW",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "InternetOpenA",
    "InternetOpenW",
    "InternetOpenUrlA",
    "InternetOpenUrlW",
    "WinHttpOpen",
    "WinHttpConnect",
    "WinHttpOpenRequest",
    "WinHttpSendRequest",
}


def extract_ascii(
    data: bytes,
) -> list[str]:
    return [
        match.decode(
            "ascii",
            errors="replace",
        )
        for match in ASCII_RE.findall(data)
    ]


def extract_utf16(
    data: bytes,
) -> list[str]:
    results: list[str] = []

    for match in UTF16_RE.findall(data):
        try:
            results.append(
                match.decode(
                    "utf-16le",
                    errors="replace",
                )
            )
        except UnicodeDecodeError:
            continue

    return results


def unique_preserve_order(
    values: list[str],
) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []

    for value in values:
        if value in seen:
            continue

        seen.add(value)
        result.append(value)

    return result


def classify_strings(
    strings: list[str],
) -> dict:
    urls: list[str] = []
    ipv4: list[str] = []
    emails: list[str] = []
    windows_paths: list[str] = []
    unc_paths: list[str] = []
    registry_paths: list[str] = []
    powershell: list[str] = []
    command_indicators: list[str] = []
    suspicious_apis: list[str] = []

    for value in strings:
        urls.extend(
            URL_RE.findall(value)
        )

        ipv4.extend(
            IPV4_RE.findall(value)
        )

        emails.extend(
            EMAIL_RE.findall(value)
        )

        windows_paths.extend(
            WINDOWS_PATH_RE.findall(value)
        )

        unc_paths.extend(
            UNC_PATH_RE.findall(value)
        )

        registry_paths.extend(
            REGISTRY_RE.findall(value)
        )

        if POWERSHELL_RE.search(value):
            powershell.append(value)

        if CMD_RE.search(value):
            command_indicators.append(value)

        for api_name in SUSPICIOUS_API_NAMES:
            if api_name.lower() in value.lower():
                suspicious_apis.append(
                    api_name
                )

    return {
        "urls": unique_preserve_order(urls),
        "ipv4": unique_preserve_order(ipv4),
        "emails": unique_preserve_order(emails),
        "windows_paths": unique_preserve_order(
            windows_paths
        ),
        "unc_paths": unique_preserve_order(
            unc_paths
        ),
        "registry_paths": unique_preserve_order(
            registry_paths
        ),
        "powershell_indicators": (
            unique_preserve_order(
                powershell
            )
        ),
        "command_indicators": (
            unique_preserve_order(
                command_indicators
            )
        ),
        "suspicious_apis": sorted(
            set(suspicious_apis)
        ),
    }


def analyze_file(
    path: Path,
) -> dict:
    data = path.read_bytes()

    ascii_strings = extract_ascii(data)
    utf16_strings = extract_utf16(data)

    all_strings = unique_preserve_order(
        ascii_strings + utf16_strings
    )

    classifications = classify_strings(
        all_strings
    )

    return {
        "tool": "SECURITY-MISC",
        "module": "string_analyzer",
        "file": str(path),
        "size_bytes": len(data),
        "counts": {
            "ascii": len(ascii_strings),
            "utf16le": len(utf16_strings),
            "total_unique": len(all_strings),
        },
        "strings": {
            "ascii": ascii_strings,
            "utf16le": utf16_strings,
        },
        "classifications": classifications,
    }


def print_report(
    report: dict,
    limit: int = 50,
) -> None:
    counts = report["counts"]
    classifications = report[
        "classifications"
    ]

    print()
    print("=" * 80)
    print(
        "SECURITY-MISC :: STRING ANALYSIS"
    )
    print("=" * 80)

    print(
        f"File        : {report['file']}"
    )

    print(
        f"Size        : "
        f"{report['size_bytes']:,} bytes"
    )

    print()
    print("COUNTS")
    print("-" * 80)

    print(
        f"ASCII       : "
        f"{counts['ascii']}"
    )

    print(
        f"UTF-16LE    : "
        f"{counts['utf16le']}"
    )

    print(
        f"Unique total: "
        f"{counts['total_unique']}"
    )

    for name, values in classifications.items():
        print()
        print(name.upper())
        print("-" * 80)

        if not values:
            print("None found.")
            continue

        for value in values[:limit]:
            print(f"  {value}")

        if len(values) > limit:
            print(
                f"  ... "
                f"({len(values) - limit} more)"
            )

    print()
    print("=" * 80)


def save_json(
    report: dict,
    output: Path,
) -> None:
    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output.write_text(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print(
        f"[+] JSON report: {output}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only ASCII/UTF-16LE "
            "string extraction and classification."
        )
    )

    parser.add_argument(
        "file",
        help="File to analyze.",
    )

    parser.add_argument(
        "--json",
        type=Path,
        help="Write results to JSON.",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum entries printed per category.",
    )

    args = parser.parse_args()

    if args.limit < 1:
        parser.error(
            "--limit must be greater than zero"
        )

    path = (
        Path(args.file)
        .expanduser()
        .resolve()
    )

    if not path.exists():
        print(
            f"[!] File not found: {path}"
        )
        return 2

    if not path.is_file():
        print(
            f"[!] Not a regular file: {path}"
        )
        return 2

    try:
        report = analyze_file(path)
        print_report(
            report,
            limit=args.limit,
        )

        if args.json:
            save_json(
                report,
                args.json,
            )

        return 0

    except PermissionError:
        print(
            f"[!] Permission denied: {path}"
        )
        return 3

    except OSError as exc:
        print(
            f"[!] File error: {exc}"
        )
        return 3


if __name__ == "__main__":
    raise SystemExit(main())