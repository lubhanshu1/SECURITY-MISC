from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
from datetime import datetime
from pathlib import Path


CHUNK_SIZE = 1024 * 1024

MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"MZ", "Windows PE/COFF candidate"),
    (b"\x7fELF", "ELF executable"),
    (b"%PDF-", "PDF document"),
    (b"PK\x03\x04", "ZIP archive / OOXML / container"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"7z\xbc\xaf'\x1c", "7-Zip archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
]

SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".sys",
    ".scr",
    ".msi",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".hta",
    ".com",
}


def calculate_hashes(path: Path) -> dict[str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def calculate_entropy(path: Path) -> float:
    frequencies = [0] * 256
    total = 0

    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            total += len(chunk)

            for value in chunk:
                frequencies[value] += 1

    if total == 0:
        return 0.0

    entropy = 0.0

    for count in frequencies:
        if count == 0:
            continue

        probability = count / total
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def detect_magic(path: Path) -> str:
    with path.open("rb") as handle:
        header = handle.read(32)

    for signature, file_type in MAGIC_SIGNATURES:
        if header.startswith(signature):
            return file_type

    return "Unknown / unsupported signature"


def extract_strings(
    path: Path,
    minimum_length: int = 6,
    maximum_results: int = 200,
) -> list[str]:
    data = path.read_bytes()

    pattern = rb"[\x20-\x7e]{%d,}" % minimum_length
    matches = re.findall(pattern, data)

    decoded = []

    for match in matches[:maximum_results]:
        decoded.append(match.decode("ascii", errors="replace"))

    return decoded


def timestamp_info(path: Path) -> dict[str, str]:
    stat = path.stat()

    return {
        "modified": datetime.fromtimestamp(
            stat.st_mtime
        ).astimezone().isoformat(),
        "accessed": datetime.fromtimestamp(
            stat.st_atime
        ).astimezone().isoformat(),
        "created_or_changed": datetime.fromtimestamp(
            stat.st_ctime
        ).astimezone().isoformat(),
    }


def analyze_file(path: Path) -> dict:
    stat = path.stat()
    extension = path.suffix.lower()

    entropy = calculate_entropy(path)

    return {
        "tool": "SECURITY-MISC",
        "module": "file_analyzer",
        "analysis_time": datetime.now().astimezone().isoformat(),
        "platform": platform.system(),
        "path": str(path),
        "name": path.name,
        "extension": extension,
        "size_bytes": stat.st_size,
        "timestamps": timestamp_info(path),
        "hashes": calculate_hashes(path),
        "file_type": detect_magic(path),
        "entropy": entropy,
        "entropy_interpretation": interpret_entropy(entropy),
        "strings": extract_strings(path),
        "suspicious_extension": extension in SUSPICIOUS_EXTENSIONS,
        "read_only": not os.access(path, os.W_OK),
    }


def interpret_entropy(entropy: float) -> str:
    if entropy == 0:
        return "Empty or effectively empty file"

    if entropy < 3.5:
        return "Low entropy"

    if entropy < 6.0:
        return "Moderate entropy"

    if entropy < 7.2:
        return "High entropy"

    return "Very high entropy"


def print_report(report: dict) -> None:
    hashes = report["hashes"]
    timestamps = report["timestamps"]

    print()
    print("=" * 74)
    print("SECURITY-MISC :: FILE FORENSICS")
    print("=" * 74)

    print(f"Name           : {report['name']}")
    print(f"Path           : {report['path']}")
    print(f"Size           : {report['size_bytes']:,} bytes")
    print(f"Extension      : {report['extension'] or '(none)'}")
    print(f"File type      : {report['file_type']}")
    print(f"Read-only      : {report['read_only']}")
    print(
        f"Suspicious ext : "
        f"{report['suspicious_extension']}"
    )

    print()
    print("TIMESTAMPS")
    print("-" * 74)
    print(f"Modified       : {timestamps['modified']}")
    print(f"Accessed       : {timestamps['accessed']}")
    print(f"Created/Chg    : {timestamps['created_or_changed']}")

    print()
    print("HASHES")
    print("-" * 74)
    print(f"MD5            : {hashes['md5']}")
    print(f"SHA-1          : {hashes['sha1']}")
    print(f"SHA-256        : {hashes['sha256']}")

    print()
    print("STATIC ANALYSIS")
    print("-" * 74)
    print(
        f"Entropy        : "
        f"{report['entropy']:.4f} / 8.0000"
    )
    print(
        f"Interpretation : "
        f"{report['entropy_interpretation']}"
    )

    strings = report["strings"]

    print()
    print(f"STRINGS ({len(strings)} shown)")
    print("-" * 74)

    for value in strings[:20]:
        print(f"  {value}")

    if len(strings) > 20:
        print("  ...")

    print()
    print("=" * 74)


def save_json(report: dict, output: Path) -> None:
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
        description="SECURITY-MISC static file forensics analyzer."
    )

    parser.add_argument(
        "file",
        help="Path to a file to analyze.",
    )

    parser.add_argument(
        "--json",
        type=Path,
        help="Write analysis results to JSON.",
    )

    parser.add_argument(
        "--strings",
        type=int,
        default=200,
        help="Maximum strings to extract.",
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
        print(f"[*] Analyzing: {path}")

        report = analyze_file(path)

        # Respect the CLI limit after analysis.
        report["strings"] = report["strings"][:args.strings]

        print_report(report)

        if args.json:
            save_json(report, args.json)

        return 0

    except PermissionError:
        print(f"[!] Permission denied: {path}")
        return 3

    except OSError as exc:
        print(f"[!] File-system error: {exc}")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())