from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path


WIN_CERT_REVISION_2_0 = 0x0200
WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002


def read_u16(data: bytes, offset: int) -> int:
    if offset + 2 > len(data):
        raise ValueError("Unexpected end of file.")
    return struct.unpack_from("<H", data, offset)[0]


def read_u32(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        raise ValueError("Unexpected end of file.")
    return struct.unpack_from("<I", data, offset)[0]


def parse_pe_security_directory(data: bytes) -> dict:
    if len(data) < 64:
        raise ValueError("File is too small to be a PE file.")

    if data[:2] != b"MZ":
        raise ValueError("Missing MZ signature.")

    pe_offset = read_u32(data, 0x3C)

    if pe_offset + 4 > len(data):
        raise ValueError("Invalid PE header offset.")

    if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        raise ValueError("Missing PE signature.")

    coff_offset = pe_offset + 4

    if coff_offset + 20 > len(data):
        raise ValueError("Incomplete COFF header.")

    size_of_optional_header = read_u16(
        data,
        coff_offset + 16,
    )

    optional_offset = coff_offset + 20

    if optional_offset + 2 > len(data):
        raise ValueError("Incomplete optional header.")

    magic = read_u16(data, optional_offset)

    if magic == 0x10B:
        directory_offset = optional_offset + 96
    elif magic == 0x20B:
        directory_offset = optional_offset + 112
    else:
        raise ValueError(
            f"Unsupported optional-header magic: 0x{magic:X}"
        )

    number_of_directories_offset = (
        optional_offset
        + (92 if magic == 0x10B else 108)
    )

    number_of_directories = read_u32(
        data,
        number_of_directories_offset,
    )

    if number_of_directories <= 4:
        return {
            "present": False,
            "file_offset": 0,
            "size": 0,
            "entries": [],
        }

    security_offset = directory_offset + (4 * 8)

    if security_offset + 8 > (
        optional_offset + size_of_optional_header
    ):
        return {
            "present": False,
            "file_offset": 0,
            "size": 0,
            "entries": [],
        }

    file_offset = read_u32(
        data,
        security_offset,
    )

    size = read_u32(
        data,
        security_offset + 4,
    )

    if file_offset == 0 or size == 0:
        return {
            "present": False,
            "file_offset": file_offset,
            "size": size,
            "entries": [],
        }

    if file_offset + size > len(data):
        raise ValueError(
            "Security directory extends beyond file size."
        )

    entries = []
    cursor = file_offset
    end = file_offset + size

    while cursor + 8 <= end:
        certificate_length = read_u32(
            data,
            cursor,
        )

        revision = read_u16(
            data,
            cursor + 4,
        )

        certificate_type = read_u16(
            data,
            cursor + 6,
        )

        if certificate_length < 8:
            break

        certificate_end = cursor + certificate_length

        if certificate_end > end:
            break

        entries.append(
            {
                "offset": cursor,
                "length": certificate_length,
                "revision": (
                    f"0x{revision:04X}"
                ),
                "type": (
                    f"0x{certificate_type:04X}"
                ),
                "is_pkcs_signed_data": (
                    certificate_type
                    == WIN_CERT_TYPE_PKCS_SIGNED_DATA
                ),
                "is_revision_2_0": (
                    revision
                    == WIN_CERT_REVISION_2_0
                ),
            }
        )

        # WIN_CERTIFICATE structures are aligned
        # to an 8-byte boundary.
        cursor += (
            certificate_length + 7
        ) & ~7

    return {
        "present": True,
        "file_offset": file_offset,
        "size": size,
        "entries": entries,
    }


def analyze(path: Path) -> dict:
    data = path.read_bytes()

    security = parse_pe_security_directory(data)

    return {
        "tool": "SECURITY-MISC",
        "module": "certificate_analysis",
        "file": str(path),
        "file_size": len(data),
        "security_directory": security,
    }


def print_report(report: dict) -> None:
    security = report["security_directory"]

    print()
    print("=" * 72)
    print("SECURITY-MISC :: CERTIFICATE ANALYSIS")
    print("=" * 72)
    print(f"File        : {report['file']}")
    print(f"File size   : {report['file_size']:,} bytes")
    print()

    if not security["present"]:
        print("[+] No PE certificate table detected.")
        print("=" * 72)
        return

    print("[+] PE certificate table detected.")
    print(f"    Offset  : 0x{security['file_offset']:X}")
    print(f"    Size    : {security['size']:,} bytes")
    print(
        f"    Entries : "
        f"{len(security['entries'])}"
    )

    print()
    print("CERTIFICATE ENTRIES")
    print("-" * 72)

    for index, entry in enumerate(
        security["entries"],
        start=1,
    ):
        print(f"Entry {index}")
        print(f"  Offset       : 0x{entry['offset']:X}")
        print(f"  Length       : {entry['length']:,}")
        print(f"  Revision     : {entry['revision']}")
        print(f"  Type         : {entry['type']}")
        print(
            f"  PKCS signed  : "
            f"{entry['is_pkcs_signed_data']}"
        )
        print(
            f"  Revision 2.0 : "
            f"{entry['is_revision_2_0']}"
        )
        print()

    print("=" * 72)


def save_json(report: dict, output: Path) -> None:
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

    print(f"[+] JSON report: {output}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Inspect the PE certificate/signature "
            "directory without executing the file."
        )
    )

    parser.add_argument(
        "file",
        help="Path to a PE file.",
    )

    parser.add_argument(
        "--json",
        type=Path,
        help="Write results to JSON.",
    )

    args = parser.parse_args()

    path = (
        Path(args.file)
        .expanduser()
        .resolve()
    )

    if not path.exists():
        print(f"[!] File not found: {path}")
        return 2

    if not path.is_file():
        print(f"[!] Not a regular file: {path}")
        return 2

    try:
        report = analyze(path)
        print_report(report)

        if args.json:
            save_json(
                report,
                args.json,
            )

        return 0

    except (OSError, ValueError) as exc:
        print(f"[!] Analysis error: {exc}")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())