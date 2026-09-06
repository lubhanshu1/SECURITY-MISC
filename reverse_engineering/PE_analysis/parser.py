from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path


DOS_MAGIC = b"MZ"
PE_SIGNATURE = b"PE\x00\x00"

PE32_MAGIC = 0x10B
PE32_PLUS_MAGIC = 0x20B


MACHINE_TYPES = {
    0x014C: "x86 (32-bit)",
    0x8664: "x64 (AMD64)",
    0x01C0: "ARM",
    0x01C4: "ARM Thumb-2",
    0xAA64: "ARM64",
}


@dataclass(slots=True)
class PEHeaders:
    pe_offset: int
    machine: int
    machine_name: str
    number_of_sections: int
    timestamp: int
    pointer_to_symbol_table: int
    number_of_symbols: int
    size_of_optional_header: int
    characteristics: int
    optional_magic: int
    bitness: str
    image_base: int
    entry_point_rva: int


def read_struct(
    data: bytes,
    offset: int,
    fmt: str,
):
    size = struct.calcsize(fmt)

    if offset < 0 or offset + size > len(data):
        raise ValueError(
            f"Unexpected end of file at offset 0x{offset:X}"
        )

    return struct.unpack_from(
        fmt,
        data,
        offset,
    )


def validate_pe(data: bytes) -> int:
    """
    Validate the DOS and PE signatures.

    Returns the PE-header file offset.
    """
    if len(data) < 64:
        raise ValueError(
            "File is too small to be a PE file."
        )

    if data[:2] != DOS_MAGIC:
        raise ValueError(
            "Missing MZ DOS signature."
        )

    pe_offset = read_struct(
        data,
        0x3C,
        "<I",
    )[0]

    if pe_offset + 4 > len(data):
        raise ValueError(
            "PE header offset points outside the file."
        )

    if (
        data[
            pe_offset:
            pe_offset + 4
        ]
        != PE_SIGNATURE
    ):
        raise ValueError(
            "Missing PE signature."
        )

    return pe_offset


def parse_headers(
    data: bytes,
) -> PEHeaders:
    """
    Parse the DOS/COFF/optional headers.

    This function only reads bytes. It never executes
    the analyzed file.
    """
    pe_offset = validate_pe(data)

    coff_offset = pe_offset + 4

    (
        machine,
        number_of_sections,
        timestamp,
        pointer_to_symbol_table,
        number_of_symbols,
        size_of_optional_header,
        characteristics,
    ) = read_struct(
        data,
        coff_offset,
        "<HHIIIHH",
    )

    optional_offset = coff_offset + 20

    optional_end = (
        optional_offset
        + size_of_optional_header
    )

    if optional_end > len(data):
        raise ValueError(
            "Optional header exceeds file size."
        )

    optional_magic = read_struct(
        data,
        optional_offset,
        "<H",
    )[0]

    if optional_magic == PE32_MAGIC:
        bitness = "PE32 (32-bit)"

        image_base = read_struct(
            data,
            optional_offset + 28,
            "<I",
        )[0]

    elif optional_magic == PE32_PLUS_MAGIC:
        bitness = "PE32+ (64-bit)"

        image_base = read_struct(
            data,
            optional_offset + 24,
            "<Q",
        )[0]

    else:
        raise ValueError(
            "Unsupported optional-header magic: "
            f"0x{optional_magic:X}"
        )

    entry_point_rva = read_struct(
        data,
        optional_offset + 16,
        "<I",
    )[0]

    return PEHeaders(
        pe_offset=pe_offset,
        machine=machine,
        machine_name=MACHINE_TYPES.get(
            machine,
            f"Unknown (0x{machine:04X})",
        ),
        number_of_sections=number_of_sections,
        timestamp=timestamp,
        pointer_to_symbol_table=(
            pointer_to_symbol_table
        ),
        number_of_symbols=number_of_symbols,
        size_of_optional_header=(
            size_of_optional_header
        ),
        characteristics=characteristics,
        optional_magic=optional_magic,
        bitness=bitness,
        image_base=image_base,
        entry_point_rva=entry_point_rva,
    )


def load_pe(
    path: Path,
) -> tuple[bytes, PEHeaders]:
    """
    Load a PE as raw bytes and parse its headers.
    """
    if not path.exists():
        raise FileNotFoundError(
            f"File not found: {path}"
        )

    if not path.is_file():
        raise ValueError(
            f"Not a regular file: {path}"
        )

    data = path.read_bytes()

    headers = parse_headers(data)

    return data, headers