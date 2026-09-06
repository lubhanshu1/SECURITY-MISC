from __future__ import annotations

import struct

from .sections import SectionInfo, rva_to_offset


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


def read_u16(
    data: bytes,
    offset: int,
) -> int:
    return read_struct(
        data,
        offset,
        "<H",
    )[0]


def read_u32(
    data: bytes,
    offset: int,
) -> int:
    return read_struct(
        data,
        offset,
        "<I",
    )[0]


def read_c_string(
    data: bytes,
    offset: int,
    maximum: int = 4096,
) -> str:
    if offset < 0 or offset >= len(data):
        return ""

    end = min(
        len(data),
        offset + maximum,
    )

    value = data[offset:end]

    nul = value.find(b"\x00")

    if nul >= 0:
        value = value[:nul]

    return value.decode(
        "ascii",
        errors="replace",
    )


def parse_exports(
    data: bytes,
    export_rva: int,
    sections: list[SectionInfo],
) -> list[str]:
    """
    Parse named PE exports.

    The binary is treated only as data.
    Nothing is executed.
    """
    if export_rva == 0:
        return []

    export_offset = rva_to_offset(
        export_rva,
        sections,
    )

    if export_offset is None:
        return []

    # IMAGE_EXPORT_DIRECTORY is 40 bytes.
    if export_offset + 40 > len(data):
        return []

    (
        _characteristics,
        _timestamp,
        _major_version,
        _minor_version,
        _name_rva,
        ordinal_base,
        _number_of_functions,
        number_of_names,
        _address_of_functions,
        address_of_names,
        address_of_name_ordinals,
    ) = read_struct(
        data,
        export_offset,
        "<IIHHIIIIIII",
    )

    names_offset = rva_to_offset(
        address_of_names,
        sections,
    )

    ordinals_offset = rva_to_offset(
        address_of_name_ordinals,
        sections,
    )

    if (
        names_offset is None
        or ordinals_offset is None
    ):
        return []

    exports: list[str] = []

    # Defensive limit for malformed binaries.
    count = min(
        number_of_names,
        100000,
    )

    for index in range(count):
        name_rva_offset = (
            names_offset
            + (index * 4)
        )

        ordinal_offset = (
            ordinals_offset
            + (index * 2)
        )

        if (
            name_rva_offset + 4
            > len(data)
            or ordinal_offset + 2
            > len(data)
        ):
            break

        name_rva = read_u32(
            data,
            name_rva_offset,
        )

        ordinal_index = read_u16(
            data,
            ordinal_offset,
        )

        name_offset = rva_to_offset(
            name_rva,
            sections,
        )

        if name_offset is None:
            continue

        name = read_c_string(
            data,
            name_offset,
        )

        if not name:
            continue

        ordinal = (
            ordinal_base
            + ordinal_index
        )

        exports.append(
            f"{name} (ordinal {ordinal})"
        )

    return exports


def summarize_exports(
    exports: list[str],
) -> dict:
    return {
        "count": len(exports),
        "functions": exports,
    }