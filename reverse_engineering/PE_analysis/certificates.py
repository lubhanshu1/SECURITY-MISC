from __future__ import annotations

import struct


WIN_CERT_REVISION_2_0 = 0x0200
WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002


def read_u16(
    data: bytes,
    offset: int,
) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise ValueError(
            f"Unexpected end of file at offset 0x{offset:X}"
        )

    return struct.unpack_from(
        "<H",
        data,
        offset,
    )[0]


def read_u32(
    data: bytes,
    offset: int,
) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise ValueError(
            f"Unexpected end of file at offset 0x{offset:X}"
        )

    return struct.unpack_from(
        "<I",
        data,
        offset,
    )[0]


def find_security_directory(
    data: bytes,
) -> tuple[int, int]:
    """
    Return:

        (file_offset, size)

    for the PE security directory.

    Important PE detail:
    the security directory's VirtualAddress field is
    a FILE OFFSET, not an RVA.
    """
    if len(data) < 64:
        raise ValueError(
            "File is too small to be a PE file."
        )

    if data[:2] != b"MZ":
        raise ValueError(
            "Missing MZ signature."
        )

    pe_offset = read_u32(
        data,
        0x3C,
    )

    if pe_offset + 4 > len(data):
        raise ValueError(
            "Invalid PE header offset."
        )

    if data[
        pe_offset:
        pe_offset + 4
    ] != b"PE\x00\x00":
        raise ValueError(
            "Missing PE signature."
        )

    coff_offset = pe_offset + 4

    if coff_offset + 20 > len(data):
        raise ValueError(
            "Incomplete COFF header."
        )

    size_of_optional_header = read_u16(
        data,
        coff_offset + 16,
    )

    optional_offset = coff_offset + 20

    if (
        optional_offset
        + size_of_optional_header
        > len(data)
    ):
        raise ValueError(
            "Optional header exceeds file size."
        )

    magic = read_u16(
        data,
        optional_offset,
    )

    if magic == 0x10B:
        directory_offset = (
            optional_offset + 96
        )
        number_of_directories_offset = (
            optional_offset + 92
        )

    elif magic == 0x20B:
        directory_offset = (
            optional_offset + 112
        )
        number_of_directories_offset = (
            optional_offset + 108
        )

    else:
        raise ValueError(
            f"Unsupported optional-header magic: 0x{magic:X}"
        )

    number_of_directories = read_u32(
        data,
        number_of_directories_offset,
    )

    if number_of_directories <= 4:
        return 0, 0

    security_directory_offset = (
        directory_offset + (4 * 8)
    )

    if (
        security_directory_offset + 8
        > optional_offset
        + size_of_optional_header
    ):
        return 0, 0

    file_offset = read_u32(
        data,
        security_directory_offset,
    )

    size = read_u32(
        data,
        security_directory_offset + 4,
    )

    return file_offset, size


def parse_certificate_table(
    data: bytes,
) -> dict:
    """
    Parse the PE WIN_CERTIFICATE structures.

    This examines certificate metadata only.
    It does not execute or validate the certificate
    against an OS trust chain.
    """
    file_offset, size = find_security_directory(
        data
    )

    if file_offset == 0 or size == 0:
        return {
            "present": False,
            "file_offset": file_offset,
            "size": size,
            "entries": [],
        }

    end = file_offset + size

    if end > len(data):
        raise ValueError(
            "Certificate table extends beyond file size."
        )

    entries: list[dict] = []

    cursor = file_offset

    while cursor + 8 <= end:
        length = read_u32(
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

        if length < 8:
            break

        certificate_end = (
            cursor + length
        )

        if certificate_end > end:
            break

        entries.append(
            {
                "offset": cursor,
                "length": length,
                "revision": f"0x{revision:04X}",
                "type": f"0x{certificate_type:04X}",
                "is_revision_2_0": (
                    revision
                    == WIN_CERT_REVISION_2_0
                ),
                "is_pkcs_signed_data": (
                    certificate_type
                    == WIN_CERT_TYPE_PKCS_SIGNED_DATA
                ),
            }
        )

        # WIN_CERTIFICATE structures are aligned
        # to an 8-byte boundary.
        cursor += (
            length + 7
        ) & ~7

    return {
        "present": True,
        "file_offset": file_offset,
        "size": size,
        "entries": entries,
    }


def summarize_certificates(
    certificate_table: dict,
) -> dict:
    entries = certificate_table.get(
        "entries",
        [],
    )

    return {
        "present": bool(
            certificate_table.get(
                "present",
                False,
            )
        ),
        "entry_count": len(entries),
        "pkcs_signed_entries": sum(
            1
            for entry in entries
            if entry.get(
                "is_pkcs_signed_data",
                False,
            )
        ),
        "revision_2_entries": sum(
            1
            for entry in entries
            if entry.get(
                "is_revision_2_0",
                False,
            )
        ),
    }