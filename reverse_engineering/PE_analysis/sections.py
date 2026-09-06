from __future__ import annotations

import math
import struct
from dataclasses import dataclass


@dataclass(slots=True)
class SectionInfo:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_pointer: int
    characteristics_raw: int
    characteristics: str
    entropy: float

    @property
    def raw_end(self) -> int:
        return self.raw_pointer + self.raw_size

    @property
    def is_executable(self) -> bool:
        return "EXECUTE" in self.characteristics

    @property
    def is_writable(self) -> bool:
        return "WRITE" in self.characteristics


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


def calculate_entropy(
    data: bytes,
) -> float:
    if not data:
        return 0.0

    counts = [0] * 256

    for value in data:
        counts[value] += 1

    total = len(data)
    entropy = 0.0

    for count in counts:
        if count == 0:
            continue

        probability = count / total

        entropy -= (
            probability
            * math.log2(probability)
        )

    return round(entropy, 4)


def format_characteristics(
    value: int,
) -> str:
    flags: list[str] = []

    # IMAGE_SCN_CNT_CODE
    if value & 0x00000020:
        flags.append("CODE")

    # IMAGE_SCN_MEM_READ
    if value & 0x40000000:
        flags.append("READ")

    # IMAGE_SCN_MEM_WRITE
    if value & 0x80000000:
        flags.append("WRITE")

    # IMAGE_SCN_MEM_EXECUTE
    if value & 0x20000000:
        flags.append("EXECUTE")

    return (
        " | ".join(flags)
        if flags
        else "NONE"
    )


def parse_sections(
    data: bytes,
    sections_offset: int,
    number_of_sections: int,
) -> list[SectionInfo]:
    sections: list[SectionInfo] = []

    for index in range(
        number_of_sections
    ):
        offset = (
            sections_offset
            + (40 * index)
        )

        if offset + 40 > len(data):
            raise ValueError(
                "Section table exceeds file size."
            )

        raw_name = data[
            offset:
            offset + 8
        ]

        name = raw_name.split(
            b"\x00",
            1,
        )[0].decode(
            "ascii",
            errors="replace",
        )

        virtual_size = read_u32(
            data,
            offset + 8,
        )

        virtual_address = read_u32(
            data,
            offset + 12,
        )

        raw_size = read_u32(
            data,
            offset + 16,
        )

        raw_pointer = read_u32(
            data,
            offset + 20,
        )

        characteristics_raw = read_u32(
            data,
            offset + 36,
        )

        section_data = b""

        if (
            raw_size > 0
            and raw_pointer < len(data)
        ):
            raw_end = min(
                raw_pointer + raw_size,
                len(data),
            )

            section_data = data[
                raw_pointer:
                raw_end
            ]

        sections.append(
            SectionInfo(
                name=name,
                virtual_size=virtual_size,
                virtual_address=virtual_address,
                raw_size=raw_size,
                raw_pointer=raw_pointer,
                characteristics_raw=(
                    characteristics_raw
                ),
                characteristics=(
                    format_characteristics(
                        characteristics_raw
                    )
                ),
                entropy=calculate_entropy(
                    section_data
                ),
            )
        )

    return sections


def rva_to_offset(
    rva: int,
    sections: list[SectionInfo],
) -> int | None:
    """
    Convert a PE RVA to a file offset.

    Returns None when the RVA points into virtual-only
    section padding rather than file-backed data.
    """
    if rva < 0:
        return None

    for section in sections:
        start = section.virtual_address

        span = max(
            section.virtual_size,
            section.raw_size,
        )

        end = start + span

        if start <= rva < end:
            delta = rva - start

            if delta >= section.raw_size:
                return None

            return (
                section.raw_pointer
                + delta
            )

    return None


def section_for_rva(
    rva: int,
    sections: list[SectionInfo],
) -> SectionInfo | None:
    """
    Return the section containing a given RVA.
    """
    if rva < 0:
        return None

    for section in sections:
        start = section.virtual_address

        span = max(
            section.virtual_size,
            section.raw_size,
        )

        end = start + span

        if start <= rva < end:
            return section

    return None