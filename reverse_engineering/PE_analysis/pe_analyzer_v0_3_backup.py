from __future__ import annotations

import argparse
import json
import math
import struct
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from reverse_engineering.PE_analysis.certificate_analysis import (
    parse_pe_security_directory,
)
from reverse_engineering.PE_analysis.indicators import (
    generate_indicators,
)


# ============================================================================
# PE CONSTANTS
# ============================================================================

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

# PE data-directory indexes.
DIRECTORY_EXPORT = 0
DIRECTORY_IMPORT = 1
DIRECTORY_RESOURCE = 2
DIRECTORY_EXCEPTION = 3
DIRECTORY_SECURITY = 4
DIRECTORY_BASERELOC = 5
DIRECTORY_DEBUG = 6
DIRECTORY_ARCHITECTURE = 7
DIRECTORY_GLOBALPTR = 8
DIRECTORY_TLS = 9
DIRECTORY_LOAD_CONFIG = 10
DIRECTORY_BOUND_IMPORT = 11
DIRECTORY_IAT = 12
DIRECTORY_DELAY_IMPORT = 13
DIRECTORY_COM_DESCRIPTOR = 14

DATA_DIRECTORY_NAMES = {
    0: "EXPORT",
    1: "IMPORT",
    2: "RESOURCE",
    3: "EXCEPTION",
    4: "SECURITY",
    5: "BASERELOC",
    6: "DEBUG",
    7: "ARCHITECTURE",
    8: "GLOBALPTR",
    9: "TLS",
    10: "LOAD_CONFIG",
    11: "BOUND_IMPORT",
    12: "IAT",
    13: "DELAY_IMPORT",
    14: "COM_DESCRIPTOR",
    15: "RESERVED",
}


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass(slots=True)
class DataDirectory:
    index: int
    name: str
    virtual_address: int
    size: int


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


# ============================================================================
# LOW-LEVEL HELPERS
# ============================================================================

def read_struct(
    data: bytes,
    offset: int,
    fmt: str,
):
    """
    Safely unpack a structure from a byte buffer.
    """
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
    """
    Read an ASCII null-terminated string.
    """
    if offset < 0 or offset >= len(data):
        return ""

    end = min(
        len(data),
        offset + maximum,
    )

    chunk = data[offset:end]

    nul = chunk.find(b"\x00")

    if nul >= 0:
        chunk = chunk[:nul]

    return chunk.decode(
        "ascii",
        errors="replace",
    )


def calculate_entropy(
    data: bytes,
) -> float:
    """
    Shannon entropy in the range 0..8.
    """
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
        entropy -= probability * math.log2(
            probability
        )

    return round(
        entropy,
        4,
    )


def format_characteristics(
    value: int,
) -> str:
    """
    Convert common IMAGE_SCN_* memory flags
    into readable text.
    """
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


# ============================================================================
# RVA / FILE OFFSET HANDLING
# ============================================================================

def rva_to_offset(
    rva: int,
    sections: list[SectionInfo],
) -> int | None:
    """
    Convert a PE RVA to a file offset.

    Returns None when the RVA cannot be mapped to
    file-backed section data.
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

            # RVA may point into virtual padding that
            # has no corresponding bytes in the file.
            if delta >= section.raw_size:
                return None

            offset = (
                section.raw_pointer
                + delta
            )

            if 0 <= offset < len(
                # We don't have the file buffer here,
                # so only validate the numerical range.
                b"\x00" * 0
            ):
                return offset

            return offset

    return None


# ============================================================================
# SECTION PARSING
# ============================================================================

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


# ============================================================================
# DATA DIRECTORIES
# ============================================================================

def parse_data_directories(
    data: bytes,
    optional_offset: int,
    is_64_bit: bool,
    size_of_optional_header: int,
) -> list[DataDirectory]:
    """
    Parse IMAGE_DATA_DIRECTORY entries.
    """
    directory_base = (
        optional_offset
        + (
            112
            if is_64_bit
            else 96
        )
    )

    count_offset = (
        optional_offset
        + (
            108
            if is_64_bit
            else 92
        )
    )

    if count_offset + 4 > len(data):
        return []

    number_of_directories = read_u32(
        data,
        count_offset,
    )

    header_directory_start = (
        112
        if is_64_bit
        else 96
    )

    if (
        size_of_optional_header
        < header_directory_start
    ):
        return []

    max_available = (
        size_of_optional_header
        - header_directory_start
    ) // 8

    directory_count = min(
        number_of_directories,
        max_available,
        16,
    )

    directories: list[DataDirectory] = []

    for index in range(
        directory_count
    ):
        offset = (
            directory_base
            + (index * 8)
        )

        if offset + 8 > len(data):
            break

        virtual_address, size = (
            read_struct(
                data,
                offset,
                "<II",
            )
        )

        directories.append(
            DataDirectory(
                index=index,
                name=DATA_DIRECTORY_NAMES.get(
                    index,
                    f"DIRECTORY_{index}",
                ),
                virtual_address=(
                    virtual_address
                ),
                size=size,
            )
        )

    return directories


def get_directory(
    directories: list[DataDirectory],
    index: int,
) -> DataDirectory | None:
    for directory in directories:
        if directory.index == index:
            return directory

    return None


# ============================================================================
# IMPORT ANALYSIS
# ============================================================================

def parse_imports(
    data: bytes,
    import_rva: int,
    import_size: int,
    sections: list[SectionInfo],
    is_64_bit: bool,
) -> list[dict]:
    """
    Parse the PE import descriptor table and
    imported function names.
    """
    if import_rva == 0:
        return []

    import_offset = rva_to_offset(
        import_rva,
        sections,
    )

    if import_offset is None:
        return []

    results: list[dict] = []

    descriptor_offset = import_offset

    if import_size:
        max_descriptors = max(
            1,
            import_size // 20,
        )
    else:
        # Defensive bound for malformed binaries.
        max_descriptors = 4096

    for _ in range(
        max_descriptors
    ):
        if (
            descriptor_offset + 20
            > len(data)
        ):
            break

        (
            original_first_thunk,
            timestamp,
            forwarder_chain,
            name_rva,
            first_thunk,
        ) = read_struct(
            data,
            descriptor_offset,
            "<IIIII",
        )

        # Null descriptor terminates table.
        if (
            original_first_thunk == 0
            and timestamp == 0
            and forwarder_chain == 0
            and name_rva == 0
            and first_thunk == 0
        ):
            break

        name_offset = rva_to_offset(
            name_rva,
            sections,
        )

        if name_offset is None:
            descriptor_offset += 20
            continue

        dll_name = read_c_string(
            data,
            name_offset,
        )

        lookup_rva = (
            original_first_thunk
            or first_thunk
        )

        lookup_offset = rva_to_offset(
            lookup_rva,
            sections,
        )

        functions: list[str] = []

        if lookup_offset is not None:
            thunk_size = (
                8
                if is_64_bit
                else 4
            )

            ordinal_flag = (
                0x8000000000000000
                if is_64_bit
                else 0x80000000
            )

            current = lookup_offset

            # Defensive bound against malformed tables.
            for _ in range(
                10000
            ):
                if (
                    current
                    + thunk_size
                    > len(data)
                ):
                    break

                if is_64_bit:
                    thunk_value = (
                        read_struct(
                            data,
                            current,
                            "<Q",
                        )[0]
                    )
                else:
                    thunk_value = (
                        read_struct(
                            data,
                            current,
                            "<I",
                        )[0]
                    )

                if thunk_value == 0:
                    break

                if thunk_value & ordinal_flag:
                    ordinal = (
                        thunk_value
                        & 0xFFFF
                    )

                    functions.append(
                        f"Ordinal_{ordinal}"
                    )

                else:
                    if is_64_bit:
                        hint_name_rva = (
                            thunk_value
                            & 0x7FFFFFFFFFFFFFFF
                        )
                    else:
                        hint_name_rva = (
                            thunk_value
                            & 0x7FFFFFFF
                        )

                    hint_name_offset = (
                        rva_to_offset(
                            hint_name_rva,
                            sections,
                        )
                    )

                    if (
                        hint_name_offset
                        is not None
                        and hint_name_offset + 2
                        <= len(data)
                    ):
                        function_name = (
                            read_c_string(
                                data,
                                hint_name_offset + 2,
                            )
                        )

                        if function_name:
                            functions.append(
                                function_name
                            )

                current += thunk_size

        results.append(
            {
                "dll": dll_name,
                "timestamp": timestamp,
                "functions": functions,
                "function_count": len(
                    functions
                ),
            }
        )

        descriptor_offset += 20

    return results


# ============================================================================
# EXPORT ANALYSIS
# ============================================================================

def parse_exports(
    data: bytes,
    export_rva: int,
    sections: list[SectionInfo],
) -> list[str]:
    """
    Parse named PE exports.
    """
    if export_rva == 0:
        return []

    export_offset = rva_to_offset(
        export_rva,
        sections,
    )

    if export_offset is None:
        return []

    if (
        export_offset + 40
        > len(data)
    ):
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

        ordinal_index = read_struct(
            data,
            ordinal_offset,
            "<H",
        )[0]

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


# ============================================================================
# OVERLAY DETECTION
# ============================================================================

def detect_overlay(
    data_size: int,
    sections: list[SectionInfo],
    security_directory: DataDirectory | None,
) -> dict:
    """
    Detect bytes after the last file-backed section.

    The PE security directory is special because its
    VirtualAddress is a FILE OFFSET rather than an RVA.
    """
    max_section_end = 0

    for section in sections:
        if section.raw_size:
            max_section_end = max(
                max_section_end,
                section.raw_end,
            )

    overlay_offset = max_section_end

    if (
        security_directory is not None
        and security_directory.virtual_address
        and security_directory.size
    ):
        certificate_end = (
            security_directory.virtual_address
            + security_directory.size
        )

        overlay_offset = max(
            overlay_offset,
            certificate_end,
        )

    overlay_size = max(
        0,
        data_size - overlay_offset,
    )

    return {
        "offset": overlay_offset,
        "size": overlay_size,
        "present": overlay_size > 0,
    }


# ============================================================================
# PE PARSER
# ============================================================================

def parse_pe(
    path: Path,
) -> dict:
    """
    Perform complete static PE analysis.
    """
    data = path.read_bytes()

    # ------------------------------------------------------------------------
    # Basic validation
    # ------------------------------------------------------------------------

    if len(data) < 64:
        raise ValueError(
            "File is too small to be a PE file."
        )

    if data[:2] != DOS_MAGIC:
        raise ValueError(
            "Missing MZ DOS signature."
        )

    pe_offset = read_u32(
        data,
        0x3C,
    )

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

    # ------------------------------------------------------------------------
    # COFF header
    # ------------------------------------------------------------------------

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

    # ------------------------------------------------------------------------
    # Optional header
    # ------------------------------------------------------------------------

    magic = read_struct(
        data,
        optional_offset,
        "<H",
    )[0]

    if magic == PE32_MAGIC:
        bitness = "PE32 (32-bit)"
        is_64_bit = False

        image_base = read_u32(
            data,
            optional_offset + 28,
        )

    elif magic == PE32_PLUS_MAGIC:
        bitness = "PE32+ (64-bit)"
        is_64_bit = True

        image_base = read_struct(
            data,
            optional_offset + 24,
            "<Q",
        )[0]

    else:
        raise ValueError(
            "Unsupported PE optional-header magic: "
            f"0x{magic:X}"
        )

    entry_point = read_u32(
        data,
        optional_offset + 16,
    )

    # ------------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------------

    sections_offset = (
        optional_offset
        + size_of_optional_header
    )

    section_table_end = (
        sections_offset
        + (number_of_sections * 40)
    )

    if section_table_end > len(data):
        raise ValueError(
            "Section table exceeds file size."
        )

    sections = parse_sections(
        data,
        sections_offset,
        number_of_sections,
    )

    # ------------------------------------------------------------------------
    # Data directories
    # ------------------------------------------------------------------------

    directories = parse_data_directories(
        data=data,
        optional_offset=optional_offset,
        is_64_bit=is_64_bit,
        size_of_optional_header=(
            size_of_optional_header
        ),
    )

    export_directory = get_directory(
        directories,
        DIRECTORY_EXPORT,
    )

    import_directory = get_directory(
        directories,
        DIRECTORY_IMPORT,
    )

    security_directory = get_directory(
        directories,
        DIRECTORY_SECURITY,
    )

    # ------------------------------------------------------------------------
    # Imports
    # ------------------------------------------------------------------------

    imports = parse_imports(
        data=data,
        import_rva=(
            import_directory.virtual_address
            if import_directory
            else 0
        ),
        import_size=(
            import_directory.size
            if import_directory
            else 0
        ),
        sections=sections,
        is_64_bit=is_64_bit,
    )

    # ------------------------------------------------------------------------
    # Exports
    # ------------------------------------------------------------------------

    exports = parse_exports(
        data=data,
        export_rva=(
            export_directory.virtual_address
            if export_directory
            else 0
        ),
        sections=sections,
    )

    # ------------------------------------------------------------------------
    # Overlay
    # ------------------------------------------------------------------------

    overlay = detect_overlay(
        data_size=len(data),
        sections=sections,
        security_directory=security_directory,
    )

    # ------------------------------------------------------------------------
    # Certificate analysis
    # ------------------------------------------------------------------------

    try:
        certificate_analysis = (
            parse_pe_security_directory(
                data
            )
        )
    except ValueError as exc:
        certificate_analysis = {
            "present": False,
            "file_offset": 0,
            "size": 0,
            "entries": [],
            "error": str(exc),
        }

    # ------------------------------------------------------------------------
    # Main report
    # ------------------------------------------------------------------------

    report = {
        "tool": "SECURITY-MISC",
        "module": "pe_analyzer",
        "analysis_version": "0.3.0",
        "analysis_time": (
            datetime.now(timezone.utc)
            .isoformat()
        ),
        "file": str(path),
        "size_bytes": len(data),

        "headers": {
            "dos_magic": "MZ",
            "pe_signature": "PE\\x00\\x00",
            "pe_offset": pe_offset,

            "machine": MACHINE_TYPES.get(
                machine,
                f"Unknown (0x{machine:04X})",
            ),

            "machine_code": (
                f"0x{machine:04X}"
            ),

            "bitness": bitness,

            "number_of_sections": (
                number_of_sections
            ),

            "timestamp_raw": timestamp,

            "pointer_to_symbol_table": (
                pointer_to_symbol_table
            ),

            "number_of_symbols": (
                number_of_symbols
            ),

            "optional_header_magic": (
                f"0x{magic:03X}"
            ),

            "optional_header_size": (
                size_of_optional_header
            ),

            "characteristics": (
                f"0x{characteristics:04X}"
            ),

            "entry_point_rva": (
                f"0x{entry_point:08X}"
            ),

            "image_base": (
                f"0x{image_base:X}"
            ),
        },

        "data_directories": [
            asdict(directory)
            for directory in directories
        ],

        "sections": [
            asdict(section)
            for section in sections
        ],

        "imports": {
            "dll_count": len(imports),
            "function_count": sum(
                item["function_count"]
                for item in imports
            ),
            "libraries": imports,
        },

        "exports": {
            "count": len(exports),
            "functions": exports,
        },

        "overlay": overlay,

        "security_directory": (
            asdict(security_directory)
            if security_directory
            else None
        ),

        "certificate_analysis": (
            certificate_analysis
        ),
    }

    # ------------------------------------------------------------------------
    # Static indicators
    # ------------------------------------------------------------------------

    indicators = generate_indicators(
        report
    )

    report["indicators"] = indicators

    severity_counts = {
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for indicator in indicators:
        severity = str(
            indicator.get(
                "severity",
                "info",
            )
        ).lower()

        if severity in severity_counts:
            severity_counts[
                severity
            ] += 1

    report["indicator_summary"] = {
        "total": len(indicators),
        "by_severity": severity_counts,
    }

    return report


# ============================================================================
# TERMINAL REPORTING
# ============================================================================

def print_report(
    report: dict,
) -> None:
    headers = report["headers"]
    imports = report["imports"]
    exports = report["exports"]
    indicators = report["indicators"]
    indicator_summary = report[
        "indicator_summary"
    ]

    print()
    print("=" * 88)
    print(
        "SECURITY-MISC :: PE STATIC ANALYSIS"
    )
    print("=" * 88)

    print(
        f"File             : "
        f"{report['file']}"
    )

    print(
        f"Size             : "
        f"{report['size_bytes']:,} bytes"
    )

    print(
        f"Analysis version : "
        f"{report['analysis_version']}"
    )

    # ------------------------------------------------------------------------
    # PE Headers
    # ------------------------------------------------------------------------

    print()
    print("PE HEADERS")
    print("-" * 88)

    print(
        f"Architecture     : "
        f"{headers['machine']}"
    )

    print(
        f"Format           : "
        f"{headers['bitness']}"
    )

    print(
        f"Sections         : "
        f"{headers['number_of_sections']}"
    )

    print(
        f"PE offset        : "
        f"0x{headers['pe_offset']:X}"
    )

    print(
        f"Entry point RVA  : "
        f"{headers['entry_point_rva']}"
    )

    print(
        f"Image base       : "
        f"{headers['image_base']}"
    )

    print(
        f"Characteristics  : "
        f"{headers['characteristics']}"
    )

    # ------------------------------------------------------------------------
    # Data directories
    # ------------------------------------------------------------------------

    print()
    print("DATA DIRECTORIES")
    print("-" * 88)

    active_directories = [
        directory
        for directory in report[
            "data_directories"
        ]
        if (
            directory["virtual_address"]
            or directory["size"]
        )
    ]

    if not active_directories:
        print(
            "[+] No populated data directories."
        )

    else:
        for directory in (
            active_directories
        ):
            print(
                f"{directory['name']:<20}"
                f"Address/Offset: "
                f"0x{directory['virtual_address']:08X}  "
                f"Size: "
                f"{directory['size']:,}"
            )

    # ------------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------------

    print()
    print("SECTIONS")
    print("-" * 88)

    print(
        f"{'NAME':<10}"
        f"{'VIRT SIZE':>12}"
        f"{'RAW SIZE':>12}"
        f"{'RVA':>12}"
        f"{'ENTROPY':>10}"
        f"  FLAGS"
    )

    for section in report[
        "sections"
    ]:
        print(
            f"{section['name']:<10}"
            f"{section['virtual_size']:>12,}"
            f"{section['raw_size']:>12,}"
            f"{section['virtual_address']:>12X}"
            f"{section['entropy']:>10.4f}"
            f"  {section['characteristics']}"
        )

    # ------------------------------------------------------------------------
    # Imports
    # ------------------------------------------------------------------------

    print()
    print("IMPORTS")
    print("-" * 88)

    print(
        f"DLLs             : "
        f"{imports['dll_count']}"
    )

    print(
        f"Functions        : "
        f"{imports['function_count']}"
    )

    for library in imports[
        "libraries"
    ]:
        print(
            f"\n  {library['dll']} "
            f"({library['function_count']} functions)"
        )

        for function in library[
            "functions"
        ][:30]:
            print(
                f"    {function}"
            )

        if library[
            "function_count"
        ] > 30:
            print(
                "    ..."
            )

    # ------------------------------------------------------------------------
    # Exports
    # ------------------------------------------------------------------------

    print()
    print("EXPORTS")
    print("-" * 88)

    print(
        f"Exported symbols : "
        f"{exports['count']}"
    )

    for function in exports[
        "functions"
    ][:50]:
        print(
            f"  {function}"
        )

    if exports["count"] > 50:
        print("  ...")

    # ------------------------------------------------------------------------
    # Overlay
    # ------------------------------------------------------------------------

    print()
    print("OVERLAY")
    print("-" * 88)

    overlay = report["overlay"]

    print(
        f"Present          : "
        f"{overlay['present']}"
    )

    print(
        f"Offset           : "
        f"0x{overlay['offset']:X}"
    )

    print(
        f"Size             : "
        f"{overlay['size']:,} bytes"
    )

    # ------------------------------------------------------------------------
    # Security / certificate directory
    # ------------------------------------------------------------------------

    print()
    print("SECURITY DIRECTORY")
    print("-" * 88)

    security = report[
        "security_directory"
    ]

    if (
        security is not None
        and security["size"]
    ):
        print(
            "[+] Certificate/security "
            "directory is present."
        )

        print(
            f"    File offset   : "
            f"0x{security['virtual_address']:X}"
        )

        print(
            f"    Size          : "
            f"{security['size']:,} bytes"
        )

    else:
        print(
            "[-] No certificate/security "
            "directory reported."
        )

    # ------------------------------------------------------------------------
    # Certificate analysis
    # ------------------------------------------------------------------------

    print()
    print("CERTIFICATE ANALYSIS")
    print("-" * 88)

    certificate = report[
        "certificate_analysis"
    ]

    if certificate.get(
        "error"
    ):
        print(
            f"[!] Certificate parser error: "
            f"{certificate['error']}"
        )

    elif not certificate[
        "present"
    ]:
        print(
            "[+] No PE certificate table detected."
        )

    else:
        print(
            "[+] PE certificate table detected."
        )

        print(
            f"    Offset        : "
            f"0x{certificate['file_offset']:X}"
        )

        print(
            f"    Size          : "
            f"{certificate['size']:,} bytes"
        )

        print(
            f"    Entries       : "
            f"{len(certificate['entries'])}"
        )

        for index, entry in enumerate(
            certificate["entries"],
            start=1,
        ):
            print(
                f"    Entry {index}"
            )

            print(
                f"      Length      : "
                f"{entry['length']:,}"
            )

            print(
                f"      Revision    : "
                f"{entry['revision']}"
            )

            print(
                f"      Type        : "
                f"{entry['type']}"
            )

            print(
                f"      PKCS signed : "
                f"{entry['is_pkcs_signed_data']}"
            )

    # ------------------------------------------------------------------------
    # Static indicators
    # ------------------------------------------------------------------------

    print()
    print("STATIC INDICATORS")
    print("-" * 88)

    print(
        f"Total            : "
        f"{indicator_summary['total']}"
    )

    print(
        f"High             : "
        f"{indicator_summary['by_severity']['high']}"
    )

    print(
        f"Medium           : "
        f"{indicator_summary['by_severity']['medium']}"
    )

    print(
        f"Low              : "
        f"{indicator_summary['by_severity']['low']}"
    )

    print(
        f"Info             : "
        f"{indicator_summary['by_severity']['info']}"
    )

    if not indicators:
        print()
        print(
            "[+] No static indicators generated."
        )

    else:
        print()

        for indicator in indicators:
            severity = str(
                indicator.get(
                    "severity",
                    "info",
                )
            ).upper()

            print(
                f"[{severity:<6}] "
                f"{indicator.get('name', 'Unnamed')}"
            )

            print(
                f"         "
                f"{indicator.get('description', '')}"
            )

    print()
    print("=" * 88)


# ============================================================================
# JSON REPORTING
# ============================================================================

def save_report(
    report: dict,
    output: Path,
) -> None:
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

    print(
        f"[+] JSON report: {output}"
    )


# ============================================================================
# CLI
# ============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "SECURITY-MISC read-only "
            "Windows PE static analyzer."
        )
    )

    parser.add_argument(
        "file",
        help="Path to the PE file.",
    )

    parser.add_argument(
        "--json",
        type=Path,
        help=(
            "Write the complete "
            "analysis report to JSON."
        ),
    )

    return parser


# ============================================================================
# ENTRY POINT
# ============================================================================

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

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
        report = parse_pe(path)

        print_report(report)

        if args.json:
            save_report(
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
            f"[!] File-system error: {exc}"
        )
        return 3

    except ValueError as exc:
        print(
            f"[!] PE parsing error: {exc}"
        )
        return 4

    except Exception as exc:
        print(
            "[!] Unexpected analyzer error: "
            f"{exc}"
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())