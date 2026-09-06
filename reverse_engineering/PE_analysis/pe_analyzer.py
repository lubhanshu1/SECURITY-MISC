from __future__ import annotations

import argparse
import hashlib
import json
import struct
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .certificates import (
    parse_certificate_table,
    summarize_certificates,
)
from .exports import parse_exports
from .imports import (
    parse_imports,
    summarize_imports,
)
from .indicators import generate_indicators
from .parser import load_pe
from .sections import parse_sections

from reverse_engineering.strings.string_analyzer import (
    analyze_file as analyze_strings_file,
)


# ============================================================================
# VERSION
# ============================================================================

ANALYSIS_VERSION = "0.7.0"


# ============================================================================
# PE DATA DIRECTORY NAMES
# ============================================================================

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
# STATIC IMPORT CATEGORIES
# ============================================================================

SUSPICIOUS_IMPORT_GROUPS: dict[str, set[str]] = {
    "process_injection": {
        "VirtualAlloc",
        "VirtualAllocEx",
        "VirtualProtect",
        "VirtualProtectEx",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "NtCreateThreadEx",
        "QueueUserAPC",
        "OpenProcess",
    },
    "process_execution": {
        "CreateProcessA",
        "CreateProcessW",
        "CreateProcessAsUserA",
        "CreateProcessAsUserW",
        "WinExec",
        "ShellExecuteA",
        "ShellExecuteW",
        "ShellExecuteExA",
        "ShellExecuteExW",
    },
    "networking": {
        "InternetOpenA",
        "InternetOpenW",
        "InternetOpenUrlA",
        "InternetOpenUrlW",
        "URLDownloadToFileA",
        "URLDownloadToFileW",
        "HttpOpenRequestA",
        "HttpOpenRequestW",
        "WinHttpOpen",
        "WinHttpConnect",
        "WinHttpOpenRequest",
        "WinHttpSendRequest",
    },
    "dynamic_loading": {
        "LoadLibraryA",
        "LoadLibraryW",
        "LoadLibraryExA",
        "LoadLibraryExW",
        "GetProcAddress",
    },
    "memory_mapping": {
        "CreateFileMappingA",
        "CreateFileMappingW",
        "MapViewOfFile",
        "UnmapViewOfFile",
    },
    "anti_analysis": {
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "OutputDebugStringA",
        "OutputDebugStringW",
    },
}


# ============================================================================
# HASHING
# ============================================================================

def calculate_hashes(
    data: bytes,
) -> dict[str, str]:
    """
    Calculate common hashes for the analyzed file.

    The input is treated only as bytes.
    """
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


# ============================================================================
# DATA DIRECTORY PARSING
# ============================================================================

def parse_data_directories(
    data: bytes,
    optional_offset: int,
    is_64_bit: bool,
    optional_header_size: int,
) -> list[dict]:
    """
    Parse the IMAGE_DATA_DIRECTORY array.

    PE32:
        +96

    PE32+:
        +112
    """
    directory_base = (
        112
        if is_64_bit
        else 96
    )

    count_base = (
        108
        if is_64_bit
        else 92
    )

    directory_offset = (
        optional_offset
        + directory_base
    )

    count_offset = (
        optional_offset
        + count_base
    )

    if count_offset + 4 > len(data):
        return []

    number_of_directories = struct.unpack_from(
        "<I",
        data,
        count_offset,
    )[0]

    if optional_header_size < directory_base:
        return []

    max_available = (
        optional_header_size
        - directory_base
    ) // 8

    count = min(
        number_of_directories,
        max_available,
        16,
    )

    directories: list[dict] = []

    for index in range(count):
        offset = (
            directory_offset
            + index * 8
        )

        if offset + 8 > len(data):
            break

        virtual_address, size = (
            struct.unpack_from(
                "<II",
                data,
                offset,
            )
        )

        directories.append(
            {
                "index": index,
                "name": DATA_DIRECTORY_NAMES.get(
                    index,
                    f"DIRECTORY_{index}",
                ),
                "virtual_address": virtual_address,
                "size": size,
            }
        )

    return directories


# ============================================================================
# SECTION INTELLIGENCE
# ============================================================================

def analyze_sections(
    sections: list[Any],
    entry_point_rva: int,
) -> dict:
    """
    Derive higher-level static observations from PE sections.
    """
    executable_sections: list[str] = []
    writable_sections: list[str] = []
    executable_writable_sections: list[str] = []
    high_entropy_sections: list[str] = []
    empty_sections: list[str] = []
    unusual_names: list[str] = []

    entry_point_section: str | None = None

    standard_names = {
        ".text",
        ".code",
        ".rdata",
        ".data",
        ".idata",
        ".edata",
        ".rsrc",
        ".reloc",
        ".pdata",
        ".bss",
        ".tls",
        ".crt",
        ".00cfg",
    }

    for section in sections:
        name = str(
            section.name
        ).strip()

        if section.is_executable:
            executable_sections.append(
                name
            )

        if section.is_writable:
            writable_sections.append(
                name
            )

        if (
            section.is_executable
            and section.is_writable
        ):
            executable_writable_sections.append(
                name
            )

        if section.entropy >= 7.2:
            high_entropy_sections.append(
                name
            )

        if (
            section.raw_size == 0
            and section.virtual_size > 0
        ):
            empty_sections.append(
                name
            )

        normalized = name.lower()

        if (
            normalized
            and normalized not in standard_names
        ):
            unusual_names.append(
                name
            )

        start = section.virtual_address

        span = max(
            section.virtual_size,
            section.raw_size,
        )

        end = start + span

        if (
            start
            <= entry_point_rva
            < end
        ):
            entry_point_section = name

    return {
        "count": len(sections),
        "executable_sections": executable_sections,
        "writable_sections": writable_sections,
        "executable_writable_sections": (
            executable_writable_sections
        ),
        "high_entropy_sections": (
            high_entropy_sections
        ),
        "empty_raw_sections": (
            empty_sections
        ),
        "unusual_names": unusual_names,
        "entry_point_section": (
            entry_point_section
        ),
        "flags": {
            "has_executable_writable_section": (
                bool(
                    executable_writable_sections
                )
            ),
            "has_high_entropy_section": (
                bool(
                    high_entropy_sections
                )
            ),
            "has_empty_raw_section": (
                bool(empty_sections)
            ),
            "has_unusual_section_name": (
                bool(unusual_names)
            ),
        },
    }


# ============================================================================
# IMPORT INTELLIGENCE
# ============================================================================

def analyze_imports(
    imports: list[dict],
) -> dict:
    """
    Analyze imported functions and group them into
    broad static-analysis categories.
    """
    all_functions: list[str] = []

    for library in imports:
        for function in library.get(
            "functions",
            [],
        ):
            if function:
                all_functions.append(
                    str(function)
                )

    unique_functions = {
        function.lower(): function
        for function in all_functions
    }

    matched_groups: dict[
        str,
        list[str],
    ] = {}

    for (
        group_name,
        names,
    ) in SUSPICIOUS_IMPORT_GROUPS.items():
        matches: list[str] = []

        for name in names:
            actual = unique_functions.get(
                name.lower()
            )

            if actual:
                matches.append(
                    actual
                )

        if matches:
            matched_groups[
                group_name
            ] = sorted(
                set(matches),
                key=str.lower,
            )

    suspicious_functions = {
        function.lower()
        for functions in matched_groups.values()
        for function in functions
    }

    return {
        **summarize_imports(
            imports
        ),

        "unique_functions": len(
            unique_functions
        ),

        "suspicious_groups": (
            matched_groups
        ),

        "suspicious_function_count": len(
            suspicious_functions
        ),
    }


# ============================================================================
# STRING INTELLIGENCE
# ============================================================================

def summarize_strings(
    string_report: dict,
) -> dict:
    """
    Produce a compact summary of the string-analysis
    subsystem.
    """
    counts = string_report.get(
        "counts",
        {},
    )

    classifications = string_report.get(
        "classifications",
        {},
    )

    return {
        "ascii": counts.get(
            "ascii",
            0,
        ),

        "utf16le": counts.get(
            "utf16le",
            0,
        ),

        "total_unique": counts.get(
            "total_unique",
            0,
        ),

        "urls": len(
            classifications.get(
                "urls",
                [],
            )
        ),

        "ipv4": len(
            classifications.get(
                "ipv4",
                [],
            )
        ),

        "emails": len(
            classifications.get(
                "emails",
                [],
            )
        ),

        "windows_paths": len(
            classifications.get(
                "windows_paths",
                [],
            )
        ),

        "unc_paths": len(
            classifications.get(
                "unc_paths",
                [],
            )
        ),

        "registry_paths": len(
            classifications.get(
                "registry_paths",
                [],
            )
        ),

        "powershell_indicators": len(
            classifications.get(
                "powershell_indicators",
                [],
            )
        ),

        "command_indicators": len(
            classifications.get(
                "command_indicators",
                [],
            )
        ),

        "suspicious_apis": len(
            classifications.get(
                "suspicious_apis",
                [],
            )
        ),
    }


# ============================================================================
# INDICATOR SUMMARY
# ============================================================================

def calculate_indicator_summary(
    indicators: list[dict],
) -> dict:
    """
    Aggregate indicator counts by severity.
    """
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

    return {
        "total": len(indicators),
        "by_severity": severity_counts,
    }


# ============================================================================
# RISK SCORING
# ============================================================================

def calculate_risk_score(
    report: dict,
) -> dict:
    """
    Produce a deterministic static-analysis score.

    This is a prioritization aid, NOT a malware verdict.
    """
    score = 0
    reasons: list[dict] = []

    def add(
        points: int,
        reason: str,
    ) -> None:
        nonlocal score

        score += points

        reasons.append(
            {
                "points": points,
                "reason": reason,
            }
        )

    section_data = report[
        "section_intelligence"
    ]

    if section_data[
        "flags"
    ][
        "has_executable_writable_section"
    ]:
        add(
            25,
            "Executable and writable PE section detected.",
        )

    if section_data[
        "flags"
    ][
        "has_high_entropy_section"
    ]:
        add(
            15,
            "High-entropy PE section detected.",
        )

    if section_data[
        "flags"
    ][
        "has_empty_raw_section"
    ]:
        add(
            3,
            "Section has virtual data without a raw file body.",
        )

    if section_data[
        "flags"
    ][
        "has_unusual_section_name"
    ]:
        add(
            5,
            "Unusual PE section name detected.",
        )

    import_data = report[
        "import_intelligence"
    ]

    for group_name in import_data[
        "suspicious_groups"
    ]:
        if group_name == "process_injection":
            add(
                25,
                "Process-injection-related API imports detected.",
            )

        elif group_name == "process_execution":
            add(
                15,
                "Process-execution-related API imports detected.",
            )

        elif group_name == "networking":
            add(
                10,
                "Networking-related API imports detected.",
            )

        elif group_name == "dynamic_loading":
            add(
                10,
                "Dynamic loading APIs detected.",
            )

        elif group_name == "memory_mapping":
            add(
                5,
                "Memory-mapping APIs detected.",
            )

        elif group_name == "anti_analysis":
            add(
                10,
                "Anti-analysis/debugger-detection APIs detected.",
            )

    string_data = report[
        "strings"
    ][
        "summary"
    ]

    if string_data[
        "powershell_indicators"
    ]:
        add(
            20,
            "PowerShell-related string artifacts detected.",
        )

    if string_data[
        "command_indicators"
    ]:
        add(
            10,
            "Command-execution-related string artifacts detected.",
        )

    if string_data[
        "urls"
    ]:
        add(
            5,
            "URL artifacts detected.",
        )

    if string_data[
        "ipv4"
    ]:
        add(
            5,
            "IPv4 artifacts detected.",
        )

    if string_data[
        "registry_paths"
    ]:
        add(
            5,
            "Registry path artifacts detected.",
        )

    if string_data[
        "suspicious_apis"
    ]:
        add(
            10,
            "Suspicious API names detected in static strings.",
        )

    indicator_counts = report[
        "indicator_summary"
    ][
        "by_severity"
    ]

    if indicator_counts["high"]:
        points = (
            indicator_counts["high"]
            * 15
        )

        score += points

        reasons.append(
            {
                "points": points,
                "reason": (
                    "High-severity static indicators "
                    "were generated."
                ),
            }
        )

    if indicator_counts["medium"]:
        points = (
            indicator_counts["medium"]
            * 7
        )

        score += points

        reasons.append(
            {
                "points": points,
                "reason": (
                    "Medium-severity static indicators "
                    "were generated."
                ),
            }
        )

    if indicator_counts["low"]:
        points = (
            indicator_counts["low"]
            * 2
        )

        score += points

        reasons.append(
            {
                "points": points,
                "reason": (
                    "Low-severity static indicators "
                    "were generated."
                ),
            }
        )

    score = max(
        0,
        min(
            score,
            100,
        ),
    )

    if score >= 70:
        rating = "HIGH"
    elif score >= 40:
        rating = "MEDIUM"
    elif score >= 15:
        rating = "LOW"
    else:
        rating = "MINIMAL"

    return {
        "score": score,
        "rating": rating,
        "method": (
            "Deterministic static observation scoring; "
            "not a malware verdict."
        ),
        "reasons": reasons,
    }


# ============================================================================
# REPORT BUILDER
# ============================================================================

def build_report(
    path: Path,
) -> dict:
    """
    Build the complete SECURITY-MISC PE report.

    The target file is read as bytes and analyzed statically.
    It is never executed.
    """
    started = time.perf_counter()

    path = (
        Path(path)
        .expanduser()
        .resolve()
    )

    data, headers = load_pe(
        path
    )

    # ------------------------------------------------------------------------
    # File identity
    # ------------------------------------------------------------------------

    hashes = calculate_hashes(
        data
    )

    # ------------------------------------------------------------------------
    # PE basics
    # ------------------------------------------------------------------------

    optional_offset = (
        headers.pe_offset
        + 4
        + 20
    )

    is_64_bit = (
        headers.optional_magic
        == 0x20B
    )

    # ------------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------------

    sections_offset = (
        optional_offset
        + headers.size_of_optional_header
    )

    sections = parse_sections(
        data,
        sections_offset,
        headers.number_of_sections,
    )

    section_intelligence = (
        analyze_sections(
            sections,
            headers.entry_point_rva,
        )
    )

    # ------------------------------------------------------------------------
    # Data directories
    # ------------------------------------------------------------------------

    directories = parse_data_directories(
        data=data,
        optional_offset=optional_offset,
        is_64_bit=is_64_bit,
        optional_header_size=(
            headers.size_of_optional_header
        ),
    )

    import_directory = next(
        (
            item
            for item in directories
            if item["index"] == 1
        ),
        None,
    )

    export_directory = next(
        (
            item
            for item in directories
            if item["index"] == 0
        ),
        None,
    )

    # ------------------------------------------------------------------------
    # Imports
    # ------------------------------------------------------------------------

    imports = parse_imports(
        data=data,
        import_rva=(
            import_directory[
                "virtual_address"
            ]
            if import_directory
            else 0
        ),
        import_size=(
            import_directory[
                "size"
            ]
            if import_directory
            else 0
        ),
        sections=sections,
        is_64_bit=is_64_bit,
    )

    import_intelligence = (
        analyze_imports(
            imports
        )
    )

    # ------------------------------------------------------------------------
    # Exports
    # ------------------------------------------------------------------------

    exports = parse_exports(
        data=data,
        export_rva=(
            export_directory[
                "virtual_address"
            ]
            if export_directory
            else 0
        ),
        sections=sections,
    )

    # ------------------------------------------------------------------------
    # Certificates
    # ------------------------------------------------------------------------

    certificate_analysis = (
        parse_certificate_table(
            data
        )
    )

    certificate_summary = (
        summarize_certificates(
            certificate_analysis
        )
    )

    # ------------------------------------------------------------------------
    # Strings
    # ------------------------------------------------------------------------

    string_report = analyze_strings_file(
        path
    )

    string_summary = summarize_strings(
        string_report
    )

    # ------------------------------------------------------------------------
    # Base report
    #
    # Keep compatibility with the earlier report:
    #   report["file"]      -> string
    #   report["size_bytes"] -> integer
    #
    # Rich file information lives under file_metadata.
    # ------------------------------------------------------------------------

    report = {
        "tool": "SECURITY-MISC",
        "module": "pe_analyzer",
        "analysis_version": (
            ANALYSIS_VERSION
        ),

        "analysis_time": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        # Backward-compatible fields.
        "file": str(path),
        "size_bytes": len(data),

        # Extended file metadata.
        "file_metadata": {
            "path": str(path),
            "name": path.name,
            "extension": path.suffix.lower(),
            "size_bytes": len(data),
            "hashes": hashes,
        },

        "hashes": hashes,

        "headers": {
            "dos_magic": "MZ",
            "pe_signature": "PE\\x00\\x00",
            "pe_offset": headers.pe_offset,

            "machine": headers.machine_name,

            "machine_code": (
                f"0x{headers.machine:04X}"
            ),

            "bitness": headers.bitness,

            "number_of_sections": (
                headers.number_of_sections
            ),

            "timestamp_raw": headers.timestamp,

            "pointer_to_symbol_table": (
                headers.pointer_to_symbol_table
            ),

            "number_of_symbols": (
                headers.number_of_symbols
            ),

            "optional_header_magic": (
                f"0x{headers.optional_magic:03X}"
            ),

            "optional_header_size": (
                headers.size_of_optional_header
            ),

            "characteristics": (
                f"0x{headers.characteristics:04X}"
            ),

            "entry_point_rva": (
                f"0x{headers.entry_point_rva:08X}"
            ),

            "image_base": (
                f"0x{headers.image_base:X}"
            ),
        },

        "data_directories": directories,

        "sections": [
            asdict(section)
            for section in sections
        ],

        "section_intelligence": (
            section_intelligence
        ),

        "imports": {
            **import_intelligence,
            "libraries": imports,
        },

        "import_intelligence": (
            import_intelligence
        ),

        "exports": {
            "count": len(exports),
            "functions": exports,
        },

        "certificate_analysis": (
            certificate_analysis
        ),

        "certificate_summary": (
            certificate_summary
        ),

        "strings": {
            "summary": string_summary,

            "classifications": (
                string_report.get(
                    "classifications",
                    {},
                )
            ),
        },
    }

    # ------------------------------------------------------------------------
    # Overlay
    # ------------------------------------------------------------------------

    max_section_end = 0

    for section in sections:
        if section.raw_size:
            max_section_end = max(
                max_section_end,
                section.raw_end,
            )

    certificate_end = 0

    if certificate_analysis.get(
        "present",
        False,
    ):
        certificate_end = (
            certificate_analysis[
                "file_offset"
            ]
            + certificate_analysis[
                "size"
            ]
        )

    file_backed_end = max(
        max_section_end,
        certificate_end,
    )

    overlay_size = max(
        0,
        len(data) - file_backed_end,
    )

    report["overlay"] = {
        "present": overlay_size > 0,
        "offset": file_backed_end,
        "size": overlay_size,
    }

    # ------------------------------------------------------------------------
    # Indicators
    # ------------------------------------------------------------------------

    indicators = generate_indicators(
        report
    )

    report["indicators"] = indicators

    report["indicator_summary"] = (
        calculate_indicator_summary(
            indicators
        )
    )

    # ------------------------------------------------------------------------
    # Risk
    # ------------------------------------------------------------------------

    report["risk_assessment"] = (
        calculate_risk_score(
            report
        )
    )

    # ------------------------------------------------------------------------
    # Performance metrics
    # ------------------------------------------------------------------------

    duration = (
        time.perf_counter()
        - started
    )

    report["analysis_metrics"] = {
        "duration_seconds": round(
            duration,
            4,
        ),

        "bytes_processed": len(data),

        "throughput_mb_per_second": round(
            (
                len(data)
                / 1024
                / 1024
                / duration
            )
            if duration > 0
            else 0.0,
            2,
        ),
    }

    return report


# ============================================================================
# TERMINAL REPORT
# ============================================================================

def print_report(
    report: dict,
    string_limit: int = 20,
) -> None:
    headers = report[
        "headers"
    ]

    certificate = report[
        "certificate_analysis"
    ]

    certificate_summary = report[
        "certificate_summary"
    ]

    imports = report[
        "imports"
    ]

    import_intelligence = report[
        "import_intelligence"
    ]

    exports = report[
        "exports"
    ]

    overlay = report[
        "overlay"
    ]

    strings = report[
        "strings"
    ]

    string_summary = strings[
        "summary"
    ]

    sections = report[
        "section_intelligence"
    ]

    indicators = report[
        "indicators"
    ]

    indicator_summary = report[
        "indicator_summary"
    ]

    risk = report[
        "risk_assessment"
    ]

    metrics = report[
        "analysis_metrics"
    ]

    print()
    print("=" * 100)
    print(
        "SECURITY-MISC :: PE STATIC ANALYSIS ENGINE"
    )
    print("=" * 100)

    print(
        f"File             : "
        f"{report['file']}"
    )

    print(
        f"Size             : "
        f"{report['size_bytes']:,} bytes"
    )

    print(
        f"MD5              : "
        f"{report['hashes']['md5']}"
    )

    print(
        f"SHA-1            : "
        f"{report['hashes']['sha1']}"
    )

    print(
        f"SHA-256          : "
        f"{report['hashes']['sha256']}"
    )

    print(
        f"Analysis version : "
        f"{report['analysis_version']}"
    )

    # ------------------------------------------------------------------------
    # Headers
    # ------------------------------------------------------------------------

    print()
    print("PE HEADERS")
    print("-" * 100)

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
    # Sections
    # ------------------------------------------------------------------------

    print()
    print("SECTIONS")
    print("-" * 100)

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

    print()
    print("SECTION INTELLIGENCE")
    print("-" * 100)

    print(
        f"Entry-point section      : "
        f"{sections['entry_point_section']}"
    )

    print(
        f"Executable sections      : "
        f"{len(sections['executable_sections'])}"
    )

    print(
        f"Writable sections        : "
        f"{len(sections['writable_sections'])}"
    )

    print(
        f"Executable + writable    : "
        f"{len(sections['executable_writable_sections'])}"
    )

    print(
        f"High entropy sections    : "
        f"{len(sections['high_entropy_sections'])}"
    )

    print(
        f"Empty raw sections       : "
        f"{len(sections['empty_raw_sections'])}"
    )

    print(
        f"Unusual section names    : "
        f"{len(sections['unusual_names'])}"
    )

    # ------------------------------------------------------------------------
    # Data directories
    # ------------------------------------------------------------------------

    print()
    print("DATA DIRECTORIES")
    print("-" * 100)

    active_directories = [
        directory
        for directory in report[
            "data_directories"
        ]
        if (
            directory[
                "virtual_address"
            ]
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
    # Imports
    # ------------------------------------------------------------------------

    print()
    print("IMPORT INTELLIGENCE")
    print("-" * 100)

    print(
        f"DLLs             : "
        f"{imports['dll_count']}"
    )

    print(
        f"Functions        : "
        f"{imports['function_count']}"
    )

    print(
        f"Unique functions : "
        f"{import_intelligence['unique_functions']}"
    )

    print(
        f"Suspicious APIs  : "
        f"{import_intelligence['suspicious_function_count']}"
    )

    if import_intelligence[
        "suspicious_groups"
    ]:
        print()
        print(
            "IMPORT CATEGORIES"
        )
        print("-" * 100)

        for (
            group_name,
            functions,
        ) in import_intelligence[
            "suspicious_groups"
        ].items():
            print(
                f"{group_name:<24}: "
                f"{', '.join(functions)}"
            )

    print()
    print("IMPORT TABLE")
    print("-" * 100)

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
    print("-" * 100)

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

    if exports[
        "count"
    ] > 50:
        print(
            "  ..."
        )

    # ------------------------------------------------------------------------
    # Certificate analysis
    # ------------------------------------------------------------------------

    print()
    print("CERTIFICATE ANALYSIS")
    print("-" * 100)

    if certificate.get(
        "present",
        False,
    ):
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
            f"{certificate_summary['entry_count']}"
        )

        print(
            f"    PKCS entries  : "
            f"{certificate_summary['pkcs_signed_entries']}"
        )

        for index, entry in enumerate(
            certificate[
                "entries"
            ],
            start=1,
        ):
            print(
                f"    Entry {index}: "
                f"Type={entry['type']} "
                f"Revision={entry['revision']} "
                f"PKCS={entry['is_pkcs_signed_data']}"
            )

    else:
        print(
            "[-] No PE certificate table detected."
        )

    # ------------------------------------------------------------------------
    # Overlay
    # ------------------------------------------------------------------------

    print()
    print("OVERLAY")
    print("-" * 100)

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
    # Strings
    # ------------------------------------------------------------------------

    print()
    print("STRING INTELLIGENCE")
    print("-" * 100)

    print(
        f"ASCII strings    : "
        f"{string_summary['ascii']}"
    )

    print(
        f"UTF-16LE strings : "
        f"{string_summary['utf16le']}"
    )

    print(
        f"Unique strings   : "
        f"{string_summary['total_unique']}"
    )

    print(
        f"URLs             : "
        f"{string_summary['urls']}"
    )

    print(
        f"IPv4 addresses   : "
        f"{string_summary['ipv4']}"
    )

    print(
        f"Email-like       : "
        f"{string_summary['emails']}"
    )

    print(
        f"Windows paths    : "
        f"{string_summary['windows_paths']}"
    )

    print(
        f"UNC paths        : "
        f"{string_summary['unc_paths']}"
    )

    print(
        f"Registry paths   : "
        f"{string_summary['registry_paths']}"
    )

    print(
        f"PowerShell hits  : "
        f"{string_summary['powershell_indicators']}"
    )

    print(
        f"Command hits     : "
        f"{string_summary['command_indicators']}"
    )

    print(
        f"Suspicious APIs  : "
        f"{string_summary['suspicious_apis']}"
    )

    classifications = strings[
        "classifications"
    ]

    display_categories = [
        ("URLS", "urls"),
        ("IPV4", "ipv4"),
        ("EMAILS", "emails"),
        ("WINDOWS PATHS", "windows_paths"),
        ("UNC PATHS", "unc_paths"),
        (
            "REGISTRY PATHS",
            "registry_paths",
        ),
        (
            "POWERSHELL INDICATORS",
            "powershell_indicators",
        ),
        (
            "COMMAND INDICATORS",
            "command_indicators",
        ),
        (
            "SUSPICIOUS APIS",
            "suspicious_apis",
        ),
    ]

    for title, key in (
        display_categories
    ):
        values = classifications.get(
            key,
            [],
        )

        if not values:
            continue

        print()
        print(title)
        print("-" * 100)

        for value in values[
            :string_limit
        ]:
            print(
                f"  {value}"
            )

        if len(values) > string_limit:
            print(
                f"  ... "
                f"({len(values) - string_limit} more)"
            )

    # ------------------------------------------------------------------------
    # Indicators
    # ------------------------------------------------------------------------

    print()
    print("STATIC INDICATORS")
    print("-" * 100)

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

    # ------------------------------------------------------------------------
    # Risk
    # ------------------------------------------------------------------------

    print()
    print("STATIC RISK ASSESSMENT")
    print("-" * 100)

    print(
        f"Score            : "
        f"{risk['score']}/100"
    )

    print(
        f"Rating           : "
        f"{risk['rating']}"
    )

    print(
        f"Method           : "
        f"{risk['method']}"
    )

    if risk[
        "reasons"
    ]:
        print()
        print("Reasons:")

        for reason in risk[
            "reasons"
        ]:
            print(
                f"  +{reason['points']:>3}  "
                f"{reason['reason']}"
            )

    # ------------------------------------------------------------------------
    # Performance
    # ------------------------------------------------------------------------

    print()
    print("ANALYSIS METRICS")
    print("-" * 100)

    print(
        f"Duration         : "
        f"{metrics['duration_seconds']:.4f}s"
    )

    print(
        f"Bytes processed  : "
        f"{metrics['bytes_processed']:,}"
    )

    print(
        f"Throughput       : "
        f"{metrics['throughput_mb_per_second']:.2f} MB/s"
    )

    print()
    print("=" * 100)


# ============================================================================
# JSON REPORT
# ============================================================================

def save_report(
    report: dict,
    output: Path,
) -> None:
    """
    Write the complete report as JSON.
    """
    output = (
        Path(output)
        .expanduser()
        .resolve()
    )

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


# ============================================================================
# CLI
# ============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-misc-pe",
        description=(
            "SECURITY-MISC read-only "
            "Windows PE static-analysis engine."
        ),
    )

    parser.add_argument(
        "file",
        help="Path to the PE file.",
    )

    parser.add_argument(
        "--json",
        type=Path,
        help=(
            "Write the complete analysis "
            "report to JSON."
        ),
    )

    parser.add_argument(
        "--string-limit",
        type=int,
        default=20,
        help=(
            "Maximum classified string artifacts "
            "printed per category."
        ),
    )

    return parser


# ============================================================================
# ENTRY POINT
# ============================================================================

def main() -> int:
    parser = build_parser()

    args = parser.parse_args()

    if args.string_limit < 1:
        parser.error(
            "--string-limit must be greater than zero."
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
        report = build_report(
            path
        )

        print_report(
            report,
            string_limit=args.string_limit,
        )

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