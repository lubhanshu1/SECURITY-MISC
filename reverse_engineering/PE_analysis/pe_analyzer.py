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
from .imports import parse_imports, summarize_imports
from .indicators import generate_indicators
from .parser import load_pe
from .sections import parse_sections

from reverse_engineering.strings.string_analyzer import (
    analyze_file as analyze_strings_file,
)


# ============================================================================
# VERSION / ENGINE METADATA
# ============================================================================

ANALYSIS_VERSION = "0.8.0"
ENGINE_NAME = "SECURITY-MISC"
ENGINE_MODULE = "pe_analyzer"

# Static-analysis safety limits. These prevent accidental resource exhaustion
# from malformed files while keeping the analyzer read-only.
MAX_FILE_SIZE_BYTES = 512 * 1024 * 1024
MAX_DATA_DIRECTORIES = 16
MAX_IMPORT_FUNCTIONS_DISPLAY = 30
MAX_EXPORTS_DISPLAY = 50


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
# HELPERS
# ============================================================================

def _safe_int(value: Any, default: int = 0) -> int:
    """Convert a value to int without allowing malformed report data to fail."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _directory_by_index(
    directories: list[dict[str, Any]],
    index: int,
) -> dict[str, Any] | None:
    """Return one PE data directory by index."""
    return next(
        (
            directory
            for directory in directories
            if directory.get("index") == index
        ),
        None,
    )


def _format_hex(value: Any, width: int = 0) -> str:
    """Format an integer as hexadecimal for human-readable reports."""
    number = _safe_int(value)
    if width:
        return f"0x{number:0{width}X}"
    return f"0x{number:X}"


def _timestamp_to_iso(timestamp: int) -> str | None:
    """
    Convert the PE COFF timestamp to UTC.

    Returns None for zero or clearly invalid timestamps.
    """
    timestamp = _safe_int(timestamp)

    if timestamp <= 0:
        return None

    try:
        return datetime.fromtimestamp(
            timestamp,
            tz=timezone.utc,
        ).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


# ============================================================================
# HASHING
# ============================================================================

def calculate_hashes(data: bytes) -> dict[str, str]:
    """
    Calculate common cryptographic hashes.

    The input is treated only as bytes and is never executed.
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
) -> list[dict[str, Any]]:
    """
    Parse the IMAGE_DATA_DIRECTORY array.

    PE32:
        directory array starts at optional-header + 96

    PE32+:
        directory array starts at optional-header + 112

    The parser is deliberately bounded by both the optional-header size and
    the physical file size.
    """
    directory_base = 112 if is_64_bit else 96
    count_base = 108 if is_64_bit else 92

    if optional_header_size < directory_base:
        return []

    directory_offset = optional_offset + directory_base
    count_offset = optional_offset + count_base

    if count_offset < 0 or count_offset + 4 > len(data):
        return []

    number_of_directories = struct.unpack_from(
        "<I",
        data,
        count_offset,
    )[0]

    max_available = (
        optional_header_size - directory_base
    ) // 8

    count = min(
        number_of_directories,
        max_available,
        MAX_DATA_DIRECTORIES,
    )

    directories: list[dict[str, Any]] = []

    for index in range(count):
        offset = directory_offset + index * 8

        if offset < 0 or offset + 8 > len(data):
            break

        virtual_address, size = struct.unpack_from(
            "<II",
            data,
            offset,
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
                "present": bool(virtual_address or size),
            }
        )

    return directories


# ============================================================================
# SECTION INTELLIGENCE
# ============================================================================

def analyze_sections(
    sections: list[Any],
    entry_point_rva: int,
) -> dict[str, Any]:
    """
    Derive higher-level static observations from PE sections.

    This function does not execute section contents.
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
        name = str(getattr(section, "name", "")).strip()
        normalized = name.lower()

        is_executable = bool(
            getattr(section, "is_executable", False)
        )
        is_writable = bool(
            getattr(section, "is_writable", False)
        )
        entropy = float(
            getattr(section, "entropy", 0.0) or 0.0
        )
        raw_size = _safe_int(
            getattr(section, "raw_size", 0)
        )
        virtual_size = _safe_int(
            getattr(section, "virtual_size", 0)
        )
        virtual_address = _safe_int(
            getattr(section, "virtual_address", 0)
        )

        if is_executable:
            executable_sections.append(name)

        if is_writable:
            writable_sections.append(name)

        if is_executable and is_writable:
            executable_writable_sections.append(name)

        if entropy >= 7.2:
            high_entropy_sections.append(name)

        if raw_size == 0 and virtual_size > 0:
            empty_sections.append(name)

        if normalized and normalized not in standard_names:
            unusual_names.append(name)

        span = max(virtual_size, raw_size)
        end = virtual_address + span

        if (
            virtual_address <= entry_point_rva < end
            and span > 0
        ):
            entry_point_section = name

    return {
        "count": len(sections),
        "executable_sections": executable_sections,
        "writable_sections": writable_sections,
        "executable_writable_sections": (
            executable_writable_sections
        ),
        "high_entropy_sections": high_entropy_sections,
        "empty_raw_sections": empty_sections,
        "unusual_names": unusual_names,
        "entry_point_section": entry_point_section,
        "flags": {
            "has_executable_writable_section": bool(
                executable_writable_sections
            ),
            "has_high_entropy_section": bool(
                high_entropy_sections
            ),
            "has_empty_raw_section": bool(
                empty_sections
            ),
            "has_unusual_section_name": bool(
                unusual_names
            ),
        },
    }


# ============================================================================
# IMPORT INTELLIGENCE
# ============================================================================

def analyze_imports(imports: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Analyze imported functions and group them into broad static categories.
    """
    all_functions: list[str] = []

    for library in imports:
        for function in library.get("functions", []):
            if function:
                all_functions.append(str(function))

    unique_functions = {
        function.lower(): function
        for function in all_functions
    }

    matched_groups: dict[str, list[str]] = {}

    for group_name, names in SUSPICIOUS_IMPORT_GROUPS.items():
        matches: list[str] = []

        for name in names:
            actual = unique_functions.get(name.lower())
            if actual:
                matches.append(actual)

        if matches:
            matched_groups[group_name] = sorted(
                set(matches),
                key=str.lower,
            )

    suspicious_functions = {
        function.lower()
        for functions in matched_groups.values()
        for function in functions
    }

    summary = summarize_imports(imports)

    return {
        **summary,
        "unique_functions": len(unique_functions),
        "suspicious_groups": matched_groups,
        "suspicious_function_count": len(
            suspicious_functions
        ),
        "category_count": len(matched_groups),
    }


# ============================================================================
# STRING INTELLIGENCE
# ============================================================================

def summarize_strings(string_report: dict[str, Any]) -> dict[str, Any]:
    """Produce a compact, stable summary of the string-analysis subsystem."""
    counts = string_report.get("counts", {})
    classifications = string_report.get(
        "classifications",
        {},
    )

    def count_category(name: str) -> int:
        value = classifications.get(name, [])
        return len(value) if isinstance(value, list) else 0

    return {
        "ascii": _safe_int(counts.get("ascii")),
        "utf16le": _safe_int(counts.get("utf16le")),
        "total_unique": _safe_int(
            counts.get("total_unique")
        ),
        "urls": count_category("urls"),
        "ipv4": count_category("ipv4"),
        "emails": count_category("emails"),
        "windows_paths": count_category("windows_paths"),
        "unc_paths": count_category("unc_paths"),
        "registry_paths": count_category("registry_paths"),
        "powershell_indicators": count_category(
            "powershell_indicators"
        ),
        "command_indicators": count_category(
            "command_indicators"
        ),
        "suspicious_apis": count_category(
            "suspicious_apis"
        ),
    }


# ============================================================================
# INDICATOR SUMMARY
# ============================================================================

def calculate_indicator_summary(
    indicators: list[dict[str, Any]],
) -> dict[str, Any]:
    """Aggregate static indicators by severity."""
    severity_counts = {
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for indicator in indicators:
        severity = str(
            indicator.get("severity", "info")
        ).lower()

        if severity in severity_counts:
            severity_counts[severity] += 1

    return {
        "total": len(indicators),
        "by_severity": severity_counts,
    }


# ============================================================================
# OVERLAY INTELLIGENCE
# ============================================================================

def calculate_overlay(
    data: bytes,
    sections: list[Any],
    certificate_analysis: dict[str, Any],
) -> dict[str, Any]:
    """
    Estimate file overlay data.

    The security-directory/certificate table is treated as file-backed data,
    so bytes after the later of the last section body and certificate table
    are classified as overlay.
    """
    max_section_end = 0

    for section in sections:
        raw_size = _safe_int(
            getattr(section, "raw_size", 0)
        )

        if raw_size:
            raw_end = _safe_int(
                getattr(section, "raw_end", 0)
            )
            if raw_end:
                max_section_end = max(
                    max_section_end,
                    raw_end,
                )

    certificate_end = 0

    if certificate_analysis.get("present", False):
        certificate_offset = _safe_int(
            certificate_analysis.get(
                "file_offset"
            )
        )
        certificate_size = _safe_int(
            certificate_analysis.get("size")
        )

        if certificate_offset >= 0 and certificate_size >= 0:
            certificate_end = (
                certificate_offset
                + certificate_size
            )

    file_backed_end = max(
        max_section_end,
        certificate_end,
    )

    overlay_size = max(
        0,
        len(data) - file_backed_end,
    )

    return {
        "present": overlay_size > 0,
        "offset": file_backed_end,
        "size": overlay_size,
    }


# ============================================================================
# RISK SCORING
# ============================================================================

def calculate_risk_score(report: dict[str, Any]) -> dict[str, Any]:
    """
    Produce a deterministic static-analysis score.

    The score is an explainable prioritization aid, not a malware verdict.
    Every score contribution is represented in ``reasons`` so that the
    displayed score can be reproduced from the report.
    """
    score = 0
    reasons: list[dict[str, Any]] = []

    def add(points: int, reason: str) -> None:
        nonlocal score

        points = max(0, int(points))
        score += points

        reasons.append(
            {
                "points": points,
                "reason": reason,
            }
        )

    section_data = report["section_intelligence"]
    section_flags = section_data["flags"]

    if section_flags["has_executable_writable_section"]:
        add(
            25,
            "Executable and writable PE section detected.",
        )

    if section_flags["has_high_entropy_section"]:
        add(
            15,
            "High-entropy PE section detected.",
        )

    if section_flags["has_empty_raw_section"]:
        add(
            3,
            "Section has virtual data without a raw file body.",
        )

    if section_flags["has_unusual_section_name"]:
        add(
            5,
            "Unusual PE section name detected.",
        )

    import_data = report["import_intelligence"]

    import_points = {
        "process_injection": (
            25,
            "Process-injection-related API imports detected.",
        ),
        "process_execution": (
            15,
            "Process-execution-related API imports detected.",
        ),
        "networking": (
            10,
            "Networking-related API imports detected.",
        ),
        "dynamic_loading": (
            10,
            "Dynamic loading APIs detected.",
        ),
        "memory_mapping": (
            5,
            "Memory-mapping APIs detected.",
        ),
        "anti_analysis": (
            10,
            "Anti-analysis/debugger-detection APIs detected.",
        ),
    }

    for group_name in import_data.get(
        "suspicious_groups",
        {},
    ):
        if group_name in import_points:
            points, reason = import_points[group_name]
            add(points, reason)

    string_data = report["strings"]["summary"]

    string_points = {
        "powershell_indicators": (
            20,
            "PowerShell-related string artifacts detected.",
        ),
        "command_indicators": (
            10,
            "Command-execution-related string artifacts detected.",
        ),
        "urls": (
            5,
            "URL artifacts detected.",
        ),
        "ipv4": (
            5,
            "IPv4 artifacts detected.",
        ),
        "registry_paths": (
            5,
            "Registry path artifacts detected.",
        ),
        "suspicious_apis": (
            10,
            "Suspicious API names detected in static strings.",
        ),
    }

    for key, (points, reason) in string_points.items():
        if string_data.get(key, 0):
            add(points, reason)

    indicator_counts = report["indicator_summary"]["by_severity"]

    if indicator_counts["high"]:
        add(
            indicator_counts["high"] * 15,
            "High-severity static indicators were generated.",
        )

    if indicator_counts["medium"]:
        add(
            indicator_counts["medium"] * 7,
            "Medium-severity static indicators were generated.",
        )

    if indicator_counts["low"]:
        add(
            indicator_counts["low"] * 2,
            "Low-severity static indicators were generated.",
        )

    # An overlay alone is not treated as malicious. It is reported for
    # analyst review, but contributes no automatic risk points.
    if report["overlay"]["present"]:
        reasons.append(
            {
                "points": 0,
                "reason": (
                    "File overlay detected; reported for analyst review "
                    "without automatic risk points."
                ),
            }
        )

    score = max(0, min(score, 100))

    if score >= 80:
        rating = "CRITICAL"
    elif score >= 70:
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
            "Deterministic static observation scoring with "
            "explainable additive reasons; not a malware verdict."
        ),
        "reasons": reasons,
    }


# ============================================================================
# REPORT BUILDER
# ============================================================================

def build_report(path: Path) -> dict[str, Any]:
    """
    Build the complete SECURITY-MISC PE report.

    The target is read as bytes and analyzed statically.
    It is never executed.
    """
    started = time.perf_counter()

    path = Path(path).expanduser().resolve()

    if not path.exists():
        raise FileNotFoundError(
            f"File not found: {path}"
        )

    if not path.is_file():
        raise ValueError(
            f"Not a regular file: {path}"
        )

    file_size = path.stat().st_size

    if file_size > MAX_FILE_SIZE_BYTES:
        raise ValueError(
            "Input file exceeds the analyzer safety limit "
            f"of {MAX_FILE_SIZE_BYTES:,} bytes."
        )

    data, headers = load_pe(path)

    if not data:
        raise ValueError("PE file is empty.")

    if len(data) != file_size:
        file_size = len(data)

    # ------------------------------------------------------------------------
    # File identity
    # ------------------------------------------------------------------------

    hashes = calculate_hashes(data)

    # ------------------------------------------------------------------------
    # PE basics
    # ------------------------------------------------------------------------

    optional_offset = headers.pe_offset + 4 + 20

    is_64_bit = headers.optional_magic == 0x20B

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

    section_intelligence = analyze_sections(
        sections,
        headers.entry_point_rva,
    )

    # ------------------------------------------------------------------------
    # Data directories
    # ------------------------------------------------------------------------

    directories = parse_data_directories(
        data=data,
        optional_offset=optional_offset,
        is_64_bit=is_64_bit,
        optional_header_size=headers.size_of_optional_header,
    )

    import_directory = _directory_by_index(
        directories,
        1,
    )

    export_directory = _directory_by_index(
        directories,
        0,
    )

    # ------------------------------------------------------------------------
    # Imports
    # ------------------------------------------------------------------------

    imports = parse_imports(
        data=data,
        import_rva=(
            import_directory["virtual_address"]
            if import_directory
            else 0
        ),
        import_size=(
            import_directory["size"]
            if import_directory
            else 0
        ),
        sections=sections,
        is_64_bit=is_64_bit,
    )

    import_intelligence = analyze_imports(imports)

    # ------------------------------------------------------------------------
    # Exports
    # ------------------------------------------------------------------------

    exports = parse_exports(
        data=data,
        export_rva=(
            export_directory["virtual_address"]
            if export_directory
            else 0
        ),
        sections=sections,
    )

    # ------------------------------------------------------------------------
    # Certificates
    # ------------------------------------------------------------------------

    certificate_analysis = parse_certificate_table(data)
    certificate_summary = summarize_certificates(
        certificate_analysis
    )

    # ------------------------------------------------------------------------
    # Strings
    # ------------------------------------------------------------------------

    string_report = analyze_strings_file(path)
    string_summary = summarize_strings(string_report)

    # ------------------------------------------------------------------------
    # Base report
    # ------------------------------------------------------------------------

    report: dict[str, Any] = {
        "tool": ENGINE_NAME,
        "module": ENGINE_MODULE,
        "analysis_version": ANALYSIS_VERSION,
        "analysis_time": datetime.now(
            timezone.utc
        ).isoformat(),

        # Backward-compatible fields.
        "file": str(path),
        "size_bytes": len(data),

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
            "machine_code": _format_hex(
                headers.machine,
                4,
            ),
            "bitness": headers.bitness,
            "number_of_sections": (
                headers.number_of_sections
            ),
            "timestamp_raw": headers.timestamp,
            "timestamp_utc": _timestamp_to_iso(
                headers.timestamp
            ),
            "pointer_to_symbol_table": (
                headers.pointer_to_symbol_table
            ),
            "number_of_symbols": (
                headers.number_of_symbols
            ),
            "optional_header_magic": _format_hex(
                headers.optional_magic,
                3,
            ),
            "optional_header_size": (
                headers.size_of_optional_header
            ),
            "characteristics": _format_hex(
                headers.characteristics,
                4,
            ),
            "entry_point_rva": _format_hex(
                headers.entry_point_rva,
                8,
            ),
            "image_base": _format_hex(
                headers.image_base
            ),
        },

        "data_directories": directories,

        "sections": [
            asdict(section)
            for section in sections
        ],

        "section_intelligence": section_intelligence,

        # Preserve the existing report shape.
        "imports": {
            **import_intelligence,
            "libraries": imports,
        },

        "import_intelligence": import_intelligence,

        "exports": {
            "count": len(exports),
            "functions": exports,
        },

        "certificate_analysis": certificate_analysis,
        "certificate_summary": certificate_summary,

        "strings": {
            "summary": string_summary,
            "classifications": string_report.get(
                "classifications",
                {},
            ),
        },
    }

    # ------------------------------------------------------------------------
    # Overlay
    # ------------------------------------------------------------------------

    report["overlay"] = calculate_overlay(
        data,
        sections,
        certificate_analysis,
    )

    # ------------------------------------------------------------------------
    # Indicators
    # ------------------------------------------------------------------------

    indicators = generate_indicators(report)

    report["indicators"] = indicators
    report["indicator_summary"] = (
        calculate_indicator_summary(indicators)
    )

    # ------------------------------------------------------------------------
    # Risk
    # ------------------------------------------------------------------------

    report["risk_assessment"] = calculate_risk_score(
        report
    )

    # ------------------------------------------------------------------------
    # Performance metrics
    # ------------------------------------------------------------------------

    duration = time.perf_counter() - started

    report["analysis_metrics"] = {
        "duration_seconds": round(
            duration,
            4,
        ),
        "bytes_processed": len(data),
        "throughput_mb_per_second": round(
            (
                len(data) / 1024 / 1024 / duration
                if duration > 0
                else 0.0
            ),
            2,
        ),
    }

    # ------------------------------------------------------------------------
    # Engine summary
    # ------------------------------------------------------------------------

    report["analysis_summary"] = {
        "static_only": True,
        "execution_performed": False,
        "sections_analyzed": len(sections),
        "imports_analyzed": len(imports),
        "exports_analyzed": len(exports),
        "data_directories_analyzed": len(
            directories
        ),
        "indicators_generated": len(indicators),
        "risk_score": report["risk_assessment"]["score"],
        "risk_rating": report["risk_assessment"]["rating"],
    }

    return report


# ============================================================================
# TERMINAL REPORT
# ============================================================================

def print_report(
    report: dict[str, Any],
    string_limit: int = 20,
) -> None:
    """Print a human-readable static-analysis report."""
    headers = report["headers"]
    certificate = report["certificate_analysis"]
    certificate_summary = report["certificate_summary"]
    imports = report["imports"]
    import_intelligence = report["import_intelligence"]
    exports = report["exports"]
    overlay = report["overlay"]
    strings = report["strings"]
    string_summary = strings["summary"]
    sections = report["section_intelligence"]
    indicators = report["indicators"]
    indicator_summary = report["indicator_summary"]
    risk = report["risk_assessment"]
    metrics = report["analysis_metrics"]

    print()
    print("=" * 100)
    print(
        f"{ENGINE_NAME} :: PE STATIC ANALYSIS ENGINE"
    )
    print("=" * 100)

    print(f"File             : {report['file']}")
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
    print(
        "Execution        : NEVER "
        "(static byte analysis only)"
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
        f"Machine code     : "
        f"{headers['machine_code']}"
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
        f"{_format_hex(headers['pe_offset'])}"
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
    print(
        f"Timestamp UTC    : "
        f"{headers['timestamp_utc'] or 'Unknown'}"
    )

    # ------------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------------

    print()
    print("SECTIONS")
    print("-" * 100)

    print(
        f"{'NAME':<12}"
        f"{'VIRT SIZE':>12}"
        f"{'RAW SIZE':>12}"
        f"{'RVA':>12}"
        f"{'ENTROPY':>10}"
        f"  FLAGS"
    )

    for section in report["sections"]:
        print(
            f"{str(section['name']):<12}"
            f"{_safe_int(section.get('virtual_size')):>12,}"
            f"{_safe_int(section.get('raw_size')):>12,}"
            f"{_safe_int(section.get('virtual_address')):>12X}"
            f"{float(section.get('entropy', 0.0)):>10.4f}"
            f"  {section.get('characteristics', '')}"
        )

    print()
    print("SECTION INTELLIGENCE")
    print("-" * 100)

    print(
        f"Entry-point section      : "
        f"{sections['entry_point_section'] or 'Unknown'}"
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
        for directory in report["data_directories"]
        if directory.get("present")
    ]

    if not active_directories:
        print("[+] No populated data directories.")
    else:
        for directory in active_directories:
            print(
                f"{directory['name']:<20}"
                f"RVA/Offset: "
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
        f"{imports.get('dll_count', 0)}"
    )
    print(
        f"Functions        : "
        f"{imports.get('function_count', 0)}"
    )
    print(
        f"Unique functions : "
        f"{import_intelligence['unique_functions']}"
    )
    print(
        f"Suspicious APIs  : "
        f"{import_intelligence['suspicious_function_count']}"
    )
    print(
        f"Matched categories: "
        f"{import_intelligence['category_count']}"
    )

    if import_intelligence["suspicious_groups"]:
        print()
        print("IMPORT CATEGORIES")
        print("-" * 100)

        for group_name, functions in (
            import_intelligence["suspicious_groups"].items()
        ):
            print(
                f"{group_name:<24}: "
                f"{', '.join(functions)}"
            )

    print()
    print("IMPORT TABLE")
    print("-" * 100)

    for library in imports.get("libraries", []):
        dll = library.get("dll", "<unknown>")
        function_count = _safe_int(
            library.get("function_count")
        )

        print(
            f"\n  {dll} "
            f"({function_count} functions)"
        )

        for function in library.get(
            "functions",
            [],
        )[:MAX_IMPORT_FUNCTIONS_DISPLAY]:
            print(f"    {function}")

        if function_count > MAX_IMPORT_FUNCTIONS_DISPLAY:
            print("    ...")

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
    ][:MAX_EXPORTS_DISPLAY]:
        print(f"  {function}")

    if exports["count"] > MAX_EXPORTS_DISPLAY:
        print("  ...")

    # ------------------------------------------------------------------------
    # Certificate analysis
    # ------------------------------------------------------------------------

    print()
    print("CERTIFICATE ANALYSIS")
    print("-" * 100)

    if certificate.get("present", False):
        print("[+] PE certificate table detected.")
        print(
            f"    Offset        : "
            f"0x{_safe_int(certificate.get('file_offset')):X}"
        )
        print(
            f"    Size          : "
            f"{_safe_int(certificate.get('size')):,} bytes"
        )
        print(
            f"    Entries       : "
            f"{certificate_summary.get('entry_count', 0)}"
        )
        print(
            f"    PKCS entries  : "
            f"{certificate_summary.get('pkcs_signed_entries', 0)}"
        )

        for index, entry in enumerate(
            certificate.get("entries", []),
            start=1,
        ):
            print(
                f"    Entry {index}: "
                f"Type={entry.get('type')} "
                f"Revision={entry.get('revision')} "
                f"PKCS={entry.get('is_pkcs_signed_data')}"
            )
    else:
        print("[-] No PE certificate table detected.")

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

    string_labels = [
        ("ASCII strings", "ascii"),
        ("UTF-16LE strings", "utf16le"),
        ("Unique strings", "total_unique"),
        ("URLs", "urls"),
        ("IPv4 addresses", "ipv4"),
        ("Email-like", "emails"),
        ("Windows paths", "windows_paths"),
        ("UNC paths", "unc_paths"),
        ("Registry paths", "registry_paths"),
        ("PowerShell hits", "powershell_indicators"),
        ("Command hits", "command_indicators"),
        ("Suspicious APIs", "suspicious_apis"),
    ]

    for label, key in string_labels:
        print(
            f"{label:<18}: "
            f"{string_summary.get(key, 0)}"
        )

    classifications = strings["classifications"]

    display_categories = [
        ("URLS", "urls"),
        ("IPV4", "ipv4"),
        ("EMAILS", "emails"),
        ("WINDOWS PATHS", "windows_paths"),
        ("UNC PATHS", "unc_paths"),
        ("REGISTRY PATHS", "registry_paths"),
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

    for title, key in display_categories:
        values = classifications.get(key, [])

        if not values:
            continue

        print()
        print(title)
        print("-" * 100)

        for value in values[:string_limit]:
            print(f"  {value}")

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

    for severity in (
        "high",
        "medium",
        "low",
        "info",
    ):
        print(
            f"{severity.capitalize():<17}: "
            f"{indicator_summary['by_severity'][severity]}"
        )

    print(
        f"{'Total':<17}: "
        f"{indicator_summary['total']}"
    )

    if not indicators:
        print()
        print("[+] No static indicators generated.")
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
                f"[{severity:<8}] "
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

    if risk["reasons"]:
        print()
        print("Reasons:")

        for reason in risk["reasons"]:
            points = _safe_int(reason.get("points"))

            prefix = "+" if points else " "
            print(
                f"  {prefix}{points:>3}  "
                f"{reason.get('reason', '')}"
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
    report: dict[str, Any],
    output: Path,
) -> None:
    """Write the complete report as UTF-8 JSON."""
    output = Path(output).expanduser().resolve()

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


# ============================================================================
# CLI
# ============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-misc-pe",
        description=(
            "SECURITY-MISC read-only Windows PE "
            "static-analysis engine."
        ),
        epilog=(
            "Safety: the target file is read and analyzed as bytes; "
            "it is never executed."
        ),
    )

    parser.add_argument(
        "file",
        help="Path to the PE file.",
    )

    parser.add_argument(
        "--json",
        type=Path,
        help="Write the complete analysis report to JSON.",
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

    path = Path(args.file).expanduser().resolve()

    if not path.exists():
        print(f"[!] File not found: {path}")
        return 2

    if not path.is_file():
        print(f"[!] Not a regular file: {path}")
        return 2

    try:
        report = build_report(path)

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
        print(f"[!] Permission denied: {path}")
        return 3

    except FileNotFoundError as exc:
        print(f"[!] File not found: {exc}")
        return 2

    except OSError as exc:
        print(f"[!] File-system error: {exc}")
        return 3

    except ValueError as exc:
        print(f"[!] PE parsing error: {exc}")
        return 4

    except Exception as exc:
        print(
            "[!] Unexpected analyzer error: "
            f"{type(exc).__name__}: {exc}"
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
