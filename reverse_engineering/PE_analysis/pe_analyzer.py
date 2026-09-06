from __future__ import annotations

import argparse
import hashlib
import json
import struct
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

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

ANALYSIS_VERSION = "0.9.1"
ENGINE_NAME = "SECURITY-MISC"
ENGINE_MODULE = "pe_analyzer"

# Static-analysis safety and output limits.
MAX_FILE_SIZE_BYTES = 512 * 1024 * 1024
MAX_DATA_DIRECTORIES = 16
MAX_IMPORT_FUNCTIONS_DISPLAY = 30
MAX_EXPORTS_DISPLAY = 50
MAX_CLASSIFIED_STRINGS_DISPLAY = 20

# Evidence thresholds are intentionally conservative. They describe
# observations; they do not establish malicious intent.
HIGH_ENTROPY_THRESHOLD = 7.2


# ============================================================================
# PE DATA DIRECTORY NAMES
# ============================================================================

DATA_DIRECTORY_NAMES: dict[int, str] = {
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
    # High-confidence process-injection primitives. APIs such as
    # VirtualProtect and OpenProcess are intentionally not placed here
    # because they are common in legitimate software.
    "process_injection": {
        "VirtualAllocEx",
        "VirtualProtectEx",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "NtCreateThreadEx",
        "QueueUserAPC",
    },
    "process_access": {
        "OpenProcess",
    },
    "memory_operations": {
        "VirtualAlloc",
        "VirtualProtect",
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
# RISK MODEL METADATA
# ============================================================================

RISK_IMPORT_POINTS: dict[str, tuple[int, str]] = {
    "process_injection": (
        25,
        "Multiple high-confidence process-injection API imports detected.",
    ),
    "process_access": (
        3,
        "Process-access API imported.",
    ),
    "memory_operations": (
        3,
        "Memory-management/protection API imported.",
    ),
    "process_execution": (
        12,
        "Process-execution-related API imports detected.",
    ),
    "networking": (
        8,
        "Networking-related API imports detected.",
    ),
    "dynamic_loading": (
        5,
        "Dynamic loading APIs detected.",
    ),
    "memory_mapping": (
        4,
        "Memory-mapping APIs detected.",
    ),
    "anti_analysis": (
        10,
        "Anti-analysis/debugger-detection APIs detected.",
    ),
}

# An individual API is rarely enough to justify the full injection score.
# Require multiple complementary primitives before applying the high score.
HIGH_CONFIDENCE_INJECTION_MIN_APIS = 2

RISK_STRING_POINTS: dict[str, tuple[int, str]] = {
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


# ============================================================================
# HELPERS
# ============================================================================

def _safe_int(value: Any, default: int = 0) -> int:
    """Convert a value to int without allowing malformed report data to fail."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Convert a value to float without allowing malformed report data to fail."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _directory_by_index(
    directories: Iterable[dict[str, Any]],
    index: int,
) -> dict[str, Any] | None:
    """Return one PE data directory by index."""
    return next(
        (
            directory
            for directory in directories
            if _safe_int(directory.get("index")) == index
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

    Returns None for zero or invalid timestamps.
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


def _unique_sorted_strings(values: Any) -> list[str]:
    """Normalize a list-like classification into deterministic strings."""
    if not isinstance(values, list):
        return []

    normalized = {
        str(value)
        for value in values
        if value is not None and str(value)
    }

    return sorted(
        normalized,
        key=str.lower,
    )


def _count_mapping_values(mapping: dict[str, Any]) -> int:
    """Count all list members in a classification mapping."""
    total = 0

    for value in mapping.values():
        if isinstance(value, list):
            total += len(value)

    return total


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
        offset = directory_offset + (index * 8)

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
                "present": bool(
                    virtual_address or size
                ),
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

    Section contents are never executed.
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
            getattr(section, "name", "")
        ).strip()

        normalized = name.lower()

        is_executable = bool(
            getattr(
                section,
                "is_executable",
                False,
            )
        )

        is_writable = bool(
            getattr(
                section,
                "is_writable",
                False,
            )
        )

        entropy = _safe_float(
            getattr(
                section,
                "entropy",
                0.0,
            )
        )

        raw_size = _safe_int(
            getattr(
                section,
                "raw_size",
                0,
            )
        )

        virtual_size = _safe_int(
            getattr(
                section,
                "virtual_size",
                0,
            )
        )

        virtual_address = _safe_int(
            getattr(
                section,
                "virtual_address",
                0,
            )
        )

        if is_executable:
            executable_sections.append(name)

        if is_writable:
            writable_sections.append(name)

        if is_executable and is_writable:
            executable_writable_sections.append(name)

        if entropy >= HIGH_ENTROPY_THRESHOLD:
            high_entropy_sections.append(name)

        if raw_size == 0 and virtual_size > 0:
            empty_sections.append(name)

        if normalized and normalized not in standard_names:
            unusual_names.append(name)

        span = max(
            virtual_size,
            raw_size,
        )

        end = virtual_address + span

        if (
            span > 0
            and virtual_address <= entry_point_rva < end
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

def analyze_imports(
    imports: list[dict[str, Any]],
) -> dict[str, Any]:
    """Analyze imported functions and group them into static categories."""
    all_functions: list[str] = []

    for library in imports:
        functions = library.get(
            "functions",
            [],
        )

        if not isinstance(functions, list):
            continue

        for function in functions:
            if function:
                all_functions.append(
                    str(function)
                )

    unique_functions = {
        function.lower(): function
        for function in all_functions
    }

    matched_groups: dict[str, list[str]] = {}

    for group_name, names in (
        SUSPICIOUS_IMPORT_GROUPS.items()
    ):
        matches: list[str] = []

        for name in names:
            actual = unique_functions.get(
                name.lower()
            )

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
        "unique_functions": len(
            unique_functions
        ),
        "suspicious_groups": matched_groups,
        "suspicious_function_count": len(
            suspicious_functions
        ),
        "category_count": len(
            matched_groups
        ),
    }


# ============================================================================
# STRING INTELLIGENCE
# ============================================================================

def summarize_strings(
    string_report: dict[str, Any],
) -> dict[str, Any]:
    """Produce a compact, stable summary of string analysis."""
    counts = string_report.get(
        "counts",
        {},
    )

    raw_classifications = string_report.get(
        "classifications",
        {},
    )

    classifications = (
        raw_classifications
        if isinstance(raw_classifications, dict)
        else {}
    )

    def count_category(name: str) -> int:
        return len(
            _unique_sorted_strings(
                classifications.get(name, [])
            )
        )

    return {
        "ascii": _safe_int(
            counts.get("ascii")
        ),
        "utf16le": _safe_int(
            counts.get("utf16le")
        ),
        "total_unique": _safe_int(
            counts.get("total_unique")
        ),
        "urls": count_category("urls"),
        "ipv4": count_category("ipv4"),
        "emails": count_category("emails"),
        "windows_paths": count_category(
            "windows_paths"
        ),
        "unc_paths": count_category(
            "unc_paths"
        ),
        "registry_paths": count_category(
            "registry_paths"
        ),
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


def normalize_string_classifications(
    string_report: dict[str, Any],
) -> dict[str, list[str]]:
    """
    Normalize classified strings into deterministic, unique lists.

    This keeps JSON output stable between repeated analyses.
    """
    raw = string_report.get(
        "classifications",
        {},
    )

    if not isinstance(raw, dict):
        return {}

    normalized: dict[str, list[str]] = {}

    for key, values in raw.items():
        normalized[str(key)] = (
            _unique_sorted_strings(values)
        )

    return dict(
        sorted(
            normalized.items(),
            key=lambda item: item[0].lower(),
        )
    )


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
            indicator.get(
                "severity",
                "info",
            )
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

    The certificate table is treated as file-backed data. Bytes after the
    later of the last section body and certificate table are classified as
    overlay.
    """
    max_section_end = 0

    for section in sections:
        raw_size = _safe_int(
            getattr(
                section,
                "raw_size",
                0,
            )
        )

        if raw_size <= 0:
            continue

        raw_end = _safe_int(
            getattr(
                section,
                "raw_end",
                0,
            )
        )

        if raw_end > 0:
            max_section_end = max(
                max_section_end,
                raw_end,
            )

    certificate_end = 0

    if certificate_analysis.get(
        "present",
        False,
    ):
        certificate_offset = _safe_int(
            certificate_analysis.get(
                "file_offset"
            )
        )

        certificate_size = _safe_int(
            certificate_analysis.get(
                "size"
            )
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

def calculate_risk_score(
    report: dict[str, Any],
) -> dict[str, Any]:
    """
    Produce a deterministic, explainable static-analysis score.

    The scoring model is intentionally contextual:
    - common Windows APIs do not receive high-risk treatment by themselves;
    - high-confidence process-injection scoring requires multiple
      complementary injection primitives;
    - suspicious API strings are not scored again when the same API is
      already explained by the PE import table;
    - observations remain visible even when they contribute zero points.

    This is a prioritization aid, not a malware verdict.
    """
    score = 0
    reasons: list[dict[str, Any]] = []

    def add(
        points: int,
        reason: str,
    ) -> None:
        nonlocal score

        normalized_points = max(
            0,
            _safe_int(points),
        )

        score += normalized_points

        reasons.append(
            {
                "points": normalized_points,
                "reason": str(reason),
            }
        )

    section_data = report.get(
        "section_intelligence",
        {},
    )

    section_flags = section_data.get(
        "flags",
        {},
    )

    if section_flags.get(
        "has_executable_writable_section",
        False,
    ):
        add(
            25,
            "Executable and writable PE section detected.",
        )

    if section_flags.get(
        "has_high_entropy_section",
        False,
    ):
        add(
            15,
            "High-entropy PE section detected.",
        )

    if section_flags.get(
        "has_empty_raw_section",
        False,
    ):
        add(
            3,
            "Section has virtual data without a raw file body.",
        )

    if section_flags.get(
        "has_unusual_section_name",
        False,
    ):
        add(
            5,
            "Unusual PE section name detected.",
        )

    import_data = report.get(
        "import_intelligence",
        {},
    )

    suspicious_groups = import_data.get(
        "suspicious_groups",
        {},
    )

    if isinstance(suspicious_groups, dict):
        for group_name in sorted(
            suspicious_groups,
            key=str.lower,
        ):
            points_reason = RISK_IMPORT_POINTS.get(
                group_name
            )

            if points_reason is None:
                continue

            points, reason = points_reason

            if group_name == "process_injection":
                functions = suspicious_groups.get(
                    group_name,
                    [],
                )

                if len(functions) >= HIGH_CONFIDENCE_INJECTION_MIN_APIS:
                    add(points, reason)
                else:
                    reasons.append(
                        {
                            "points": 0,
                            "reason": (
                                "Process-injection API observed, but fewer "
                                "than "
                                f"{HIGH_CONFIDENCE_INJECTION_MIN_APIS} "
                                "complementary injection primitives were "
                                "present; reported without automatic "
                                "high-risk points."
                            ),
                        }
                    )
            else:
                add(points, reason)

    # Build the set of APIs already explained by the import table. This
    # prevents a normal imported API name from being counted again merely
    # because the same name also occurs in static strings.
    imported_functions: set[str] = set()

    for library in report.get(
        "imports",
        {},
    ).get(
        "libraries",
        [],
    ):
        functions = library.get(
            "functions",
            [],
        )

        if not isinstance(functions, list):
            continue

        for function in functions:
            if function:
                imported_functions.add(
                    str(function).strip().lower()
                )

    string_data = report.get(
        "strings",
        {},
    ).get(
        "summary",
        {},
    )

    string_classifications = report.get(
        "strings",
        {},
    ).get(
        "classifications",
        {},
    )

    for key, (points, reason) in (
        RISK_STRING_POINTS.items()
    ):
        count = _safe_int(
            string_data.get(
                key,
                0,
            )
        )

        if count <= 0:
            continue

        if key == "suspicious_apis":
            suspicious_api_strings = (
                string_classifications.get(
                    "suspicious_apis",
                    [],
                )
                if isinstance(
                    string_classifications,
                    dict,
                )
                else []
            )

            unexplained_api_strings = [
                value
                for value in suspicious_api_strings
                if str(value).strip().lower()
                not in imported_functions
            ]

            if not unexplained_api_strings:
                reasons.append(
                    {
                        "points": 0,
                        "reason": (
                            "Suspicious API string artifacts were found, "
                            "but they are already explained by imported "
                            "API names; no duplicate risk points applied."
                        ),
                    }
                )
                continue

            add(
                points,
                (
                    f"{reason} "
                    f"Unexplained API strings: "
                    f"{len(unexplained_api_strings)}."
                ),
            )
            continue

        add(
            points,
            reason,
        )

    indicator_counts = report.get(
        "indicator_summary",
        {},
    ).get(
        "by_severity",
        {},
    )

    high_count = _safe_int(
        indicator_counts.get(
            "high",
            0,
        )
    )

    medium_count = _safe_int(
        indicator_counts.get(
            "medium",
            0,
        )
    )

    low_count = _safe_int(
        indicator_counts.get(
            "low",
            0,
        )
    )

    if high_count:
        add(
            high_count * 15,
            "High-severity static indicators were generated.",
        )

    if medium_count:
        add(
            medium_count * 7,
            "Medium-severity static indicators were generated.",
        )

    if low_count:
        add(
            low_count * 2,
            "Low-severity static indicators were generated.",
        )

    # Overlay is evidence worth reporting, but by itself it is too ambiguous
    # to receive automatic points.
    if report.get(
        "overlay",
        {},
    ).get(
        "present",
        False,
    ):
        reasons.append(
            {
                "points": 0,
                "reason": (
                    "File overlay detected; reported for analyst review "
                    "without automatic risk points."
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
            "Context-aware deterministic static observation scoring "
            "with explainable additive reasons; common API names are "
            "de-duplicated against imports and high-confidence "
            "process-injection scoring requires corroborating primitives; "
            "not a malware verdict."
        ),
        "reasons": reasons,
    }

# ============================================================================
# EXPLAINABILITY SUMMARY
# ============================================================================

def build_evidence_summary(
    report: dict[str, Any],
) -> dict[str, Any]:
    """
    Build a compact, analyst-oriented evidence summary.

    This layer groups existing observations without changing the underlying
    evidence or claiming that any single observation proves malicious intent.
    """
    section_data = report.get(
        "section_intelligence",
        {},
    )

    import_data = report.get(
        "import_intelligence",
        {},
    )

    string_summary = report.get(
        "strings",
        {},
    ).get(
        "summary",
        {},
    )

    string_classifications = report.get(
        "strings",
        {},
    ).get(
        "classifications",
        {},
    )

    indicator_summary = report.get(
        "indicator_summary",
        {},
    )

    evidence_groups: dict[str, dict[str, Any]] = {
        "memory_and_execution": {
            "observations": [],
            "strength": "none",
        },
        "networking": {
            "observations": [],
            "strength": "none",
        },
        "anti_analysis": {
            "observations": [],
            "strength": "none",
        },
        "packing_or_obfuscation": {
            "observations": [],
            "strength": "none",
        },
        "persistence_or_configuration": {
            "observations": [],
            "strength": "none",
        },
    }

    def add_observation(
        group: str,
        observation: str,
    ) -> None:
        evidence_groups[group]["observations"].append(
            observation
        )

    suspicious_groups = import_data.get(
        "suspicious_groups",
        {},
    )

    if isinstance(suspicious_groups, dict):
        if "process_injection" in suspicious_groups:
            add_observation(
                "memory_and_execution",
                (
                    "Process-injection-related imports: "
                    + ", ".join(
                        suspicious_groups["process_injection"]
                    )
                ),
            )

        if "process_access" in suspicious_groups:
            add_observation(
                "memory_and_execution",
                (
                    "Process-access imports: "
                    + ", ".join(
                        suspicious_groups["process_access"]
                    )
                ),
            )

        if "memory_operations" in suspicious_groups:
            add_observation(
                "memory_and_execution",
                (
                    "Memory-management/protection imports: "
                    + ", ".join(
                        suspicious_groups["memory_operations"]
                    )
                ),
            )

        if "process_execution" in suspicious_groups:
            add_observation(
                "memory_and_execution",
                (
                    "Process-execution-related imports: "
                    + ", ".join(
                        suspicious_groups["process_execution"]
                    )
                ),
            )

        if "networking" in suspicious_groups:
            add_observation(
                "networking",
                (
                    "Networking-related imports: "
                    + ", ".join(
                        suspicious_groups["networking"]
                    )
                ),
            )

        if "anti_analysis" in suspicious_groups:
            add_observation(
                "anti_analysis",
                (
                    "Anti-analysis imports: "
                    + ", ".join(
                        suspicious_groups["anti_analysis"]
                    )
                ),
            )

    if section_data.get(
        "flags",
        {},
    ).get(
        "has_executable_writable_section",
        False,
    ):
        add_observation(
            "memory_and_execution",
            "Executable and writable PE section.",
        )

    if section_data.get(
        "flags",
        {},
    ).get(
        "has_high_entropy_section",
        False,
    ):
        add_observation(
            "packing_or_obfuscation",
            "High-entropy PE section.",
        )

    if _safe_int(
        string_summary.get(
            "powershell_indicators"
        )
    ):
        add_observation(
            "networking",
            "PowerShell-related string artifacts.",
        )

    if _safe_int(
        string_summary.get(
            "command_indicators"
        )
    ):
        add_observation(
            "memory_and_execution",
            "Command-execution-related string artifacts.",
        )

    if _safe_int(
        string_summary.get(
            "urls"
        )
    ):
        add_observation(
            "networking",
            "URL artifacts in static strings.",
        )

    if _safe_int(
        string_summary.get(
            "ipv4"
        )
    ):
        add_observation(
            "networking",
            "IPv4 artifacts in static strings.",
        )

    if _safe_int(
        string_summary.get(
            "registry_paths"
        )
    ):
        add_observation(
            "persistence_or_configuration",
            "Registry path artifacts.",
        )

    if _safe_int(
        string_summary.get(
            "suspicious_apis"
        )
    ):
        add_observation(
            "memory_and_execution",
            "Suspicious API names in static strings.",
        )

    # Avoid coupling the summary to a particular indicator naming scheme.
    indicator_counts = indicator_summary.get(
        "by_severity",
        {},
    )

    if _safe_int(
        indicator_counts.get(
            "high",
            0,
        )
    ):
        add_observation(
            "memory_and_execution",
            "High-severity static indicators were generated.",
        )

    if _safe_int(
        indicator_counts.get(
            "medium",
            0,
        )
    ):
        add_observation(
            "memory_and_execution",
            "Medium-severity static indicators were generated.",
        )

    if string_classifications.get(
        "registry_paths",
    ):
        add_observation(
            "persistence_or_configuration",
            "Registry path classifications present.",
        )

    for group in evidence_groups.values():
        observations = group["observations"]

        if not observations:
            group["strength"] = "none"
        elif len(observations) == 1:
            group["strength"] = "observed"
        elif len(observations) == 2:
            group["strength"] = "corroborated"
        else:
            group["strength"] = "multiple"

    populated_groups = [
        group_name
        for group_name, group in evidence_groups.items()
        if group["observations"]
    ]

    return {
        "evidence_groups": evidence_groups,
        "populated_group_count": len(
            populated_groups
        ),
        "populated_groups": sorted(
            populated_groups
        ),
        "correlation_note": (
            "Grouping indicates related static observations only; "
            "it does not establish behavior or malicious intent."
        ),
    }


# ============================================================================
# ANALYSIS SUMMARY
# ============================================================================

def build_analysis_summary(
    report: dict[str, Any],
) -> dict[str, Any]:
    """Build a compact top-level summary that mirrors the detailed report."""
    sections = report.get(
        "sections",
        [],
    )

    imports = report.get(
        "imports",
        {},
    ).get(
        "libraries",
        [],
    )

    exports = report.get(
        "exports",
        {},
    )

    directories = report.get(
        "data_directories",
        [],
    )

    indicators = report.get(
        "indicator_summary",
        {},
    )

    risk = report.get(
        "risk_assessment",
        {},
    )

    evidence = report.get(
        "evidence_summary",
        {},
    )

    string_summary = report.get(
        "strings",
        {},
    ).get(
        "summary",
        {},
    )

    return {
        "static_only": True,
        "execution_performed": False,
        "sections_analyzed": len(sections),
        "imports_analyzed": len(imports),
        "exports_analyzed": _safe_int(
            exports.get("count")
        ),
        "data_directories_analyzed": len(
            directories
        ),
        "indicators_generated": _safe_int(
            indicators.get("total")
        ),
        "risk_score": _safe_int(
            risk.get("score")
        ),
        "risk_rating": str(
            risk.get(
                "rating",
                "MINIMAL",
            )
        ),
        "evidence_groups_populated": _safe_int(
            evidence.get(
                "populated_group_count",
                0,
            )
        ),
        "classified_string_artifacts": (
            _count_mapping_values(
                report.get(
                    "strings",
                    {},
                ).get(
                    "classifications",
                    {},
                )
                if isinstance(
                    report.get(
                        "strings",
                        {},
                    ).get(
                        "classifications",
                        {},
                    ),
                    dict,
                )
                else {}
            )
        ),
    }


# ============================================================================
# REPORT BUILDER
# ============================================================================

def build_report(
    path: Path,
) -> dict[str, Any]:
    """
    Build the complete SECURITY-MISC PE report.

    The target is read as bytes and analyzed statically.
    It is never executed.
    """
    started = time.perf_counter()

    path = (
        Path(path)
        .expanduser()
        .resolve()
    )

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
        raise ValueError(
            "PE file is empty."
        )

    if len(data) != file_size:
        file_size = len(data)

    # ------------------------------------------------------------------------
    # File identity
    # ------------------------------------------------------------------------

    hashes = calculate_hashes(data)

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
        optional_header_size=(
            headers.size_of_optional_header
        ),
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

    import_intelligence = analyze_imports(
        imports
    )

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

    certificate_analysis = (
        parse_certificate_table(data)
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

    string_classifications = (
        normalize_string_classifications(
            string_report
        )
    )

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
            "classifications": string_classifications,
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
    # Explainability
    # ------------------------------------------------------------------------

    report["evidence_summary"] = (
        build_evidence_summary(
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

    # ------------------------------------------------------------------------
    # Top-level analysis summary
    # ------------------------------------------------------------------------

    report["analysis_summary"] = (
        build_analysis_summary(
            report
        )
    )

    return report


# ============================================================================
# TERMINAL REPORT
# ============================================================================

def print_report(
    report: dict[str, Any],
    string_limit: int = MAX_CLASSIFIED_STRINGS_DISPLAY,
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
    evidence = report["evidence_summary"]
    metrics = report["analysis_metrics"]
    analysis_summary = report["analysis_summary"]

    print()
    print("=" * 100)
    print(
        f"{ENGINE_NAME} :: PE STATIC ANALYSIS ENGINE"
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
            f"{str(section.get('name', '')):<12}"
            f"{_safe_int(section.get('virtual_size')):>12,}"
            f"{_safe_int(section.get('raw_size')):>12,}"
            f"{_safe_int(section.get('virtual_address')):>12X}"
            f"{_safe_float(section.get('entropy')):>10.4f}"
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
        print(
            "[+] No populated data directories."
        )
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

    if import_intelligence[
        "suspicious_groups"
    ]:
        print()
        print("IMPORT CATEGORIES")
        print("-" * 100)

        for group_name, functions in (
            import_intelligence[
                "suspicious_groups"
            ].items()
        ):
            print(
                f"{group_name:<24}: "
                f"{', '.join(functions)}"
            )

    print()
    print("IMPORT TABLE")
    print("-" * 100)

    for library in imports.get(
        "libraries",
        [],
    ):
        dll = library.get(
            "dll",
            "<unknown>",
        )

        function_count = _safe_int(
            library.get(
                "function_count"
            )
        )

        print(
            f"\n  {dll} "
            f"({function_count} functions)"
        )

        for function in library.get(
            "functions",
            [],
        )[:MAX_IMPORT_FUNCTIONS_DISPLAY]:
            print(
                f"    {function}"
            )

        if function_count > MAX_IMPORT_FUNCTIONS_DISPLAY:
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
    ][:MAX_EXPORTS_DISPLAY]:
        print(
            f"  {function}"
        )

    if exports["count"] > MAX_EXPORTS_DISPLAY:
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
            certificate.get(
                "entries",
                [],
            ),
            start=1,
        ):
            print(
                f"    Entry {index}: "
                f"Type={entry.get('type')} "
                f"Revision={entry.get('revision')} "
                f"PKCS={entry.get('is_pkcs_signed_data')}"
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

    classifications = strings[
        "classifications"
    ]

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
        values = classifications.get(
            key,
            [],
        )

        if not values:
            continue

        print()
        print(title)
        print("-" * 100)

        for value in values[:string_limit]:
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
                f"[{severity:<8}] "
                f"{indicator.get('name', 'Unnamed')}"
            )

            print(
                f"         "
                f"{indicator.get('description', '')}"
            )

    # ------------------------------------------------------------------------
    # Evidence summary
    # ------------------------------------------------------------------------

    print()
    print("EVIDENCE SUMMARY")
    print("-" * 100)

    print(
        f"Populated groups : "
        f"{evidence['populated_group_count']}"
    )

    for group_name, group in (
        evidence["evidence_groups"].items()
    ):
        observations = group["observations"]

        print(
            f"  {group_name:<28}"
            f"{group['strength']:<14}"
            f"{len(observations)} observation(s)"
        )

        for observation in observations:
            print(
                f"    - {observation}"
            )

    print(
        f"Note             : "
        f"{evidence['correlation_note']}"
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
            points = _safe_int(
                reason.get(
                    "points"
                )
            )

            prefix = "+" if points else " "
            print(
                f"  {prefix}{points:>3}  "
                f"{reason.get('reason', '')}"
            )

    # ------------------------------------------------------------------------
    # Analysis summary
    # ------------------------------------------------------------------------

    print()
    print("ANALYSIS SUMMARY")
    print("-" * 100)

    print(
        f"Static only            : "
        f"{analysis_summary['static_only']}"
    )

    print(
        f"Execution performed    : "
        f"{analysis_summary['execution_performed']}"
    )

    print(
        f"Sections analyzed      : "
        f"{analysis_summary['sections_analyzed']}"
    )

    print(
        f"Imports analyzed       : "
        f"{analysis_summary['imports_analyzed']}"
    )

    print(
        f"Exports analyzed       : "
        f"{analysis_summary['exports_analyzed']}"
    )

    print(
        f"Data directories       : "
        f"{analysis_summary['data_directories_analyzed']}"
    )

    print(
        f"Indicators generated   : "
        f"{analysis_summary['indicators_generated']}"
    )

    print(
        f"Evidence groups        : "
        f"{analysis_summary['evidence_groups_populated']}"
    )

    print(
        f"Risk score             : "
        f"{analysis_summary['risk_score']}/100"
    )

    print(
        f"Risk rating            : "
        f"{analysis_summary['risk_rating']}"
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
    """Build the command-line parser."""
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
        help=(
            "Write the complete analysis "
            "report to JSON."
        ),
    )

    parser.add_argument(
        "--string-limit",
        type=int,
        default=MAX_CLASSIFIED_STRINGS_DISPLAY,
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
    """CLI entry point."""
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

    except FileNotFoundError as exc:
        print(
            f"[!] File not found: {exc}"
        )
        return 2

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
            f"{type(exc).__name__}: {exc}"
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
