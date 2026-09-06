from __future__ import annotations

import json
import struct
from pathlib import Path

from reverse_engineering.PE_analysis.certificates import (
    parse_certificate_table,
    summarize_certificates,
)
from reverse_engineering.PE_analysis.exports import (
    parse_exports,
)
from reverse_engineering.PE_analysis.imports import (
    parse_imports,
)
from reverse_engineering.PE_analysis.parser import (
    load_pe,
)
from reverse_engineering.PE_analysis.pe_analyzer import (
    build_report,
)
from reverse_engineering.PE_analysis.sections import (
    parse_sections,
)


# ============================================================================
# TEST FIXTURE
# ============================================================================

PYTHON_EXE = (
    Path.home()
    / "AppData"
    / "Local"
    / "Programs"
    / "Python"
    / "Python311"
    / "python.exe"
)


# ============================================================================
# BASIC FILE VALIDATION
# ============================================================================


def test_python_executable_exists() -> None:
    """Verify that the PE sample used by the test suite exists."""

    assert PYTHON_EXE.exists()
    assert PYTHON_EXE.is_file()


# ============================================================================
# PE PARSER TESTS
# ============================================================================


def test_parser_loads_python() -> None:
    """Verify that the PE parser can load Python.exe."""

    data, headers = load_pe(PYTHON_EXE)

    assert len(data) > 0

    assert headers.machine_name
    assert headers.bitness in {
        "PE32 (32-bit)",
        "PE32+ (64-bit)",
    }

    assert headers.number_of_sections > 0
    assert headers.image_base > 0


# ============================================================================
# SECTION ANALYSIS TESTS
# ============================================================================


def test_sections_are_parsed() -> None:
    """Verify that all PE sections are parsed correctly."""

    data, headers = load_pe(PYTHON_EXE)

    optional_offset = (
        headers.pe_offset
        + 4
        + 20
    )

    sections_offset = (
        optional_offset
        + headers.size_of_optional_header
    )

    sections = parse_sections(
        data,
        sections_offset,
        headers.number_of_sections,
    )

    assert len(sections) == (
        headers.number_of_sections
    )

    assert all(
        section.name
        for section in sections
    )

    assert all(
        section.entropy >= 0.0
        for section in sections
    )


# ============================================================================
# IMPORT ANALYSIS TESTS
# ============================================================================


def test_imports_are_parsed() -> None:
    """Verify that the PE import directory can be parsed."""

    data, headers = load_pe(PYTHON_EXE)

    optional_offset = (
        headers.pe_offset
        + 4
        + 20
    )

    sections_offset = (
        optional_offset
        + headers.size_of_optional_header
    )

    sections = parse_sections(
        data,
        sections_offset,
        headers.number_of_sections,
    )

    is_64_bit = (
        headers.optional_magic == 0x20B
    )

    directory_offset = (
        optional_offset
        + (
            112
            if is_64_bit
            else 96
        )
    )

    import_rva, import_size = (
        struct.unpack_from(
            "<II",
            data,
            directory_offset + 8,
        )
    )

    imports = parse_imports(
        data,
        import_rva,
        import_size,
        sections,
        is_64_bit,
    )

    assert isinstance(
        imports,
        list,
    )

    # Python.exe should contain
    # at least one normal import library.
    assert len(imports) > 0


# ============================================================================
# EXPORT ANALYSIS TESTS
# ============================================================================


def test_exports_are_parseable() -> None:
    """Verify that the PE export directory is safely parseable."""

    data, headers = load_pe(PYTHON_EXE)

    optional_offset = (
        headers.pe_offset
        + 4
        + 20
    )

    sections_offset = (
        optional_offset
        + headers.size_of_optional_header
    )

    sections = parse_sections(
        data,
        sections_offset,
        headers.number_of_sections,
    )

    is_64_bit = (
        headers.optional_magic == 0x20B
    )

    directory_offset = (
        optional_offset
        + (
            112
            if is_64_bit
            else 96
        )
    )

    export_rva = struct.unpack_from(
        "<I",
        data,
        directory_offset,
    )[0]

    exports = parse_exports(
        data,
        export_rva,
        sections,
    )

    assert isinstance(
        exports,
        list,
    )


# ============================================================================
# CERTIFICATE ANALYSIS TESTS
# ============================================================================


def test_certificate_analysis() -> None:
    """Verify certificate-table parsing and certificate summarization."""

    data, _headers = load_pe(PYTHON_EXE)

    certificate = (
        parse_certificate_table(data)
    )

    assert isinstance(
        certificate,
        dict,
    )

    assert "present" in certificate
    assert "entries" in certificate

    summary = summarize_certificates(
        certificate
    )

    assert isinstance(
        summary,
        dict,
    )

    assert summary["entry_count"] == len(
        certificate["entries"]
    )


# ============================================================================
# COMPLETE REPORT TESTS
# ============================================================================


def test_complete_report() -> None:
    """Verify that the complete PE analysis report is generated."""

    report = build_report(
        PYTHON_EXE
    )

    assert report["tool"] == (
        "SECURITY-MISC"
    )

    assert report["module"] == (
        "pe_analyzer"
    )

    assert report["size_bytes"] > 0

    assert "headers" in report
    assert "sections" in report
    assert "imports" in report
    assert "exports" in report

    assert "certificate_analysis" in report
    assert "certificate_summary" in report

    assert "strings" in report
    assert "overlay" in report

    assert "indicators" in report
    assert "indicator_summary" in report

    assert "risk_assessment" in report

    assert "analysis_metrics" in report


# ============================================================================
# INDICATOR TESTS
# ============================================================================


def test_indicator_summary_is_consistent() -> None:
    """Verify that the indicator summary has a valid structure."""

    report = build_report(
        PYTHON_EXE
    )

    indicators = report["indicators"]
    summary = report["indicator_summary"]

    assert isinstance(
        indicators,
        list,
    )

    assert isinstance(
        summary,
        dict,
    )

    assert summary["total"] == len(
        indicators
    )

    assert "by_severity" in summary

    severity_counts = (
        summary["by_severity"]
    )

    assert isinstance(
        severity_counts,
        dict,
    )

    for severity in (
        "high",
        "medium",
        "low",
        "info",
    ):
        assert severity in severity_counts
        assert isinstance(
            severity_counts[severity],
            int,
        )
        assert severity_counts[severity] >= 0


# ============================================================================
# RISK ASSESSMENT TESTS
# ============================================================================


def test_risk_assessment_is_present_and_valid() -> None:
    """Verify the structure and bounds of the deterministic risk assessment."""

    report = build_report(
        PYTHON_EXE
    )

    risk = report["risk_assessment"]

    assert isinstance(
        risk,
        dict,
    )

    assert "score" in risk
    assert "rating" in risk
    assert "method" in risk
    assert "reasons" in risk

    assert isinstance(
        risk["score"],
        int,
    )

    assert 0 <= risk["score"] <= 100

    assert risk["rating"] in {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }

    assert isinstance(
        risk["method"],
        str,
    )

    assert len(
        risk["method"]
    ) > 0

    assert isinstance(
        risk["reasons"],
        list,
    )


def test_risk_reasons_have_valid_structure() -> None:
    """Verify that every risk reason contains points and a description."""

    report = build_report(
        PYTHON_EXE
    )

    risk = report["risk_assessment"]

    for reason in risk["reasons"]:
        assert isinstance(
            reason,
            dict,
        )

        assert "points" in reason
        assert "reason" in reason

        assert isinstance(
            reason["points"],
            int,
        )

        assert isinstance(
            reason["reason"],
            str,
        )

        assert len(
            reason["reason"]
        ) > 0

        assert reason["points"] >= 0


def test_risk_score_matches_reason_points() -> None:
    """Verify that the displayed risk score equals the sum of its reasons."""

    report = build_report(
        PYTHON_EXE
    )

    risk = report["risk_assessment"]

    calculated_score = sum(
        reason["points"]
        for reason in risk["reasons"]
    )

    assert risk["score"] == min(
        calculated_score,
        100,
    )


# ============================================================================
# JSON SERIALIZATION TEST
# ============================================================================


def test_report_is_json_serializable() -> None:
    """Verify that the complete report can be serialized to JSON."""

    report = build_report(
        PYTHON_EXE
    )

    serialized = json.dumps(
        report
    )

    assert isinstance(
        serialized,
        str,
    )

    assert len(
        serialized
    ) > 0

    # Also verify that the serialized output
    # can be decoded back into a Python object.
    decoded = json.loads(
        serialized
    )

    assert isinstance(
        decoded,
        dict,
    )

    assert decoded["tool"] == (
        "SECURITY-MISC"
    )