from __future__ import annotations

import json
import struct
from pathlib import Path

from reverse_engineering.PE_analysis.certificates import (
    parse_certificate_table,
    summarize_certificates,
)
from reverse_engineering.PE_analysis.exports import parse_exports
from reverse_engineering.PE_analysis.imports import parse_imports
from reverse_engineering.PE_analysis.pe_analyzer import build_report
from reverse_engineering.PE_analysis.parser import load_pe
from reverse_engineering.PE_analysis.sections import parse_sections


# ============================================================================
# TEST FIXTURE / CONSTANTS
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

EXPECTED_RISK_RATINGS = {
    "MINIMAL",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}

EXPECTED_SEVERITIES = {
    "high",
    "medium",
    "low",
    "info",
}


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

    assert len(sections) == headers.number_of_sections

    assert all(
        section.name
        for section in sections
    )

    assert all(
        section.entropy >= 0.0
        for section in sections
    )

    assert all(
        section.raw_size >= 0
        for section in sections
    )

    assert all(
        section.virtual_size >= 0
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

    is_64_bit = headers.optional_magic == 0x20B

    directory_offset = (
        optional_offset
        + (
            112
            if is_64_bit
            else 96
        )
    )

    import_rva, import_size = struct.unpack_from(
        "<II",
        data,
        directory_offset + 8,
    )

    imports = parse_imports(
        data,
        import_rva,
        import_size,
        sections,
        is_64_bit,
    )

    assert isinstance(imports, list)
    assert len(imports) > 0

    for library in imports:
        assert isinstance(library, dict)
        assert isinstance(library.get("dll"), str)
        assert isinstance(library.get("functions"), list)


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

    is_64_bit = headers.optional_magic == 0x20B

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

    assert isinstance(exports, list)

    assert all(
        isinstance(function, str)
        for function in exports
    )


# ============================================================================
# CERTIFICATE ANALYSIS TESTS
# ============================================================================


def test_certificate_analysis() -> None:
    """Verify certificate-table parsing and certificate summarization."""

    data, _headers = load_pe(PYTHON_EXE)

    certificate = parse_certificate_table(data)

    assert isinstance(certificate, dict)
    assert "present" in certificate
    assert "entries" in certificate

    assert isinstance(
        certificate["present"],
        bool,
    )

    assert isinstance(
        certificate["entries"],
        list,
    )

    summary = summarize_certificates(certificate)

    assert isinstance(summary, dict)

    assert summary["entry_count"] == len(
        certificate["entries"]
    )


# ============================================================================
# COMPLETE REPORT TESTS
# ============================================================================


def test_complete_report() -> None:
    """Verify that the complete PE analysis report is generated."""

    report = build_report(PYTHON_EXE)

    assert report["tool"] == "SECURITY-MISC"
    assert report["module"] == "pe_analyzer"
    assert isinstance(report["analysis_version"], str)
    assert report["size_bytes"] > 0

    required_keys = {
        "tool",
        "module",
        "analysis_version",
        "analysis_time",
        "file",
        "size_bytes",
        "file_metadata",
        "hashes",
        "headers",
        "data_directories",
        "sections",
        "section_intelligence",
        "imports",
        "import_intelligence",
        "exports",
        "certificate_analysis",
        "certificate_summary",
        "strings",
        "overlay",
        "indicators",
        "indicator_summary",
        "risk_assessment",
        "analysis_metrics",
        "analysis_summary",
    }

    assert required_keys.issubset(report.keys())


# ============================================================================
# INDICATOR TESTS
# ============================================================================


def test_indicator_summary_is_consistent() -> None:
    """Verify that indicator totals match their severity breakdown."""

    report = build_report(PYTHON_EXE)

    indicators = report["indicators"]
    summary = report["indicator_summary"]

    assert isinstance(indicators, list)
    assert isinstance(summary, dict)
    assert summary["total"] == len(indicators)

    severity_counts = summary["by_severity"]

    assert isinstance(severity_counts, dict)
    assert set(severity_counts) == EXPECTED_SEVERITIES

    for severity in EXPECTED_SEVERITIES:
        assert isinstance(
            severity_counts[severity],
            int,
        )
        assert severity_counts[severity] >= 0

    assert summary["total"] == sum(
        severity_counts.values()
    )

    for indicator in indicators:
        severity = str(
            indicator.get("severity", "info")
        ).lower()

        assert severity in EXPECTED_SEVERITIES


# ============================================================================
# RISK ASSESSMENT TESTS
# ============================================================================


def test_risk_assessment_is_present_and_valid() -> None:
    """Verify the structure and bounds of the deterministic risk assessment."""

    report = build_report(PYTHON_EXE)
    risk = report["risk_assessment"]

    assert isinstance(risk, dict)

    assert "score" in risk
    assert "rating" in risk
    assert "method" in risk
    assert "reasons" in risk

    assert isinstance(risk["score"], int)
    assert 0 <= risk["score"] <= 100

    assert risk["rating"] in EXPECTED_RISK_RATINGS

    assert isinstance(risk["method"], str)
    assert len(risk["method"].strip()) > 0

    assert isinstance(risk["reasons"], list)


def test_risk_reasons_have_valid_structure() -> None:
    """Verify that every risk reason contains valid points and text."""

    report = build_report(PYTHON_EXE)
    risk = report["risk_assessment"]

    for reason in risk["reasons"]:
        assert isinstance(reason, dict)

        assert "points" in reason
        assert "reason" in reason

        assert isinstance(reason["points"], int)
        assert reason["points"] >= 0

        assert isinstance(reason["reason"], str)
        assert len(reason["reason"].strip()) > 0


def test_risk_score_matches_reason_points() -> None:
    """Verify that the displayed score equals the capped reason total."""

    report = build_report(PYTHON_EXE)
    risk = report["risk_assessment"]

    calculated_score = sum(
        reason["points"]
        for reason in risk["reasons"]
    )

    expected_score = min(
        calculated_score,
        100,
    )

    assert risk["score"] == expected_score


# ============================================================================
# RISK RATING CONSISTENCY
# ============================================================================


def test_risk_rating_matches_score() -> None:
    """Verify that the risk rating follows the analyzer's score thresholds."""

    report = build_report(PYTHON_EXE)
    risk = report["risk_assessment"]

    score = risk["score"]
    rating = risk["rating"]

    if score >= 80:
        assert rating == "CRITICAL"
    elif score >= 70:
        assert rating == "HIGH"
    elif score >= 40:
        assert rating == "MEDIUM"
    elif score >= 15:
        assert rating == "LOW"
    else:
        assert rating == "MINIMAL"


# ============================================================================
# RISK REASON QUALITY
# ============================================================================


def test_risk_reasons_are_non_negative() -> None:
    """Verify that risk scoring never contains negative reason weights."""

    report = build_report(PYTHON_EXE)

    reasons = report["risk_assessment"]["reasons"]

    assert all(
        reason["points"] >= 0
        for reason in reasons
    )


def test_risk_reasons_have_unique_descriptions() -> None:
    """Verify that risk explanations are not duplicated."""

    report = build_report(PYTHON_EXE)

    reasons = report["risk_assessment"]["reasons"]

    descriptions = [
        reason["reason"]
        for reason in reasons
    ]

    assert len(descriptions) == len(
        set(descriptions)
    )


# ============================================================================
# ANALYSIS SUMMARY TESTS
# ============================================================================


def test_analysis_summary_is_present_and_consistent() -> None:
    """Verify that the top-level analysis summary matches the report."""

    report = build_report(PYTHON_EXE)
    summary = report["analysis_summary"]

    assert isinstance(summary, dict)

    assert summary["static_only"] is True
    assert summary["execution_performed"] is False

    assert summary["sections_analyzed"] == len(
        report["sections"]
    )

    assert summary["imports_analyzed"] == len(
        report["imports"]["libraries"]
    )

    assert summary["exports_analyzed"] == report[
        "exports"
    ]["count"]

    assert summary[
        "data_directories_analyzed"
    ] == len(
        report["data_directories"]
    )

    assert summary[
        "indicators_generated"
    ] == report[
        "indicator_summary"
    ]["total"]

    assert summary["risk_score"] == report[
        "risk_assessment"
    ]["score"]

    assert summary["risk_rating"] == report[
        "risk_assessment"
    ]["rating"]


# ============================================================================
# HASH TESTS
# ============================================================================


def test_report_contains_hashes() -> None:
    """Verify that the report contains stable file hashes."""

    report = build_report(PYTHON_EXE)
    hashes = report["hashes"]

    assert isinstance(hashes, dict)

    assert set(hashes) == {
        "md5",
        "sha1",
        "sha256",
    }

    for value in hashes.values():
        assert isinstance(value, str)
        assert len(value) > 0

    assert report["file_metadata"]["hashes"] == hashes


# ============================================================================
# DETERMINISM TEST
# ============================================================================


def test_risk_assessment_is_deterministic() -> None:
    """Verify that repeated static analysis produces the same risk result."""

    first_report = build_report(PYTHON_EXE)
    second_report = build_report(PYTHON_EXE)

    assert first_report["risk_assessment"] == (
        second_report["risk_assessment"]
    )

    assert first_report["indicator_summary"] == (
        second_report["indicator_summary"]
    )


# ============================================================================
# JSON SERIALIZATION TEST
# ============================================================================


def test_report_is_json_serializable() -> None:
    """Verify that the complete report can be serialized and decoded."""

    report = build_report(PYTHON_EXE)

    serialized = json.dumps(report)

    assert isinstance(serialized, str)
    assert len(serialized) > 0

    decoded = json.loads(serialized)

    assert isinstance(decoded, dict)
    assert decoded["tool"] == "SECURITY-MISC"
    assert decoded["module"] == "pe_analyzer"

    assert decoded["risk_assessment"]["score"] == (
        report["risk_assessment"]["score"]
    )

    assert decoded["analysis_summary"] == (
        report["analysis_summary"]
    )
