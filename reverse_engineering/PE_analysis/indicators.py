from __future__ import annotations

from dataclasses import dataclass


SUSPICIOUS_SECTION_NAMES = {
    "upx0",
    "upx1",
    "upx2",
    ".upx",
    ".aspack",
    ".adata",
    ".packed",
    ".petite",
    ".themida",
}


@dataclass(slots=True)
class Indicator:
    severity: str
    name: str
    description: str


def analyze_sections(sections: list[dict]) -> list[Indicator]:
    findings: list[Indicator] = []

    for section in sections:
        name = section["name"].lower()
        entropy = float(section["entropy"])
        characteristics = section["characteristics"]

        if name in SUSPICIOUS_SECTION_NAMES:
            findings.append(
                Indicator(
                    severity="medium",
                    name="Known packer-style section name",
                    description=(
                        f"Section '{section['name']}' matches a "
                        "commonly observed packer-style name."
                    ),
                )
            )

        if entropy >= 7.2:
            findings.append(
                Indicator(
                    severity="medium",
                    name="Very high section entropy",
                    description=(
                        f"Section '{section['name']}' has entropy "
                        f"{entropy:.4f}. High entropy can indicate "
                        "compression or encryption, but is not proof "
                        "of packing or maliciousness."
                    ),
                )
            )

        if "WRITE" in characteristics and "EXECUTE" in characteristics:
            findings.append(
                Indicator(
                    severity="high",
                    name="Writable executable section",
                    description=(
                        f"Section '{section['name']}' is marked both "
                        "writable and executable."
                    ),
                )
            )

    return findings


def analyze_imports(imports: dict) -> list[Indicator]:
    findings: list[Indicator] = []

    libraries = imports.get("libraries", [])

    if not libraries:
        findings.append(
            Indicator(
                severity="info",
                name="No import table recovered",
                description=(
                    "No import libraries were recovered by the "
                    "static parser. This can occur with unusual "
                    "or malformed binaries and should be investigated "
                    "before drawing conclusions."
                ),
            )
        )

    for library in libraries:
        dll = library.get("dll", "")

        if not dll:
            continue

        lowered = dll.lower()

        if lowered in {
            "wininet.dll",
            "winhttp.dll",
            "ws2_32.dll",
            "urlmon.dll",
        }:
            findings.append(
                Indicator(
                    severity="info",
                    name="Network-capable Windows library",
                    description=(
                        f"Imported library '{dll}' provides "
                        "network-related functionality."
                    ),
                )
            )

    return findings


def generate_indicators(report: dict) -> list[dict]:
    findings = []

    findings.extend(
        analyze_sections(
            report.get("sections", [])
        )
    )

    findings.extend(
        analyze_imports(
            report.get("imports", {})
        )
    )

    return [
        {
            "severity": finding.severity,
            "name": finding.name,
            "description": finding.description,
        }
        for finding in findings
    ]


def print_indicators(indicators: list[dict]) -> None:
    print()
    print("=" * 78)
    print("STATIC INDICATORS")
    print("=" * 78)

    if not indicators:
        print("[+] No static indicators were generated.")
        print("=" * 78)
        return

    for finding in indicators:
        severity = finding["severity"].upper()

        print(
            f"[{severity:<6}] "
            f"{finding['name']}"
        )
        print(
            f"         {finding['description']}"
        )

    print("=" * 78)