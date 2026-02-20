"""Unit tests for the multi-framework compliance mapper."""
import pytest
from src.compliance.mapper import ComplianceMapper, FrameworkMapper


# ── FrameworkMapper ────────────────────────────────────────────────────────

def test_cis_100_when_no_findings():
    m = FrameworkMapper("cis")
    r = m.map_findings([])
    assert r["score"] == 100.0
    assert r["controls_failed"] == 0


def test_cis_fails_on_matching_control():
    m = FrameworkMapper("cis")
    findings = [{"cis_control": "1.5", "severity": "CRITICAL", "resource": "root", "issue": "No MFA"}]
    r = m.map_findings(findings)
    failed_ids = [c["id"] for c in r["failed_controls"]]
    assert "1.5" in failed_ids
    assert r["score"] < 100.0


def test_nist_cross_reference():
    """CIS 1.5 → NIST PR.AC-1 via cross-reference map."""
    m = FrameworkMapper("nist")
    findings = [{"cis_control": "1.5", "severity": "CRITICAL", "resource": "root", "issue": "No MFA"}]
    r = m.map_findings(findings)
    failed_ids = [c["id"] for c in r["failed_controls"]]
    assert "PR.AC-1" in failed_ids


def test_pci_cross_reference():
    """CIS 1.5 → PCI-DSS 8.4.2 via cross-reference map."""
    m = FrameworkMapper("pci")
    findings = [{"cis_control": "1.5", "severity": "CRITICAL", "resource": "root", "issue": "No MFA"}]
    r = m.map_findings(findings)
    failed_ids = [c["id"] for c in r["failed_controls"]]
    assert "8.4.2" in failed_ids


# ── ComplianceMapper ───────────────────────────────────────────────────────

def test_all_frameworks_present():
    mapper = ComplianceMapper()
    result = mapper.map_findings([])
    assert "frameworks" in result
    assert "cis" in result["frameworks"]
    assert "nist" in result["frameworks"]
    assert "pci" in result["frameworks"]


def test_primary_score_is_cis():
    mapper = ComplianceMapper()
    result = mapper.map_findings([])
    assert result["score"] == result["frameworks"]["cis"]["score"]


def test_score_drops_with_more_findings():
    mapper = ComplianceMapper(frameworks=["cis"])
    few = [{"cis_control": "1.5", "severity": "CRITICAL", "resource": "r", "issue": "x"}]
    many = [
        {"cis_control": c, "severity": "HIGH", "resource": "r", "issue": "x"}
        for c in ["1.5", "2.1.5", "3.1", "5.2", "5.4", "1.4", "1.16"]
    ]
    score_few  = mapper.map_findings(few)["score"]
    score_many = mapper.map_findings(many)["score"]
    assert score_many < score_few


def test_nist_annotation_added_to_finding():
    """ComplianceMapper should annotate findings with nist_control."""
    mapper = ComplianceMapper(frameworks=["cis", "nist"])
    findings = [{"cis_control": "5.2", "severity": "CRITICAL", "resource": "sg", "issue": "SSH"}]
    mapper.map_findings(findings)
    # PR.AC-5 mapped from CIS 5.2 via nist_csf.json
    assert "nist_control" in findings[0]


def test_get_framework_names():
    mapper = ComplianceMapper()
    names = mapper.get_framework_names()
    assert len(names) == 3
    assert all("v" in v for v in names.values())  # version string present
