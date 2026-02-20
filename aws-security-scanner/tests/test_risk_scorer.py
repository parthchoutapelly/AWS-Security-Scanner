"""Unit tests for the risk scoring algorithm."""
import pytest
from src.analysis.risk_scorer import RiskScorer


def test_critical_public_finding_scores_high():
    """Public, CRITICAL finding with PII should score >= 8.0."""
    scorer = RiskScorer()
    finding = {"severity": "CRITICAL", "issue": "Public bucket ACL", "cis_control": "2.1.5"}
    context = {
        "publicly_accessible": True,
        "compliance_violation": True,
        "affected_resource_count": 50,
        "contains_pii": True,
        "revenue_impacting": True,
        "part_of_attack_chain": False,
    }
    score = scorer.score_finding(finding, context)
    assert score >= 8.0, f"Expected >= 8.0 but got {score}"
    assert finding["risk_score"] == score
    assert "exploitability" in finding["risk_rationale"]


def test_low_severity_scores_below_4():
    """A low-severity, non-public finding should score < 4.0."""
    scorer = RiskScorer()
    finding = {"severity": "LOW", "issue": "Minor versioning gap", "cis_control": "2.1.3"}
    context = {
        "publicly_accessible": False,
        "compliance_violation": False,
        "affected_resource_count": 1,
        "contains_pii": False,
        "revenue_impacting": False,
        "part_of_attack_chain": False,
    }
    score = scorer.score_finding(finding, context)
    assert score < 4.0, f"Expected < 4.0 but got {score}"


def test_attack_chain_boost():
    """Findings in an attack chain should score higher than isolated ones."""
    scorer = RiskScorer()
    finding_base = {"severity": "HIGH", "issue": "SSH open to world", "cis_control": "5.2", "resource": "sg-123"}
    finding_chain = {"severity": "HIGH", "issue": "SSH open to world", "cis_control": "5.2", "resource": "sg-123"}

    ctx_base = {"publicly_accessible": True, "compliance_violation": True, "affected_resource_count": 1, "contains_pii": False, "revenue_impacting": False, "part_of_attack_chain": False}
    ctx_chain = {**ctx_base, "part_of_attack_chain": True}

    score_base = scorer.score_finding(finding_base, ctx_base)
    score_chain = scorer.score_finding(finding_chain, ctx_chain)

    assert score_chain >= score_base, "Attack chain member should score at least as high"


def test_score_is_capped_at_10():
    """Risk score must never exceed 10."""
    scorer = RiskScorer()
    finding = {"severity": "CRITICAL", "issue": "Root MFA disabled", "cis_control": "1.5"}
    context = {
        "publicly_accessible": True, "compliance_violation": True,
        "affected_resource_count": 500, "contains_pii": True,
        "revenue_impacting": True, "part_of_attack_chain": True,
    }
    score = scorer.score_finding(finding, context)
    assert score <= 10.0


def test_score_all_returns_sorted():
    """score_all should return findings sorted by risk_score descending."""
    scorer = RiskScorer()
    findings = [
        {"severity": "LOW",      "issue": "Versioning",  "cis_control": "2.1.3"},
        {"severity": "CRITICAL", "issue": "Public ACL",  "cis_control": "2.1.5"},
        {"severity": "MEDIUM",   "issue": "No logging",  "cis_control": "2.1.2"},
    ]
    result = scorer.score_all(findings)
    scores = [f["risk_score"] for f in result]
    assert scores == sorted(scores, reverse=True), "Findings not sorted by risk_score"


def test_cost_impact_is_annotated():
    """Finding should have cost_impact after scoring."""
    scorer = RiskScorer()
    finding = {"severity": "HIGH", "issue": "No encryption", "cis_control": "2.1.1"}
    scorer.score_finding(finding, {})
    assert "cost_impact" in finding
    assert "description" in finding["cost_impact"]


def test_mark_attack_chain_members():
    """Findings in attack chain nodes should get boosted scores."""
    scorer = RiskScorer()
    findings = [
        {"id": "f1", "severity": "HIGH", "issue": "Public ACL", "cis_control": "2.1.5", "resource": "public-bucket"},
        {"id": "f2", "severity": "LOW",  "issue": "Versioning",  "cis_control": "2.1.3", "resource": "other-bucket"},
    ]
    scorer.score_all(findings)
    score_before = findings[0]["risk_score"]

    attack_paths = [{"path": ["public-bucket", "admin-role"]}]
    scorer.mark_attack_chain_members(findings, attack_paths)

    assert findings[0]["risk_score"] >= score_before
    assert "attack_chain_boost" in findings[0]["risk_rationale"]
