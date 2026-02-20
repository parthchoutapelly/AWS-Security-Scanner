"""
Risk Scoring Algorithm
======================
Calculates a composite risk score (0–10) for each finding using a
CVSS-inspired formula:

    RiskScore = (Exploitability × 0.4) + (BlastRadius × 0.3) + (BusinessImpact × 0.3)

Scores are normalised to the 0–10 range and annotated with a rationale
breakdown so analysts understand *why* a finding is ranked the way it is.
"""
from typing import Dict, Any


# ── Severity base scores ────────────────────────────────────────────────────
SEVERITY_BASE: Dict[str, float] = {
    "CRITICAL": 9.0,
    "HIGH": 7.0,
    "MEDIUM": 5.0,
    "LOW": 2.5,
}

# ── Cost-impact templates by CIS control prefix ────────────────────────────
COST_IMPACT_TEMPLATES: Dict[str, Dict] = {
    "1.": {
        "description": "Identity breach risk — compromised IAM credentials can lead to full account takeover",
        "estimated_penalty": "Account takeover, data exfiltration costs, potential GDPR fines (up to 4% global revenue)",
    },
    "2.1": {
        "description": "Data exposure risk — public or unencrypted S3 data",
        "estimated_penalty": "GDPR / HIPAA breach fines; reputational damage; class action exposure",
    },
    "2.3": {
        "description": "Database exposure risk",
        "estimated_penalty": "Data breach fines; PCI-DSS penalties (up to $100k/month); legal liability",
    },
    "3.": {
        "description": "Audit trail gap — without logs, breaches may go undetected for months",
        "estimated_penalty": "SOC 2 audit failure; regulatory fines; extended breach investigation costs",
    },
    "5.": {
        "description": "Network exposure — overly permissive network rules enable lateral movement",
        "estimated_penalty": "Ransomware deployment risk; data exfiltration; production downtime",
    },
}


class RiskScorer:
    """
    CVSS-inspired composite risk scorer.

    Produces a score 0–10 and a human-readable rationale for every finding.
    """

    # Exploitability sub-factor weights
    EXPLOITABILITY_WEIGHTS = {
        "public_exposure": 3.0,
        "no_auth_required": 2.5,
        "known_exploit_pattern": 2.0,
        "lateral_movement_possible": 1.5,
        "privileged_access": 1.0,
    }

    def score_finding(self, finding: Dict[str, Any], context: Dict[str, Any]) -> float:
        """
        Score a single finding and annotate it with risk_score + risk_rationale.

        Args:
            finding: The finding dict (mutated in-place).
            context: Environmental context for this resource:
                - publicly_accessible (bool)
                - part_of_attack_chain (bool)
                - affected_resource_count (int)
                - contains_pii (bool)
                - compliance_violation (bool)
                - revenue_impacting (bool)

        Returns:
            Composite score 0–10.
        """
        exploitability = self._score_exploitability(finding, context)
        blast_radius = self._score_blast_radius(context)
        business_impact = self._score_business_impact(finding, context)

        raw = (exploitability * 0.4) + (blast_radius * 0.3) + (business_impact * 0.3)
        score = min(round(raw, 1), 10.0)

        finding["risk_score"] = score
        finding["risk_rationale"] = {
            "exploitability": round(exploitability, 2),
            "blast_radius": round(blast_radius, 2),
            "business_impact": round(business_impact, 2),
            "formula": "score = (E×0.4) + (B×0.3) + (I×0.3)",
        }
        finding["cost_impact"] = self._cost_impact(finding)

        return score

    def score_all(self, findings: list, inventory: Dict = None) -> list:
        """Score every finding and return sorted by risk_score descending."""
        inventory = inventory or {}
        for finding in findings:
            context = self._build_context(finding, inventory)
            # Mark if part of an attack chain (enriched after attack path analysis)
            self.score_finding(finding, context)
        return sorted(findings, key=lambda f: f.get("risk_score", 0), reverse=True)

    def mark_attack_chain_members(self, findings: list, attack_paths: list) -> None:
        """
        After attack path analysis, re-score findings that participate in a chain —
        they get a boost to exploitability.
        """
        chain_resources = set()
        for path in attack_paths:
            for node in path.get("path", []):
                chain_resources.add(node)

        for finding in findings:
            if finding.get("resource") in chain_resources:
                old_score = finding.get("risk_score", 0)
                # Re-score with attack chain flag
                context = self._build_context(finding, {})
                context["part_of_attack_chain"] = True
                self.score_finding(finding, context)
                finding["risk_rationale"]["attack_chain_boost"] = (
                    f"Score boosted from {old_score} — resource participates in an attack chain"
                )

    # ── Sub-scorers ──────────────────────────────────────────────────────────

    def _score_exploitability(self, finding: dict, context: dict) -> float:
        score = SEVERITY_BASE.get(finding.get("severity", "LOW"), 2.5)

        if context.get("publicly_accessible"):
            score += self.EXPLOITABILITY_WEIGHTS["public_exposure"]
        if finding.get("severity") == "CRITICAL":
            score += self.EXPLOITABILITY_WEIGHTS["no_auth_required"]
        if context.get("part_of_attack_chain"):
            score += self.EXPLOITABILITY_WEIGHTS["lateral_movement_possible"]
        if "administrator" in finding.get("issue", "").lower():
            score += self.EXPLOITABILITY_WEIGHTS["privileged_access"]

        return min(score, 10.0)

    def _score_blast_radius(self, context: dict) -> float:
        count = context.get("affected_resource_count", 1)
        if count >= 100:
            return 10.0
        elif count >= 50:
            return 7.5
        elif count >= 10:
            return 5.0
        elif count >= 5:
            return 3.5
        return 2.5

    def _score_business_impact(self, finding: dict, context: dict) -> float:
        score = 0.0
        if context.get("contains_pii"):
            score += 4.0
        if context.get("compliance_violation") or finding.get("cis_control"):
            score += 3.0
        if context.get("revenue_impacting"):
            score += 3.0
        # Severity backstop
        score = max(score, SEVERITY_BASE.get(finding.get("severity", "LOW"), 2.5) * 0.5)
        return min(score, 10.0)

    def _build_context(self, finding: dict, inventory: dict) -> dict:
        sev = finding.get("severity", "LOW")
        return {
            "publicly_accessible": sev == "CRITICAL",
            "part_of_attack_chain": False,
            "affected_resource_count": 1,
            "contains_pii": any(
                kw in finding.get("resource", "").lower()
                for kw in ("prod", "production", "customer", "user", "pii", "data")
            ),
            "compliance_violation": bool(finding.get("cis_control")),
            "revenue_impacting": sev in ("CRITICAL", "HIGH"),
        }

    def _cost_impact(self, finding: dict) -> dict:
        cis = finding.get("cis_control", "")
        for prefix, template in COST_IMPACT_TEMPLATES.items():
            if cis.startswith(prefix):
                return template
        return {
            "description": "Security misconfiguration may result in compliance violations",
            "estimated_penalty": "Varies by regulatory framework and breach scope",
        }
