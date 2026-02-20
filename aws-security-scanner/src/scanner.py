"""
Main Scan Orchestrator (v2)
===========================
Coordinates all auditor modules, applies risk scoring, runs attack path
analysis, and assembles the final report data payload.
"""
import asyncio
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

import boto3

from src.auditors.s3 import S3Auditor
from src.auditors.iam import IAMAuditor
from src.auditors.ec2 import EC2Auditor
from src.auditors.rds import RDSAuditor
from src.auditors.vpc import VPCAuditor
from src.auditors.cloudtrail import CloudTrailAuditor
from src.auditors.eks import EKSAuditor
from src.auditors.secrets_manager import SecretsManagerAuditor
from src.compliance.mapper import ComplianceMapper
from src.analysis.risk_scorer import RiskScorer
from src.analysis.attack_path import AttackPathAnalyzer
from src.utils.logger import get_logger

logger = get_logger(__name__)

AUDITOR_MAP = {
    "s3":              S3Auditor,
    "iam":             IAMAuditor,
    "ec2":             EC2Auditor,
    "rds":             RDSAuditor,
    "vpc":             VPCAuditor,
    "cloudtrail":      CloudTrailAuditor,
    "eks":             EKSAuditor,
    "secretsmanager":  SecretsManagerAuditor,
}

ALL_SERVICES = list(AUDITOR_MAP.keys())


class ScanConfig:
    def __init__(
        self,
        services: List[str] = None,
        region: str = "us-east-1",
        account_id: str = "unknown",
        enable_attack_paths: bool = True,
        frameworks: List[str] = None,
    ):
        self.services = services or ALL_SERVICES
        self.region = region
        self.account_id = account_id
        self.enable_attack_paths = enable_attack_paths
        self.frameworks = frameworks or ["cis", "nist", "pci"]


class SecurityScanner:
    """Orchestrates all audit modules and aggregates findings with risk scoring."""

    def __init__(self, session: boto3.Session, config: ScanConfig):
        self.session = session
        self.config = config
        self.all_findings: List[Dict[str, Any]] = []
        self._auditor_results: Dict[str, List] = {}
        self.attack_paths: List[Dict] = []
        self.graph_data: Dict = {}
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self._risk_scorer = RiskScorer()
        self._attack_analyzer = AttackPathAnalyzer()

    def initialize_auditors(self) -> List:
        auditors = []
        for svc in self.config.services:
            cls = AUDITOR_MAP.get(svc.lower())
            if cls:
                auditors.append(cls(self.session, region=self.config.region))
            else:
                logger.warning(f"Unknown service '{svc}' — skipping.")
        return auditors

    async def _run_auditor(self, auditor) -> Dict:
        svc = auditor.SERVICE_NAME
        logger.info(f"  → Auditing {svc}...")
        findings = await asyncio.to_thread(auditor.audit)
        logger.info(f"  ✓ {svc}: {len(findings)} finding(s)")
        return {"service": svc, "findings": findings}

    async def _scan_async(self):
        auditors = self.initialize_auditors()
        if not auditors:
            return

        tasks = [self._run_auditor(a) for a in auditors]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Auditor failed: {result}")
            else:
                svc = result["service"]
                self._auditor_results[svc] = result["findings"]
                self.all_findings.extend(result["findings"])

    def scan(self) -> List[Dict[str, Any]]:
        """Run the full scan (blocking). Returns findings list."""
        self.start_time = datetime.now(timezone.utc)
        asyncio.run(self._scan_async())

        # ── Risk scoring ──────────────────────────────────────────────────
        logger.info("  Scoring findings...")
        inventory = self._build_inventory()
        self._risk_scorer.score_all(self.all_findings, inventory)

        # ── Attack path analysis ──────────────────────────────────────────
        if self.config.enable_attack_paths:
            logger.info("  Running attack path analysis...")
            self._attack_analyzer.build_resource_graph(self.all_findings, inventory)
            self.attack_paths = self._attack_analyzer.find_attack_paths()
            self.graph_data = self._attack_analyzer.export_graph_data()

            # Re-score findings that are part of an attack chain
            if self.attack_paths:
                self._risk_scorer.mark_attack_chain_members(self.all_findings, self.attack_paths)

        # Sort by risk score descending
        self.all_findings.sort(key=lambda f: f.get("risk_score", 0), reverse=True)

        self.end_time = datetime.now(timezone.utc)
        return self.all_findings

    def _build_inventory(self) -> Dict:
        """
        Assemble a lightweight resource inventory from the findings themselves.
        In a production system this would call AWS APIs to enumerate all resources.
        """
        resources = []
        seen = set()
        for f in self.all_findings:
            rid = f.get("resource", "")
            svc = f.get("service", "Unknown")
            if rid and rid not in seen:
                seen.add(rid)
                resources.append({
                    "id": rid,
                    "type": svc,
                    "region": f.get("region", self.config.region),
                    "account_id": self.config.account_id,
                    "public_exposure": f.get("severity") == "CRITICAL",
                    "sensitive": svc in ("RDS", "IAM", "EKS", "SecretsManager"),
                })
        return {
            "resources": resources,
            "iam_roles": [
                {"arn": f["resource"], "assumable_by_external": True}
                for f in self.all_findings
                if f.get("service") == "IAM" and "administrator" in f.get("issue", "").lower()
            ],
            "s3_objects": {},  # Would be populated by S3 object enumeration
        }

    def get_summary(self) -> Dict[str, Any]:
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        svc_counts: Dict[str, int] = {}

        for f in self.all_findings:
            sev = f.get("severity", "LOW")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            svc = f.get("service", "Unknown")
            svc_counts[svc] = svc_counts.get(svc, 0) + 1

        duration = None
        if self.start_time and self.end_time:
            duration = round((self.end_time - self.start_time).total_seconds(), 1)

        return {
            "total_findings": len(self.all_findings),
            "by_severity": sev_counts,
            "by_service": svc_counts,
            "scan_duration_seconds": duration,
            "attack_paths_detected": len(self.attack_paths),
        }

    def get_compliance(self) -> Dict[str, Any]:
        mapper = ComplianceMapper(frameworks=self.config.frameworks)
        return mapper.map_findings(self.all_findings)

    def build_report_data(self) -> Dict[str, Any]:
        summary = self.get_summary()
        compliance = self.get_compliance()

        return {
            "scan_metadata": {
                "scan_time": self.start_time.isoformat() if self.start_time else None,
                "account_id": self.config.account_id,
                "region": self.config.region,
                "services_scanned": self.config.services,
                "scan_duration_seconds": summary["scan_duration_seconds"],
                "scanner_version": "2.0",
            },
            "findings": self.all_findings,
            "attack_paths": self.attack_paths,
            "graph_data": self.graph_data,
            "compliance": compliance,
            "statistics": summary,
        }
