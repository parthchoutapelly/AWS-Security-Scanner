"""Abstract base class for all AWS service auditors."""
from abc import ABC, abstractmethod
from typing import List, Dict, Any
import boto3

from src.utils.logger import get_logger

logger = get_logger(__name__)


class BaseAuditor(ABC):
    """
    Base class for all AWS service auditors.

    Each subclass audits a single AWS service and returns a list of findings.
    A finding has the structure:
    {
        "id":            str  — unique finding ID
        "resource":      str  — resource name / ARN
        "resource_type": str  — CloudFormation resource type (e.g. AWS::S3::Bucket)
        "issue":         str  — short description of the problem
        "description":   str  — full description
        "severity":      str  — CRITICAL | HIGH | MEDIUM | LOW
        "cis_control":   str  — CIS control ID (e.g. "2.1.5")
        "remediation":   str  — plain-text remediation steps
        "remediation_cli": str — AWS CLI command to fix the issue (if applicable)
        "region":        str  — AWS region
        "service":       str  — AWS service (e.g. "S3")
    }
    """

    SERVICE_NAME: str = "Unknown"

    def __init__(self, session: boto3.Session, region: str = "us-east-1"):
        self.session = session
        self.region = region
        self.findings: List[Dict[str, Any]] = []
        self._finding_counter = 0
        self.logger = get_logger(self.__class__.__name__)

    @abstractmethod
    def audit(self) -> List[Dict[str, Any]]:
        """Perform security audit. Returns list of findings."""
        pass

    def _next_id(self) -> str:
        self._finding_counter += 1
        return f"{self.SERVICE_NAME.lower()}-{self._finding_counter:04d}"

    def add_finding(
        self,
        resource: str,
        resource_type: str,
        issue: str,
        description: str,
        severity: str,
        cis_control: str,
        remediation: str,
        remediation_cli: str = "",
        region: str = None,
    ) -> Dict[str, Any]:
        """Create and register a finding."""
        finding = {
            "id": self._next_id(),
            "resource": resource,
            "resource_type": resource_type,
            "issue": issue,
            "description": description,
            "severity": severity,
            "cis_control": cis_control,
            "remediation": remediation,
            "remediation_cli": remediation_cli,
            "region": region or self.region,
            "service": self.SERVICE_NAME,
        }
        self.findings.append(finding)
        return finding

    def _safe_get(self, func, *args, default=None, **kwargs):
        """Call an AWS API function; return default on ClientError."""
        try:
            return func(*args, **kwargs)
        except Exception as e:
            self.logger.debug(f"API call failed ({func.__name__}): {e}")
            return default
