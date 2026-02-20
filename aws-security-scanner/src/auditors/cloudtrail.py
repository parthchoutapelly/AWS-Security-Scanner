"""CloudTrail Security Auditor — checks logging, validation, and encryption."""
from typing import List, Dict, Any

from botocore.exceptions import ClientError

from src.auditors.base import BaseAuditor


class CloudTrailAuditor(BaseAuditor):
    """Audits CloudTrail configuration."""

    SERVICE_NAME = "CloudTrail"

    def audit(self) -> List[Dict[str, Any]]:
        ct = self.session.client("cloudtrail", region_name=self.region)

        self.logger.info("Scanning CloudTrail configuration...")
        self._check_trails(ct)

        return self.findings

    def _check_trails(self, ct):
        try:
            trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
        except ClientError as e:
            self.logger.error(f"Cannot describe CloudTrail trails: {e}")
            return

        if not trails:
            self.add_finding(
                resource="cloudtrail",
                resource_type="AWS::CloudTrail::Trail",
                issue="No CloudTrail trails configured",
                description=(
                    "No CloudTrail trails were found. CloudTrail must be enabled to maintain "
                    "an audit log of API activity in the account."
                ),
                severity="CRITICAL",
                cis_control="3.1",
                remediation="Create a multi-region CloudTrail trail logging to an S3 bucket.",
                remediation_cli=(
                    "aws cloudtrail create-trail --name management-events "
                    "--s3-bucket-name <your-log-bucket> --is-multi-region-trail "
                    "--include-global-service-events\n"
                    "aws cloudtrail start-logging --name management-events"
                ),
            )
            return

        self.logger.info(f"Scanning {len(trails)} CloudTrail trail(s)...")

        multi_region_trail_exists = False

        for trail in trails:
            name = trail["Name"]
            arn = trail.get("TrailARN", name)

            # Multi-region
            if trail.get("IsMultiRegionTrail", False):
                multi_region_trail_exists = True

            # Get trail status
            try:
                status = ct.get_trail_status(Name=arn)
            except ClientError:
                status = {}

            # Logging enabled?
            if not status.get("IsLogging", False):
                self.add_finding(
                    resource=name,
                    resource_type="AWS::CloudTrail::Trail",
                    issue=f"CloudTrail trail '{name}' is not actively logging",
                    description=f"Trail '{name}' exists but logging is currently disabled.",
                    severity="CRITICAL",
                    cis_control="3.1",
                    remediation=f"Enable logging for CloudTrail trail '{name}'.",
                    remediation_cli=f"aws cloudtrail start-logging --name {name} --region {self.region}",
                )

            # Log file validation
            if not trail.get("LogFileValidationEnabled", False):
                self.add_finding(
                    resource=name,
                    resource_type="AWS::CloudTrail::Trail",
                    issue=f"CloudTrail trail '{name}' does not have log file validation enabled",
                    description=(
                        f"Trail '{name}' does not have log file validation enabled. "
                        "Without validation, tampered log files cannot be detected."
                    ),
                    severity="MEDIUM",
                    cis_control="3.2",
                    remediation=f"Enable log file validation for trail '{name}'.",
                    remediation_cli=(
                        f"aws cloudtrail update-trail --name {name} "
                        f"--enable-log-file-validation --region {self.region}"
                    ),
                )

            # Encryption
            if not trail.get("KMSKeyId"):
                self.add_finding(
                    resource=name,
                    resource_type="AWS::CloudTrail::Trail",
                    issue=f"CloudTrail trail '{name}' is not encrypted with KMS",
                    description=(
                        f"Trail '{name}' logs are stored unencrypted in S3. "
                        "KMS encryption provides an additional layer of protection."
                    ),
                    severity="MEDIUM",
                    cis_control="3.7",
                    remediation=f"Configure a KMS key for CloudTrail log encryption.",
                    remediation_cli=(
                        f"aws cloudtrail update-trail --name {name} "
                        f"--kms-key-id <kms-key-arn> --region {self.region}"
                    ),
                )

        if not multi_region_trail_exists:
            self.add_finding(
                resource="cloudtrail",
                resource_type="AWS::CloudTrail::Trail",
                issue="No multi-region CloudTrail trail configured",
                description=(
                    "No CloudTrail trail with multi-region logging was found. "
                    "A multi-region trail ensures API activity is captured across all regions."
                ),
                severity="HIGH",
                cis_control="3.3",
                remediation="Create or update a trail with --is-multi-region-trail enabled.",
                remediation_cli=(
                    "aws cloudtrail update-trail --name <trail-name> "
                    "--is-multi-region-trail --region us-east-1"
                ),
            )
