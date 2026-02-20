"""S3 Security Auditor — checks buckets for public access, encryption, versioning, and logging."""
import json
from typing import List, Dict, Any

from botocore.exceptions import ClientError

from src.auditors.base import BaseAuditor


class S3Auditor(BaseAuditor):
    """Audits S3 buckets for security misconfigurations."""

    SERVICE_NAME = "S3"

    def audit(self) -> List[Dict[str, Any]]:
        """Run all S3 security checks."""
        s3 = self.session.client("s3", region_name=self.region)

        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except ClientError as e:
            self.logger.error(f"Cannot list S3 buckets: {e}")
            return []

        self.logger.info(f"Scanning {len(buckets)} S3 buckets...")

        for bucket in buckets:
            name = bucket["Name"]
            bucket_region = self._get_bucket_region(s3, name)
            self._check_public_access_block(s3, name, bucket_region)
            self._check_bucket_acl(s3, name, bucket_region)
            self._check_bucket_policy(s3, name, bucket_region)
            self._check_encryption(s3, name, bucket_region)
            self._check_versioning(s3, name, bucket_region)
            self._check_logging(s3, name, bucket_region)

        return self.findings

    # ── helpers ──────────────────────────────────────────────────────────────

    def _get_bucket_region(self, s3, name: str) -> str:
        try:
            loc = s3.get_bucket_location(Bucket=name)
            return loc["LocationConstraint"] or "us-east-1"
        except ClientError:
            return self.region

    def _check_public_access_block(self, s3, name: str, region: str):
        try:
            pab = s3.get_public_access_block(Bucket=name)
            cfg = pab["PublicAccessBlockConfiguration"]
            all_blocked = all([
                cfg.get("BlockPublicAcls", False),
                cfg.get("IgnorePublicAcls", False),
                cfg.get("BlockPublicPolicy", False),
                cfg.get("RestrictPublicBuckets", False),
            ])
            if not all_blocked:
                self.add_finding(
                    resource=name,
                    resource_type="AWS::S3::Bucket",
                    issue="S3 Public Access Block not fully enabled",
                    description=f"Bucket '{name}' does not have all four Public Access Block settings enabled.",
                    severity="HIGH",
                    cis_control="2.1.5",
                    remediation="Enable all four S3 Block Public Access settings on the bucket.",
                    remediation_cli=(
                        f"aws s3api put-public-access-block --bucket {name} "
                        "--public-access-block-configuration "
                        "BlockPublicAcls=true,IgnorePublicAcls=true,"
                        "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                    ),
                    region=region,
                )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchPublicAccessBlockConfiguration":
                self.add_finding(
                    resource=name,
                    resource_type="AWS::S3::Bucket",
                    issue="S3 Public Access Block not configured",
                    description=f"Bucket '{name}' has no Public Access Block configuration.",
                    severity="HIGH",
                    cis_control="2.1.5",
                    remediation="Enable all four S3 Block Public Access settings on the bucket.",
                    remediation_cli=(
                        f"aws s3api put-public-access-block --bucket {name} "
                        "--public-access-block-configuration "
                        "BlockPublicAcls=true,IgnorePublicAcls=true,"
                        "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                    ),
                    region=region,
                )

    def _check_bucket_acl(self, s3, name: str, region: str):
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            public_uris = [
                "http://acs.amazonaws.com/groups/global/AllUsers",
                "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
            ]
            for grant in acl.get("Grants", []):
                grantee_uri = grant.get("Grantee", {}).get("URI", "")
                if grantee_uri in public_uris:
                    label = "AllUsers" if "AllUsers" in grantee_uri else "AuthenticatedUsers"
                    permission = grant.get("Permission", "UNKNOWN")
                    self.add_finding(
                        resource=name,
                        resource_type="AWS::S3::Bucket",
                        issue=f"Bucket ACL grants {permission} to {label}",
                        description=(
                            f"Bucket '{name}' has an ACL entry that grants {permission} "
                            f"to {label}, making it publicly accessible."
                        ),
                        severity="CRITICAL",
                        cis_control="2.1.5",
                        remediation="Remove public ACL grants and use bucket policies with explicit principals instead.",
                        remediation_cli=f"aws s3api put-bucket-acl --bucket {name} --acl private",
                        region=region,
                    )
        except ClientError:
            pass

    def _check_bucket_policy(self, s3, name: str, region: str):
        try:
            policy_str = s3.get_bucket_policy(Bucket=name)["Policy"]
            policy = json.loads(policy_str)
            for stmt in policy.get("Statement", []):
                principal = stmt.get("Principal", "")
                effect = stmt.get("Effect", "")
                if effect == "Allow" and (principal == "*" or principal == {"AWS": "*"}):
                    self.add_finding(
                        resource=name,
                        resource_type="AWS::S3::Bucket",
                        issue="Bucket policy allows public access (Principal: *)",
                        description=(
                            f"Bucket '{name}' has a bucket policy with a statement that "
                            "allows access to all principals (Principal: *)."
                        ),
                        severity="CRITICAL",
                        cis_control="2.1.5",
                        remediation=(
                            "Review and restrict the bucket policy to specific AWS "
                            "accounts, IAM roles, or users."
                        ),
                        remediation_cli=f"aws s3api get-bucket-policy --bucket {name}  # review and update",
                        region=region,
                    )
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                self.logger.debug(f"Could not read bucket policy for {name}: {e}")

    def _check_encryption(self, s3, name: str, region: str):
        try:
            enc = s3.get_bucket_encryption(Bucket=name)
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            for rule in rules:
                algo = rule.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "")
                if algo == "AES256":
                    # AES-256 is acceptable, but KMS is preferred
                    self.add_finding(
                        resource=name,
                        resource_type="AWS::S3::Bucket",
                        issue="Bucket uses AES-256 encryption instead of AWS KMS",
                        description=(
                            f"Bucket '{name}' uses SSE-S3 (AES-256). "
                            "Consider upgrading to SSE-KMS for better key management and audit trails."
                        ),
                        severity="LOW",
                        cis_control="2.1.1",
                        remediation="Enable SSE-KMS encryption with a customer-managed KMS key.",
                        remediation_cli=(
                            f"aws s3api put-bucket-encryption --bucket {name} "
                            "--server-side-encryption-configuration "
                            '\'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"},"BucketKeyEnabled":true}]}\''
                        ),
                        region=region,
                    )
        except ClientError as e:
            if e.response["Error"]["Code"] in (
                "ServerSideEncryptionConfigurationNotFoundError",
                "NoSuchBucketPolicy",
            ):
                self.add_finding(
                    resource=name,
                    resource_type="AWS::S3::Bucket",
                    issue="S3 bucket default encryption not enabled",
                    description=f"Bucket '{name}' does not have server-side encryption configured by default.",
                    severity="HIGH",
                    cis_control="2.1.1",
                    remediation="Enable default server-side encryption (SSE-S3 or SSE-KMS) on the bucket.",
                    remediation_cli=(
                        f"aws s3api put-bucket-encryption --bucket {name} "
                        "--server-side-encryption-configuration "
                        '\'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}\''
                    ),
                    region=region,
                )

    def _check_versioning(self, s3, name: str, region: str):
        try:
            v = s3.get_bucket_versioning(Bucket=name)
            status = v.get("Status", "")
            if status != "Enabled":
                self.add_finding(
                    resource=name,
                    resource_type="AWS::S3::Bucket",
                    issue="S3 bucket versioning not enabled",
                    description=(
                        f"Bucket '{name}' does not have versioning enabled. "
                        "Without versioning, objects cannot be recovered after accidental deletion or overwrite."
                    ),
                    severity="MEDIUM",
                    cis_control="2.1.3",
                    remediation="Enable versioning on the bucket.",
                    remediation_cli=f"aws s3api put-bucket-versioning --bucket {name} --versioning-configuration Status=Enabled",
                    region=region,
                )
        except ClientError:
            pass

    def _check_logging(self, s3, name: str, region: str):
        try:
            log = s3.get_bucket_logging(Bucket=name)
            if "LoggingEnabled" not in log:
                self.add_finding(
                    resource=name,
                    resource_type="AWS::S3::Bucket",
                    issue="S3 bucket access logging not enabled",
                    description=(
                        f"Bucket '{name}' does not have server access logging enabled. "
                        "Access logs are required for security auditing and compliance."
                    ),
                    severity="MEDIUM",
                    cis_control="2.1.2",
                    remediation="Enable server access logging and direct logs to a dedicated logging bucket.",
                    remediation_cli=(
                        f"aws s3api put-bucket-logging --bucket {name} "
                        "--bucket-logging-status "
                        '\'{"LoggingEnabled":{"TargetBucket":"<logging-bucket>","TargetPrefix":"' + name + '/"}}\''
                    ),
                    region=region,
                )
        except ClientError:
            pass
