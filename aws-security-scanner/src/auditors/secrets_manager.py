"""Secrets Manager Security Auditor — checks rotation policies, unused secrets, and public access."""
from datetime import datetime, timezone
from typing import List, Dict, Any

from botocore.exceptions import ClientError

from src.auditors.base import BaseAuditor

UNUSED_SECRET_DAYS = 90
ROTATION_MAX_DAYS = 90


class SecretsManagerAuditor(BaseAuditor):
    """Audits AWS Secrets Manager for rotation gaps and access policy issues."""

    SERVICE_NAME = "SecretsManager"

    def audit(self) -> List[Dict[str, Any]]:
        sm = self.session.client("secretsmanager", region_name=self.region)

        self.logger.info("Scanning Secrets Manager secrets...")
        try:
            paginator = sm.get_paginator("list_secrets")
            secrets = []
            for page in paginator.paginate():
                secrets.extend(page["SecretList"])
        except ClientError as e:
            self.logger.warning(f"Cannot list Secrets Manager secrets: {e}")
            return []

        self.logger.info(f"Scanning {len(secrets)} secret(s)...")
        for secret in secrets:
            self._check_rotation(secret)
            self._check_last_accessed(secret)
            self._check_resource_policy(sm, secret)

        return self.findings

    def _check_rotation(self, secret: dict):
        name = secret["Name"]
        rotation_enabled = secret.get("RotationEnabled", False)
        rotation_days = secret.get("RotationRules", {}).get("AutomaticallyAfterDays")

        if not rotation_enabled:
            self.add_finding(
                resource=f"secret:{name}",
                resource_type="AWS::SecretsManager::Secret",
                issue=f"Secret '{name}' does not have automatic rotation enabled",
                description=(
                    f"Secret '{name}' in Secrets Manager does not have automatic rotation "
                    "configured. Secrets that never rotate create long-lived credential exposure windows."
                ),
                severity="HIGH",
                cis_control="1.14",
                remediation=f"Enable automatic rotation for secret '{name}'.",
                remediation_cli=(
                    f"aws secretsmanager rotate-secret --secret-id {name} "
                    f"--rotation-lambda-arn <rotation-lambda-arn> "
                    f"--rotation-rules AutomaticallyAfterDays=30 --region {self.region}"
                ),
            )
        elif rotation_days and rotation_days > ROTATION_MAX_DAYS:
            self.add_finding(
                resource=f"secret:{name}",
                resource_type="AWS::SecretsManager::Secret",
                issue=f"Secret '{name}' rotation interval is {rotation_days} days (>{ROTATION_MAX_DAYS})",
                description=(
                    f"Secret '{name}' rotates every {rotation_days} days. "
                    f"Rotation intervals longer than {ROTATION_MAX_DAYS} days reduce the window "
                    "in which a compromised secret is invalidated."
                ),
                severity="MEDIUM",
                cis_control="1.14",
                remediation=f"Reduce rotation interval to {ROTATION_MAX_DAYS} days or fewer.",
                remediation_cli=(
                    f"aws secretsmanager rotate-secret --secret-id {name} "
                    f"--rotation-rules AutomaticallyAfterDays={ROTATION_MAX_DAYS} --region {self.region}"
                ),
            )

    def _check_last_accessed(self, secret: dict):
        name = secret["Name"]
        last_accessed = secret.get("LastAccessedDate")
        last_changed = secret.get("LastChangedDate")

        now = datetime.now(timezone.utc)

        # Unused secret (never accessed or not accessed in a long time)
        if last_accessed:
            unused_days = (now - last_accessed).days
            if unused_days > UNUSED_SECRET_DAYS:
                self.add_finding(
                    resource=f"secret:{name}",
                    resource_type="AWS::SecretsManager::Secret",
                    issue=f"Secret '{name}' has not been accessed in {unused_days} days",
                    description=(
                        f"Secret '{name}' was last accessed {unused_days} days ago. "
                        "Secrets that are no longer actively used should be deleted to reduce the "
                        "attack surface."
                    ),
                    severity="LOW",
                    cis_control="1.12",
                    remediation=f"Delete secret '{name}' if it is no longer required.",
                    remediation_cli=(
                        f"aws secretsmanager delete-secret --secret-id {name} "
                        f"--recovery-window-in-days 7 --region {self.region}"
                    ),
                )

    def _check_resource_policy(self, sm, secret: dict):
        name = secret["Name"]
        try:
            policy_resp = sm.get_resource_policy(SecretId=name)
            policy_str = policy_resp.get("ResourcePolicy")
            if not policy_str:
                return

            import json
            policy = json.loads(policy_str)
            for stmt in policy.get("Statement", []):
                principal = stmt.get("Principal", "")
                effect = stmt.get("Effect", "")
                if effect == "Allow" and (principal == "*" or principal == {"AWS": "*"}):
                    self.add_finding(
                        resource=f"secret:{name}",
                        resource_type="AWS::SecretsManager::Secret",
                        issue=f"Secret '{name}' resource policy allows public access (Principal: *)",
                        description=(
                            f"Secret '{name}' has a resource-based policy with a wildcard principal, "
                            "meaning any AWS principal can access it."
                        ),
                        severity="CRITICAL",
                        cis_control="1.16",
                        remediation="Restrict the secret's resource policy to specific IAM principals.",
                        remediation_cli=(
                            f"aws secretsmanager get-resource-policy --secret-id {name} "
                            f"--region {self.region}  # review and restrict the policy"
                        ),
                    )
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                self.logger.debug(f"Cannot get resource policy for secret '{name}': {e}")
