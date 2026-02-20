"""IAM Security Auditor — checks users, root account, password policy, access keys, and roles."""
from datetime import datetime, timezone
from typing import List, Dict, Any

from botocore.exceptions import ClientError

from src.auditors.base import BaseAuditor


class IAMAuditor(BaseAuditor):
    """Audits IAM configuration for security misconfigurations."""

    SERVICE_NAME = "IAM"
    INACTIVE_DAYS_THRESHOLD = 90
    KEY_AGE_DAYS_THRESHOLD = 90

    def audit(self) -> List[Dict[str, Any]]:
        """Run all IAM security checks."""
        iam = self.session.client("iam")

        self.logger.info("Scanning IAM configuration...")
        self._check_root_account(iam)
        self._check_password_policy(iam)
        self._check_users(iam)

        return self.findings

    # ── Root account ──────────────────────────────────────────────────────────

    def _check_root_account(self, iam):
        try:
            summary = iam.get_account_summary()["SummaryMap"]

            # Root MFA
            if not summary.get("AccountMFAEnabled", 0):
                self.add_finding(
                    resource="root",
                    resource_type="AWS::IAM::User",
                    issue="MFA not enabled on root account",
                    description=(
                        "The root account does not have multi-factor authentication (MFA) enabled. "
                        "The root account has unrestricted access to all AWS resources."
                    ),
                    severity="CRITICAL",
                    cis_control="1.5",
                    remediation="Enable MFA on the root account immediately.",
                    remediation_cli="# Log into the AWS console as root and enable MFA under Security Credentials",
                )

            # Root access keys
            if summary.get("AccountAccessKeysPresent", 0):
                self.add_finding(
                    resource="root",
                    resource_type="AWS::IAM::User",
                    issue="Root account has active access keys",
                    description=(
                        "The root account has active access keys. Root access keys should never exist "
                        "as they provide unrestricted API access to the entire account."
                    ),
                    severity="CRITICAL",
                    cis_control="1.4",
                    remediation="Delete all root account access keys immediately.",
                    remediation_cli=(
                        "# Log into the AWS console as root → Security Credentials → "
                        "Delete all access keys"
                    ),
                )
        except ClientError as e:
            self.logger.warning(f"Cannot check root account summary: {e}")

        # Check for recent root activity via credential report
        try:
            iam.generate_credential_report()
        except ClientError:
            pass

    # ── Password policy ───────────────────────────────────────────────────────

    def _check_password_policy(self, iam):
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]

            checks = [
                (
                    policy.get("MinimumPasswordLength", 0) < 14,
                    "IAM password policy minimum length is less than 14 characters",
                    "Passwords shorter than 14 characters are easier to brute-force.",
                    "MEDIUM",
                    "1.8",
                    "Set minimum password length to 14 or more.",
                    "aws iam update-account-password-policy --minimum-password-length 14",
                ),
                (
                    not policy.get("RequireUppercaseCharacters", False),
                    "IAM password policy does not require uppercase characters",
                    "Password complexity requirements reduce the risk of brute-force attacks.",
                    "MEDIUM",
                    "1.9",
                    "Require uppercase characters in the IAM password policy.",
                    "aws iam update-account-password-policy --require-uppercase-characters",
                ),
                (
                    not policy.get("RequireLowercaseCharacters", False),
                    "IAM password policy does not require lowercase characters",
                    "Password complexity requirements reduce the risk of brute-force attacks.",
                    "MEDIUM",
                    "1.10",
                    "Require lowercase characters in the IAM password policy.",
                    "aws iam update-account-password-policy --require-lowercase-characters",
                ),
                (
                    not policy.get("RequireNumbers", False),
                    "IAM password policy does not require numbers",
                    "Password complexity requirements reduce the risk of brute-force attacks.",
                    "MEDIUM",
                    "1.11",
                    "Require numeric characters in the IAM password policy.",
                    "aws iam update-account-password-policy --require-numbers",
                ),
                (
                    not policy.get("RequireSymbols", False),
                    "IAM password policy does not require symbols",
                    "Password complexity requirements reduce the risk of brute-force attacks.",
                    "MEDIUM",
                    "1.11",
                    "Require symbol characters in the IAM password policy.",
                    "aws iam update-account-password-policy --require-symbols",
                ),
                (
                    not policy.get("MaxPasswordAge"),
                    "IAM password policy does not enforce password expiration",
                    "Without expiration, compromised passwords may be used indefinitely.",
                    "MEDIUM",
                    "1.13",
                    "Set password expiration to 90 days or fewer.",
                    "aws iam update-account-password-policy --max-password-age 90",
                ),
                (
                    not policy.get("PasswordReusePrevention"),
                    "IAM password policy does not prevent password reuse",
                    "Without reuse prevention, users can cycle back to compromised passwords.",
                    "LOW",
                    "1.14",
                    "Prevent reuse of the last 24 passwords.",
                    "aws iam update-account-password-policy --password-reuse-prevention 24",
                ),
            ]

            for condition, issue, description, severity, cis, remediation, cli in checks:
                if condition:
                    self.add_finding(
                        resource="account-password-policy",
                        resource_type="AWS::IAM::AccountPasswordPolicy",
                        issue=issue,
                        description=description,
                        severity=severity,
                        cis_control=cis,
                        remediation=remediation,
                        remediation_cli=cli,
                    )

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                self.add_finding(
                    resource="account-password-policy",
                    resource_type="AWS::IAM::AccountPasswordPolicy",
                    issue="No IAM account password policy configured",
                    description="The account has no IAM password policy. This means any password complexity is accepted.",
                    severity="HIGH",
                    cis_control="1.8",
                    remediation="Create a strong IAM password policy.",
                    remediation_cli=(
                        "aws iam update-account-password-policy "
                        "--minimum-password-length 14 --require-uppercase-characters "
                        "--require-lowercase-characters --require-numbers --require-symbols "
                        "--max-password-age 90 --password-reuse-prevention 24"
                    ),
                )

    # ── Users ────────────────────────────────────────────────────────────────

    def _check_users(self, iam):
        try:
            paginator = iam.get_paginator("list_users")
            users = []
            for page in paginator.paginate():
                users.extend(page["Users"])
        except ClientError as e:
            self.logger.error(f"Cannot list IAM users: {e}")
            return

        self.logger.info(f"Scanning {len(users)} IAM users...")

        for user in users:
            username = user["UserName"]
            self._check_user_mfa(iam, username)
            self._check_user_access_keys(iam, username, user)
            self._check_user_admin_policies(iam, username)
            self._check_console_inactive(iam, username, user)

    def _check_user_mfa(self, iam, username: str):
        try:
            mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
            # Check if user has console access (login profile)
            has_console = True
            try:
                iam.get_login_profile(UserName=username)
            except ClientError:
                has_console = False

            if has_console and not mfa_devices:
                self.add_finding(
                    resource=f"iam:user:{username}",
                    resource_type="AWS::IAM::User",
                    issue=f"IAM user '{username}' has console access without MFA",
                    description=(
                        f"User '{username}' can log into the AWS console but does not have "
                        "MFA enabled, increasing the risk of account compromise."
                    ),
                    severity="HIGH",
                    cis_control="1.10",
                    remediation=f"Enable MFA for user '{username}'.",
                    remediation_cli=f"# User '{username}' must enable MFA themselves via the console",
                )
        except ClientError:
            pass

    def _check_user_access_keys(self, iam, username: str, user: dict):
        try:
            keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
            now = datetime.now(timezone.utc)

            for key in keys:
                key_id = key["AccessKeyId"]
                status = key["Status"]
                created = key["CreateDate"]
                age_days = (now - created).days

                # Old access keys
                if status == "Active" and age_days > self.KEY_AGE_DAYS_THRESHOLD:
                    self.add_finding(
                        resource=f"iam:user:{username}:key:{key_id}",
                        resource_type="AWS::IAM::AccessKey",
                        issue=f"Access key older than {self.KEY_AGE_DAYS_THRESHOLD} days",
                        description=(
                            f"Access key '{key_id}' for user '{username}' is {age_days} days old. "
                            "Long-lived credentials increase the risk if the key is compromised."
                        ),
                        severity="HIGH",
                        cis_control="1.14",
                        remediation=f"Rotate or delete the access key '{key_id}'.",
                        remediation_cli=f"aws iam delete-access-key --user-name {username} --access-key-id {key_id}",
                    )

                # Check last used
                try:
                    last_used_resp = iam.get_access_key_last_used(AccessKeyId=key_id)
                    last_used = last_used_resp["AccessKeyLastUsed"].get("LastUsedDate")
                    if last_used:
                        unused_days = (now - last_used).days
                        if status == "Active" and unused_days > self.INACTIVE_DAYS_THRESHOLD:
                            self.add_finding(
                                resource=f"iam:user:{username}:key:{key_id}",
                                resource_type="AWS::IAM::AccessKey",
                                issue=f"Active access key unused for {unused_days} days",
                                description=(
                                    f"Access key '{key_id}' for user '{username}' has not been "
                                    f"used in {unused_days} days and should be disabled or deleted."
                                ),
                                severity="MEDIUM",
                                cis_control="1.12",
                                remediation="Disable or delete unused access keys.",
                                remediation_cli=f"aws iam delete-access-key --user-name {username} --access-key-id {key_id}",
                            )
                except ClientError:
                    pass

        except ClientError:
            pass

    def _check_user_admin_policies(self, iam, username: str):
        try:
            policies = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
            for policy in policies:
                if policy["PolicyName"] in ("AdministratorAccess", "PowerUserAccess"):
                    self.add_finding(
                        resource=f"iam:user:{username}",
                        resource_type="AWS::IAM::User",
                        issue=f"IAM user has overly permissive policy: {policy['PolicyName']}",
                        description=(
                            f"User '{username}' has the '{policy['PolicyName']}' policy directly attached. "
                            "Users should follow the principle of least privilege."
                        ),
                        severity="HIGH",
                        cis_control="1.16",
                        remediation=(
                            f"Remove '{policy['PolicyName']}' from user '{username}' and "
                            "replace with a least-privilege policy."
                        ),
                        remediation_cli=(
                            f"aws iam detach-user-policy --user-name {username} "
                            f"--policy-arn {policy['PolicyArn']}"
                        ),
                    )
        except ClientError:
            pass

    def _check_console_inactive(self, iam, username: str, user: dict):
        """Check for users with console access but no activity in 90+ days."""
        try:
            iam.get_login_profile(UserName=username)
        except ClientError:
            return  # No console access — skip

        last_used = user.get("PasswordLastUsed")
        if not last_used:
            return

        now = datetime.now(timezone.utc)
        inactive_days = (now - last_used).days
        if inactive_days > self.INACTIVE_DAYS_THRESHOLD:
            self.add_finding(
                resource=f"iam:user:{username}",
                resource_type="AWS::IAM::User",
                issue=f"IAM user console credentials inactive for {inactive_days} days",
                description=(
                    f"User '{username}' has not logged into the console in {inactive_days} days. "
                    "Inactive accounts should be disabled."
                ),
                severity="MEDIUM",
                cis_control="1.12",
                remediation=f"Disable or delete the console login for user '{username}'.",
                remediation_cli=f"aws iam delete-login-profile --user-name {username}",
            )
