"""
Multi-Account Scanner
=====================
Integrates with AWS Organizations to automatically discover all active
member accounts and run the full security scan against each one,
producing a consolidated cross-account report.
"""
import asyncio
from typing import Dict, List, Any

import boto3
from botocore.exceptions import ClientError

from src.utils.logger import get_logger

logger = get_logger(__name__)

DEFAULT_SCANNER_ROLE = "SecurityScannerRole"


class MultiAccountScanner:
    """
    Discovers all AWS Organization member accounts and scans each one
    by assuming a cross-account IAM role.
    """

    def __init__(
        self,
        master_session: boto3.Session,
        scanner_role_name: str = DEFAULT_SCANNER_ROLE,
        region: str = "us-east-1",
        services: List[str] = None,
    ):
        self.master_session = master_session
        self.scanner_role_name = scanner_role_name
        self.region = region
        self.services = services or ["s3", "iam", "ec2", "rds", "vpc", "cloudtrail"]
        self.org_client = master_session.client("organizations")
        self.sts_client = master_session.client("sts")

    # ── Account discovery ─────────────────────────────────────────────────

    def list_accounts(self) -> List[Dict]:
        """Return all ACTIVE accounts in the AWS Organization."""
        try:
            paginator = self.org_client.get_paginator("list_accounts")
            accounts = []
            for page in paginator.paginate():
                accounts.extend(
                    a for a in page["Accounts"] if a["Status"] == "ACTIVE"
                )
            logger.info(f"Discovered {len(accounts)} active accounts in Organization.")
            return accounts
        except ClientError as e:
            if e.response["Error"]["Code"] == "AWSOrganizationsNotInUseException":
                logger.warning("This account is not part of an AWS Organization.")
            else:
                logger.error(f"Cannot list Organization accounts: {e}")
            return []

    def assume_role_in_account(self, account_id: str) -> boto3.Session:
        """Assume the scanner role in a member account."""
        role_arn = f"arn:aws:iam::{account_id}:role/{self.scanner_role_name}"
        try:
            resp = self.sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName="SecurityScanner",
                DurationSeconds=3600,
            )
            creds = resp["Credentials"]
            return boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=self.region,
            )
        except ClientError as e:
            raise RuntimeError(f"Cannot assume role in account {account_id}: {e}") from e

    # ── Scanning ──────────────────────────────────────────────────────────

    async def scan_account(self, account: Dict) -> Dict[str, Any]:
        """Scan a single account and return its results."""
        account_id = account["Id"]
        account_name = account.get("Name", account_id)
        logger.info(f"  → Scanning account {account_name} ({account_id})...")

        try:
            session = self.assume_role_in_account(account_id)
        except RuntimeError as e:
            logger.warning(str(e))
            return {
                "account_id": account_id,
                "account_name": account_name,
                "status": "error",
                "error": str(e),
                "findings": [],
                "attack_paths": [],
                "compliance": {},
            }

        # Import here to avoid circular imports at module load time
        from src.scanner import SecurityScanner, ScanConfig

        config = ScanConfig(
            services=self.services,
            region=self.region,
            account_id=account_id,
        )
        scanner = SecurityScanner(session, config)
        findings = await asyncio.to_thread(scanner.scan)

        return {
            "account_id": account_id,
            "account_name": account_name,
            "status": "success",
            "findings": scanner.all_findings,
            "compliance": scanner.get_compliance(),
            "statistics": scanner.get_summary(),
            "attack_paths": [],  # populated by scanner.build_report_data() if enabled
        }

    async def scan_all_accounts(
        self, account_ids: List[str] = None
    ) -> Dict[str, Any]:
        """
        Scan all (or a subset of) accounts in the Organization concurrently.

        Args:
            account_ids: Optional explicit list of account IDs. If None, discovers all.

        Returns:
            {
                "accounts": {account_id: result, ...},
                "consolidated_findings": [...],
                "account_summaries": [...],
            }
        """
        if account_ids:
            accounts = [{"Id": aid, "Name": aid} for aid in account_ids]
        else:
            accounts = self.list_accounts()

        if not accounts:
            logger.warning("No accounts to scan.")
            return {"accounts": {}, "consolidated_findings": [], "account_summaries": []}

        logger.info(f"Scanning {len(accounts)} account(s) in parallel...")
        tasks = [self.scan_account(account) for account in accounts]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        accounts_data: Dict[str, Any] = {}
        consolidated_findings: List[Dict] = []
        summaries = []

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                account_id = accounts[i]["Id"]
                logger.error(f"Account {account_id} scan failed: {result}")
                accounts_data[account_id] = {"status": "error", "error": str(result)}
                continue

            account_id = result["account_id"]
            accounts_data[account_id] = result

            for f in result.get("findings", []):
                f["account_id"] = account_id
                f["account_name"] = result.get("account_name", account_id)
                consolidated_findings.append(f)

            summaries.append({
                "account_id": account_id,
                "account_name": result.get("account_name", account_id),
                "status": result["status"],
                "total_findings": len(result.get("findings", [])),
                "cis_score": result.get("compliance", {}).get("score"),
            })

        logger.info(
            f"Multi-account scan complete. "
            f"{len(consolidated_findings)} total findings across {len(accounts)} accounts."
        )

        return {
            "accounts": accounts_data,
            "consolidated_findings": consolidated_findings,
            "account_summaries": summaries,
        }
