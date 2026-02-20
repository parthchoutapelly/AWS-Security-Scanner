"""RDS Security Auditor — checks DB instances for public access, encryption, and backups."""
from typing import List, Dict, Any

from botocore.exceptions import ClientError

from src.auditors.base import BaseAuditor

MIN_BACKUP_RETENTION_DAYS = 7


class RDSAuditor(BaseAuditor):
    """Audits RDS instances and clusters for security misconfigurations."""

    SERVICE_NAME = "RDS"

    def audit(self) -> List[Dict[str, Any]]:
        rds = self.session.client("rds", region_name=self.region)

        self.logger.info("Scanning RDS instances...")
        self._check_db_instances(rds)
        self._check_db_clusters(rds)

        return self.findings

    def _check_db_instances(self, rds):
        try:
            paginator = rds.get_paginator("describe_db_instances")
            instances = []
            for page in paginator.paginate():
                instances.extend(page["DBInstances"])
        except ClientError as e:
            self.logger.error(f"Cannot list RDS instances: {e}")
            return

        self.logger.info(f"Scanning {len(instances)} RDS instances...")

        for db in instances:
            db_id = db["DBInstanceIdentifier"]
            engine = db.get("Engine", "unknown")

            # Public accessibility
            if db.get("PubliclyAccessible", False):
                self.add_finding(
                    resource=f"rds:{db_id}",
                    resource_type="AWS::RDS::DBInstance",
                    issue=f"RDS instance '{db_id}' is publicly accessible",
                    description=(
                        f"RDS instance '{db_id}' (engine: {engine}) is configured to be publicly accessible. "
                        "Database instances should never be reachable from the public internet."
                    ),
                    severity="CRITICAL",
                    cis_control="2.3.2",
                    remediation=f"Disable public accessibility on RDS instance '{db_id}'.",
                    remediation_cli=(
                        f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                        "--no-publicly-accessible --apply-immediately "
                        f"--region {self.region}"
                    ),
                )

            # Encryption at rest
            if not db.get("StorageEncrypted", False):
                self.add_finding(
                    resource=f"rds:{db_id}",
                    resource_type="AWS::RDS::DBInstance",
                    issue=f"RDS instance '{db_id}' storage is not encrypted",
                    description=(
                        f"RDS instance '{db_id}' does not have storage encryption enabled. "
                        "Unencrypted database storage risks data exposure if the underlying storage is compromised."
                    ),
                    severity="HIGH",
                    cis_control="2.3.1",
                    remediation=(
                        f"Create an encrypted snapshot of '{db_id}', then restore to a new encrypted instance. "
                        "Note: encryption cannot be enabled on an existing instance in-place."
                    ),
                    remediation_cli=(
                        f"aws rds create-db-snapshot --db-instance-identifier {db_id} "
                        f"--db-snapshot-identifier {db_id}-snap --region {self.region}\n"
                        f"# Then copy snapshot with encryption and restore"
                    ),
                )

            # Backup retention
            retention = db.get("BackupRetentionPeriod", 0)
            if retention < MIN_BACKUP_RETENTION_DAYS:
                self.add_finding(
                    resource=f"rds:{db_id}",
                    resource_type="AWS::RDS::DBInstance",
                    issue=f"RDS instance '{db_id}' has insufficient backup retention ({retention} days)",
                    description=(
                        f"RDS instance '{db_id}' has automated backup retention set to {retention} day(s). "
                        f"The recommended minimum is {MIN_BACKUP_RETENTION_DAYS} days."
                    ),
                    severity="MEDIUM",
                    cis_control="2.3.3",
                    remediation=f"Set backup retention period to at least {MIN_BACKUP_RETENTION_DAYS} days.",
                    remediation_cli=(
                        f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                        f"--backup-retention-period {MIN_BACKUP_RETENTION_DAYS} "
                        f"--apply-immediately --region {self.region}"
                    ),
                )

            # Auto minor version upgrade
            if not db.get("AutoMinorVersionUpgrade", False):
                self.add_finding(
                    resource=f"rds:{db_id}",
                    resource_type="AWS::RDS::DBInstance",
                    issue=f"RDS instance '{db_id}' auto minor version upgrade is disabled",
                    description=(
                        f"Automatic minor version upgrades are disabled for RDS instance '{db_id}'. "
                        "Minor upgrades often include important security patches."
                    ),
                    severity="LOW",
                    cis_control="2.3.4",
                    remediation=f"Enable auto minor version upgrades for '{db_id}'.",
                    remediation_cli=(
                        f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                        f"--auto-minor-version-upgrade --apply-immediately --region {self.region}"
                    ),
                )

            # Deletion protection
            if not db.get("DeletionProtection", False):
                self.add_finding(
                    resource=f"rds:{db_id}",
                    resource_type="AWS::RDS::DBInstance",
                    issue=f"RDS instance '{db_id}' deletion protection is disabled",
                    description=(
                        f"Deletion protection is disabled for RDS instance '{db_id}'. "
                        "Without this, the instance can be accidentally deleted."
                    ),
                    severity="LOW",
                    cis_control="2.3.5",
                    remediation=f"Enable deletion protection for '{db_id}'.",
                    remediation_cli=(
                        f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                        f"--deletion-protection --apply-immediately --region {self.region}"
                    ),
                )

    def _check_db_clusters(self, rds):
        try:
            paginator = rds.get_paginator("describe_db_clusters")
            clusters = []
            for page in paginator.paginate():
                clusters.extend(page["DBClusters"])
        except ClientError as e:
            self.logger.debug(f"Cannot list RDS clusters: {e}")
            return

        for cluster in clusters:
            cluster_id = cluster["DBClusterIdentifier"]

            if not cluster.get("StorageEncrypted", False):
                self.add_finding(
                    resource=f"rds:cluster:{cluster_id}",
                    resource_type="AWS::RDS::DBCluster",
                    issue=f"RDS cluster '{cluster_id}' storage is not encrypted",
                    description=(
                        f"Aurora cluster '{cluster_id}' does not have storage encryption enabled."
                    ),
                    severity="HIGH",
                    cis_control="2.3.1",
                    remediation="Create a new encrypted cluster and migrate data.",
                    remediation_cli=f"# Encryption must be set at cluster creation time",
                )

            retention = cluster.get("BackupRetentionPeriod", 0)
            if retention < MIN_BACKUP_RETENTION_DAYS:
                self.add_finding(
                    resource=f"rds:cluster:{cluster_id}",
                    resource_type="AWS::RDS::DBCluster",
                    issue=f"RDS cluster '{cluster_id}' backup retention is {retention} days",
                    description=(
                        f"Aurora cluster '{cluster_id}' backup retention period is {retention} day(s). "
                        f"Minimum recommended is {MIN_BACKUP_RETENTION_DAYS} days."
                    ),
                    severity="MEDIUM",
                    cis_control="2.3.3",
                    remediation=f"Increase backup retention to at least {MIN_BACKUP_RETENTION_DAYS} days.",
                    remediation_cli=(
                        f"aws rds modify-db-cluster --db-cluster-identifier {cluster_id} "
                        f"--backup-retention-period {MIN_BACKUP_RETENTION_DAYS} "
                        f"--apply-immediately --region {self.region}"
                    ),
                )
