"""EKS Security Auditor — checks cluster public access, logging, and RBAC configuration."""
from typing import List, Dict, Any

from botocore.exceptions import ClientError

from src.auditors.base import BaseAuditor


class EKSAuditor(BaseAuditor):
    """Audits EKS clusters for security misconfigurations."""

    SERVICE_NAME = "EKS"

    def audit(self) -> List[Dict[str, Any]]:
        eks = self.session.client("eks", region_name=self.region)

        self.logger.info("Scanning EKS clusters...")
        try:
            clusters = eks.list_clusters().get("clusters", [])
        except ClientError as e:
            self.logger.warning(f"Cannot list EKS clusters (may not be in use): {e}")
            return []

        self.logger.info(f"Scanning {len(clusters)} EKS cluster(s)...")
        for cluster_name in clusters:
            self._check_cluster(eks, cluster_name)

        return self.findings

    def _check_cluster(self, eks, cluster_name: str):
        try:
            resp = eks.describe_cluster(name=cluster_name)
            cluster = resp["cluster"]
        except ClientError as e:
            self.logger.warning(f"Cannot describe EKS cluster '{cluster_name}': {e}")
            return

        self._check_public_endpoint(cluster)
        self._check_logging(cluster)
        self._check_secrets_encryption(cluster)
        self._check_kubernetes_version(cluster)

    def _check_public_endpoint(self, cluster: dict):
        name = cluster["name"]
        resources_cfg = cluster.get("resourcesVpcConfig", {})
        public = resources_cfg.get("endpointPublicAccess", False)
        public_cidrs = resources_cfg.get("publicAccessCidrs", ["0.0.0.0/0"])

        if public and "0.0.0.0/0" in public_cidrs:
            self.add_finding(
                resource=f"eks:{name}",
                resource_type="AWS::EKS::Cluster",
                issue=f"EKS cluster '{name}' API endpoint is publicly accessible from 0.0.0.0/0",
                description=(
                    f"The EKS cluster '{name}' has its Kubernetes API server endpoint publicly "
                    "accessible from any IP (0.0.0.0/0). This exposes the cluster to brute-force "
                    "and exploit attempts targeting the Kubernetes API."
                ),
                severity="HIGH",
                cis_control="5.4",
                remediation=(
                    f"Restrict public endpoint access to known CIDR ranges, or disable public "
                    "endpoint access and use private VPC access only."
                ),
                remediation_cli=(
                    f"aws eks update-cluster-config --name {name} "
                    "--resources-vpc-config endpointPublicAccess=true,publicAccessCidrs='YOUR_IP/32',endpointPrivateAccess=true "
                    f"--region {self.region}"
                ),
            )
        elif not public:
            pass  # private endpoint — good
        else:
            # Public but restricted CIDRs — informational low
            self.add_finding(
                resource=f"eks:{name}",
                resource_type="AWS::EKS::Cluster",
                issue=f"EKS cluster '{name}' API endpoint is public (restricted CIDRs)",
                description=(
                    f"EKS cluster '{name}' has a public endpoint restricted to {public_cidrs}. "
                    "Consider using private endpoint access only."
                ),
                severity="LOW",
                cis_control="5.4",
                remediation="Switch to private-only endpoint access.",
                remediation_cli=(
                    f"aws eks update-cluster-config --name {name} "
                    "--resources-vpc-config endpointPublicAccess=false,endpointPrivateAccess=true "
                    f"--region {self.region}"
                ),
            )

    def _check_logging(self, cluster: dict):
        name = cluster["name"]
        logging_cfg = cluster.get("logging", {}).get("clusterLogging", [])

        required_types = {"api", "audit", "authenticator", "controllerManager", "scheduler"}
        enabled_types = set()
        for log_setup in logging_cfg:
            if log_setup.get("enabled"):
                enabled_types.update(log_setup.get("types", []))

        missing = required_types - enabled_types
        if missing:
            self.add_finding(
                resource=f"eks:{name}",
                resource_type="AWS::EKS::Cluster",
                issue=f"EKS cluster '{name}' missing control plane log types: {', '.join(sorted(missing))}",
                description=(
                    f"EKS cluster '{name}' has the following control plane log types disabled: "
                    f"{', '.join(sorted(missing))}. Without audit logs in particular, malicious "
                    "API calls are invisible."
                ),
                severity="MEDIUM",
                cis_control="3.1",
                remediation="Enable all control plane log types for the EKS cluster.",
                remediation_cli=(
                    f"aws eks update-cluster-config --name {name} "
                    '--logging \'{"clusterLogging":[{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}]}\' '
                    f"--region {self.region}"
                ),
            )

    def _check_secrets_encryption(self, cluster: dict):
        name = cluster["name"]
        encryption_configs = cluster.get("encryptionConfig", [])

        has_secrets_encryption = any(
            "secrets" in cfg.get("resources", [])
            for cfg in encryption_configs
        )

        if not has_secrets_encryption:
            self.add_finding(
                resource=f"eks:{name}",
                resource_type="AWS::EKS::Cluster",
                issue=f"EKS cluster '{name}' Kubernetes Secrets are not encrypted with KMS",
                description=(
                    f"EKS cluster '{name}' does not have envelope encryption configured for "
                    "Kubernetes Secrets. Without this, secrets stored in etcd are only base64-encoded."
                ),
                severity="HIGH",
                cis_control="2.1.1",
                remediation="Enable Secrets encryption using a KMS customer-managed key.",
                remediation_cli=(
                    f"aws eks associate-encryption-config --cluster-name {name} "
                    "--encryption-config '[{\"resources\":[\"secrets\"],\"provider\":{\"keyArn\":\"<kms-key-arn>\"}}]' "
                    f"--region {self.region}"
                ),
            )

    def _check_kubernetes_version(self, cluster: dict):
        name = cluster["name"]
        version = cluster.get("version", "")

        # Kubernetes versions older than 1.27 are out of EKS extended support
        try:
            major, minor = int(version.split(".")[0]), int(version.split(".")[1])
            if major == 1 and minor < 27:
                self.add_finding(
                    resource=f"eks:{name}",
                    resource_type="AWS::EKS::Cluster",
                    issue=f"EKS cluster '{name}' is running an outdated Kubernetes version ({version})",
                    description=(
                        f"EKS cluster '{name}' is running Kubernetes {version}. "
                        "Older versions may have known CVEs and no longer receive security patches."
                    ),
                    severity="MEDIUM",
                    cis_control="2.3.4",
                    remediation=f"Upgrade EKS cluster '{name}' to a supported Kubernetes version.",
                    remediation_cli=(
                        f"aws eks update-cluster-version --name {name} --kubernetes-version 1.29 "
                        f"--region {self.region}"
                    ),
                )
        except (ValueError, IndexError):
            pass
