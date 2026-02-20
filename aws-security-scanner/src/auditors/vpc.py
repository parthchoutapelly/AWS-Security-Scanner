"""VPC Security Auditor — checks flow logs, default VPC usage, and network ACLs."""
from typing import List, Dict, Any

from botocore.exceptions import ClientError

from src.auditors.base import BaseAuditor


class VPCAuditor(BaseAuditor):
    """Audits VPC configuration for security misconfigurations."""

    SERVICE_NAME = "VPC"

    def audit(self) -> List[Dict[str, Any]]:
        ec2 = self.session.client("ec2", region_name=self.region)

        self.logger.info("Scanning VPC configuration...")
        self._check_vpcs(ec2)

        return self.findings

    def _check_vpcs(self, ec2):
        try:
            vpcs = ec2.describe_vpcs()["Vpcs"]
        except ClientError as e:
            self.logger.error(f"Cannot list VPCs: {e}")
            return

        self.logger.info(f"Scanning {len(vpcs)} VPC(s)...")

        try:
            flow_log_resp = ec2.describe_flow_logs()
            flow_log_vpc_ids = {
                fl["ResourceId"]
                for fl in flow_log_resp.get("FlowLogs", [])
                if fl.get("FlowLogStatus") == "ACTIVE"
            }
        except ClientError:
            flow_log_vpc_ids = set()

        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            is_default = vpc.get("IsDefault", False)

            # Default VPC in use
            if is_default:
                # Check if any resources are using the default VPC
                try:
                    instances = ec2.describe_instances(
                        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
                    )
                    reservations = instances.get("Reservations", [])
                    instance_count = sum(len(r["Instances"]) for r in reservations)
                    if instance_count > 0:
                        self.add_finding(
                            resource=vpc_id,
                            resource_type="AWS::EC2::VPC",
                            issue=f"Default VPC has {instance_count} EC2 instance(s)",
                            description=(
                                f"The default VPC ({vpc_id}) contains {instance_count} EC2 instance(s). "
                                "Resources should use custom VPCs with proper network segmentation."
                            ),
                            severity="MEDIUM",
                            cis_control="5.1",
                            remediation="Migrate resources to a custom VPC and delete the default VPC.",
                            remediation_cli=f"aws ec2 delete-vpc --vpc-id {vpc_id} --region {self.region}  # After migrating resources",
                        )
                except ClientError:
                    pass

            # Flow logs
            if vpc_id not in flow_log_vpc_ids:
                self.add_finding(
                    resource=vpc_id,
                    resource_type="AWS::EC2::VPC",
                    issue=f"VPC flow logs not enabled for {vpc_id}",
                    description=(
                        f"VPC '{vpc_id}' does not have flow logs enabled. "
                        "Flow logs are required for network traffic monitoring and incident response."
                    ),
                    severity="MEDIUM",
                    cis_control="3.9",
                    remediation=f"Enable VPC flow logs for '{vpc_id}'.",
                    remediation_cli=(
                        f"aws ec2 create-flow-logs --resource-type VPC "
                        f"--resource-ids {vpc_id} --traffic-type ALL "
                        "--log-destination-type cloud-watch-logs "
                        f"--log-group-name /aws/vpc/flowlogs --region {self.region}"
                    ),
                )

        # Check network ACLs for overly permissive rules
        self._check_network_acls(ec2)

    def _check_network_acls(self, ec2):
        try:
            acls = ec2.describe_network_acls()["NetworkAcls"]
        except ClientError:
            return

        for acl in acls:
            acl_id = acl["NetworkAclId"]
            for entry in acl.get("Entries", []):
                # Only inbound rules (Egress=False), allowing all traffic from anywhere
                if (
                    not entry.get("Egress", True)
                    and entry.get("RuleAction") == "allow"
                    and entry.get("Protocol") == "-1"
                    and (
                        entry.get("CidrBlock") == "0.0.0.0/0"
                        or entry.get("Ipv6CidrBlock") == "::/0"
                    )
                    and not acl.get("IsDefault", False)
                ):
                    self.add_finding(
                        resource=acl_id,
                        resource_type="AWS::EC2::NetworkAcl",
                        issue=f"Network ACL '{acl_id}' allows all inbound traffic",
                        description=(
                            f"Network ACL '{acl_id}' has an ALLOW rule for all inbound traffic "
                            f"from 0.0.0.0/0. Network ACLs should restrict traffic to required ports only."
                        ),
                        severity="MEDIUM",
                        cis_control="5.1",
                        remediation="Replace the allow-all rule with specific port and source restrictions.",
                        remediation_cli=f"aws ec2 describe-network-acls --network-acl-ids {acl_id} --region {self.region}",
                    )
