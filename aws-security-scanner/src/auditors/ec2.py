"""EC2 Security Auditor — checks security groups for overly permissive rules."""
from typing import List, Dict, Any

from botocore.exceptions import ClientError

from src.auditors.base import BaseAuditor

# Ports that should never be open to the world
SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    9300: "Elasticsearch cluster",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
}


class EC2Auditor(BaseAuditor):
    """Audits EC2 security groups and instances for misconfigurations."""

    SERVICE_NAME = "EC2"

    def audit(self) -> List[Dict[str, Any]]:
        ec2 = self.session.client("ec2", region_name=self.region)

        self.logger.info("Scanning EC2 security groups...")
        self._check_security_groups(ec2)

        return self.findings

    # ── Security groups ───────────────────────────────────────────────────────

    def _check_security_groups(self, ec2):
        try:
            paginator = ec2.get_paginator("describe_security_groups")
            sgs = []
            for page in paginator.paginate():
                sgs.extend(page["SecurityGroups"])
        except ClientError as e:
            self.logger.error(f"Cannot list security groups: {e}")
            return

        self.logger.info(f"Scanning {len(sgs)} security groups...")

        # Get SGs actually attached to something
        attached_sgs = self._get_attached_sg_ids(ec2)

        for sg in sgs:
            sg_id = sg["GroupId"]
            sg_name = sg["GroupName"]
            vpc_id = sg.get("VpcId", "")

            self._check_ingress_rules(sg)
            self._check_default_sg(sg)

            if sg_id not in attached_sgs:
                self.add_finding(
                    resource=f"{sg_id} ({sg_name})",
                    resource_type="AWS::EC2::SecurityGroup",
                    issue="Unused security group",
                    description=(
                        f"Security group '{sg_name}' ({sg_id}) in VPC {vpc_id} is not "
                        "attached to any EC2 instance, ENI, RDS instance, or Lambda function."
                    ),
                    severity="LOW",
                    cis_control="5.4",
                    remediation=f"Review and delete security group '{sg_name}' if it is no longer needed.",
                    remediation_cli=f"aws ec2 delete-security-group --group-id {sg_id} --region {self.region}",
                )

    def _check_ingress_rules(self, sg: dict):
        sg_id = sg["GroupId"]
        sg_name = sg["GroupName"]

        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)
            protocol = rule.get("IpProtocol", "-1")

            # Collect all open CIDR ranges
            open_ipv4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", []))
            open_ipv6 = any(r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", []))
            open_to_world = open_ipv4 or open_ipv6
            cidr = "0.0.0.0/0" if open_ipv4 else "::/0"

            if not open_to_world:
                continue

            # All-traffic open
            if protocol == "-1":
                self.add_finding(
                    resource=f"{sg_id} ({sg_name})",
                    resource_type="AWS::EC2::SecurityGroup",
                    issue="Security group allows all inbound traffic from the internet",
                    description=(
                        f"Security group '{sg_name}' ({sg_id}) allows all inbound traffic "
                        f"from {cidr} on all ports and protocols."
                    ),
                    severity="CRITICAL",
                    cis_control="5.2",
                    remediation="Restrict the security group rules to only allow traffic from trusted sources on specific ports.",
                    remediation_cli=(
                        f"aws ec2 revoke-security-group-ingress --group-id {sg_id} "
                        f"--protocol all --cidr {cidr} --region {self.region}"
                    ),
                )
                continue

            # Sensitive specific port
            for port in range(from_port, to_port + 1):
                if port in SENSITIVE_PORTS:
                    service_name = SENSITIVE_PORTS[port]
                    self.add_finding(
                        resource=f"{sg_id} ({sg_name})",
                        resource_type="AWS::EC2::SecurityGroup",
                        issue=f"Security group allows {service_name} (port {port}) from the internet",
                        description=(
                            f"Security group '{sg_name}' ({sg_id}) allows {service_name} traffic "
                            f"(port {port}/{protocol}) from {cidr}. This exposes the service to the public internet."
                        ),
                        severity="CRITICAL" if port in (22, 3389) else "HIGH",
                        cis_control="5.2" if port in (22, 3389) else "5.3",
                        remediation=(
                            f"Restrict port {port} to specific trusted IP addresses or use a VPN/bastion host."
                        ),
                        remediation_cli=(
                            f"aws ec2 revoke-security-group-ingress --group-id {sg_id} "
                            f"--protocol {protocol} --port {port} --cidr {cidr} --region {self.region}"
                        ),
                    )
                    break  # Only report once per rule even if range spans multiple sensitive ports

            # Any port open to world (not already caught as sensitive)
            else:
                # Warn about wide-open non-sensitive port ranges
                port_range = f"{from_port}" if from_port == to_port else f"{from_port}-{to_port}"
                if (to_port - from_port) > 100:
                    self.add_finding(
                        resource=f"{sg_id} ({sg_name})",
                        resource_type="AWS::EC2::SecurityGroup",
                        issue=f"Security group opens large port range {port_range} to the internet",
                        description=(
                            f"Security group '{sg_name}' ({sg_id}) allows inbound traffic on "
                            f"ports {port_range} from {cidr}."
                        ),
                        severity="MEDIUM",
                        cis_control="5.3",
                        remediation="Restrict the port range to only required ports.",
                        remediation_cli=(
                            f"aws ec2 revoke-security-group-ingress --group-id {sg_id} "
                            f"--protocol {protocol} --port {from_port}-{to_port} --cidr {cidr} --region {self.region}"
                        ),
                    )

    def _check_default_sg(self, sg: dict):
        if sg["GroupName"] != "default":
            return
        has_rules = sg.get("IpPermissions") or sg.get("IpPermissionsEgress")
        if has_rules:
            self.add_finding(
                resource=f"{sg['GroupId']} (default)",
                resource_type="AWS::EC2::SecurityGroup",
                issue="Default security group has inbound or outbound rules",
                description=(
                    "The default security group should not have any inbound or outbound rules. "
                    "Instances should use custom security groups with explicit rules."
                ),
                severity="MEDIUM",
                cis_control="5.4",
                remediation="Remove all rules from the default security group.",
                remediation_cli=(
                    f"# Revoke all ingress/egress rules from default SG {sg['GroupId']}:\n"
                    f"aws ec2 describe-security-groups --group-ids {sg['GroupId']} --region {self.region}"
                ),
            )

    def _get_attached_sg_ids(self, ec2) -> set:
        """Return set of security group IDs currently attached to any resource."""
        attached = set()
        try:
            paginator = ec2.get_paginator("describe_network_interfaces")
            for page in paginator.paginate():
                for eni in page["NetworkInterfaces"]:
                    for sg in eni.get("Groups", []):
                        attached.add(sg["GroupId"])
        except ClientError:
            pass
        return attached
