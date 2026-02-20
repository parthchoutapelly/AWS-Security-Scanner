"""Unit tests for AWS service auditors using moto mocks."""
import json
import pytest
import boto3
from moto import mock_aws


# ── S3 Tests ───────────────────────────────────────────────────────────────


@mock_aws
def test_s3_public_acl_detection():
    """Public-read ACL on a bucket should trigger a CRITICAL finding."""
    from src.auditors.s3 import S3Auditor

    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="public-bucket")
    s3.put_bucket_acl(Bucket="public-bucket", ACL="public-read")

    session = boto3.Session(region_name="us-east-1")
    auditor = S3Auditor(session, region="us-east-1")
    findings = auditor.audit()

    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    assert len(critical) > 0
    assert any("public" in f["issue"].lower() for f in critical)


@mock_aws
def test_s3_no_encryption_detection():
    """Bucket without encryption should trigger a HIGH finding."""
    from src.auditors.s3 import S3Auditor

    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="unencrypted-bucket")

    session = boto3.Session(region_name="us-east-1")
    auditor = S3Auditor(session, region="us-east-1")
    findings = auditor.audit()

    enc_findings = [f for f in findings if "encrypt" in f["issue"].lower()]
    assert len(enc_findings) > 0
    assert any(f["severity"] == "HIGH" for f in enc_findings)


@mock_aws
def test_s3_no_versioning_detection():
    """Bucket without versioning should trigger a MEDIUM finding."""
    from src.auditors.s3 import S3Auditor

    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="no-versioning-bucket")

    session = boto3.Session(region_name="us-east-1")
    auditor = S3Auditor(session, region="us-east-1")
    findings = auditor.audit()

    versioning_findings = [f for f in findings if "version" in f["issue"].lower()]
    assert len(versioning_findings) > 0
    assert versioning_findings[0]["severity"] == "MEDIUM"


@mock_aws
def test_s3_encrypted_versioned_bucket_has_fewer_findings():
    """A hardened bucket should produce fewer findings than an unhardened one."""
    from src.auditors.s3 import S3Auditor

    s3 = boto3.client("s3", region_name="us-east-1")

    # Hardened bucket
    s3.create_bucket(Bucket="hardened-bucket")
    s3.put_bucket_encryption(
        Bucket="hardened-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    s3.put_bucket_versioning(
        Bucket="hardened-bucket",
        VersioningConfiguration={"Status": "Enabled"},
    )

    # Bare bucket
    s3.create_bucket(Bucket="bare-bucket")

    session = boto3.Session(region_name="us-east-1")
    auditor = S3Auditor(session, region="us-east-1")
    findings = auditor.audit()

    hardened_findings = [f for f in findings if "hardened-bucket" in f["resource"]]
    bare_findings = [f for f in findings if "bare-bucket" in f["resource"]]
    assert len(hardened_findings) < len(bare_findings)


# ── IAM Tests ──────────────────────────────────────────────────────────────


@mock_aws
def test_iam_no_password_policy():
    """Missing password policy should trigger a HIGH finding."""
    from src.auditors.iam import IAMAuditor

    session = boto3.Session(region_name="us-east-1")
    auditor = IAMAuditor(session)
    findings = auditor.audit()

    pw_findings = [f for f in findings if "password policy" in f["issue"].lower()]
    assert len(pw_findings) > 0


@mock_aws
def test_iam_user_without_mfa():
    """Console user without MFA should trigger a HIGH finding."""
    from src.auditors.iam import IAMAuditor

    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Password123!")

    session = boto3.Session(region_name="us-east-1")
    auditor = IAMAuditor(session)
    findings = auditor.audit()

    mfa_findings = [f for f in findings if "mfa" in f["issue"].lower() and "alice" in f["resource"]]
    assert len(mfa_findings) > 0
    assert mfa_findings[0]["severity"] == "HIGH"


@mock_aws
def test_iam_admin_policy_attached():
    """User with AdministratorAccess should trigger a HIGH finding."""
    from src.auditors.iam import IAMAuditor

    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="admin-bob")
    iam.attach_user_policy(
        UserName="admin-bob",
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
    )

    session = boto3.Session(region_name="us-east-1")
    auditor = IAMAuditor(session)
    findings = auditor.audit()

    admin_findings = [
        f for f in findings
        if "administrator" in f["issue"].lower() and "admin-bob" in f["resource"]
    ]
    assert len(admin_findings) > 0


# ── EC2 Tests ──────────────────────────────────────────────────────────────


@mock_aws
def test_ec2_ssh_open_to_world():
    """Security group with SSH (22) open to 0.0.0.0/0 should be CRITICAL."""
    from src.auditors.ec2 import EC2Auditor

    ec2 = boto3.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(GroupName="open-ssh", Description="open ssh")
    sg_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )

    session = boto3.Session(region_name="us-east-1")
    auditor = EC2Auditor(session, region="us-east-1")
    findings = auditor.audit()

    ssh_findings = [f for f in findings if "ssh" in f["issue"].lower() or "port 22" in f["issue"].lower()]
    assert len(ssh_findings) > 0
    assert ssh_findings[0]["severity"] == "CRITICAL"


@mock_aws
def test_ec2_rdp_open_to_world():
    """Security group with RDP (3389) open to 0.0.0.0/0 should be CRITICAL."""
    from src.auditors.ec2 import EC2Auditor

    ec2 = boto3.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(GroupName="open-rdp", Description="open rdp")
    sg_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 3389,
            "ToPort": 3389,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )

    session = boto3.Session(region_name="us-east-1")
    auditor = EC2Auditor(session, region="us-east-1")
    findings = auditor.audit()

    rdp_findings = [f for f in findings if "rdp" in f["issue"].lower() or "3389" in f["issue"]]
    assert len(rdp_findings) > 0
    assert rdp_findings[0]["severity"] == "CRITICAL"


@mock_aws
def test_ec2_clean_sg_no_critical_findings():
    """A restricted security group should have no CRITICAL findings."""
    from src.auditors.ec2 import EC2Auditor

    ec2 = boto3.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(GroupName="restricted", Description="restricted sg")
    sg_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 443,
            "ToPort": 443,
            "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
        }],
    )

    session = boto3.Session(region_name="us-east-1")
    auditor = EC2Auditor(session, region="us-east-1")
    findings = auditor.audit()

    restricted_findings = [f for f in findings if "restricted" in f["resource"]]
    critical = [f for f in restricted_findings if f["severity"] == "CRITICAL"]
    assert len(critical) == 0


# ── RDS Tests ──────────────────────────────────────────────────────────────


@mock_aws
def test_rds_public_instance_detection():
    """Publicly accessible RDS instance should trigger a CRITICAL finding."""
    from src.auditors.rds import RDSAuditor

    ec2 = boto3.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(GroupName="rds-sg", Description="rds sg")

    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="public-db",
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="Password123!",
        PubliclyAccessible=True,
        VpcSecurityGroupIds=[sg["GroupId"]],
    )

    session = boto3.Session(region_name="us-east-1")
    auditor = RDSAuditor(session, region="us-east-1")
    findings = auditor.audit()

    public_findings = [f for f in findings if "publicly accessible" in f["issue"].lower()]
    assert len(public_findings) > 0
    assert public_findings[0]["severity"] == "CRITICAL"


# ── Compliance Mapper Tests ────────────────────────────────────────────────


def test_compliance_mapper_score_100_when_no_findings():
    """With zero findings, all controls should pass (100% score)."""
    from src.compliance.mapper import ComplianceMapper

    mapper = ComplianceMapper()
    result = mapper.map_findings([])
    assert result["score"] == 100.0
    assert result["controls_failed"] == 0
    assert result["controls_passed"] == result["controls_total"]


def test_compliance_mapper_failed_controls():
    """Findings with known CIS controls should mark those controls as failed."""
    from src.compliance.mapper import ComplianceMapper

    findings = [
        {"cis_control": "1.5", "severity": "CRITICAL", "resource": "root", "issue": "No MFA"},
        {"cis_control": "2.1.5", "severity": "HIGH", "resource": "my-bucket", "issue": "Public bucket"},
    ]
    mapper = ComplianceMapper()
    result = mapper.map_findings(findings)

    failed_ids = [c["id"] for c in result["failed_controls"]]
    assert "1.5" in failed_ids
    assert "2.1.5" in failed_ids
    assert result["score"] < 100.0


def test_compliance_mapper_score_decreases_with_more_findings():
    """More distinct failed controls should reduce the compliance score."""
    from src.compliance.mapper import ComplianceMapper

    few_findings = [{"cis_control": "1.5", "severity": "CRITICAL", "resource": "r", "issue": "x"}]
    many_findings = [
        {"cis_control": c, "severity": "HIGH", "resource": "r", "issue": "x"}
        for c in ["1.5", "2.1.5", "3.1", "5.2", "5.4"]
    ]

    mapper = ComplianceMapper()
    score_few = mapper.map_findings(few_findings)["score"]
    score_many = mapper.map_findings(many_findings)["score"]
    assert score_many < score_few


# ── Report Generator Tests ─────────────────────────────────────────────────


def test_report_generator_json(tmp_path):
    """JSON report should be valid JSON with expected top-level keys."""
    from src.reports.generator import ReportGenerator

    data = {
        "scan_metadata": {"scan_time": "2024-01-01T00:00:00Z", "account_id": "123", "region": "us-east-1", "services_scanned": ["s3"], "scan_duration_seconds": 5},
        "findings": [{"id": "s3-0001", "severity": "HIGH", "service": "S3", "resource": "my-bucket", "issue": "Test", "cis_control": "2.1.1", "remediation": "Fix it", "remediation_cli": "", "region": "us-east-1", "resource_type": "AWS::S3::Bucket", "description": "desc"}],
        "compliance": {"framework": "CIS v1.5", "score": 90.0, "controls_total": 10, "controls_passed": 9, "controls_failed": 1, "failed_controls": [], "passed_controls": []},
        "statistics": {"total_findings": 1, "by_severity": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0}, "by_service": {"S3": 1}, "scan_duration_seconds": 5},
    }

    out = tmp_path / "report.json"
    gen = ReportGenerator(data)
    gen.generate(str(out), fmt="json")

    assert out.exists()
    with open(out) as f:
        parsed = json.load(f)
    assert "findings" in parsed
    assert "compliance" in parsed
    assert "scan_metadata" in parsed


def test_report_generator_csv(tmp_path):
    """CSV report should have a header row and one data row per finding."""
    import csv
    from src.reports.generator import ReportGenerator

    data = {
        "scan_metadata": {"scan_time": "2024-01-01T00:00:00Z", "account_id": "123", "region": "us-east-1", "services_scanned": ["s3"], "scan_duration_seconds": 5},
        "findings": [
            {"id": "s3-0001", "severity": "HIGH", "service": "S3", "resource": "bucket-1", "issue": "No encryption", "cis_control": "2.1.1", "remediation": "Enable it", "remediation_cli": "aws ...", "region": "us-east-1", "resource_type": "AWS::S3::Bucket", "description": "desc"},
            {"id": "s3-0002", "severity": "CRITICAL", "service": "S3", "resource": "bucket-2", "issue": "Public access", "cis_control": "2.1.5", "remediation": "Block it", "remediation_cli": "aws ...", "region": "us-east-1", "resource_type": "AWS::S3::Bucket", "description": "desc"},
        ],
        "compliance": {"framework": "CIS", "score": 80, "controls_total": 5, "controls_passed": 4, "controls_failed": 1, "failed_controls": [], "passed_controls": []},
        "statistics": {"total_findings": 2, "by_severity": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0}, "by_service": {"S3": 2}, "scan_duration_seconds": 5},
    }

    out = tmp_path / "report.csv"
    gen = ReportGenerator(data)
    gen.generate(str(out), fmt="csv")

    assert out.exists()
    with open(out, newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 2
    assert "severity" in rows[0]


def test_report_generator_html(tmp_path):
    """HTML report should be non-empty and contain expected elements."""
    from src.reports.generator import ReportGenerator

    data = {
        "scan_metadata": {"scan_time": "2024-01-01T00:00:00Z", "account_id": "123456789012", "region": "us-east-1", "services_scanned": ["s3", "iam"], "scan_duration_seconds": 10},
        "findings": [],
        "compliance": {"framework": "CIS AWS Foundations Benchmark v1.5.0", "score": 100.0, "controls_total": 28, "controls_passed": 28, "controls_failed": 0, "failed_controls": [], "passed_controls": []},
        "statistics": {"total_findings": 0, "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}, "by_service": {}, "scan_duration_seconds": 10},
    }

    out = tmp_path / "report.html"
    gen = ReportGenerator(data)
    gen.generate(str(out), fmt="html")

    assert out.exists()
    content = out.read_text()
    assert "AWS Security Posture Report" in content
    assert "123456789012" in content
    assert "CIS" in content
