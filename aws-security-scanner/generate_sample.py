import sys, json, os
sys.path.insert(0, '.')
from src.analysis.risk_scorer import RiskScorer
from src.analysis.attack_path import AttackPathAnalyzer
from src.compliance.mapper import ComplianceMapper
from src.reports.generator import ReportGenerator

findings_raw = [
    {"id":"s3-0001","severity":"CRITICAL","service":"S3","resource":"my-prod-data-bucket","resource_type":"AWS::S3::Bucket","issue":"Bucket ACL grants READ to AllUsers","description":"Bucket my-prod-data-bucket has a public-read ACL.","cis_control":"2.1.5","remediation":"Remove public ACL.","remediation_cli":"aws s3api put-bucket-acl --bucket my-prod-data-bucket --acl private","region":"us-east-1"},
    {"id":"s3-0002","severity":"HIGH","service":"S3","resource":"prod-backups","resource_type":"AWS::S3::Bucket","issue":"S3 bucket default encryption not enabled","description":"Bucket prod-backups has no server-side encryption.","cis_control":"2.1.1","remediation":"Enable SSE.","remediation_cli":"aws s3api put-bucket-encryption ...","region":"us-east-1"},
    {"id":"s3-0003","severity":"MEDIUM","service":"S3","resource":"prod-backups","resource_type":"AWS::S3::Bucket","issue":"S3 bucket versioning not enabled","description":"No versioning on prod-backups.","cis_control":"2.1.3","remediation":"Enable versioning.","remediation_cli":"aws s3api put-bucket-versioning ...","region":"us-east-1"},
    {"id":"iam-0001","severity":"CRITICAL","service":"IAM","resource":"root","resource_type":"AWS::IAM::User","issue":"MFA not enabled on root account","description":"Root account has no MFA.","cis_control":"1.5","remediation":"Enable MFA.","remediation_cli":"# Enable via console","region":"us-east-1"},
    {"id":"iam-0002","severity":"CRITICAL","service":"IAM","resource":"root","resource_type":"AWS::IAM::User","issue":"Root account has active access keys","description":"Root access keys exist.","cis_control":"1.4","remediation":"Delete root access keys.","remediation_cli":"# Delete via console","region":"us-east-1"},
    {"id":"iam-0003","severity":"HIGH","service":"IAM","resource":"iam:user:alice","resource_type":"AWS::IAM::User","issue":"IAM user has console access without MFA","description":"User alice has no MFA.","cis_control":"1.10","remediation":"Enable MFA.","remediation_cli":"","region":"us-east-1"},
    {"id":"iam-0004","severity":"HIGH","service":"IAM","resource":"iam:user:admin-bob","resource_type":"AWS::IAM::User","issue":"IAM user has overly permissive policy: AdministratorAccess","description":"admin-bob has AdministratorAccess.","cis_control":"1.16","remediation":"Remove admin policy.","remediation_cli":"aws iam detach-user-policy ...","region":"us-east-1"},
    {"id":"ec2-0001","severity":"CRITICAL","service":"EC2","resource":"sg-0a1b2c (web-servers)","resource_type":"AWS::EC2::SecurityGroup","issue":"Security group allows SSH (port 22) from the internet","description":"SSH open to 0.0.0.0/0.","cis_control":"5.2","remediation":"Restrict SSH.","remediation_cli":"aws ec2 revoke-security-group-ingress ...","region":"us-east-1"},
    {"id":"rds-0001","severity":"CRITICAL","service":"RDS","resource":"rds:prod-mysql","resource_type":"AWS::RDS::DBInstance","issue":"RDS instance prod-mysql is publicly accessible","description":"prod-mysql is public.","cis_control":"2.3.2","remediation":"Disable public access.","remediation_cli":"aws rds modify-db-instance ...","region":"us-east-1"},
    {"id":"ct-0001","severity":"HIGH","service":"CloudTrail","resource":"cloudtrail","resource_type":"AWS::CloudTrail::Trail","issue":"No multi-region CloudTrail trail configured","description":"No multi-region trail.","cis_control":"3.3","remediation":"Enable multi-region.","remediation_cli":"aws cloudtrail update-trail ...","region":"us-east-1"},
    {"id":"vpc-0001","severity":"MEDIUM","service":"VPC","resource":"vpc-0123456789abcdef0","resource_type":"AWS::EC2::VPC","issue":"VPC flow logs not enabled","description":"No flow logs.","cis_control":"3.9","remediation":"Enable flow logs.","remediation_cli":"aws ec2 create-flow-logs ...","region":"us-east-1"},
    {"id":"eks-0001","severity":"HIGH","service":"EKS","resource":"eks:prod-cluster","resource_type":"AWS::EKS::Cluster","issue":"EKS cluster prod-cluster API endpoint is publicly accessible from 0.0.0.0/0","description":"EKS public endpoint.","cis_control":"5.4","remediation":"Restrict endpoint.","remediation_cli":"aws eks update-cluster-config ...","region":"us-east-1"},
    {"id":"sm-0001","severity":"HIGH","service":"SecretsManager","resource":"secret:prod/db-password","resource_type":"AWS::SecretsManager::Secret","issue":"Secret prod/db-password does not have automatic rotation enabled","description":"No rotation configured.","cis_control":"1.14","remediation":"Enable rotation.","remediation_cli":"aws secretsmanager rotate-secret ...","region":"us-east-1"},
]

scorer = RiskScorer()
inventory = {
    "resources": [
        {"id":"my-prod-data-bucket","type":"S3","region":"us-east-1","account_id":"123456789012","public_exposure":True},
        {"id":"iam:user:admin-bob","type":"IAM","region":"global","account_id":"123456789012","public_exposure":False,"sensitive":True},
        {"id":"rds:prod-mysql","type":"RDS","region":"us-east-1","account_id":"123456789012","sensitive":True},
        {"id":"sg-0a1b2c (web-servers)","type":"EC2","region":"us-east-1","account_id":"123456789012","sensitive":True},
    ],
    "iam_roles": [{"arn":"iam:user:admin-bob","assumable_by_external":True}],
    "s3_objects": {"my-prod-data-bucket": ["credentials", ".env", "config.yml"]},
}
scored = scorer.score_all(findings_raw, inventory)

analyzer = AttackPathAnalyzer()
analyzer.build_resource_graph(findings_raw, inventory)
attack_paths = analyzer.find_attack_paths()
graph_data = analyzer.export_graph_data()
scorer.mark_attack_chain_members(scored, attack_paths)

mapper = ComplianceMapper()
compliance = mapper.map_findings(scored)

stats = {"total_findings":len(scored),"by_severity":{"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0},"by_service":{},"scan_duration_seconds":52.3,"attack_paths_detected":len(attack_paths)}
for f in scored:
    stats["by_severity"][f["severity"]] = stats["by_severity"].get(f["severity"],0)+1
    stats["by_service"][f["service"]] = stats["by_service"].get(f["service"],0)+1

report_data = {
    "scan_metadata":{"scan_time":"2026-02-20T10:30:00Z","account_id":"123456789012","region":"us-east-1","services_scanned":["s3","iam","ec2","rds","vpc","cloudtrail","eks","secretsmanager"],"scan_duration_seconds":52.3,"scanner_version":"2.0"},
    "findings":scored,"attack_paths":attack_paths,"graph_data":graph_data,"compliance":compliance,"statistics":stats,
}

gen = ReportGenerator(report_data)
gen.generate("/tmp/v2_report.html", fmt="html")
gen.generate("/tmp/v2_report.json", fmt="json")
gen.generate("/tmp/v2_report.csv", fmt="csv")

print(f"HTML: {os.path.getsize('/tmp/v2_report.html'):,} bytes")
print(f"JSON: {os.path.getsize('/tmp/v2_report.json'):,} bytes")
print(f"CSV:  {os.path.getsize('/tmp/v2_report.csv'):,} bytes")
print(f"Findings: {len(scored)} | Attack paths: {len(attack_paths)} | CIS: {compliance['score']}% | NIST: {compliance['frameworks']['nist']['score']}% | PCI: {compliance['frameworks']['pci']['score']}%")
print(f"Top risk: [{scored[0]['severity']}] {scored[0]['issue']} (risk {scored[0]['risk_score']})")
if attack_paths:
    print(f"Top chain: {attack_paths[0]['entry_point']} → {attack_paths[0]['target']} (risk {attack_paths[0]['risk_score']})")
    print(f"Steps: {attack_paths[0]['attack_steps']}")
