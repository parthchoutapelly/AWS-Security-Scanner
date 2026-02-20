"""AWS Lambda handler for serverless continuous security monitoring."""
import json
import os
import boto3

from src.scanner import SecurityScanner, ScanConfig
from src.reports.generator import ReportGenerator


def lambda_handler(event, context):
    """
    Lambda entry point.
    Triggered by EventBridge on a schedule; sends SNS alerts for critical findings
    and uploads the report to S3.
    """
    region = os.environ.get("AWS_REGION", "us-east-1")
    sns_topic_arn = os.environ.get("SNS_TOPIC_ARN")
    s3_report_bucket = os.environ.get("REPORT_S3_BUCKET")
    services = os.environ.get("SERVICES", "s3,iam,ec2,rds,vpc,cloudtrail").split(",")

    session = boto3.Session()
    account_id = session.client("sts").get_caller_identity()["Account"]

    config = ScanConfig(services=services, region=region, account_id=account_id)
    scanner = SecurityScanner(session, config)
    scanner.scan()

    report_data = scanner.build_report_data()
    summary = scanner.get_summary()

    # Generate JSON report
    import tempfile, os as _os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        generator = ReportGenerator(report_data)
        generator.generate(tmp_path, fmt="json")

        # Upload to S3
        if s3_report_bucket:
            from datetime import datetime
            key = f"reports/{datetime.utcnow().strftime('%Y/%m/%d')}/security-scan.json"
            s3 = session.client("s3")
            s3.upload_file(tmp_path, s3_report_bucket, key)
            print(f"Report uploaded to s3://{s3_report_bucket}/{key}")
    finally:
        _os.unlink(tmp_path)

    # Alert on critical findings
    critical_findings = [f for f in scanner.all_findings if f["severity"] == "CRITICAL"]
    if critical_findings and sns_topic_arn:
        sns = session.client("sns")
        message = (
            f"🚨 AWS Security Scanner — Critical Findings Detected\n\n"
            f"Account: {account_id}\nRegion: {region}\n"
            f"Total critical findings: {len(critical_findings)}\n\n"
        )
        for f in critical_findings[:10]:
            message += f"• [{f['cis_control']}] {f['issue']} — {f['resource']}\n"

        sns.publish(
            TopicArn=sns_topic_arn,
            Subject=f"[{account_id}] AWS Security: {len(critical_findings)} Critical Finding(s)",
            Message=message,
        )

    return {
        "statusCode": 200,
        "body": json.dumps({
            "account_id": account_id,
            "total_findings": summary["total_findings"],
            "critical": summary["by_severity"]["CRITICAL"],
            "high": summary["by_severity"]["HIGH"],
            "compliance_score": report_data["compliance"]["score"],
        }),
    }
