# AWS-Security-Scanner
Enterprise-grade AWS Security Posture Scanner that audits multi-account cloud environments for misconfigurations, maps findings to CIS/NIST/PCI frameworks, performs graph-based attack path analysis, and applies risk scoring for prioritized remediation. Supports async scanning, HTML reports, and serverless deployment via Lambda and Terraform.


# AWS Security Posture Scanner

Enterprise-grade Cloud Security Posture Management (CSPM) tool for auditing AWS environments, detecting misconfigurations, analyzing attack paths, and ensuring compliance with security frameworks.

---

## Overview

AWS Security Posture Scanner automatically audits AWS resources across multiple services, identifies security risks, maps findings to compliance frameworks, and prioritizes remediation using a risk scoring engine and attack path analysis.

This tool helps security teams gain visibility into their cloud security posture and detect exploitable misconfigurations before attackers do.

---

## Key Features

- 60+ automated security checks across AWS services:
  - S3
  - IAM
  - EC2
  - RDS
  - VPC
  - CloudTrail

- Compliance mapping:
  - CIS AWS Foundations Benchmark
  - NIST Cybersecurity Framework
  - PCI-DSS

- Risk scoring algorithm
  - Exploitability-based prioritization
  - Blast radius analysis
  - Business impact scoring

- Attack path analysis
  - Graph-based infrastructure modeling (NetworkX)
  - Detect chained exploit paths
  - Visual attack graph in HTML report

- Async parallel scanning
  - Faster scans using asyncio

- Multi-format reporting
  - HTML dashboard
  - JSON
  - CSV

- Multi-account scanning
  - AWS Organizations support
  - Cross-account role assumption

- Serverless deployment support
  - AWS Lambda
  - EventBridge scheduling
  - SNS alerting
  - Terraform IaC

---

## Architecture

```
CLI / Dashboard
      ↓
Async Scan Engine
      ↓
AWS Auditors
(S3, IAM, EC2, RDS, VPC, CloudTrail)
      ↓
Compliance Mapper
      ↓
Risk Scoring Engine
      ↓
Attack Path Analyzer
      ↓
Report Generator
(HTML, JSON, CSV)
```

---

## Project Structure

```
src/
 ├ auditors/
 ├ compliance/
 ├ reports/
 ├ analysis/
 ├ utils/
 ├ scanner.py
 └ cli.py

lambda_handler.py
terraform/
tests/
examples/
```

---

## Installation

Clone repository:

```bash
git clone https://github.com/yourusername/aws-security-scanner.git
cd aws-security-scanner
```

Create virtual environment:

```bash
python -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Configure AWS Credentials

```bash
aws configure
```

Required permissions:

- ReadOnlyAccess (minimum)
- SecurityAudit (recommended)

---

## Usage

Run full scan:

```bash
python -m src.cli scan
```

Scan specific services:

```bash
python -m src.cli scan --services s3,iam,ec2
```

Generate JSON report:

```bash
python -m src.cli scan --format json --output report.json
```

Launch dashboard:

```bash
python -m src.cli dashboard
```

---

## Example Output

- Compliance score dashboard
- Risk-scored findings
- Attack path graph
- Remediation recommendations

---

## Deployment (Serverless)

Deploy using Terraform:

```bash
cd terraform
terraform init
terraform apply
```

This enables automated continuous security monitoring.

---

## Technologies Used

- Python
- Boto3
- asyncio
- NetworkX
- Flask
- Jinja2
- Terraform
- AWS Lambda

---

## Use Cases

- Cloud security auditing
- Compliance validation
- Attack path analysis
- DevSecOps automation
- Continuous security monitoring

---

## Future Enhancements

- GuardDuty integration
- SecurityHub integration
- Docker support
- Web dashboard improvements
- Real-time monitoring

---

## Author

Your Name  
Cloud Security | AWS | DevSecOps | Python

GitHub: https://github.com/yourusername

---

## License

MIT License
