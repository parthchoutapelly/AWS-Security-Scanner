"""CLI entry point for AWS Security Posture Scanner v2."""
import sys
import asyncio

import click

from src.utils.aws_helper import AWSSessionManager
from src.utils.exceptions import AWSAuthenticationError
from src.scanner import SecurityScanner, ScanConfig
from src.reports.generator import ReportGenerator

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False


def _c(text, color):
    if not HAS_COLOR:
        return text
    colors = {"red": Fore.RED, "green": Fore.GREEN, "yellow": Fore.YELLOW,
              "cyan": Fore.CYAN, "blue": Fore.BLUE, "magenta": Fore.MAGENTA,
              "white": Fore.WHITE, "bold": Style.BRIGHT}
    return f"{colors.get(color,'')}{text}{Style.RESET_ALL}"


SEV_COLORS = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan", "LOW": "green"}


@click.group()
def cli():
    """🔒 AWS Security Posture Scanner v2 — Enterprise cloud security auditing."""
    pass


@cli.command()
@click.option("--profile", default=None, help="AWS profile from ~/.aws/credentials")
@click.option("--region", default="us-east-1", show_default=True)
@click.option("--services", default="all", show_default=True,
              help="Comma-separated: s3,iam,ec2,rds,vpc,cloudtrail,eks,secretsmanager  (or 'all')")
@click.option("--output", default="report.html", show_default=True)
@click.option("--format", "fmt", type=click.Choice(["html", "json", "csv"]), default="html", show_default=True)
@click.option("--role-arn", default=None, help="IAM role ARN for cross-account scanning")
@click.option("--all-accounts", is_flag=True, help="Scan all accounts in AWS Organization")
@click.option("--attack-paths/--no-attack-paths", default=True, show_default=True,
              help="Enable attack path analysis (requires networkx)")
@click.option("--frameworks", default="cis,nist,pci", show_default=True,
              help="Compliance frameworks: cis,nist,pci")
@click.option("--min-severity",
              type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"], case_sensitive=False),
              default="LOW", show_default=True)
@click.option("--save-history", is_flag=True, help="Save scan results to local SQLite history DB")
def scan(profile, region, services, output, fmt, role_arn, all_accounts,
         attack_paths, frameworks, min_severity, save_history):
    """Run an AWS security posture scan."""
    click.echo("")
    click.echo(_c("🔒 AWS Security Posture Scanner v2.0", "bold"))
    click.echo(_c("=" * 54, "blue"))
    click.echo("")

    svc_list = (
        ["s3", "iam", "ec2", "rds", "vpc", "cloudtrail", "eks", "secretsmanager"]
        if services.lower() == "all"
        else [s.strip().lower() for s in services.split(",")]
    )
    fw_list = [f.strip().lower() for f in frameworks.split(",")]

    # ── Auth ──────────────────────────────────────────────────────────────
    try:
        mgr = AWSSessionManager(profile_name=profile, region=region)
        if role_arn:
            click.echo(f"  Assuming role: {role_arn}")
            session = mgr.assume_role(role_arn)
        else:
            session = mgr.create_session()
        account_id = mgr.get_account_id()
    except AWSAuthenticationError as e:
        click.echo(_c(f"\n  ❌ Authentication failed: {e}", "red"), err=True)
        sys.exit(1)

    click.echo(f"  {'Account:':<22} {account_id}")
    click.echo(f"  {'Region:':<22} {region}")
    click.echo(f"  {'Services:':<22} {', '.join(svc_list)}")
    click.echo(f"  {'Frameworks:':<22} {', '.join(fw_list).upper()}")
    click.echo(f"  {'Attack path analysis:':<22} {'✓' if attack_paths else '✗'}")
    click.echo("")

    # ── Multi-account mode ────────────────────────────────────────────────
    if all_accounts:
        from src.multi_account import MultiAccountScanner
        click.echo(_c("  🏢 Multi-account scan via AWS Organizations...", "bold"))
        multi = MultiAccountScanner(session, region=region, services=svc_list)
        results = asyncio.run(multi.scan_all_accounts())
        click.echo("")
        for summary in results.get("account_summaries", []):
            icon = "✓" if summary["status"] == "success" else "✗"
            score = f"{summary['cis_score']:.0f}%" if summary.get("cis_score") else "—"
            click.echo(f"  {icon} {summary['account_name']:<30} {summary['total_findings']:>4} findings  CIS: {score}")
        all_findings = results.get("consolidated_findings", [])
        click.echo(f"\n  Total findings across all accounts: {len(all_findings)}")
        return

    # ── Single account scan ───────────────────────────────────────────────
    click.echo(_c("  📊 Running security audit...", "bold"))
    click.echo("")

    config = ScanConfig(
        services=svc_list,
        region=region,
        account_id=account_id,
        enable_attack_paths=attack_paths,
        frameworks=fw_list,
    )
    scanner = SecurityScanner(session, config)
    scanner.scan()

    # Per-service results
    for svc, svc_findings in scanner._auditor_results.items():
        count = len(svc_findings)
        icon = "⚠" if count else "✓"
        color = "yellow" if count else "green"
        click.echo(f"  {_c(icon, color)}  {svc:<20} {count} finding(s)")

    click.echo("")

    # ── Attack paths ───────────────────────────────────────────────────────
    if attack_paths and scanner.attack_paths:
        click.echo(_c(f"  🔗 Attack Paths Detected: {len(scanner.attack_paths)}", "red"))
        for i, path in enumerate(scanner.attack_paths[:3], 1):
            chain = " → ".join(str(n)[:20] for n in path.get("path", [])[:4])
            click.echo(f"     Path {i} (Risk {path['risk_score']:.1f}): {chain}")
        click.echo("")

    # ── Compliance ─────────────────────────────────────────────────────────
    compliance = scanner.get_compliance()
    fws = compliance.get("frameworks", {})
    click.echo(_c("  📊 Compliance Scores:", "bold"))
    for key, fw in fws.items():
        sc = fw["score"]
        color = "green" if sc >= 80 else ("yellow" if sc >= 60 else "red")
        click.echo(f"     {fw['framework']:<40} {_c(f'{sc}%', color)}")
    click.echo("")

    # ── Severity summary ───────────────────────────────────────────────────
    summary = scanner.get_summary()
    click.echo(_c("  🎯 Findings by severity:", "bold"))
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = summary["by_severity"].get(sev, 0)
        if count:
            click.echo(f"     {_c(sev, SEV_COLORS[sev]):<25} {count}")

    # Apply severity filter
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    min_idx = sev_order[min_severity.upper()]
    report_data = scanner.build_report_data()
    report_data["findings"] = [
        f for f in report_data["findings"]
        if sev_order.get(f["severity"], 3) <= min_idx
    ]

    # ── Generate report ────────────────────────────────────────────────────
    click.echo(f"\n  📝 Generating {fmt.upper()} report...")
    generator = ReportGenerator(report_data)
    generator.generate(output, fmt=fmt)
    click.echo(_c(f"\n  ✅ Report saved to: {output}", "green"))

    # ── Save to history ────────────────────────────────────────────────────
    if save_history:
        from src.db.history import ScanHistoryDB
        db = ScanHistoryDB()
        scan_id = db.save_scan(report_data)
        click.echo(f"  💾 Saved to history (scan ID: {scan_id})")

    click.echo("")


@cli.command()
@click.option("--port", default=5000, show_default=True)
@click.option("--host", default="127.0.0.1", show_default=True)
def dashboard(port, host):
    """Launch the real-time web dashboard."""
    try:
        from src.web.app import create_app
        app, socketio = create_app()
        click.echo(f"\n  🌐 Dashboard at http://{host}:{port}")
        click.echo("  Press Ctrl+C to stop\n")
        socketio.run(app, host=host, port=port)
    except ImportError as e:
        click.echo(_c(f"\n  ❌ {e}", "red"), err=True)
        click.echo("  Install with: pip install flask flask-socketio", err=True)
        sys.exit(1)


@cli.command("list-services")
def list_services():
    """List all supported AWS services."""
    services = {
        "s3": "Bucket permissions, encryption, versioning, logging",
        "iam": "Users, root account, password policy, access keys, roles",
        "ec2": "Security groups, open ports, default SG",
        "rds": "Public access, encryption, backup retention",
        "vpc": "Flow logs, default VPC, network ACLs",
        "cloudtrail": "Logging status, validation, encryption",
        "eks": "Cluster endpoint, logging, secrets encryption, version",
        "secretsmanager": "Rotation policies, unused secrets, resource policies",
    }
    click.echo("\n  Supported services (v2.0):\n")
    for svc, desc in services.items():
        click.echo(f"  {_c(svc, 'cyan'):<22} {desc}")
    click.echo("")


if __name__ == "__main__":
    cli()
