"""Report generator — JSON, HTML (with D3.js attack graph), and CSV."""
import csv
import json
import os
from typing import Dict, Any

from jinja2 import Environment, FileSystemLoader

from src.utils.exceptions import ReportGenerationError
from src.utils.logger import get_logger

logger = get_logger(__name__)
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")


class ReportGenerator:
    def __init__(self, report_data: Dict[str, Any]):
        self.data = report_data
        self.findings = report_data.get("findings", [])

    def generate(self, output_path: str, fmt: str = "html") -> str:
        fmt = fmt.lower()
        generators = {"html": self._html, "json": self._json, "csv": self._csv}
        if fmt not in generators:
            raise ReportGenerationError(f"Unsupported format: '{fmt}'")
        generators[fmt](output_path)
        logger.info(f"Report written to: {output_path}")
        return output_path

    def _html(self, path: str):
        env = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=True)
        template = env.get_template("html_report.j2")
        html = template.render(data=self.data)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def _json(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, default=str)

    def _csv(self, path: str):
        fieldnames = [
            "id", "risk_score", "severity", "service", "resource", "resource_type",
            "issue", "cis_control", "nist_control", "pci_control",
            "region", "remediation", "remediation_cli",
        ]
        priority = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(
            self.findings, key=lambda x: (
                priority.get(x.get("severity", "LOW"), 99),
                -(x.get("risk_score") or 0)
            )
        )
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(sorted_findings)
