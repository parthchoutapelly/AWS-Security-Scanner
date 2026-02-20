"""
Compliance Mapper — maps findings to CIS, NIST CSF, and PCI-DSS frameworks
and calculates per-framework compliance scores.
"""
import json
import os
from typing import List, Dict, Any

FRAMEWORKS_DIR = os.path.join(os.path.dirname(__file__), "frameworks")

FRAMEWORK_FILES = {
    "cis": "cis_aws_v1_5.json",
    "nist": "nist_csf.json",
    "pci": "pci_dss.json",
}


class FrameworkMapper:
    """Handles a single compliance framework file."""

    def __init__(self, framework_key: str):
        path = os.path.join(FRAMEWORKS_DIR, FRAMEWORK_FILES[framework_key])
        with open(path) as f:
            data = json.load(f)

        self.key = framework_key
        self.name = f"{data['framework']} v{data['version']}"
        self.controls: Dict[str, Dict] = data["controls"]
        self._cis_map: Dict[str, List[str]] = data.get(
            f"cis_to_{framework_key}", {}
        ) if framework_key != "cis" else {}

    def map_findings(self, findings: List[Dict]) -> Dict[str, Any]:
        failed_control_ids: set = set()

        for finding in findings:
            cis_id = finding.get("cis_control", "")
            if not cis_id:
                continue

            if self.key == "cis":
                if cis_id in self.controls:
                    failed_control_ids.add(cis_id)
            else:
                for ctrl_id in self._cis_map.get(cis_id, []):
                    if ctrl_id in self.controls:
                        failed_control_ids.add(ctrl_id)
                        key_name = f"{self.key}_control"
                        if key_name not in finding:
                            finding[key_name] = ctrl_id

        failed = []
        passed = []
        for ctrl_id, meta in self.controls.items():
            entry = {
                "id": ctrl_id,
                "title": meta.get("title", ctrl_id),
                "section": meta.get("section") or meta.get("function") or meta.get("requirement", ""),
            }
            (failed if ctrl_id in failed_control_ids else passed).append(entry)

        total = len(self.controls)
        n_passed = len(passed)
        n_failed = len(failed)
        score = round((n_passed / total) * 100, 1) if total else 0.0

        return {
            "framework": self.name,
            "key": self.key,
            "score": score,
            "controls_total": total,
            "controls_passed": n_passed,
            "controls_failed": n_failed,
            "failed_controls": sorted(failed, key=lambda x: x["id"]),
            "passed_controls": sorted(passed, key=lambda x: x["id"]),
        }


class ComplianceMapper:
    """
    Maps scanner findings against CIS, NIST CSF, and PCI-DSS frameworks.

    Usage:
        mapper = ComplianceMapper()
        result = mapper.map_findings(findings)
    """

    def __init__(self, frameworks: List[str] = None):
        self.frameworks_keys = frameworks or ["cis", "nist", "pci"]
        self._mappers = {k: FrameworkMapper(k) for k in self.frameworks_keys}

    def map_findings(self, findings: List[Dict]) -> Dict[str, Any]:
        results = {}
        for key, mapper in self._mappers.items():
            results[key] = mapper.map_findings(findings)

        primary = results.get("cis") or next(iter(results.values()))

        return {
            "primary_framework": primary["framework"],
            "primary_score": primary["score"],
            "frameworks": results,
            # Backward-compat flat fields
            "failed_controls": primary["failed_controls"],
            "passed_controls": primary["passed_controls"],
            "controls_total": primary["controls_total"],
            "controls_passed": primary["controls_passed"],
            "controls_failed": primary["controls_failed"],
            "score": primary["score"],
            "framework": primary["framework"],
        }

    def get_framework_names(self) -> Dict[str, str]:
        return {k: m.name for k, m in self._mappers.items()}
