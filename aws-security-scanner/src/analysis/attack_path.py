"""
Attack Path Analyzer
====================
Models the AWS environment as a directed graph (NetworkX DiGraph) where:
  - Nodes  = AWS resources (buckets, IAM roles, EC2 instances, RDS, etc.)
  - Edges  = possible lateral movement or privilege-escalation transitions
    derived from misconfiguration relationships detected by the auditors.

The analyzer finds all simple paths from "public entry-point" nodes to
"sensitive target" nodes and ranks them by exploitability.
"""
from __future__ import annotations

import json
from typing import Dict, List, Any, Optional

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False

from src.utils.logger import get_logger

logger = get_logger(__name__)

# ── Attack transition patterns ──────────────────────────────────────────────
# These describe which misconfiguration issues create edges between resources.
ATTACK_TRANSITIONS = [
    {
        "trigger_keywords": ["public bucket acl", "public access block", "bucket policy allows public",
                              "grants read to allusers", "grants write to allusers",
                              "bucket acl grants", "publicly accessible", "public s3"],
        "attack_type": "credential_exposure",
        "edge_description": "Public S3 bucket may expose credentials / sensitive data to attackers",
        "target_type": "IAM",
    },
    {
        "trigger_keywords": ["administratoraccess", "poweruseraccess", "overly permissive policy"],
        "attack_type": "privilege_escalation",
        "edge_description": "Over-privileged IAM role/user can control all EC2 instances",
        "target_type": "EC2",
    },
    {
        "trigger_keywords": ["ssh", "port 22", "rdp", "port 3389"],
        "attack_type": "remote_access",
        "edge_description": "Open remote-access port exposes instance to brute-force / exploitation",
        "target_type": "EC2",
    },
    {
        "trigger_keywords": ["publicly accessible", "rds"],
        "attack_type": "database_exposure",
        "edge_description": "Publicly accessible RDS instance reachable from the internet",
        "target_type": "RDS",
    },
    {
        "trigger_keywords": ["no mfa", "mfa not enabled"],
        "attack_type": "account_takeover",
        "edge_description": "Credential without MFA can be taken over via phishing/credential stuffing",
        "target_type": "IAM",
    },
    {
        "trigger_keywords": ["cloudtrail", "not actively logging", "no cloudtrail"],
        "attack_type": "detection_evasion",
        "edge_description": "No audit trail — attacker activity goes undetected",
        "target_type": "ANY",
    },
]

# Resource types considered sensitive targets
SENSITIVE_TYPES = {"RDS", "EC2", "IAM", "EKS", "SecretsManager"}
# Resource types that represent public entry points
PUBLIC_ENTRY_TYPES = {"S3"}


class AttackPathAnalyzer:
    """
    Builds a directed resource graph and identifies exploitable attack chains.

    Usage:
        analyzer = AttackPathAnalyzer()
        analyzer.build_resource_graph(findings, inventory)
        paths = analyzer.find_attack_paths()
        graph_json = analyzer.export_graph_data()
    """

    def __init__(self):
        if not HAS_NETWORKX:
            logger.warning(
                "networkx is not installed — attack path analysis will be simulated. "
                "Install with: pip install networkx"
            )
        self.graph = nx.DiGraph() if HAS_NETWORKX else None
        self._attack_paths: List[Dict] = []

    # ── Graph construction ────────────────────────────────────────────────

    def build_resource_graph(self, findings: List[Dict], inventory: Dict) -> None:
        """
        Populate the graph from auditor findings and resource inventory.

        Args:
            findings:  All scanner findings (may mutate: adds 'part_of_attack_chain').
            inventory: Dict with keys:
                - resources: list of {id, type, region, account_id}
                - iam_roles: list of {arn, assumable_by_external}
                - s3_objects: {bucket_id: [object_key, ...]}
        """
        if not HAS_NETWORKX:
            return

        # Add all known resources as nodes
        for resource in inventory.get("resources", []):
            is_public = resource.get("type") in PUBLIC_ENTRY_TYPES
            is_sensitive = resource.get("type") in SENSITIVE_TYPES
            self.graph.add_node(
                resource["id"],
                type=resource.get("type", "Unknown"),
                region=resource.get("region", "unknown"),
                account=resource.get("account_id", "unknown"),
                public_exposure=is_public,
                sensitive=is_sensitive,
                label=resource.get("id", "")[:30],
            )

        # Add edges based on misconfiguration relationships
        for finding in findings:
            self._add_attack_edges(finding, inventory)

    def _add_attack_edges(self, finding: Dict, inventory: Dict) -> None:
        """Add directed edges based on which misconfiguration pattern matches."""
        issue_lower = finding.get("issue", "").lower()
        resource_id = finding.get("resource", "")
        svc = finding.get("service", "Unknown")

        # Ensure source node exists
        if resource_id not in self.graph:
            self.graph.add_node(
                resource_id,
                type=svc,
                region=finding.get("region", "unknown"),
                account="unknown",
                public_exposure=finding.get("severity") == "CRITICAL",
                sensitive=svc in SENSITIVE_TYPES,
                label=resource_id[:30],
            )

        for transition in ATTACK_TRANSITIONS:
            if not any(kw in issue_lower for kw in transition["trigger_keywords"]):
                continue

            target_type = transition["target_type"]

            # For credential_exposure: only add edge if bucket has known cred files
            # (if object list is absent, we conservatively add the edge anyway)
            if transition["attack_type"] == "credential_exposure":
                s3_objects = inventory.get("s3_objects", {}).get(resource_id, None)
                if s3_objects is not None:
                    cred_pats = [".aws", "credentials", ".env", "config", "secret", "key"]
                    if not any(any(p in obj.lower() for p in cred_pats) for obj in s3_objects):
                        break

            # Build edges to matching target resources
            targets = [
                n for n, d in self.graph.nodes(data=True)
                if d.get("type") == target_type or target_type == "ANY"
            ]
            if target_type == "IAM":
                inv_roles = [r["arn"] for r in inventory.get("iam_roles", [])]
                if inv_roles:
                    targets = inv_roles
                for t in targets:
                    if t not in self.graph:
                        self.graph.add_node(t, type="IAM", public_exposure=False, sensitive=True, label=t[:30], region="global", account="unknown")

            for target in targets:
                if target == resource_id:
                    continue
                if not self.graph.has_edge(resource_id, target):
                    self.graph.add_edge(
                        resource_id,
                        target,
                        attack_type=transition["attack_type"],
                        description=transition["edge_description"],
                        finding_id=finding.get("id", ""),
                        severity=finding.get("severity", "MEDIUM"),
                    )
            break  # Only first matching transition per finding

    # ── Path discovery ────────────────────────────────────────────────────

    def find_attack_paths(self, max_depth: int = 6) -> List[Dict]:
        """
        Find all simple paths from public entry-points to sensitive targets.

        Returns paths sorted by risk_score descending.
        """
        if not HAS_NETWORKX or not self.graph:
            return self._simulated_paths()

        entry_points = [
            n for n, d in self.graph.nodes(data=True)
            if d.get("public_exposure")
        ]
        sensitive_targets = [
            n for n, d in self.graph.nodes(data=True)
            if d.get("sensitive")
        ]

        paths = []
        for source in entry_points:
            for target in sensitive_targets:
                if source == target:
                    continue
                try:
                    simple_paths = list(
                        nx.all_simple_paths(self.graph, source, target, cutoff=max_depth)
                    )
                    for path in simple_paths:
                        paths.append({
                            "id": f"path-{len(paths)+1:03d}",
                            "entry_point": source,
                            "target": target,
                            "path": path,
                            "length": len(path),
                            "attack_steps": self._describe_path(path),
                            "risk_score": self._score_path(path),
                            "attack_types": self._path_attack_types(path),
                        })
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue

        self._attack_paths = sorted(paths, key=lambda p: p["risk_score"], reverse=True)
        return self._attack_paths

    def _describe_path(self, path: List[str]) -> List[str]:
        steps = []
        for i in range(len(path) - 1):
            edge_data = self.graph.edges.get((path[i], path[i + 1]), {})
            desc = edge_data.get("description", "Lateral movement to next resource")
            steps.append(f"Step {i+1}: {desc} ({path[i]} → {path[i+1]})")
        return steps

    def _path_attack_types(self, path: List[str]) -> List[str]:
        types = []
        for i in range(len(path) - 1):
            t = self.graph.edges.get((path[i], path[i + 1]), {}).get("attack_type")
            if t and t not in types:
                types.append(t)
        return types

    def _score_path(self, path: List[str]) -> float:
        """Shorter paths = easier to exploit = higher risk."""
        base = 10.0 - (len(path) * 0.8)

        # Bonus for admin privilege escalation in path
        for i in range(len(path) - 1):
            edge = self.graph.edges.get((path[i], path[i + 1]), {})
            if edge.get("attack_type") == "privilege_escalation":
                base += 1.5
            if edge.get("severity") == "CRITICAL":
                base += 0.5

        return min(round(base, 1), 10.0)

    def _simulated_paths(self) -> List[Dict]:
        """Fallback when networkx is not installed — returns empty list."""
        logger.info("Attack path analysis skipped (networkx not installed).")
        return []

    # ── Graph export ──────────────────────────────────────────────────────

    def export_graph_data(self) -> Dict:
        """
        Export the graph as D3.js-compatible JSON for the HTML report.

        Returns:
            {"nodes": [...], "links": [...], "attack_paths": [...]}
        """
        if not HAS_NETWORKX or not self.graph:
            return {"nodes": [], "links": [], "attack_paths": []}

        nodes = []
        for node_id, attrs in self.graph.nodes(data=True):
            nodes.append({
                "id": node_id,
                "label": attrs.get("label", node_id[:20]),
                "type": attrs.get("type", "Unknown"),
                "region": attrs.get("region", "unknown"),
                "account": attrs.get("account", "unknown"),
                "public_exposure": attrs.get("public_exposure", False),
                "sensitive": attrs.get("sensitive", False),
            })

        # Collect attack-path node IDs for highlighting
        path_node_ids = set()
        for path in self._attack_paths:
            path_node_ids.update(path.get("path", []))

        links = []
        for src, tgt, attrs in self.graph.edges(data=True):
            links.append({
                "source": src,
                "target": tgt,
                "attack_type": attrs.get("attack_type", ""),
                "description": attrs.get("description", ""),
                "severity": attrs.get("severity", "MEDIUM"),
                "is_attack_path": src in path_node_ids and tgt in path_node_ids,
            })

        return {
            "nodes": nodes,
            "links": links,
            "attack_paths": self._attack_paths[:10],  # Top 10 for UI
            "stats": {
                "total_nodes": len(nodes),
                "total_edges": len(links),
                "attack_path_count": len(self._attack_paths),
                "entry_points": [n["id"] for n in nodes if n["public_exposure"]],
                "sensitive_targets": [n["id"] for n in nodes if n["sensitive"]],
            },
        }

    def get_stats(self) -> Dict:
        """Summary statistics about the attack graph."""
        if not HAS_NETWORKX or not self.graph:
            return {"nodes": 0, "edges": 0, "attack_paths": 0}
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "attack_paths": len(self._attack_paths),
            "entry_points": sum(1 for _, d in self.graph.nodes(data=True) if d.get("public_exposure")),
            "sensitive_targets": sum(1 for _, d in self.graph.nodes(data=True) if d.get("sensitive")),
        }
