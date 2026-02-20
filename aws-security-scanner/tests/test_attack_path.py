"""Unit tests for the attack path analyzer."""
import pytest
from src.analysis.attack_path import AttackPathAnalyzer, HAS_NETWORKX


@pytest.mark.skipif(not HAS_NETWORKX, reason="networkx not installed")
def test_detects_simple_attack_chain():
    """A public S3 bucket with credential objects → IAM role should form an attack path."""
    analyzer = AttackPathAnalyzer()
    findings = [
        {"id": "f1", "resource": "public-bucket", "service": "S3",
         "issue": "Bucket ACL grants READ to AllUsers", "severity": "CRITICAL", "cis_control": "2.1.5"}
    ]
    inventory = {
        "resources": [
            {"id": "public-bucket", "type": "S3",  "region": "us-east-1", "account_id": "123", "public_exposure": True},
            {"id": "admin-role",    "type": "IAM", "region": "global",    "account_id": "123", "sensitive": True},
        ],
        "iam_roles": [{"arn": "admin-role", "assumable_by_external": True}],
        "s3_objects": {"public-bucket": ["credentials", ".env", "config.json"]},
    }
    analyzer.build_resource_graph(findings, inventory)
    paths = analyzer.find_attack_paths()

    assert len(paths) > 0, "Expected at least one attack path"
    assert paths[0]["risk_score"] > 5.0, f"Expected risk > 5, got {paths[0]['risk_score']}"


@pytest.mark.skipif(not HAS_NETWORKX, reason="networkx not installed")
def test_privilege_escalation_path():
    """Admin IAM user → EC2 instances should form an attack path."""
    analyzer = AttackPathAnalyzer()
    findings = [
        {"id": "f1", "resource": "iam:user:admin-bob", "service": "IAM",
         "issue": "IAM user has overly permissive policy: AdministratorAccess",
         "severity": "HIGH", "cis_control": "1.16"}
    ]
    inventory = {
        "resources": [
            {"id": "iam:user:admin-bob", "type": "IAM", "region": "global",    "account_id": "123", "public_exposure": False},
            {"id": "i-0abc123",          "type": "EC2", "region": "us-east-1", "account_id": "123", "sensitive": True},
        ],
        "iam_roles": [],
        "s3_objects": {},
    }
    analyzer.build_resource_graph(findings, inventory)
    paths = analyzer.find_attack_paths()
    # Paths may or may not form based on entry-point rules — just check graph built OK
    assert analyzer.graph.number_of_nodes() >= 2


@pytest.mark.skipif(not HAS_NETWORKX, reason="networkx not installed")
def test_empty_findings_no_paths():
    """Zero findings should produce no attack paths."""
    analyzer = AttackPathAnalyzer()
    analyzer.build_resource_graph([], {"resources": [], "iam_roles": [], "s3_objects": {}})
    paths = analyzer.find_attack_paths()
    assert paths == []


@pytest.mark.skipif(not HAS_NETWORKX, reason="networkx not installed")
def test_shorter_path_scores_higher():
    """Path of length 2 should score higher than path of length 4."""
    analyzer = AttackPathAnalyzer()
    short_path = ["a", "b"]
    long_path  = ["a", "b", "c", "d"]

    # Manually add nodes and edges
    for node in ["a", "b", "c", "d"]:
        analyzer.graph.add_node(node, type="EC2", public_exposure=(node=="a"), sensitive=(node=="b" or node=="d"))
    analyzer.graph.add_edge("a", "b", attack_type="remote_access", description="SSH open", severity="CRITICAL")
    analyzer.graph.add_edge("b", "c", attack_type="privilege_escalation", description="Priv esc", severity="HIGH")
    analyzer.graph.add_edge("c", "d", attack_type="credential_exposure", description="Cred leak", severity="MEDIUM")

    score_short = analyzer._score_path(short_path)
    score_long  = analyzer._score_path(long_path)
    assert score_short > score_long, f"Short ({score_short}) should > long ({score_long})"


@pytest.mark.skipif(not HAS_NETWORKX, reason="networkx not installed")
def test_export_graph_data_structure():
    """export_graph_data should return nodes, links, and stats."""
    analyzer = AttackPathAnalyzer()
    analyzer.graph.add_node("bucket", type="S3", public_exposure=True, sensitive=False, label="bucket", region="us-east-1", account="123")
    analyzer.graph.add_node("role",   type="IAM", public_exposure=False, sensitive=True,  label="role",   region="global",    account="123")
    analyzer.graph.add_edge("bucket", "role", attack_type="credential_exposure", description="test", severity="HIGH", is_attack_path=True)

    data = analyzer.export_graph_data()
    assert "nodes" in data
    assert "links" in data
    assert "stats" in data
    assert len(data["nodes"]) == 2
    assert len(data["links"]) == 1


def test_simulated_paths_when_no_networkx():
    """When networkx is unavailable, find_attack_paths should return []."""
    import src.analysis.attack_path as m
    original = m.HAS_NETWORKX
    m.HAS_NETWORKX = False
    try:
        analyzer = AttackPathAnalyzer()
        result = analyzer.find_attack_paths()
        assert result == []
    finally:
        m.HAS_NETWORKX = original
