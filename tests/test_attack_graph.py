"""Tests for attack-graph correlation, search, scoring, and reporting."""

from __future__ import annotations

import json
from pathlib import Path

from scanner.attack_graph import AttackGraphEngine
from scanner.attack_graph.nodes import NodeType
from scanner.attack_graph.scoring import score_path, score_to_severity
from scanner.findings import Finding, Severity
from scanner.remediation import get_remediation
from reports.report_generator import generate_reports


def _finding(
    fid: str,
    resource: str,
    severity: Severity = Severity.CRITICAL,
    module: str = "test",
) -> Finding:
    return Finding(
        id=fid,
        module=module,
        severity=severity,
        resource=resource,
        title=fid,
        description=f"{fid} on {resource}",
        remediation=get_remediation(fid),
    )


def test_public_bucket_path():
    findings = [
        _finding("S3-PUBLIC-ACL", "arn:aws:s3:::evil-bucket", module="s3"),
    ]
    engine = AttackGraphEngine()
    graph, paths = engine.analyze(findings)
    assert graph.get_node("internet") is not None
    assert any(n.type == NodeType.S3_BUCKET for n in graph.nodes())
    assert paths
    assert any("evil-bucket" in p.chain_labels() for p in paths)
    assert any(p.node_ids[0] == "internet" for p in paths)


def test_imds_passrole_s3_chain():
    findings = [
        _finding("SSRF-IMDSV1-ALLOWED", "i-abc123", module="ssrf"),
        _finding("SSRF-STATIC-TAINT", "app.py:10", module="ssrf", severity=Severity.HIGH),
        _finding("NET-SG-OPEN-ADMIN", "sg-open", module="network", severity=Severity.HIGH),
        _finding(
            "IAM-PRIV-ESC-PASSROLE",
            "arn:aws:iam::123456789012:role/AppRole",
            module="iam",
        ),
        _finding("IAM-WILDCARD-ACTION", "arn:aws:iam::123456789012:role/AppRole", module="iam"),
        _finding("S3-PUBLIC-POLICY", "arn:aws:s3:::prod-data", module="s3"),
    ]
    engine = AttackGraphEngine()
    _graph, paths = engine.analyze(findings, method="bfs")
    assert paths
    # Expect a path that reaches credentials or a role / bucket from Internet
    assert any(
        NodeType.METADATA_CREDENTIALS in {n.type for n in p.nodes}
        or NodeType.IAM_ROLE in {n.type for n in p.nodes}
        or NodeType.S3_BUCKET in {n.type for n in p.nodes}
        for p in paths
    )
    # Multi-hop IMDS chain should exist
    imds_paths = [
        p
        for p in paths
        if any(n.type == NodeType.METADATA_SERVICE for n in p.nodes)
        or any(n.type == NodeType.METADATA_CREDENTIALS for n in p.nodes)
    ]
    assert imds_paths
    assert max(p.score for p in paths) >= 26


def test_docker_socket_and_container_escape():
    findings = [
        _finding(
            "CONTAINER-DOCKER-SOCKET-EXPOSED",
            "tcp://0.0.0.0:2375",
            module="container",
        ),
        _finding(
            "CONTAINER-RUN-AS-ROOT",
            "arn:aws:ecs:us-east-1:123:task-definition/web:1/web",
            module="container",
            severity=Severity.MEDIUM,
        ),
    ]
    engine = AttackGraphEngine()
    graph, paths = engine.analyze(findings)
    assert any(n.type == NodeType.DOCKER_HOST for n in graph.nodes())
    assert any(n.type == NodeType.CONTAINER for n in graph.nodes())
    assert paths
    assert any(
        any(e.relationship.value == "ESCAPES_TO" for e in p.edges) for p in paths
    )


def test_dijkstra_and_dfs_methods():
    findings = [
        _finding("S3-PUBLIC-ACL", "arn:aws:s3:::b1", module="s3"),
        _finding("SSRF-IMDSV1-ALLOWED", "i-1", module="ssrf"),
    ]
    engine = AttackGraphEngine()
    engine.build(findings)
    bfs = engine.find_paths(findings, method="bfs")
    dfs = engine.find_paths(findings, method="dfs")
    short = engine.find_paths(findings, method="dijkstra")
    assert bfs and dfs and short
    assert all(p.node_ids[0] == "internet" for p in short)


def test_scoring_bands():
    assert score_to_severity(10) == Severity.LOW
    assert score_to_severity(30) == Severity.MEDIUM
    assert score_to_severity(60) == Severity.HIGH
    assert score_to_severity(90) == Severity.CRITICAL

    findings = [
        _finding("SSRF-IMDSV1-ALLOWED", "i-1", module="ssrf"),
        _finding("IAM-PRIV-ESC-PASSROLE", "role", module="iam"),
        _finding("S3-PUBLIC-ACL", "arn:aws:s3:::x", module="s3"),
    ]
    score, sev, components = score_path(
        findings=findings,
        node_types=["INTERNET", "METADATA_CREDENTIALS", "IAM_ROLE", "S3_BUCKET"],
        relationships=["EXPOSES", "COMPROMISES", "ESCALATES_TO", "CAN_READ"],
        descriptions=["privilege escalation", "metadata"],
    )
    assert components["internet_exposure"] == 1
    assert components["credential_theft"] == 1
    assert components["privilege_escalations"] == 1
    assert components["data_access"] == 1
    assert score >= 76
    assert sev == Severity.CRITICAL


def test_rules_are_extensible_without_engine_edit():
    from scanner.attack_graph.rules import AttackRule, RuleContext
    from scanner.attack_graph.edges import Edge, Relationship
    from scanner.attack_graph.nodes import NodeType

    class TinyRule(AttackRule):
        name = "tiny"
        description = "test"
        required_findings = frozenset({"PUBLIC_BUCKET"})
        attack_cost = 1.0

        def apply(self, ctx: RuleContext) -> list[Edge]:
            ctx.ensure_node(
                "custom:x", NodeType.LAMBDA, name="CustomLambda"
            )
            return [
                Edge(
                    source=ctx.internet_id,
                    target="custom:x",
                    relationship=Relationship.CAN_EXECUTE,
                    weight=1.0,
                    rule=self.name,
                    description="custom",
                )
            ]

    findings = [_finding("S3-PUBLIC-POLICY", "arn:aws:s3:::z", module="s3")]
    engine = AttackGraphEngine(rules=[TinyRule()])
    graph, paths = engine.analyze(findings)
    assert graph.get_node("custom:x") is not None
    assert any("CustomLambda" in p.chain_labels() for p in paths)


def test_report_writes_attack_artifacts(tmp_path: Path):
    findings = [
        _finding("S3-PUBLIC-ACL", "arn:aws:s3:::pub", module="s3"),
        _finding("SSRF-IMDSV1-ALLOWED", "i-xyz", module="ssrf"),
    ]
    payload = generate_reports(findings, output_dir=tmp_path, print_cli=False)
    assert (tmp_path / "report.json").exists()
    assert (tmp_path / "attack_paths.json").exists()
    assert (tmp_path / "attack_graph.dot").exists()
    assert (tmp_path / "report.html").exists()
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "Attack Paths" in html
    data = json.loads((tmp_path / "attack_paths.json").read_text(encoding="utf-8"))
    assert data["count"] == payload["attack_path_count"]
    assert data["count"] >= 1
    dot = (tmp_path / "attack_graph.dot").read_text(encoding="utf-8")
    assert "digraph WardenAttackGraph" in dot
