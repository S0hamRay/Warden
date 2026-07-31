"""
Attack-path engine: correlate findings → build graph → apply rules → search paths.

Scanner modules remain unaware of this subsystem; they only emit Findings.
"""

from __future__ import annotations

import heapq
import logging
from collections import deque
from typing import Sequence

from scanner.attack_graph.attack_path import AttackPath
from scanner.attack_graph.edges import Edge
from scanner.attack_graph.graph import AssetGraph
from scanner.attack_graph.nodes import (
    SENSITIVE_NODE_TYPES,
    AssetNode,
    NodeType,
)
from scanner.attack_graph.rules import DEFAULT_RULES, AttackRule, RuleContext
from scanner.attack_graph.scoring import score_path
from scanner.findings import Finding

logger = logging.getLogger("warden.attack_graph")

INTERNET_ID = "internet"
IMDS_ID = "imds"


class AttackGraphEngine:
    def __init__(self, rules: Sequence[AttackRule] | None = None) -> None:
        self.rules = list(rules) if rules is not None else list(DEFAULT_RULES)
        self.graph = AssetGraph()

    def build(self, findings: list[Finding]) -> AssetGraph:
        self.graph = AssetGraph()
        self._seed_anchors()
        ctx = RuleContext(
            graph=self.graph,
            findings=findings,
            internet_id=INTERNET_ID,
            imds_id=IMDS_ID,
        )
        for rule in self.rules:
            if not rule.applicable(ctx):
                continue
            try:
                edges = rule.apply(ctx)
            except Exception:
                logger.exception("Attack rule %s failed", rule.name)
                continue
            for edge in edges:
                if self.graph.get_node(edge.source) is None:
                    continue
                if self.graph.get_node(edge.target) is None:
                    continue
                self.graph.add_edge(edge)
            logger.info(
                "Rule %s applied (%d edge(s))", rule.name, len(edges)
            )
        return self.graph

    def _seed_anchors(self) -> None:
        self.graph.add_node(
            AssetNode(
                id=INTERNET_ID,
                type=NodeType.INTERNET,
                name="Internet",
                attributes={"anchor": True},
            )
        )
        self.graph.add_node(
            AssetNode(
                id=IMDS_ID,
                type=NodeType.METADATA_SERVICE,
                name="IMDS (169.254.169.254)",
                attributes={"anchor": True},
            )
        )

    def find_paths(
        self,
        findings: list[Finding],
        *,
        method: str = "bfs",
        max_paths: int = 50,
        max_depth: int = 10,
    ) -> list[AttackPath]:
        if not self.graph.nodes():
            self.build(findings)

        targets = [
            n.id
            for n in self.graph.nodes()
            if n.type in SENSITIVE_NODE_TYPES and n.id != INTERNET_ID
        ]
        if INTERNET_ID not in {n.id for n in self.graph.nodes()}:
            return []

        raw_paths: list[list[str]]
        if method == "dfs":
            raw_paths = self._dfs_paths(INTERNET_ID, targets, max_depth, max_paths)
        elif method in {"dijkstra", "shortest", "a_star", "astar"}:
            raw_paths = self._shortest_paths(INTERNET_ID, targets, max_paths)
        else:
            raw_paths = self._bfs_paths(INTERNET_ID, targets, max_depth, max_paths)

        attack_paths = [
            self._to_attack_path(node_ids, findings) for node_ids in raw_paths
        ]
        attack_paths.sort(key=lambda p: (-p.score, p.severity, len(p.nodes)))
        return attack_paths

    def analyze(
        self,
        findings: list[Finding],
        *,
        method: str = "bfs",
        max_paths: int = 50,
    ) -> tuple[AssetGraph, list[AttackPath]]:
        self.build(findings)
        paths = self.find_paths(
            findings, method=method, max_paths=max_paths
        )
        return self.graph, paths

    def _bfs_paths(
        self,
        start: str,
        targets: Sequence[str],
        max_depth: int,
        max_paths: int,
    ) -> list[list[str]]:
        target_set = set(targets)
        paths: list[list[str]] = []
        queue: deque[list[str]] = deque([[start]])
        while queue and len(paths) < max_paths:
            path = queue.popleft()
            node = path[-1]
            if len(path) > 1 and node in target_set:
                paths.append(path)
                # continue exploring alternate routes, but don't expand past target
                # if we want all paths through targets, still expand carefully
            if len(path) > max_depth:
                continue
            for neighbor, _edge in self.graph.neighbors(node):
                if neighbor.id in path:
                    continue
                queue.append(path + [neighbor.id])
        return paths

    def _dfs_paths(
        self,
        start: str,
        targets: Sequence[str],
        max_depth: int,
        max_paths: int,
    ) -> list[list[str]]:
        target_set = set(targets)
        paths: list[list[str]] = []

        def dfs(path: list[str]) -> None:
            if len(paths) >= max_paths:
                return
            node = path[-1]
            if len(path) > 1 and node in target_set:
                paths.append(list(path))
            if len(path) > max_depth:
                return
            for neighbor, _edge in self.graph.neighbors(node):
                if neighbor.id in path:
                    continue
                path.append(neighbor.id)
                dfs(path)
                path.pop()

        dfs([start])
        return paths

    def _shortest_paths(
        self,
        start: str,
        targets: Sequence[str],
        max_paths: int,
    ) -> list[list[str]]:
        """Dijkstra from Internet to each sensitive target; return unique paths."""
        paths: list[list[str]] = []
        seen: set[tuple[str, ...]] = set()
        for target in targets:
            path = self._dijkstra(start, target)
            if not path:
                continue
            key = tuple(path)
            if key in seen:
                continue
            seen.add(key)
            paths.append(path)
            if len(paths) >= max_paths:
                break
        return paths

    def _dijkstra(self, start: str, goal: str) -> list[str] | None:
        pq: list[tuple[float, str]] = [(0.0, start)]
        dist = {start: 0.0}
        prev: dict[str, tuple[str, Edge] | None] = {start: None}
        while pq:
            cost, node = heapq.heappop(pq)
            if node == goal:
                break
            if cost > dist.get(node, float("inf")):
                continue
            for neighbor, edge in self.graph.neighbors(node):
                new_cost = cost + float(edge.weight)
                if new_cost < dist.get(neighbor.id, float("inf")):
                    dist[neighbor.id] = new_cost
                    prev[neighbor.id] = (node, edge)
                    heapq.heappush(pq, (new_cost, neighbor.id))
        if goal not in prev:
            return None
        path = [goal]
        cur = goal
        while cur != start:
            parent = prev.get(cur)
            if parent is None:
                return None
            cur = parent[0]
            path.append(cur)
        path.reverse()
        return path

    def _edges_for_path(self, node_ids: list[str]) -> list[Edge]:
        edges: list[Edge] = []
        for src, dst in zip(node_ids, node_ids[1:]):
            chosen: Edge | None = None
            for edge in self.graph.outgoing(src):
                if edge.target == dst:
                    if chosen is None or edge.weight < chosen.weight:
                        chosen = edge
            if chosen:
                edges.append(chosen)
        return edges

    def _related_findings(
        self, nodes: list[AssetNode], findings: list[Finding]
    ) -> list[Finding]:
        resources: set[str] = set()
        for node in nodes:
            if node.arn:
                resources.add(node.arn)
            resources.add(node.name)
            resources.add(node.id)
            for key in ("instance_id",):
                if key in node.attributes:
                    resources.add(str(node.attributes[key]))

        related: list[Finding] = []
        for finding in findings:
            if finding.resource in resources:
                related.append(finding)
                continue
            # Match s3 arns / role arns loosely
            for res in resources:
                if res and (res in finding.resource or finding.resource in res):
                    related.append(finding)
                    break
            else:
                # Type-based correlation for chain context
                if (
                    any(n.type == NodeType.METADATA_SERVICE for n in nodes)
                    and finding.id.startswith("SSRF-")
                ):
                    related.append(finding)
                elif (
                    any(n.type == NodeType.DOCKER_HOST for n in nodes)
                    and finding.id.startswith("CONTAINER-DOCKER")
                ):
                    related.append(finding)
        # Deduplicate preserving order
        seen: set[tuple[str, str]] = set()
        unique: list[Finding] = []
        for f in related:
            key = (f.id, f.resource)
            if key in seen:
                continue
            seen.add(key)
            unique.append(f)
        return unique

    def _to_attack_path(
        self, node_ids: list[str], findings: list[Finding]
    ) -> AttackPath:
        nodes = [self.graph.get_node(i) for i in node_ids]
        nodes_f = [n for n in nodes if n is not None]
        edges = self._edges_for_path(node_ids)
        related = self._related_findings(nodes_f, findings)
        score, severity, components = score_path(
            findings=related,
            node_types=[n.type.value for n in nodes_f],
            relationships=[e.relationship.value for e in edges],
            descriptions=[e.description for e in edges],
        )
        chain = " → ".join(n.name for n in nodes_f)
        description = (
            f"Attack path from Internet to {nodes_f[-1].name}: {chain}"
            if nodes_f
            else "Empty path"
        )
        impact = _business_impact(nodes_f, edges)
        recs = _recommendations(related, edges)
        return AttackPath(
            nodes=nodes_f,
            edges=edges,
            score=score,
            severity=severity,
            description=description,
            business_impact=impact,
            recommendations=recs,
            related_findings=related,
            score_components=components,
        )


def _business_impact(nodes: list[AssetNode], edges: list[Edge]) -> str:
    types = {n.type for n in nodes}
    if NodeType.IAM_ROLE in types and any(
        n.attributes.get("privileged") for n in nodes
    ):
        return "Attacker can obtain administrative AWS credentials and escalate privileges."
    if NodeType.METADATA_CREDENTIALS in types and NodeType.S3_BUCKET in types:
        return (
            "Attacker can steal instance credentials via IMDS and access sensitive S3 data."
        )
    if NodeType.S3_BUCKET in types and NodeType.INTERNET in types:
        return "Attacker can read data from an Internet-exposed S3 bucket."
    if NodeType.DOCKER_HOST in types:
        return "Attacker can control the Docker host and escape to the underlying system."
    if NodeType.METADATA_CREDENTIALS in types:
        return "Attacker can obtain temporary AWS credentials from instance metadata."
    if edges:
        return edges[-1].description or "Attacker can move laterally through misconfigurations."
    return "Potential multi-step compromise of cloud assets."


def _recommendations(findings: list[Finding], edges: list[Edge]) -> list[str]:
    recs: list[str] = []
    for finding in findings:
        if finding.remediation:
            # First sentence / line only for brevity
            line = finding.remediation.strip().split("\n")[0].strip()
            if line and line not in recs:
                recs.append(line)
    rule_recs = {
        "public_ec2_imdsv1": "Enforce IMDSv2 (HttpTokens=required) on all instances",
        "passrole_priv_esc": "Remove iam:PassRole or constrain PassRole resource ARNs",
        "public_bucket": "Enable S3 Block Public Access and remove public ACL/policy",
        "docker_socket_exposed": "Bind Docker to a unix socket only; never expose TCP 2375/2376",
        "container_escape_root_socket": "Run containers as non-root and do not mount docker.sock",
    }
    for edge in edges:
        tip = rule_recs.get(edge.rule)
        if tip and tip not in recs:
            recs.append(tip)
    return recs[:8]


def render_dot_png(dot_source: str, dot_path: str, png_path: str) -> bool:
    """Write DOT and optionally render PNG via system Graphviz `dot`."""
    from pathlib import Path
    import subprocess

    Path(dot_path).write_text(dot_source, encoding="utf-8")
    try:
        result = subprocess.run(
            ["dot", "-Tpng", dot_path, "-o", png_path],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("Graphviz render skipped: %s", exc)
        return False
