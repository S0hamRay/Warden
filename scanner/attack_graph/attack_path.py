"""AttackPath representation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from scanner.attack_graph.edges import Edge
from scanner.attack_graph.nodes import AssetNode
from scanner.findings import Finding, Severity


@dataclass
class AttackPath:
    nodes: list[AssetNode]
    edges: list[Edge]
    score: int
    severity: Severity
    description: str
    business_impact: str = ""
    recommendations: list[str] = field(default_factory=list)
    related_findings: list[Finding] = field(default_factory=list)
    score_components: dict[str, int] = field(default_factory=dict)

    @property
    def node_ids(self) -> list[str]:
        return [n.id for n in self.nodes]

    def chain_labels(self) -> list[str]:
        return [n.name for n in self.nodes]

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "score": self.score,
            "severity": self.severity.value,
            "description": self.description,
            "business_impact": self.business_impact,
            "recommendations": self.recommendations,
            "chain": self.chain_labels(),
            "related_findings": [f.to_dict() for f in self.related_findings],
            "score_components": self.score_components,
        }
