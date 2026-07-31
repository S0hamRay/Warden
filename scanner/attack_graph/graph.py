"""Asset graph: nodes + directed weighted edges."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Iterator

from scanner.attack_graph.edges import Edge, Relationship
from scanner.attack_graph.nodes import AssetNode, NodeType


class AssetGraph:
    def __init__(self) -> None:
        self._nodes: dict[str, AssetNode] = {}
        self._edges: dict[str, Edge] = {}
        self._out: dict[str, list[str]] = defaultdict(list)
        self._in: dict[str, list[str]] = defaultdict(list)

    def add_node(self, node: AssetNode) -> AssetNode:
        existing = self._nodes.get(node.id)
        if existing is None:
            self._nodes[node.id] = node
            return node
        # Merge attributes / fill blanks
        if node.arn and not existing.arn:
            existing.arn = node.arn
        if node.name and node.name != existing.name:
            existing.name = node.name
        existing.attributes.update(node.attributes)
        return existing

    def get_node(self, node_id: str) -> AssetNode | None:
        return self._nodes.get(node_id)

    def nodes(self) -> list[AssetNode]:
        return list(self._nodes.values())

    def nodes_of_type(self, *types: NodeType) -> list[AssetNode]:
        wanted = set(types)
        return [n for n in self._nodes.values() if n.type in wanted]

    def add_edge(self, edge: Edge) -> Edge:
        if edge.source not in self._nodes or edge.target not in self._nodes:
            raise KeyError(
                f"Edge endpoints must exist: {edge.source} -> {edge.target}"
            )
        key = edge.id
        if key in self._edges:
            # Keep lower weight (cheaper attack) if duplicate
            if edge.weight < self._edges[key].weight:
                self._edges[key] = edge
            return self._edges[key]
        self._edges[key] = edge
        self._out[edge.source].append(key)
        self._in[edge.target].append(key)
        return edge

    def edges(self) -> list[Edge]:
        return list(self._edges.values())

    def outgoing(self, node_id: str) -> list[Edge]:
        return [self._edges[k] for k in self._out.get(node_id, [])]

    def neighbors(self, node_id: str) -> Iterator[tuple[AssetNode, Edge]]:
        for edge in self.outgoing(node_id):
            target = self._nodes[edge.target]
            yield target, edge

    def has_edge(
        self,
        source: str,
        target: str,
        relationship: Relationship | None = None,
    ) -> bool:
        for edge in self.outgoing(source):
            if edge.target != target:
                continue
            if relationship is None or edge.relationship == relationship:
                return True
        return False

    def to_dict(self) -> dict:
        return {
            "nodes": [n.to_dict() for n in self.nodes()],
            "edges": [e.to_dict() for e in self.edges()],
        }

    def to_dot(self, highlight_paths: Iterable[list[str]] | None = None) -> str:
        """Serialize graph to Graphviz DOT with severity-ish coloring."""
        path_nodes: set[str] = set()
        path_edges: set[tuple[str, str]] = set()
        if highlight_paths:
            for path in highlight_paths:
                path_nodes.update(path)
                for a, b in zip(path, path[1:]):
                    path_edges.add((a, b))

        type_color = {
            NodeType.INTERNET: "#e85d5d",
            NodeType.METADATA_SERVICE: "#e6a23c",
            NodeType.METADATA_CREDENTIALS: "#e85d5d",
            NodeType.IAM_ROLE: "#e6a23c",
            NodeType.S3_BUCKET: "#3db8c9",
            NodeType.EC2_INSTANCE: "#6bbf8a",
            NodeType.DOCKER_HOST: "#e85d5d",
            NodeType.CONTAINER: "#e6a23c",
            NodeType.SECURITY_GROUP: "#9aa7b8",
            NodeType.APPLICATION: "#3db8c9",
        }

        lines = [
            "digraph WardenAttackGraph {",
            '  rankdir=LR;',
            '  node [shape=box, style="rounded,filled", fontname="Helvetica"];',
            '  edge [fontname="Helvetica", fontsize=10];',
        ]
        for node in self.nodes():
            fill = type_color.get(node.type, "#1a2332")
            fontcolor = "#0f1419" if node.type != NodeType.SECURITY_GROUP else "#e7ecf3"
            if node.type in {
                NodeType.INTERNET,
                NodeType.METADATA_CREDENTIALS,
                NodeType.DOCKER_HOST,
            }:
                fontcolor = "#ffffff"
            penwidth = "2.5" if node.id in path_nodes else "1"
            label = f"{node.name}\\n({node.type.value})"
            lines.append(
                f'  "{node.id}" [label="{_escape(label)}", fillcolor="{fill}", '
                f'fontcolor="{fontcolor}", penwidth={penwidth}];'
            )

        for edge in self.edges():
            color = "#e85d5d" if (edge.source, edge.target) in path_edges else "#9aa7b8"
            penwidth = "2.2" if (edge.source, edge.target) in path_edges else "1"
            label = edge.relationship.value
            lines.append(
                f'  "{edge.source}" -> "{edge.target}" '
                f'[label="{_escape(label)}", color="{color}", penwidth={penwidth}];'
            )
        lines.append("}")
        return "\n".join(lines) + "\n"


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')
