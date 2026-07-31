"""Directed relationship edges for the asset graph."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Relationship(str, Enum):
    ATTACHED_TO = "ATTACHED_TO"
    ASSUMES = "ASSUMES"
    CAN_ASSUME = "CAN_ASSUME"
    CAN_PASS_ROLE = "CAN_PASS_ROLE"
    CAN_READ = "CAN_READ"
    CAN_WRITE = "CAN_WRITE"
    CAN_EXECUTE = "CAN_EXECUTE"
    HOSTS = "HOSTS"
    CONNECTED_TO = "CONNECTED_TO"
    RUNS = "RUNS"
    HAS_POLICY = "HAS_POLICY"
    EXPOSES = "EXPOSES"
    CAN_REACH = "CAN_REACH"
    USES_ROLE = "USES_ROLE"
    COMPROMISES = "COMPROMISES"
    ESCALATES_TO = "ESCALATES_TO"
    ESCAPES_TO = "ESCAPES_TO"

    def __str__(self) -> str:
        return self.value


@dataclass
class Edge:
    source: str
    target: str
    relationship: Relationship
    weight: float = 1.0
    description: str = ""
    rule: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return f"{self.source}|{self.relationship.value}|{self.target}|{self.rule}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "relationship": self.relationship.value,
            "weight": self.weight,
            "description": self.description,
            "rule": self.rule,
            "attributes": self.attributes,
        }
