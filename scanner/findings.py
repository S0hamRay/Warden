"""Finding dataclass, severity levels, and JSON serialization."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
        }
        return order[self] < order[other]


@dataclass
class Finding:
    id: str
    module: str
    severity: Severity
    resource: str
    title: str
    description: str
    evidence: Any = field(default_factory=dict)
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


def count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


def has_critical(findings: list[Finding]) -> bool:
    return any(f.severity == Severity.CRITICAL for f in findings)
