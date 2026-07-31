"""Asset graph node types and node dataclass."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class NodeType(str, Enum):
    IAM_USER = "IAM_USER"
    IAM_ROLE = "IAM_ROLE"
    IAM_POLICY = "IAM_POLICY"
    EC2_INSTANCE = "EC2_INSTANCE"
    LAMBDA = "LAMBDA"
    ECS_TASK = "ECS_TASK"
    EKS_CLUSTER = "EKS_CLUSTER"
    S3_BUCKET = "S3_BUCKET"
    SECURITY_GROUP = "SECURITY_GROUP"
    VPC = "VPC"
    INTERNET = "INTERNET"
    METADATA_SERVICE = "METADATA_SERVICE"
    METADATA_CREDENTIALS = "METADATA_CREDENTIALS"
    DOCKER_HOST = "DOCKER_HOST"
    KUBERNETES_NAMESPACE = "KUBERNETES_NAMESPACE"
    APPLICATION = "APPLICATION"
    CONTAINER = "CONTAINER"

    def __str__(self) -> str:
        return self.value


# Assets considered valuable terminals for attack-path search.
SENSITIVE_NODE_TYPES = frozenset(
    {
        NodeType.S3_BUCKET,
        NodeType.IAM_ROLE,
        NodeType.IAM_USER,
        NodeType.DOCKER_HOST,
        NodeType.METADATA_CREDENTIALS,
        NodeType.EKS_CLUSTER,
        NodeType.LAMBDA,
    }
)


@dataclass
class AssetNode:
    id: str
    type: NodeType
    name: str
    arn: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "name": self.name,
            "arn": self.arn,
            "attributes": self.attributes,
        }
