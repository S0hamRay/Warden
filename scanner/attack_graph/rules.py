"""
Declarative attack rules.

Rules never live inside the engine — add new rules by subclassing AttackRule
and registering them in DEFAULT_RULES.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Iterable

from scanner.attack_graph.edges import Edge, Relationship
from scanner.attack_graph.nodes import AssetNode, NodeType
from scanner.findings import Finding

if TYPE_CHECKING:
    from scanner.attack_graph.graph import AssetGraph


# Map abstract rule requirements → concrete scanner finding IDs.
FINDING_TYPE_ALIASES: dict[str, frozenset[str]] = {
    "IMDSV1_ENABLED": frozenset({"SSRF-IMDSV1-ALLOWED"}),
    "SSRF": frozenset({"SSRF-STATIC-TAINT"}),
    "PASS_ROLE": frozenset({"IAM-PRIV-ESC-PASSROLE"}),
    "WILDCARD_IAM": frozenset({"IAM-WILDCARD-ACTION", "IAM-WILDCARD-RESOURCE"}),
    "PUBLIC_BUCKET": frozenset({"S3-PUBLIC-ACL", "S3-PUBLIC-POLICY"}),
    "DOCKER_SOCKET_EXPOSED": frozenset({"CONTAINER-DOCKER-SOCKET-EXPOSED"}),
    "RUN_AS_ROOT": frozenset({"CONTAINER-RUN-AS-ROOT"}),
    "OPEN_SG": frozenset({"NET-SG-OPEN-ALL", "NET-SG-OPEN-ADMIN"}),
    "TRUST_WILDCARD": frozenset({"IAM-TRUST-WILDCARD"}),
}


def findings_matching(
    findings: Iterable[Finding], *aliases: str
) -> list[Finding]:
    ids: set[str] = set()
    for alias in aliases:
        ids |= FINDING_TYPE_ALIASES.get(alias, frozenset({alias}))
    return [f for f in findings if f.id in ids]


@dataclass
class RuleContext:
    """Shared state passed into every rule."""

    graph: AssetGraph
    findings: list[Finding]
    internet_id: str = "internet"
    imds_id: str = "imds"

    def findings_of(self, *aliases: str) -> list[Finding]:
        return findings_matching(self.findings, *aliases)

    def ensure_node(
        self,
        node_id: str,
        node_type: NodeType,
        name: str,
        arn: str = "",
        **attributes: Any,
    ) -> AssetNode:
        return self.graph.add_node(
            AssetNode(
                id=node_id,
                type=node_type,
                name=name,
                arn=arn,
                attributes=attributes,
            )
        )


class AttackRule(ABC):
    name: str = "unnamed"
    description: str = ""
    required_findings: frozenset[str] = frozenset()
    attack_cost: float = 1.0
    generated_relationship: Relationship = Relationship.CAN_REACH

    def applicable(self, ctx: RuleContext) -> bool:
        if not self.required_findings:
            return True
        return all(ctx.findings_of(alias) for alias in self.required_findings)

    @abstractmethod
    def apply(self, ctx: RuleContext) -> list[Edge]:
        """Inspect findings/graph and return edges to add."""


class PublicEc2ToImdsRule(AttackRule):
    """Rule 1: Public EC2 + IMDSv1 → Internet → Metadata Service."""

    name = "public_ec2_imdsv1"
    description = (
        "Internet-reachable EC2 with IMDSv1 allows SSRF to steal metadata credentials."
    )
    required_findings = frozenset({"IMDSV1_ENABLED"})
    attack_cost = 1.0
    generated_relationship = Relationship.CAN_REACH

    def apply(self, ctx: RuleContext) -> list[Edge]:
        edges: list[Edge] = []
        imds_findings = ctx.findings_of("IMDSV1_ENABLED")
        open_sg = ctx.findings_of("OPEN_SG")
        ssrf = ctx.findings_of("SSRF")

        # Public exposure: open SG findings, or SSRF static hit implying app exposure.
        is_public = bool(open_sg or ssrf or imds_findings)

        for finding in imds_findings:
            instance_id = finding.resource
            ec2 = ctx.ensure_node(
                f"ec2:{instance_id}",
                NodeType.EC2_INSTANCE,
                name=instance_id,
                arn=instance_id,
                imdsv1=True,
                public=is_public,
            )
            app = ctx.ensure_node(
                f"app:{instance_id}",
                NodeType.APPLICATION,
                name=f"App on {instance_id}",
                hosted_on=instance_id,
            )
            ctx.graph.add_edge(
                Edge(
                    source=ec2.id,
                    target=app.id,
                    relationship=Relationship.HOSTS,
                    weight=0.5,
                    description="EC2 hosts application workload",
                    rule=self.name,
                )
            )
            if ssrf:
                edges.append(
                    Edge(
                        source=app.id,
                        target=ctx.imds_id,
                        relationship=Relationship.CAN_REACH,
                        weight=self.attack_cost,
                        description="SSRF-prone app can reach instance metadata",
                        rule=self.name,
                    )
                )
            else:
                edges.append(
                    Edge(
                        source=ec2.id,
                        target=ctx.imds_id,
                        relationship=Relationship.CAN_REACH,
                        weight=self.attack_cost,
                        description="IMDSv1 reachable without session token",
                        rule=self.name,
                    )
                )

            if is_public:
                edges.append(
                    Edge(
                        source=ctx.internet_id,
                        target=ec2.id,
                        relationship=Relationship.EXPOSES,
                        weight=self.attack_cost,
                        description="EC2 exposed to Internet (open SG and/or SSRF surface)",
                        rule=self.name,
                    )
                )
                edges.append(
                    Edge(
                        source=ctx.internet_id,
                        target=ctx.imds_id,
                        relationship=Relationship.CAN_REACH,
                        weight=self.attack_cost + 0.5,
                        description="Internet → metadata credentials via public EC2 + IMDSv1",
                        rule=self.name,
                    )
                )
        return edges


class MetadataToInstanceRoleRule(AttackRule):
    """Rule 2: Metadata credentials → compromise instance role."""

    name = "metadata_to_instance_role"
    description = "Stolen IMDS credentials assume the EC2 instance profile role."
    required_findings = frozenset({"IMDSV1_ENABLED"})
    attack_cost = 1.0
    generated_relationship = Relationship.COMPROMISES

    def apply(self, ctx: RuleContext) -> list[Edge]:
        edges: list[Edge] = []
        for finding in ctx.findings_of("IMDSV1_ENABLED"):
            instance_id = finding.resource
            creds = ctx.ensure_node(
                f"creds:{instance_id}",
                NodeType.METADATA_CREDENTIALS,
                name=f"Credentials ({instance_id})",
                instance_id=instance_id,
            )
            role = ctx.ensure_node(
                f"role:instance/{instance_id}",
                NodeType.IAM_ROLE,
                name=f"InstanceRole/{instance_id}",
                arn=f"arn:aws:iam::assumed-role/instance/{instance_id}",
                instance_profile=True,
            )
            edges.append(
                Edge(
                    source=ctx.imds_id,
                    target=creds.id,
                    relationship=Relationship.EXPOSES,
                    weight=0.5,
                    description="IMDS returns temporary instance credentials",
                    rule=self.name,
                )
            )
            edges.append(
                Edge(
                    source=creds.id,
                    target=role.id,
                    relationship=Relationship.COMPROMISES,
                    weight=self.attack_cost,
                    description="Metadata credentials compromise the instance role",
                    rule=self.name,
                )
            )
        return edges


class PassRolePrivilegeEscalationRule(AttackRule):
    """Rule 3: PassRole + CreateFunction → privilege escalation."""

    name = "passrole_priv_esc"
    description = (
        "iam:PassRole combined with lambda:CreateFunction enables privilege escalation."
    )
    required_findings = frozenset({"PASS_ROLE"})
    attack_cost = 2.0
    generated_relationship = Relationship.ESCALATES_TO

    def apply(self, ctx: RuleContext) -> list[Edge]:
        edges: list[Edge] = []
        admin = ctx.ensure_node(
            "role:escalated-admin",
            NodeType.IAM_ROLE,
            name="EscalatedAdmin",
            arn="arn:aws:iam::role/EscalatedAdmin",
            privileged=True,
        )
        for finding in ctx.findings_of("PASS_ROLE"):
            role = ctx.ensure_node(
                f"role:{finding.resource}",
                NodeType.IAM_ROLE,
                name=_short_name(finding.resource),
                arn=finding.resource,
                pass_role=True,
            )
            edges.append(
                Edge(
                    source=role.id,
                    target=admin.id,
                    relationship=Relationship.ESCALATES_TO,
                    weight=self.attack_cost,
                    description=self.description,
                    rule=self.name,
                )
            )
            edges.append(
                Edge(
                    source=role.id,
                    target=admin.id,
                    relationship=Relationship.CAN_PASS_ROLE,
                    weight=self.attack_cost,
                    description="Can pass privileged role into new Lambda",
                    rule=self.name,
                )
            )
            # Bridge instance roles / wildcard roles into this principal when present
            for inst_role in ctx.graph.nodes_of_type(NodeType.IAM_ROLE):
                if inst_role.attributes.get("instance_profile"):
                    edges.append(
                        Edge(
                            source=inst_role.id,
                            target=role.id,
                            relationship=Relationship.CAN_ASSUME,
                            weight=1.5,
                            description="Compromised instance role can use PassRole chain",
                            rule=self.name,
                        )
                    )
        # Wildcard admin also escalates
        for finding in ctx.findings_of("WILDCARD_IAM"):
            role = ctx.ensure_node(
                f"role:{finding.resource}",
                NodeType.IAM_ROLE,
                name=_short_name(finding.resource),
                arn=finding.resource,
                wildcard=True,
            )
            edges.append(
                Edge(
                    source=role.id,
                    target=admin.id,
                    relationship=Relationship.ESCALATES_TO,
                    weight=1.0,
                    description="Wildcard IAM policy enables full privilege escalation",
                    rule=self.name,
                )
            )
        return edges


class RoleCanReadBucketRule(AttackRule):
    """Rule 4: Role with s3:GetObject (or wildcard) → bucket."""

    name = "role_can_read_bucket"
    description = "IAM principal can read S3 objects."
    required_findings = frozenset()  # needs role + bucket nodes/findings
    attack_cost = 1.0
    generated_relationship = Relationship.CAN_READ

    def applicable(self, ctx: RuleContext) -> bool:
        roles = ctx.findings_of("PASS_ROLE", "WILDCARD_IAM")
        buckets = ctx.findings_of("PUBLIC_BUCKET") or [
            f for f in ctx.findings if f.id.startswith("S3-")
        ]
        return bool(roles and buckets) or bool(
            ctx.graph.nodes_of_type(NodeType.IAM_ROLE)
            and (
                buckets
                or ctx.graph.nodes_of_type(NodeType.S3_BUCKET)
            )
        )

    def apply(self, ctx: RuleContext) -> list[Edge]:
        edges: list[Edge] = []
        bucket_findings = [
            f for f in ctx.findings if f.module == "s3" or f.id.startswith("S3-")
        ]
        buckets: list[AssetNode] = []
        for finding in bucket_findings:
            arn = finding.resource
            name = arn.split(":")[-1] if arn.startswith("arn:") else arn
            buckets.append(
                ctx.ensure_node(
                    f"s3:{name}",
                    NodeType.S3_BUCKET,
                    name=name,
                    arn=arn if arn.startswith("arn:") else f"arn:aws:s3:::{name}",
                )
            )
        if not buckets:
            return edges

        readable_roles = ctx.findings_of("PASS_ROLE", "WILDCARD_IAM")
        role_nodes: list[AssetNode] = []
        for finding in readable_roles:
            role_nodes.append(
                ctx.ensure_node(
                    f"role:{finding.resource}",
                    NodeType.IAM_ROLE,
                    name=_short_name(finding.resource),
                    arn=finding.resource,
                )
            )
        # Also connect escalated admin + instance roles
        role_nodes.extend(
            n
            for n in ctx.graph.nodes_of_type(NodeType.IAM_ROLE)
            if n.attributes.get("privileged")
            or n.attributes.get("wildcard")
            or n.attributes.get("instance_profile")
            or n.attributes.get("pass_role")
        )

        seen: set[tuple[str, str]] = set()
        for role in role_nodes:
            for bucket in buckets:
                key = (role.id, bucket.id)
                if key in seen:
                    continue
                seen.add(key)
                edges.append(
                    Edge(
                        source=role.id,
                        target=bucket.id,
                        relationship=Relationship.CAN_READ,
                        weight=self.attack_cost,
                        description=f"{role.name} can read {bucket.name}",
                        rule=self.name,
                    )
                )
        return edges


class PublicBucketRule(AttackRule):
    """Rule 5: Public bucket → Internet → Bucket."""

    name = "public_bucket"
    description = "Public S3 bucket is directly reachable from the Internet."
    required_findings = frozenset({"PUBLIC_BUCKET"})
    attack_cost = 1.0
    generated_relationship = Relationship.EXPOSES

    def apply(self, ctx: RuleContext) -> list[Edge]:
        edges: list[Edge] = []
        for finding in ctx.findings_of("PUBLIC_BUCKET"):
            arn = finding.resource
            name = arn.split(":")[-1] if arn.startswith("arn:") else arn
            bucket = ctx.ensure_node(
                f"s3:{name}",
                NodeType.S3_BUCKET,
                name=name,
                arn=arn if arn.startswith("arn:") else f"arn:aws:s3:::{name}",
                public=True,
            )
            edges.append(
                Edge(
                    source=ctx.internet_id,
                    target=bucket.id,
                    relationship=Relationship.EXPOSES,
                    weight=self.attack_cost,
                    description="Public ACL/policy exposes bucket to the Internet",
                    rule=self.name,
                )
            )
            edges.append(
                Edge(
                    source=ctx.internet_id,
                    target=bucket.id,
                    relationship=Relationship.CAN_READ,
                    weight=self.attack_cost,
                    description="Anonymous principal can read bucket objects",
                    rule=self.name,
                )
            )
        return edges


class DockerSocketExposedRule(AttackRule):
    """Rule 6: Docker socket exposed → Internet → Docker Host."""

    name = "docker_socket_exposed"
    description = "Docker API exposed on the network enables full host takeover."
    required_findings = frozenset({"DOCKER_SOCKET_EXPOSED"})
    attack_cost = 1.0
    generated_relationship = Relationship.EXPOSES

    def apply(self, ctx: RuleContext) -> list[Edge]:
        edges: list[Edge] = []
        for finding in ctx.findings_of("DOCKER_SOCKET_EXPOSED"):
            host = ctx.ensure_node(
                f"docker:{finding.resource}",
                NodeType.DOCKER_HOST,
                name=finding.resource,
                arn=finding.resource,
                socket_exposed=True,
            )
            edges.append(
                Edge(
                    source=ctx.internet_id,
                    target=host.id,
                    relationship=Relationship.EXPOSES,
                    weight=self.attack_cost,
                    description="Docker daemon reachable over TCP from the network",
                    rule=self.name,
                )
            )
        return edges


class ContainerEscapeRule(AttackRule):
    """Rule 7: Root container + Docker socket → container escape."""

    name = "container_escape_root_socket"
    description = (
        "Container running as root with Docker socket access can escape to the host."
    )
    required_findings = frozenset({"RUN_AS_ROOT", "DOCKER_SOCKET_EXPOSED"})
    attack_cost = 2.0
    generated_relationship = Relationship.ESCAPES_TO

    def apply(self, ctx: RuleContext) -> list[Edge]:
        edges: list[Edge] = []
        sockets = ctx.findings_of("DOCKER_SOCKET_EXPOSED")
        roots = ctx.findings_of("RUN_AS_ROOT")
        if not sockets or not roots:
            return edges

        for sock in sockets:
            host = ctx.ensure_node(
                f"docker:{sock.resource}",
                NodeType.DOCKER_HOST,
                name=sock.resource,
                arn=sock.resource,
                socket_exposed=True,
            )
            for root in roots:
                container = ctx.ensure_node(
                    f"container:{root.resource}",
                    NodeType.CONTAINER,
                    name=_short_name(root.resource),
                    arn=root.resource,
                    runs_as_root=True,
                )
                edges.append(
                    Edge(
                        source=container.id,
                        target=host.id,
                        relationship=Relationship.ESCAPES_TO,
                        weight=self.attack_cost,
                        description=self.description,
                        rule=self.name,
                    )
                )
                edges.append(
                    Edge(
                        source=ctx.internet_id,
                        target=container.id,
                        relationship=Relationship.CAN_REACH,
                        weight=1.5,
                        description="Attacker reaches root container that mounts Docker socket",
                        rule=self.name,
                    )
                )
        return edges


class OpenSgToInternetRule(AttackRule):
    """Supporting rule: open security groups attach Internet exposure nodes."""

    name = "open_security_group"
    description = "Security group allows ingress from the Internet."
    required_findings = frozenset({"OPEN_SG"})
    attack_cost = 1.0
    generated_relationship = Relationship.EXPOSES

    def apply(self, ctx: RuleContext) -> list[Edge]:
        edges: list[Edge] = []
        for finding in ctx.findings_of("OPEN_SG"):
            sg = ctx.ensure_node(
                f"sg:{finding.resource}",
                NodeType.SECURITY_GROUP,
                name=finding.resource,
                arn=finding.resource,
                open_to_world=True,
            )
            edges.append(
                Edge(
                    source=ctx.internet_id,
                    target=sg.id,
                    relationship=Relationship.EXPOSES,
                    weight=self.attack_cost,
                    description=finding.title,
                    rule=self.name,
                )
            )
            # Link open SG to known EC2 nodes
            for ec2 in ctx.graph.nodes_of_type(NodeType.EC2_INSTANCE):
                edges.append(
                    Edge(
                        source=sg.id,
                        target=ec2.id,
                        relationship=Relationship.CONNECTED_TO,
                        weight=0.5,
                        description="Security group associated with instance exposure",
                        rule=self.name,
                    )
                )
        return edges


DEFAULT_RULES: list[AttackRule] = [
    PublicEc2ToImdsRule(),
    MetadataToInstanceRoleRule(),
    PassRolePrivilegeEscalationRule(),
    PublicBucketRule(),
    RoleCanReadBucketRule(),
    DockerSocketExposedRule(),
    ContainerEscapeRule(),
    OpenSgToInternetRule(),
]


def _short_name(resource: str) -> str:
    if "/" in resource:
        return resource.rsplit("/", 1)[-1]
    if resource.startswith("arn:aws:s3:::"):
        return resource.split(":::")[-1]
    return resource
