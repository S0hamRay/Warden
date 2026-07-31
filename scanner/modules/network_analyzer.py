"""Network analyzer for security groups and NACLs."""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from scanner.aws_client import AwsClient
from scanner.findings import Finding, Severity
from scanner.remediation import get_remediation

MODULE = "network"
ADMIN_PORTS = {22, 3389}
WORLD_CIDRS = {"0.0.0.0/0", "::/0"}


def run(aws: AwsClient, **_kwargs: Any) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_scan_security_groups(aws))
    findings.extend(_scan_nacls(aws))
    return findings


def _scan_security_groups(aws: AwsClient) -> list[Finding]:
    ec2 = aws.client("ec2")
    findings: list[Finding] = []
    try:
        paginator = ec2.get_paginator("describe_security_groups")
        pages = paginator.paginate()
    except ClientError:
        return []

    for page in pages:
        for sg in page.get("SecurityGroups", []):
            sg_id = sg.get("GroupId", "unknown")
            for perm in sg.get("IpPermissions", []):
                findings.extend(_check_sg_permission(sg_id, perm))
    return findings


def _ip_ranges_world(perm: dict[str, Any]) -> bool:
    for rng in perm.get("IpRanges", []):
        if rng.get("CidrIp") in WORLD_CIDRS:
            return True
    for rng in perm.get("Ipv6Ranges", []):
        if rng.get("CidrIpv6") in WORLD_CIDRS:
            return True
    return False


def _port_set(perm: dict[str, Any]) -> set[int] | None:
    """Return ports covered, or None if all protocols/ports."""
    protocol = str(perm.get("IpProtocol", ""))
    if protocol in {"-1", "all"}:
        return None
    from_port = perm.get("FromPort")
    to_port = perm.get("ToPort")
    if from_port is None or to_port is None:
        return set()
    return set(range(int(from_port), int(to_port) + 1))


def _check_sg_permission(sg_id: str, perm: dict[str, Any]) -> list[Finding]:
    if not _ip_ranges_world(perm):
        return []

    ports = _port_set(perm)
    if ports is None:
        return [
            Finding(
                id="NET-SG-OPEN-ALL",
                module=MODULE,
                severity=Severity.CRITICAL,
                resource=sg_id,
                title="Security group allows all traffic from the internet",
                description=(
                    f"Security group {sg_id} allows all protocols/ports from "
                    "0.0.0.0/0 or ::/0."
                ),
                evidence={"permission": perm},
                remediation=get_remediation("NET-SG-OPEN-ALL"),
            )
        ]

    admin_hits = ports & ADMIN_PORTS
    if not admin_hits:
        return []

    return [
        Finding(
            id="NET-SG-OPEN-ADMIN",
            module=MODULE,
            severity=Severity.HIGH,
            resource=sg_id,
            title="Security group exposes admin ports to the internet",
            description=(
                f"Security group {sg_id} allows inbound "
                f"{sorted(admin_hits)} from 0.0.0.0/0 or ::/0."
            ),
            evidence={"permission": perm, "ports": sorted(admin_hits)},
            remediation=get_remediation("NET-SG-OPEN-ADMIN"),
        )
    ]


def _scan_nacls(aws: AwsClient) -> list[Finding]:
    ec2 = aws.client("ec2")
    findings: list[Finding] = []
    try:
        resp = ec2.describe_network_acls()
    except ClientError:
        return []

    for nacl in resp.get("NetworkAcls", []):
        nacl_id = nacl.get("NetworkAclId", "unknown")
        for entry in nacl.get("Entries", []):
            if entry.get("Egress"):
                continue
            if entry.get("RuleAction", "").lower() != "allow":
                continue
            cidr = entry.get("CidrBlock") or entry.get("Ipv6CidrBlock")
            if cidr not in WORLD_CIDRS:
                continue
            protocol = str(entry.get("Protocol", ""))
            port_range = entry.get("PortRange") or {}
            # Allow-all: protocol -1 or covers all ports
            is_all = protocol == "-1" or (
                port_range.get("From") == 0 and port_range.get("To") == 65535
            )
            if not is_all:
                continue
            findings.append(
                Finding(
                    id="NET-NACL-OPEN-ALL",
                    module=MODULE,
                    severity=Severity.HIGH,
                    resource=nacl_id,
                    title="NACL allows all inbound traffic from the internet",
                    description=(
                        f"Network ACL {nacl_id} has an allow-all inbound rule "
                        f"from {cidr}."
                    ),
                    evidence={"entry": entry},
                    remediation=get_remediation("NET-NACL-OPEN-ALL"),
                )
            )
    return findings
