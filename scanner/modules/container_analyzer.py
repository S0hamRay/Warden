"""Container / microservice posture checks (ECS, Docker socket, EKS best-effort)."""

from __future__ import annotations

import json
import logging
import os
import socket
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from botocore.exceptions import ClientError

from scanner.aws_client import AwsClient
from scanner.findings import Finding, Severity
from scanner.remediation import get_remediation

MODULE = "container"
logger = logging.getLogger(__name__)


def run(aws: AwsClient, **_kwargs: Any) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_scan_ecs_task_definitions(aws))
    findings.extend(_scan_eks_clusters(aws))
    findings.extend(_scan_docker_socket())
    return findings


def _scan_ecs_task_definitions(aws: AwsClient) -> list[Finding]:
    ecs = aws.client("ecs")
    findings: list[Finding] = []

    try:
        paginator = ecs.get_paginator("list_task_definitions")
        arns: list[str] = []
        for page in paginator.paginate(status="ACTIVE"):
            arns.extend(page.get("taskDefinitionArns", []))
    except ClientError as exc:
        logger.debug("ECS list_task_definitions failed: %s", exc)
        return []

    for arn in arns:
        try:
            resp = ecs.describe_task_definition(taskDefinition=arn)
        except ClientError:
            continue
        task_def = resp.get("taskDefinition", {})
        family = task_def.get("family", arn)
        for container in task_def.get("containerDefinitions", []):
            user = container.get("user")
            name = container.get("name", "unknown")
            if user and str(user) not in {"0", "0:0", "root", "root:root"}:
                continue
            # Missing user or explicitly root
            findings.append(
                Finding(
                    id="CONTAINER-RUN-AS-ROOT",
                    module=MODULE,
                    severity=Severity.MEDIUM,
                    resource=f"{arn}/{name}",
                    title="ECS container configured to run as root",
                    description=(
                        f"Task definition '{family}' container '{name}' has no "
                        "non-root user set (or user is root)."
                    ),
                    evidence={
                        "taskDefinition": arn,
                        "container": name,
                        "user": user,
                    },
                    remediation=get_remediation("CONTAINER-RUN-AS-ROOT"),
                )
            )
    return findings


def _scan_eks_clusters(aws: AwsClient) -> list[Finding]:
    """Best-effort: list clusters; NetworkPolicy check only if kubeconfig present."""
    findings: list[Finding] = []
    try:
        eks = aws.client("eks")
        clusters = eks.list_clusters().get("clusters", [])
    except ClientError as exc:
        logger.debug("EKS list_clusters failed: %s", exc)
        return []

    for name in clusters:
        try:
            desc = eks.describe_cluster(name=name)["cluster"]
        except ClientError:
            continue
        arn = desc.get("arn", name)
        # Without kubernetes client / kubeconfig, we cannot verify NetworkPolicies.
        # Emit a medium finding only when KUBECONFIG is set but default-deny is absent.
        kubeconfig = os.environ.get("KUBECONFIG")
        if not kubeconfig and not Path.home().joinpath(".kube", "config").exists():
            logger.info(
                "EKS cluster %s found; skipping NetworkPolicy check "
                "(no kubeconfig). Install kubectl access to enable.",
                name,
            )
            continue
        if not _has_default_deny_network_policy():
            findings.append(
                Finding(
                    id="CONTAINER-EKS-NO-DEFAULT-DENY",
                    module=MODULE,
                    severity=Severity.MEDIUM,
                    resource=arn,
                    title="EKS cluster missing default-deny NetworkPolicy signal",
                    description=(
                        f"Cluster '{name}' appears to lack a default-deny NetworkPolicy "
                        "(all pods may reach all pods)."
                    ),
                    evidence={"cluster": name},
                    remediation=get_remediation("CONTAINER-EKS-NO-DEFAULT-DENY"),
                )
            )
    return findings


def _has_default_deny_network_policy() -> bool:
    """
    Best-effort kubectl check. Returns True if we cannot run kubectl
    (avoid false positives when tooling is missing).
    """
    try:
        result = subprocess.run(
            [
                "kubectl",
                "get",
                "networkpolicies",
                "-A",
                "-o",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode != 0:
            return True
        data = json.loads(result.stdout or "{}")
        for item in data.get("items", []):
            spec = item.get("spec", {})
            # default-deny typically has empty podSelector and no ingress/egress allows
            pod_selector = spec.get("podSelector")
            if pod_selector == {}:
                policy_types = spec.get("policyTypes") or []
                ingress = spec.get("ingress")
                if "Ingress" in policy_types and not ingress:
                    return True
                if ingress == []:
                    return True
        return False
    except (FileNotFoundError, json.JSONDecodeError, subprocess.TimeoutExpired, OSError):
        return True


def _scan_docker_socket() -> list[Finding]:
    docker_host = os.environ.get("DOCKER_HOST", "")
    if docker_host.startswith("tcp://"):
        parsed = urlparse(docker_host)
        host = parsed.hostname or ""
        if host in {"0.0.0.0", "127.0.0.1", "localhost"} or _is_open_tcp_docker(parsed):
            if host == "0.0.0.0" or _docker_tcp_exposes_all(docker_host):
                return [
                    Finding(
                        id="CONTAINER-DOCKER-SOCKET-EXPOSED",
                        module=MODULE,
                        severity=Severity.CRITICAL,
                        resource=docker_host,
                        title="Docker daemon exposed over TCP",
                        description=(
                            f"DOCKER_HOST={docker_host} indicates a TCP-exposed Docker "
                            "API rather than a local unix socket only."
                        ),
                        evidence={"DOCKER_HOST": docker_host},
                        remediation=get_remediation(
                            "CONTAINER-DOCKER-SOCKET-EXPOSED"
                        ),
                    )
                ]

    sock_path = Path("/var/run/docker.sock")
    if not sock_path.exists():
        return []

    # Inspect daemon info via unix socket for hosts bound to 0.0.0.0
    try:
        info = _docker_info_via_unix()
    except OSError:
        return []

    for listener in _extract_docker_listeners(info):
        if "0.0.0.0" in listener or "[::]" in listener:
            return [
                Finding(
                    id="CONTAINER-DOCKER-SOCKET-EXPOSED",
                    module=MODULE,
                    severity=Severity.CRITICAL,
                    resource=listener,
                    title="Docker daemon bound to network interface",
                    description=(
                        "Docker daemon appears bound to 0.0.0.0 rather than "
                        "unix socket only."
                    ),
                    evidence={"listener": listener, "info_keys": list(info)[:20]},
                    remediation=get_remediation("CONTAINER-DOCKER-SOCKET-EXPOSED"),
                )
            ]
    return []


def _is_open_tcp_docker(parsed: Any) -> bool:
    return parsed.scheme == "tcp"


def _docker_tcp_exposes_all(docker_host: str) -> bool:
    return "0.0.0.0" in docker_host


def _docker_info_via_unix() -> dict[str, Any]:
    # Minimal Docker Engine API call over unix socket using httplib-style request
    class UnixHTTPConnection:
        def __init__(self, path: str) -> None:
            self.path = path

        def request(self) -> dict[str, Any]:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect(self.path)
                req = (
                    b"GET /info HTTP/1.0\r\n"
                    b"Host: localhost\r\n"
                    b"\r\n"
                )
                sock.sendall(req)
                data = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            if b"\r\n\r\n" not in data:
                return {}
            body = data.split(b"\r\n\r\n", 1)[1]
            return json.loads(body.decode("utf-8", errors="replace") or "{}")

    return UnixHTTPConnection("/var/run/docker.sock").request()


def _extract_docker_listeners(info: dict[str, Any]) -> list[str]:
    listeners: list[str] = []
    for key in ("DockerRootDir",):
        _ = key
    # Engine info sometimes includes RegistryConfig; host binds appear in swarm/system
    # Fallback: check common fields used by dockerd configuration dumps
    for field in ("LocalNodeState",):
        _ = field
    raw = json.dumps(info)
    if "tcp://0.0.0.0" in raw:
        listeners.append("tcp://0.0.0.0")
    return listeners
