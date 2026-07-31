"""SSRF-to-metadata credential analyzer (IMDS + static source scan)."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any, Iterator

from scanner.aws_client import AwsClient
from scanner.findings import Finding, Severity
from scanner.remediation import get_remediation

MODULE = "ssrf"

HTTP_METHODS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "request",
    "urlopen",
}

JAVA_SINK_RE = re.compile(
    r"(new\s+URL\s*\(|\.openConnection\s*\(|RestTemplate|"
    r"HttpClient|HttpURLConnection)",
    re.MULTILINE,
)
JAVA_SOURCE_RE = re.compile(
    r"(getParameter\s*\(|@RequestParam|getQueryString\s*\(|"
    r"getHeader\s*\(|HttpServletRequest)",
)


def run(
    aws: AwsClient,
    source_path: str | None = None,
    **_kwargs: Any,
) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_scan_ec2_imds(aws))
    if source_path:
        findings.extend(_scan_source_tree(Path(source_path)))
    return findings


def _scan_ec2_imds(aws: AwsClient) -> list[Finding]:
    ec2 = aws.client("ec2")
    findings: list[Finding] = []

    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate():
        for reservation in page.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                instance_id = instance.get("InstanceId", "unknown")
                state = instance.get("State", {}).get("Name")
                if state == "terminated":
                    continue
                meta = instance.get("MetadataOptions") or {}
                tokens = meta.get("HttpTokens", "optional")
                hop = meta.get("HttpPutResponseHopLimit", 1)

                if tokens != "required":
                    findings.append(
                        Finding(
                            id="SSRF-IMDSV1-ALLOWED",
                            module=MODULE,
                            severity=Severity.CRITICAL,
                            resource=instance_id,
                            title="IMDSv1 allowed (HttpTokens not required)",
                            description=(
                                f"Instance {instance_id} has MetadataOptions.HttpTokens="
                                f"'{tokens}'. SSRF in an app on this host can fetch "
                                "credentials with a simple GET and no session token."
                            ),
                            evidence={"MetadataOptions": meta},
                            remediation=get_remediation("SSRF-IMDSV1-ALLOWED"),
                        )
                    )

                if isinstance(hop, int) and hop > 1:
                    findings.append(
                        Finding(
                            id="SSRF-IMDS-HOP-LIMIT",
                            module=MODULE,
                            severity=Severity.MEDIUM,
                            resource=instance_id,
                            title="IMDS hop limit raised above 1",
                            description=(
                                f"Instance {instance_id} has HttpPutResponseHopLimit={hop}. "
                                "Elevated hop limits can allow containers to reach the "
                                "instance metadata service."
                            ),
                            evidence={"MetadataOptions": meta},
                            remediation=get_remediation("SSRF-IMDS-HOP-LIMIT"),
                        )
                    )
    return findings


def _scan_source_tree(root: Path) -> list[Finding]:
    if not root.exists():
        return []

    findings: list[Finding] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part.startswith(".") for part in path.parts):
            continue
        if "node_modules" in path.parts or "venv" in path.parts:
            continue
        if path.suffix == ".py":
            findings.extend(_scan_python_file(path))
        elif path.suffix == ".java":
            findings.extend(_scan_java_file(path))
    return findings


def _scan_python_file(path: Path) -> list[Finding]:
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return []

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not _is_http_sink(node.func):
            continue
        url_arg = _url_argument(node)
        if url_arg is None:
            continue
        if _is_literal_url(url_arg):
            continue
        findings.append(
            Finding(
                id="SSRF-STATIC-TAINT",
                module=MODULE,
                severity=Severity.HIGH,
                resource=f"{path}:{node.lineno}",
                title="User-influenced outbound HTTP request (possible SSRF)",
                description=(
                    f"Non-literal URL passed to outbound HTTP call in {path.name} "
                    f"at line {node.lineno}. Validate/allowlist destinations and "
                    "enforce IMDSv2."
                ),
                evidence={
                    "file": str(path),
                    "line": node.lineno,
                    "snippet": ast.get_source_segment(source, node)
                    or _line_snippet(source, node.lineno),
                },
                remediation=get_remediation("SSRF-STATIC-TAINT"),
            )
        )
    return findings


def _is_http_sink(func: ast.AST) -> bool:
    if isinstance(func, ast.Name):
        return func.id in {"urlopen", "request"}
    if isinstance(func, ast.Attribute):
        if func.attr not in HTTP_METHODS:
            return False
        # requests.get / httpx.get / urllib.request.urlopen
        return True
    return False


def _url_argument(call: ast.Call) -> ast.AST | None:
    if call.args:
        return call.args[0]
    for kw in call.keywords:
        if kw.arg in {"url", "URL"}:
            return kw.value
    return None


def _is_literal_url(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.JoinedStr):
        # f-strings are treated as non-literal / potentially tainted
        return False
    return False


def _line_snippet(source: str, lineno: int) -> str:
    lines = source.splitlines()
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].strip()
    return ""


def _scan_java_file(path: Path) -> list[Finding]:
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []

    findings: list[Finding] = []
    lines = source.splitlines()
    sink_lines = [i + 1 for i, line in enumerate(lines) if JAVA_SINK_RE.search(line)]
    source_lines = {
        i + 1 for i, line in enumerate(lines) if JAVA_SOURCE_RE.search(line)
    }

    for sink_line in sink_lines:
        window = range(max(1, sink_line - 25), sink_line + 1)
        if not any(line in source_lines for line in window):
            # Also flag sinks that clearly use a variable named like a request param
            sink_text = lines[sink_line - 1]
            if not re.search(
                r"(request|param|url|target|host|uri)", sink_text, re.I
            ):
                continue
        findings.append(
            Finding(
                id="SSRF-STATIC-TAINT",
                module=MODULE,
                severity=Severity.HIGH,
                resource=f"{path}:{sink_line}",
                title="User-influenced outbound HTTP request (possible SSRF)",
                description=(
                    f"Java HTTP sink near user-input source in {path.name} "
                    f"around line {sink_line}. Validate/allowlist destinations "
                    "and enforce IMDSv2."
                ),
                evidence={
                    "file": str(path),
                    "line": sink_line,
                    "snippet": lines[sink_line - 1].strip(),
                },
                remediation=get_remediation("SSRF-STATIC-TAINT"),
            )
        )
    return findings


def iter_python_sinks(source: str) -> Iterator[int]:
    """Helper for tests: yield line numbers of non-literal HTTP sinks."""
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_http_sink(node.func):
            url_arg = _url_argument(node)
            if url_arg is not None and not _is_literal_url(url_arg):
                yield node.lineno
