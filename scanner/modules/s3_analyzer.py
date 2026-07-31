"""S3 bucket misconfiguration scanner."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import unquote

from botocore.exceptions import ClientError

from scanner.aws_client import AwsClient
from scanner.findings import Finding, Severity
from scanner.remediation import get_remediation

MODULE = "s3"

PUBLIC_URI_MARKERS = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)


def run(aws: AwsClient, **_kwargs: Any) -> list[Finding]:
    s3 = aws.client("s3")
    findings: list[Finding] = []

    buckets = s3.list_buckets().get("Buckets", [])
    for bucket in buckets:
        name = bucket["Name"]
        arn = f"arn:aws:s3:::{name}"
        findings.extend(_check_acl(s3, name, arn))
        findings.extend(_check_policy(s3, name, arn))
        findings.extend(_check_public_access_block(s3, name, arn))
        findings.extend(_check_encryption(s3, name, arn))
        findings.extend(_check_versioning(s3, name, arn))
        findings.extend(_check_logging(s3, name, arn))
    return findings


def _check_acl(s3: Any, name: str, arn: str) -> list[Finding]:
    try:
        acl = s3.get_bucket_acl(Bucket=name)
    except ClientError:
        return []

    public_grants = []
    for grant in acl.get("Grants", []):
        grantee = grant.get("Grantee", {})
        uri = grantee.get("URI", "")
        if uri in PUBLIC_URI_MARKERS:
            public_grants.append(grant)

    if not public_grants:
        return []

    return [
        Finding(
            id="S3-PUBLIC-ACL",
            module=MODULE,
            severity=Severity.CRITICAL,
            resource=arn,
            title="S3 bucket ACL grants public access",
            description=(
                f"Bucket '{name}' has ACL grants to AllUsers or AuthenticatedUsers."
            ),
            evidence={"grants": public_grants},
            remediation=get_remediation("S3-PUBLIC-ACL"),
        )
    ]


def _decode_policy(policy: str) -> dict[str, Any]:
    return json.loads(unquote(policy))


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _principal_is_wildcard(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, str):
        return principal == "*"
    if isinstance(principal, dict):
        for v in principal.values():
            for item in _as_list(v):
                if item == "*":
                    return True
    return False


def _has_restrictive_condition(condition: Any) -> bool:
    """Treat any Condition block as a restriction for Principal '*' Allow."""
    return bool(condition)


def _check_policy(s3: Any, name: str, arn: str) -> list[Finding]:
    try:
        resp = s3.get_bucket_policy(Bucket=name)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in {"NoSuchBucketPolicy", "NoSuchBucket"}:
            return []
        return []

    document = _decode_policy(resp["Policy"])
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    risky = []
    for stmt in statements:
        if str(stmt.get("Effect", "Allow")).lower() != "allow":
            continue
        if not _principal_is_wildcard(stmt.get("Principal")):
            continue
        if _has_restrictive_condition(stmt.get("Condition")):
            continue
        risky.append(stmt)

    if not risky:
        return []

    return [
        Finding(
            id="S3-PUBLIC-POLICY",
            module=MODULE,
            severity=Severity.CRITICAL,
            resource=arn,
            title="S3 bucket policy allows Principal '*' without condition",
            description=(
                f"Bucket '{name}' policy allows Principal '*' without a "
                "restrictive Condition."
            ),
            evidence={"statements": risky},
            remediation=get_remediation("S3-PUBLIC-POLICY"),
        )
    ]


def _check_public_access_block(s3: Any, name: str, arn: str) -> list[Finding]:
    flags = {
        "BlockPublicAcls": False,
        "IgnorePublicAcls": False,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": False,
    }
    try:
        resp = s3.get_public_access_block(Bucket=name)
        cfg = resp.get("PublicAccessBlockConfiguration", {})
        for key in flags:
            flags[key] = bool(cfg.get(key, False))
    except ClientError:
        # Missing configuration → fail closed (treat as not fully enabled)
        pass

    if all(flags.values()):
        return []

    return [
        Finding(
            id="S3-PUBLIC-ACCESS-BLOCK",
            module=MODULE,
            severity=Severity.HIGH,
            resource=arn,
            title="S3 Public Access Block not fully enabled",
            description=(
                f"Bucket '{name}' does not have all four Public Access Block "
                "settings enabled."
            ),
            evidence=flags,
            remediation=get_remediation("S3-PUBLIC-ACCESS-BLOCK"),
        )
    ]


def _check_encryption(s3: Any, name: str, arn: str) -> list[Finding]:
    try:
        resp = s3.get_bucket_encryption(Bucket=name)
        rules = (
            resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        )
        if rules:
            return []
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code not in {
            "ServerSideEncryptionConfigurationNotFoundError",
            "NoSuchBucket",
        }:
            return []

    return [
        Finding(
            id="S3-NO-ENCRYPTION",
            module=MODULE,
            severity=Severity.MEDIUM,
            resource=arn,
            title="S3 default encryption not configured",
            description=(
                f"Bucket '{name}' has no default SSE-S3 or SSE-KMS encryption."
            ),
            evidence={},
            remediation=get_remediation("S3-NO-ENCRYPTION"),
        )
    ]


def _check_versioning(s3: Any, name: str, arn: str) -> list[Finding]:
    try:
        resp = s3.get_bucket_versioning(Bucket=name)
    except ClientError:
        return []

    if resp.get("Status") == "Enabled":
        return []

    return [
        Finding(
            id="S3-VERSIONING-DISABLED",
            module=MODULE,
            severity=Severity.LOW,
            resource=arn,
            title="S3 versioning disabled",
            description=(
                f"Bucket '{name}' does not have versioning Enabled "
                "(impacts ransomware/accidental-deletion recovery)."
            ),
            evidence={"Status": resp.get("Status", "Disabled")},
            remediation=get_remediation("S3-VERSIONING-DISABLED"),
        )
    ]


def _check_logging(s3: Any, name: str, arn: str) -> list[Finding]:
    try:
        resp = s3.get_bucket_logging(Bucket=name)
    except ClientError:
        return []

    if resp.get("LoggingEnabled"):
        return []

    return [
        Finding(
            id="S3-LOGGING-DISABLED",
            module=MODULE,
            severity=Severity.LOW,
            resource=arn,
            title="S3 server access logging disabled",
            description=(
                f"Bucket '{name}' does not have server access logging enabled."
            ),
            evidence={},
            remediation=get_remediation("S3-LOGGING-DISABLED"),
        )
    ]
