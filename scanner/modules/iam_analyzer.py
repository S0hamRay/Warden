"""IAM over-permissioning analyzer."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote

from scanner.aws_client import AwsClient
from scanner.findings import Finding, Severity
from scanner.remediation import get_remediation

MODULE = "iam"
ACCESS_ADVISOR_ROLE_CAP = 25
UNUSED_MEDIUM_DAYS = 90
UNUSED_LOW_DAYS = 180

PRIV_ESC_PARTNERS = {
    "iam:createrole",
    "lambda:createfunction",
    "ec2:runinstances",
}


def run(aws: AwsClient, **_kwargs: Any) -> list[Finding]:
    iam = aws.client("iam")
    findings: list[Finding] = []

    roles = _list_roles(iam)
    for role in roles:
        role_name = role["RoleName"]
        role_arn = role["Arn"]

        findings.extend(_check_trust_policy(role))

        policies = _collect_role_policies(iam, role_name)
        for policy_name, document in policies:
            findings.extend(
                _check_policy_document(role_arn, policy_name, document)
            )

        action_set = _collect_actions(policies)
        if _has_passrole_priv_esc(action_set):
            findings.append(
                Finding(
                    id="IAM-PRIV-ESC-PASSROLE",
                    module=MODULE,
                    severity=Severity.CRITICAL,
                    resource=role_arn,
                    title="Privilege escalation via PassRole combination",
                    description=(
                        f"Role {role_name} can iam:PassRole together with "
                        "iam:CreateRole, lambda:CreateFunction, and/or "
                        "ec2:RunInstances — a known privilege-escalation chain."
                    ),
                    evidence={"actions": sorted(action_set)},
                    remediation=get_remediation("IAM-PRIV-ESC-PASSROLE"),
                )
            )

    findings.extend(_check_unused_permissions(iam, roles[:ACCESS_ADVISOR_ROLE_CAP]))
    return findings


def _list_roles(iam: Any) -> list[dict[str, Any]]:
    roles: list[dict[str, Any]] = []
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        roles.extend(page.get("Roles", []))
    return roles


def _decode_policy(document: Any) -> dict[str, Any]:
    if isinstance(document, str):
        return json.loads(unquote(document))
    return document


def _iter_statements(document: dict[str, Any]) -> list[dict[str, Any]]:
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        return [statements]
    return list(statements)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _check_trust_policy(role: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    trust = _decode_policy(role.get("AssumeRolePolicyDocument", {}))
    role_arn = role["Arn"]

    for stmt in _iter_statements(trust):
        if str(stmt.get("Effect", "Allow")).lower() != "allow":
            continue
        principal = stmt.get("Principal", {})
        principals = _flatten_principals(principal)
        has_condition = bool(stmt.get("Condition"))
        for p in principals:
            broad = p == "*" or (p.endswith(":root") and not has_condition)
            if not broad:
                continue
            findings.append(
                Finding(
                    id="IAM-TRUST-WILDCARD",
                    module=MODULE,
                    severity=Severity.HIGH,
                    resource=role_arn,
                    title="Overly broad IAM trust policy principal",
                    description=(
                        f"Role trust policy allows principal '{p}'"
                        + (
                            " without a restrictive Condition"
                            if p != "*"
                            else ""
                        )
                        + "."
                    ),
                    evidence={"statement": stmt},
                    remediation=get_remediation("IAM-TRUST-WILDCARD"),
                )
            )
            break
    return findings


def _flatten_principals(principal: Any) -> list[str]:
    if principal == "*":
        return ["*"]
    if isinstance(principal, str):
        return [principal]
    if isinstance(principal, dict):
        values: list[str] = []
        for v in principal.values():
            values.extend(str(x) for x in _as_list(v))
        return values
    return []


def _collect_role_policies(
    iam: Any, role_name: str
) -> list[tuple[str, dict[str, Any]]]:
    policies: list[tuple[str, dict[str, Any]]] = []

    attached = iam.list_attached_role_policies(RoleName=role_name).get(
        "AttachedPolicies", []
    )
    for attached_policy in attached:
        policy_arn = attached_policy["PolicyArn"]
        policy = iam.get_policy(PolicyArn=policy_arn)["Policy"]
        version_id = policy["DefaultVersionId"]
        version = iam.get_policy_version(
            PolicyArn=policy_arn, VersionId=version_id
        )
        document = _decode_policy(version["PolicyVersion"]["Document"])
        policies.append((attached_policy["PolicyName"], document))

    inline_names = iam.list_role_policies(RoleName=role_name).get(
        "PolicyNames", []
    )
    for name in inline_names:
        inline = iam.get_role_policy(RoleName=role_name, PolicyName=name)
        policies.append((name, _decode_policy(inline["PolicyDocument"])))

    return policies


def _is_wildcard_action(action: str) -> bool:
    a = action.lower().strip()
    return a == "*" or a.endswith(":*")


def _is_wildcard_resource(resource: str) -> bool:
    return resource.strip() == "*"


def _check_policy_document(
    role_arn: str, policy_name: str, document: dict[str, Any]
) -> list[Finding]:
    findings: list[Finding] = []
    for stmt in _iter_statements(document):
        if str(stmt.get("Effect", "Allow")).lower() != "allow":
            continue
        actions = [str(a) for a in _as_list(stmt.get("Action", []))]
        resources = [str(r) for r in _as_list(stmt.get("Resource", []))]

        wild_actions = [a for a in actions if _is_wildcard_action(a)]
        if wild_actions:
            findings.append(
                Finding(
                    id="IAM-WILDCARD-ACTION",
                    module=MODULE,
                    severity=Severity.CRITICAL,
                    resource=role_arn,
                    title="Wildcard Action in IAM policy",
                    description=(
                        f"Policy '{policy_name}' grants wildcard Action "
                        f"{wild_actions} on role {role_arn}."
                    ),
                    evidence={"policy": policy_name, "statement": stmt},
                    remediation=get_remediation("IAM-WILDCARD-ACTION"),
                )
            )

        wild_resources = [r for r in resources if _is_wildcard_resource(r)]
        if wild_resources:
            findings.append(
                Finding(
                    id="IAM-WILDCARD-RESOURCE",
                    module=MODULE,
                    severity=Severity.CRITICAL,
                    resource=role_arn,
                    title="Wildcard Resource in IAM policy",
                    description=(
                        f"Policy '{policy_name}' grants Action on Resource '*' "
                        f"for role {role_arn}."
                    ),
                    evidence={"policy": policy_name, "statement": stmt},
                    remediation=get_remediation("IAM-WILDCARD-RESOURCE"),
                )
            )
    return findings


def _normalize_action(action: str) -> str:
    return action.lower().strip()


def _collect_actions(
    policies: list[tuple[str, dict[str, Any]]],
) -> set[str]:
    actions: set[str] = set()
    for _, document in policies:
        for stmt in _iter_statements(document):
            if str(stmt.get("Effect", "Allow")).lower() != "allow":
                continue
            for action in _as_list(stmt.get("Action", [])):
                actions.add(_normalize_action(str(action)))
    return actions


def _has_passrole_priv_esc(actions: set[str]) -> bool:
    has_passrole = "iam:passrole" in actions or "*" in actions or "iam:*" in actions
    if not has_passrole:
        return False
    if "*" in actions or "iam:*" in actions:
        # Wildcard already covers partners; still escalate if PassRole pattern
        # is present via wildcard + any create-style service wildcards.
        return True
    return any(
        partner in actions
        or partner.split(":")[0] + ":*" in actions
        for partner in PRIV_ESC_PARTNERS
    )


def _check_unused_permissions(
    iam: Any, roles: list[dict[str, Any]]
) -> list[Finding]:
    findings: list[Finding] = []
    now = datetime.now(timezone.utc)

    for role in roles:
        role_arn = role["Arn"]
        try:
            job = iam.generate_service_last_accessed_details(Arn=role_arn)
            job_id = job["JobId"]
            details = _poll_access_advisor(iam, job_id)
        except Exception:
            # Access Advisor may be unavailable (moto / permissions).
            continue

        unused_services: list[dict[str, Any]] = []
        for svc in details.get("ServicesLastAccessed", []):
            last = svc.get("LastAuthenticated")
            if last is None:
                unused_services.append(
                    {
                        "ServiceNamespace": svc.get("ServiceNamespace"),
                        "LastAuthenticated": None,
                        "days_unused": None,
                    }
                )
                continue
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            days = (now - last).days
            if days >= UNUSED_MEDIUM_DAYS:
                unused_services.append(
                    {
                        "ServiceNamespace": svc.get("ServiceNamespace"),
                        "LastAuthenticated": last.isoformat(),
                        "days_unused": days,
                    }
                )

        if not unused_services:
            continue

        max_days = max(
            (s["days_unused"] for s in unused_services if s["days_unused"] is not None),
            default=UNUSED_MEDIUM_DAYS,
        )
        never_used = any(s["days_unused"] is None for s in unused_services)
        severity = (
            Severity.LOW
            if max_days >= UNUSED_LOW_DAYS or never_used
            else Severity.MEDIUM
        )
        # Prefer MEDIUM for 90-179, LOW for 180+; never-used → LOW per plan table
        if never_used and max_days < UNUSED_LOW_DAYS:
            # mix of never-used and medium window — keep MEDIUM if any in 90-179
            medium_hits = [
                s
                for s in unused_services
                if s["days_unused"] is not None
                and UNUSED_MEDIUM_DAYS <= s["days_unused"] < UNUSED_LOW_DAYS
            ]
            severity = Severity.MEDIUM if medium_hits else Severity.LOW
        elif (
            any(
                s["days_unused"] is not None
                and UNUSED_MEDIUM_DAYS <= s["days_unused"] < UNUSED_LOW_DAYS
                for s in unused_services
            )
            and max_days < UNUSED_LOW_DAYS
        ):
            severity = Severity.MEDIUM

        findings.append(
            Finding(
                id="IAM-UNUSED-PERMISSIONS",
                module=MODULE,
                severity=severity,
                resource=role_arn,
                title="Unused IAM permissions detected",
                description=(
                    f"Role has services with no access in {UNUSED_MEDIUM_DAYS}+ days "
                    f"(Access Advisor; capped scan)."
                ),
                evidence={"unused_services": unused_services[:20]},
                remediation=get_remediation("IAM-UNUSED-PERMISSIONS"),
            )
        )
    return findings


def _poll_access_advisor(
    iam: Any, job_id: str, attempts: int = 10, delay: float = 0.2
) -> dict[str, Any]:
    for _ in range(attempts):
        resp = iam.get_service_last_accessed_details(JobId=job_id)
        if resp.get("JobStatus") == "COMPLETED":
            return resp
        if resp.get("JobStatus") == "FAILED":
            return {}
        time.sleep(delay)
    return {}
