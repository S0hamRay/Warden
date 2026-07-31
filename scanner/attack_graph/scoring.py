"""Attack path scoring and severity mapping."""

from __future__ import annotations

from scanner.findings import Finding, Severity

SEVERITY_POINTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
}

PRIV_ESC_MARKERS = {
    "ESCALATES_TO",
    "CAN_PASS_ROLE",
    "IAM-PRIV-ESC-PASSROLE",
    "privilege escalation",
}
CREDENTIAL_THEFT_MARKERS = {
    "METADATA_CREDENTIALS",
    "METADATA_SERVICE",
    "COMPROMISES",
    "IMDSV1",
    "SSRF-IMDSV1-ALLOWED",
}
DATA_ACCESS_MARKERS = {
    "S3_BUCKET",
    "CAN_READ",
    "CAN_WRITE",
    "PUBLIC_BUCKET",
}
INTERNET_MARKERS = {"INTERNET", "EXPOSES", "CAN_REACH"}


def score_to_severity(score: int) -> Severity:
    if score >= 76:
        return Severity.CRITICAL
    if score >= 51:
        return Severity.HIGH
    if score >= 26:
        return Severity.MEDIUM
    return Severity.LOW


def score_path(
    *,
    findings: list[Finding],
    node_types: list[str],
    relationships: list[str],
    descriptions: list[str],
) -> tuple[int, Severity, dict[str, int]]:
    """
    score =
      sum(finding severities)
      + privilege_escalations × 20
      + internet_exposure × 25
      + credential_theft × 25
      + data_access × 20
    Clamped to 0-100.
    """
    finding_points = sum(
        SEVERITY_POINTS.get(f.severity, 0) for f in findings
    )

    blob = " ".join(
        [*node_types, *relationships, *descriptions, *[f.id for f in findings]]
    ).upper()

    priv_esc = int(
        any(m.upper() in blob for m in PRIV_ESC_MARKERS)
        or any(f.id == "IAM-PRIV-ESC-PASSROLE" for f in findings)
    )
    internet = int(
        "INTERNET" in node_types
        or any(m in blob for m in ("EXPOSES", "CAN_REACH", "PUBLIC"))
    )
    credential_theft = int(
        any(m.upper() in blob for m in CREDENTIAL_THEFT_MARKERS)
        or any("IMDS" in f.id or "SSRF" in f.id for f in findings)
    )
    data_access = int(
        "S3_BUCKET" in node_types
        or any(m.upper() in blob for m in DATA_ACCESS_MARKERS)
        or any(f.id.startswith("S3-") for f in findings)
    )

    components = {
        "finding_severity_points": finding_points,
        "privilege_escalations": priv_esc,
        "internet_exposure": internet,
        "credential_theft": credential_theft,
        "data_access": data_access,
    }
    raw = (
        finding_points
        + priv_esc * 20
        + internet * 25
        + credential_theft * 25
        + data_access * 20
    )
    score = max(0, min(100, raw))
    return score, score_to_severity(score), components
