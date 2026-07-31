"""Maps finding type IDs to remediation guidance and optional IaC/CLI snippets."""

from __future__ import annotations

REMEDIATIONS: dict[str, str] = {
    "IAM-WILDCARD-ACTION": (
        "Replace wildcard Action values with the minimum required actions. "
        "Example: change \"Action\": \"*\" to an explicit list such as "
        "\"s3:GetObject\", \"s3:PutObject\"."
    ),
    "IAM-WILDCARD-RESOURCE": (
        "Scope Resource ARNs instead of \"*\". Prefer account/resource-specific ARNs "
        "and condition keys (e.g. aws:ResourceTag) where possible."
    ),
    "IAM-PRIV-ESC-PASSROLE": (
        "Remove iam:PassRole from roles that can also create compute/roles "
        "(iam:CreateRole, lambda:CreateFunction, ec2:RunInstances), or tightly "
        "constrain PassRole with a Resource allowlist of specific role ARNs."
    ),
    "IAM-TRUST-WILDCARD": (
        "Replace Principal \"*\" or overly broad account trust with specific "
        "AWS principals (role/user ARNs) and add Condition blocks "
        "(e.g. aws:SourceAccount, sts:ExternalId)."
    ),
    "IAM-UNUSED-PERMISSIONS": (
        "Review Access Advisor results and detach unused managed policies or "
        "trim inline statements for services not accessed in 90+ days."
    ),
    "S3-PUBLIC-ACL": (
        "Remove AllUsers/AuthenticatedUsers ACL grants. Enable Block Public Access "
        "and prefer bucket policies with explicit principals over ACLs.\n"
        "aws s3api put-public-access-block --bucket BUCKET "
        "--public-access-block-configuration "
        "BlockPublicAcls=true,IgnorePublicAcls=true,"
        "BlockPublicPolicy=true,RestrictPublicBuckets=true"
    ),
    "S3-PUBLIC-POLICY": (
        "Remove Principal \"*\" Allow statements without restrictive conditions, "
        "or add conditions (aws:SourceVpce, aws:PrincipalOrgID). Enable all four "
        "Public Access Block settings."
    ),
    "S3-PUBLIC-ACCESS-BLOCK": (
        "Enable all four Public Access Block settings on the bucket (and account):\n"
        "BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets."
    ),
    "S3-NO-ENCRYPTION": (
        "Enable default encryption (SSE-S3 or SSE-KMS):\n"
        "aws s3api put-bucket-encryption --bucket BUCKET --server-side-encryption-configuration "
        "'{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'"
    ),
    "S3-VERSIONING-DISABLED": (
        "Enable versioning to support recovery from ransomware or accidental deletes:\n"
        "aws s3api put-bucket-versioning --bucket BUCKET "
        "--versioning-configuration Status=Enabled"
    ),
    "S3-LOGGING-DISABLED": (
        "Enable server access logging to a dedicated logging bucket for IR/detection:\n"
        "aws s3api put-bucket-logging --bucket BUCKET --bucket-logging-status ..."
    ),
    "SSRF-IMDSV1-ALLOWED": (
        "Enforce IMDSv2 on the instance so metadata requires a session token:\n"
        "aws ec2 modify-instance-metadata-options --instance-id ID "
        "--http-tokens required --http-endpoint enabled\n"
        "Also validate/allowlist outbound HTTP destinations in the application."
    ),
    "SSRF-IMDS-HOP-LIMIT": (
        "Set MetadataOptions.HttpPutResponseHopLimit to 1 unless containers on the "
        "host explicitly require a higher value:\n"
        "aws ec2 modify-instance-metadata-options --instance-id ID "
        "--http-put-response-hop-limit 1"
    ),
    "SSRF-STATIC-TAINT": (
        "Do not pass user-controlled input directly into outbound HTTP clients. "
        "Validate and allowlist destination hosts/schemes, block link-local/"
        "metadata IPs (169.254.169.254), and enforce IMDSv2 on the host."
    ),
    "CONTAINER-RUN-AS-ROOT": (
        "Set a non-root user in the ECS task definition container (\"user\": \"1000:1000\") "
        "or Docker USER directive. Drop unnecessary Linux capabilities."
    ),
    "CONTAINER-DOCKER-SOCKET-EXPOSED": (
        "Bind the Docker daemon to a unix socket only (unix:///var/run/docker.sock). "
        "Do not expose the Docker API on 0.0.0.0 TCP."
    ),
    "CONTAINER-EKS-NO-DEFAULT-DENY": (
        "Apply a default-deny NetworkPolicy in each namespace and explicitly allow "
        "required pod-to-pod traffic."
    ),
    "NET-SG-OPEN-ADMIN": (
        "Restrict SSH/RDP (22/3389) ingress to known admin CIDRs or use SSM Session "
        "Manager instead of public SSH."
    ),
    "NET-SG-OPEN-ALL": (
        "Remove security group rules that allow all protocols/ports from 0.0.0.0/0 "
        "or ::/0. Prefer least-privilege ports and source ranges."
    ),
    "NET-NACL-OPEN-ALL": (
        "Replace network ACL allow-all inbound rules from 0.0.0.0/0 with explicit "
        "ephemeral/port allowlists matching required traffic."
    ),
}


def get_remediation(finding_type: str) -> str:
    return REMEDIATIONS.get(
        finding_type,
        "Review the resource configuration and apply least-privilege hardening.",
    )
