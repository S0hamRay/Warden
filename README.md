# Warden

Cloud Security Posture Scanner for AWS. Warden audits IAM over-permissioning, public S3 buckets, SSRF/IMDS credential-theft exposure, container posture, and overly open network rules — then emits JSON, HTML, and colored CLI reports suitable for demos and CI gates.

This is a **read-only posture scanner** plus **static source analysis** for SSRF-prone outbound HTTP patterns. It does not exploit systems or fetch instance metadata credentials.

## Quickstart

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Scan the current AWS account/profile
python -m scanner.core --region us-east-1 --output reports/

# Include application SSRF static analysis
python -m scanner.core --source-path ./path/to/app --output reports/

# CI-friendly wrapper (exit 1 on CRITICAL)
./scripts/run_scan.sh
```

Reports land in `reports/report.json`, `reports/report.html`, `reports/attack_paths.json`, and `reports/attack_graph.dot` (PNG if Graphviz `dot` is installed).

## Attack-path analysis

After scanners emit findings, the `scanner/attack_graph` engine correlates them into multi-step paths (e.g. Internet → public EC2 → SSRF → IMDSv1 → instance role → PassRole escalation → S3).

- Rules are declarative classes in `scanner/attack_graph/rules.py` — add new chains without editing the engine
- Search methods: `--attack-path-method bfs|dfs|dijkstra`
- Disable with `--no-attack-graph`
- Install Graphviz to render `attack_graph.png`: `brew install graphviz`

## Modules

| Module | Checks |
|--------|--------|
| `iam` | Wildcard Action/Resource, PassRole privilege-escalation chains, broad trust policies, unused permissions via Access Advisor (capped at 25 roles) |
| `s3` | Public ACLs/policies, incomplete Public Access Block, encryption, versioning, access logging |
| `ssrf` | EC2 IMDSv1 (`HttpTokens != required`), elevated IMDS hop limit, Python/Java static SSRF sink patterns |
| `container` | ECS tasks running as root, Docker TCP exposure, EKS default-deny NetworkPolicy (best-effort with kubeconfig) |
| `network` | Security groups open on 22/3389 or all traffic; NACLs allow-all inbound |

Select modules with `--modules iam,s3,ssrf`.

## Scanner IAM permissions

Attach a least-privilege read-only policy to the principal running Warden (outline):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "iam:ListRoles",
      "iam:GetRole",
      "iam:ListAttachedRolePolicies",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:ListRolePolicies",
      "iam:GetRolePolicy",
      "iam:GenerateServiceLastAccessedDetails",
      "iam:GetServiceLastAccessedDetails",
      "s3:ListAllMyBuckets",
      "s3:GetBucketAcl",
      "s3:GetBucketPolicy",
      "s3:GetBucketEncryption",
      "s3:GetBucketVersioning",
      "s3:GetBucketLogging",
      "s3:GetBucketPublicAccessBlock",
      "ec2:DescribeInstances",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeNetworkAcls",
      "ecs:ListTaskDefinitions",
      "ecs:DescribeTaskDefinition",
      "eks:ListClusters",
      "eks:DescribeCluster"
    ],
    "Resource": "*"
  }]
}
```

## Tests

Unit tests use [moto](https://github.com/getmoto/moto) so they never need real AWS credentials:

```bash
pytest -q
```

## Live sandbox demo

`sandbox/terraform/` provisions deliberately misconfigured resources (public S3, over-privileged IAM role, EC2 with IMDSv1, open SSH security group), tagged `Project=WardenSandbox`.

```bash
./scripts/setup_sandbox.sh
./scripts/run_scan.sh
cd sandbox/terraform && terraform destroy
```

Use only in a disposable/demo account.

## Ethical note

Warden is for authorized security posture assessment of accounts and codebases you own or have permission to scan. The static SSRF module flags insecure request patterns; it does not perform network requests against metadata services or third-party targets.

## Project Tiramisu

Project manager: Jordan Ellis.
