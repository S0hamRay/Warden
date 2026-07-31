#!/usr/bin/env bash
# Provisions intentionally misconfigured AWS resources for a live Warden demo.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_DIR="$ROOT_DIR/sandbox/terraform"

cat <<'EOF'
============================================================
 WARNING: This creates INTENTIONALLY INSECURE AWS resources
 (public S3, over-privileged IAM, IMDSv1 EC2, open SSH SG).
 Use only in a disposable/demo account. Destroy when done:
   cd sandbox/terraform && terraform destroy
============================================================
EOF

read -r -p "Type YES to continue: " confirm
if [[ "$confirm" != "YES" ]]; then
  echo "Aborted."
  exit 1
fi

cd "$TF_DIR"
terraform init
terraform apply "$@"

echo
echo "Sandbox ready. Run a scan with:"
echo "  ./scripts/run_scan.sh"
