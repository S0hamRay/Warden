#!/usr/bin/env bash
# CI-friendly Warden scan entrypoint. Exits non-zero if CRITICAL findings exist.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VENV_DIR="${VENV_DIR:-.venv}"
OUTPUT_DIR="${OUTPUT_DIR:-reports}"
REGION="${AWS_REGION:-us-east-1}"
MODULES="${MODULES:-iam,s3,ssrf,container,network}"
SOURCE_PATH="${SOURCE_PATH:-}"

if [[ ! -d "$VENV_DIR" ]]; then
  python3 -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
python -m pip install --upgrade pip >/dev/null
python -m pip install -r requirements.txt >/dev/null

ARGS=(--region "$REGION" --modules "$MODULES" --output "$OUTPUT_DIR")
if [[ -n "${AWS_PROFILE:-}" ]]; then
  ARGS+=(--profile "$AWS_PROFILE")
fi
if [[ -n "$SOURCE_PATH" ]]; then
  ARGS+=(--source-path "$SOURCE_PATH")
fi

echo "Running Warden scan (region=$REGION modules=$MODULES)..."
set +e
python -m scanner.core "${ARGS[@]}"
STATUS=$?
set -e

if [[ $STATUS -ne 0 ]]; then
  echo "Warden scan failed with exit code $STATUS (CRITICAL findings or error)."
  exit "$STATUS"
fi

echo "Warden scan completed with no CRITICAL findings."
exit 0
