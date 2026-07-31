"""Orchestrator: loads config, runs modules, aggregates findings, writes reports."""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Sequence

from scanner.aws_client import AwsClient
from scanner.findings import Finding, has_critical
from scanner.modules import MODULE_REGISTRY
from reports.report_generator import generate_reports

logger = logging.getLogger("warden")

DEFAULT_MODULES = ["iam", "s3", "ssrf", "container", "network"]


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="warden",
        description="Warden Cloud Security Posture Scanner",
    )
    parser.add_argument(
        "--modules",
        default=",".join(DEFAULT_MODULES),
        help=f"Comma-separated modules to run (default: {','.join(DEFAULT_MODULES)})",
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", default=None, help="AWS named profile")
    parser.add_argument(
        "--source-path",
        default=None,
        help="Path to application source for SSRF static analysis",
    )
    parser.add_argument(
        "--output",
        default="reports",
        help="Directory for report.json / report.html",
    )
    parser.add_argument(
        "--fail-on-critical",
        action="store_true",
        default=True,
        help="Exit 1 if any CRITICAL finding (default: true)",
    )
    parser.add_argument(
        "--no-fail-on-critical",
        action="store_false",
        dest="fail_on_critical",
        help="Do not exit non-zero on CRITICAL findings",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args(argv)


def select_modules(module_csv: str) -> list[str]:
    names = [m.strip().lower() for m in module_csv.split(",") if m.strip()]
    unknown = [m for m in names if m not in MODULE_REGISTRY]
    if unknown:
        raise SystemExit(
            f"Unknown modules: {', '.join(unknown)}. "
            f"Available: {', '.join(MODULE_REGISTRY)}"
        )
    return names


def run_scan(
    modules: list[str],
    aws: AwsClient,
    source_path: str | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for name in modules:
        mod = MODULE_REGISTRY[name]
        logger.info("Running module: %s", name)
        try:
            module_findings = mod.run(aws, source_path=source_path)
        except Exception:
            logger.exception("Module %s failed", name)
            continue
        logger.info("Module %s produced %d finding(s)", name, len(module_findings))
        findings.extend(module_findings)
    findings.sort(key=lambda f: (f.severity, f.module, f.resource))
    return findings


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    modules = select_modules(args.modules)
    aws = AwsClient(region=args.region, profile=args.profile)
    findings = run_scan(modules, aws, source_path=args.source_path)
    generate_reports(findings, output_dir=args.output)

    if args.fail_on_critical and has_critical(findings):
        logger.error("CRITICAL findings detected — failing scan")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
