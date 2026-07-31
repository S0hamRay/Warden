"""Tests for orchestrator exit semantics and reporting."""

from __future__ import annotations

import json
from pathlib import Path

import boto3

from scanner.core import main
from scanner.findings import Finding, Severity, has_critical
from reports.report_generator import generate_reports


def test_has_critical_helper():
    findings = [
        Finding(
            id="X",
            module="s3",
            severity=Severity.LOW,
            resource="r",
            title="t",
            description="d",
        )
    ]
    assert not has_critical(findings)
    findings.append(
        Finding(
            id="Y",
            module="s3",
            severity=Severity.CRITICAL,
            resource="r",
            title="t",
            description="d",
        )
    )
    assert has_critical(findings)


def test_generate_reports_writes_files(tmp_path: Path):
    findings = [
        Finding(
            id="S3-PUBLIC-ACL",
            module="s3",
            severity=Severity.CRITICAL,
            resource="arn:aws:s3:::x",
            title="Public",
            description="Public ACL",
            remediation="fix it",
        )
    ]
    payload = generate_reports(findings, output_dir=tmp_path, print_cli=False)
    assert (tmp_path / "report.json").exists()
    assert (tmp_path / "report.html").exists()
    assert (tmp_path / "attack_paths.json").exists()
    assert (tmp_path / "attack_graph.dot").exists()
    data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert data["summary"]["CRITICAL"] == 1
    assert payload["finding_count"] == 1
    assert payload["attack_path_count"] >= 1



def test_main_exits_one_on_critical(mocked_aws, tmp_path: Path):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="exit-critical-bucket")
    s3.put_bucket_acl(
        Bucket="exit-critical-bucket",
        AccessControlPolicy={
            "Grants": [
                {
                    "Grantee": {
                        "Type": "Group",
                        "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                    },
                    "Permission": "READ",
                }
            ],
            "Owner": s3.get_bucket_acl(Bucket="exit-critical-bucket")["Owner"],
        },
    )

    code = main(
        [
            "--modules",
            "s3",
            "--region",
            "us-east-1",
            "--output",
            str(tmp_path),
        ]
    )
    assert code == 1
