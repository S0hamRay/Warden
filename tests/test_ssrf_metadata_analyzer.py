"""Unit tests for SSRF / IMDS analyzer."""

from __future__ import annotations

from pathlib import Path

import boto3

from scanner.modules import ssrf_metadata_analyzer


def test_imdsv1_flagged(mocked_aws):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    image = ec2.describe_images()["Images"][0]["ImageId"]
    resp = ec2.run_instances(
        ImageId=image,
        MinCount=1,
        MaxCount=1,
        MetadataOptions={
            "HttpTokens": "optional",
            "HttpPutResponseHopLimit": 2,
        },
    )
    instance_id = resp["Instances"][0]["InstanceId"]

    findings = ssrf_metadata_analyzer.run(mocked_aws)
    assert any(
        f.id == "SSRF-IMDSV1-ALLOWED" and f.resource == instance_id for f in findings
    )
    assert any(f.id == "SSRF-IMDS-HOP-LIMIT" for f in findings)


def test_imdsv2_required_clean(mocked_aws):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    image = ec2.describe_images()["Images"][0]["ImageId"]
    ec2.run_instances(
        ImageId=image,
        MinCount=1,
        MaxCount=1,
        MetadataOptions={
            "HttpTokens": "required",
            "HttpPutResponseHopLimit": 1,
        },
    )

    findings = ssrf_metadata_analyzer.run(mocked_aws)
    assert not any(f.id == "SSRF-IMDSV1-ALLOWED" for f in findings)
    assert not any(f.id == "SSRF-IMDS-HOP-LIMIT" for f in findings)


def test_python_static_ssrf(tmp_path: Path, mocked_aws):
    app = tmp_path / "app.py"
    app.write_text(
        "import requests\n"
        "def handler(url):\n"
        "    return requests.get(url)\n"
        "def safe():\n"
        "    return requests.get('https://example.com')\n",
        encoding="utf-8",
    )

    findings = ssrf_metadata_analyzer.run(mocked_aws, source_path=str(tmp_path))
    static = [f for f in findings if f.id == "SSRF-STATIC-TAINT"]
    assert len(static) == 1
    assert "app.py:3" in static[0].resource


def test_java_static_ssrf(tmp_path: Path, mocked_aws):
    java = tmp_path / "Controller.java"
    java.write_text(
        "import java.net.URL;\n"
        "class Controller {\n"
        "  void go(HttpServletRequest request) throws Exception {\n"
        "    String target = request.getParameter(\"url\");\n"
        "    URL u = new URL(target);\n"
        "    u.openConnection();\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )

    findings = ssrf_metadata_analyzer.run(mocked_aws, source_path=str(tmp_path))
    assert any(f.id == "SSRF-STATIC-TAINT" for f in findings)
