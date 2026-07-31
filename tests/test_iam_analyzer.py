"""Unit tests for IAM analyzer using moto."""

from __future__ import annotations

import json

import boto3

from scanner.modules import iam_analyzer


def _create_role(iam, name: str, trust: dict) -> str:
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
    )
    return resp["Role"]["Arn"]


def test_wildcard_action_flagged(mocked_aws):
    iam = boto3.client("iam", region_name="us-east-1")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    _create_role(iam, "wildcard-role", trust)
    iam.put_role_policy(
        RoleName="wildcard-role",
        PolicyName="AdminStar",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::bucket"}
                ],
            }
        ),
    )

    findings = iam_analyzer.run(mocked_aws)
    ids = {f.id for f in findings}
    assert "IAM-WILDCARD-ACTION" in ids


def test_wildcard_resource_flagged(mocked_aws):
    iam = boto3.client("iam", region_name="us-east-1")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    _create_role(iam, "star-resource", trust)
    iam.put_role_policy(
        RoleName="star-resource",
        PolicyName="StarResource",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
                ],
            }
        ),
    )

    findings = iam_analyzer.run(mocked_aws)
    assert any(f.id == "IAM-WILDCARD-RESOURCE" for f in findings)


def test_passrole_priv_esc_flagged(mocked_aws):
    iam = boto3.client("iam", region_name="us-east-1")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    _create_role(iam, "priv-esc", trust)
    iam.put_role_policy(
        RoleName="priv-esc",
        PolicyName="Escalator",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "iam:PassRole",
                            "lambda:CreateFunction",
                        ],
                        "Resource": "arn:aws:iam::123456789012:role/specific",
                    }
                ],
            }
        ),
    )

    findings = iam_analyzer.run(mocked_aws)
    assert any(f.id == "IAM-PRIV-ESC-PASSROLE" for f in findings)
    assert any(
        f.id == "IAM-PRIV-ESC-PASSROLE" and f.severity.value == "CRITICAL"
        for f in findings
    )


def test_wildcard_trust_principal(mocked_aws):
    iam = boto3.client("iam", region_name="us-east-1")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole",
            }
        ],
    }
    _create_role(iam, "open-trust", trust)
    iam.put_role_policy(
        RoleName="open-trust",
        PolicyName="ReadOnlyS3",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:ListBucket",
                        "Resource": "arn:aws:s3:::safe",
                    }
                ],
            }
        ),
    )

    findings = iam_analyzer.run(mocked_aws)
    assert any(f.id == "IAM-TRUST-WILDCARD" for f in findings)
