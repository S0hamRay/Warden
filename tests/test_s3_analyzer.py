"""Unit tests for S3 analyzer using moto."""

from __future__ import annotations

import json

import boto3

from scanner.modules import s3_analyzer


def test_public_acl_and_policy(mocked_aws):
    s3 = boto3.client("s3", region_name="us-east-1")
    bucket = "warden-public-bucket"
    s3.create_bucket(Bucket=bucket)

    s3.put_bucket_acl(
        Bucket=bucket,
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
            "Owner": s3.get_bucket_acl(Bucket=bucket)["Owner"],
        },
    )

    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "PublicRead",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{bucket}/*",
                    }
                ],
            }
        ),
    )

    findings = s3_analyzer.run(mocked_aws)
    ids = {f.id for f in findings}
    assert "S3-PUBLIC-ACL" in ids
    assert "S3-PUBLIC-POLICY" in ids


def test_missing_encryption_versioning_logging_pab(mocked_aws):
    s3 = boto3.client("s3", region_name="us-east-1")
    bucket = "warden-plain-bucket"
    s3.create_bucket(Bucket=bucket)

    findings = s3_analyzer.run(mocked_aws)
    ids = {f.id for f in findings}
    assert "S3-NO-ENCRYPTION" in ids
    assert "S3-VERSIONING-DISABLED" in ids
    assert "S3-LOGGING-DISABLED" in ids
    assert "S3-PUBLIC-ACCESS-BLOCK" in ids


def test_secure_bucket_minimal_findings(mocked_aws):
    s3 = boto3.client("s3", region_name="us-east-1")
    bucket = "warden-secure-bucket"
    s3.create_bucket(Bucket=bucket)
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    }
                }
            ]
        },
    )
    s3.put_bucket_versioning(
        Bucket=bucket,
        VersioningConfiguration={"Status": "Enabled"},
    )
    # logging still off → LOW only expected among soft checks
    findings = s3_analyzer.run(mocked_aws)
    critical = [f for f in findings if f.severity.value == "CRITICAL"]
    assert not critical
    assert any(f.id == "S3-LOGGING-DISABLED" for f in findings)
