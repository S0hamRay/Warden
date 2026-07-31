"""Unit tests for network analyzer."""

from __future__ import annotations

import boto3

from scanner.modules import network_analyzer


def test_sg_open_ssh(mocked_aws):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(
        GroupName="warden-open-ssh",
        Description="open ssh",
    )
    sg_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    findings = network_analyzer.run(mocked_aws)
    assert any(
        f.id == "NET-SG-OPEN-ADMIN" and f.resource == sg_id for f in findings
    )


def test_sg_open_all(mocked_aws):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(
        GroupName="warden-open-all",
        Description="open all",
    )
    sg_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    findings = network_analyzer.run(mocked_aws)
    assert any(
        f.id == "NET-SG-OPEN-ALL"
        and f.severity.value == "CRITICAL"
        and f.resource == sg_id
        for f in findings
    )
