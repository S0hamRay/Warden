"""Shared pytest fixtures."""

from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from scanner.aws_client import AwsClient


@pytest.fixture
def aws_region() -> str:
    return "us-east-1"


@pytest.fixture
def mocked_aws(aws_region: str):
    with mock_aws():
        # Ensure default session region is set for clients created inside tests
        boto3.setup_default_session(region_name=aws_region)
        yield AwsClient(region=aws_region)
