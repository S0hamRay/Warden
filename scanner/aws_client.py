"""boto3 session/client wrapper with credential handling and retries."""

from __future__ import annotations

from typing import Any

import boto3
from botocore.config import Config


class AwsClient:
    """Thin wrapper around a boto3 Session with standard retry config."""

    def __init__(
        self,
        region: str | None = None,
        profile: str | None = None,
    ) -> None:
        session_kwargs: dict[str, Any] = {}
        if profile:
            session_kwargs["profile_name"] = profile
        if region:
            session_kwargs["region_name"] = region

        self.region = region or "us-east-1"
        self.session = boto3.Session(**session_kwargs)
        self._config = Config(
            retries={"max_attempts": 10, "mode": "standard"},
            user_agent_extra="warden-cspm/0.1",
        )
        self._clients: dict[str, Any] = {}

    def client(self, service: str, region: str | None = None) -> Any:
        key = f"{service}:{region or self.region}"
        if key not in self._clients:
            self._clients[key] = self.session.client(
                service,
                region_name=region or self.region,
                config=self._config,
            )
        return self._clients[key]

    def resource(self, service: str, region: str | None = None) -> Any:
        return self.session.resource(
            service,
            region_name=region or self.region,
            config=self._config,
        )
