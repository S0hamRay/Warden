"""Unit tests for container analyzer."""

from __future__ import annotations

import boto3

from scanner.modules import container_analyzer


def test_ecs_task_without_user(mocked_aws):
    ecs = boto3.client("ecs", region_name="us-east-1")
    ecs.register_task_definition(
        family="warden-root-task",
        containerDefinitions=[
            {
                "name": "web",
                "image": "nginx:latest",
                "memory": 256,
                "essential": True,
            }
        ],
    )

    findings = container_analyzer.run(mocked_aws)
    assert any(f.id == "CONTAINER-RUN-AS-ROOT" for f in findings)


def test_ecs_task_with_non_root_user(mocked_aws):
    ecs = boto3.client("ecs", region_name="us-east-1")
    ecs.register_task_definition(
        family="warden-safe-task",
        containerDefinitions=[
            {
                "name": "web",
                "image": "nginx:latest",
                "memory": 256,
                "essential": True,
                "user": "1000:1000",
            }
        ],
    )

    findings = container_analyzer.run(mocked_aws)
    assert not any(
        f.id == "CONTAINER-RUN-AS-ROOT" and "warden-safe-task" in f.resource
        for f in findings
    )


def test_docker_host_tcp_exposed(mocked_aws, monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "tcp://0.0.0.0:2375")
    findings = container_analyzer.run(mocked_aws)
    assert any(f.id == "CONTAINER-DOCKER-SOCKET-EXPOSED" for f in findings)
    monkeypatch.delenv("DOCKER_HOST", raising=False)
