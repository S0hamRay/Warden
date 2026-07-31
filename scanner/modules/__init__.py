"""Analyzer modules for Warden CSPM scans."""

from scanner.modules import (
    container_analyzer,
    iam_analyzer,
    network_analyzer,
    s3_analyzer,
    ssrf_metadata_analyzer,
)

MODULE_REGISTRY = {
    "iam": iam_analyzer,
    "s3": s3_analyzer,
    "ssrf": ssrf_metadata_analyzer,
    "container": container_analyzer,
    "network": network_analyzer,
}

__all__ = ["MODULE_REGISTRY"]
