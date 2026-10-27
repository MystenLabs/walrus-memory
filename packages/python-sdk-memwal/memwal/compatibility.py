"""Relayer/API compatibility checks for the Python SDK."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional, Tuple

MEMWAL_PYTHON_COMPATIBILITY_VERSION = "0.1.0"
SUPPORTED_RELAYER_API_MAJOR = 1


def compatibility_error(metadata: Dict[str, Any], server_url: str) -> Optional[str]:
    """Return an actionable error string when relayer metadata is unsupported."""

    if not isinstance(metadata, dict):
        return (
            f"Walrus Memory relayer at {server_url} does not expose compatibility metadata. "
            "Upgrade the relayer to a version that serves GET /version, or use an older SDK."
        )

    api_version = metadata.get("apiVersion")
    relayer_version = metadata.get("relayerVersion")
    min_supported = metadata.get("minSupportedSdk")

    if not api_version or not relayer_version or not isinstance(min_supported, dict):
        return (
            f"Walrus Memory relayer at {server_url} does not expose compatibility metadata. "
            "Upgrade the relayer to a version that serves GET /version, or use an older SDK."
        )

    api_major = _semver_major(str(api_version))
    if api_major is None:
        return f'Walrus Memory relayer at {server_url} returned invalid apiVersion "{api_version}".'

    if api_major != SUPPORTED_RELAYER_API_MAJOR:
        return (
            "This Walrus Memory Python SDK supports relayer API "
            f"{SUPPORTED_RELAYER_API_MAJOR}.x, but {server_url} reports apiVersion "
            f"{api_version}. Upgrade or downgrade the SDK/relayer pair."
        )

    min_python = min_supported.get("python")
    if not isinstance(min_python, str):
        return f"Walrus Memory relayer at {server_url} did not report minSupportedSdk.python."
    if _parse_semver(min_python) is None:
        return (
            f'Walrus Memory relayer at {server_url} returned invalid '
            f'minSupportedSdk.python "{min_python}".'
        )

    if _compare_semver(MEMWAL_PYTHON_COMPATIBILITY_VERSION, min_python) < 0:
        return (
            f"Walrus Memory relayer at {server_url} requires Python SDK >= {min_python}, "
            f"but this package supports the {MEMWAL_PYTHON_COMPATIBILITY_VERSION} "
            "compatibility baseline. Upgrade memwal or use an older compatible relayer."
        )

    return None


def _semver_major(version: str) -> Optional[int]:
    parsed = _parse_semver(version)
    return parsed[0] if parsed else None


def _compare_semver(left: str, right: str) -> int:
    left_parts = _parse_semver(left)
    right_parts = _parse_semver(right)
    if left_parts is None or right_parts is None:
        raise ValueError(f"invalid semver comparison: {left} vs {right}")
    return (left_parts > right_parts) - (left_parts < right_parts)


def _parse_semver(version: str) -> Optional[Tuple[int, int, int]]:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$", version.strip())
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))
