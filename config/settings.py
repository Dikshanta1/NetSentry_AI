"""Central configuration for NetSentry AI.

All tunable values (detection thresholds, upload limits, LLM settings) live
here so they can be explained and changed in one place. Detection and upload
settings are plain frozen dataclasses; LLM settings are read from environment
variables at call time so no secret is ever stored in source code.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import time
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
SAMPLE_DATA_PATH: Path = PROJECT_ROOT / "data" / "sample_traffic.csv"

MIB: int = 1024 * 1024


@dataclass(frozen=True)
class UploadLimits:
    """Limits applied to user-supplied CSV files before and during parsing."""

    max_upload_bytes: int = 5 * MIB
    max_rows: int = 50_000
    max_errors_reported: int = 200


@dataclass(frozen=True)
class DetectionConfig:
    """Thresholds and windows used by the rule-based detection engine."""

    # NET-001: potential port scan
    port_scan_window_seconds: int = 300
    port_scan_unique_ports_threshold: int = 15

    # NET-002: high data transfer
    transfer_window_seconds: int = 300
    transfer_bytes_threshold: int = 50 * MIB

    # NET-003: off-hours connection
    business_hours_start: time = time(9, 0)  # inclusive
    business_hours_end: time = time(18, 0)  # exclusive
    timezone: str = "UTC"

    def __post_init__(self) -> None:
        if self.port_scan_window_seconds <= 0 or self.transfer_window_seconds <= 0:
            raise ValueError("Detection windows must be positive.")
        if self.port_scan_unique_ports_threshold < 1:
            raise ValueError("Port-scan threshold must be at least 1.")
        if self.transfer_bytes_threshold < 1:
            raise ValueError("Transfer threshold must be at least 1 byte.")
        if self.business_hours_start >= self.business_hours_end:
            raise ValueError("Business hours start must be before business hours end.")
        try:
            ZoneInfo(self.timezone)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"Unknown timezone: {self.timezone!r}") from exc

    @property
    def tzinfo(self) -> ZoneInfo:
        """Return the configured business-hours timezone."""
        return ZoneInfo(self.timezone)


@dataclass(frozen=True)
class LLMConfig:
    """Settings for the optional, advisory LLM explainer.

    The endpoint is expected to be OpenAI-compatible (``/chat/completions``).
    ``api_key`` is deliberately excluded from ``repr`` so it never appears in
    logs or the UI.
    """

    api_url: str = ""
    model: str = ""
    api_key: str = field(default="", repr=False)
    timeout_seconds: float = 20.0

    @property
    def is_configured(self) -> bool:
        """True when endpoint, model and key are all present."""
        return bool(self.api_url and self.model and self.api_key)

    @classmethod
    def from_env(cls) -> "LLMConfig":
        """Build the config from ``NETSENTRY_LLM_*`` environment variables."""
        try:
            timeout = float(os.environ.get("NETSENTRY_LLM_TIMEOUT", "20"))
        except ValueError:
            timeout = 20.0
        return cls(
            api_url=os.environ.get("NETSENTRY_LLM_API_URL", "").strip(),
            model=os.environ.get("NETSENTRY_LLM_MODEL", "").strip(),
            api_key=os.environ.get("NETSENTRY_LLM_API_KEY", "").strip(),
            timeout_seconds=min(max(timeout, 1.0), 120.0),
        )


DEFAULT_UPLOAD_LIMITS = UploadLimits()
DEFAULT_DETECTION_CONFIG = DetectionConfig()
