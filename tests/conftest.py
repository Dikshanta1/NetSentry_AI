"""Shared fixtures: deterministic record builders that go through real validation."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import datetime, timedelta, timezone
from typing import Any

import pandas as pd
import pytest

from config.settings import DetectionConfig
from netsentry.validation import validate_dataframe

BASE_TIME = datetime(2026, 10, 26, 10, 0, 0, tzinfo=timezone.utc)  # inside business hours


def raw_row(
    *,
    ts: datetime = BASE_TIME,
    src_ip: str = "192.0.2.10",
    dst_ip: str = "198.51.100.20",
    src_port: int | str = 51000,
    dst_port: int | str = 443,
    protocol: str = "TCP",
    bytes_sent: int | str = 1500,
    action: str = "ALLOW",
) -> dict[str, str]:
    """Build one raw (string-valued) CSV row."""
    return {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": str(src_port),
        "dst_port": str(dst_port),
        "protocol": protocol,
        "bytes_sent": str(bytes_sent),
        "action": action,
    }


def to_records(rows: Iterable[dict[str, Any]]) -> pd.DataFrame:
    """Validate raw rows and return the normalized frame (asserting no errors)."""
    result = validate_dataframe(pd.DataFrame(list(rows), dtype=str))
    assert result.is_valid, [str(e) for e in result.errors]
    return result.records


@pytest.fixture
def make_records() -> Callable[[Iterable[dict[str, Any]]], pd.DataFrame]:
    """Fixture form of :func:`to_records`."""
    return to_records


@pytest.fixture
def config() -> DetectionConfig:
    """Default detection configuration (explicit for readability)."""
    return DetectionConfig()


@pytest.fixture
def scan_rows() -> list[dict[str, str]]:
    """One source probing 20 ports, one every 10 seconds (well inside 5 minutes)."""
    return [
        raw_row(ts=BASE_TIME + timedelta(seconds=10 * i), src_ip="203.0.113.50",
                dst_port=1000 + i, action="DENY")
        for i in range(20)
    ]


def minutes(n: float) -> timedelta:
    """Shorthand for ``timedelta(minutes=n)``."""
    return timedelta(minutes=n)
