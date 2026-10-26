"""Shared data structures: input schema, alerts and validation errors."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

REQUIRED_COLUMNS: tuple[str, ...] = (
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "bytes_sent",
    "action",
)

ALLOWED_PROTOCOLS: frozenset[str] = frozenset({"TCP", "UDP", "ICMP"})
ALLOWED_ACTIONS: frozenset[str] = frozenset({"ALLOW", "DENY"})

# Columns of the normalized DataFrame produced by validation.
# ``source_row`` is the 1-based line number in the original CSV (header = line 1).
NORMALIZED_COLUMNS: tuple[str, ...] = REQUIRED_COLUMNS + ("source_row",)


class Severity(str, Enum):
    """Alert severity. Assigned only by detection rules, never by the LLM."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def rank(self) -> int:
        """Sort key: higher is more severe."""
        return {"HIGH": 3, "MEDIUM": 2, "LOW": 1}[self.value]


def format_utc(value: datetime) -> str:
    """Format a timezone-aware datetime as an ISO 8601 UTC string ending in ``Z``."""
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class RowError:
    """A validation problem tied to a specific CSV line and column."""

    row: int | None
    column: str | None
    message: str

    def __str__(self) -> str:
        location = f"Row {self.row}" if self.row is not None else "File"
        if self.column:
            location += f", column '{self.column}'"
        return f"{location}: {self.message}"


@dataclass(frozen=True)
class Alert:
    """A structured detection result.

    The dataclass is frozen so downstream consumers (reporting, the UI, the
    optional LLM explainer) cannot alter IDs, severity or evidence.
    """

    alert_id: str
    rule_id: str
    rule_name: str
    timestamp: datetime
    src_ip: str
    severity: Severity
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommended_actions: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the alert."""
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "timestamp": format_utc(self.timestamp),
            "src_ip": self.src_ip,
            "severity": self.severity.value,
            "summary": self.summary,
            "evidence": dict(self.evidence),
            "recommended_actions": list(self.recommended_actions),
        }
