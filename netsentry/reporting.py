"""Reporting helpers: summaries, tables, time series and CSV/JSON exports."""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

import pandas as pd

from config.settings import DetectionConfig
from netsentry import __version__
from netsentry.schemas import Alert, Severity, format_utc

ALERT_TABLE_COLUMNS: tuple[str, ...] = (
    "alert_id",
    "timestamp",
    "src_ip",
    "rule_id",
    "rule_name",
    "severity",
    "summary",
    "evidence",
)


def severity_counts(alerts: Iterable[Alert]) -> dict[str, int]:
    """Count alerts per severity, always including HIGH, MEDIUM and LOW keys."""
    counts = {s.value: 0 for s in Severity}
    for alert in alerts:
        counts[alert.severity.value] += 1
    return counts


def alerts_to_dataframe(alerts: Sequence[Alert]) -> pd.DataFrame:
    """Flatten alerts into a table; ``evidence`` is rendered as compact JSON text."""
    rows = [
        {
            "alert_id": a.alert_id,
            "timestamp": pd.Timestamp(a.timestamp),
            "src_ip": a.src_ip,
            "rule_id": a.rule_id,
            "rule_name": a.rule_name,
            "severity": a.severity.value,
            "summary": a.summary,
            "evidence": json.dumps(a.evidence, sort_keys=True, separators=(",", ":")),
        }
        for a in alerts
    ]
    return pd.DataFrame(rows, columns=list(ALERT_TABLE_COLUMNS))


def alerts_to_csv(alerts: Sequence[Alert]) -> str:
    """Serialize alerts to CSV text (timestamps as ISO 8601 UTC)."""
    frame = alerts_to_dataframe(alerts)
    if not frame.empty:
        frame["timestamp"] = [format_utc(a.timestamp) for a in alerts]
    frame["recommended_actions"] = [" | ".join(a.recommended_actions) for a in alerts]
    return frame.to_csv(index=False)


def build_report(
    alerts: Sequence[Alert],
    *,
    record_count: int,
    config: DetectionConfig,
    data_source: str,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Build a JSON-serializable report containing metadata and all alerts."""
    generated = generated_at or datetime.now(timezone.utc)
    config_dict = asdict(config)
    config_dict["business_hours_start"] = config.business_hours_start.strftime("%H:%M")
    config_dict["business_hours_end"] = config.business_hours_end.strftime("%H:%M")
    return {
        "report": {
            "tool": "NetSentry AI",
            "version": __version__,
            "generated_at": format_utc(generated),
            "data_source": data_source,
            "records_analyzed": record_count,
            "alert_count": len(alerts),
            "severity_counts": severity_counts(alerts),
            "detection_config": config_dict,
            "disclaimer": (
                "Rule-based detections for educational defensive analysis. "
                "Alerts are leads for investigation, not proof of malicious activity."
            ),
        },
        "alerts": [a.to_dict() for a in alerts],
    }


def alerts_to_json(alerts: Sequence[Alert], **report_kwargs: Any) -> str:
    """Serialize a full report (see :func:`build_report`) to indented JSON."""
    return json.dumps(build_report(alerts, **report_kwargs), indent=2, sort_keys=False)


def top_sources(records: pd.DataFrame, limit: int = 10) -> pd.DataFrame:
    """Return the source IPs with the most events, with event and byte totals."""
    if records.empty:
        return pd.DataFrame(columns=["src_ip", "events", "bytes_sent", "denied"])
    grouped = records.groupby("src_ip").agg(
        events=("src_ip", "size"),
        bytes_sent=("bytes_sent", "sum"),
        denied=("action", lambda s: int((s == "DENY").sum())),
    )
    return (
        grouped.sort_values(["events", "bytes_sent"], ascending=False)
        .head(limit)
        .reset_index()
    )


def build_timeseries(
    records: pd.DataFrame, alerts: Sequence[Alert], freq: str = "30min"
) -> pd.DataFrame:
    """Bucket connections and alerts over time.

    Returns a long-format frame with columns ``bucket``, ``series``
    (``"Connections"`` or ``"Alerts"``) and ``count`` suitable for charting.
    """
    if records.empty:
        return pd.DataFrame(columns=["bucket", "series", "count"])
    conn = records.set_index("timestamp").resample(freq).size().rename("count").reset_index()
    conn = conn.rename(columns={"timestamp": "bucket"}).assign(series="Connections")
    frames = [conn]
    if alerts:
        alert_times = pd.Series(1, index=pd.DatetimeIndex([pd.Timestamp(a.timestamp) for a in alerts]))
        alert_counts = alert_times.resample(freq).sum().rename("count").reset_index()
        alert_counts = alert_counts.rename(columns={"index": "bucket"}).assign(series="Alerts")
        frames.append(alert_counts)
    return pd.concat(frames, ignore_index=True)[["bucket", "series", "count"]]
