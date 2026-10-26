"""Transparent, rule-based detection engine.

The engine takes the normalized DataFrame produced by
:mod:`netsentry.validation` and returns a list of :class:`Alert` objects. It
has no dependency on Streamlit or on any LLM, and its output depends only on
the input records and the :class:`DetectionConfig`.

Windowed rules (NET-001, NET-002) use a sliding window per source IP: for
every event, the window covers that event and all earlier events from the
same source within ``window_seconds``. Triggering windows that overlap are
merged into a single *episode*, and each episode produces exactly one alert.
This avoids one duplicate alert per record during a single scan or transfer.
"""

from __future__ import annotations

import hashlib
import logging
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import pandas as pd

from config.settings import DEFAULT_DETECTION_CONFIG, DetectionConfig
from netsentry.schemas import Alert, Severity, format_utc

logger = logging.getLogger(__name__)

MAX_LISTED_ITEMS: int = 50  # cap on lists stored in evidence (ports, IPs)

RULE_PORT_SCAN = "NET-001"
RULE_HIGH_TRANSFER = "NET-002"
RULE_OFF_HOURS = "NET-003"

RULE_NAMES: dict[str, str] = {
    RULE_PORT_SCAN: "Potential port scan",
    RULE_HIGH_TRANSFER: "High data transfer",
    RULE_OFF_HOURS: "Off-hours connection",
}

RECOMMENDATIONS: dict[str, tuple[str, ...]] = {
    RULE_PORT_SCAN: (
        "Inspect all connections from the source IP around the alert window.",
        "Check whether the source is an approved vulnerability scanner or monitoring tool.",
        "Correlate with firewall, IDS and endpoint logs for the destination hosts.",
        "Review whether any contacted ports were ALLOWED and exposed unexpectedly.",
        "Escalate according to your organization's incident-response procedures if unexplained.",
    ),
    RULE_HIGH_TRANSFER: (
        "Identify the process or user on the source host responsible for the transfer.",
        "Check whether the destination is an approved backup, sync or update service.",
        "Correlate with proxy, DLP and endpoint logs for the same time window.",
        "Compare the volume with this host's normal baseline.",
        "Escalate according to your organization's incident-response procedures if unexplained.",
    ),
    RULE_OFF_HOURS: (
        "Check whether the activity matches a scheduled job, maintenance window or on-call work.",
        "Inspect related connections from the same source before and after these events.",
        "Correlate with authentication logs to see which account was active.",
        "Escalate according to your organization's incident-response procedures only if other "
        "indicators are present; off-hours activity alone is not proof of malicious behavior.",
    ),
}


@dataclass(frozen=True)
class _Window:
    """A triggering window: event index range [left, right] and its metric."""

    left: int
    right: int
    metric: int


@dataclass(frozen=True)
class _Episode:
    """Merged run of overlapping triggering windows for a single source."""

    first: int  # index of first event in the first triggering window
    last: int  # index of last event in the last triggering window
    first_trigger: int  # index of the event at which the threshold was first met
    peak: _Window


def make_alert_id(rule_id: str, src_ip: str, start: datetime, end: datetime) -> str:
    """Build a deterministic alert ID from stable rule and episode data."""
    key = f"{rule_id}|{src_ip}|{format_utc(start)}|{format_utc(end)}"
    return f"{rule_id}-{hashlib.sha256(key.encode()).hexdigest()[:10]}"


def _merge_windows(windows: Sequence[_Window]) -> list[_Episode]:
    """Merge triggering windows that share at least one event into episodes."""
    episodes: list[_Episode] = []
    current: _Episode | None = None
    for window in windows:
        if current is not None and window.left <= current.last:
            peak = window if window.metric > current.peak.metric else current.peak
            current = _Episode(current.first, window.right, current.first_trigger, peak)
            continue
        if current is not None:
            episodes.append(current)
        current = _Episode(window.left, window.right, window.right, window)
    if current is not None:
        episodes.append(current)
    return episodes


def _sliding_windows(
    times: Sequence[pd.Timestamp],
    window: timedelta,
    add: Callable[[int], None],
    remove: Callable[[int], None],
    metric: Callable[[], int],
    threshold: int,
) -> list[_Window]:
    """Two-pointer sliding window over time-sorted events of one source.

    For each event ``right`` the window holds events with
    ``times[right] - times[left] <= window``. ``add``/``remove`` update the
    caller's running state; ``metric`` reads it.
    """
    triggered: list[_Window] = []
    left = 0
    for right in range(len(times)):
        add(right)
        while times[right] - times[left] > window:
            remove(left)
            left += 1
        value = metric()
        if value >= threshold:
            triggered.append(_Window(left, right, value))
    return triggered


def _capped(values: Sequence[Any]) -> tuple[list[Any], bool]:
    items = list(values)
    return items[:MAX_LISTED_ITEMS], len(items) > MAX_LISTED_ITEMS


def _episode_common_evidence(group: pd.DataFrame, episode: _Episode) -> dict[str, Any]:
    span = group.iloc[episode.first : episode.last + 1]
    dst_ips, dst_ips_truncated = _capped(sorted(span["dst_ip"].unique()))
    return {
        "episode_start": format_utc(span["timestamp"].iloc[0]),
        "episode_end": format_utc(span["timestamp"].iloc[-1]),
        "episode_event_count": int(len(span)),
        "denied_event_count": int((span["action"] == "DENY").sum()),
        "destination_ips": dst_ips,
        "destination_ips_truncated": dst_ips_truncated,
        "source_rows": [int(r) for r in span["source_row"].head(MAX_LISTED_ITEMS)],
    }


def detect_port_scans(records: pd.DataFrame, config: DetectionConfig) -> list[Alert]:
    """NET-001: flag sources contacting many unique destination ports in a window."""
    window = timedelta(seconds=config.port_scan_window_seconds)
    threshold = config.port_scan_unique_ports_threshold
    alerts: list[Alert] = []

    for src_ip, group in records.groupby("src_ip", sort=True):
        group = group.reset_index(drop=True)
        ports = group["dst_port"].tolist()
        counter: Counter[int] = Counter()

        def add(i: int) -> None:
            counter[ports[i]] += 1

        def remove(i: int) -> None:
            counter[ports[i]] -= 1
            if counter[ports[i]] == 0:
                del counter[ports[i]]

        windows = _sliding_windows(
            group["timestamp"].tolist(), window, add, remove, lambda: len(counter), threshold
        )
        for episode in _merge_windows(windows):
            span = group.iloc[episode.first : episode.last + 1]
            peak = group.iloc[episode.peak.left : episode.peak.right + 1]
            peak_ports = sorted(int(p) for p in peak["dst_port"].unique())
            all_ports, ports_truncated = _capped(sorted(int(p) for p in span["dst_port"].unique()))
            start, end = span["timestamp"].iloc[0], span["timestamp"].iloc[-1]
            evidence = {
                "threshold_unique_ports": threshold,
                "observed_unique_ports": episode.peak.metric,
                "window_seconds": config.port_scan_window_seconds,
                "peak_window_start": format_utc(peak["timestamp"].iloc[0]),
                "peak_window_end": format_utc(peak["timestamp"].iloc[-1]),
                "peak_window_ports": peak_ports[:MAX_LISTED_ITEMS],
                "destination_ports": all_ports,
                "destination_ports_truncated": ports_truncated,
                "episode_unique_ports": int(span["dst_port"].nunique()),
                **_episode_common_evidence(group, episode),
            }
            alerts.append(
                Alert(
                    alert_id=make_alert_id(RULE_PORT_SCAN, str(src_ip), start, end),
                    rule_id=RULE_PORT_SCAN,
                    rule_name=RULE_NAMES[RULE_PORT_SCAN],
                    timestamp=group["timestamp"].iloc[episode.first_trigger].to_pydatetime(),
                    src_ip=str(src_ip),
                    severity=Severity.HIGH,
                    summary=(
                        f"{src_ip} contacted {episode.peak.metric} unique destination ports "
                        f"within {config.port_scan_window_seconds // 60} minutes "
                        f"(threshold {threshold})."
                    ),
                    evidence=evidence,
                    recommended_actions=RECOMMENDATIONS[RULE_PORT_SCAN],
                )
            )
    return alerts


def detect_high_transfers(records: pd.DataFrame, config: DetectionConfig) -> list[Alert]:
    """NET-002: flag sources whose bytes sent in a window reach the threshold."""
    window = timedelta(seconds=config.transfer_window_seconds)
    threshold = config.transfer_bytes_threshold
    alerts: list[Alert] = []

    for src_ip, group in records.groupby("src_ip", sort=True):
        group = group.reset_index(drop=True)
        sizes = group["bytes_sent"].tolist()
        total = [0]

        def add(i: int) -> None:
            total[0] += sizes[i]

        def remove(i: int) -> None:
            total[0] -= sizes[i]

        windows = _sliding_windows(
            group["timestamp"].tolist(), window, add, remove, lambda: total[0], threshold
        )
        for episode in _merge_windows(windows):
            span = group.iloc[episode.first : episode.last + 1]
            peak = group.iloc[episode.peak.left : episode.peak.right + 1]
            start, end = span["timestamp"].iloc[0], span["timestamp"].iloc[-1]
            evidence = {
                "threshold_bytes": threshold,
                "observed_bytes": episode.peak.metric,
                "observed_mib": round(episode.peak.metric / (1024 * 1024), 2),
                "window_seconds": config.transfer_window_seconds,
                "peak_window_start": format_utc(peak["timestamp"].iloc[0]),
                "peak_window_end": format_utc(peak["timestamp"].iloc[-1]),
                "event_count": int(len(peak)),
                "episode_total_bytes": int(span["bytes_sent"].sum()),
                **_episode_common_evidence(group, episode),
            }
            alerts.append(
                Alert(
                    alert_id=make_alert_id(RULE_HIGH_TRANSFER, str(src_ip), start, end),
                    rule_id=RULE_HIGH_TRANSFER,
                    rule_name=RULE_NAMES[RULE_HIGH_TRANSFER],
                    timestamp=group["timestamp"].iloc[episode.first_trigger].to_pydatetime(),
                    src_ip=str(src_ip),
                    severity=Severity.MEDIUM,
                    summary=(
                        f"{src_ip} sent {evidence['observed_mib']} MiB in {len(peak)} events "
                        f"within {config.transfer_window_seconds // 60} minutes "
                        f"(threshold {threshold / (1024 * 1024):g} MiB)."
                    ),
                    evidence=evidence,
                    recommended_actions=RECOMMENDATIONS[RULE_HIGH_TRANSFER],
                )
            )
    return alerts


def is_off_hours(timestamp: datetime, config: DetectionConfig) -> bool:
    """Return True when ``timestamp`` falls outside configured business hours."""
    local_time = timestamp.astimezone(config.tzinfo).time()
    return not (config.business_hours_start <= local_time < config.business_hours_end)


def detect_off_hours(records: pd.DataFrame, config: DetectionConfig) -> list[Alert]:
    """NET-003: flag connections outside business hours.

    To keep the alert list readable, off-hours events are grouped into one
    alert per source IP per local calendar date. Every individual event is
    still listed (up to a cap) in the evidence.
    """
    if records.empty:
        return []
    local = records["timestamp"].dt.tz_convert(config.tzinfo)
    start_t, end_t = config.business_hours_start, config.business_hours_end
    mask = local.dt.time.map(lambda t: not (start_t <= t < end_t)).astype(bool)
    off = records.loc[mask].assign(local_date=local[mask].dt.date, local_time=local[mask])
    alerts: list[Alert] = []
    hours = (
        f"{config.business_hours_start.strftime('%H:%M')}-"
        f"{config.business_hours_end.strftime('%H:%M')} {config.timezone}"
    )

    for (src_ip, local_date), group in off.groupby(["src_ip", "local_date"], sort=True):
        start, end = group["timestamp"].iloc[0], group["timestamp"].iloc[-1]
        ports, ports_truncated = _capped(sorted(int(p) for p in group["dst_port"].unique()))
        dst_ips, dst_ips_truncated = _capped(sorted(group["dst_ip"].unique()))
        evidence = {
            "business_hours": hours,
            "timezone": config.timezone,
            "local_date": local_date.isoformat(),
            "event_count": int(len(group)),
            "first_seen": format_utc(start),
            "last_seen": format_utc(end),
            "local_times": [t.strftime("%H:%M:%S") for t in group["local_time"].head(MAX_LISTED_ITEMS)],
            "destination_ips": dst_ips,
            "destination_ips_truncated": dst_ips_truncated,
            "destination_ports": ports,
            "destination_ports_truncated": ports_truncated,
            "denied_event_count": int((group["action"] == "DENY").sum()),
            "total_bytes": int(group["bytes_sent"].sum()),
            "source_rows": [int(r) for r in group["source_row"].head(MAX_LISTED_ITEMS)],
            "note": "Off-hours activity is not proof of malicious behavior.",
        }
        alerts.append(
            Alert(
                alert_id=make_alert_id(RULE_OFF_HOURS, str(src_ip), start, end),
                rule_id=RULE_OFF_HOURS,
                rule_name=RULE_NAMES[RULE_OFF_HOURS],
                timestamp=start.to_pydatetime(),
                src_ip=str(src_ip),
                severity=Severity.LOW,
                summary=(
                    f"{src_ip} made {len(group)} connection(s) outside business hours "
                    f"({hours}) on {local_date.isoformat()}."
                ),
                evidence=evidence,
                recommended_actions=RECOMMENDATIONS[RULE_OFF_HOURS],
            )
        )
    return alerts


def run_detection(
    records: pd.DataFrame, config: DetectionConfig = DEFAULT_DETECTION_CONFIG
) -> list[Alert]:
    """Run all detection rules and return alerts sorted by time, then rule ID.

    Args:
        records: Normalized records from :mod:`netsentry.validation`.
        config: Detection thresholds and windows.
    """
    if records.empty:
        return []
    ordered = records.sort_values(["timestamp", "source_row"], kind="stable").reset_index(drop=True)
    alerts = [
        *detect_port_scans(ordered, config),
        *detect_high_transfers(ordered, config),
        *detect_off_hours(ordered, config),
    ]
    alerts.sort(key=lambda a: (a.timestamp, a.rule_id, a.src_ip))
    logger.info("Detection produced %d alert(s) from %d record(s)", len(alerts), len(records))
    return alerts
