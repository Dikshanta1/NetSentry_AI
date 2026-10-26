"""Tests for the rule-based detection engine."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import time, timedelta

import pytest

from config.settings import MIB, SAMPLE_DATA_PATH, DetectionConfig
from netsentry.detection import (
    RULE_HIGH_TRANSFER,
    RULE_OFF_HOURS,
    RULE_PORT_SCAN,
    run_detection,
)
from netsentry.schemas import Severity
from netsentry.validation import empty_records_frame, load_csv_file

from conftest import BASE_TIME, minutes, raw_row, to_records


def _by_rule(alerts, rule_id):  # type: ignore[no-untyped-def]
    return [a for a in alerts if a.rule_id == rule_id]


# --- general -----------------------------------------------------------------


def test_empty_dataset_produces_no_alerts(config: DetectionConfig) -> None:
    assert run_detection(empty_records_frame(), config) == []


def test_normal_traffic_produces_no_alerts(config: DetectionConfig) -> None:
    rows = [raw_row(ts=BASE_TIME + minutes(i), dst_port=443) for i in range(30)]
    assert run_detection(to_records(rows), config) == []


def test_alerts_have_required_fields_and_are_immutable(scan_rows, config) -> None:  # type: ignore[no-untyped-def]
    alert = run_detection(to_records(scan_rows), config)[0]
    data = alert.to_dict()
    for key in ("alert_id", "rule_id", "rule_name", "timestamp", "src_ip", "severity",
                "summary", "evidence", "recommended_actions"):
        assert data[key], key
    with pytest.raises(FrozenInstanceError):
        alert.severity = Severity.LOW  # type: ignore[misc]


def test_alert_ids_are_deterministic(scan_rows, config) -> None:  # type: ignore[no-untyped-def]
    first = [a.alert_id for a in run_detection(to_records(scan_rows), config)]
    second = [a.alert_id for a in run_detection(to_records(scan_rows), config)]
    assert first == second


# --- NET-001 port scan -------------------------------------------------------


def test_port_scan_detected_with_evidence(scan_rows, config) -> None:  # type: ignore[no-untyped-def]
    alerts = _by_rule(run_detection(to_records(scan_rows), config), RULE_PORT_SCAN)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.severity is Severity.HIGH
    assert alert.src_ip == "203.0.113.50"
    ev = alert.evidence
    assert ev["threshold_unique_ports"] == 15
    assert ev["observed_unique_ports"] == 20
    assert ev["window_seconds"] == 300
    assert ev["destination_ports"] == list(range(1000, 1020))
    # Threshold first reached on the 15th event (index 14).
    assert alert.timestamp == BASE_TIME + timedelta(seconds=140)


def test_port_scan_threshold_boundary(config: DetectionConfig) -> None:
    def rows(n: int) -> list[dict[str, str]]:
        return [raw_row(ts=BASE_TIME + timedelta(seconds=5 * i), dst_port=2000 + i) for i in range(n)]

    assert _by_rule(run_detection(to_records(rows(14)), config), RULE_PORT_SCAN) == []
    assert len(_by_rule(run_detection(to_records(rows(15)), config), RULE_PORT_SCAN)) == 1


def test_repeated_ports_do_not_count_as_unique(config: DetectionConfig) -> None:
    rows = [raw_row(ts=BASE_TIME + timedelta(seconds=i), dst_port=1000 + i % 10) for i in range(100)]
    assert _by_rule(run_detection(to_records(rows), config), RULE_PORT_SCAN) == []


def test_ports_spread_beyond_window_do_not_trigger(config: DetectionConfig) -> None:
    # 20 unique ports, but one per minute: at most 6 fall in any 5-minute window.
    rows = [raw_row(ts=BASE_TIME + minutes(i), dst_port=3000 + i) for i in range(20)]
    assert _by_rule(run_detection(to_records(rows), config), RULE_PORT_SCAN) == []


def test_port_scan_overlapping_windows_deduplicated(config: DetectionConfig) -> None:
    # 60 unique ports over ~10 minutes: many overlapping triggering windows -> one alert.
    rows = [raw_row(ts=BASE_TIME + timedelta(seconds=10 * i), dst_port=4000 + i) for i in range(60)]
    alerts = _by_rule(run_detection(to_records(rows), config), RULE_PORT_SCAN)
    assert len(alerts) == 1
    assert alerts[0].evidence["episode_event_count"] == 60
    assert alerts[0].evidence["episode_unique_ports"] == 60


def test_separate_scan_episodes_produce_separate_alerts(scan_rows, config) -> None:  # type: ignore[no-untyped-def]
    later = [
        raw_row(ts=BASE_TIME + minutes(60) + timedelta(seconds=10 * i), src_ip="203.0.113.50",
                dst_port=5000 + i)
        for i in range(16)
    ]
    alerts = _by_rule(run_detection(to_records(scan_rows + later), config), RULE_PORT_SCAN)
    assert len(alerts) == 2
    assert len({a.alert_id for a in alerts}) == 2


def test_multiple_sources_analyzed_independently(config: DetectionConfig) -> None:
    # Two sources each touch 10 unique ports in the same window: 20 combined, but
    # neither reaches the per-source threshold of 15.
    rows = [
        raw_row(ts=BASE_TIME + timedelta(seconds=i), src_ip=src, dst_port=6000 + i)
        for src in ("192.0.2.1", "192.0.2.2")
        for i in range(10)
    ]
    assert _by_rule(run_detection(to_records(rows), config), RULE_PORT_SCAN) == []

    scanner = [raw_row(ts=BASE_TIME + timedelta(seconds=i), src_ip="192.0.2.3", dst_port=7000 + i)
               for i in range(15)]
    alerts = _by_rule(run_detection(to_records(rows + scanner), config), RULE_PORT_SCAN)
    assert [a.src_ip for a in alerts] == ["192.0.2.3"]


def test_port_scan_threshold_is_configurable(scan_rows) -> None:  # type: ignore[no-untyped-def]
    strict = DetectionConfig(port_scan_unique_ports_threshold=25)
    assert _by_rule(run_detection(to_records(scan_rows), strict), RULE_PORT_SCAN) == []


# --- NET-002 high transfer ---------------------------------------------------


def _transfer_rows(sizes: list[int], src: str = "192.0.2.25", spacing_s: int = 30):
    return [
        raw_row(ts=BASE_TIME + timedelta(seconds=spacing_s * i), src_ip=src, bytes_sent=size)
        for i, size in enumerate(sizes)
    ]


def test_high_transfer_detected_with_evidence(config: DetectionConfig) -> None:
    alerts = _by_rule(run_detection(to_records(_transfer_rows([20 * MIB] * 3)), config),
                      RULE_HIGH_TRANSFER)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.severity is Severity.MEDIUM
    ev = alert.evidence
    assert ev["observed_bytes"] == 60 * MIB
    assert ev["threshold_bytes"] == 50 * MIB
    assert ev["event_count"] == 3
    assert ev["window_seconds"] == 300


def test_high_transfer_threshold_is_inclusive(config: DetectionConfig) -> None:
    at = _transfer_rows([25 * MIB, 25 * MIB])
    below = _transfer_rows([25 * MIB, 25 * MIB - 1])
    assert len(_by_rule(run_detection(to_records(at), config), RULE_HIGH_TRANSFER)) == 1
    assert _by_rule(run_detection(to_records(below), config), RULE_HIGH_TRANSFER) == []


def test_high_transfer_outside_window_not_summed(config: DetectionConfig) -> None:
    rows = _transfer_rows([30 * MIB, 30 * MIB], spacing_s=301)
    assert _by_rule(run_detection(to_records(rows), config), RULE_HIGH_TRANSFER) == []


def test_high_transfer_overlapping_windows_deduplicated(config: DetectionConfig) -> None:
    # Sustained 30 MiB every 30s for 10 minutes: every window triggers, one alert.
    rows = _transfer_rows([30 * MIB] * 20)
    alerts = _by_rule(run_detection(to_records(rows), config), RULE_HIGH_TRANSFER)
    assert len(alerts) == 1
    assert alerts[0].evidence["episode_event_count"] == 20
    assert alerts[0].evidence["episode_total_bytes"] == 600 * MIB


def test_high_transfer_sources_not_combined(config: DetectionConfig) -> None:
    rows = _transfer_rows([30 * MIB], src="192.0.2.1") + _transfer_rows([30 * MIB], src="192.0.2.2")
    assert _by_rule(run_detection(to_records(rows), config), RULE_HIGH_TRANSFER) == []


# --- NET-003 off-hours -------------------------------------------------------


def test_off_hours_detected_and_grouped_per_source_and_day(config: DetectionConfig) -> None:
    day = BASE_TIME.replace(hour=0)
    rows = [
        raw_row(ts=day.replace(hour=2), src_ip="192.0.2.77"),
        raw_row(ts=day.replace(hour=3), src_ip="192.0.2.77"),
        raw_row(ts=day.replace(hour=22), src_ip="192.0.2.78"),
        raw_row(ts=day.replace(hour=12), src_ip="192.0.2.79"),  # business hours
    ]
    alerts = _by_rule(run_detection(to_records(rows), config), RULE_OFF_HOURS)
    assert [(a.src_ip, a.evidence["event_count"]) for a in alerts] == [
        ("192.0.2.77", 2),
        ("192.0.2.78", 1),
    ]
    assert all(a.severity is Severity.LOW for a in alerts)
    assert "not proof" in alerts[0].evidence["note"]


def test_business_hours_boundaries(config: DetectionConfig) -> None:
    day = BASE_TIME.replace(hour=0)
    cases = {
        time(8, 59, 59): True,
        time(9, 0, 0): False,  # start inclusive
        time(17, 59, 59): False,
        time(18, 0, 0): True,  # end exclusive
    }
    for t, expected in cases.items():
        ts = day.replace(hour=t.hour, minute=t.minute, second=t.second)
        alerts = _by_rule(run_detection(to_records([raw_row(ts=ts)]), config), RULE_OFF_HOURS)
        assert bool(alerts) is expected, t


def test_off_hours_respects_configured_timezone() -> None:
    # 10:00 UTC is 06:00 in New York (EDT, UTC-4, on 2026-10-26).
    rows = [raw_row(ts=BASE_TIME)]
    assert _by_rule(run_detection(to_records(rows), DetectionConfig()), RULE_OFF_HOURS) == []
    ny = DetectionConfig(timezone="America/New_York")
    alerts = _by_rule(run_detection(to_records(rows), ny), RULE_OFF_HOURS)
    assert len(alerts) == 1
    assert alerts[0].evidence["local_times"] == ["06:00:00"]


def test_invalid_config_rejected() -> None:
    with pytest.raises(ValueError):
        DetectionConfig(timezone="Mars/Olympus")
    with pytest.raises(ValueError):
        DetectionConfig(business_hours_start=time(18), business_hours_end=time(9))


# --- bundled dataset ----------------------------------------------------------


def test_bundled_dataset_triggers_every_rule() -> None:
    alerts = run_detection(load_csv_file(SAMPLE_DATA_PATH).records)
    rules = {a.rule_id for a in alerts}
    assert rules == {RULE_PORT_SCAN, RULE_HIGH_TRANSFER, RULE_OFF_HOURS}
    assert [a.src_ip for a in _by_rule(alerts, RULE_PORT_SCAN)] == ["203.0.113.50"]
    assert [a.src_ip for a in _by_rule(alerts, RULE_HIGH_TRANSFER)] == ["192.0.2.25"]
