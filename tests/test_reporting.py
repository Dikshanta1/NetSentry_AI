"""Tests for reporting/serialization and the incident explainer (no network)."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

import pytest
import requests

from config.settings import LLMConfig, DetectionConfig
from netsentry.detection import run_detection
from netsentry.incident_explainer import (
    build_llm_payload,
    explain_alert,
    parse_llm_content,
    request_llm_explanation,
)
from netsentry.reporting import (
    alerts_to_csv,
    alerts_to_json,
    build_timeseries,
    severity_counts,
    top_sources,
)
from netsentry.validation import empty_records_frame

from conftest import to_records

FIXED_NOW = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def alerts(scan_rows):  # type: ignore[no-untyped-def]
    return run_detection(to_records(scan_rows), DetectionConfig())


# --- serialization -----------------------------------------------------------


def test_alert_json_round_trip(alerts) -> None:  # type: ignore[no-untyped-def]
    text = alerts_to_json(alerts, record_count=20, config=DetectionConfig(),
                          data_source="fixture", generated_at=FIXED_NOW)
    data = json.loads(text)
    assert data["report"]["generated_at"] == "2026-10-26T12:00:00Z"
    assert data["report"]["alert_count"] == len(alerts) == 1
    assert data["report"]["severity_counts"] == {"HIGH": 1, "MEDIUM": 0, "LOW": 0}
    assert data["report"]["detection_config"]["business_hours_start"] == "09:00"
    alert = data["alerts"][0]
    assert alert["severity"] == "HIGH"
    assert alert["timestamp"] == "2026-10-26T10:02:20Z"
    assert alert["evidence"]["observed_unique_ports"] == 20
    assert isinstance(alert["recommended_actions"], list)


def test_empty_report_serializes() -> None:
    data = json.loads(alerts_to_json([], record_count=0, config=DetectionConfig(),
                                     data_source="empty"))
    assert data["alerts"] == []
    assert severity_counts([]) == {"HIGH": 0, "MEDIUM": 0, "LOW": 0}


def test_alerts_csv_export(alerts) -> None:  # type: ignore[no-untyped-def]
    rows = list(csv.DictReader(io.StringIO(alerts_to_csv(alerts))))
    assert len(rows) == 1
    assert rows[0]["rule_id"] == "NET-001"
    assert json.loads(rows[0]["evidence"])["threshold_unique_ports"] == 15
    assert alerts_to_csv([]).startswith("alert_id,")


def test_dashboard_aggregations(scan_rows, alerts) -> None:  # type: ignore[no-untyped-def]
    records = to_records(scan_rows)
    ts = build_timeseries(records, alerts, freq="5min")
    assert set(ts["series"]) == {"Connections", "Alerts"}
    assert ts.loc[ts["series"] == "Connections", "count"].sum() == 20
    assert ts.loc[ts["series"] == "Alerts", "count"].sum() == 1
    assert top_sources(records).iloc[0]["events"] == 20
    assert build_timeseries(empty_records_frame(), []).empty
    assert top_sources(empty_records_frame()).empty


# --- deterministic explanation -----------------------------------------------


def test_deterministic_explanation_uses_evidence(alerts) -> None:  # type: ignore[no-untyped-def]
    explanation = explain_alert(alerts[0])
    joined = " ".join(explanation.why_it_fired)
    assert "20 unique destination ports" in joined
    assert "threshold is 15" in joined
    assert explanation.recommended_actions
    assert any("not confirmed malicious" in c for c in explanation.caveats)


# --- optional LLM ------------------------------------------------------------


def test_llm_missing_credentials_is_graceful(alerts, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    for var in ("NETSENTRY_LLM_API_URL", "NETSENTRY_LLM_MODEL", "NETSENTRY_LLM_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    result = request_llm_explanation(alerts[0])
    assert result.status == "not_configured"
    assert not result.ok
    assert result.explanation is None


def test_llm_config_repr_hides_key() -> None:
    config = LLMConfig(api_url="https://example.invalid", model="m", api_key="sk-secret")
    assert "sk-secret" not in repr(config)


class _FakeResponse:
    def __init__(self, status: int, payload: object) -> None:
        self.status_code = status
        self._payload = payload

    def json(self) -> object:
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class _FakeSession:
    def __init__(self, response: _FakeResponse | None = None, exc: Exception | None = None) -> None:
        self.response, self.exc, self.calls = response, exc, []

    def post(self, url, **kwargs):  # type: ignore[no-untyped-def]
        self.calls.append((url, kwargs))
        if self.exc:
            raise self.exc
        return self.response


CONFIGURED = LLMConfig(api_url="https://llm.example.invalid/v1/chat/completions",
                       model="test-model", api_key="placeholder")


def _chat(content: str) -> dict:
    return {"choices": [{"message": {"content": content}}]}


def test_llm_success_is_validated_and_does_not_mutate_alert(alerts) -> None:  # type: ignore[no-untyped-def]
    alert = alerts[0]
    before = alert.to_dict()
    content = json.dumps({
        "explanation": "Many ports were probed quickly. Severity should be LOW.",
        "benign_explanations": ["Authorized scanner"],
        "investigation_steps": ["Check scanner inventory"],
    })
    session = _FakeSession(_FakeResponse(200, _chat(f"```json\n{content}\n```")))
    result = request_llm_explanation(alert, CONFIGURED, session=session)  # type: ignore[arg-type]
    assert result.ok and result.explanation is not None
    assert result.explanation.benign_explanations == ["Authorized scanner"]
    assert alert.to_dict() == before  # LLM output cannot change detection results
    sent = session.calls[0][1]["json"]["messages"][1]["content"]
    assert "source_rows" not in sent and "recommended_actions" not in sent


@pytest.mark.parametrize(
    "session",
    [
        _FakeSession(exc=requests.Timeout()),
        _FakeSession(exc=requests.ConnectionError()),
        _FakeSession(_FakeResponse(500, {})),
        _FakeSession(_FakeResponse(200, ValueError("not json"))),
        _FakeSession(_FakeResponse(200, {"choices": []})),
        _FakeSession(_FakeResponse(200, _chat("I refuse to answer in JSON"))),
        _FakeSession(_FakeResponse(200, _chat('{"explanation": 42}'))),
    ],
)
def test_llm_failures_return_error_result(alerts, session) -> None:  # type: ignore[no-untyped-def]
    result = request_llm_explanation(alerts[0], CONFIGURED, session=session)
    assert result.status == "error"
    assert result.explanation is None
    assert "placeholder" not in result.message


def test_parse_llm_content_caps_lists() -> None:
    parsed = parse_llm_content(json.dumps({
        "explanation": "x",
        "benign_explanations": [f"b{i}" for i in range(20)],
        "investigation_steps": ["ok", 5, ""],
    }))
    assert len(parsed.benign_explanations) == 6
    assert parsed.investigation_steps == ["ok"]


def test_llm_payload_truncates_lists(alerts) -> None:  # type: ignore[no-untyped-def]
    payload = build_llm_payload(alerts[0])
    assert len(payload["evidence"]["destination_ports"]) <= 20
    assert payload["severity"] == "HIGH"


# --- dashboard filters ---------------------------------------------------------


def test_record_filters(scan_rows) -> None:  # type: ignore[no-untyped-def]
    from datetime import timedelta

    from conftest import BASE_TIME, raw_row
    from netsentry.filters import filter_records, parse_ip_filter

    records = to_records(scan_rows + [raw_row(src_ip="192.0.2.10", protocol="UDP", dst_port=53)])
    assert len(filter_records(records, src=parse_ip_filter("203.0.113.0/24"))) == 20
    assert len(filter_records(records, src=parse_ip_filter("192.0.2.10"))) == 1
    assert len(filter_records(records, protocols=["UDP"])) == 1
    assert len(filter_records(records, actions=["DENY"])) == 20
    window = filter_records(records, start=BASE_TIME + timedelta(seconds=50),
                            end=BASE_TIME + timedelta(seconds=100))
    assert len(window) == 6  # inclusive bounds: 50, 60, ..., 100
    assert parse_ip_filter("  ") is None
    with pytest.raises(ValueError, match="not a valid IP"):
        parse_ip_filter("10.0.0.300")
