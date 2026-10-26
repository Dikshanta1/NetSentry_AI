"""Headless smoke tests for the Streamlit UI (no browser, no network)."""

from __future__ import annotations

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

APP_PATH = str(Path(__file__).resolve().parent.parent / "app.py")
PAGES = ("Overview", "Traffic Explorer", "Security Alerts", "Incident Explainer", "Data Management")


@pytest.fixture
def app(monkeypatch) -> AppTest:  # type: ignore[no-untyped-def]
    for var in ("NETSENTRY_LLM_API_URL", "NETSENTRY_LLM_MODEL", "NETSENTRY_LLM_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    at = AppTest.from_file(APP_PATH, default_timeout=30)
    at.run()
    return at


@pytest.mark.parametrize("page", PAGES)
def test_every_page_renders_without_exceptions(app: AppTest, page: str) -> None:
    app.sidebar.radio[0].set_value(page).run()
    assert not app.exception, [e.value for e in app.exception]
    assert app.subheader[0].value == page


def test_overview_shows_bundled_data_metrics(app: AppTest) -> None:
    metrics = {m.label: m.value for m in app.metric}
    assert metrics["Connection records"] == "279"
    assert metrics["Alerts"] == "5"
    assert any("synthetic" in w.value for w in app.warning)


def test_invalid_ip_filter_shows_error(app: AppTest) -> None:
    app.sidebar.radio[0].set_value("Traffic Explorer").run()
    app.text_input[0].set_value("10.0.0.999").run()
    assert not app.exception
    assert any("not a valid IP" in e.value for e in app.error)


def test_explainer_without_llm_still_explains(app: AppTest) -> None:
    app.sidebar.radio[0].set_value("Incident Explainer").run()
    assert not app.exception
    assert any("disabled" in i.value for i in app.info)
    assert any("Why it fired" in m.value for m in app.markdown)
