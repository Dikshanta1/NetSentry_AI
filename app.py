"""NetSentry AI — Streamlit dashboard.

Run with:  streamlit run app.py

The UI only orchestrates: validation, detection, reporting and explanations
live in the ``netsentry`` package and can be used without Streamlit.
"""

from __future__ import annotations

import logging
from datetime import datetime, time, timedelta, timezone
from zoneinfo import available_timezones

import altair as alt
import pandas as pd
import streamlit as st

from config.settings import (
    DEFAULT_UPLOAD_LIMITS,
    MIB,
    SAMPLE_DATA_PATH,
    DetectionConfig,
    LLMConfig,
)
from netsentry.detection import RULE_NAMES, run_detection
from netsentry.filters import filter_records, parse_ip_filter
from netsentry.incident_explainer import explain_alert, request_llm_explanation
from netsentry.reporting import (
    alerts_to_csv,
    alerts_to_dataframe,
    alerts_to_json,
    build_timeseries,
    severity_counts,
    top_sources,
)
from netsentry.schemas import REQUIRED_COLUMNS, Alert
from netsentry.validation import ValidationResult, load_csv_file, validate_csv_bytes

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("netsentry.app")

PAGES = ("Overview", "Traffic Explorer", "Security Alerts", "Incident Explainer", "Data Management")
SEVERITY_COLORS = {"HIGH": "#f43f5e", "MEDIUM": "#f59e0b", "LOW": "#38bdf8"}
SAMPLE_LABEL = "Bundled synthetic sample"

st.set_page_config(page_title="NetSentry AI", page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
      .block-container { padding-top: 2rem; }
      div[data-testid="stMetric"] {
        background: #131c2e; border: 1px solid #1e293b; border-radius: 10px;
        padding: 0.75rem 1rem;
      }
      .ns-badge { display: inline-block; padding: 0.15rem 0.6rem; border-radius: 999px;
        font-weight: 700; font-size: 0.8rem; letter-spacing: 0.04em; color: #0b1220; }
      .ns-HIGH { background: #f43f5e; } .ns-MEDIUM { background: #f59e0b; } .ns-LOW { background: #38bdf8; }
      .ns-panel { border-radius: 10px; padding: 0.9rem 1.1rem; margin-bottom: 0.75rem; }
      .ns-rule { background: rgba(34, 211, 238, 0.07); border-left: 4px solid #22d3ee; }
      .ns-ai { background: rgba(168, 85, 247, 0.08); border-left: 4px solid #a855f7; }
      .ns-subtitle { color: #94a3b8; margin-top: -0.6rem; }
    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------------------------------- state


def _set_dataset(result: ValidationResult, label: str) -> None:
    st.session_state.records = result.records
    st.session_state.source_label = label
    st.session_state.selected_alert = None
    st.session_state.llm_results = {}


def _load_sample() -> None:
    result = load_csv_file(SAMPLE_DATA_PATH)
    if result.fatal:
        st.session_state.load_error = "; ".join(str(e) for e in result.errors)
        return
    _set_dataset(result, SAMPLE_LABEL)


def _init_state() -> None:
    defaults = {
        "page": PAGES[0],
        "selected_alert": None,
        "llm_results": {},
        "pending_upload": None,
        "load_error": None,
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)
    if "records" not in st.session_state:
        _load_sample()


@st.cache_data(show_spinner=False)
def _detect(records: pd.DataFrame, config: DetectionConfig) -> list[Alert]:
    return run_detection(records, config)


def _go_to(page: str, alert_id: str | None = None) -> None:
    st.session_state.page = page
    if alert_id:
        st.session_state.selected_alert = alert_id


# ------------------------------------------------------------------------ helpers


def severity_badge(severity: str) -> str:
    """Return an HTML badge. Only called with validated Severity values."""
    return f'<span class="ns-badge ns-{severity}">{severity}</span>'


def _style_severity(frame: pd.DataFrame):  # type: ignore[no-untyped-def]
    def color(value: str) -> str:
        c = SEVERITY_COLORS.get(value)
        return f"color: {c}; font-weight: 700" if c else ""

    return frame.style.map(color, subset=["severity"])


def _alert_table(alerts: list[Alert]) -> pd.DataFrame:
    frame = alerts_to_dataframe(alerts)
    return frame.drop(columns=["evidence"]) if not frame.empty else frame


def _synthetic_notice() -> None:
    if st.session_state.source_label == SAMPLE_LABEL:
        st.warning(
            "All records currently loaded are **synthetic** and use documentation-only IP "
            "ranges (RFC 5737). They are not real captured traffic.",
            icon="🧪",
        )


def _select_alert(alerts: list[Alert], key: str) -> Alert | None:
    """Alert picker that remembers the selection across pages."""
    if not alerts:
        return None
    ids = [a.alert_id for a in alerts]
    current = st.session_state.selected_alert
    index = ids.index(current) if current in ids else 0
    by_id = {a.alert_id: a for a in alerts}
    chosen = st.selectbox(
        "Select an alert",
        ids,
        index=index,
        key=key,
        format_func=lambda i: f"{i} · {by_id[i].severity.value} · {by_id[i].rule_name} · {by_id[i].src_ip}",
    )
    st.session_state.selected_alert = chosen
    return by_id[chosen]


def _detection_config_sidebar() -> DetectionConfig:
    defaults = DetectionConfig()
    with st.sidebar.expander("Detection thresholds", expanded=False):
        ports = st.number_input("NET-001 unique ports", 1, 1000, defaults.port_scan_unique_ports_threshold)
        scan_window = st.number_input("NET-001 window (minutes)", 1, 120, defaults.port_scan_window_seconds // 60)
        mib = st.number_input("NET-002 bytes threshold (MiB)", 1, 1_000_000, defaults.transfer_bytes_threshold // MIB)
        xfer_window = st.number_input("NET-002 window (minutes)", 1, 120, defaults.transfer_window_seconds // 60)
        start_h, end_h = st.slider("NET-003 business hours", 0, 24, (9, 18))
        zones = sorted(available_timezones())
        tz = st.selectbox("NET-003 timezone", zones, index=zones.index("UTC") if "UTC" in zones else 0)
    try:
        return DetectionConfig(
            port_scan_window_seconds=int(scan_window) * 60,
            port_scan_unique_ports_threshold=int(ports),
            transfer_window_seconds=int(xfer_window) * 60,
            transfer_bytes_threshold=int(mib) * MIB,
            business_hours_start=time(start_h),
            business_hours_end=time(end_h - 1, 59, 59, 999999) if end_h == 24 else time(end_h),
            timezone=tz,
        )
    except ValueError as exc:
        st.sidebar.error(f"Invalid detection settings ({exc}); using defaults.")
        return defaults


# -------------------------------------------------------------------------- pages


def page_overview(records: pd.DataFrame, alerts: list[Alert]) -> None:
    st.subheader("Overview")
    _synthetic_notice()
    counts = severity_counts(alerts)
    top_row, sev_row = st.columns(3), st.columns(3)
    top_row[0].metric("Connection records", f"{len(records):,}")
    top_row[1].metric("Alerts", len(alerts))
    top_row[2].metric("Unique source IPs", records["src_ip"].nunique() if not records.empty else 0)
    sev_row[0].metric("🔴 High", counts["HIGH"])
    sev_row[1].metric("🟠 Medium", counts["MEDIUM"])
    sev_row[2].metric("🔵 Low", counts["LOW"])

    if records.empty:
        st.info("No records loaded. Go to **Data Management** to load the sample or upload a CSV.")
        return

    left, right = st.columns([2, 1])
    with left:
        st.markdown("**Connections per 30 minutes (UTC); vertical lines mark alerts**")
        ts = build_timeseries(records, alerts)
        conn = (
            alt.Chart(ts[ts["series"] == "Connections"])
            .mark_area(opacity=0.35, color="#22d3ee", line={"color": "#22d3ee"})
            .encode(
                x=alt.X("bucket:T", title="Time (UTC)", scale=alt.Scale(type="utc"),
                        axis=alt.Axis(format="%H:%M")),
                y=alt.Y("count:Q", title="Connections"),
                tooltip=[alt.Tooltip("bucket:T", title="bucket start", format="%Y-%m-%d %H:%M"),
                         alt.Tooltip("count:Q", title="connections")],
            )
        )
        layers = [conn]
        if alerts:
            marks = pd.DataFrame(
                {"time": [pd.Timestamp(a.timestamp) for a in alerts],
                 "severity": [a.severity.value for a in alerts],
                 "alert": [f"{a.rule_id} · {a.src_ip}" for a in alerts]}
            )
            layers.append(
                alt.Chart(marks).mark_rule(strokeWidth=2, strokeDash=[4, 3]).encode(
                    x="time:T",
                    color=alt.Color("severity:N", title="Alert severity",
                                    scale=alt.Scale(domain=list(SEVERITY_COLORS),
                                                    range=list(SEVERITY_COLORS.values()))),
                    tooltip=[alt.Tooltip("time:T", format="%Y-%m-%d %H:%M:%S"), "severity:N", "alert:N"],
                )
            )
        st.altair_chart(alt.layer(*layers).properties(height=320), width="stretch")
    with right:
        st.markdown("**Top source IPs by event count**")
        top = top_sources(records, limit=8)
        chart = (
            alt.Chart(top)
            .mark_bar(color="#22d3ee")
            .encode(x=alt.X("events:Q", title="Events"), y=alt.Y("src_ip:N", sort="-x", title=None),
                    tooltip=["src_ip", "events", "bytes_sent", "denied"])
        )
        st.altair_chart(chart, width="stretch")

    st.markdown("**Recent alerts**")
    if not alerts:
        st.success("No alerts with the current thresholds.")
    else:
        recent = sorted(alerts, key=lambda a: a.timestamp, reverse=True)[:10]
        st.dataframe(_style_severity(_alert_table(recent)), hide_index=True, width="stretch")


def page_traffic(records: pd.DataFrame) -> None:
    st.subheader("Traffic Explorer")
    st.caption("Normalized connection records. Each row is one connection event, not necessarily a full session.")
    _synthetic_notice()
    if records.empty:
        st.info("No records loaded. Go to **Data Management** to load data.")
        return

    c1, c2, c3, c4 = st.columns(4)
    src_text = c1.text_input("Source IP or CIDR", placeholder="e.g. 192.0.2.0/24")
    dst_text = c2.text_input("Destination IP or CIDR", placeholder="e.g. 198.51.100.30")
    protocols = c3.multiselect("Protocol", sorted(records["protocol"].unique()))
    actions = c4.multiselect("Action", sorted(records["action"].unique()))

    lo = records["timestamp"].min().to_pydatetime()
    hi = records["timestamp"].max().to_pydatetime()
    start, end = lo, hi
    if lo < hi:
        start, end = st.slider(
            "Time range (UTC)", min_value=lo, max_value=hi, value=(lo, hi),
            step=timedelta(minutes=1), format="YYYY-MM-DD HH:mm",
        )

    problems = []
    try:
        src = parse_ip_filter(src_text)
    except ValueError as exc:
        src, problems = None, problems + [f"Source filter: {exc}"]
    try:
        dst = parse_ip_filter(dst_text)
    except ValueError as exc:
        dst, problems = None, problems + [f"Destination filter: {exc}"]
    for problem in problems:
        st.error(problem)
    if problems:
        return

    filtered = filter_records(
        records, src=src, dst=dst, protocols=protocols, actions=actions,
        start=start.replace(second=0) if lo < hi else None,
        end=(end + timedelta(seconds=59)) if lo < hi else None,
    )
    st.caption(f"Showing {len(filtered):,} of {len(records):,} records.")
    if filtered.empty:
        st.info("No records match these filters. Try widening the time range or clearing an IP filter.")
        return
    st.dataframe(
        filtered.drop(columns=["source_row"]),
        hide_index=True,
        width="stretch",
        column_config={
            "timestamp": st.column_config.DatetimeColumn("timestamp (UTC)", format="YYYY-MM-DD HH:mm:ss"),
            "bytes_sent": st.column_config.NumberColumn("bytes_sent", format="%d"),
        },
    )


def page_alerts(records: pd.DataFrame, alerts: list[Alert], config: DetectionConfig) -> None:
    st.subheader("Security Alerts")
    st.caption("Deterministic, rule-based detections. Alerts are leads for investigation, not verdicts.")
    _synthetic_notice()
    if not alerts:
        st.info("No alerts were generated for the current dataset and thresholds.")
        return

    c1, c2, c3 = st.columns(3)
    sev = c1.multiselect("Severity", ["HIGH", "MEDIUM", "LOW"])
    srcs = c2.multiselect("Source IP", sorted({a.src_ip for a in alerts}))
    rules = c3.multiselect("Rule", sorted({a.rule_id for a in alerts}),
                           format_func=lambda r: f"{r} · {RULE_NAMES.get(r, r)}")
    filtered = [
        a for a in alerts
        if (not sev or a.severity.value in sev)
        and (not srcs or a.src_ip in srcs)
        and (not rules or a.rule_id in rules)
    ]

    st.caption(f"Showing {len(filtered)} of {len(alerts)} alerts.")
    if filtered:
        st.dataframe(_style_severity(alerts_to_dataframe(filtered)), hide_index=True, width="stretch")
    else:
        st.info("No alerts match these filters.")

    d1, d2, _ = st.columns([1, 1, 2])
    d1.download_button(
        "⬇️ Filtered alerts (CSV)", alerts_to_csv(filtered), "netsentry_alerts_filtered.csv",
        "text/csv", disabled=not filtered, width="stretch",
    )
    d2.download_button(
        "⬇️ All alerts report (JSON)",
        alerts_to_json(alerts, record_count=len(records), config=config,
                       data_source=st.session_state.source_label),
        "netsentry_alerts_report.json", "application/json", width="stretch",
    )

    st.divider()
    alert = _select_alert(filtered, key="alerts_select")
    if alert is None:
        return
    st.markdown(f"### {severity_badge(alert.severity.value)} &nbsp; {alert.rule_id} · {alert.rule_name}",
                unsafe_allow_html=True)
    st.write(alert.summary)
    left, right = st.columns([3, 2])
    with left:
        st.markdown("**Structured evidence**")
        st.json(alert.to_dict()["evidence"], expanded=True)
    with right:
        st.markdown("**Recommended actions**")
        for action in alert.recommended_actions:
            st.markdown(f"- {action}")
        st.button("Explain this alert →", on_click=_go_to, args=("Incident Explainer", alert.alert_id))


def page_explainer(alerts: list[Alert]) -> None:
    st.subheader("Incident Explainer")
    if not alerts:
        st.info("There are no alerts to explain for the current dataset.")
        return
    alert = _select_alert(alerts, key="explainer_select")
    if alert is None:
        return
    explanation = explain_alert(alert)

    st.markdown(
        '<div class="ns-panel ns-rule"><b>🛡️ Deterministic explanation</b> — generated from the rule\'s '
        "own evidence. Detection results and severity come only from these rules.</div>",
        unsafe_allow_html=True,
    )
    st.markdown(f"{severity_badge(alert.severity.value)} &nbsp; **{explanation.headline}**", unsafe_allow_html=True)
    st.markdown("**Why it fired**")
    for line in explanation.why_it_fired:
        st.markdown(f"- {line}")
    st.markdown("**Caveats**")
    for line in explanation.caveats:
        st.markdown(f"- {line}")
    st.markdown("**Recommended actions**")
    for line in explanation.recommended_actions:
        st.markdown(f"- {line}")

    st.divider()
    st.markdown(
        '<div class="ns-panel ns-ai"><b>✨ Optional AI explanation — advisory only</b><br/>'
        "Generated by an external language model from this alert's structured evidence. It may be wrong, "
        "is not authoritative, and cannot change the alert, its ID or its severity.</div>",
        unsafe_allow_html=True,
    )
    llm_config = LLMConfig.from_env()
    if not llm_config.is_configured:
        st.info(
            "AI explanations are disabled because no LLM is configured. Set `NETSENTRY_LLM_API_URL`, "
            "`NETSENTRY_LLM_MODEL` and `NETSENTRY_LLM_API_KEY` (see README). Everything else works without it."
        )
        return
    st.caption(f"Model: `{llm_config.model}`. Only this alert's summary and evidence are sent.")
    if st.button("Generate advisory AI explanation", type="primary"):
        with st.spinner("Asking the model…"):
            st.session_state.llm_results[alert.alert_id] = request_llm_explanation(alert, llm_config)
    result = st.session_state.llm_results.get(alert.alert_id)
    if result is None:
        return
    if not result.ok:
        st.warning(f"{result.message} The deterministic explanation above is unaffected.")
        return
    ai = result.explanation
    st.markdown("**Advisory explanation**")
    st.write(ai.explanation)
    if ai.benign_explanations:
        st.markdown("**Possible benign explanations**")
        for line in ai.benign_explanations:
            st.markdown(f"- {line}")
    if ai.investigation_steps:
        st.markdown("**Suggested investigation steps**")
        for line in ai.investigation_steps:
            st.markdown(f"- {line}")


def _show_validation_errors(result: ValidationResult) -> None:
    rows = [
        {"row": str(e.row) if e.row is not None else "whole file", "column": e.column or "—", "problem": e.message}
        for e in result.errors
    ]
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    if result.total_error_count > len(result.errors):
        st.caption(f"Showing the first {len(result.errors)} of {result.total_error_count} problems.")


def page_data() -> None:
    st.subheader("Data Management")
    limits = DEFAULT_UPLOAD_LIMITS
    st.markdown(
        f"**Current dataset:** {st.session_state.source_label} · "
        f"{len(st.session_state.records):,} valid records"
    )
    if st.session_state.load_error:
        st.error(f"Could not load the bundled dataset: {st.session_state.load_error}")

    if st.button("🔄 Load / restore bundled synthetic dataset", type="primary"):
        st.session_state.pending_upload = None
        st.session_state.load_error = None
        _load_sample()
        if not st.session_state.load_error:
            st.success("Bundled synthetic dataset loaded.")

    st.divider()
    st.markdown("**Upload a CSV**")
    st.caption(
        f"Required header: `{','.join(REQUIRED_COLUMNS)}` · max {limits.max_upload_bytes // MIB} MiB · "
        f"max {limits.max_rows:,} rows · timestamps in ISO 8601 (no offset = UTC)."
    )
    st.download_button(
        "Download CSV template", ",".join(REQUIRED_COLUMNS) + "\n"
        "2026-10-26T10:00:00Z,192.0.2.10,198.51.100.20,51000,443,TCP,1500,ALLOW\n",
        "netsentry_template.csv", "text/csv",
    )
    uploaded = st.file_uploader("CSV file", type=["csv"])
    # Validate each uploaded file once, so loading it doesn't re-trigger validation on rerun.
    if uploaded is not None and st.session_state.get("upload_id") != uploaded.file_id:
        st.session_state.upload_id = uploaded.file_id
        result = validate_csv_bytes(uploaded.getvalue(), limits)
        st.session_state.pending_upload = (uploaded.name, result)

    pending = st.session_state.pending_upload
    if pending is None:
        return
    name, result = pending
    if result.fatal:
        st.error(f"`{name}` was rejected and not loaded:")
        _show_validation_errors(result)
        return
    if result.is_valid:
        st.success(f"`{name}`: all {result.total_rows:,} rows passed validation.")
    else:
        st.warning(
            f"`{name}`: {len(result.records):,} of {result.total_rows:,} rows are valid; "
            f"{result.rejected_row_count:,} row(s) rejected. Rejected rows are never auto-corrected."
        )
        _show_validation_errors(result)
    if len(result.records) == 0:
        st.info("There are no valid rows to load.")
        return
    label = "Load this dataset" if result.is_valid else f"Load the {len(result.records):,} valid rows only"
    if st.button(label):
        _set_dataset(result, f"Upload: {name}")
        st.session_state.pending_upload = None
        logger.info("Loaded uploaded dataset with %d records", len(result.records))
        st.rerun()


# --------------------------------------------------------------------------- main


def main() -> None:
    """Render the dashboard."""
    _init_state()
    st.title("🛡️ NetSentry AI")
    st.markdown(
        '<p class="ns-subtitle">Rule-based network threat detection and incident analysis for '
        "defensive, educational log review. Detections are deterministic; AI explanations are "
        "optional and advisory.</p>",
        unsafe_allow_html=True,
    )

    st.sidebar.radio("Navigate", PAGES, key="page")
    config = _detection_config_sidebar()
    st.sidebar.caption(f"Dataset: {st.session_state.source_label}")
    st.sidebar.caption(
        "AI explainer: " + ("configured" if LLMConfig.from_env().is_configured else "not configured (optional)")
    )

    records: pd.DataFrame = st.session_state.records
    alerts = _detect(records, config)
    page = st.session_state.page
    if page == "Overview":
        page_overview(records, alerts)
    elif page == "Traffic Explorer":
        page_traffic(records)
    elif page == "Security Alerts":
        page_alerts(records, alerts, config)
    elif page == "Incident Explainer":
        page_explainer(alerts)
    else:
        page_data()
    st.caption(
        f"NetSentry AI is an educational defensive tool, not a production IDS. "
        f"Rendered {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC."
    )


main()
