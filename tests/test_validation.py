"""Tests for input validation and normalization."""

from __future__ import annotations

from datetime import timezone

import pandas as pd

from config.settings import SAMPLE_DATA_PATH, UploadLimits
from netsentry.validation import load_csv_file, validate_csv_bytes, validate_dataframe

from conftest import raw_row

HEADER = "timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes_sent,action\n"
VALID_LINE = "2026-10-26T10:00:00Z,192.0.2.10,198.51.100.20,51000,443,TCP,1500,ALLOW\n"


def _errors_for(**overrides: object) -> list[str]:
    result = validate_dataframe(pd.DataFrame([raw_row(**overrides)], dtype=str))  # type: ignore[arg-type]
    assert len(result.records) == 0, "invalid row must not be accepted"
    return [str(e) for e in result.errors]


def test_valid_record_is_normalized() -> None:
    result = validate_csv_bytes(
        (HEADER + " 2026-10-26T10:00:00Z, 192.0.2.10,198.51.100.20,51000,443,tcp,1500,allow\n").encode()
    )
    assert result.is_valid
    row = result.records.iloc[0]
    assert row["timestamp"].tzinfo is not None
    assert row["timestamp"].tz_convert(timezone.utc).hour == 10
    assert row["protocol"] == "TCP"
    assert row["action"] == "ALLOW"
    assert row["src_ip"] == "192.0.2.10"
    assert row["dst_port"] == 443
    assert row["source_row"] == 2


def test_offset_timestamp_is_converted_to_utc() -> None:
    result = validate_csv_bytes(
        (HEADER + "2026-10-26T12:00:00+02:00,192.0.2.10,198.51.100.20,51000,443,TCP,1,ALLOW\n").encode()
    )
    assert result.is_valid
    assert result.records.iloc[0]["timestamp"] == pd.Timestamp("2026-10-26T10:00:00Z")


def test_ipv6_is_accepted_and_canonicalized() -> None:
    result = validate_dataframe(pd.DataFrame([raw_row(src_ip="2001:DB8:0:0::1")], dtype=str))
    assert result.is_valid
    assert result.records.iloc[0]["src_ip"] == "2001:db8::1"


def test_invalid_ip_addresses_rejected() -> None:
    assert any("src_ip" in e and "not a valid" in e for e in _errors_for(src_ip="192.0.2.999"))
    assert any("dst_ip" in e for e in _errors_for(dst_ip="not-an-ip"))
    assert any("IP address is empty" in e for e in _errors_for(src_ip=""))


def test_invalid_ports_rejected() -> None:
    assert any("between 1 and 65535" in e for e in _errors_for(dst_port=0))
    assert any("between 1 and 65535" in e for e in _errors_for(dst_port=70000))
    assert any("whole number" in e for e in _errors_for(src_port="443.5"))
    assert any("whole number" in e for e in _errors_for(src_port="http"))
    assert any("must not be negative" in e for e in _errors_for(dst_port=-1))


def test_negative_bytes_rejected() -> None:
    errors = _errors_for(bytes_sent=-10)
    assert errors == ["Row 2, column 'bytes_sent': bytes_sent must not be negative (got -10)"]


def test_zero_bytes_is_valid() -> None:
    assert validate_dataframe(pd.DataFrame([raw_row(bytes_sent=0)], dtype=str)).is_valid


def test_invalid_timestamps_rejected() -> None:
    for bad in ("yesterday", "2026-13-01T00:00:00Z", "2026-10-26", ""):
        result = validate_csv_bytes(
            (HEADER + f"{bad},192.0.2.10,198.51.100.20,51000,443,TCP,1,ALLOW\n").encode()
        )
        assert not result.is_valid, bad
        assert result.errors[0].column == "timestamp"
        assert result.errors[0].row == 2


def test_invalid_protocol_and_action_rejected() -> None:
    assert any("protocol 'GRE'" in e for e in _errors_for(protocol="GRE"))
    assert any("action 'DROP'" in e for e in _errors_for(action="DROP"))


def test_missing_columns_is_fatal() -> None:
    result = validate_csv_bytes(b"timestamp,src_ip,dst_ip\n2026-10-26T10:00:00Z,192.0.2.1,192.0.2.2\n")
    assert result.fatal
    assert len(result.records) == 0
    message = str(result.errors[0])
    assert "src_port" in message and "action" in message


def test_mixed_rows_keep_valid_and_report_invalid_with_row_numbers() -> None:
    bad = "2026-10-26T10:01:00Z,192.0.2.300,198.51.100.20,51000,99999,TCP,-1,ALLOW\n"
    result = validate_csv_bytes((HEADER + VALID_LINE + bad + VALID_LINE).encode())
    assert not result.fatal
    assert len(result.records) == 2
    assert result.rejected_row_count == 1
    assert {e.row for e in result.errors} == {3}
    assert {e.column for e in result.errors} == {"src_ip", "dst_port", "bytes_sent"}


def test_empty_file_and_header_only() -> None:
    assert validate_csv_bytes(b"").fatal
    header_only = validate_csv_bytes(HEADER.encode())
    assert header_only.is_valid
    assert header_only.records.empty


def test_size_and_row_limits() -> None:
    limits = UploadLimits(max_upload_bytes=100, max_rows=2)
    assert validate_csv_bytes(b"x" * 101, limits).fatal
    too_many = (HEADER + VALID_LINE * 3).encode()
    result = validate_csv_bytes(too_many, UploadLimits(max_rows=2))
    assert result.fatal and "limit is 2" in result.errors[0].message


def test_malformed_csv_and_binary_do_not_raise() -> None:
    assert validate_csv_bytes(b"\xff\xfe\x00garbage").fatal
    result = validate_csv_bytes((HEADER + VALID_LINE + "a,b,c,d,e,f,g,h,i,j,k\n").encode())
    assert result.fatal


def test_error_list_is_capped() -> None:
    bad = "bad,bad,bad,bad,bad,bad,bad,bad\n"
    result = validate_csv_bytes((HEADER + bad * 50).encode(), UploadLimits(max_errors_reported=10))
    assert len(result.errors) == 10
    assert result.total_error_count == 400


def test_bundled_sample_dataset_is_valid() -> None:
    result = load_csv_file(SAMPLE_DATA_PATH)
    assert result.is_valid
    assert len(result.records) >= 200
    assert set(result.records["action"]) == {"ALLOW", "DENY"}
    assert result.records["src_ip"].nunique() > 5
