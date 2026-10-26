"""Validation and normalization of untrusted connection-log CSV data.

Every uploaded value is treated as untrusted text. Rows that fail any check
are rejected with a row-specific message; they are never "repaired" into
valid records. Valid rows are normalized (UTC timestamps, canonical IP
strings, uppercase protocol/action, integer ports and byte counts).

This module has no UI dependencies so it can be tested and reused directly.
"""

from __future__ import annotations

import io
import ipaddress
import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from config.settings import DEFAULT_UPLOAD_LIMITS, UploadLimits
from netsentry.schemas import (
    ALLOWED_ACTIONS,
    ALLOWED_PROTOCOLS,
    NORMALIZED_COLUMNS,
    REQUIRED_COLUMNS,
    RowError,
)

logger = logging.getLogger(__name__)

MAX_BYTES_SENT: int = 10**15  # sanity cap so aggregated sums stay well inside int64
_UNSIGNED_INT = re.compile(r"\+?\d{1,20}")
_NEGATIVE_INT = re.compile(r"-\d+")


@dataclass
class ValidationResult:
    """Outcome of validating a CSV file or DataFrame.

    Attributes:
        records: Normalized DataFrame containing only valid rows.
        errors: Row-specific (or file-level) problems, possibly truncated.
        total_rows: Number of data rows read from the input.
        fatal: True when the file as a whole could not be accepted
            (unreadable, too large, missing columns...). ``records`` is then empty.
        total_error_count: Number of errors found before truncation.
    """

    records: pd.DataFrame
    errors: list[RowError] = field(default_factory=list)
    total_rows: int = 0
    fatal: bool = False
    total_error_count: int = 0

    @property
    def is_valid(self) -> bool:
        """True when the input was accepted and every row passed validation."""
        return not self.fatal and self.total_error_count == 0

    @property
    def rejected_row_count(self) -> int:
        """Number of data rows that were rejected."""
        return 0 if self.fatal else self.total_rows - len(self.records)


def empty_records_frame() -> pd.DataFrame:
    """Return an empty DataFrame with the normalized schema and dtypes."""
    return pd.DataFrame(
        {
            "timestamp": pd.Series([], dtype="datetime64[ns, UTC]"),
            "src_ip": pd.Series([], dtype=object),
            "dst_ip": pd.Series([], dtype=object),
            "src_port": pd.Series([], dtype="int64"),
            "dst_port": pd.Series([], dtype="int64"),
            "protocol": pd.Series([], dtype=object),
            "bytes_sent": pd.Series([], dtype="int64"),
            "action": pd.Series([], dtype=object),
            "source_row": pd.Series([], dtype="int64"),
        }
    )


def _fatal(message: str) -> ValidationResult:
    return ValidationResult(
        records=empty_records_frame(),
        errors=[RowError(row=None, column=None, message=message)],
        fatal=True,
        total_error_count=1,
    )


def _preview(value: str, limit: int = 40) -> str:
    """Shorten a raw value for inclusion in an error message."""
    value = value.replace("\n", " ").replace("\r", " ")
    return value if len(value) <= limit else value[:limit] + "…"


def parse_timestamp(value: str) -> datetime:
    """Parse an ISO 8601 timestamp into a UTC-aware datetime.

    Timestamps without an offset are interpreted as UTC (documented behavior).

    Raises:
        ValueError: if the value is empty, has no time component or is not ISO 8601.
    """
    text = value.strip()
    if not text:
        raise ValueError("timestamp is empty")
    if "T" not in text and " " not in text:
        raise ValueError(
            f"'{_preview(text)}' has no time component (expected e.g. 2026-10-26T10:00:00Z)"
        )
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise ValueError(
            f"'{_preview(text)}' is not a valid ISO 8601 timestamp "
            "(expected e.g. 2026-10-26T10:00:00Z)"
        ) from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_ip(value: str) -> str:
    """Validate an IPv4/IPv6 address and return its canonical string form.

    Raises:
        ValueError: if the value is not a valid IP address.
    """
    text = value.strip()
    if not text:
        raise ValueError("IP address is empty")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        raise ValueError(f"'{_preview(text)}' is not a valid IPv4 or IPv6 address") from None


def _parse_non_negative_int(value: str, label: str) -> int:
    text = value.strip()
    if not text:
        raise ValueError(f"{label} is empty")
    if _NEGATIVE_INT.fullmatch(text):
        raise ValueError(f"{label} must not be negative (got {_preview(text)})")
    if not _UNSIGNED_INT.fullmatch(text):
        raise ValueError(f"{label} must be a whole number (got '{_preview(text)}')")
    return int(text)


def parse_port(value: str) -> int:
    """Validate a TCP/UDP port number (integer between 1 and 65535).

    Raises:
        ValueError: if the value is not an integer in range.
    """
    port = _parse_non_negative_int(value, "port")
    if not 1 <= port <= 65535:
        raise ValueError(f"port must be between 1 and 65535 (got {port})")
    return port


def parse_bytes_sent(value: str) -> int:
    """Validate ``bytes_sent`` as a non-negative integer.

    Raises:
        ValueError: if the value is negative, non-integer or implausibly large.
    """
    amount = _parse_non_negative_int(value, "bytes_sent")
    if amount > MAX_BYTES_SENT:
        raise ValueError(f"bytes_sent exceeds the supported maximum of {MAX_BYTES_SENT}")
    return amount


def _parse_choice(value: str, allowed: frozenset[str], label: str) -> str:
    normalized = value.strip().upper()
    if normalized not in allowed:
        options = ", ".join(sorted(allowed))
        raise ValueError(f"{label} '{_preview(value.strip())}' is not one of: {options}")
    return normalized


def validate_row(
    row: Mapping[str, Any], row_number: int
) -> tuple[dict[str, Any] | None, list[RowError]]:
    """Validate and normalize one raw record.

    Args:
        row: Mapping of column name to raw (string) value.
        row_number: 1-based CSV line number used in error messages.

    Returns:
        ``(record, [])`` when valid, otherwise ``(None, errors)`` listing every
        problem found in the row.
    """
    parsers = {
        "timestamp": parse_timestamp,
        "src_ip": parse_ip,
        "dst_ip": parse_ip,
        "src_port": parse_port,
        "dst_port": parse_port,
        "protocol": lambda v: _parse_choice(v, ALLOWED_PROTOCOLS, "protocol"),
        "bytes_sent": parse_bytes_sent,
        "action": lambda v: _parse_choice(v, ALLOWED_ACTIONS, "action"),
    }
    record: dict[str, Any] = {}
    errors: list[RowError] = []
    for column, parser in parsers.items():
        raw = row.get(column, "")
        raw_text = "" if raw is None else str(raw)
        try:
            record[column] = parser(raw_text)
        except ValueError as exc:
            errors.append(RowError(row=row_number, column=column, message=str(exc)))
    if errors:
        return None, errors
    record["source_row"] = row_number
    return record, []


def validate_dataframe(
    raw: pd.DataFrame, limits: UploadLimits = DEFAULT_UPLOAD_LIMITS
) -> ValidationResult:
    """Validate a raw DataFrame of string values against the input schema.

    Extra columns are ignored. Missing required columns or too many rows make
    the whole input fatal; otherwise invalid rows are rejected individually.
    """
    raw = raw.rename(columns=lambda c: str(c).strip().lower())
    missing = [c for c in REQUIRED_COLUMNS if c not in raw.columns]
    if missing:
        return _fatal(
            f"Missing required column(s): {', '.join(missing)}. "
            f"Expected header: {','.join(REQUIRED_COLUMNS)}"
        )
    if len(raw) > limits.max_rows:
        return _fatal(f"File has {len(raw):,} rows; the limit is {limits.max_rows:,}.")

    valid: list[dict[str, Any]] = []
    errors: list[RowError] = []
    error_count = 0
    for offset, row in enumerate(raw[list(REQUIRED_COLUMNS)].to_dict("records")):
        record, row_errors = validate_row(row, row_number=offset + 2)  # header is line 1
        if record is not None:
            valid.append(record)
            continue
        error_count += len(row_errors)
        remaining = limits.max_errors_reported - len(errors)
        if remaining > 0:
            errors.extend(row_errors[:remaining])

    if error_count:
        logger.info("Validation rejected %d of %d rows", len(raw) - len(valid), len(raw))
    return ValidationResult(
        records=_to_frame(valid),
        errors=errors,
        total_rows=len(raw),
        total_error_count=error_count,
    )


def _to_frame(records: list[dict[str, Any]]) -> pd.DataFrame:
    if not records:
        return empty_records_frame()
    frame = pd.DataFrame.from_records(records, columns=list(NORMALIZED_COLUMNS))
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True)
    for column in ("src_port", "dst_port", "bytes_sent", "source_row"):
        frame[column] = frame[column].astype("int64")
    for column in ("src_ip", "dst_ip", "protocol", "action"):
        frame[column] = frame[column].astype(object)
    return frame.sort_values(["timestamp", "source_row"], kind="stable").reset_index(drop=True)


def validate_csv_bytes(
    data: bytes, limits: UploadLimits = DEFAULT_UPLOAD_LIMITS
) -> ValidationResult:
    """Validate raw CSV bytes (for example, from an upload).

    The size limit is enforced before parsing. Parsing errors are converted to
    a fatal :class:`ValidationResult` rather than raised.
    """
    if len(data) > limits.max_upload_bytes:
        return _fatal(
            f"File is {len(data):,} bytes; the limit is {limits.max_upload_bytes:,} bytes."
        )
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return _fatal("File is not valid UTF-8 text.")
    if not text.strip():
        return _fatal("File is empty.")
    try:
        raw = pd.read_csv(
            io.StringIO(text),
            dtype=str,
            keep_default_na=False,
            na_filter=False,
            skipinitialspace=True,
        )
    except pd.errors.EmptyDataError:
        return _fatal("File is empty.")
    except pd.errors.ParserError as exc:
        logger.warning("CSV parser error: %s", exc)
        return _fatal(f"File could not be parsed as CSV: {_preview(str(exc), 200)}")
    return validate_dataframe(raw, limits)


def load_csv_file(path: Path, limits: UploadLimits = DEFAULT_UPLOAD_LIMITS) -> ValidationResult:
    """Read and validate a CSV file from disk."""
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        logger.error("Could not read %s: %s", path, exc)
        return _fatal(f"Could not read file '{Path(path).name}'.")
    return validate_csv_bytes(data, limits)
