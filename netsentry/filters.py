"""Pure filtering helpers used by the dashboard (kept out of the UI for testing)."""

from __future__ import annotations

import ipaddress
from collections.abc import Collection
from datetime import datetime

import pandas as pd

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_ip_filter(text: str) -> IPNetwork | None:
    """Parse a user-entered IP address or CIDR block.

    Returns ``None`` for blank input (meaning "no filter").

    Raises:
        ValueError: with a user-friendly message if the input is not an IP or CIDR.
    """
    value = text.strip()
    if not value:
        return None
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise ValueError(
            f"'{value[:60]}' is not a valid IP address or CIDR block "
            "(examples: 192.0.2.10 or 192.0.2.0/24)."
        ) from None


def _in_network(series: pd.Series, network: IPNetwork) -> pd.Series:
    return series.map(lambda ip: ipaddress.ip_address(ip) in network).astype(bool)


def filter_records(
    records: pd.DataFrame,
    *,
    src: IPNetwork | None = None,
    dst: IPNetwork | None = None,
    protocols: Collection[str] | None = None,
    actions: Collection[str] | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> pd.DataFrame:
    """Filter normalized records. ``None`` or empty arguments mean "no filter".

    ``start`` and ``end`` are inclusive and must be timezone-aware.
    """
    mask = pd.Series(True, index=records.index)
    if src is not None:
        mask &= _in_network(records["src_ip"], src)
    if dst is not None:
        mask &= _in_network(records["dst_ip"], dst)
    if protocols:
        mask &= records["protocol"].isin(list(protocols))
    if actions:
        mask &= records["action"].isin(list(actions))
    if start is not None:
        mask &= records["timestamp"] >= pd.Timestamp(start)
    if end is not None:
        mask &= records["timestamp"] <= pd.Timestamp(end)
    return records.loc[mask]
