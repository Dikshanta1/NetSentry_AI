"""Generate the bundled SYNTHETIC dataset at data/sample_traffic.csv.

All addresses come from documentation-only ranges (RFC 5737):
192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24. None of this is real
captured traffic. Output is deterministic (fixed random seed).

Run from the project root:  python scripts/generate_sample_data.py
"""

from __future__ import annotations

import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUTPUT = Path(__file__).resolve().parent.parent / "data" / "sample_traffic.csv"
DAY = datetime(2026, 10, 26, tzinfo=timezone.utc)
MIB = 1024 * 1024

Row = tuple[datetime, str, str, int, int, str, int, str]


def normal_traffic(rng: random.Random) -> list[Row]:
    """Ordinary business-hours HTTPS, DNS, NTP, mail and SSH traffic."""
    clients = [f"192.0.2.{n}" for n in (10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21)]
    web = [f"198.51.100.{n}" for n in (20, 21, 22, 23, 24)]
    services = [
        # (weight, protocol, port, destinations, byte range)
        (55, "TCP", 443, web, (800, 250_000)),
        (20, "UDP", 53, ["198.51.100.53"], (60, 300)),
        (8, "TCP", 80, web, (500, 40_000)),
        (5, "UDP", 123, ["198.51.100.123"], (48, 90)),
        (6, "TCP", 25, ["198.51.100.25"], (2_000, 60_000)),
        (6, "TCP", 22, ["198.51.100.40"], (1_000, 30_000)),
    ]
    weights = [s[0] for s in services]
    rows: list[Row] = []
    for _ in range(230):
        _, proto, port, dsts, (lo, hi) = rng.choices(services, weights)[0]
        ts = DAY + timedelta(hours=9, seconds=rng.randrange(0, 9 * 3600))  # 09:00-17:59:59
        action = "DENY" if rng.random() < 0.06 else "ALLOW"
        rows.append(
            (ts, rng.choice(clients), rng.choice(dsts), rng.randint(49152, 65535), port,
             proto, rng.randint(lo, hi), action)
        )
    # A few denied attempts to blocked services.
    for port in (23, 3389, 445):
        ts = DAY + timedelta(hours=11, minutes=rng.randrange(0, 300))
        rows.append((ts, rng.choice(clients), "198.51.100.22", rng.randint(49152, 65535),
                     port, "TCP", rng.randint(0, 120), "DENY"))
    # ICMP echo traffic (ports are required by the schema; 1 is used as a placeholder).
    for _ in range(6):
        ts = DAY + timedelta(hours=10, minutes=rng.randrange(0, 420))
        rows.append((ts, rng.choice(clients), rng.choice(web), 1, 1, "ICMP", 64, "ALLOW"))
    return rows


def port_scan(rng: random.Random) -> list[Row]:
    """203.0.113.50 probes 25 ports on one host in about 3.5 minutes."""
    start = DAY + timedelta(hours=10, minutes=15)
    ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
             1433, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200]
    rows: list[Row] = []
    for i, port in enumerate(ports):
        ts = start + timedelta(seconds=i * 8 + rng.randint(0, 3))
        action = "ALLOW" if port in (22, 80, 443) else "DENY"
        rows.append((ts, "203.0.113.50", "198.51.100.30", rng.randint(40000, 60000),
                     port, "TCP", rng.randint(0, 60), action))
    return rows


def high_transfer(rng: random.Random) -> list[Row]:
    """192.0.2.25 uploads ~66 MiB to one external host within 4 minutes."""
    start = DAY + timedelta(hours=14, minutes=2)
    return [
        (start + timedelta(seconds=i * 40), "192.0.2.25", "203.0.113.80",
         rng.randint(49152, 65535), 443, "TCP", 11 * MIB + rng.randint(0, 4096), "ALLOW")
        for i in range(6)
    ]


def off_hours(rng: random.Random) -> list[Row]:
    """Night-time SSH/backup-like activity and one late-evening HTTPS session."""
    rows: list[Row] = []
    for i in range(5):
        ts = DAY + timedelta(hours=2, minutes=10 + i * 7)
        rows.append((ts, "192.0.2.77", "198.51.100.40", rng.randint(49152, 65535), 22,
                     "TCP", rng.randint(20_000, 400_000), "ALLOW"))
    for i in range(3):
        ts = DAY + timedelta(hours=21, minutes=30 + i * 4)
        rows.append((ts, "192.0.2.14", "198.51.100.21", rng.randint(49152, 65535), 443,
                     "TCP", rng.randint(1_000, 80_000), "ALLOW"))
    ts = DAY + timedelta(hours=23, minutes=48)
    rows.append((ts, "203.0.113.9", "198.51.100.40", rng.randint(49152, 65535), 22,
                 "TCP", 320, "DENY"))
    return rows


def main() -> None:
    rng = random.Random(20261026)
    rows = normal_traffic(rng) + port_scan(rng) + high_transfer(rng) + off_hours(rng)
    rows.sort(key=lambda r: r[0])
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
                         "protocol", "bytes_sent", "action"])
        for ts, *rest in rows:
            writer.writerow([ts.strftime("%Y-%m-%dT%H:%M:%SZ"), *rest])
    print(f"Wrote {len(rows)} synthetic records to {OUTPUT}")


if __name__ == "__main__":
    main()
