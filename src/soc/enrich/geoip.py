"""Rough location of an IP address, looked up OFFLINE.

Two questions, in this order:
  1. What kind of address is it? loopback = this computer, private = our own network,
     reserved = not routable on the internet. None of these have a meaningful country.
  2. Only for public addresses: which country is the block registered/routed in?
     Answered from DB-IP's free "IP to Country Lite" CSV (CC BY 4.0), downloaded once with
     `make geoip`. No web API: that would be a cloud call and would leak the attacker IP.

Accuracy: country-level only. VPNs, Tor and cloud servers show where the SERVER is, not the person.

CSV rows: start_ip,end_ip,country_code (IPv4 and IPv6, sorted, non-overlapping).
Lookup: binary search (bisect) over the range starts -> O(log n).
"""

from __future__ import annotations

import csv
import gzip
import ipaddress
import json
import os
from bisect import bisect_right
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from soc.parsing.schema import ip_scope

DEFAULT_DB = Path("data/geo/dbip-country-lite.csv.gz")
ATTRIBUTION = "IP geolocation by DB-IP (db-ip.com), CC BY 4.0"
COUNTRIES: dict[str, str] = json.loads((Path(__file__).with_name("countries.json")).read_text(encoding="utf-8"))


class GeoDB:
    """Sorted IP ranges per IP version; lookup by binary search."""

    def __init__(self, rows) -> None:
        self._starts: dict[int, list[int]] = {4: [], 6: []}
        self._ends: dict[int, list[int]] = {4: [], 6: []}
        self._codes: dict[int, list[str]] = {4: [], 6: []}
        for start, end, code in rows:
            a, b = ipaddress.ip_address(start), ipaddress.ip_address(end)
            self._starts[a.version].append(int(a))
            self._ends[a.version].append(int(b))
            self._codes[a.version].append(code)
        for v in (4, 6):  # bisect needs sorted starts; the file is sorted, but don't rely on it
            order = sorted(range(len(self._starts[v])), key=self._starts[v].__getitem__)
            self._starts[v] = [self._starts[v][i] for i in order]
            self._ends[v] = [self._ends[v][i] for i in order]
            self._codes[v] = [self._codes[v][i] for i in order]

    @classmethod
    def load(cls, path: Path | str) -> GeoDB:
        opener = gzip.open if str(path).endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8", newline="") as f:
            return cls(row[:3] for row in csv.reader(f) if len(row) >= 3)

    def country(self, ip: str) -> str | None:
        """ISO country code, or None if the address isn't in any range (or DB-IP says 'ZZ' = unknown)."""
        addr = ipaddress.ip_address(ip)
        n, v = int(addr), addr.version
        i = bisect_right(self._starts[v], n) - 1   # last range that starts at or before n
        if i >= 0 and n <= self._ends[v][i]:
            code = self._codes[v][i]
            return None if code == "ZZ" else code
        return None


@lru_cache(maxsize=1)
def default_db() -> GeoDB | None:
    """Load once per process (~1-2 s). None if `make geoip` hasn't been run: the page still works."""
    path = Path(os.environ.get("GEOIP_DB", DEFAULT_DB))
    return GeoDB.load(path) if path.exists() else None


@dataclass(frozen=True)
class Location:
    ip: str
    scope: str           # loopback | private | public | reserved | invalid
    place: str           # short answer, e.g. "This computer", "Germany (DE)"
    explanation: str     # what it means for the analyst
    country_code: str = ""


def locate(ip: str, host: str | None = None, db: GeoDB | None = None) -> Location:
    """Where did this address come from? Scope is recomputed here, never trusted from stored data."""
    scope = ip_scope(ip)
    on = f" ({host})" if host else ""
    if scope is None:
        return Location(ip, "invalid", "Unknown", "Not a valid IP address.")
    if scope == "loopback":
        return Location(ip, scope, f"This computer{on}",
                        "Loopback address: the activity started on the monitored machine itself, "
                        "e.g. a local script, service or logged-in user. Not from the network.")
    if scope == "private":
        return Location(ip, scope, "Your local network",
                        "Private address: a device inside your own network. Find it in your router's "
                        "DHCP/ARP table. It has no public location.")
    if scope == "reserved":
        return Location(ip, scope, "Not routable",
                        "Reserved/documentation range: can't come from the real internet. "
                        "Likely test data or a spoofed/misparsed field.")
    if db is None:
        return Location(ip, scope, "Internet (country unknown)",
                        "Public address, but no offline GeoIP database is installed. Run `make geoip`.")
    code = db.country(ip)
    if code is None:
        return Location(ip, scope, "Internet (country unknown)", "Public address not found in the GeoIP database.")
    return Location(ip, scope, f"{COUNTRIES.get(code, code)} ({code})",
                    "Public address, country from IP registration data. Approximate: VPNs, Tor and "
                    "cloud servers show where the server is, not the person.", code)
