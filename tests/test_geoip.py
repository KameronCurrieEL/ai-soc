import gzip

import pytest

from soc.enrich.geoip import GeoDB, locate

# Tiny fake database. Real ranges don't matter: we test the lookup logic, not DB-IP's data.
ROWS = [
    ("1.0.0.0", "1.0.0.255", "AU"),
    ("8.8.8.0", "8.8.8.255", "US"),
    ("9.9.9.0", "9.9.9.255", "ZZ"),           # DB-IP's "unknown"
    ("2a00:1450::", "2a00:1450:ffff:ffff:ffff:ffff:ffff:ffff", "IE"),
]


@pytest.fixture
def db():
    return GeoDB(ROWS)


@pytest.mark.parametrize("ip,code", [
    ("8.8.8.8", "US"), ("8.8.8.0", "US"), ("8.8.8.255", "US"),   # inside, first, last
    ("1.0.0.7", "AU"),
    ("8.8.9.0", None),                                          # just after a range: gap
    ("0.0.0.1", None),                                          # before the first range
    ("9.9.9.9", None),                                          # ZZ -> unknown
    ("2a00:1450:4001::1", "IE"),                                # IPv6 searched separately
])
def test_country_lookup_boundaries(db, ip, code):
    assert db.country(ip) == code


def test_load_from_gzip_csv(tmp_path):
    p = tmp_path / "geo.csv.gz"
    with gzip.open(p, "wt") as f:
        f.write("8.8.8.0,8.8.8.255,US\n")
    assert GeoDB.load(p).country("8.8.8.8") == "US"


def test_unsorted_input_still_works():
    assert GeoDB(list(reversed(ROWS))).country("1.0.0.1") == "AU"


def test_non_public_addresses_never_get_a_country(db):
    # even if the database (wrongly) contained them, scope is decided first
    bad = GeoDB([("127.0.0.0", "127.255.255.255", "US"), ("192.168.0.0", "192.168.255.255", "US")])
    assert locate("::1", "windows-host", bad).place == "This computer (windows-host)"
    assert locate("127.0.0.1", None, bad).country_code == ""
    assert locate("192.168.1.20", None, bad).place == "Your local network"
    assert locate("203.0.113.5", None, db).scope == "reserved"      # documentation range


def test_public_with_and_without_database(db):
    us = locate("8.8.8.8", None, db)
    assert (us.place, us.country_code) == ("United States (US)", "US") and "VPN" in us.explanation
    assert "make geoip" in locate("8.8.8.8", None, None).explanation
    assert locate("8.8.9.1", None, db).place == "Internet (country unknown)"


def test_garbage_ip_is_not_a_crash(db):
    assert locate("not-an-ip", None, db).scope == "invalid"
