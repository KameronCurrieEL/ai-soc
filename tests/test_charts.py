import math
from datetime import datetime, timezone

from soc.agent.insights import Bucket
from soc.web.charts import RING, R, SIZE, hour_tooltip, radar_24h

NOW = datetime(2026, 11, 17, 23, 30, tzinfo=timezone.utc)


def bucket(h, **counts):
    c = {"low": 0, "medium": 0, "high": 0, "critical": 0, **counts}
    return Bucket(datetime(2026, 11, 17, h, tzinfo=timezone.utc), c)


def inc(id_, prio, last_seen, status="open", title="Brute force from ::1"):
    return {"id": id_, "priority": prio, "last_seen": last_seen, "status": status, "title": title}


def dist_from_centre(b):
    return math.dist((b.x, b.y), (SIZE / 2, SIZE / 2))


def test_hour_tooltip():
    assert hour_tooltip(bucket(19, medium=25, high=2)) == "19:00-19:59 UTC: 27 alerts (2 high, 25 medium)"
    assert hour_tooltip(bucket(3, high=1)) == "03:00-03:59 UTC: 1 alert (1 high)"
    assert "0 alerts" in hour_tooltip(bucket(4))


def test_wedges_only_for_busy_hours_and_total():
    r = radar_24h([bucket(18), bucket(19, medium=25, high=2), bucket(20, low=1)], [], now=NOW)
    assert [w.hour for w in r.wedges] == [19, 20] and r.total == 28


def test_angle_is_time_of_day_midnight_at_top():
    r = radar_24h([], [inc("INC-a", "low", "2026-11-17T00:00:00+00:00"), inc("INC-b", "low", "2026-11-17T06:00:00+00:00")],
                  now=datetime(2026, 11, 17, 12, tzinfo=timezone.utc))
    top, right = sorted(r.blips, key=lambda b: b.id)
    assert abs(top.x - SIZE / 2) < 1 and top.y < SIZE / 2          # 00:00 straight up
    assert right.x > SIZE / 2 and abs(right.y - SIZE / 2) < 1       # 06:00 at three o'clock


def test_severity_sits_closer_to_centre():
    r = radar_24h([], [inc("INC-c", "critical", "2026-11-17T20:00:00+00:00"),
                       inc("INC-l", "low", "2026-11-17T08:00:00+00:00")], now=NOW)
    by = {b.id: b for b in r.blips}
    assert dist_from_centre(by["INC-c"]) < dist_from_centre(by["INC-l"])
    assert abs(dist_from_centre(by["INC-l"]) - RING["low"] * R) < 1


def test_old_incidents_left_out_and_open_first():
    r = radar_24h([], [inc("INC-old", "high", "2026-11-15T20:00:00+00:00"),
                       inc("INC-closed", "critical", "2026-11-17T20:00:00+00:00", status="closed"),
                       inc("INC-open", "low", "2026-11-17T21:00:00+00:00")], now=NOW)
    assert [b.id for b in r.blips] == ["INC-open", "INC-closed"]
    assert r.blips[1].closed and not r.blips[0].closed


def test_overlapping_blips_are_nudged_apart():
    same = "2026-11-17T22:00:00+00:00"
    r = radar_24h([], [inc(f"INC-{i}", "medium", same) for i in range(3)], now=NOW)
    pts = [(b.x, b.y) for b in r.blips]
    assert all(math.dist(a, b) >= 10 for i, a in enumerate(pts) for b in pts[i + 1:])


def test_bad_timestamps_are_skipped_not_fatal():
    r = radar_24h([], [inc("INC-x", "high", "not a time")], now=NOW)
    assert r.blips == []
