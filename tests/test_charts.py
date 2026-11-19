from datetime import datetime, timezone

from soc.agent.insights import Bucket
from soc.web.charts import nice_max, stacked_hourly


def bucket(h, **counts):
    c = {"low": 0, "medium": 0, "high": 0, "critical": 0, **counts}
    return Bucket(datetime(2026, 11, 17, h, tzinfo=timezone.utc), c)


def test_nice_max():
    assert [nice_max(n) for n in (0, 1, 3, 7, 27, 200, 201)] == [1, 1, 5, 10, 50, 200, 500]


def test_stacked_bars_order_scale_and_tooltip():
    c = stacked_hourly([bucket(18), bucket(19, medium=25, high=2)], width=100, height=120)
    empty, busy = c.bars
    assert empty.segments == [] and "0 alerts" in empty.tooltip
    assert [s.priority for s in busy.segments] == ["medium", "high"]           # low at bottom, severe on top
    assert busy.segments[1].y < busy.segments[0].y                             # high is drawn above medium
    assert busy.tooltip == "19:00-19:59 UTC: 27 alerts (2 high, 25 medium)"
    assert c.y_max == 50 and all(s.y >= 0 and s.y + s.height <= c.plot_height for s in busy.segments)


def test_tiny_counts_stay_visible():
    c = stacked_hourly([bucket(1, low=1000, critical=1)])
    assert c.bars[0].segments[-1].height >= 1   # one critical among 1000 lows still shows
