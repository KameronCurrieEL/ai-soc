from soc.decision.correlate import find_bursts
from soc.parsing.schema import Alert


def fail(i, ts, ip="::1", user="u", event="4625", mitre=()):
    return Alert(f"a{i}", ts, "windows_event", "60122", 5, "low", "fail", "001", "host",
                 mitre_ids=mitre, user=user, src_ip=ip, src_ip_scope="loopback" if ip == "::1" else "public",
                 event_id=event, details={"requested_by": "labuser"})


def ts(sec):
    return f"2026-11-17T19:{40 + sec // 60:02d}:{sec % 60:02d}.000+0000"


def test_same_millisecond_burst_is_caught():
    alerts = [fail(i, "2026-11-17T19:43:36.260+0000") for i in range(10)]
    [b] = find_bursts(alerts)
    assert b.count == 10 and b.source == "::1" and b.users == ["u"] and b.requested_by == ["labuser"]


def test_below_threshold_is_ignored():
    assert find_bursts([fail(i, ts(i)) for i in range(4)]) == []


def test_spread_out_failures_are_not_a_burst():
    assert find_bursts([fail(i, ts(i * 120)) for i in range(6)]) == []  # one every 2 min


def test_out_of_order_input_is_sorted():
    alerts = [fail(i, ts(s)) for i, s in enumerate([50, 10, 40, 0, 30, 20])]
    [b] = find_bursts(alerts)
    assert b.count == 6 and b.first == ts(0) and b.last == ts(50)


def test_sources_counted_separately_and_users_collected():
    alerts = [fail(i, ts(i), ip="8.8.8.8", user=f"u{i % 2}") for i in range(5)]
    alerts += [fail(10 + i, ts(i)) for i in range(3)]
    [b] = find_bursts(alerts)
    assert b.src_ip == "8.8.8.8" and b.users == ["u0", "u1"]


def test_correlation_alerts_and_successes_are_not_counted():
    alerts = [fail(i, ts(i), mitre=("T1110",)) for i in range(5)] + [fail(9 + i, ts(i), event="4624") for i in range(5)]
    assert find_bursts(alerts) == []


def test_missing_ip_groups_by_agent():
    [b] = find_bursts([fail(i, ts(i), ip=None) for i in range(5)])
    assert b.source == "local:001"
