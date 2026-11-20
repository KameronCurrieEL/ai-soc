"""Chart geometry for server-rendered SVG (no JavaScript, so the strict CSP stays).

SVG attributes like d="..." are not CSS, so they're allowed under `default-src 'self'`
(inline style="..." would not be). Colors come from CSS classes in style.css.

The 24h chart is a radar scope:
  - angle = time of day (UTC), 00:00 at the top, clockwise, like a clock;
  - wedges on the outer edge = alerts per hour (length scaled to the busiest hour);
  - blips = incidents seen in the window, on a ring per priority: the more severe, the closer to the center.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

from soc.agent.insights import PRIORITY_ORDER, Bucket, parse_any_time

SIZE = 400                     # viewBox is SIZE x SIZE
R = 150                        # outer ring radius; wedges grow outward from here
WEDGE_MAX = 32                 # px a wedge reaches for the busiest hour
RING = {"critical": .25, "high": .5, "medium": .73, "low": .95}   # fraction of R per priority
MAX_BLIPS = 10
MIN_GAP = 14                   # px between blip centres before we nudge one inward


def hour_tooltip(b: Bucket) -> str:
    """'19:00-19:59 UTC: 27 alerts (2 high, 25 medium)'"""
    label, end = b.start.strftime("%H:%M"), b.start.strftime("%H") + ":59"
    parts = ", ".join(f"{b.counts[p]} {p}" for p in reversed(PRIORITY_ORDER) if b.counts.get(p))
    return f"{label}-{end} UTC: {b.total} alert{'s' if b.total != 1 else ''}" + (f" ({parts})" if parts else "")


def _angle(hour: float) -> float:
    return hour / 24 * 2 * math.pi - math.pi / 2


def _pt(hour: float, r: float) -> tuple[float, float]:
    a = _angle(hour)
    return round(SIZE / 2 + r * math.cos(a), 1), round(SIZE / 2 + r * math.sin(a), 1)


@dataclass
class Wedge:
    hour: int
    total: int
    d: str              # SVG path
    tooltip: str


@dataclass
class Blip:
    id: str
    title: str
    priority: str
    closed: bool
    x: float
    y: float
    lx: float           # label anchor
    ly: float
    anchor: str         # "start" | "end"
    tooltip: str


@dataclass
class Radar:
    size: int
    rings: list[tuple[str, float]]                 # (priority, radius)
    ticks: list[tuple[float, float, float, float, bool]]
    hour_labels: list[tuple[str, float, float]]
    wedges: list[Wedge]
    blips: list[Blip]
    now_line: tuple[float, float]                  # end point of the "now" hand
    total: int
    hidden_blips: int = 0
    center: float = field(default=SIZE / 2)


def _wedge_path(hour: int, length: float) -> str:
    ri, ro = R + 4, R + 4 + length
    (x0, y0), (x1, y1) = _pt(hour + .12, ri), _pt(hour + .12, ro)
    (x2, y2), (x3, y3) = _pt(hour + .88, ro), _pt(hour + .88, ri)
    return f"M{x0},{y0} L{x1},{y1} A{ro:.1f},{ro:.1f} 0 0 1 {x2},{y2} L{x3},{y3} Z"


def radar_24h(buckets: Sequence[Bucket], incidents: Sequence[Mapping[str, Any]],
              now: datetime | None = None) -> Radar:
    now = now or datetime.now(timezone.utc)
    busiest = max((b.total for b in buckets), default=0)
    wedges = [Wedge(b.start.hour, b.total, _wedge_path(b.start.hour, max(b.total / busiest * WEDGE_MAX, 2)), hour_tooltip(b))
              for b in buckets if b.total]

    ticks = []
    for h in range(24):
        major = h % 6 == 0
        ticks.append((*_pt(h, R), *_pt(h, R - (8 if major else 4)), major))
    hour_labels = [(f"{h:02d}", *_pt(h, R - 20)) for h in (0, 6, 12, 18)]

    # Blips: open incidents first, then by severity; only those seen in the last 24 h.
    rank = {p: i for i, p in enumerate(reversed(PRIORITY_ORDER))}          # critical=0 ... low=3
    recent = []
    for r in incidents:
        try:
            seen = parse_any_time(r["last_seen"])
        except (ValueError, TypeError, KeyError):
            continue
        if now - timedelta(hours=24) <= seen <= now + timedelta(minutes=5):
            recent.append((r["status"] != "open", rank.get(r["priority"], 9), seen, r))
    recent.sort(key=lambda t: (t[0], t[1], -t[2].timestamp()))
    placed: list[tuple[float, float]] = []
    blips = []
    for closed, _, seen, r in recent[:MAX_BLIPS]:
        hour = seen.hour + seen.minute / 60
        radius = RING.get(r["priority"], RING["low"]) * R
        x, y = _pt(hour, radius)
        for _ in range(4):                                # nudge inward so blips don't sit on top of each other
            if all(math.dist((x, y), p) >= MIN_GAP for p in placed):
                break
            radius -= 12
            x, y = _pt(hour, radius)
        placed.append((x, y))
        right = x >= SIZE / 2
        title = r["title"] if len(r["title"]) <= 24 else r["title"][:23] + "…"
        blips.append(Blip(r["id"], title, r["priority"], closed, x, y,
                          round(x + (12 if right else -12), 1), round(y - 3, 1), "start" if right else "end",
                          f"{r['id']} · {r['priority']} · {r['title']} · last seen {seen:%H:%M} UTC · {r['status']}"))

    return Radar(SIZE, [(p, RING[p] * R) for p in ("critical", "high", "medium", "low")], ticks, hour_labels,
                 wedges, blips, _pt(now.hour + now.minute / 60, R), sum(b.total for b in buckets),
                 hidden_blips=max(len(recent) - MAX_BLIPS, 0))
