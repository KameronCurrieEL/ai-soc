"""Chart geometry for server-rendered SVG (no JavaScript, so the strict CSP stays).

SVG attributes like height="..." are not CSS, so they're allowed under `default-src 'self'`
(inline style="..." would not be). Colors come from CSS classes in style.css.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from soc.agent.insights import PRIORITY_ORDER, Bucket

GAP = 2  # px of surface between stacked segments and between bars


@dataclass
class Segment:
    priority: str
    y: float
    height: float


@dataclass
class Bar:
    x: float
    width: float
    label: str            # "19:00"
    tooltip: str          # "19:00-20:00 UTC: 27 alerts (25 medium, 2 high)"
    total: int
    segments: list[Segment] = field(default_factory=list)


@dataclass
class StackedChart:
    width: int
    height: int
    plot_height: int
    y_max: int
    bars: list[Bar]
    ticks: list[Bar]      # bars that get an x-axis label


def nice_max(n: int) -> int:
    """Round the axis max up to 1, 2 or 5 x 10^k so the top label is readable."""
    if n <= 0:
        return 1
    step = 1
    while True:
        for m in (1, 2, 5):
            if m * step >= n:
                return m * step
        step *= 10


def stacked_hourly(buckets: list[Bucket], width: int = 720, height: int = 150, label_every: int = 6) -> StackedChart:
    """Stacked bars, low at the bottom, most severe on top (it's what the eye lands on)."""
    plot_h = height - 20                    # room for x labels
    y_max = nice_max(max((b.total for b in buckets), default=0))
    slot = width / max(len(buckets), 1)
    bars = []
    for i, b in enumerate(buckets):
        label = b.start.strftime("%H:%M")
        end = b.start.strftime("%H") + ":59"
        parts = ", ".join(f"{b.counts[p]} {p}" for p in reversed(PRIORITY_ORDER) if b.counts.get(p))
        tip = f"{label}-{end} UTC: {b.total} alert{'s' if b.total != 1 else ''}" + (f" ({parts})" if parts else "")
        bar = Bar(round(i * slot + GAP / 2, 2), round(slot - GAP, 2), label, tip, b.total)
        y = float(plot_h)
        for p in PRIORITY_ORDER:
            n = b.counts.get(p, 0)
            if not n:
                continue
            h = n / y_max * plot_h
            seg_h = max(h - GAP, 1.0)        # gap on top of each segment; never invisible
            y -= h
            bar.segments.append(Segment(p, round(y + GAP, 2) if h > GAP + 1 else round(y, 2), round(seg_h, 2)))
        bars.append(bar)
    return StackedChart(width, height, plot_h, y_max, bars, bars[::label_every])
