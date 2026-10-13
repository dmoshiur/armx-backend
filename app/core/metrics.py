# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Minimal dependency-free metrics.

Deliberately small: counters and meters that the Security Gateway, the harness and the
worker increment, rendered in Prometheus text format on ``/metrics``. No label value ever
contains a user id, email, or argument - labels are tool names, outcomes and routes only,
so the metrics endpoint cannot become a data-leak side channel.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import Final

__all__ = [
    "counter_value",
    "inc",
    "observe",
    "observe_latency",
    "render_prometheus",
    "reset_metrics",
    "set_gauge",
]

_LOCK: Final = threading.Lock()
_COUNTERS: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
_GAUGES: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
_METER_SUM: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
_METER_COUNT: dict[tuple[str, tuple[tuple[str, str], ...]], int] = defaultdict(int)

_PREFIX = "armx_"


def _key(name: str, labels: dict[str, str] | None) -> tuple[str, tuple[tuple[str, str], ...]]:
    normalised = tuple(sorted((str(k), str(v)[:64]) for k, v in (labels or {}).items()))
    return f"{_PREFIX}{name}", normalised


def inc(name: str, labels: dict[str, str] | None = None, amount: float = 1.0) -> None:
    """Increment a counter."""
    with _LOCK:
        _COUNTERS[_key(name, labels)] += amount


def set_gauge(name: str, value: float, labels: dict[str, str] | None = None) -> None:
    """Set a gauge to an absolute value."""
    with _LOCK:
        _GAUGES[_key(name, labels)] = float(value)


def observe(name: str, value: float, labels: dict[str, str] | None = None) -> None:
    """Record a value in a summary-style meter (sum + count)."""
    with _LOCK:
        key = _key(f"{name}_seconds", labels)
        _METER_SUM[key] += float(value)
        _METER_COUNT[key] += 1


def observe_latency(name: str, seconds: float, labels: dict[str, str] | None = None) -> None:
    """Alias with an explicit unit for readability at call sites."""
    observe(name, seconds, labels)


def counter_value(name: str, labels: dict[str, str] | None = None) -> float:
    """Read a counter (used by tests)."""
    with _LOCK:
        return _COUNTERS.get(_key(name, labels), 0.0)


def reset_metrics() -> None:
    """Clear every series (tests only)."""
    with _LOCK:
        _COUNTERS.clear()
        _GAUGES.clear()
        _METER_SUM.clear()
        _METER_COUNT.clear()


def _render_labels(labels: tuple[tuple[str, str], ...]) -> str:
    if not labels:
        return ""
    rendered = ",".join(f'{k}="{v}"' for k, v in labels)
    return f"{{{rendered}}}"


def render_prometheus() -> str:
    """Prometheus text-exposition format."""
    lines: list[str] = []
    with _LOCK:
        for (name, labels), value in sorted(_COUNTERS.items()):
            lines.append(f"{name}_total{_render_labels(labels)} {value:g}")
        for (name, labels), value in sorted(_GAUGES.items()):
            lines.append(f"{name}{_render_labels(labels)} {value:g}")
        for (name, labels), total in sorted(_METER_SUM.items()):
            count = _METER_COUNT.get((name, labels), 0)
            lines.append(f"{name}_sum{_render_labels(labels)} {total:g}")
            lines.append(f"{name}_count{_render_labels(labels)} {count}")
    return "\n".join(lines) + "\n"
