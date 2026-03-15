"""Timestamp utilities."""

import time


def now_ns() -> int:
    """Return the current time as nanoseconds since the Unix epoch."""
    return time.time_ns()
