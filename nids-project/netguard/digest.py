"""Small scheduler for weekly NetGuard digest callbacks."""

from __future__ import annotations

import datetime as dt
import threading
from typing import Callable, Optional


DAY_INDEX = {
    "mon": 0,
    "tue": 1,
    "wed": 2,
    "thu": 3,
    "fri": 4,
    "sat": 5,
    "sun": 6,
}


def seconds_until_next_digest(
    day: str,
    hour: int,
    now: Optional[dt.datetime] = None,
) -> float:
    """Return seconds until the next configured weekly digest time."""
    current = now or dt.datetime.now()
    target_day = DAY_INDEX[day.strip().lower()[:3]]
    days_ahead = (target_day - current.weekday()) % 7
    target = (current + dt.timedelta(days=days_ahead)).replace(
        hour=hour, minute=0, second=0, microsecond=0
    )
    if target <= current:
        target += dt.timedelta(days=7)
    return max(0.0, (target - current).total_seconds())


class DigestScheduler:
    """Run a digest callback once per configured weekly schedule."""

    def __init__(self, callback: Callable[[], object], day: str = "sun", hour: int = 9):
        self.callback = callback
        self.day = day
        self.hour = hour
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="netguard-digest")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _run(self) -> None:
        while not self._stop.wait(seconds_until_next_digest(self.day, self.hour)):
            self.callback()