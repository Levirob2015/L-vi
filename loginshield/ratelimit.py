"""Rate-Limiting mit gleitendem Zeitfenster.

Bewusst im Arbeitsspeicher: Requests sind um Groessenordnungen haeufiger als
Login-Fehlversuche, jeder Treffer als SQLite-Insert waere Verschwendung. Die
Anzahl der Schluessel ist gedeckelt (LRU), damit ein Angriff aus vielen IPs
nicht den Speicher fuellt.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from typing import Deque, Optional, Tuple


class SlidingWindow:
    """Zaehlt Ereignisse pro Schluessel in einem gleitenden Fenster."""

    def __init__(self, limit: int, window: float, *, max_keys: int = 50_000) -> None:
        if limit <= 0 or window <= 0:
            raise ValueError("limit und window muessen groesser als 0 sein")
        self.limit = int(limit)
        self.window = float(window)
        self.max_keys = int(max_keys)
        self._entries: "OrderedDict[str, Deque[float]]" = OrderedDict()
        self._lock = threading.Lock()

    def hit(self, key: str, now: Optional[float] = None) -> Tuple[bool, int, int]:
        """Registriert ein Ereignis.

        Rueckgabe: ``(erlaubt, retry_after, anzahl_im_fenster)``. Ein
        abgewiesenes Ereignis wird trotzdem gezaehlt - wer weiter haemmert,
        verlaengert damit seine eigene Wartezeit.
        """
        now = time.time() if now is None else now
        cutoff = now - self.window
        with self._lock:
            bucket = self._entries.get(key)
            if bucket is None:
                bucket = deque()
                self._entries[key] = bucket
            else:
                self._entries.move_to_end(key)

            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            bucket.append(now)
            count = len(bucket)
            self._evict_locked()

            if count > self.limit:
                retry_after = max(1, int(bucket[0] + self.window - now) + 1)
                return False, retry_after, count
            return True, 0, count

    def peek(self, key: str, now: Optional[float] = None) -> int:
        now = time.time() if now is None else now
        cutoff = now - self.window
        with self._lock:
            bucket = self._entries.get(key)
            if not bucket:
                return 0
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            return len(bucket)

    def reset(self, key: Optional[str] = None) -> None:
        with self._lock:
            if key is None:
                self._entries.clear()
            else:
                self._entries.pop(key, None)

    def _evict_locked(self) -> None:
        while len(self._entries) > self.max_keys:
            self._entries.popitem(last=False)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
