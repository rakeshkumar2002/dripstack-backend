"""Collision-resistant, URL-safe IDs (cuid-style) for primary keys.

Prisma used `cuid()`; we don't need byte-identical output (the DB is reseeded),
only the same shape: a short, sortable, opaque string safe in URLs/tokens.
"""

from __future__ import annotations

import os
import threading
import time

_BASE36 = "0123456789abcdefghijklmnopqrstuvwxyz"
_counter = 0
_lock = threading.Lock()


def _b36(n: int) -> str:
    if n == 0:
        return "0"
    out = []
    while n > 0:
        n, r = divmod(n, 36)
        out.append(_BASE36[r])
    return "".join(reversed(out))


def cuid() -> str:
    global _counter
    with _lock:
        _counter = (_counter + 1) % (36**4)
        count = _counter
    ts = _b36(int(time.time() * 1000)).rjust(8, "0")
    block = _b36(count).rjust(4, "0")
    rand = _b36(int.from_bytes(os.urandom(8), "big")).rjust(8, "0")[:8]
    return f"c{ts}{block}{rand}"
