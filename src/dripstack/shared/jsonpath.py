"""Minimal, dependency-free JSONPath evaluator (port of shared/src/jsonpath.ts).

Supports the subset DripStack needs: dot paths, bracket keys, array indices.
Reused by contact resolution, trigger conditions, and code/json/log blocks.

    $.a.b.c        $.error.code
    $.a[0].b       $["weird key"].b
    a.b            (leading $ optional)

Returns None for any path that does not resolve.
"""

from __future__ import annotations

from typing import Any

_UNRESOLVED = object()


def get_by_path(obj: Any, path: str) -> Any:
    cur: Any = obj
    for token in _tokenize(path):
        if isinstance(cur, dict):
            if token not in cur:
                return None
            cur = cur[token]
        elif isinstance(cur, (list, tuple)):
            try:
                idx = int(token)
            except (ValueError, TypeError):
                return None
            if idx < 0 or idx >= len(cur):
                return None
            cur = cur[idx]
        else:
            return None
    return cur


def path_exists(obj: Any, path: str) -> bool:
    return _resolve(obj, path) is not _UNRESOLVED


def _resolve(obj: Any, path: str) -> Any:
    cur: Any = obj
    for token in _tokenize(path):
        if isinstance(cur, dict):
            if token not in cur:
                return _UNRESOLVED
            cur = cur[token]
        elif isinstance(cur, (list, tuple)):
            try:
                idx = int(token)
            except (ValueError, TypeError):
                return _UNRESOLVED
            if idx < 0 or idx >= len(cur):
                return _UNRESOLVED
            cur = cur[idx]
        else:
            return _UNRESOLVED
    return cur


def _tokenize(path: str) -> list[str]:
    tokens: list[str] = []
    i = 0
    n = len(path)
    if path[:1] == "$":
        i = 1
    while i < n:
        ch = path[i]
        if ch == ".":
            i += 1
            continue
        if ch == "[":
            close = path.find("]", i)
            if close == -1:
                break
            inner = path[i + 1 : close].strip()
            if (inner.startswith('"') and inner.endswith('"')) or (inner.startswith("'") and inner.endswith("'")):
                inner = inner[1:-1]
            tokens.append(inner)
            i = close + 1
            continue
        j = i
        while j < n and path[j] != "." and path[j] != "[":
            j += 1
        key = path[i:j]
        if key:
            tokens.append(key)
        i = j
    return tokens
