"""
scans/active.log: Akashi's audit trail of every ACTIVE request and refusal.

One JSON object per line, written BEFORE the request is sent, so a request that
hangs or crashes is still on record. Same shape as Monomi's active log, so the
two tools read the same way: what was sent, to whom, under which scope.

    {"time", "event": "request", "via": "cli"|"mcp", ["approval",] "tool", "host",
     "url", "scope_rule", "scope_sha256"}
    {"time", "event": "refused", "via", ["approval",] "tool", "host"|null,
     "reason", "scope_sha256"}

"via" says where the run was started: "cli" (the akashi command) unless a
caller wraps it in context(via="mcp", approval=<id>), as 0x41 does for an
active proof a person approved in a terminal for an agent (0x41 issue #2).
"approval" is present only then, so each line ties back to its approval.

The file lives under Akashi's data home (AKASHI_HOME, the repo, or ~/.akashi),
the same place as the proof history.
"""

import contextlib
import contextvars
import json
import os
import threading

from monomi.common import now_utc

from akashi import home

_lock = threading.Lock()
VIA = ("cli", "mcp")
# Who started this run, for every line written while it lasts. A context
# variable, so concurrent runs in other threads each keep their own.
_context = contextvars.ContextVar("akashi_activelog_context", default={"via": "cli"})


@contextlib.contextmanager
def context(via: str = "cli", approval: str | None = None):
    """Every line logged inside this block says via=<via> (and the approval id)."""
    if via not in VIA:
        raise ValueError(f"via must be one of {VIA}")
    token = _context.set({"via": via, **({"approval": approval} if approval else {})})
    try:
        yield
    finally:
        _context.reset(token)


def path() -> str:
    return home.data_dir("scans", "active.log")


def _write(entry: dict) -> str:
    p = path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    line = json.dumps({"time": now_utc(), **entry})
    with _lock, open(p, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    return p


def request(tool, host, url, scope_rule, scope_sha) -> str:
    """One active request, logged just before it's sent."""
    return _write({"event": "request", **_context.get(), "tool": tool, "host": host,
                   "url": url, "scope_rule": scope_rule, "scope_sha256": scope_sha})


def refused(tool, reason, host=None, scope_sha=None) -> str:
    """Something Akashi refused to send."""
    return _write({"event": "refused", **_context.get(), "tool": tool, "host": host,
                   "reason": reason, "scope_sha256": scope_sha})
