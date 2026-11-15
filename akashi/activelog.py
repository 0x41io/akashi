"""
scans/active.log: Akashi's audit trail of every ACTIVE request and refusal.

One JSON object per line, written BEFORE the request is sent, so a request that
hangs or crashes is still on record. Same shape as Monomi's active log, so the
two tools read the same way: what was sent, to whom, under which scope.

    {"time", "event": "request", "via": "cli", "tool", "host", "url",
     "scope_rule", "scope_sha256"}
    {"time", "event": "refused", "via": "cli", "tool", "host"|null,
     "reason", "scope_sha256"}

The file lives under Akashi's data home (AKASHI_HOME, the repo, or ~/.akashi),
the same place as the proof history.
"""

import json
import os
import threading

from monomi.common import now_utc

from akashi import home

_lock = threading.Lock()


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
    return _write({"event": "request", "via": "cli", "tool": tool, "host": host,
                   "url": url, "scope_rule": scope_rule, "scope_sha256": scope_sha})


def refused(tool, reason, host=None, scope_sha=None) -> str:
    """Something Akashi refused to send."""
    return _write({"event": "refused", "via": "cli", "tool": tool, "host": host,
                   "reason": reason, "scope_sha256": scope_sha})
