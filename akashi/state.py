"""
The proof history: an append-only record of every verdict, per target.

One file per target under <data home>/history/<target>.jsonl, one JSON object
per line. Append-only so the trail of "prove, fix, re-check" is never
rewritten: a later re-check adds a line, it doesn't replace the earlier one.
This is the start of fix tracking (did the fix close it?).
"""

import json
import os
import re

from dataclasses import asdict

from akashi import home


def _history_path(target: str) -> str:
    # keep the filename tame whatever the scan's target string is
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", target) or "unknown"
    return home.data_dir("history", f"{safe}.jsonl")


def record(target: str, verdict) -> str:
    """Append one verdict to the target's history. Returns the file path."""
    path = _history_path(target)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps({"target": target, **asdict(verdict)}) + "\n")
    return path


def history(target: str) -> list:
    """Every verdict recorded for a target, oldest first (empty if none)."""
    path = _history_path(target)
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]
