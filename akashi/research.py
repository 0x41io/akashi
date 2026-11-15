"""
The research header: an identifying header that some bug bounty programs
require on active traffic (e.g. ``X-Bug-Bounty: your-handle``).

Monomi has no such header, so by design Akashi carries it. It lives in a small
file you point at with ``--research``, one ``Name: value`` header per line.
Akashi hashes that file and shows the hash in the plan, exactly like scope, so
what goes out is auditable: the only headers sent are the ones in the file you
approved. Comments (``#``) and blank lines are ignored.

Passive checks never send it — they don't contact the target at all. Only the
active check (going around the CDN) adds it.
"""

import hashlib
import re
from dataclasses import dataclass

# A header line: a name (letters, digits, hyphens) then ": value".
LINE_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9-]*):[ \t]?(.*)$")


class ResearchError(Exception):
    """The research file can't be used (unreadable or a line isn't a header)."""


@dataclass
class Research:
    headers: dict      # the headers to add to every active request
    sha256: str        # hash of the exact file approved
    path: str

    @property
    def summary(self) -> str:
        return ", ".join(f"{name}: {value}" for name, value in self.headers.items())


def load(path: str) -> Research:
    """Read and hash a research-header file, or raise ResearchError."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        raise ResearchError(f"can't read {path}: {e}")
    sha = hashlib.sha256(raw).hexdigest()
    headers = {}
    for n, line in enumerate(raw.decode("utf-8", "replace").splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = LINE_RE.match(s)
        if not m:
            raise ResearchError(f"line {n} isn't a 'Name: value' header: {line!r}")
        headers[m.group(1)] = m.group(2)
    if not headers:
        raise ResearchError("no headers found in the research file")
    return Research(headers, sha, path)
