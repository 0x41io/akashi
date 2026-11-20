"""
The research header: an identifying header that some bug bounty programs
require on active traffic (e.g. ``X-Bug-Bounty: your-handle``).

Since v0.2.7 this is Monomi's ``monomi.research`` (Monomi v1.19.0 added its
own ``--research``), so Akashi and Monomi read a research file exactly the
same way: one ``Name: value`` header per line, ``#`` comments, sha256-hashed
and shown in the plan like the scope. Values are stripped (``requests``
refuses a value that starts with a space), and ``Host``, ``Content-Length``,
``Transfer-Encoding`` and ``Connection`` are refused: the file may only say
who sent a request, never change where it goes.

Passive checks never send it — they don't contact the target at all. Only the
active check (going around the CDN) adds it.
"""

from monomi.research import Research, ResearchError, load

__all__ = ["Research", "ResearchError", "load"]
