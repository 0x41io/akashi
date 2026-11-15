"""
The result of trying to prove one lead.

A verdict is deliberately one of three things. "inconclusive" is the default
and the safe one: a partial or unclear check never becomes "confirmed". Every
verdict carries its own evidence (the DNS answers, who confirmed them, the
time), so a person or Kaidoku can see exactly why.
"""

from dataclasses import dataclass, field

CONFIRMED = "confirmed"      # the lead still holds, proven now with evidence
RULED_OUT = "ruled_out"      # the lead no longer holds (e.g. fixed since the scan)
INCONCLUSIVE = "inconclusive"  # not enough to say either way; says what's missing

# Reasons an inconclusive verdict can carry, so recheck (and later Kaidoku)
# can explain it without parsing the headline.
ORIGIN_SILENT = "origin_silent"  # origin timed out while the CDN still answered


@dataclass
class Verdict:
    id: str                             # the lead's id, e.g. "P1"
    rule: str
    status: str                         # CONFIRMED / RULED_OUT / INCONCLUSIVE
    headline: str                       # one line a person reads first
    evidence: list = field(default_factory=list)   # the facts it rests on
    checked_at: str = ""                # when the check ran (UTC)
    fix: list = field(default_factory=list)        # how to close it (confirmed only)
    owner: str = ""                     # who typically owns that fix
    key: str = ""                       # stable lead key (scan.lead_key), used by recheck
    reason: str = ""                    # why it's inconclusive, when code knows (e.g. ORIGIN_SILENT)
    facts: dict = field(default_factory=dict)      # structured facts a fix is built from (email, v0.1.3)

    def line(self) -> str:
        mark = {CONFIRMED: "✓", RULED_OUT: "✗", INCONCLUSIVE: "?"}.get(self.status, "?")
        return f"[{self.id}] {self.rule}: {mark} {self.status} — {self.headline}"
