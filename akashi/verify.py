"""
Run the proofs. v0.1 runs the passive ones (DNS and registry): they ask public
services about a name and never contact the target. The one active proof
(around_cdn) is added in the next milestone.

The CLI handles showing the plan, the typed yes, printing and recording; this
module just maps a lead to its proof and runs it, turning any failure into an
inconclusive verdict rather than a crash.
"""

from akashi.proofs import email, takeover
from akashi.verdict import INCONCLUSIVE, Verdict

# rule -> the function that proves it, for the checks that never touch the target
PASSIVE_PROOFS = {
    "takeover": takeover.prove,
    "takeover_unknown": takeover.prove,
    "email_spoofing": email.prove,
}


def is_passive(item: dict) -> bool:
    return item.get("rule") in PASSIVE_PROOFS


def prove(item: dict) -> Verdict:
    """The verdict for one passive lead. A lookup failure (DNS down, etc.)
    becomes inconclusive with the reason, never an exception."""
    try:
        return PASSIVE_PROOFS[item["rule"]](item)
    except Exception as e:  # network/DNS failure: can't say, don't guess
        from monomi import common
        return Verdict(item.get("id", "?"), item.get("rule", "?"), INCONCLUSIVE,
                       f"the check could not complete: {e}", [f"error: {e}"], common.now_utc())
