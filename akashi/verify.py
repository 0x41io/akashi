"""
Run the proofs. v0.1 runs the passive ones (DNS and registry): they ask public
services about a name and never contact the target. The one active proof
(around_cdn) is added in the next milestone.

The CLI handles showing the plan, the typed yes, printing and recording; this
module just maps a lead to its proof and runs it, turning any failure into an
inconclusive verdict rather than a crash.
"""

from akashi import activelog
from akashi.proofs import around_cdn, email, takeover
from akashi.verdict import INCONCLUSIVE, Verdict

# rule -> the function that proves it, for the checks that never touch the target
PASSIVE_PROOFS = {
    "takeover": takeover.prove,
    "takeover_unknown": takeover.prove,
    "email_spoofing": email.prove,
}

# rule -> the function that proves it, for the checks that send real requests
ACTIVE_PROOFS = {
    "around_cdn": around_cdn.prove,
}


def is_passive(item: dict) -> bool:
    return item.get("rule") in PASSIVE_PROOFS


def is_active(item: dict) -> bool:
    return item.get("rule") in ACTIVE_PROOFS


def _inconclusive(item: dict, reason: str) -> Verdict:
    from monomi import common
    return Verdict(item.get("id", "?"), item.get("rule", "?"), INCONCLUSIVE,
                   f"the check could not complete: {reason}", [f"error: {reason}"],
                   common.now_utc())


def prove(item: dict) -> Verdict:
    """The verdict for one passive lead. A lookup failure (DNS down, etc.)
    becomes inconclusive with the reason, never an exception."""
    try:
        return PASSIVE_PROOFS[item["rule"]](item)
    except Exception as e:  # network/DNS failure: can't say, don't guess
        return _inconclusive(item, str(e))


def prove_active(item: dict, *, scope, research=None, send=None) -> Verdict:
    """The verdict for one active lead (around the CDN). Builds the audit-log
    callback so the CLI stays simple, and turns any failure into inconclusive.
    An out-of-scope target is refused inside the proof, before any request."""
    sha = getattr(scope, "sha256", None)

    def log(host, url, rule):
        if rule is None:
            activelog.refused("around_cdn", f"{host} out of scope", host=host, scope_sha=sha)
        else:
            activelog.request("around_cdn", host, url, rule, sha)

    kwargs = {"scope": scope, "research": research, "log": log}
    if send is not None:
        kwargs["send"] = send
    try:
        return ACTIVE_PROOFS[item["rule"]](item, **kwargs)
    except Exception as e:
        activelog.refused("around_cdn", f"error: {e}", scope_sha=sha)
        return _inconclusive(item, str(e))
