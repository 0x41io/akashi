"""
The fix for a confirmed lead: the exact steps that close it.

Built the same way as the verdicts — from Monomi's typed ``rule`` and
``targets``, never from its prose, so a Monomi wording change can't quietly
alter an Akashi fix. Pure data, no network. Only a confirmed verdict gets a
fix; a ruled-out or inconclusive one has nothing to close.

Each fix is a short ordered list of steps a person can act on, plus the role
that usually owns it. Re-check (later) runs the lead's proof again after the
fix to confirm it's actually closed.
"""

# role labels, kept generic (a role, never a person)
DNS_ADMIN = "DNS admin"
SERVER_ADMIN = "server / infrastructure admin"


def _takeover(t: dict) -> tuple[list, str]:
    host = (t.get("hosts") or ["the host"])[0]
    cname = t.get("cname") or "the deleted target"
    return ([
        f"Remove the dangling CNAME record for {host} (or re-point it at a "
        "resource you control).",
        f"Until it's removed, anyone can register {cname} and serve content as "
        f"{host}.",
        f"Then re-check {host} to confirm the CNAME is gone.",
    ], DNS_ADMIN)


def _email(t: dict) -> tuple[list, str]:
    domain = (t.get("hosts") or ["the domain"])[0]
    return ([
        f"Publish a DMARC record for {domain} with a p=reject policy "
        "(or p=quarantine to start), e.g. at _dmarc." + domain + ".",
        "Make sure SPF and DKIM are in place first, so your legitimate mail "
        "still passes once DMARC enforces.",
        "Then re-check to confirm the policy now enforces.",
    ], DNS_ADMIN)


def _around_cdn(t: dict) -> tuple[list, str]:
    ip = (t.get("ips") or ["the origin"])[0]
    front = (t.get("fronted") or ["the fronted host"])[0]
    cdn = t.get("cdn") or "the CDN"
    return ([
        f"Stop {ip} from answering web requests sent directly to it: allow only "
        f"{cdn}'s IP ranges at the firewall, or use an authenticated origin "
        "pull so the origin only serves requests that came through " + cdn + ".",
        f"Or put {front}'s origin behind {cdn} too, so there's no un-fronted "
        "way in.",
        f"Then re-check that {front} can no longer be reached directly at {ip}.",
    ], SERVER_ADMIN)


# rule -> the function that builds its fix
_BUILDERS = {
    "takeover": _takeover,
    "takeover_unknown": _takeover,
    "email_spoofing": _email,
    "around_cdn": _around_cdn,
}


def for_rule(rule: str, targets: dict) -> tuple[list, str]:
    """(steps, owner) for a confirmed lead of this rule. Unknown rule -> no
    fix, so a future rule degrades quietly instead of printing a wrong fix."""
    builder = _BUILDERS.get(rule)
    if builder is None:
        return [], ""
    return builder(targets or {})
