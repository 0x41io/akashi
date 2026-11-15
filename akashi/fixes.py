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
EMAIL_OWNERS = "DNS admin and email admin"
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


def _email(t: dict, facts: dict | None = None) -> tuple[list, str]:
    domain = (t.get("hosts") or ["the domain"])[0]
    if facts:
        return _email_from_facts(domain, facts)
    # history from before v0.1.3 has no facts: the general steps
    return ([
        f"Publish a DMARC record for {domain} with a p=reject policy "
        "(or p=quarantine to start), e.g. at _dmarc." + domain + ".",
        "Make sure SPF and DKIM are in place first, so your legitimate mail "
        "still passes once DMARC enforces.",
        "Then re-check to confirm the policy now enforces.",
    ], DNS_ADMIN)


def _email_from_facts(domain: str, f: dict) -> tuple[list, str]:
    """Steps built from what the live check found for this domain (v0.1.3).

    Three cases, decided by code:
      - says it sends no mail (SPF is just -all, no DKIM): reject straight away
      - has no SPF and no DKIM: depends on whether it sends mail, so say both
      - sends mail: collect reports, check every sender passes, then enforce
    """
    recheck = "Then run `akashi recheck` to confirm DMARC now enforces."
    if f.get("spf_only_all") and not f.get("dkim"):
        return ([
            f"{domain} says it sends no mail (SPF is just -all, no DKIM found), so DMARC can "
            f"enforce right away: publish \"v=DMARC1; p=reject\" at _dmarc.{domain}.",
            recheck,
        ], DNS_ADMIN)

    if f.get("spf") == "missing" and not f.get("dkim"):
        return ([
            f"{domain} has no SPF and no DKIM. If it sends no mail, publish \"v=spf1 -all\" "
            f"and \"v=DMARC1; p=reject\" at _dmarc.{domain}: that closes it.",
            f"If it does send mail, first add an SPF record listing every service that sends as "
            f"{domain}, and turn on DKIM signing for each of them.",
            f"Then publish DMARC at _dmarc.{domain} with a reporting address (rua=mailto:...), "
            "starting at p=none, and move to p=quarantine, then p=reject, once the reports show "
            "only your own mail.",
            recheck,
        ], EMAIL_OWNERS)

    steps = []
    # 1. Reports first: they show who really sends as the domain before enforcing
    if f.get("dmarc") == "missing":
        steps.append(f"Publish a DMARC record at _dmarc.{domain} starting at p=none with a "
                     "reporting address (rua=mailto:...), so you can see who sends mail as "
                     f"{domain} before enforcing.")
    elif not f.get("dmarc_rua"):
        steps.append(f"Add a reporting address to the DMARC record (rua=mailto:...): today it's "
                     f"p={f.get('dmarc_policy') or 'none'} with no reports, so nobody sees who "
                     f"sends mail as {domain}.")
    else:
        steps.append("Read the DMARC reports you already collect (rua is set) to see who sends "
                     f"mail as {domain}.")

    # 2. The senders: what's already in place, what's missing
    senders = f" (SPF includes {', '.join(f['spf_includes'])})" if f.get("spf_includes") else ""
    if f.get("spf") == "multiple":
        steps.append(f"Merge the SPF records into one: {domain} has more than one, which breaks "
                     "SPF for every receiver.")
    elif f.get("spf") == "missing":
        steps.append(f"Add an SPF record listing every service that sends mail as {domain}.")
    elif f.get("spf_all") == "+all":
        steps.append("Replace '+all' in the SPF record: it lets any server in the world send "
                     f"mail as {domain}.")
    if not f.get("dkim"):
        steps.append("Turn on DKIM signing for each service that sends mail (none found under "
                     "common selectors; a custom selector may already be in use).")
    if f.get("spf") == "present" and f.get("spf_all") != "+all" and f.get("dkim"):
        sel = ", ".join(f["dkim"])
        steps.append(f"SPF and DKIM ({sel}) are already in place. Use the reports to confirm "
                     f"mail from every sender passes{senders}.")
    else:
        steps.append(f"Use the reports to confirm mail from every sender passes{senders}.")

    # 3. Enforce, then prove it
    steps.append("Move DMARC to p=quarantine, then p=reject once the reports show only "
                 "legitimate mail.")
    steps.append(recheck)
    return steps, EMAIL_OWNERS


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


def for_rule(rule: str, targets: dict, facts: dict | None = None) -> tuple[list, str]:
    """(steps, owner) for a confirmed lead of this rule. Unknown rule -> no
    fix, so a future rule degrades quietly instead of printing a wrong fix.
    `facts` are what the proof found (email, v0.1.3); rules that don't use
    them ignore them."""
    builder = _BUILDERS.get(rule)
    if builder is None:
        return [], ""
    if builder is _email:
        return builder(targets or {}, facts)
    return builder(targets or {})
