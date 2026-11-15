"""
Prove a subdomain-takeover lead, passively.

Monomi flags these when a hostname's CNAME points at a service name that no
longer exists in DNS (NXDOMAIN) on a service known to let deleted names be
re-registered. Scans can be days old, so Akashi re-checks the same two facts
right now:

  1. the hostname still points at that same CNAME target, and
  2. that target still does not exist, confirmed by both DoH resolvers.

Both still true  -> the lead holds (confirmed for a known-claimable service;
                    for an unknown service, still a lead pending the registry
                    check, so inconclusive here).
Either now false -> the lead no longer holds (someone fixed the record, or the
                    target was recreated), so ruled out.

This asks public DNS resolvers about names. It never contacts the target, and
it never claims or registers anything.
"""

from monomi import common, dnscheck

from akashi.verdict import CONFIRMED, INCONCLUSIVE, RULED_OUT, Verdict

BOTH_RESOLVERS = {"Cloudflare", "Google"}


def prove(item: dict) -> Verdict:
    rule = item["rule"]
    t = item["targets"]
    host = (t.get("hosts") or [""])[0]
    cname = t.get("cname") or ""
    now = common.now_utc()
    ev = []

    current = dnscheck.get_cname(host)
    ev.append(f"{host} CNAME now: {current or 'none'} (scan saw: {cname})")
    if not current or current.rstrip(".") != cname.rstrip("."):
        return Verdict(item["id"], rule, RULED_OUT,
                       f"{host} no longer points at the deleted target {cname} "
                       "(the dangling CNAME is gone)", ev, now)

    exists, confirmed_by = dnscheck.check_exists(cname)
    if exists:
        ev.append(f"{cname} now resolves")
        return Verdict(item["id"], rule, RULED_OUT,
                       f"{cname} now exists again, so {host} is no longer dangling", ev, now)

    ev.append(f"{cname} does not exist; confirmed by: {', '.join(confirmed_by) or 'system DNS only'}")
    if not BOTH_RESOLVERS.issubset(set(confirmed_by)):
        return Verdict(item["id"], rule, INCONCLUSIVE,
                       f"{host} still points at {cname} and it looks gone, but both DoH "
                       "resolvers did not confirm it; re-run before relying on it", ev, now)

    if rule == "takeover_unknown":
        return Verdict(item["id"], rule, INCONCLUSIVE,
                       f"{host} still dangles at {cname}; whether an attacker could claim it "
                       "depends on the registry, which the registry check settles", ev, now)

    return Verdict(item["id"], rule, CONFIRMED,
                   f"{host} still points at {cname}, which still does not exist on both "
                   "resolvers: the takeover lead holds", ev, now)
