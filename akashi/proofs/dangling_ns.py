"""
Prove a dangling NS delegation lead (mønømi's rule dangling_ns), passively.

mønømi flags a zone (the "cut", e.g. dev.example.com) whose lookups fail
because the nameservers it's delegated to refuse to answer for it. Whether
that's a takeover depends on WHICH nameservers they are, and only the parent
zone knows: public resolvers fail as soon as they follow the broken
delegation. So Akashi:

  1. re-checks over DNS-over-HTTPS that the cut is still a broken delegation
     (fixed -> ruled out);
  2. asks ONE of the parent zone's own nameservers, once, which nameservers
     the cut is delegated to: a single non-recursive NS query, the same
     question any resolver asks while looking a name up (`dig +trace` does
     it too). It goes to the target's DNS provider, never to its web
     servers, and the evidence names the server asked;
  3. looks up in the domain registry (RDAP) whether each nameserver's domain
     is registered. One that isn't is the dangerous case: whoever registers
     it answers DNS for every name under the cut.

Like the registry check for takeovers, a "free" answer is never turned into
"confirmed, go claim it": it's inconclusive with a confirm-by-hand headline,
because a 404 can also mean the registry has no RDAP service, and claiming a
domain is a person's decision. Every other outcome that isn't "fixed" is
inconclusive too, saying what was learned (the nameservers, who runs them).
Nothing is ever registered, claimed or created.
"""

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
from monomi import common, dnscheck, takeover

from akashi.proofs import registry
from akashi.verdict import INCONCLUSIVE, RULED_OUT, Verdict

QUERY_TIMEOUT = 5  # seconds for the one direct query

# Who runs a nameserver, from its name (a label for the reader, never a
# verdict: whether a provider lets anyone create a zone isn't decided here).
PROVIDERS = [
    (".awsdns-", "AWS Route 53"), (".azure-dns.", "Azure DNS"), (".akam.net", "Akamai"),
    (".cloudflare.com", "Cloudflare"), (".googledomains.com", "Google"),
    (".google.com", "Google Cloud DNS"), (".nsone.net", "NS1"), (".ultradns.", "UltraDNS"),
    (".dnsmadeeasy.com", "DNS Made Easy"), (".digitalocean.com", "DigitalOcean"),
    (".linode.com", "Linode"), (".domaincontrol.com", "GoDaddy"),
]


def provider_of(ns: str) -> str | None:
    name = "." + ns.lower().rstrip(".")
    return next((p for marker, p in PROVIDERS if marker in name), None)


def _parent(name: str) -> str:
    return name.split(".", 1)[1] if "." in name else name


def parent_server(cut: str) -> tuple[str, str]:
    """(nameserver name, IP) of one of the zone that holds the cut's
    delegation: the zone above the cut, found with ordinary lookups through
    the system resolver. Raises dns.exception.DNSException or LookupError."""
    zone = dns.resolver.zone_for_name(_parent(cut))
    names = sorted(str(r.target).rstrip(".") for r in dns.resolver.resolve(zone, "NS"))
    for ns in names:
        try:
            return ns, dns.resolver.resolve(ns, "A")[0].address
        except dns.exception.DNSException:
            continue
    raise LookupError(f"none of {zone.to_text().rstrip('.')}'s nameservers has an IPv4 address")


def ask_parent(cut: str, server_ip: str) -> dict:
    """The one direct query: a non-recursive NS question to the parent's
    nameserver. Returns {"rcode", "names", "via", "via_names", "no_delegation"}:
      names          NS names for the cut itself (a referral, or an answer if
                     that server also holds the cut)
      via, via_names a referral for a zone BETWEEN the parent and the cut
                     (v0.7.0, PlayStation pcs-nonprod: when that zone is itself
                     broken, the lookup for "the zone above" skips past it, and
                     the server asked refers onward to it). The delegation that
                     matters then sits at `via`
      no_delegation  the server answered for its own zone with no NS for the
                     cut (an SOA in the authority section): no delegation there
    """
    q = dns.message.make_query(cut, dns.rdatatype.NS)
    q.flags &= ~dns.flags.RD          # don't ask it to look anything up for us
    r = dns.query.udp(q, server_ip, timeout=QUERY_TIMEOUT)
    cut = cut.lower().rstrip(".")
    names, via, via_names, soa = [], "", [], False
    for rrset in list(r.answer) + list(r.authority):
        owner = rrset.name.to_text().rstrip(".").lower()
        if rrset.rdtype == dns.rdatatype.SOA:
            soa = True
        if rrset.rdtype != dns.rdatatype.NS:
            continue
        targets = sorted({str(rd.target).rstrip(".").lower() for rd in rrset})
        if owner == cut:
            names += targets
        elif cut.endswith("." + owner) and len(owner) > len(via):
            via, via_names = owner, targets      # the closest zone above the cut
    return {"rcode": dns.rcode.to_text(r.rcode()), "names": sorted(set(names)), "via": via,
            "via_names": via_names, "no_delegation": soa and not names and not via}


def prove(item: dict) -> Verdict:
    t = item["targets"]
    cut = (t.get("cut") or "").rstrip(".").lower()
    now = common.now_utc()
    ev = []

    # 1. still broken? (DoH, the same check mønømi used)
    lame = dnscheck.lame_delegation(cut)
    if not lame:
        ev.append(f"{cut} no longer fails as a broken delegation on DNS-over-HTTPS")
        return Verdict(item["id"], "dangling_ns", RULED_OUT,
                       f"{cut} is no longer a broken delegation (its nameservers answer, or the "
                       "delegation is gone)", ev, now)
    ns_ips, grade, pool = takeover.delegation_view(lame)
    ev.append(f"{cut} still fails: {lame.get('detail') or 'lame delegation'}")

    # 2. which nameservers? (the one direct query)
    try:
        server, ip = parent_server(cut)
        answer = ask_parent(cut, ip)
    except Exception as e:  # DNS down, port 53 blocked, a timeout: say so, never guess
        ev.append(f"couldn't ask the parent zone's nameservers who {cut} is delegated to: {e}")
        on = f" ({pool})" if pool else ""
        return Verdict(item["id"], "dangling_ns", INCONCLUSIVE,
                       f"{cut} is still a broken delegation{on}, but its exact nameservers couldn't "
                       "be learned from the parent zone; check them by hand (dig +trace)", ev, now)
    names, zone = answer["names"], cut
    said = ", ".join(names) if names else "no NS records"
    if not names and answer["via"]:
        names, zone = answer["via_names"], answer["via"]
        said = f"a referral to {zone} ({', '.join(names)})"
    ev.append(f"asked {server} ({ip}) once, non-recursively, for {cut}'s NS: {answer['rcode']}, {said}")
    if not names:
        why = (f"answers for its own zone with no delegation for {cut}" if answer["no_delegation"]
               else "names no nameservers for it")
        return Verdict(item["id"], "dangling_ns", INCONCLUSIVE,
                       f"{cut} still fails, but the parent zone's nameserver ({server}) {why}; the break "
                       "may sit elsewhere: check by hand (dig +trace)", ev, now)
    higher = f" (the delegation sits higher, at {zone})" if zone != cut else ""

    # 3. can those nameservers be had?
    zone_owner = registry.registrable(zone)
    free = []
    for ns in names:
        domain = registry.registrable(ns)
        if domain and domain == zone_owner:
            ev.append(f"{ns} is under {domain} itself: only its owner can create that name")
            continue
        if not domain:
            ev.append(f"{ns} has no registrable domain (reserved or unknown TLD)")
            continue
        status, why = registry.registration(domain)
        ev.append(f"{ns}: {why}")
        if status != registry.REGISTERED:
            free.append((ns, domain))
    runs = sorted({p for p in (provider_of(ns) for ns in names) if p}) or ([pool] if pool else [])
    who = f" ({', '.join(runs)})" if runs else ""

    if free:
        ns, domain = free[0]
        return Verdict(item["id"], "dangling_ns", INCONCLUSIVE,
                       f"{zone} is delegated to {ns}{higher}, and no registration was found for {domain}: "
                       f"if it's free, whoever registers it answers DNS for every name under {zone}. "
                       "Confirm by hand before treating it as claimable", ev, now)
    if grade == "theoretical" or "AWS Route 53" in runs:
        why = ("Route 53 assigns nameservers from a large pool, so getting this exact set again "
               "is impractical")
    else:
        why = "whether that DNS service lets anyone recreate the zone wasn't checked"
    return Verdict(item["id"], "dangling_ns", INCONCLUSIVE,
                   f"{zone} is still delegated to {', '.join(names[:4])}{who}{higher}, every one on a "
                   f"registered domain, so it can't be had by registering one; {why}", ev, now)
