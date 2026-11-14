"""
Turn Monomi's leads into a plan of what Akashi would do to prove them.

This is pure data: it reads a scan's findings and decides, for each one, what
checks it needs and whether scope allows them. It never touches the network.
`akashi plan` prints the result; `akashi verify` (later) runs it after a typed
yes. Keeping the plan separate from the doing is what lets a person see exactly
what will happen before anything is sent.
"""

from dataclasses import dataclass, field


# How a proof reaches its answer, and whether it touches the target at all:
#   dns          only asks public DNS resolvers about a name (never the target)
#   dns+registry the above plus a domain-registry (RDAP) lookup
#   active       sends a request to the target or its origin server
PASSIVE_KINDS = ("dns", "dns+registry")


@dataclass
class Step:
    """One lead and what proving it would take. Built without any network."""
    id: str
    rule: str
    where: str                       # "path" or "lead", as Monomi had it
    kind: str                        # one of the kinds above
    summary: str                     # one line: what proving it would check
    looks_up: list = field(default_factory=list)   # names/domains a passive check queries
    requests: list = field(default_factory=list)   # active requests, in order (strings)
    ready: bool = True               # would it actually run?
    blocked: str = ""                # if not, why (scope)

    @property
    def active(self) -> bool:
        return self.kind not in PASSIVE_KINDS


def _host_in_scope(scope, host: str) -> bool:
    return scope is not None and scope.match(host).allowed


def _around_cdn(item, scope) -> tuple[bool, str, list]:
    """Scope decision and request list for a go-around-the-CDN check.

    An active check is fail-closed: it runs only inside an approved scope. For
    this one that means the fronted host is in scope, and at least one in-scope
    hostname (Monomi already filtered targets["hosts"] to those) resolves to
    the origin, so the origin is reached through a name we're allowed to test,
    not a bare IP.
    """
    t = item["targets"]
    fronted = t.get("fronted") or []
    direct = t.get("hosts") or []
    ips = t.get("ips") or []
    if scope is None:
        return False, "no scope file loaded (active checks need one)", []
    if not fronted or not ips:
        return False, "the lead is missing a fronted host or an origin IP", []
    front = fronted[0]
    in_scope_direct = [h for h in direct if _host_in_scope(scope, h)]
    if not _host_in_scope(scope, front):
        return False, f"the fronted host {front} is out of scope", []
    if not in_scope_direct:
        return False, f"no in-scope hostname resolves to the origin {ips[0]}", []
    ip = ips[0]
    requests = [
        f"GET https://{front}/  (through the CDN)",
        f"GET the origin {ip} with Host: {front}  (reached via {in_scope_direct[0]})",
    ]
    return True, "", requests


def step_for(item: dict, scope=None) -> Step:
    """The plan step for one provable lead. No network, no scope changes."""
    rule, t = item["rule"], item["targets"]
    sid, where = item.get("id", "?"), item.get("where", "lead")

    if rule in ("takeover", "takeover_unknown"):
        host = (t.get("hosts") or ["?"])[0]
        cname = t.get("cname", "?")
        looks_up = [host, cname]
        summary = (f"re-check now that {host} still points at {cname} and that "
                   f"{cname} still does not exist (both DoH resolvers)")
        if rule == "takeover_unknown":
            summary += f"; then look up whether the domain of {cname} is free to register"
            return Step(sid, rule, where, "dns+registry", summary, looks_up=looks_up)
        return Step(sid, rule, where, "dns", summary, looks_up=looks_up)

    if rule == "email_spoofing":
        domain = (t.get("hosts") or ["?"])[0]
        return Step(sid, rule, where, "dns", f"re-check SPF, DMARC and DKIM for {domain}",
                    looks_up=[domain])

    if rule == "around_cdn":
        ready, blocked, requests = _around_cdn(item, scope)
        fronted = (t.get("fronted") or ["?"])[0]
        ip = (t.get("ips") or ["?"])[0]
        summary = (f"check whether {fronted} can be reached directly at the origin {ip}, "
                   "around the CDN")
        return Step(sid, rule, where, "active", summary, requests=requests,
                    ready=ready, blocked=blocked)

    # scan.provable() only yields the rules above, so this is unreachable in
    # normal use; it's here so a future rule fails loudly instead of silently.
    raise ValueError(f"no plan step for rule {rule!r}")


def build(provable_items: list, scope=None) -> list:
    """A plan step for every provable lead, in the scan's order."""
    return [step_for(item, scope) for item in provable_items]
