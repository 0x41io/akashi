"""
Turn Monomi's leads into a plan of what Akashi would do to prove them.

This is pure data: it reads a scan's findings and decides, for each one, what
checks it needs and whether scope allows them. It never touches the network.
`akashi plan` prints the result; `akashi verify` (later) runs it after a typed
yes. Keeping the plan separate from the doing is what lets a person see exactly
what will happen before anything is sent.
"""

from dataclasses import dataclass, field

from akashi.proofs import exposed_file


# How a proof reaches its answer, and whether it touches the target at all:
#   dns          only asks public DNS resolvers about a name (never the target)
#   dns+registry the above plus a domain-registry (RDAP) lookup
#   dns+parent   the above plus ONE non-recursive DNS query to a nameserver of
#                the parent zone (v0.7.0, dangling_ns): the question every
#                resolver asks while looking a name up, sent to the target's
#                DNS provider, never to its web servers
#   active       sends a request to the target or its origin server
PASSIVE_KINDS = ("dns", "dns+registry", "dns+parent")


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


# Origins tried per around-the-CDN lead (v0.4.0, mønømi v1.24 groups every
# origin candidate into one lead): one request each, plus the one through the
# CDN. The rest are named in the plan and keep the verdict from ruling it out.
MAX_ORIGINS = 5


def origins_of(item) -> list[dict]:
    """Every origin candidate of an around-the-CDN lead, ranked, as
    [{"ip", "hosts"}]. mønømi v1.24 lists them in targets["origins"]; an
    older scan has one origin per lead: its first IP and its hosts."""
    t = item["targets"]
    if t.get("origins"):
        return [{"ip": o["ip"], "hosts": list(o.get("hosts") or [])} for o in t["origins"]]
    return [{"ip": ip, "hosts": list(t.get("hosts") or [])} for ip in (t.get("ips") or [])[:1]]


def origins_to_try(item, scope) -> tuple[list[dict], list[dict]]:
    """(tried, past the cap): the origins this check sends a request to, each
    {"ip", "via"} (the first in-scope hostname pointing at it, so the origin is
    reached through a name we're allowed to test, never a bare IP alone), in
    mønømi's order. The plan and the proof both use this, so the requests a
    person approves are exactly the ones sent."""
    usable = []
    for o in origins_of(item):
        via = [h for h in o["hosts"] if _host_in_scope(scope, h)]
        if via:
            usable.append({"ip": o["ip"], "via": via[0]})
    return usable[:MAX_ORIGINS], usable[MAX_ORIGINS:]


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
    tried, _ = origins_to_try(item, scope)
    if not in_scope_direct or not tried:
        if len(origins_of(item)) > 1:
            return False, f"no in-scope hostname resolves to any of the {len(origins_of(item))} origins", []
        return False, f"no in-scope hostname resolves to the origin {ips[0]}", []
    requests = [f"GET https://{front}/  (through the CDN)"]
    requests += [f"GET the origin {o['ip']} with Host: {front}  (reached via {o['via']})" for o in tried]
    return True, "", requests


def _exposed_file(item, scope) -> tuple[bool, str, list]:
    """Scope decision and request list for an exposed-files check (v0.6.0).

    Fail closed: the path's host must be in scope. Each file costs three
    made-up paths (random names, made up when the check runs, so they can't
    be listed exactly) and then the file itself."""
    host = ((item["targets"].get("hosts") or [""])[0])
    if scope is None:
        return False, "no scope file loaded (active checks need one)", []
    if not host:
        return False, "the path names no host", []
    if not _host_in_scope(scope, host):
        return False, f"{host} is out of scope", []
    tried, _, _ = exposed_file.files_to_try(item)
    if not tried:
        return False, f"none of the files listed for {host} can be asked for", []
    requests = []
    for f in tried:
        base = f["url"].split("/", 3)[:3]
        requests.append(f"GET 3 made-up paths on {'/'.join(base)}  (what its not-found looks like now)")
        requests.append(f"GET {f['url']}  (the {f['kind']} file, read up to 16 KB, never followed)")
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

    if rule == "dangling_ns":
        cut = t.get("cut", "?")
        summary = (f"re-check that {cut} is still a broken delegation (both DoH resolvers); ask one "
                   f"of the parent zone's nameservers, once, which nameservers {cut} is delegated "
                   "to; then look up whether their domains are registered")
        return Step(sid, rule, where, "dns+parent", summary, looks_up=[cut])

    if rule == "around_cdn":
        ready, blocked, requests = _around_cdn(item, scope)
        fronted = (t.get("fronted") or ["?"])[0]
        origins = origins_of(item)
        if len(origins) <= 1:
            ip = (t.get("ips") or ["?"])[0]
            summary = (f"check whether {fronted} can be reached directly at the origin {ip}, "
                       "around the CDN")
        else:
            shown = ", ".join(o["ip"] for o in origins[:3]) + (f" and {len(origins) - 3} more"
                                                               if len(origins) > 3 else "")
            summary = (f"check whether {fronted} can be reached directly at any of {len(origins)} "
                       f"origins ({shown}), around the CDN")
            tried, extra = origins_to_try(item, scope)
            if extra:
                summary += (f"; the first {MAX_ORIGINS} in scope are tried, {len(extra)} more "
                            "aren't (they keep the verdict from ruling it out)")
        return Step(sid, rule, where, "active", summary, requests=requests,
                    ready=ready, blocked=blocked)

    if rule == "exposed_file":
        ready, blocked, requests = _exposed_file(item, scope)
        host = (t.get("hosts") or ["?"])[0]
        files = t.get("files") or []
        summary = (f"ask {host} again for the {len(files)} file{'s' if len(files) != 1 else ''} Monomi "
                   "found, and check each is still the real thing")
        tried, extra, refused = exposed_file.files_to_try(item)
        if extra:
            summary += (f"; the first {exposed_file.MAX_FILES} are asked, {len(extra)} more "
                        "aren't (they keep the verdict from ruling it out)")
        if refused and ready:
            summary += f"; {len(refused)} can't be asked (named in the verdict)"
        return Step(sid, rule, where, "active", summary, requests=requests,
                    ready=ready, blocked=blocked)

    # scan.provable() only yields the rules above, so this is unreachable in
    # normal use; it's here so a future rule fails loudly instead of silently.
    raise ValueError(f"no plan step for rule {rule!r}")


def build(provable_items: list, scope=None) -> list:
    """A plan step for every provable lead, in the scan's order."""
    return [step_for(item, scope) for item in provable_items]
