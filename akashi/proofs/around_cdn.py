"""
Prove a go-around-the-CDN lead, actively.

Monomi raises this when a host sits behind a CDN (Cloudflare, etc.) but an
origin IP it found answers web requests directly. The worry: if that origin
serves the protected site itself, an attacker can talk to it straight and skip
whatever the CDN filters. It's only a lead until someone checks, because the
origin might serve something else entirely (a different site, a default page,
or nothing for that host).

Akashi checks it with the requests the plan printed, and only those:

  1. GET https://{front}/        — through the CDN, the normal way in.
  2. GET https://{ip}/ , Host: {front}  — straight to the origin IP, asking it
     for the same site by name (HTTP/1.1 virtual-host routing), once per
     origin candidate (v0.4.0: mønømi v1.24 lists every candidate in one lead,
     ranked), up to plan.MAX_ORIGINS of them, each reached through an in-scope
     name (plan.origins_to_try picks them, for the plan and this proof alike).

Then it compares, for each origin:

  origin serves the same site (200 + matching body/title) -> CONFIRMED: the CDN
      can be bypassed. A stock default page ("Welcome to nginx!") or a short
      generic title ("Home") never counts as a match: many unrelated servers
      show those, so they stay INCONCLUSIVE.
  origin refuses the host (connection refused/reset, or 403/404/421 with a
      different body)                                      -> RULED_OUT: the
      origin doesn't serve this site unprotected.
  anything unclear (timeout, TLS error, 200 but different content)
                                                           -> INCONCLUSIVE.
  origin times out while the CDN still answers             -> INCONCLUSIVE,
      marked ORIGIN_SILENT: what a firewall that silently drops non-CDN
      traffic looks like. A timeout can't prove that, so it never becomes
      ruled out, but the verdict says so plainly and what to do.

With several origins: confirmed if any of them serves the site (naming which),
ruled out only if every one was tried and none does, and inconclusive
otherwise, including when origins past the cap weren't tried. One origin
gives that origin's own verdict, exactly as before.

This is the only check in Akashi that touches a target, so it is fail-closed on
scope, logs every request before sending, and carries the honest Akashi
User-Agent plus the research header when one is loaded. It never follows
redirects, never sends anything but these requests, and never changes
anything on the target.

The origin request connects to a bare IP, so its certificate can't match a
hostname; we don't verify it (and say so in the evidence) and judge by the Host
header instead. An origin that strictly requires SNI may not serve the vhost on
a bare-IP request, which is one reason a real bypass can still come back
INCONCLUSIVE — the safe default.
"""

import hashlib
import re
from dataclasses import dataclass, field

from monomi import common
from monomi.common import ACTIVE_USER_AGENT

from akashi.verdict import CONFIRMED, INCONCLUSIVE, ORIGIN_SILENT, RULED_OUT, Verdict

TIMEOUT = 10          # seconds per request
BODY_BYTES = 4096     # how much of each body we compare
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
# statuses where a server is clearly declining this Host (not serving the site)
REFUSING_STATUS = {400, 403, 404, 409, 421, 503}
# connection errors that mean "nothing serves this host here" (vs. a timeout)
REFUSED_WORDS = ("refused", "reset", "no route", "name or service", "unreachable")
# Words in the stock "it's installed" pages web servers and hosts ship with. If
# both sides show one of these, matching proves nothing: lots of unrelated
# servers serve the same default page. Compared lowercase against the title,
# or the start of the body when there's no title.
DEFAULT_PAGE_WORDS = (
    "welcome to nginx", "apache2 ubuntu default page", "apache2 debian default page",
    "it works!", "test page for the apache", "test page for the nginx",
    "iis windows server", "welcome to caddy", "default web site page",
    "web server's default page", "default page", "coming soon",
    "this site can't be reached", "domain parked", "parked domain",
)
# Error words that mean the TLS handshake with the bare IP failed. Often the
# origin wants the site's name during the handshake (SNI), which a request to
# a bare IP can't send, so this is a known blind spot, not a sign it's safe.
TLS_WORDS = ("ssl", "tls", "handshake", "certificate", "sni")
# Error words that mean the origin never answered in time. A firewall set to
# DROP (ufw "deny", most cloud firewalls) looks exactly like this.
TIMEOUT_WORDS = ("timed out", "timeout")
# A title this short ("Home", "Login", "App") is too common to count alone.
MIN_TITLE_CHARS = 8


@dataclass
class Fetched:
    """What one request got back (or why it didn't). Kept tiny so tests can
    hand one in directly, with no network."""
    url: str
    status: int | None = None
    headers: dict = field(default_factory=dict)
    body: str = ""
    error: str = ""


def _send(url: str, headers: dict, verify: bool) -> Fetched:
    """The real sender: one GET, no redirects, a capped body. Any network
    failure becomes a Fetched with .error set, never an exception."""
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    try:
        r = requests.get(url, headers=headers, verify=verify, allow_redirects=False,
                         timeout=TIMEOUT)
        return Fetched(url, r.status_code, {k.lower(): v for k, v in r.headers.items()},
                       r.text[:BODY_BYTES])
    except requests.RequestException as e:
        return Fetched(url, error=str(e))


def _title(body: str) -> str:
    m = TITLE_RE.search(body)
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""


def _fingerprint(body: str) -> str:
    """A hash of the body with runs of whitespace collapsed, so trivial
    differences don't matter but real content does."""
    norm = re.sub(r"\s+", " ", body.strip())[:BODY_BYTES]
    return hashlib.sha256(norm.encode("utf-8", "replace")).hexdigest()


def is_default_page(body: str) -> bool:
    """Is this a web server's or host's stock placeholder page (nginx's
    "Welcome to nginx!", Apache's "It works!", a parked-domain page...)?"""
    head = (_title(body) or body[:300]).lower()
    return any(w in head for w in DEFAULT_PAGE_WORDS)


def _same_site(cdn: Fetched, origin: Fetched) -> bool:
    """Does the origin serve what the CDN serves? Strict, because a match is
    what turns the lead into CONFIRMED:

      - an empty CDN body can't confirm anything;
      - a stock default page never counts, even if both sides match;
      - identical body fingerprint counts;
      - otherwise a matching <title> counts only if it's specific enough
        (MIN_TITLE_CHARS or longer), not a generic "Home" or "Login".
    """
    if not cdn.body.strip():
        return False
    if is_default_page(cdn.body) or is_default_page(origin.body):
        return False
    if _fingerprint(cdn.body) == _fingerprint(origin.body):
        return True
    ct, ot = _title(cdn.body), _title(origin.body)
    return len(ct) >= MIN_TITLE_CHARS and ct == ot


def _judge(front: str, ip: str, cdn: Fetched, origin: Fetched) -> tuple[str, str, list, str]:
    """One origin's result: (status, headline, extra evidence, reason). The
    rules are the ones in this module's docstring, the same for every origin."""
    ev = []
    # The origin didn't answer at all.
    if origin.status is None:
        # TLS first: a failed handshake means something answered, so even an
        # error that says "reset" here is not proof that nothing serves the site.
        if any(w in origin.error.lower() for w in TLS_WORDS):
            ev.append("the TLS handshake with the bare IP failed; origins that require the "
                      "site name in the handshake (SNI) do this, so Akashi can't tell here")
            return (INCONCLUSIVE, f"the origin {ip} refused the TLS handshake for a bare-IP request; "
                    "it may still serve the site, so check by hand", ev, "")
        if any(w in origin.error.lower() for w in REFUSED_WORDS):
            return (RULED_OUT, f"the origin {ip} does not answer web requests for {front}; "
                    "it can't be reached around the CDN", ev, "")
        if cdn.status is not None and any(w in origin.error.lower() for w in TIMEOUT_WORDS):
            ev.append(f"the CDN answered but the origin stayed silent for {TIMEOUT}s; a "
                      "firewall that drops (not rejects) non-CDN traffic does this, and so "
                      "does a slow or overloaded server, so Akashi can't tell which")
            return (INCONCLUSIVE, f"the origin {ip} went silent (timed out) while the CDN still serves "
                    f"{front}; likely a firewall dropping direct traffic, but a timeout "
                    "can't prove it", ev, ORIGIN_SILENT)
        return (INCONCLUSIVE, f"the origin {ip} didn't respond cleanly ({origin.error}); "
                "re-run before relying on it", ev, "")

    same = _same_site(cdn, origin)
    if origin.status == 200 and not same and is_default_page(origin.body):
        ev.append("the origin answered with a stock default page, which many unrelated "
                  "servers show, so a match can't prove it serves this site")
        return (INCONCLUSIVE, f"the origin {ip} answered with a default page, not clearly {front}; "
                "check by hand", ev, "")
    if origin.status == 200 and same:
        ev.append("origin returned the same site as the CDN (matching body/title)")
        return (CONFIRMED, f"{front} is served directly at the origin {ip}: the CDN can be "
                "bypassed", ev, "")
    if origin.status in REFUSING_STATUS and not same:
        return (RULED_OUT, f"the origin {ip} declines {front} (status {origin.status}): not "
                "reachable around the CDN", ev, "")
    return (INCONCLUSIVE, f"the origin {ip} answered (status {origin.status}) but didn't clearly "
            f"serve {front}; check by hand", ev, "")


def _combine(front: str, results: list, extra: list) -> tuple[str, str, str]:
    """(status, headline, reason) for a lead with several origins (v0.4.0).

    confirmed     any origin serves the site: the CDN can be bypassed there
    ruled out     every origin was tried and none serves it
    inconclusive  anything else, including origins past the cap not tried:
                  an origin nobody asked can't be ruled out"""
    n = len(results)
    confirmed = [ip for ip, (status, *_) in results if status == CONFIRMED]
    if confirmed:
        return (CONFIRMED, f"{front} is served directly at the origin {', '.join(confirmed)}: the CDN "
                f"can be bypassed ({len(confirmed)} of {n} origins tried)", "")
    unclear = [(ip, r) for ip, r in results if r[0] != RULED_OUT]
    if not unclear and not extra:
        ips = ", ".join(ip for ip, _ in results)
        return (RULED_OUT, f"none of the {n} origins ({ips}) serves {front}: it can't be reached "
                "around the CDN", "")
    if not unclear:
        return (INCONCLUSIVE, f"none of the {n} origins tried serves {front}, but {len(extra)} more "
                "past the cap weren't tried, so it can't be ruled out", "")
    silent = all(r[3] == ORIGIN_SILENT for _, r in unclear) and not extra
    return (INCONCLUSIVE, f"{len(unclear)} of {n} origins didn't clearly answer for {front} "
            f"({', '.join(ip for ip, _ in unclear)}); check by hand", ORIGIN_SILENT if silent else "")


def prove(item: dict, *, scope, research=None, log=None, send=None) -> Verdict:
    from akashi.plan import origins_to_try  # here: plan is the one place that picks the origins
    send = send or _send      # resolved here so tests can swap the module's _send
    t = item["targets"]
    front = (t.get("fronted") or [""])[0]
    now = common.now_utc()
    ev = []

    # Fail closed: re-check scope right before sending, not just at plan time.
    if scope is None or not scope.match(front).allowed:
        if log:
            log(front, f"https://{front}/", None)  # records the refusal via the caller
        return Verdict(item["id"], "around_cdn", INCONCLUSIVE,
                       f"refused: {front} is not in the approved scope, so the "
                       "around-the-CDN check did not run", [f"{front}: out of scope"], now)
    # The same origins, in the same order, as the plan the person approved
    tried, extra = origins_to_try(item, scope)
    if not tried:
        return Verdict(item["id"], "around_cdn", INCONCLUSIVE,
                       "refused: no in-scope hostname resolves to an origin, so the "
                       "around-the-CDN check did not run", [f"{front}: no in-scope origin"], now)

    headers = {"User-Agent": ACTIVE_USER_AGENT}
    if research is not None:
        headers.update(research.headers)
        ev.append(f"research header sent: {research.summary}")

    cdn_url = f"https://{front}/"
    # The scope rule that allowed it (e.g. "*.example.com"), recorded in the
    # audit log like mønømi does. Not the host: that's in the log line already.
    rule = scope.match(front).rule

    # Request 1: the normal way in, through the CDN.
    if log:
        log(front, cdn_url, rule)
    cdn = send(cdn_url, headers, True)
    ev.append(f"through the CDN: GET {cdn_url} -> " + (str(cdn.status) if cdn.status else cdn.error))

    # Then each origin, straight to its IP, asking for the same site by name.
    results = []
    for o in tried:
        ip, origin_url = o["ip"], f"https://{o['ip']}/"
        if log:
            log(front, origin_url, rule)
        origin = send(origin_url, {**headers, "Host": front}, False)
        ev.append(f"at the origin {ip} (Host: {front}, certificate not checked): GET {origin_url} -> "
                  + (str(origin.status) if origin.status else origin.error))
        judged = _judge(front, ip, cdn, origin)
        ev += judged[2]
        results.append((ip, judged))

    if len(results) == 1 and not extra:  # one origin: its own verdict, as before v0.4.0
        status, headline, _, reason = results[0][1]
    else:
        ev += [f"origin {ip}: {r[0]}: {r[1]}" for ip, r in results]
        if extra:
            ev.append(f"not tried (past the cap of {len(tried)}): " + ", ".join(o["ip"] for o in extra))
        status, headline, reason = _combine(front, results, extra)
    v = Verdict(item["id"], "around_cdn", status, headline, ev, now)
    v.reason = reason
    v.facts = {"confirmed_origins": [ip for ip, r in results if r[0] == CONFIRMED]}
    return v
