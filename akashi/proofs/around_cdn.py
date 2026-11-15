"""
Prove a go-around-the-CDN lead, actively.

Monomi raises this when a host sits behind a CDN (Cloudflare, etc.) but an
origin IP it found answers web requests directly. The worry: if that origin
serves the protected site itself, an attacker can talk to it straight and skip
whatever the CDN filters. It's only a lead until someone checks, because the
origin might serve something else entirely (a different site, a default page,
or nothing for that host).

Akashi checks it with exactly two requests, the ones the plan printed:

  1. GET https://{front}/        — through the CDN, the normal way in.
  2. GET https://{ip}/ , Host: {front}  — straight to the origin IP, asking it
     for the same site by name (HTTP/1.1 virtual-host routing).

Then it compares:

  origin serves the same site (200 + matching body/title) -> CONFIRMED: the CDN
      can be bypassed. A stock default page ("Welcome to nginx!") or a short
      generic title ("Home") never counts as a match: many unrelated servers
      show those, so they stay INCONCLUSIVE.
  origin refuses the host (connection refused/reset, or 403/404/421 with a
      different body)                                      -> RULED_OUT: the
      origin doesn't serve this site unprotected.
  anything unclear (timeout, TLS error, 200 but different content)
                                                           -> INCONCLUSIVE.

This is the only check in v0.1 that touches a target, so it is fail-closed on
scope, logs both requests before sending, and carries the honest Akashi
User-Agent plus the research header when one is loaded. It never follows
redirects, never sends anything but these two requests, and never changes
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

from akashi.verdict import CONFIRMED, INCONCLUSIVE, RULED_OUT, Verdict

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


def prove(item: dict, *, scope, research=None, log=None, send=None) -> Verdict:
    send = send or _send      # resolved here so tests can swap the module's _send
    t = item["targets"]
    front = (t.get("fronted") or [""])[0]
    ip = (t.get("ips") or [""])[0]
    now = common.now_utc()
    ev = []

    # Fail closed: re-check scope right before sending, not just at plan time.
    if scope is None or not scope.match(front).allowed:
        if log:
            log(front, f"https://{front}/", None)  # records the refusal via the caller
        return Verdict(item["id"], "around_cdn", INCONCLUSIVE,
                       f"refused: {front} is not in the approved scope, so the "
                       "around-the-CDN check did not run", [f"{front}: out of scope"], now)

    headers = {"User-Agent": ACTIVE_USER_AGENT}
    if research is not None:
        headers.update(research.headers)
        ev.append(f"research header sent: {research.summary}")

    cdn_url = f"https://{front}/"
    origin_url = f"https://{ip}/"
    rule = front  # what we matched in scope; recorded in the audit log

    # Request 1: the normal way in, through the CDN.
    if log:
        log(front, cdn_url, rule)
    cdn = send(cdn_url, headers, True)

    # Request 2: straight to the origin IP, asking for the same site by name.
    if log:
        log(front, origin_url, rule)
    origin = send(origin_url, {**headers, "Host": front}, False)

    ev.append(f"through the CDN: GET {cdn_url} -> " + (str(cdn.status) if cdn.status else cdn.error))
    ev.append(f"at the origin {ip} (Host: {front}, certificate not checked): GET {origin_url} -> "
              + (str(origin.status) if origin.status else origin.error))

    # The origin didn't answer at all.
    if origin.status is None:
        # TLS first: a failed handshake means something answered, so even an
        # error that says "reset" here is not proof that nothing serves the site.
        if any(w in origin.error.lower() for w in TLS_WORDS):
            ev.append("the TLS handshake with the bare IP failed; origins that require the "
                      "site name in the handshake (SNI) do this, so Akashi can't tell here")
            return Verdict(item["id"], "around_cdn", INCONCLUSIVE,
                           f"the origin {ip} refused the TLS handshake for a bare-IP request; "
                           "it may still serve the site, so check by hand", ev, now)
        if any(w in origin.error.lower() for w in REFUSED_WORDS):
            return Verdict(item["id"], "around_cdn", RULED_OUT,
                           f"the origin {ip} does not answer web requests for {front}; "
                           "it can't be reached around the CDN", ev, now)
        return Verdict(item["id"], "around_cdn", INCONCLUSIVE,
                       f"the origin {ip} didn't respond cleanly ({origin.error}); "
                       "re-run before relying on it", ev, now)

    same = _same_site(cdn, origin)
    if origin.status == 200 and not same and is_default_page(origin.body):
        ev.append("the origin answered with a stock default page, which many unrelated "
                  "servers show, so a match can't prove it serves this site")
        return Verdict(item["id"], "around_cdn", INCONCLUSIVE,
                       f"the origin {ip} answered with a default page, not clearly {front}; "
                       "check by hand", ev, now)
    if origin.status == 200 and same:
        ev.append("origin returned the same site as the CDN (matching body/title)")
        return Verdict(item["id"], "around_cdn", CONFIRMED,
                       f"{front} is served directly at the origin {ip}: the CDN can be "
                       "bypassed", ev, now)
    if origin.status in REFUSING_STATUS and not same:
        return Verdict(item["id"], "around_cdn", RULED_OUT,
                       f"the origin {ip} declines {front} (status {origin.status}): not "
                       "reachable around the CDN", ev, now)
    return Verdict(item["id"], "around_cdn", INCONCLUSIVE,
                   f"the origin {ip} answered (status {origin.status}) but didn't clearly "
                   f"serve {front}; check by hand", ev, now)
