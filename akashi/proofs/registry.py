"""
Registry (RDAP) lookup: is a domain registered, or free for anyone to take?

Used to settle a takeover_unknown lead. Monomi flags it when a hostname's CNAME
points at a name on a service it doesn't recognise. Whether an attacker could
claim it by registering a domain comes down to one question: is the CNAME
target's registrable domain registered? (A claim inside a vendor's own
platform is a different question, which this doesn't test.)

  - registered  -> someone owns it, so it can't be claimed by registering it
                   (rules the lead out)
  - anything else (no active registration found, no RDAP for the TLD, an error,
                   a reserved TLD) -> left inconclusive. A "free" answer from a
                   redirector is ambiguous (truly free vs no RDAP service), and
                   claiming a domain is a human decision, so Akashi never turns
                   this into a "confirmed, go claim it".

This asks the public RDAP registry about a domain name. It never contacts the
target, and never registers or claims anything.

The registrable domain (eTLD+1) is found with tldextract's bundled Public
Suffix List snapshot, so it's correct for cases like .co.uk and github.io and
never makes a surprise network call.
"""

import time

import requests
import tldextract
from monomi.common import USER_AGENT

# bundled suffix-list snapshot only: suffix_list_urls=() means it never fetches
_extract = tldextract.TLDExtract(suffix_list_urls=())

# rdap.org redirects to the authoritative registry for the domain's TLD
RDAP_BASE = "https://rdap.org/domain/"

REGISTERED = "registered"
# v0.7.0: a 404 ("no active registration") is NOT_FOUND, kept apart from
# UNKNOWN (couldn't check: rate-limited, an error, a timeout). Neither is
# "free", but only NOT_FOUND may raise the "confirm by hand" alarm: a 429 once
# read as "no registration found" for one of Amazon's own awsdns domains.
NOT_FOUND = "not_found"
UNKNOWN = "unknown"

# v0.7.2: a vet with five Route 53 delegations asks ~20 different awsdns
# domains, most of them at one registry (.net, .com), and one retry after 5s
# wasn't enough (np.internal.de: "couldn't be checked for awsdns-16.net").
# Now each registry is paced, and a 429 waits as long as RDAP asks.
PACE = 1.0              # seconds between first asks to the same registry (TLD)
RATE_LIMIT_WAIT = 5     # wait after a 429 with no usable Retry-After; doubles on the next
MAX_WAIT = 30           # never wait longer than this for one retry, whatever Retry-After says
RETRIES = 2             # retries after a 429, so at most 3 asks per domain
_seen = {}              # domain -> (status, evidence), so a run asks each domain once
_last_ask = {}          # TLD -> time.monotonic() of the last first-ask to it


def registrable(name: str) -> str:
    """The registrable domain of a name (eTLD+1), or "" if it has none
    (a reserved or unknown TLD, like .test, or a bare hostname)."""
    return _extract(name).top_domain_under_public_suffix or ""


def _ask(domain: str):
    return requests.get(RDAP_BASE + domain, timeout=15,
                        headers={"User-Agent": USER_AGENT}, allow_redirects=True)


def _pace(domain: str) -> None:
    """Wait until PACE seconds have passed since the last ask to this domain's
    registry (its TLD: one registry runs each), so a run doesn't trip it."""
    tld = domain.rsplit(".", 1)[-1]
    last = _last_ask.get(tld)
    if last is not None:
        gap = last + PACE - time.monotonic()
        if gap > 0:
            time.sleep(gap)
    _last_ask[tld] = time.monotonic()


def _retry_wait(resp, attempt: int) -> float:
    """How long to wait after a 429: RDAP's Retry-After when it gives seconds,
    else RATE_LIMIT_WAIT doubling per attempt; never above MAX_WAIT."""
    try:
        wait = float(resp.headers.get("Retry-After"))
    except (TypeError, ValueError):
        wait = RATE_LIMIT_WAIT * (2 ** attempt)
    return min(max(wait, 0), MAX_WAIT)


def registration(domain: str) -> tuple[str, str]:
    """(status, evidence) for a registrable domain: REGISTERED only when RDAP
    positively says so, NOT_FOUND for its "no active registration" (404),
    UNKNOWN when it couldn't be checked. Never "free". Each domain is asked
    once per run, paced per registry (v0.7.2); a 429 (too many requests)
    waits as RDAP asks (up to MAX_WAIT) and tries again, RETRIES times."""
    if domain in _seen:
        return _seen[domain]
    try:
        _pace(domain)
        resp = _ask(domain)
        for attempt in range(RETRIES):
            if resp.status_code != 429:
                break
            time.sleep(_retry_wait(resp, attempt))
            resp = _ask(domain)
    except requests.RequestException as e:
        return UNKNOWN, f"RDAP lookup failed for {domain}: {e}"   # not cached: a retry may work
    if resp.status_code == 200:
        out = (REGISTERED, f"RDAP says {domain} is registered (HTTP 200)")
    elif resp.status_code == 404:
        out = (NOT_FOUND, f"RDAP has no active registration for {domain} (HTTP 404) — but 404 can also "
                          "mean the TLD has no RDAP service, so verify by hand before treating it as claimable")
    elif resp.status_code == 429:
        return UNKNOWN, (f"RDAP rate-limited the lookup for {domain} (HTTP 429), even after {RETRIES} "
                         "waits; can't say")
    else:
        out = (UNKNOWN, f"RDAP returned HTTP {resp.status_code} for {domain}; can't say")
    _seen[domain] = out
    return out
