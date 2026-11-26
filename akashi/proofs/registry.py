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

RATE_LIMIT_WAIT = 5     # seconds to wait after a 429, at most, before the one retry
_seen = {}              # domain -> (status, evidence), so a run asks each domain once


def registrable(name: str) -> str:
    """The registrable domain of a name (eTLD+1), or "" if it has none
    (a reserved or unknown TLD, like .test, or a bare hostname)."""
    return _extract(name).top_domain_under_public_suffix or ""


def _ask(domain: str):
    return requests.get(RDAP_BASE + domain, timeout=15,
                        headers={"User-Agent": USER_AGENT}, allow_redirects=True)


def registration(domain: str) -> tuple[str, str]:
    """(status, evidence) for a registrable domain: REGISTERED only when RDAP
    positively says so, NOT_FOUND for its "no active registration" (404),
    UNKNOWN when it couldn't be checked. Never "free". Each domain is asked
    once per run; a 429 (too many requests) waits once, as RDAP asks, up to
    RATE_LIMIT_WAIT seconds, and tries again."""
    if domain in _seen:
        return _seen[domain]
    try:
        resp = _ask(domain)
        if resp.status_code == 429:
            try:
                wait = min(float(resp.headers.get("Retry-After", RATE_LIMIT_WAIT)), RATE_LIMIT_WAIT)
            except ValueError:
                wait = RATE_LIMIT_WAIT
            time.sleep(max(wait, 0))
            resp = _ask(domain)
    except requests.RequestException as e:
        return UNKNOWN, f"RDAP lookup failed for {domain}: {e}"   # not cached: a retry may work
    if resp.status_code == 200:
        out = (REGISTERED, f"RDAP says {domain} is registered (HTTP 200)")
    elif resp.status_code == 404:
        out = (NOT_FOUND, f"RDAP has no active registration for {domain} (HTTP 404) — but 404 can also "
                          "mean the TLD has no RDAP service, so verify by hand before treating it as claimable")
    elif resp.status_code == 429:
        return UNKNOWN, f"RDAP rate-limited the lookup for {domain} (HTTP 429), even after waiting; can't say"
    else:
        out = (UNKNOWN, f"RDAP returned HTTP {resp.status_code} for {domain}; can't say")
    _seen[domain] = out
    return out
