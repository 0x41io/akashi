"""
Registry (RDAP) lookup: is a domain registered, or free for anyone to take?

Used to settle a takeover_unknown lead. Monomi flags it when a hostname's CNAME
points at a name on a service it doesn't recognise. Whether an attacker could
claim it comes down to one question: is the CNAME target's registrable domain
registered?

  - registered  -> someone owns it, so an attacker can't claim it (rules the
                   lead out)
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

import requests
import tldextract
from monomi.common import USER_AGENT

# bundled suffix-list snapshot only: suffix_list_urls=() means it never fetches
_extract = tldextract.TLDExtract(suffix_list_urls=())

# rdap.org redirects to the authoritative registry for the domain's TLD
RDAP_BASE = "https://rdap.org/domain/"

REGISTERED = "registered"
UNKNOWN = "unknown"


def registrable(name: str) -> str:
    """The registrable domain of a name (eTLD+1), or "" if it has none
    (a reserved or unknown TLD, like .test, or a bare hostname)."""
    return _extract(name).top_domain_under_public_suffix or ""


def registration(domain: str) -> tuple[str, str]:
    """(status, evidence) for a registrable domain. status is REGISTERED only
    when RDAP positively says so; everything else is UNKNOWN, never "free"."""
    try:
        resp = requests.get(RDAP_BASE + domain, timeout=15,
                            headers={"User-Agent": USER_AGENT}, allow_redirects=True)
    except requests.RequestException as e:
        return UNKNOWN, f"RDAP lookup failed: {e}"
    if resp.status_code == 200:
        return REGISTERED, f"RDAP says {domain} is registered (HTTP 200)"
    if resp.status_code == 404:
        return UNKNOWN, (f"RDAP has no active registration for {domain} (HTTP 404) — but 404 can also "
                         "mean the TLD has no RDAP service, so verify by hand before treating it as claimable")
    return UNKNOWN, f"RDAP returned HTTP {resp.status_code} for {domain}; can't say"
