"""
Read a saved Monomi scan and pick the leads Akashi can prove.

Akashi never re-derives what Monomi decided. It reads the typed fields Monomi
writes since v1.15.0 (``rule`` and ``targets`` on every item) and refuses any
scan too old to have them, instead of guessing from the text.
"""

import json

from monomi import common

# The oldest Monomi a scan may come from: v1.15.0 is the first with rule +
# targets on every finding (monomi/tests/test_contract.py locks them).
MIN_MONOMI = (1, 15, 0)

# The rules Akashi knows how to prove. Everything else in a scan is left
# alone (reported as "not handled yet"), never guessed at.
PROVABLE = ("takeover", "takeover_unknown", "email_spoofing", "around_cdn", "exposed_file")


class ScanError(Exception):
    """A saved scan can't be used: unreadable, not a Monomi scan, or too old."""


def load_scan(path: str) -> dict:
    """The parsed scan at ``path``, or a ScanError that says what's wrong."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise ScanError(f"no scan file at {path}")
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ScanError(f"{path} isn't valid JSON (is it a Monomi --json scan?)")
    if not isinstance(data, dict):
        raise ScanError(f"{path} isn't a Monomi scan (expected an object at the top)")
    return data


def scan_version(scan: dict) -> tuple[int, int, int]:
    """The scan's Monomi version, or a ScanError if it's missing or too old.

    A scan from before v1.15.0 has no ``monomi_version`` (or a version below
    the minimum), so it lacks the rule/targets fields Akashi reads. Comparing
    is done as numbers, not text, by monomi.common.scan_version.
    """
    version = common.scan_version(scan)
    if version is None:
        raise ScanError(
            "this scan has no monomi_version, so it predates the fields Akashi "
            "needs. Re-run it with Monomi "
            + ".".join(map(str, MIN_MONOMI)) + " or newer.")
    if version < MIN_MONOMI:
        raise ScanError(
            f"this scan is from Monomi {'.'.join(map(str, version))}, but Akashi "
            f"needs {'.'.join(map(str, MIN_MONOMI))} or newer. Re-run the scan.")
    return version


def items(scan: dict):
    """Every finding and lead in the scan, each tagged with where it sits.

    Monomi puts confirmed-twice takeovers and email spoofing in ``paths``
    (they passed the gate) and the rest in ``leads``; Akashi re-proves both,
    since a scan can be days old. Yields (where, item) with where in
    {"path", "lead"}.
    """
    built = scan.get("paths") or {}
    for where, group in (("path", "paths"), ("lead", "leads")):
        for item in built.get(group) or []:
            yield where, item


def _names(values) -> list[str]:
    """Host names compared the way DNS does: lowercase, no trailing dot,
    sorted so their order in a scan never matters."""
    return sorted(str(v).lower().rstrip(".") for v in values or [])


def lead_key(item: dict) -> str:
    """A stable name for a lead, built from what it is about (its rule and
    targets), never from its id.

    Monomi numbers leads by position (P1, L2, ...), so the same lead can get
    a different id in the next scan once something else is fixed. The key
    stays the same as long as the lead is about the same things:

      takeover / takeover_unknown -> the host and the CNAME it points at
      email_spoofing              -> the domain
      around_cdn                  -> the fronted hosts and the CDN (mønømi v1.24),
                                     or the fronted host and the origin IP (older scans)
      exposed_file                -> the host alone (mønømi v1.27): its file list
                                     shrinks as files are removed, and its IPs
                                     rotate behind a CDN, but it's the same question
      anything else               -> its hosts and IPs

    e.g. "takeover:old-app.example.test>old-app.azurewebsites.net".
    """
    rule = item.get("rule") or "?"
    t = item.get("targets") or {}
    if rule in ("takeover", "takeover_unknown"):
        parts = [",".join(_names(t.get("hosts"))), str(t.get("cname") or "").lower().rstrip(".")]
    elif rule == "email_spoofing":
        parts = [",".join(_names(t.get("hosts")))]
    elif rule == "around_cdn" and "origins" in t:
        # mønømi v1.24: one lead per CDN, so its fronted hosts and CDN name it.
        # Its origin IPs change (load balancers rotate), and with them in the
        # key every re-check would start a new history for the same question
        parts = [",".join(_names(t.get("fronted"))), str(t.get("cdn") or "cdn").lower()]
    elif rule == "around_cdn":
        parts = [",".join(_names(t.get("fronted"))), ",".join(sorted(t.get("ips") or []))]
    elif rule == "exposed_file":
        parts = [",".join(_names(t.get("hosts")))]
    else:
        parts = [",".join(_names(t.get("hosts"))), ",".join(sorted(t.get("ips") or []))]
    return f"{rule}:" + ">".join(parts)


def provable(scan: dict) -> list[dict]:
    """The scan's findings and leads whose rule Akashi can prove.

    Each is returned as-is (it already carries ``id``, ``rule`` and
    ``targets``), with ``where`` added so the caller knows if Monomi had it as
    a path or a lead.
    """
    out = []
    for where, item in items(scan):
        if item.get("rule") in PROVABLE:
            out.append({**item, "where": where})
    return out


def unhandled(scan: dict) -> list[dict]:
    """The scan's findings and leads whose rule Akashi can't prove yet.

    Surfaced so nothing is skipped silently: the plan names them instead of
    quietly dropping them.
    """
    out = []
    for where, item in items(scan):
        if item.get("rule") not in PROVABLE:
            out.append({**item, "where": where})
    return out
