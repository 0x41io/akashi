"""
Prove an email-spoofing lead, passively.

Monomi flags a domain as spoofable when its DMARC policy doesn't tell receivers
to reject mail that fails SPF/DKIM. Akashi re-runs the same SPF/DMARC/DKIM
lookup now (Monomi's own emailauth) and compares:

  still "spoofable" -> the lead holds (confirmed)
  now "protected"   -> fixed since the scan (ruled out)
  now "partial"     -> it changed but isn't fully closed (inconclusive)

DNS lookups only. It never sends mail and never contacts the target.
"""

from monomi import common, emailauth

from akashi.verdict import CONFIRMED, INCONCLUSIVE, RULED_OUT, Verdict


def prove(item: dict) -> Verdict:
    domain = (item["targets"].get("hosts") or [""])[0]
    scan_said = item["targets"].get("verdict") or "spoofable"
    now = common.now_utc()

    result = emailauth.check_email(domain)
    current = result["verdict"]["verdict"]
    dmarc = (result.get("dmarc") or {}).get("policy")
    ev = [
        f"scan verdict: {scan_said}; now: {current}",
        f"DMARC policy now: {dmarc or 'none'}",
        f"SPF record: {'present' if (result.get('spf') or {}).get('record') else 'none'}",
    ]

    if current == "spoofable":
        return Verdict(item["id"], "email_spoofing", CONFIRMED,
                       f"{domain} is still spoofable: DMARC does not enforce", ev, now)
    if current == "protected":
        return Verdict(item["id"], "email_spoofing", RULED_OUT,
                       f"{domain} is now protected: DMARC enforces (fixed since the scan)", ev, now)
    return Verdict(item["id"], "email_spoofing", INCONCLUSIVE,
                   f"{domain} is now only partly protected (changed since the scan)", ev, now)
