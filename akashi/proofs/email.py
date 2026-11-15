"""
Prove an email-spoofing lead, passively.

Monomi flags a domain as spoofable when its DMARC policy doesn't tell receivers
to reject mail that fails SPF/DKIM. Akashi re-runs the same SPF/DMARC/DKIM
lookup now (Monomi's own emailauth) and compares:

  still "spoofable" -> the lead holds (confirmed)
  now "protected"   -> fixed since the scan (ruled out)
  now "partial"     -> it changed but isn't fully closed (inconclusive)

DNS lookups only. It never sends mail and never contacts the target.

Since v0.1.3 the proof also keeps what the lookup found (SPF and its "all"
rule, the senders SPF includes, DKIM selectors, whether DMARC reports are
collected) as structured facts on the verdict, so the fix is built for this
domain's setup instead of the same steps for everyone.
"""

import re

from monomi import common, emailauth

from akashi.verdict import CONFIRMED, INCONCLUSIVE, RULED_OUT, Verdict


# Only include: names that look like hostnames are kept. The SPF record comes
# from the target, so nothing else from it reaches the fix text or the screen.
_HOSTNAME = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,62}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9-]{0,62}[a-z0-9])?)+$")
_SELECTOR = re.compile(r"[a-z0-9_-]{1,63}")   # a DKIM selector is one DNS label
_ALL_RULES = {"all": "+all", "+all": "+all", "-all": "-all", "~all": "~all", "?all": "?all"}
MAX_INCLUDES = 5


def email_facts(result: dict) -> dict:
    """The parts of Monomi's email check a fix needs, as plain data.

    spf          "missing" | "present" | "multiple"
    spf_all      "-all" | "~all" | "?all" | "+all" | "redirect" | "" (no all rule)
    spf_includes up to MAX_INCLUDES hostnames from include: terms
    spf_only_all True when SPF is just "v=spf1 -all" (the domain says it sends no mail)
    dkim         the DKIM selectors found (from Monomi's fixed list)
    dmarc        "missing" | "present"
    dmarc_policy the p= value, or ""
    dmarc_rua    True when the DMARC record asks for aggregate reports (rua=)
    """
    spf = result.get("spf") or {}
    dmarc = result.get("dmarc") or {}
    record = spf.get("record") or ""
    if not record:
        spf_state = "missing"
    elif " | " in record:
        spf_state = "multiple"
    else:
        spf_state = "present"
    terms = record.lower().split()[1:] if spf_state == "present" else []
    rules = [_ALL_RULES[t] for t in terms if t in _ALL_RULES]
    spf_all = rules[-1] if rules else ("redirect" if any(t.startswith("redirect=") for t in terms) else "")
    includes = [t[len("include:"):] for t in terms if t.startswith("include:")]
    includes = [h for h in includes if _HOSTNAME.match(h)][:MAX_INCLUDES]
    tags = emailauth.parse_tags(dmarc.get("record") or "") if dmarc.get("record") else {}
    return {
        "spf": spf_state,
        "spf_all": spf_all,
        "spf_includes": includes,
        "spf_only_all": spf_state == "present" and terms == ["-all"],
        "dkim": [s for s in ((result.get("dkim") or {}).get("selectors") or [])
                 if _SELECTOR.fullmatch(s)],
        "dmarc": "present" if dmarc.get("record") else "missing",
        "dmarc_policy": dmarc.get("policy") or "",
        "dmarc_rua": bool(tags.get("rua")),
    }


def _evidence(scan_said: str, current: str, f: dict) -> list:
    spf = {"missing": "none", "multiple": "more than one (SPF breaks)"}.get(f["spf"], "present")
    if f["spf"] == "present" and f["spf_all"]:
        spf += f" ({f['spf_all']})"
    return [
        f"scan verdict: {scan_said}; now: {current}",
        ("DMARC policy now: no DMARC record" if f["dmarc"] == "missing"
         else f"DMARC policy now: {f['dmarc_policy'] or 'none'}"),
        f"DMARC reports (rua): {'set' if f['dmarc_rua'] else 'none set'}",
        f"SPF record: {spf}",
        "DKIM: " + (f"{', '.join(f['dkim'])} selector{'s' if len(f['dkim']) > 1 else ''} found"
                    if f["dkim"] else "none found under common selectors"),
    ]


def prove(item: dict) -> Verdict:
    domain = (item["targets"].get("hosts") or [""])[0]
    scan_said = item["targets"].get("verdict") or "spoofable"
    now = common.now_utc()

    result = emailauth.check_email(domain)
    current = result["verdict"]["verdict"]
    facts = email_facts(result)
    ev = _evidence(scan_said, current, facts)

    if current == "spoofable":
        v = Verdict(item["id"], "email_spoofing", CONFIRMED,
                    f"{domain} is still spoofable: DMARC does not enforce", ev, now)
    elif current == "protected":
        v = Verdict(item["id"], "email_spoofing", RULED_OUT,
                    f"{domain} is now protected: DMARC enforces (fixed since the scan)", ev, now)
    else:
        v = Verdict(item["id"], "email_spoofing", INCONCLUSIVE,
                    f"{domain} is now only partly protected (changed since the scan)", ev, now)
    v.facts = facts
    return v
