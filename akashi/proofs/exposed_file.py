"""
Prove an exposed-files path, actively (v0.6.0, mønømi v1.27).

Monomi's --content found files a host serves that it shouldn't (/.git/HEAD,
/.env, a backup zip...) and checked each one's content: a real Git HEAD, a
real environment file. Its exposed_file path lists every file found on one
host. A scan can be days old, so Akashi asks for each file again, right now:

  1. three made-up paths on the same host first (random names), to see what
     its "not found" looks like today. If a made-up path passes the same file
     check (the site now serves one page for every URL), the host can't show
     anything and the file is not asked for;
  2. one GET for the file, no redirect followed, only the first 16 KB read;
  3. the same content check Monomi used. Akashi never copies it: it calls
     monomi.content.recheck_file(), which uses Monomi's own judge_file(), so
     the two tools can never disagree on what "the real file" is.

Per file, recheck_file says still_served, gone, untrusted or unclear. For the
path as a whole:

  any file still served        -> CONFIRMED, naming every file still there
  every file tried and gone    -> RULED_OUT (removed, or blocked for that
                                  path alone, which is the fix)
  anything else                -> INCONCLUSIVE (a timeout, a host blocking
                                  every path, a catch-all page, or files past
                                  the cap not tried: a file nobody asked for
                                  can't be ruled out)

The evidence says what a file is ("an environment file with 12 settings, 3
named like secrets"), never what it holds: recheck_file keeps no values, keys
or code, and nothing here stores the body.

Like every active proof it is fail-closed on scope (checked again here, and
again by Monomi for every request), logs each request before it is sent, and
carries the honest User-Agent plus the research header when one is loaded.
It sends GET requests only and changes nothing on the target.
"""

from monomi import common, content
from monomi.scope import OutOfScope, request_host

from akashi.verdict import CONFIRMED, INCONCLUSIVE, RULED_OUT, Verdict

# Files re-asked per path: each costs content.RECHECK_REQUESTS requests (three
# made-up paths and the file). The rest are named in the plan and keep the
# verdict from ruling the path out.
MAX_FILES = 5


def files_to_try(item: dict) -> tuple[list[dict], list[dict], list[dict]]:
    """(tried, past the cap, refused): the files this proof asks for, in
    Monomi's order. A file whose URL doesn't name the path's own host, or
    whose kind Monomi doesn't check, is refused and never sent: Akashi asks
    only for what the plan shows, on the host the plan names. The plan and
    the proof both use this, so what a person approves is what is sent."""
    t = item.get("targets") or {}
    host = ((t.get("hosts") or [""])[0]).lower().rstrip(".")
    usable, refused = [], []
    for f in t.get("files") or []:
        url, kind = f.get("url") or "", f.get("kind") or ""
        try:
            real = request_host(url)
        except Exception:  # a malformed URL from a hand-edited scan
            real = None
        if not host or real != host:
            refused.append({**f, "why": f"its URL doesn't point at {host or 'the path host'}"})
        elif kind not in content.CHECKS:
            refused.append({**f, "why": f"{kind!r} isn't a file kind Monomi checks"})
        else:
            usable.append(f)
    return usable[:MAX_FILES], usable[MAX_FILES:], refused


def _combine(host: str, results: list, extra: list, refused: list) -> tuple[str, str]:
    """(status, headline) for the whole path, by the rules in the docstring."""
    served = [f["path"] for f, r in results if r["result"] == content.STILL_SERVED]
    if served:
        return (CONFIRMED, f"{host} still serves {', '.join(served)} to anyone "
                f"({len(served)} of {len(results)} file{'s' if len(results) != 1 else ''} asked)")
    if results and all(r["result"] == content.GONE for _, r in results) and not extra and not refused:
        return (RULED_OUT, f"{host} no longer serves any of the {len(results)} file"
                f"{'s' if len(results) != 1 else ''} Monomi found")
    unclear = [f["path"] for f, r in results if r["result"] != content.GONE]
    bits = []
    if unclear:
        bits.append(f"{', '.join(unclear)} gave no clear answer")
    if extra:
        bits.append(f"{len(extra)} more past the cap weren't asked")
    if refused:
        bits.append(f"{len(refused)} couldn't be asked")
    if not results and not bits:
        bits.append("the path lists no file to ask for")
    return (INCONCLUSIVE, f"none of the files asked on {host} is still served, but "
            + "; ".join(bits) + ", so it can't be ruled out")


def prove(item: dict, *, scope, research=None, log=None, send=None) -> Verdict:
    """send: stands in for monomi.content.recheck_file in tests (same call)."""
    recheck = send or content.recheck_file
    t = item.get("targets") or {}
    host = ((t.get("hosts") or [""])[0]).lower().rstrip(".")
    now = common.now_utc()

    # Fail closed: re-check scope right before sending, not just at plan time.
    if scope is None or not host or not scope.match(host).allowed:
        if log:
            log(host, f"https://{host}/", None)  # records the refusal via the caller
        return Verdict(item["id"], "exposed_file", INCONCLUSIVE,
                       f"refused: {host or 'the host'} is not in the approved scope, so the "
                       "exposed-files check did not run", [f"{host}: out of scope"], now)

    tried, extra, refused = files_to_try(item)
    ev = []
    if research is not None:
        ev.append(f"research header sent: {research.summary}")
    results = []
    for f in tried:
        try:
            r = recheck(f["url"], f["kind"], scope=scope, research=research, on_request=log)
        except OutOfScope as e:
            # Monomi's own check refused it (e.g. the name now connects elsewhere): nothing was sent
            r = {"result": content.UNCLEAR, "why": f"refused before sending: {e}", "calibration": [],
                 "status": None, "requests": 0}
        results.append((f, r))
        made_up = ", ".join(str(c) for c in r.get("calibration", [])) or "no answer"
        ev.append(f"{f['path']} ({f.get('severity', '?')}): {r['result']}: {r['why']}  "
                  f"[made-up paths answered: {made_up}; {r.get('requests', 0)} requests]")
    for f in extra:
        ev.append(f"{f['path']}: not asked (past the cap of {MAX_FILES})")
    for f in refused:
        ev.append(f"{f.get('path', '?')}: not asked ({f['why']})")

    status, headline = _combine(host, results, extra, refused)
    v = Verdict(item["id"], "exposed_file", status, headline, ev, now)
    served = [f for f, r in results if r["result"] == content.STILL_SERVED]
    v.facts = {"still_served": [f["path"] for f in served],
               "secrets": [f["path"] for f in served if f.get("severity") == "secrets"],
               "source": [f["path"] for f in served if f.get("severity") == "source"]}
    return v
