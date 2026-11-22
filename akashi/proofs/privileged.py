"""
Prove a missing-function-level-access-control lead, actively.

The question: can a low-privilege account (`actor`) reach an admin-only
endpoint that the `privileged` account can? Both are the person's own test
accounts, so the only data touched is theirs. This is OWASP's "broken access
control" at the function level, the sibling of access.py's object-level (IDOR)
check: there the actor reaches another user's object; here the actor reaches a
function its role shouldn't have at all.

The requests, in order (the plan prints these before the yes):

  1. POST login as the privileged account.
  2. privileged GET endpoint  -> must be 200. The baseline: the endpoint works
                                 for an allowed account. Without it there is
                                 nothing to prove.
  3. GET endpoint with no login -> an admin-only endpoint should refuse the
                                 anonymous. If it serves anyone, it is public,
                                 not a privileged function (INCONCLUSIVE).
  4. POST login as the actor (low-privilege).
  5. actor GET endpoint.

Then:

  actor gets 200 and the SAME response the privileged account got (compared by
      a body hash, so Akashi keeps no copy), AND the anonymous request was
      refused                                     -> CONFIRMED: the actor
      reached a function its role shouldn't have.
  actor gets 401 / 403 / 404                      -> RULED_OUT: the endpoint
      checks the role.
  anything else — a login failed, the baseline wasn't 200, the endpoint was
      public, the anonymous request also got 200, or the actor's response
      didn't match the privileged one             -> INCONCLUSIVE, the safe
      default, with the reason.

Requiring the actor's response to match the privileged baseline exactly is the
conservative choice: it never calls a soft-200 error page a finding, at the
cost of staying silent (INCONCLUSIVE) on endpoints where an over-privileged
actor would legitimately see different data. A false "confirmed" would waste a
bounty submission and dent the brand promise; a false "inconclusive" just asks
a human to look. Same fail-closed rules as access.py: scope re-checked right
before any request, GET only to the endpoint and POST only to the login path,
no redirects, the research header on every request, each request logged first,
and passwords never logged or returned.
"""

import time

from monomi import common
from monomi.common import ACTIVE_USER_AGENT

from akashi.proofs import access
from akashi.verdict import CONFIRMED, INCONCLUSIVE, RULED_OUT, Verdict

RULE = "privileged_function"
REFUSING_STATUS = access.REFUSING_STATUS   # 401 / 403 / 404: the actor being refused


def _inconclusive(item, headline, ev, now):
    return Verdict(item["id"], RULE, INCONCLUSIVE, headline, ev, now)


def prove(item: dict, *, scope, research=None, log=None, send=None, sleep=None) -> Verdict:
    """Prove (or rule out) one privileged_function case. Same item shape as
    access.prove: {"case": Case, "passwords": {privileged: pw, actor: pw}}.
    The Case's `owner` field holds the privileged (baseline) account."""
    send = send or access._send
    sleep = sleep or time.sleep
    case = item["targets"]["case"]
    passwords = item["targets"]["passwords"]
    now = common.now_utc()
    ev = []

    # Fail closed: re-check scope right before sending, not just at plan time.
    if scope is None or not scope.match(case.host).allowed:
        if log:
            log(case.host, case.resource_url, None)
        return _inconclusive(item, f"refused: {case.host} is not in the approved scope, so the "
                             "privilege check did not run", [f"{case.host}: out of scope"], now)

    rule = scope.match(case.host).rule
    base_headers = {"User-Agent": ACTIVE_USER_AGENT}
    if research is not None:
        base_headers.update(research.headers)
        ev.append(f"research header sent: {research.summary}")

    http = access.Session(case, passwords, rule=rule, base_headers=base_headers,
                          log=log, send=send, sleep=sleep)
    priv, actor = case.owner, case.actor   # owner holds the privileged account

    # 1-2. Baseline: the privileged account can use the endpoint.
    priv_auth, priv_status = http.login(priv)
    if priv_auth is None:
        return _inconclusive(item, f"could not log in as the privileged account {priv} "
                             f"(status {priv_status}), so there is nothing to prove",
                             ev + [f"login {priv}: {priv_status}"], now)
    priv_resp = http.get(priv_auth)
    ev.append(f"privileged {priv} GET {case.resource}: {priv_resp.status or priv_resp.error}")
    if priv_resp.status != 200:
        return _inconclusive(item, f"the privileged account {priv} did not get the endpoint "
                             f"(status {priv_resp.status or priv_resp.error}); without a "
                             "baseline there is nothing to prove", ev, now)
    priv_fp = access._fingerprint(priv_resp.body)

    # 3. Is it protected at all? An anonymous request should be refused.
    anon = http.get(None)
    ev.append(f"no login GET {case.resource}: {anon.status or anon.error}")
    if anon.status == 200 and access._fingerprint(anon.body) == priv_fp:
        return _inconclusive(item, "the endpoint is served to anyone with no login, so it is a "
                             "public endpoint, not a privileged function", ev, now)

    # 4-5. The actor: a low-privilege account that should be refused.
    actor_auth, actor_status = http.login(actor)
    if actor_auth is None:
        return _inconclusive(item, f"could not log in as {actor} (status {actor_status})",
                             ev + [f"login {actor}: {actor_status}"], now)
    actor_resp = http.get(actor_auth)
    ev.append(f"actor {actor} GET {case.resource}: {actor_resp.status or actor_resp.error}")

    if actor_resp.status == 200 and access._fingerprint(actor_resp.body) == priv_fp:
        if anon.status == 200:
            # anon got 200 too (a different body than privileged): whether the
            # endpoint is really restricted is murky, so don't confirm.
            return _inconclusive(item, f"{actor} received the privileged response, but an "
                                 "anonymous request also returned 200, so whether the endpoint "
                                 "is really restricted is unclear; check by hand", ev, now)
        ev.append("the actor received the same response as the privileged account "
                  "(identical fingerprint); no copy of the data is kept")
        return Verdict(item["id"], RULE, CONFIRMED,
                       f"{actor} can reach the privileged endpoint {case.resource} — missing "
                       "function-level access control", ev, now,
                       fix=[f"enforce the role/privilege check for {case.resource} on the server, "
                            "for every request, not only by hiding the link in the UI",
                            "apply the same check to every admin-only endpoint, not just this one",
                            "return 403 (or 404) for an account without the role, and test it with a "
                            "low-privilege account, not only an admin"],
                       owner="app / backend developer")
    if actor_resp.status in REFUSING_STATUS:
        return Verdict(item["id"], RULE, RULED_OUT,
                       f"{actor} is refused {case.resource} (status {actor_resp.status}); the "
                       "endpoint checks the role", ev, now)
    return _inconclusive(item, f"{actor} got an unexpected result "
                         f"(status {actor_resp.status or actor_resp.error}); can't say either way",
                         ev, now)
