"""
Prove a broken-access-control lead, actively, between two accounts the person
controls.

The question: can the `actor` account read a resource that belongs to the
`owner` account? Both accounts are the person's own test accounts, so the only
data ever touched is theirs. Akashi sends a fixed, short set of requests and
stops the moment it has its answer — it never walks ids or pages through data.

The requests, in order (the plan prints these before the yes):

  1. POST login as owner.
  2. owner GET resource         -> must be 200. The baseline: the resource
                                   exists and its owner can read it. Without
                                   this, there is nothing to prove.
  3. GET resource with no login -> if this is 200 too, the resource is simply
                                   public, which is not an access-control flaw.
                                   The verdict is INCONCLUSIVE, not confirmed.
  4. POST login as actor.
  5. actor GET resource.

Then:

  actor gets 200 and the SAME response the owner got (compared by a hash of the
      body, so Akashi keeps no copy of the data)   -> CONFIRMED: the actor
      reached another account's resource.
  actor gets 401 / 403 / 404                        -> RULED_OUT: access control
      is doing its job.
  anything else (a login failed, an unexpected status, the owner baseline
      wasn't 200, the resource was public)          -> INCONCLUSIVE, the safe
      default, with the reason.

Fail-closed on scope, like around_cdn: the host is re-checked right before any
request, GET is only ever sent to the one resource and POST only to the login
path, no redirects are followed, the research header rides every request, and
each request is logged before it is sent. Passwords are never logged or
returned.
"""

import hashlib
import re
import time
from dataclasses import dataclass, field

from monomi import common
from monomi.common import ACTIVE_USER_AGENT

from akashi.verdict import CONFIRMED, INCONCLUSIVE, RULED_OUT, Verdict

TIMEOUT = 10          # seconds per request
BODY_BYTES = 4096     # how much of each body we hash
PACE = 1.0            # seconds between requests (1 req/sec)
# The actor being refused the resource looks like one of these.
REFUSING_STATUS = {401, 403, 404}


@dataclass
class Fetched:
    """What one request got back (or why it didn't). Small on purpose so tests
    can hand one in with no network."""
    status: int | None = None
    body: str = ""
    error: str = ""


def _fingerprint(body: str) -> str:
    """A hash of the body with whitespace runs collapsed: the same record
    matches, trivial differences don't, and Akashi keeps no copy of the data."""
    norm = re.sub(r"\s+", " ", body.strip())[:BODY_BYTES]
    return hashlib.sha256(norm.encode("utf-8", "replace")).hexdigest()


def _send(method: str, url: str, headers: dict, body: bytes | None) -> Fetched:
    """The real sender: one request, no redirects, a capped body. Any network
    failure becomes a Fetched with .error set, never an exception."""
    import requests
    try:
        r = requests.request(method, url, headers=headers, data=body,
                             allow_redirects=False, timeout=TIMEOUT)
        return Fetched(r.status_code, r.text[:BODY_BYTES])
    except requests.RequestException as e:
        return Fetched(error=str(e))


def _inconclusive(item, headline, ev, now, reason=""):
    return Verdict(item["id"], "access_between_accounts", INCONCLUSIVE, headline, ev, now, reason=reason)


def prove(item: dict, *, scope, research=None, log=None, send=None, sleep=time.sleep) -> Verdict:
    """Prove (or rule out) one access_between_accounts case.

    item carries the Case and the per-account passwords under "targets":
        {"case": Case, "passwords": {owner: pw, actor: pw}}
    scope, research, log, send: same roles as in around_cdn. sleep is the pacing
    hook (tests pass a no-op)."""
    send = send or _send
    case = item["targets"]["case"]
    passwords = item["targets"]["passwords"]
    now = common.now_utc()
    ev = []

    # Fail closed: re-check scope right before sending, not just at plan time.
    if scope is None or not scope.match(case.host).allowed:
        if log:
            log(case.host, case.resource_url, None)
        return _inconclusive(item, f"refused: {case.host} is not in the approved scope, "
                             "so the access check did not run", [f"{case.host}: out of scope"], now)

    rule = scope.match(case.host).rule
    base_headers = {"User-Agent": ACTIVE_USER_AGENT}
    if research is not None:
        base_headers.update(research.headers)
        ev.append(f"research header sent: {research.summary}")

    sent = 0

    def login(name: str):
        """Log in as `name`, return (token or None, status). Passwords are
        sent here and nowhere else, and never logged or returned."""
        nonlocal sent
        if sent:
            sleep(PACE)
        sent += 1
        if log:
            log(case.host, case.login_url, rule)  # the URL, never the body
        import json
        body = json.dumps({case.login.user_field: name,
                           case.login.password_field: passwords[name]}).encode()
        got = send("POST", case.login_url, {**base_headers, "Content-Type": "application/json"}, body)
        if got.status != 200:
            return None, got.status
        try:
            token = json.loads(got.body).get(case.login.token_field)
        except ValueError:
            token = None
        return (token if isinstance(token, str) and token else None), got.status

    def get(token: str | None):
        """GET the one resource, optionally as a logged-in user."""
        nonlocal sent
        if sent:
            sleep(PACE)
        sent += 1
        if log:
            log(case.host, case.resource_url, rule)
        headers = dict(base_headers)
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return send("GET", case.resource_url, headers, None)

    # 1-2. Baseline: the owner can read their own resource.
    owner_token, owner_login_status = login(case.owner)
    if owner_token is None:
        return _inconclusive(item, f"could not log in as the owner {case.owner} "
                             f"(status {owner_login_status}), so there is nothing to prove",
                             ev + [f"login {case.owner}: {owner_login_status}"], now)
    owner_resp = get(owner_token)
    ev.append(f"owner {case.owner} GET {case.resource}: {owner_resp.status or owner_resp.error}")
    if owner_resp.status != 200:
        return _inconclusive(item, f"the owner {case.owner} did not get the resource "
                             f"(status {owner_resp.status or owner_resp.error}); "
                             "without a baseline there is nothing to prove", ev, now)
    owner_fp = _fingerprint(owner_resp.body)

    # 3. Is it simply public? If so, it's not an access-control flaw.
    anon = get(None)
    ev.append(f"no login GET {case.resource}: {anon.status or anon.error}")
    if anon.status == 200 and _fingerprint(anon.body) == owner_fp:
        return _inconclusive(item, f"the resource is served to anyone with no login, so this is "
                             "a public resource, not broken access control", ev, now)

    # 4-5. The actor: can they read the owner's resource?
    actor_token, actor_login_status = login(case.actor)
    if actor_token is None:
        return _inconclusive(item, f"could not log in as {case.actor} "
                             f"(status {actor_login_status})",
                             ev + [f"login {case.actor}: {actor_login_status}"], now)
    actor_resp = get(actor_token)
    ev.append(f"actor {case.actor} GET {case.resource}: {actor_resp.status or actor_resp.error}")

    if actor_resp.status == 200 and _fingerprint(actor_resp.body) == owner_fp:
        ev.append("the actor received the same resource the owner did "
                  "(identical response fingerprint); no copy of the data is kept")
        return Verdict(item["id"], "access_between_accounts", CONFIRMED,
                       f"{case.actor} can read {case.owner}'s resource {case.resource} — "
                       "broken access control", ev, now,
                       fix=[f"on {case.resource}, check that the logged-in user owns (or is allowed) "
                            "the requested object before returning it, server-side",
                            "apply the same owner check to every endpoint that returns a user's object, "
                            "not just this one",
                            "return 404 (not 403) for someone else's object, so the endpoint doesn't "
                            "reveal that it exists"],
                       owner="app / backend developer")
    if actor_resp.status in REFUSING_STATUS:
        return Verdict(item["id"], "access_between_accounts", RULED_OUT,
                       f"{case.actor} is refused {case.resource} (status {actor_resp.status}); "
                       "access control is enforced", ev, now)
    return _inconclusive(item, f"{case.actor} got an unexpected result "
                         f"(status {actor_resp.status or actor_resp.error}); can't say either way",
                         ev, now)
