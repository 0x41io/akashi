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

How the login keeps a session is set by the case (login.session, v0.5.0):
"token" (default) reads a token from the login's JSON body and sends it as
`Authorization: Bearer ...`; "cookie" captures the login's Set-Cookie and
sends it back as `Cookie: ...` on every later request, the way a browser
does, so the check works against ordinary session-cookie web apps and not
only JSON-token APIs. Either way the login body is sent once, to the login
path only, and the session credential it returns is never logged or returned.

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
    cookie: str = ""      # the cookies the response set, "name=value; ..." (cookie-session login)


def _fingerprint(body: str) -> str:
    """A hash of the body with whitespace runs collapsed: the same record
    matches, trivial differences don't, and Akashi keeps no copy of the data."""
    norm = re.sub(r"\s+", " ", body.strip())[:BODY_BYTES]
    return hashlib.sha256(norm.encode("utf-8", "replace")).hexdigest()


def _send(method: str, url: str, headers: dict, body: bytes | None) -> Fetched:
    """The real sender: one request, no redirects, a capped body. Any network
    failure becomes a Fetched with .error set, never an exception. The cookies
    the response set are captured (for a cookie-session login), not the request's."""
    import requests
    try:
        r = requests.request(method, url, headers=headers, data=body,
                             allow_redirects=False, timeout=TIMEOUT)
        cookie = "; ".join(f"{c.name}={c.value}" for c in r.cookies)
        return Fetched(r.status_code, r.text[:BODY_BYTES], cookie=cookie)
    except requests.RequestException as e:
        return Fetched(error=str(e))


def _inconclusive(item, headline, ev, now, reason=""):
    return Verdict(item["id"], "access_between_accounts", INCONCLUSIVE, headline, ev, now, reason=reason)


class Session:
    """How an app-logic proof talks to the target: log in as an account, then
    GET the one resource. Scope is already checked by the caller; this class
    owns the pacing, the per-request log line, the GET-to-resource /
    POST-to-login-only rule, and the cookie-or-token session (login.session).
    Shared by every app-logic proof, so the session handling and its safety
    rules live in one place. A password is sent only inside login(), to the
    login path, and the token or cookie it yields is never logged or returned."""

    def __init__(self, case, passwords, *, rule, base_headers, log, send, sleep):
        self.case, self.passwords, self.rule = case, passwords, rule
        self.base_headers, self.log, self.send, self.sleep = base_headers, log, send, sleep
        self.sent = 0

    def _pace(self):
        if self.sent:
            self.sleep(PACE)
        self.sent += 1

    def login(self, name: str):
        """Log in as `name`; return (auth-headers or None, status). The headers
        are {"Authorization": "Bearer ..."} for a token login or {"Cookie": "..."}
        for a cookie session; None means no usable session came back."""
        import json
        self._pace()
        if self.log:
            self.log(self.case.host, self.case.login_url, self.rule)  # the URL, never the body
        body = json.dumps({self.case.login.user_field: name,
                           self.case.login.password_field: self.passwords[name]}).encode()
        got = self.send("POST", self.case.login_url,
                        {**self.base_headers, "Content-Type": "application/json"}, body)
        if got.status != 200:
            return None, got.status
        if self.case.login.session == "cookie":
            return ({"Cookie": got.cookie} if got.cookie else None), got.status
        try:
            token = json.loads(got.body).get(self.case.login.token_field)
        except ValueError:
            token = None
        return ({"Authorization": f"Bearer {token}"} if isinstance(token, str) and token
                else None), got.status

    def get(self, auth: dict | None):
        """GET the one resource, optionally signed in (auth from login())."""
        self._pace()
        if self.log:
            self.log(self.case.host, self.case.resource_url, self.rule)
        headers = dict(self.base_headers)
        if auth:
            headers.update(auth)
        return self.send("GET", self.case.resource_url, headers, None)


def prove(item: dict, *, scope, research=None, log=None, send=None, sleep=None) -> Verdict:
    """Prove (or rule out) one access_between_accounts case.

    item carries the Case and the per-account passwords under "targets":
        {"case": Case, "passwords": {owner: pw, actor: pw}}
    scope, research, log, send: same roles as in around_cdn. sleep is the pacing
    hook (tests pass a no-op)."""
    send = send or _send
    sleep = sleep or time.sleep   # looked up per call, so tests can switch the pause off
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

    http = Session(case, passwords, rule=rule, base_headers=base_headers,
                   log=log, send=send, sleep=sleep)
    login, get = http.login, http.get

    # 1-2. Baseline: the owner can read their own resource.
    owner_auth, owner_login_status = login(case.owner)
    if owner_auth is None:
        return _inconclusive(item, f"could not log in as the owner {case.owner} "
                             f"(status {owner_login_status}), so there is nothing to prove",
                             ev + [f"login {case.owner}: {owner_login_status}"], now)
    owner_resp = get(owner_auth)
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
    actor_auth, actor_login_status = login(case.actor)
    if actor_auth is None:
        return _inconclusive(item, f"could not log in as {case.actor} "
                             f"(status {actor_login_status})",
                             ev + [f"login {case.actor}: {actor_login_status}"], now)
    actor_resp = get(actor_auth)
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
