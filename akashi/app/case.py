"""
Read and check an app-logic case file.

A case file is how a person tells Akashi about one suspected application flaw
to prove. It is deliberately narrow: one check type, one resource, named
accounts. Akashi never widens it — it proves exactly what the file says and
stops. Keeping the input this tight is what makes "stop at proof" real: there
is no id range to walk and no pattern to expand, because the file can't hold
one.

Two check types so far. Both ask "an account reaches something it should not,"
and both name a baseline account that IS allowed plus an `actor` that must not be.

"access_between_accounts" (object-level): can `actor` read a resource OWNED by
the `owner` account?

    type     = "access_between_accounts"
    base     = "https://app.example.com"
    resource = "/api/notes/2"        # one exact path, never a pattern
    owner    = "bob"                 # the account that owns it
    actor    = "alice"              # the account that must not reach it

"privileged_function" (function-level): can `actor`, a low-privilege account,
reach an admin-only endpoint that the `privileged` account can?

    type       = "privileged_function"
    base       = "https://app.example.com"
    resource   = "/api/admin/users"  # one admin-only endpoint
    privileged = "admin"             # the account that IS allowed (baseline)
    actor      = "alice"            # the low-privilege account that must not be
    login    = { path = "/api/login", user_field = "username",
                 password_field = "password", token_field = "token" }

How the login keeps you signed in is set by `login.session` (v0.5.0):
  "token"  (default) the login returns a token in its JSON body
           (`token_field`), sent back as `Authorization: Bearer <token>`.
  "cookie" the login sets a session cookie (`Set-Cookie`), sent back as
           `Cookie: ...` on every later request, the way a browser does.
           This is how most web apps (not just JSON APIs) keep a session.

`base` fixes the host; `resource` is one path under it. Both accounts must
appear in the creds file (creds.py), which is separate so secrets never live
in the case file.
"""

import tomllib
from dataclasses import dataclass

TYPES = ("access_between_accounts", "privileged_function")
# The TOML key that names the baseline (allowed) account, per type. It loads
# into the Case's `owner` field either way, so one proof scaffold serves both.
_BASELINE_KEY = {"access_between_accounts": "owner", "privileged_function": "privileged"}
# A resource is one path, not a pattern: no "*", no ".." , must start with "/".
# This is part of the safety story, so it's checked, not assumed.
_BAD_IN_PATH = ("*", "..", " ")


class CaseError(ValueError):
    """The case file can't be used; the message says why. Nothing ran."""


SESSIONS = ("token", "cookie")


@dataclass(frozen=True)
class Login:
    path: str
    user_field: str = "username"
    password_field: str = "password"
    token_field: str = "token"
    session: str = "token"    # "token" (JSON bearer) or "cookie" (Set-Cookie)


@dataclass(frozen=True)
class Case:
    type: str
    base: str                 # e.g. https://app.example.com (scheme + host, no path)
    host: str                 # the host alone, for the scope check
    resource: str             # one path under base, e.g. /api/notes/2
    owner: str                # account that owns the resource
    actor: str                # account that should not reach it
    login: Login

    @property
    def resource_url(self) -> str:
        return self.base + self.resource

    @property
    def login_url(self) -> str:
        return self.base + self.login.path

    @property
    def accounts(self) -> list:
        """Every account name the check needs a login for."""
        return [self.owner, self.actor]


def _str(data: dict, key: str) -> str:
    v = data.get(key)
    if not isinstance(v, str) or not v.strip():
        raise CaseError(f"'{key}' is required and must be a non-empty string")
    return v.strip()


def _check_base(base: str) -> tuple[str, str]:
    """(base, host). HTTPS only, a host, and no path/query/fragment, so the
    only path Akashi ever requests is the resource (and the login path).

    Since v0.5.1 the host must be one clear host: no "@" (a login inside the
    URL) and no backslash, and the host requests will really connect to must
    be the one checked against the scope. With "https://evil.test\\@app.lab"
    urlsplit reads app.lab (in scope) while requests connects to evil.test,
    so the login, with the test account's password, would have gone there."""
    from urllib.parse import urlsplit
    from monomi.scope import named_host, request_host
    u = urlsplit(base)
    if u.scheme != "https":
        raise CaseError(f"'base' must start with https:// (got {base!r})")
    if not u.hostname:
        raise CaseError(f"'base' has no host (got {base!r})")
    if u.path not in ("", "/") or u.query or u.fragment:
        raise CaseError("'base' must be just scheme + host, e.g. https://app.example.com "
                        "(the path goes in 'resource')")
    if "@" in u.netloc or "\\" in base:
        raise CaseError(f"'base' must be just https:// and a host, with no '@' or backslash (got {base!r})")
    real = request_host(f"https://{u.netloc}/")
    if real is None or real != named_host(base):
        raise CaseError(f"'base' doesn't name one clear host to connect to (got {base!r})")
    return f"https://{u.netloc}", real


def _check_path(value: str, key: str) -> str:
    if not value.startswith("/"):
        raise CaseError(f"'{key}' must start with '/' (got {value!r})")
    if any(bad in value for bad in _BAD_IN_PATH):
        raise CaseError(f"'{key}' must be one exact path, with no '*', '..' or spaces (got {value!r})")
    return value


def load(path: str) -> Case:
    """Read a case file, or raise CaseError. Never touches the network."""
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError:
        raise CaseError(f"no case file at {path}")
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise CaseError(f"can't read the case file ({e})")

    ctype = _str(data, "type")
    if ctype not in TYPES:
        raise CaseError(f"unknown case type {ctype!r} (Akashi knows: {', '.join(TYPES)})")

    base, host = _check_base(_str(data, "base"))
    resource = _check_path(_str(data, "resource"), "resource")
    baseline_key = _BASELINE_KEY[ctype]   # "owner" or "privileged"
    owner, actor = _str(data, baseline_key), _str(data, "actor")
    if owner == actor:
        raise CaseError(f"'{baseline_key}' and 'actor' must be two different accounts")

    login_raw = data.get("login")
    if not isinstance(login_raw, dict):
        raise CaseError("'login' must be a table, e.g. login = { path = \"/api/login\" }")
    session = login_raw.get("session", "token")
    if session not in SESSIONS:
        raise CaseError(f'login.session must be one of {SESSIONS} (got {session!r})')
    login = Login(
        path=_check_path(_str(login_raw, "path"), "login.path"),
        user_field=login_raw.get("user_field", "username"),
        password_field=login_raw.get("password_field", "password"),
        token_field=login_raw.get("token_field", "token"),
        session=session,
    )
    return Case(ctype, base, host, resource, owner, actor, login)
