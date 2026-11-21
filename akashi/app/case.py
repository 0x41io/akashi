"""
Read and check an app-logic case file.

A case file is how a person tells Akashi about one suspected application flaw
to prove. It is deliberately narrow: one check type, one resource, named
accounts. Akashi never widens it — it proves exactly what the file says and
stops. Keeping the input this tight is what makes "stop at proof" real: there
is no id range to walk and no pattern to expand, because the file can't hold
one.

Milestone 1 knows one type, "access_between_accounts": can the `actor` account
read a resource owned by the `owner` account? The file:

    type     = "access_between_accounts"
    base     = "https://app.example.com"
    resource = "/api/notes/2"        # one exact path, never a pattern
    owner    = "bob"                 # the account that owns it
    actor    = "alice"              # the account that must not reach it
    login    = { path = "/api/login", user_field = "username",
                 password_field = "password", token_field = "token" }

`base` fixes the host; `resource` is one path under it. Both accounts must
appear in the creds file (creds.py), which is separate so secrets never live
in the case file.
"""

import tomllib
from dataclasses import dataclass

TYPES = ("access_between_accounts",)
# A resource is one path, not a pattern: no "*", no ".." , must start with "/".
# This is part of the safety story, so it's checked, not assumed.
_BAD_IN_PATH = ("*", "..", " ")


class CaseError(ValueError):
    """The case file can't be used; the message says why. Nothing ran."""


@dataclass(frozen=True)
class Login:
    path: str
    user_field: str = "username"
    password_field: str = "password"
    token_field: str = "token"


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
    only path Akashi ever requests is the resource (and the login path)."""
    from urllib.parse import urlsplit
    u = urlsplit(base)
    if u.scheme != "https":
        raise CaseError(f"'base' must start with https:// (got {base!r})")
    if not u.hostname:
        raise CaseError(f"'base' has no host (got {base!r})")
    if u.path not in ("", "/") or u.query or u.fragment:
        raise CaseError("'base' must be just scheme + host, e.g. https://app.example.com "
                        "(the path goes in 'resource')")
    return f"https://{u.netloc}", u.hostname


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
    owner, actor = _str(data, "owner"), _str(data, "actor")
    if owner == actor:
        raise CaseError("'owner' and 'actor' must be two different accounts")

    login_raw = data.get("login")
    if not isinstance(login_raw, dict):
        raise CaseError("'login' must be a table, e.g. login = { path = \"/api/login\" }")
    login = Login(
        path=_check_path(_str(login_raw, "path"), "login.path"),
        user_field=login_raw.get("user_field", "username"),
        password_field=login_raw.get("password_field", "password"),
        token_field=login_raw.get("token_field", "token"),
    )
    return Case(ctype, base, host, resource, owner, actor, login)
