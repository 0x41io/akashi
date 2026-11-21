"""
Read the test-account credentials for an app-logic check.

These are logins for accounts the person controls, used to prove whether one
of their own accounts can reach another's data. They live in their own file,
never in the case file, and the file is refused unless only its owner can read
it (a real file, owned by you, permissions 600) — the same rule Monomi's key
file uses, and the one ssh uses for private keys.

    {
      "alice": {"password": "..."},
      "bob":   {"password": "..."}
    }

A password is never printed, never logged, and never put into an AI prompt.
The reader hands back only the accounts the case names, so an unrelated login
in the file is left untouched.
"""

import json
import os
import stat


class CredsError(ValueError):
    """The creds file can't be used; the message says why."""


def _check_perms(path: str) -> None:
    """Refuse a creds file others can read, the way ssh refuses a loose key.
    Skipped on native Windows, which has no POSIX permission bits."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise CredsError(f"no creds file at {path}")
    if stat.S_ISLNK(st.st_mode):
        raise CredsError(f"{path} is a symlink; use a real file")
    if os.name != "posix":
        return
    if st.st_uid != os.getuid():
        raise CredsError(f"{path} must be owned by you")
    if st.st_mode & 0o077:
        raise CredsError(f"{path} is readable by others; run: chmod 600 {path}")


def load(path: str, accounts: list) -> dict:
    """{name: password} for exactly the accounts asked for, or CredsError.
    Only the named accounts are returned; anything else in the file is ignored."""
    _check_perms(path)
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        raise CredsError(f"can't read the creds file ({e})")
    if not isinstance(data, dict):
        raise CredsError("the creds file must be a JSON object of account -> {password}")

    out = {}
    for name in accounts:
        entry = data.get(name)
        if not isinstance(entry, dict) or not isinstance(entry.get("password"), str):
            raise CredsError(f"no password for account {name!r} in the creds file")
        out[name] = entry["password"]
    return out
