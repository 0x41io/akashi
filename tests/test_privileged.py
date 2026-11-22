"""The privileged_function app check (v0.5.0): a low-privilege account reaching
an admin-only endpoint. No test touches the network — a fake sender stands in."""

import json
import os

import pytest

from akashi.app import case as case_mod
from akashi.proofs import access, privileged
from akashi.verdict import CONFIRMED, INCONCLUSIVE, RULED_OUT

CASE_TOML = """\
type       = "privileged_function"
base       = "https://app.41xlab.test"
resource   = "/api/admin/users"
privileged = "admin"
actor      = "alice"
login      = { path = "/api/login" }
"""


def write(tmp_path, text, name="case.toml"):
    p = tmp_path / name
    p.write_text(text)
    return str(p)


# --- case file ------------------------------------------------------------------

def test_a_privileged_case_loads_with_privileged_as_the_baseline(tmp_path):
    c = case_mod.load(write(tmp_path, CASE_TOML))
    assert c.type == "privileged_function"
    assert c.owner == "admin" and c.actor == "alice"      # owner holds the privileged account
    assert c.resource_url == "https://app.41xlab.test/api/admin/users"
    assert c.accounts == ["admin", "alice"]


def test_privileged_is_required_for_that_type(tmp_path):
    bad = CASE_TOML.replace('privileged = "admin"', 'owner = "admin"')
    with pytest.raises(case_mod.CaseError, match="'privileged' is required"):
        case_mod.load(write(tmp_path, bad))


def test_privileged_and_actor_must_differ(tmp_path):
    bad = CASE_TOML.replace('actor      = "alice"', 'actor      = "admin"')
    with pytest.raises(case_mod.CaseError, match="'privileged' and 'actor' must be two different"):
        case_mod.load(write(tmp_path, bad))


# --- the proof ------------------------------------------------------------------

class Scope:
    def __init__(self, allowed=True):
        self.allowed = allowed

    def match(self, host):
        return type("M", (), {"allowed": self.allowed, "rule": "*.test" if self.allowed else None})()


def item():
    c = case_mod.Case("privileged_function", "https://app.41xlab.test", "app.41xlab.test",
                      "/api/admin/users", "admin", "alice", case_mod.Login("/api/login"))
    return {"id": "A1", "targets": {"case": c, "passwords": {"admin": "apw", "alice": "lpw"}}}


def sender(responses):
    calls = []

    def send(method, url, headers, body):
        calls.append({"method": method, "url": url, "body": body})
        return responses.pop(0)
    return send, calls


F = access.Fetched
ADMIN = '{"users": [{"secretname": "zzq"}]}'   # what the admin endpoint returns


def run(responses, scope=None):
    send, calls = sender(list(responses))
    v = privileged.prove(item(), scope=scope or Scope(), send=send, sleep=lambda s: None)
    return v, calls


def test_confirmed_when_the_actor_reaches_the_admin_endpoint():
    # admin login+200, anon refused, actor login+same 200 as admin
    v, _ = run([F(200, '{"token": "ADM"}'), F(200, ADMIN),
                F(403, ""),                                  # anon refused: it IS protected
                F(200, '{"token": "ACT"}'), F(200, ADMIN)])  # actor sees the admin response
    assert v.status == CONFIRMED and "missing function-level access control" in v.headline
    assert "no copy of the data is kept" in " ".join(v.evidence)
    assert "secretname" not in json.dumps(v.evidence)   # the response body itself is never stored


def test_ruled_out_when_the_actor_is_refused():
    v, _ = run([F(200, '{"token": "ADM"}'), F(200, ADMIN), F(403, ""),
                F(200, '{"token": "ACT"}'), F(403, "")])
    assert v.status == RULED_OUT and "checks the role" in v.headline


def test_a_public_endpoint_is_not_a_privilege_flaw():
    # anon also gets the admin response: it's just public
    v, _ = run([F(200, '{"token": "ADM"}'), F(200, ADMIN), F(200, ADMIN)])
    assert v.status == INCONCLUSIVE and "public endpoint" in v.headline


def test_actor_matching_admin_but_anon_also_200_is_inconclusive():
    # anon got 200 with a different body: whether it's really restricted is murky
    v, _ = run([F(200, '{"token": "ADM"}'), F(200, ADMIN),
                F(200, '{"different": "page"}'),               # anon 200, not the admin body
                F(200, '{"token": "ACT"}'), F(200, ADMIN)])
    assert v.status == INCONCLUSIVE and "unclear" in v.headline


def test_no_privileged_baseline_means_nothing_to_prove():
    v, _ = run([F(200, '{"token": "ADM"}'), F(500, "")])   # admin can't use it either
    assert v.status == INCONCLUSIVE and "baseline" in v.headline


def test_actor_different_200_is_inconclusive_not_confirmed():
    # actor gets 200 but NOT the admin's response: conservative -> inconclusive
    v, _ = run([F(200, '{"token": "ADM"}'), F(200, ADMIN), F(403, ""),
                F(200, '{"token": "ACT"}'), F(200, '{"users": []}')])  # filtered/empty, differs
    assert v.status == INCONCLUSIVE


def test_out_of_scope_sends_nothing():
    v, calls = run([], scope=Scope(allowed=False))
    assert v.status == INCONCLUSIVE and "not in the approved scope" in v.headline and calls == []


def test_only_the_endpoint_and_login_paths_are_requested():
    _, calls = run([F(200, '{"token": "ADM"}'), F(200, ADMIN), F(403, ""),
                    F(200, '{"token": "ACT"}'), F(200, ADMIN)])
    assert {c["url"] for c in calls} == {"https://app.41xlab.test/api/login",
                                         "https://app.41xlab.test/api/admin/users"}
    assert {c["method"] for c in calls} == {"POST", "GET"}


def test_a_confirmed_verdict_has_a_fix_and_the_right_rule():
    v, _ = run([F(200, '{"token": "ADM"}'), F(200, ADMIN), F(403, ""),
                F(200, '{"token": "ACT"}'), F(200, ADMIN)])
    assert v.rule == "privileged_function" and v.fix and v.owner == "app / backend developer"
    assert any("role" in step for step in v.fix)


# --- cookie session works for this type too (shared Session) ---------------------

def test_privileged_check_supports_a_cookie_session():
    c = case_mod.Case("privileged_function", "https://app.41xlab.test", "app.41xlab.test",
                      "/api/admin/users", "admin", "alice", case_mod.Login("/api/login", session="cookie"))
    it = {"id": "A1", "targets": {"case": c, "passwords": {"admin": "a", "alice": "l"}}}
    send, calls = sender([F(200, "{}", cookie="sid=ADM"), F(200, ADMIN), F(403, ""),
                          F(200, "{}", cookie="sid=ACT"), F(200, ADMIN)])
    v = privileged.prove(it, scope=Scope(), send=send, sleep=lambda s: None)
    assert v.status == CONFIRMED


# --- end to end through the CLI, no network -------------------------------------

from akashi import cli  # noqa: E402


@pytest.fixture
def lab(tmp_path, monkeypatch):
    monkeypatch.setenv("AKASHI_HOME", str(tmp_path))
    casep = write(tmp_path, CASE_TOML)
    scope = tmp_path / "scope.txt"
    scope.write_text("app.41xlab.test\n*.41xlab.test\n")
    creds = tmp_path / "creds.json"
    creds.write_text(json.dumps({"admin": {"password": "a"}, "alice": {"password": "l"}}))
    os.chmod(creds, 0o600)
    return {"case": casep, "scope": str(scope), "creds": str(creds)}


def test_plan_shows_the_privilege_question_and_sends_nothing(lab, capsys, monkeypatch):
    called = {"sent": False}
    monkeypatch.setattr(access, "_send", lambda *a: called.__setitem__("sent", True))
    monkeypatch.setattr(privileged, "_send", lambda *a: called.__setitem__("sent", True)) \
        if hasattr(privileged, "_send") else None
    assert cli.main(["app", "plan", lab["case"]]) == 0
    out = capsys.readouterr().out
    assert "can alice reach the admin-only /api/admin/users" in out and not called["sent"]
    assert "admin-only should refuse it" in out


def test_verify_confirms_end_to_end(lab, capsys, monkeypatch):
    queue = [F(200, '{"token": "ADM"}'), F(200, ADMIN), F(403, ""),
             F(200, '{"token": "ACT"}'), F(200, ADMIN)]
    monkeypatch.setattr(access, "_send", lambda *a: queue.pop(0))
    monkeypatch.setattr(access.time, "sleep", lambda s: None)
    monkeypatch.setattr(cli, "_ask", lambda prompt: "yes")
    code = cli.main(["app", "verify", lab["case"], "--scope", lab["scope"], "--creds", lab["creds"]])
    out = capsys.readouterr().out
    assert code == 0 and "missing function-level access control" in out
