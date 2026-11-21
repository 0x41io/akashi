"""
App-logic milestone 1: the case file, the creds file, and the
access_between_accounts proof. No test touches the network — a fake sender
stands in — and the planted data is all .test / made up.
"""

import json
import os

import pytest

from akashi.app import case as case_mod
from akashi.app import creds as creds_mod
from akashi.proofs import access
from akashi.verdict import CONFIRMED, INCONCLUSIVE, RULED_OUT

CASE_TOML = """\
type     = "access_between_accounts"
base     = "https://app.41xlab.test"
resource = "/api/notes/2"
owner    = "bob"
actor    = "alice"
login    = { path = "/api/login" }
"""


# --- case file ------------------------------------------------------------------

def write(tmp_path, text, name="case.toml"):
    p = tmp_path / name
    p.write_text(text)
    return str(p)


def test_a_good_case_loads(tmp_path):
    c = case_mod.load(write(tmp_path, CASE_TOML))
    assert c.type == "access_between_accounts"
    assert c.host == "app.41xlab.test"
    assert c.resource_url == "https://app.41xlab.test/api/notes/2"
    assert c.login_url == "https://app.41xlab.test/api/login"
    assert c.accounts == ["bob", "alice"]


@pytest.mark.parametrize("field, value, msg", [
    ("type", 'type = "sql_injection"', "unknown case type"),
    ("base", 'base = "http://app.41xlab.test"', "must start with https"),
    ("base", 'base = "https://app.41xlab.test/api"', "just scheme"),
    ("resource", 'resource = "/api/notes/*"', "one exact path"),
    ("resource", 'resource = "api/notes/2"', "must start with"),
    ("resource", 'resource = "/api/../etc"', "one exact path"),
])
def test_bad_fields_are_refused(tmp_path, field, value, msg):
    bad = "\n".join(value if ln.startswith(field + " ") else ln for ln in CASE_TOML.splitlines())
    with pytest.raises(case_mod.CaseError, match=msg):
        case_mod.load(write(tmp_path, bad))


def test_owner_and_actor_must_differ(tmp_path):
    bad = CASE_TOML.replace('actor    = "alice"', 'actor    = "bob"')
    with pytest.raises(case_mod.CaseError, match="two different accounts"):
        case_mod.load(write(tmp_path, bad))


def test_a_missing_file_is_a_clean_error(tmp_path):
    with pytest.raises(case_mod.CaseError, match="no case file"):
        case_mod.load(str(tmp_path / "nope.toml"))


# --- creds file -----------------------------------------------------------------

def creds_file(tmp_path, data=None, mode=0o600):
    p = tmp_path / "creds.json"
    p.write_text(json.dumps(data if data is not None else
                            {"alice": {"password": "a"}, "bob": {"password": "b"}}))
    os.chmod(p, mode)
    return str(p)


def test_creds_returns_only_the_named_accounts(tmp_path):
    path = creds_file(tmp_path, {"alice": {"password": "a"}, "bob": {"password": "b"},
                                 "carol": {"password": "c"}})
    got = creds_mod.load(path, ["bob", "alice"])
    assert got == {"bob": "b", "alice": "a"}  # carol left untouched


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_a_world_readable_creds_file_is_refused(tmp_path):
    path = creds_file(tmp_path, mode=0o644)
    with pytest.raises(creds_mod.CredsError, match="readable by others"):
        creds_mod.load(path, ["alice"])


def test_a_missing_account_is_refused(tmp_path):
    path = creds_file(tmp_path, {"alice": {"password": "a"}})
    with pytest.raises(creds_mod.CredsError, match="no password for account 'bob'"):
        creds_mod.load(path, ["bob"])


# --- the proof ------------------------------------------------------------------

class Scope:
    """Every host in scope, rule '*.test'. A real scope has the same surface."""
    def __init__(self, allowed=True):
        self.allowed = allowed

    def match(self, host):
        return type("M", (), {"allowed": self.allowed, "rule": "*.test" if self.allowed else None})()


def item():
    c = case_mod.Case("access_between_accounts", "https://app.41xlab.test", "app.41xlab.test",
                      "/api/notes/2", "bob", "alice", case_mod.Login("/api/login"))
    return {"id": "A1", "targets": {"case": c, "passwords": {"bob": "bpw", "alice": "apw"}}}


def sender(responses):
    """A fake send() that returns queued Fetched objects and records calls."""
    calls = []

    def send(method, url, headers, body):
        calls.append({"method": method, "url": url, "auth": headers.get("Authorization"),
                      "body": body})
        return responses.pop(0)
    return send, calls


F = access.Fetched
SECRET = '{"id": 2, "owner": "bob", "text": "secret"}'


def run(responses, scope=None):
    send, calls = sender(list(responses))
    v = access.prove(item(), scope=scope or Scope(), send=send, sleep=lambda s: None)
    return v, calls


def test_confirmed_when_actor_reads_the_owners_resource():
    v, calls = run([F(200, '{"token": "OWN"}'), F(200, SECRET),      # owner login + read
                    F(401, ""),                                       # anon: not public
                    F(200, '{"token": "ACT"}'), F(200, SECRET)])      # actor login + read
    assert v.status == CONFIRMED
    assert "no copy of the data is kept" in " ".join(v.evidence)
    # the secret body itself is never stored on the verdict
    assert "secret" not in json.dumps(v.evidence)


def test_ruled_out_when_the_actor_is_refused():
    v, _ = run([F(200, '{"token": "OWN"}'), F(200, SECRET), F(401, ""),
                F(200, '{"token": "ACT"}'), F(404, '{"error": "not found"}')])
    assert v.status == RULED_OUT


def test_a_public_resource_is_not_a_flaw():
    v, _ = run([F(200, '{"token": "OWN"}'), F(200, SECRET), F(200, SECRET)])  # anon also 200
    assert v.status == INCONCLUSIVE
    assert "public resource" in v.headline


def test_no_owner_baseline_means_nothing_to_prove():
    v, _ = run([F(200, '{"token": "OWN"}'), F(500, "")])  # owner can't even read it
    assert v.status == INCONCLUSIVE
    assert "baseline" in v.headline


def test_a_failed_login_is_inconclusive_not_confirmed():
    v, _ = run([F(401, "")])  # owner login fails
    assert v.status == INCONCLUSIVE


def test_out_of_scope_sends_nothing():
    v, calls = run([], scope=Scope(allowed=False))
    assert v.status == INCONCLUSIVE and "not in the approved scope" in v.headline
    assert calls == []  # fail-closed: nothing was sent


def test_only_the_resource_and_login_paths_are_ever_requested():
    _, calls = run([F(200, '{"token": "OWN"}'), F(200, SECRET), F(401, ""),
                    F(200, '{"token": "ACT"}'), F(200, SECRET)])
    urls = {c["url"] for c in calls}
    assert urls == {"https://app.41xlab.test/api/login", "https://app.41xlab.test/api/notes/2"}
    methods = {c["method"] for c in calls}
    assert methods == {"POST", "GET"}  # POST only to login, GET only to the resource


def test_the_password_is_sent_only_to_the_login_path():
    _, calls = run([F(200, '{"token": "OWN"}'), F(200, SECRET), F(401, ""),
                    F(200, '{"token": "ACT"}'), F(200, SECRET)])
    for c in calls:
        if c["body"] is not None:                       # only login carries a body
            assert c["url"].endswith("/api/login")
        if c["method"] == "GET":
            assert c["body"] is None                    # the resource GET carries no password


# --- the akashi app commands (plan / verify / recheck), no network ---------------

from akashi import cli  # noqa: E402

CASE_LIVE = CASE_TOML.replace("app.41xlab.test", "app.41xlab.test")  # host used below


@pytest.fixture
def lab(tmp_path, monkeypatch):
    monkeypatch.setenv("AKASHI_HOME", str(tmp_path))
    casep = write(tmp_path, CASE_TOML)
    scope = tmp_path / "scope.txt"
    scope.write_text("app.41xlab.test\n*.41xlab.test\n")
    creds = tmp_path / "creds.json"
    creds.write_text(json.dumps({"bob": {"password": "bpw"}, "alice": {"password": "apw"}}))
    os.chmod(creds, 0o600)
    return {"case": casep, "scope": str(scope), "creds": str(creds), "tmp": tmp_path}


def fake_proof(monkeypatch, responses):
    """Make access._send return queued Fetched objects, so the real command
    runs end to end with no network."""
    queue = list(responses)

    def send(method, url, headers, body):
        return queue.pop(0)
    monkeypatch.setattr(access, "_send", send)
    monkeypatch.setattr(access.time, "sleep", lambda s: None)   # no real 1 s pacing in tests


def test_app_plan_sends_nothing(lab, capsys, monkeypatch):
    called = {"sent": False}
    monkeypatch.setattr(access, "_send", lambda *a: called.__setitem__("sent", True))
    assert cli.main(["app", "plan", lab["case"]]) == 0
    out = capsys.readouterr().out
    assert "can alice read bob's /api/notes/2" in out and not called["sent"]


def test_app_verify_needs_a_yes(lab, capsys, monkeypatch):
    monkeypatch.setattr(cli, "_ask", lambda p: "no")
    fake_proof(monkeypatch, [])  # nothing should be sent
    code = cli.main(["app", "verify", lab["case"], "--scope", lab["scope"], "--creds", lab["creds"]])
    assert code == 1 and "Nothing was sent" in capsys.readouterr().out


def test_app_verify_confirms_then_recheck_sees_the_fix(lab, capsys, monkeypatch):
    monkeypatch.setattr(cli, "_ask", lambda p: "yes")
    # verify: vulnerable -> confirmed
    fake_proof(monkeypatch, [F(200, '{"token": "OWN"}'), F(200, SECRET), F(401, ""),
                             F(200, '{"token": "ACT"}'), F(200, SECRET)])
    assert cli.main(["app", "verify", lab["case"], "--scope", lab["scope"], "--creds", lab["creds"]]) == 0
    out = capsys.readouterr().out
    assert "confirmed" in out and "Fix:" in out

    # recheck: fixed -> actor now 404 -> ruled_out -> "fixed"
    fake_proof(monkeypatch, [F(200, '{"token": "OWN"}'), F(200, SECRET), F(401, ""),
                             F(200, '{"token": "ACT"}'), F(404, '{"error": "not found"}')])
    assert cli.main(["app", "recheck", lab["case"], "--scope", lab["scope"], "--creds", lab["creds"]]) == 0
    assert "fixed" in capsys.readouterr().out


def test_recheck_needs_a_prior_confirmation(lab, capsys, monkeypatch):
    fake_proof(monkeypatch, [])
    code = cli.main(["app", "recheck", lab["case"], "--scope", lab["scope"], "--creds", lab["creds"]])
    assert code == 2 and "no confirmed access finding" in capsys.readouterr().out


def test_verify_refuses_a_loose_creds_file(lab, capsys, monkeypatch):
    os.chmod(lab["creds"], 0o644)
    monkeypatch.setattr(cli, "_ask", lambda p: "yes")
    code = cli.main(["app", "verify", lab["case"], "--scope", lab["scope"], "--creds", lab["creds"]])
    assert code == 2 and "readable by others" in capsys.readouterr().out
