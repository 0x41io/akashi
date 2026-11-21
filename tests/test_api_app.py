"""
akashi.api for app-logic cases (v0.3.1): app_plan() and prove_app(), what
0x41 calls when a person approves an app check Claude asked for.

The keys these return are a contract (0x41 reads them), locked below. No
test touches the network: access._send is replaced with a queue of answers.
"""

import json
import os

import pytest

from akashi import activelog, api
from akashi.app.case import CaseError
from akashi.app.creds import CredsError
from akashi.proofs import access

F = access.Fetched
RECORD = '{"id": 2, "owner": "bob", "text": "planted"}'
VULNERABLE = [F(200, '{"token": "O"}'), F(200, RECORD), F(401, ""), F(200, '{"token": "A"}'), F(200, RECORD)]
FIXED = [F(200, '{"token": "O"}'), F(200, RECORD), F(401, ""), F(200, '{"token": "A"}'), F(404, "")]


@pytest.fixture
def lab(tmp_path, monkeypatch):
    monkeypatch.setenv("AKASHI_HOME", str(tmp_path))
    case = tmp_path / "notes-idor.toml"
    case.write_text('type = "access_between_accounts"\nbase = "https://app.41xlab.test"\n'
                    'resource = "/api/notes/2"\nowner = "bob"\nactor = "alice"\n'
                    'login = { path = "/api/login" }\n')
    scope = tmp_path / "scope.txt"
    scope.write_text("app.41xlab.test\n")
    creds = tmp_path / "creds.json"
    creds.write_text(json.dumps({"bob": {"password": "bob-secret-pw"}, "alice": {"password": "alice-secret-pw"}}))
    os.chmod(creds, 0o600)
    return {"case": str(case), "scope": str(scope), "creds": str(creds), "tmp": tmp_path}


def answers(monkeypatch, queue):
    queue = list(queue)
    sent = []

    def send(method, url, headers, body):
        sent.append((method, url))
        return queue.pop(0)
    monkeypatch.setattr(access, "_send", send)
    monkeypatch.setattr(access.time, "sleep", lambda s: None)
    return sent


# --- app_plan ---------------------------------------------------------------------

def test_app_plan_keys_are_a_contract(lab):
    p = api.app_plan(lab["case"], lab["scope"])
    assert set(p) == {"akashi_version", "api_version", "target", "case", "requests", "scope"}
    assert set(p["case"]) == {"path", "sha256", "type", "host", "resource", "owner", "actor"}
    assert set(p["scope"]) == {"loaded", "problem", "in_scope"}
    assert all(set(r) == {"method", "url", "purpose"} for r in p["requests"])


def test_app_plan_lists_the_five_requests_and_sends_nothing(lab, monkeypatch):
    sent = answers(monkeypatch, [])
    p = api.app_plan(lab["case"], lab["scope"])
    assert [r["method"] for r in p["requests"]] == ["POST", "GET", "GET", "POST", "GET"]
    assert {r["url"] for r in p["requests"]} == {"https://app.41xlab.test/api/login",
                                                 "https://app.41xlab.test/api/notes/2"}
    assert p["scope"]["in_scope"] is True and sent == []


def test_app_plan_hash_changes_when_the_case_file_does(lab):
    before = api.app_plan(lab["case"])["case"]["sha256"]
    with open(lab["case"], "a") as f:
        f.write("# edited\n")
    assert api.app_plan(lab["case"])["case"]["sha256"] != before


def test_app_plan_says_when_the_host_is_out_of_scope(lab):
    with open(lab["scope"], "w") as f:
        f.write("other.test\n")
    assert api.app_plan(lab["case"], lab["scope"])["scope"]["in_scope"] is False


def test_app_plan_refuses_a_bad_case_file(lab, tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text('type = "access_between_accounts"\nbase = "https://x.test"\nresource = "/a/*"\n'
                   'owner = "a"\nactor = "b"\nlogin = { path = "/l" }\n')
    with pytest.raises(CaseError):
        api.app_plan(str(bad))


# --- prove_app ----------------------------------------------------------------------

def test_verify_confirms_records_and_never_returns_a_password(lab, monkeypatch):
    answers(monkeypatch, VULNERABLE)
    out = api.prove_app(lab["case"], lab["scope"], lab["creds"], kind="verify", via="mcp", approval="k7m2-x9pq")
    assert out["kind"] == "verify" and out["tally"]["confirmed"] == 1
    assert out["verdicts"][0]["key"] == "access_between_accounts:app.41xlab.test:/api/notes/2:alice>bob"
    assert out["history"] and os.path.exists(out["history"])
    text = json.dumps(out)
    assert "secret-pw" not in text and "planted" not in text   # no password, no record data
    log = open(activelog.path()).read()
    assert '"via": "mcp"' in log and "k7m2-x9pq" in log and "secret-pw" not in log


def test_recheck_after_the_fix_reports_fixed(lab, monkeypatch):
    answers(monkeypatch, VULNERABLE)
    api.prove_app(lab["case"], lab["scope"], lab["creds"])
    answers(monkeypatch, FIXED)
    out = api.prove_app(lab["case"], lab["scope"], lab["creds"], kind="recheck")
    assert out["transition"] == "fixed" and out["tally"]["ruled_out"] == 1


def test_recheck_needs_a_confirmed_finding_and_sends_nothing(lab, monkeypatch):
    sent = answers(monkeypatch, [])
    with pytest.raises(ValueError, match="no confirmed access finding"):
        api.prove_app(lab["case"], lab["scope"], lab["creds"], kind="recheck")
    assert sent == []


def test_no_scope_means_nothing_runs(lab, monkeypatch):
    sent = answers(monkeypatch, [])
    with pytest.raises(ValueError, match="usable scope file"):
        api.prove_app(lab["case"], None, lab["creds"])
    assert sent == []


def test_out_of_scope_host_sends_nothing(lab, monkeypatch):
    with open(lab["scope"], "w") as f:
        f.write("other.test\n")
    sent = answers(monkeypatch, [])
    out = api.prove_app(lab["case"], lab["scope"], lab["creds"])
    assert out["tally"]["inconclusive"] == 1 and sent == []


def test_a_loose_creds_file_is_refused_before_anything_is_sent(lab, monkeypatch):
    os.chmod(lab["creds"], 0o644)
    sent = answers(monkeypatch, [])
    with pytest.raises(CredsError, match="readable by others"):
        api.prove_app(lab["case"], lab["scope"], lab["creds"])
    assert sent == []


def test_an_unknown_kind_is_refused(lab):
    with pytest.raises(ValueError, match="kind must be one of"):
        api.prove_app(lab["case"], lab["scope"], lab["creds"], kind="sweep")
