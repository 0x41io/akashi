"""
The contract with the 0x41 pipeline (v0.2): what akashi.api returns.

`0x41 run` calls these instead of the command line. If a change renames or
drops one of these keys, this fails before the pipeline breaks. DNS, email
and HTTP are all stubbed: no test reaches the network (see conftest.py).
"""

import json

import pytest
from monomi import emailauth

import conftest
from akashi import api, state
from akashi.proofs import around_cdn
from akashi.scan import ScanError

HEADER = {"akashi_version", "api_version", "target", "monomi_version"}
STEP_KEYS = {"id", "rule", "where", "kind", "summary", "looks_up", "requests", "ready", "blocked", "active"}
VERDICT_KEYS = {"id", "rule", "status", "headline", "evidence", "fix", "owner", "key", "reason", "facts"}
PAGE = "<title>Origins test site</title>hello"


@pytest.fixture(autouse=True)
def history_in_tmp(monkeypatch, tmp_path):
    monkeypatch.setenv("AKASHI_HOME", str(tmp_path / "akashi-home"))


@pytest.fixture
def spoofable(monkeypatch):
    monkeypatch.setattr(emailauth, "check_email", lambda domain: {
        "spf": emailauth.check_spf([]), "dmarc": emailauth.check_dmarc([]),
        "dkim": {"record": None, "selectors": [], "issues": []},
        "verdict": {"verdict": "spoofable", "summary": "", "notes": []}})


@pytest.fixture
def origin_answers(monkeypatch):
    sent = []

    def send(url, headers, verify):
        sent.append(url)
        return around_cdn.Fetched(url, 200, {}, PAGE)
    monkeypatch.setattr(around_cdn, "_send", send)
    return sent


def scope(tmp_path):
    return conftest.write_scope(tmp_path, "origins.test\n*.origins.test\n")


# ---------- plan ----------

def test_plan_contract_sends_nothing(tmp_path, capsys, origin_answers):
    scan, scope_file = conftest.cdn_and_email_scan(tmp_path), scope(tmp_path)
    capsys.readouterr()                       # drop the test helper's own "Saved results" line
    p = api.plan(scan, scope_file)
    assert set(p) == HEADER | {"scope", "steps", "unhandled"} and p["api_version"] == 1
    assert p["target"] == "origins.test" and p["scope"] == {"loaded": True, "problem": None}
    assert all(STEP_KEYS <= set(s) for s in p["steps"])
    by_rule = {s["rule"]: s for s in p["steps"]}
    assert by_rule["email_spoofing"]["active"] is False
    assert by_rule["around_cdn"]["active"] is True and by_rule["around_cdn"]["ready"] is True
    assert origin_answers == [] and capsys.readouterr().out == ""      # sends and prints nothing


def test_plan_without_scope_blocks_active(tmp_path):
    p = api.plan(conftest.cdn_and_email_scan(tmp_path))
    cdn = next(s for s in p["steps"] if s["rule"] == "around_cdn")
    assert p["scope"]["loaded"] is False and cdn["ready"] is False and cdn["blocked"]


def test_plan_refuses_a_bad_scan(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{}", encoding="utf-8")
    with pytest.raises(ScanError):
        api.plan(str(bad))


# ---------- prove_passive ----------

def test_prove_passive_runs_only_passive_and_records(tmp_path, capsys, spoofable, origin_answers):
    scan = conftest.cdn_and_email_scan(tmp_path)
    capsys.readouterr()                       # drop the test helper's own "Saved results" line
    out = api.prove_passive(scan)
    assert set(out) == HEADER | {"verdicts", "tally", "history"}
    assert [v["rule"] for v in out["verdicts"]] == ["email_spoofing"]   # never the active one
    assert origin_answers == []                                          # nothing sent to the target
    v = out["verdicts"][0]
    assert VERDICT_KEYS <= set(v) and v["status"] == "confirmed" and v["fix"]
    assert out["tally"]["confirmed"] == 1
    assert [r["rule"] for r in state.history("origins.test")] == ["email_spoofing"]
    assert capsys.readouterr().out == ""


def test_prove_passive_record_false_writes_no_history(tmp_path, spoofable):
    out = api.prove_passive(conftest.cdn_and_email_scan(tmp_path), record=False)
    assert out["history"] is None and state.history("origins.test") == []


# ---------- prove_active ----------

def test_prove_active_runs_only_approved_ready_leads(tmp_path, origin_answers):
    scan = conftest.cdn_and_email_scan(tmp_path)
    cdn_id = next(s["id"] for s in api.plan(scan, scope(tmp_path))["steps"] if s["rule"] == "around_cdn")
    email_id = next(s["id"] for s in api.plan(scan)["steps"] if s["rule"] == "email_spoofing")
    out = api.prove_active(scan, scope(tmp_path), approved_ids=[cdn_id, email_id, "Z9"])
    assert set(out) == HEADER | {"verdicts", "tally", "history", "skipped"}
    assert [v["rule"] for v in out["verdicts"]] == ["around_cdn"]
    assert out["verdicts"][0]["status"] == "confirmed" and len(origin_answers) == 2
    reasons = {s["id"]: s["reason"] for s in out["skipped"]}
    assert "passive" in reasons[email_id] and "no provable lead" in reasons["Z9"]


def test_prove_active_with_nothing_approved_sends_nothing(tmp_path, origin_answers):
    out = api.prove_active(conftest.cdn_and_email_scan(tmp_path), scope(tmp_path), approved_ids=[])
    assert out["verdicts"] == [] and origin_answers == []


def test_prove_active_needs_a_scope_file(tmp_path, origin_answers):
    scan = conftest.cdn_and_email_scan(tmp_path)
    with pytest.raises(ValueError, match="usable scope file"):
        api.prove_active(scan, None, approved_ids=["L1"])
    with pytest.raises(ValueError, match="usable scope file"):
        api.prove_active(scan, str(tmp_path / "missing.txt"), approved_ids=["L1"])
    assert origin_answers == []


def test_prove_active_out_of_scope_lead_is_skipped(tmp_path, origin_answers):
    scan = conftest.cdn_and_email_scan(tmp_path)
    cdn_id = next(s["id"] for s in api.plan(scan, scope(tmp_path))["steps"] if s["rule"] == "around_cdn")
    narrow = conftest.write_scope(tmp_path, "elsewhere.test\n")    # last: same file, now narrow
    out = api.prove_active(scan, narrow, approved_ids=[cdn_id])
    assert out["verdicts"] == [] and out["skipped"][0]["id"] == cdn_id and origin_answers == []


def test_verdicts_are_plain_json(tmp_path, spoofable):
    out = api.prove_passive(conftest.cdn_and_email_scan(tmp_path))
    assert json.loads(json.dumps(out))["verdicts"][0]["rule"] == "email_spoofing"


# ---------- the plan wording (v0.2) ----------

def _empty_scan(tmp_path):
    path = conftest.cdn_and_email_scan(tmp_path)
    data = json.loads(open(path, encoding="utf-8").read())
    data["paths"] = {**data["paths"], "paths": [], "leads": []}
    open(path, "w", encoding="utf-8").write(json.dumps(data))
    return path


def test_a_clean_scan_says_monomi_found_nothing(tmp_path, capsys):
    from akashi import cli
    assert cli.main(["verify", _empty_scan(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "Monomi found no leads in this scan: nothing to verify." in out
    assert "Nothing to verify in this scan." not in out                 # said once, not twice
    assert "yet" not in out.split("Monomi found")[1].split("\n")[0]


# ---------- active.log: who started the run (v0.2.2, for 0x41 issue #2) ----------

def log_lines(tmp_path):
    from akashi import activelog
    with open(activelog.path(), encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def cdn_lead(tmp_path):
    scan = conftest.cdn_and_email_scan(tmp_path)
    return scan, next(s["id"] for s in api.plan(scan, scope(tmp_path))["steps"] if s["rule"] == "around_cdn")


def test_a_run_through_an_mcp_approval_says_so_on_every_line(tmp_path, origin_answers):
    scan, cdn_id = cdn_lead(tmp_path)
    api.prove_active(scan, scope(tmp_path), approved_ids=[cdn_id], via="mcp", approval="k7m2-x9pq")
    lines = log_lines(tmp_path)
    assert len(lines) == 2 and all(e["event"] == "request" for e in lines)
    assert all(e["via"] == "mcp" and e["approval"] == "k7m2-x9pq" for e in lines)


def test_a_normal_run_still_says_cli_and_has_no_approval(tmp_path, origin_answers):
    scan, cdn_id = cdn_lead(tmp_path)
    api.prove_active(scan, scope(tmp_path), approved_ids=[cdn_id])
    lines = log_lines(tmp_path)
    assert lines and all(e["via"] == "cli" and "approval" not in e for e in lines)


def test_the_context_ends_with_the_run(tmp_path, origin_answers):
    from akashi import activelog
    scan, cdn_id = cdn_lead(tmp_path)
    api.prove_active(scan, scope(tmp_path), approved_ids=[cdn_id], via="mcp", approval="k7m2-x9pq")
    activelog.refused("around_cdn", "later, from the command line")
    last = log_lines(tmp_path)[-1]
    assert last["via"] == "cli" and "approval" not in last


def test_refusals_carry_it_too(tmp_path, origin_answers):
    from akashi import activelog
    with activelog.context(via="mcp", approval="k7m2-x9pq"):
        activelog.refused("around_cdn", "www.origins.test out of scope", host="www.origins.test")
    assert log_lines(tmp_path)[-1] | {"time": None} == {
        "time": None, "event": "refused", "via": "mcp", "approval": "k7m2-x9pq", "tool": "around_cdn",
        "host": "www.origins.test", "reason": "www.origins.test out of scope", "scope_sha256": None}


def test_via_is_cli_or_mcp_only(tmp_path):
    with pytest.raises(ValueError, match="via must be one of"):
        api.prove_active(conftest.cdn_and_email_scan(tmp_path), scope(tmp_path), approved_ids=[], via="web")
