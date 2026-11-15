"""`akashi recheck`: re-run a previously-confirmed lead and report whether the
fix closed it. Driven through verify first (to record a confirmed verdict),
then recheck with DNS stubbed to the before/after state. No network."""

import pytest
from monomi import dnscheck

from akashi import cli, home, state
import conftest


def answer(monkeypatch, text):
    monkeypatch.setattr(cli, "_ask", lambda prompt: text)


@pytest.fixture(autouse=True)
def home_tmp(monkeypatch, tmp_path):
    monkeypatch.setenv(home.ENV_VAR, str(tmp_path))
    return tmp_path


def _still_dangling(monkeypatch):
    monkeypatch.setattr(dnscheck, "get_cname", lambda name: "old-app-zz9.azurewebsites.net"
                        if name == "old-app.takeover.test" else "gone-zz9.unknownhost.test")
    monkeypatch.setattr(dnscheck, "check_exists", lambda name: (False, ["Cloudflare", "Google"]))


def _verify_to_confirm(monkeypatch, tmp_path):
    """Run verify so the takeover lead is recorded confirmed, and return the scan."""
    scan = conftest.takeover_scan(tmp_path)
    _still_dangling(monkeypatch)
    answer(monkeypatch, "yes")
    cli.main(["verify", scan])
    return scan


def test_recheck_with_nothing_confirmed_says_so(tmp_path, capsys):
    code = cli.main(["recheck", conftest.takeover_scan(tmp_path)])
    out = capsys.readouterr().out
    assert code == 0 and "No confirmed leads to re-check" in out


def test_recheck_reports_fixed_when_the_cname_is_gone(monkeypatch, tmp_path, capsys):
    scan = _verify_to_confirm(monkeypatch, tmp_path)
    capsys.readouterr()
    # the dangling CNAME has been removed since -> ruled out -> fixed
    monkeypatch.setattr(dnscheck, "get_cname", lambda name: None)
    answer(monkeypatch, "yes")
    cli.main(["recheck", scan])
    out = capsys.readouterr().out
    assert "fixed" in out and "1 fixed" in out
    # the new verdict is appended, so the history now shows the transition
    statuses = [r["status"] for r in state.history("takeover.test") if r["id"] == "P1"]
    assert statuses[-2:] == ["confirmed", "ruled_out"]


def test_recheck_reports_still_open_when_unchanged(monkeypatch, tmp_path, capsys):
    scan = _verify_to_confirm(monkeypatch, tmp_path)
    capsys.readouterr()
    answer(monkeypatch, "yes")              # still dangling from the verify stub
    cli.main(["recheck", scan])
    out = capsys.readouterr().out
    assert "still open" in out and "1 still open" in out


def test_recheck_cancelled_sends_nothing(monkeypatch, tmp_path, capsys):
    scan = _verify_to_confirm(monkeypatch, tmp_path)
    capsys.readouterr()
    answer(monkeypatch, "no")
    cli.main(["recheck", scan])
    assert "Cancelled. Nothing was sent." in capsys.readouterr().out


def test_recheck_finds_the_lead_in_a_fresh_scan_that_renumbered_it(monkeypatch, tmp_path, capsys):
    """v0.1.1: a new scan after the fix can give the same lead a new id.
    Recheck matches by rule + targets, so it still finds it."""
    import json
    scan = _verify_to_confirm(monkeypatch, tmp_path)
    capsys.readouterr()
    data = json.load(open(scan))
    for group in ("paths", "leads"):
        for item in data["paths"].get(group) or []:
            item["id"] = item["id"] + "9"        # P1 -> P19, L1 -> L19, ...
    fresh = tmp_path / "fresh.json"
    fresh.write_text(json.dumps(data))
    monkeypatch.setattr(dnscheck, "get_cname", lambda name: None)   # fixed since
    answer(monkeypatch, "yes")
    cli.main(["recheck", str(fresh)])
    out = capsys.readouterr().out
    assert "No confirmed leads" not in out
    assert "fixed" in out


def test_verify_records_the_stable_key(monkeypatch, tmp_path):
    _verify_to_confirm(monkeypatch, tmp_path)
    keys = {r["key"] for r in state.history("takeover.test")}
    assert "takeover:old-app.takeover.test>old-app-zz9.azurewebsites.net" in keys
