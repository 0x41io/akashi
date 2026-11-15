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
