"""The `akashi verify` command: the typed-yes gate, running passive checks,
and recording them. DNS and email are stubbed."""

import pytest
from monomi import dnscheck, emailauth

from akashi import cli, home, state
import conftest


@pytest.fixture(autouse=True)
def stubbed(monkeypatch, tmp_path):
    monkeypatch.setenv(home.ENV_VAR, str(tmp_path))
    # every takeover host still dangles; every domain still spoofable
    monkeypatch.setattr(dnscheck, "get_cname", lambda name: "old-app-zz9.azurewebsites.net"
                        if name == "old-app.takeover.test" else "gone-zz9.unknownhost.test")
    monkeypatch.setattr(dnscheck, "check_exists", lambda name: (False, ["Cloudflare", "Google"]))
    monkeypatch.setattr(emailauth, "check_email", lambda domain: {
        "verdict": {"verdict": "spoofable", "summary": "", "notes": []},
        "dmarc": {"policy": None}, "spf": {"record": None}})


def answer(monkeypatch, text):
    monkeypatch.setattr(cli, "_ask", lambda prompt: text)


def test_verify_runs_after_yes_and_records(monkeypatch, tmp_path, capsys):
    answer(monkeypatch, "yes")
    code = cli.main(["verify", conftest.cdn_and_email_scan(tmp_path)])
    out = capsys.readouterr().out
    assert code == 0
    assert "confirmed" in out and "still spoofable" in out
    assert "Saved to the proof history" in out
    assert len(state.history("origins.test")) == 1   # the email verdict was recorded


def test_verify_cancelled_sends_nothing(monkeypatch, tmp_path, capsys):
    answer(monkeypatch, "no")
    code = cli.main(["verify", conftest.cdn_and_email_scan(tmp_path)])
    out = capsys.readouterr().out
    assert code == 0
    assert "Cancelled. Nothing was sent." in out
    assert state.history("origins.test") == []       # nothing recorded


def test_verify_a_blank_answer_cancels(monkeypatch, tmp_path, capsys):
    answer(monkeypatch, "")
    cli.main(["verify", conftest.cdn_and_email_scan(tmp_path)])
    assert "Cancelled" in capsys.readouterr().out


def test_verify_takeover_scan_records_both(monkeypatch, tmp_path, capsys):
    answer(monkeypatch, "yes")
    cli.main(["verify", conftest.takeover_scan(tmp_path)])
    rows = state.history("takeover.test")
    assert {r["status"] for r in rows} == {"confirmed", "inconclusive"}  # takeover + takeover_unknown


def test_verify_notes_active_checks_not_run(monkeypatch, tmp_path, capsys):
    answer(monkeypatch, "yes")
    scope = conftest.write_scope(tmp_path, "origins.test\n*.origins.test\n")
    cli.main(["verify", conftest.cdn_and_email_scan(tmp_path), "--scope", scope])
    out = capsys.readouterr().out
    assert "active check(s) (around the CDN) are not run in this step" in out


def test_verify_refuses_old_scan(monkeypatch, tmp_path, capsys):
    import json
    path = conftest.cdn_and_email_scan(tmp_path)
    scan = json.loads(open(path).read())
    scan["monomi_version"] = "1.14.1"
    open(path, "w").write(json.dumps(scan))
    code = cli.main(["verify", path])
    assert code == 2 and "needs 1.15.0" in capsys.readouterr().err
