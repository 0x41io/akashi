"""The `akashi plan` command: prints a plan, sends nothing, and refuses a
scan that's too old."""

from akashi.cli import main
import conftest


def test_plan_prints_and_exits_zero(tmp_path, capsys):
    scope = conftest.write_scope(tmp_path, "origins.test\n*.origins.test\n")
    code = main(["plan", conftest.cdn_and_email_scan(tmp_path), "--scope", scope])
    out = capsys.readouterr().out
    assert code == 0
    assert "Akashi plan for origins.test" in out
    assert "around_cdn" in out and "email_spoofing" in out
    assert "would send:" in out               # the active check is ready and shown
    assert "sends nothing" in out


def test_plan_without_scope_blocks_the_active_check(tmp_path, capsys):
    code = main(["plan", conftest.cdn_and_email_scan(tmp_path)])
    out = capsys.readouterr().out
    assert code == 0
    assert "active checks would be blocked" in out
    assert "blocked:" in out
    assert "would send:" not in out           # nothing is ready without a scope


def test_plan_refuses_an_old_scan(tmp_path, capsys):
    path = conftest.cdn_and_email_scan(tmp_path)
    data = path  # the file; rewrite its version to an old one
    import json
    scan = json.loads(open(data).read())
    scan["monomi_version"] = "1.14.1"
    open(data, "w").write(json.dumps(scan))
    code = main(["plan", data])
    err = capsys.readouterr().err
    assert code == 2 and "needs 1.15.0" in err


def test_plan_passive_only_scan_says_so(tmp_path, capsys):
    code = main(["plan", conftest.takeover_scan(tmp_path)])
    out = capsys.readouterr().out
    assert code == 0
    # takeover + takeover_unknown are both passive
    assert "passive (DNS/registry, never touches the target)" in out
    assert "would send:" not in out
