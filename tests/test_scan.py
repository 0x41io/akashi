"""Reading and validating a saved Monomi scan."""

import json

import pytest

from akashi.scan import MIN_MONOMI, PROVABLE, ScanError, lead_key, load_scan, provable, scan_version, unhandled
import conftest


def test_load_scan_reads_a_real_scan(tmp_path):
    scan = load_scan(conftest.takeover_scan(tmp_path))
    assert scan["target"] == "takeover.test"
    assert scan["monomi_version"]  # Monomi stamped it


def test_load_scan_errors_are_clear(tmp_path):
    with pytest.raises(ScanError, match="no scan file"):
        load_scan(str(tmp_path / "missing.json"))
    bad = tmp_path / "bad.json"
    bad.write_text("not json {", encoding="utf-8")
    with pytest.raises(ScanError, match="isn't valid JSON"):
        load_scan(str(bad))
    arr = tmp_path / "arr.json"
    arr.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ScanError, match="isn't a Monomi scan"):
        load_scan(str(arr))


def test_scan_version_accepts_current_and_refuses_old(tmp_path):
    scan = load_scan(conftest.takeover_scan(tmp_path))
    assert scan_version(scan) >= MIN_MONOMI

    # A scan from before v1.15.0 has no monomi_version
    old = {k: v for k, v in scan.items() if k != "monomi_version"}
    with pytest.raises(ScanError, match="no monomi_version"):
        scan_version(old)

    scan["monomi_version"] = "1.14.1"
    with pytest.raises(ScanError, match="1.14.1.*needs 1.15.0|needs 1.15.0"):
        scan_version(scan)


def test_provable_picks_the_four_rules_and_tags_where(tmp_path):
    scan = load_scan(conftest.takeover_scan(tmp_path))
    items = provable(scan)
    by_rule = {i["rule"]: i for i in items}
    assert set(by_rule) == {"takeover", "takeover_unknown"}
    # A claimable takeover passed Monomi's gate, so it's a path; the unknown is a lead
    assert by_rule["takeover"]["where"] == "path"
    assert by_rule["takeover_unknown"]["where"] == "lead"
    assert all(i["rule"] in PROVABLE for i in items)


def test_provable_reads_both_cdn_and_email(tmp_path):
    scan = load_scan(conftest.cdn_and_email_scan(tmp_path))
    rules = {i["rule"] for i in provable(scan)}
    assert "around_cdn" in rules and "email_spoofing" in rules


def test_provable_skips_rules_akashi_cant_prove_yet(tmp_path):
    # A side_door lead is in the scan but not among PROVABLE, so it's left out
    scan = load_scan(conftest.cdn_and_email_scan(tmp_path))
    scan["paths"]["leads"].append({"id": "L9", "rule": "side_door", "targets": {"hosts": ["x"], "ips": ["y"]}})
    assert "side_door" not in {i["rule"] for i in provable(scan)}


def test_unhandled_lists_rules_akashi_cant_prove(tmp_path):
    from akashi.scan import unhandled
    scan = load_scan(conftest.cdn_and_email_scan(tmp_path))
    scan["paths"]["leads"].append({"id": "L9", "rule": "side_door",
                                   "targets": {"hosts": ["x"], "ips": ["y"]}})
    left = unhandled(scan)
    assert [i["rule"] for i in left] == ["side_door"]
    assert left[0]["id"] == "L9" and left[0]["where"] == "lead"
    # nothing provable shows up as unhandled, and nothing unhandled is provable
    assert not ({i["rule"] for i in left} & set(PROVABLE))


def test_dangling_ns_from_monomi_is_named_not_proved(tmp_path):
    # Monomi v1.17's new rule: Akashi has no proof for it yet, so it must be
    # listed as unhandled (never dropped, never handed to a proof)
    scan = load_scan(conftest.dangling_ns_scan(tmp_path))
    assert scan_version(scan) >= (1, 17, 0)
    assert "dangling_ns" not in PROVABLE
    assert provable(scan) == []
    left = unhandled(scan)
    assert [i["rule"] for i in left] == ["dangling_ns"]
    t = left[0]["targets"]
    assert t["cut"] == "lame.lame-ns.test" and t["grade"] == "theoretical"
    assert sorted(t["hosts"]) == ["app.lame.lame-ns.test", "www.lame.lame-ns.test"]


# ---------- lead_key: a stable name from rule + targets (v0.1.1) ----------

def test_lead_key_takeover_uses_host_and_cname():
    item = {"id": "P1", "rule": "takeover",
            "targets": {"hosts": ["Old-App.example.test."], "ips": [], "cname": "x.azurewebsites.net"}}
    assert lead_key(item) == "takeover:old-app.example.test>x.azurewebsites.net"


def test_lead_key_ignores_the_id():
    t = {"hosts": ["example.test"], "ips": [], "verdict": "spoofable"}
    assert lead_key({"id": "P1", "rule": "email_spoofing", "targets": t}) == \
        lead_key({"id": "P7", "rule": "email_spoofing", "targets": t})


def test_lead_key_around_cdn_is_per_front_and_origin():
    def item(ip):
        return {"rule": "around_cdn", "targets": {"hosts": ["dev.example.test"], "ips": [ip],
                                                  "fronted": ["www.example.test"], "cdn": "Cloudflare"}}
    assert lead_key(item("192.0.2.1")) == "around_cdn:www.example.test>192.0.2.1"
    assert lead_key(item("192.0.2.1")) != lead_key(item("192.0.2.2"))


def test_lead_key_host_order_does_not_matter():
    a = {"rule": "side_door", "targets": {"hosts": ["b.test", "a.test"], "ips": ["192.0.2.1"]}}
    b = {"rule": "side_door", "targets": {"hosts": ["a.test", "b.test"], "ips": ["192.0.2.1"]}}
    assert lead_key(a) == lead_key(b)
