"""Building the plan: what Akashi would check, and the scope gate on the one
active check. No test here touches the network."""

from monomi import scope as scope_mod

from akashi import plan
from akashi.scan import load_scan, provable
import conftest


def steps_by_rule(scan_path, scope=None):
    scan = load_scan(scan_path)
    return {s.rule: s for s in plan.build(provable(scan), scope)}


# ---------- passive checks never touch the target ----------

def test_takeover_steps_are_passive_dns(tmp_path):
    steps = steps_by_rule(conftest.takeover_scan(tmp_path))
    tk = steps["takeover"]
    assert not tk.active and tk.kind == "dns"
    assert "old-app.takeover.test" in tk.looks_up and "old-app-zz9.azurewebsites.net" in tk.looks_up
    assert tk.requests == []  # nothing is sent to anyone

    unk = steps["takeover_unknown"]
    assert unk.kind == "dns+registry" and not unk.active
    assert "free to register" in unk.summary


def test_email_step_is_passive_dns(tmp_path):
    steps = steps_by_rule(conftest.cdn_and_email_scan(tmp_path))
    em = steps["email_spoofing"]
    assert not em.active and em.kind == "dns"
    assert em.looks_up == ["origins.test"]


# ---------- the active check is fail-closed on scope ----------

def test_around_cdn_blocked_without_a_scope(tmp_path):
    steps = steps_by_rule(conftest.cdn_and_email_scan(tmp_path), scope=None)
    cdn = steps["around_cdn"]
    assert cdn.active and not cdn.ready
    assert "no scope" in cdn.blocked and cdn.requests == []


def test_around_cdn_blocked_when_out_of_scope(tmp_path):
    scope = scope_mod.from_bytes(b"something-else.test\n")
    steps = steps_by_rule(conftest.cdn_and_email_scan(tmp_path), scope=scope)
    cdn = steps["around_cdn"]
    assert not cdn.ready and "out of scope" in cdn.blocked
    assert cdn.requests == []


def test_around_cdn_ready_inside_scope(tmp_path):
    scope = scope_mod.from_bytes(b"origins.test\n*.origins.test\n")
    steps = steps_by_rule(conftest.cdn_and_email_scan(tmp_path), scope=scope)
    cdn = steps["around_cdn"]
    assert cdn.ready and cdn.blocked == ""
    assert len(cdn.requests) == 2
    # the two requests: one through the CDN, one to the origin IP with the Host header
    assert "through the CDN" in cdn.requests[0]
    assert "203.0.113.10" in cdn.requests[1] and "Host: www.origins.test" in cdn.requests[1]


def test_around_cdn_needs_an_in_scope_direct_host(tmp_path):
    # The fronted host is in scope, but the only host on the origin is excluded,
    # so there's no in-scope name resolving to the origin: fail closed.
    scope = scope_mod.from_bytes(b"www.origins.test\n!origins.test\n")
    steps = steps_by_rule(conftest.cdn_and_email_scan(tmp_path), scope=scope)
    cdn = steps["around_cdn"]
    assert not cdn.ready and "origin" in cdn.blocked
