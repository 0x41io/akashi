"""The passive proofs and the verify command. DNS and email are stubbed, so
no test touches the network."""

import pytest
from monomi import common, dnscheck, emailauth

from akashi import verify
from akashi.verdict import CONFIRMED, INCONCLUSIVE, RULED_OUT


@pytest.fixture(autouse=True)
def frozen_time(monkeypatch):
    monkeypatch.setattr(common, "now_utc", lambda: "2026-11-14T18:00:00+00:00")


def takeover_item(rule="takeover", cname="old-app-zz9.azurewebsites.test"):
    return {"id": "P1", "rule": rule, "where": "path",
            "targets": {"hosts": ["old-app.takeover.test"], "ips": [], "cname": cname,
                        "service": "Azure App Service", "claimable": rule == "takeover",
                        "nxdomain_confirmed_by": ["Cloudflare", "Google"]}}


def email_item(verdict="spoofable"):
    return {"id": "P2", "rule": "email_spoofing", "where": "path",
            "targets": {"hosts": ["origins.test"], "ips": [], "verdict": verdict}}


def set_dns(monkeypatch, cname, exists, confirmed_by):
    monkeypatch.setattr(dnscheck, "get_cname", lambda name: cname)
    monkeypatch.setattr(dnscheck, "check_exists", lambda name: (exists, confirmed_by))


def set_email(monkeypatch, verdict, policy=None, spf=None):
    monkeypatch.setattr(emailauth, "check_email", lambda domain: {
        "verdict": {"verdict": verdict, "summary": "", "notes": []},
        "dmarc": {"policy": policy}, "spf": {"record": spf}})


# ---------- takeover ----------

def test_takeover_still_dangling_is_confirmed(monkeypatch):
    set_dns(monkeypatch, "old-app-zz9.azurewebsites.test", False, ["Cloudflare", "Google"])
    v = verify.prove(takeover_item())
    assert v.status == CONFIRMED and "still points at" in v.headline
    assert any("does not exist" in e for e in v.evidence)


def test_takeover_cname_gone_is_ruled_out(monkeypatch):
    set_dns(monkeypatch, None, False, [])  # the host no longer has that CNAME
    v = verify.prove(takeover_item())
    assert v.status == RULED_OUT and "no longer points" in v.headline


def test_takeover_target_back_is_ruled_out(monkeypatch):
    set_dns(monkeypatch, "old-app-zz9.azurewebsites.test", True, [])  # target exists again
    v = verify.prove(takeover_item())
    assert v.status == RULED_OUT and "exists again" in v.headline


def test_takeover_one_resolver_only_is_inconclusive(monkeypatch):
    set_dns(monkeypatch, "old-app-zz9.azurewebsites.test", False, ["Cloudflare"])
    v = verify.prove(takeover_item())
    assert v.status == INCONCLUSIVE and "both DoH" in v.headline


def test_takeover_unknown_still_dangling_is_inconclusive(monkeypatch):
    # an unknown service: still dangling, but claimability needs the registry
    set_dns(monkeypatch, "gone-zz9.unknownhost.test", False, ["Cloudflare", "Google"])
    v = verify.prove(takeover_item(rule="takeover_unknown", cname="gone-zz9.unknownhost.test"))
    assert v.status == INCONCLUSIVE and "registry" in v.headline


# ---------- email ----------

def test_email_still_spoofable_is_confirmed(monkeypatch):
    set_email(monkeypatch, "spoofable", policy=None)
    v = verify.prove(email_item())
    assert v.status == CONFIRMED and "still spoofable" in v.headline


def test_email_now_protected_is_ruled_out(monkeypatch):
    set_email(monkeypatch, "protected", policy="reject")
    v = verify.prove(email_item())
    assert v.status == RULED_OUT and "now protected" in v.headline


def test_email_partial_is_inconclusive(monkeypatch):
    set_email(monkeypatch, "partial", policy="none")
    v = verify.prove(email_item())
    assert v.status == INCONCLUSIVE


# ---------- a failure never crashes, it's inconclusive ----------

def test_a_lookup_failure_is_inconclusive(monkeypatch):
    def boom(name):
        raise dnscheck.DNSLookupError("no DNS")
    monkeypatch.setattr(dnscheck, "get_cname", boom)
    v = verify.prove(takeover_item())
    assert v.status == INCONCLUSIVE and "could not complete" in v.headline
