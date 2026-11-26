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


def set_registry(monkeypatch, status):
    from akashi.proofs import registry
    monkeypatch.setattr(registry, "registration", lambda domain: (status, f"stubbed {status}"))


def test_takeover_unknown_reserved_tld_is_inconclusive(monkeypatch):
    # a .test target has no registrable domain, so the registry can't settle it
    set_dns(monkeypatch, "gone-zz9.unknownhost.test", False, ["Cloudflare", "Google"])
    v = verify.prove(takeover_item(rule="takeover_unknown", cname="gone-zz9.unknownhost.test"))
    assert v.status == INCONCLUSIVE and "registrable" in v.headline


def test_takeover_unknown_registered_domain_is_ruled_out(monkeypatch):
    from akashi.proofs import registry
    set_dns(monkeypatch, "gone-zz9.unknownhost.com", False, ["Cloudflare", "Google"])
    set_registry(monkeypatch, registry.REGISTERED)
    v = verify.prove(takeover_item(rule="takeover_unknown", cname="gone-zz9.unknownhost.com"))
    assert v.status == RULED_OUT and "registered" in v.headline
    # Says what was checked, no more (v0.6.1, from PlayStation: gigya.com, siteforce.com):
    # registering the domain is ruled out; a claim inside the vendor's platform isn't tested
    assert "can't be claimed by registering the domain" in v.headline
    assert "an attacker can't claim it" not in v.headline


def test_takeover_unknown_no_owner_found_is_inconclusive(monkeypatch):
    from akashi.proofs import registry
    set_dns(monkeypatch, "gone-zz9.unknownhost.com", False, ["Cloudflare", "Google"])
    set_registry(monkeypatch, registry.UNKNOWN)
    v = verify.prove(takeover_item(rule="takeover_unknown", cname="gone-zz9.unknownhost.com"))
    assert v.status == INCONCLUSIVE and "confirm by hand" in v.headline


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


def test_email_verdict_records_its_facts_and_a_tailored_fix(monkeypatch):
    # v0.1.3: the proof keeps what it found, and the fix is built from it
    monkeypatch.setattr(emailauth, "check_email", lambda domain: {
        "spf": emailauth.check_spf(["v=spf1 include:_spf.google" + ".com ~all"]),
        "dmarc": emailauth.check_dmarc(["v=DMARC1;p=none"]),
        "dkim": {"record": "google", "selectors": ["google"], "issues": []},
        "verdict": {"verdict": "spoofable", "summary": "", "notes": []}})
    v = verify.prove(email_item())
    assert v.status == "confirmed"
    assert v.facts["dkim"] == ["google"] and v.facts["dmarc_rua"] is False
    assert "DKIM: google selector found" in v.evidence
    assert "DMARC reports (rua): none set" in v.evidence
    assert "SPF record: present (~all)" in v.evidence
    assert v.fix[0].startswith("Add a reporting address") and "email admin" in v.owner


def test_no_dmarc_record_is_not_called_p_none(monkeypatch):
    monkeypatch.setattr(emailauth, "check_email", lambda domain: {
        "spf": emailauth.check_spf([]), "dmarc": emailauth.check_dmarc([]),
        "dkim": {"record": None, "selectors": [], "issues": []},
        "verdict": {"verdict": "spoofable", "summary": "", "notes": []}})
    v = verify.prove(email_item())
    assert "DMARC policy now: no DMARC record" in v.evidence
