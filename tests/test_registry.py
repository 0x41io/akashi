"""The registry (RDAP) check. The registrable-domain part is pure and tested
for real; the RDAP HTTP call is stubbed, so no test touches the network."""

import requests

from akashi.proofs import registry


def test_registrable_handles_tricky_suffixes():
    assert registry.registrable("gone.unknownhost.com") == "unknownhost.com"
    assert registry.registrable("a.b.example.co.uk") == "example.co.uk"   # multi-part TLD
    assert registry.registrable("app.github.io") == "github.io"
    # reserved / unregistrable TLDs and bare names have no registrable domain
    assert registry.registrable("gone.unknownhost.test") == ""
    assert registry.registrable("localhost") == ""


class FakeResp:
    def __init__(self, status):
        self.status_code = status


def test_registration_registered(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp(200))
    status, why = registry.registration("example.com")
    assert status == registry.REGISTERED and "registered" in why


def test_registration_404_is_unknown_not_free(monkeypatch):
    # 404 is ambiguous (free vs no RDAP for the TLD), so never "registered",
    # and the reason says to verify by hand
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp(404))
    status, why = registry.registration("example.com")
    assert status == registry.UNKNOWN and "verify by hand" in why


def test_registration_other_status_is_unknown(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp(500))
    assert registry.registration("example.com")[0] == registry.UNKNOWN


def test_registration_network_error_is_unknown(monkeypatch):
    def boom(*a, **k):
        raise requests.ConnectionError("no network")
    monkeypatch.setattr(requests, "get", boom)
    status, why = registry.registration("example.com")
    assert status == registry.UNKNOWN and "failed" in why
