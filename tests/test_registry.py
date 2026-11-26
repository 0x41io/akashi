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
    def __init__(self, status, headers=None):
        self.status_code = status
        self.headers = headers or {}


def test_registration_registered(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp(200))
    status, why = registry.registration("example.com")
    assert status == registry.REGISTERED and "registered" in why


def test_registration_404_is_not_found_never_free(monkeypatch):
    # 404 is ambiguous (free vs no RDAP for the TLD), so never "registered" and
    # never "free": NOT_FOUND (v0.7.0), and the reason says to verify by hand
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp(404))
    status, why = registry.registration("example.com")
    assert status == registry.NOT_FOUND and "verify by hand" in why


def test_a_rate_limit_is_unknown_never_not_found(monkeypatch):
    """PlayStation: a 429 for awsdns-02.net (Amazon's own) read as "no registration
    found". Now it waits once, as RDAP asks, tries again, and if still limited it
    says it couldn't check."""
    calls, waits = [], []
    monkeypatch.setattr(registry.time, "sleep", waits.append)
    monkeypatch.setattr(requests, "get", lambda *a, **k: calls.append(1) or FakeResp(429, {"Retry-After": "2"}))
    status, why = registry.registration("awsdns-02.net")
    assert status == registry.UNKNOWN and "rate-limited" in why
    assert len(calls) == 2 and waits == [2.0]


def test_a_rate_limit_then_an_answer_uses_the_answer(monkeypatch):
    answers = iter([FakeResp(429, {"Retry-After": "60"}), FakeResp(200)])
    waits = []
    monkeypatch.setattr(registry.time, "sleep", waits.append)
    monkeypatch.setattr(requests, "get", lambda *a, **k: next(answers))
    assert registry.registration("awsdns-02.net")[0] == registry.REGISTERED
    assert waits == [registry.RATE_LIMIT_WAIT]  # a long Retry-After is capped


def test_each_domain_is_asked_once_per_run(monkeypatch):
    calls = []
    monkeypatch.setattr(requests, "get", lambda *a, **k: calls.append(1) or FakeResp(200))
    registry.registration("awsdns-23.com")
    registry.registration("awsdns-23.com")
    assert len(calls) == 1


def test_registration_other_status_is_unknown(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp(500))
    assert registry.registration("example.com")[0] == registry.UNKNOWN


def test_registration_network_error_is_unknown(monkeypatch):
    def boom(*a, **k):
        raise requests.ConnectionError("no network")
    monkeypatch.setattr(requests, "get", boom)
    status, why = registry.registration("example.com")
    assert status == registry.UNKNOWN and "failed" in why
