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
    found". It waits as RDAP asks and tries again (v0.7.2: twice), and if still
    limited it says it couldn't check."""
    calls, waits = [], []
    monkeypatch.setattr(registry.time, "sleep", waits.append)
    monkeypatch.setattr(requests, "get", lambda *a, **k: calls.append(1) or FakeResp(429, {"Retry-After": "2"}))
    status, why = registry.registration("awsdns-02.net")
    assert status == registry.UNKNOWN and "rate-limited" in why
    assert len(calls) == 1 + registry.RETRIES and waits == [2.0, 2.0]


def test_a_rate_limit_then_an_answer_uses_the_answer(monkeypatch):
    answers = iter([FakeResp(429, {"Retry-After": "60"}), FakeResp(200)])
    waits = []
    monkeypatch.setattr(registry.time, "sleep", waits.append)
    monkeypatch.setattr(requests, "get", lambda *a, **k: next(answers))
    assert registry.registration("awsdns-02.net")[0] == registry.REGISTERED
    assert waits == [registry.MAX_WAIT]  # a long Retry-After is capped


def test_np_internal_de_a_second_429_still_gets_an_answer(monkeypatch):
    """PlayStation np.internal.de (v0.7.2): one retry after 5s wasn't enough for
    awsdns-16.net. With no Retry-After the wait doubles, and the third ask counts."""
    answers = iter([FakeResp(429), FakeResp(429), FakeResp(200)])
    waits = []
    monkeypatch.setattr(registry.time, "sleep", waits.append)
    monkeypatch.setattr(requests, "get", lambda *a, **k: next(answers))
    assert registry.registration("awsdns-16.net")[0] == registry.REGISTERED
    assert waits == [registry.RATE_LIMIT_WAIT, registry.RATE_LIMIT_WAIT * 2]


def test_asks_to_one_registry_are_paced_but_other_registries_arent(monkeypatch):
    clock = [100.0]
    waits = []
    monkeypatch.setattr(registry.time, "monotonic", lambda: clock[0])

    def sleep(s):
        waits.append(round(s, 3))
        clock[0] += s
    monkeypatch.setattr(registry.time, "sleep", sleep)
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp(200))
    registry.registration("awsdns-16.net")
    registry.registration("awsdns-31.org")      # another registry: no wait
    clock[0] += 0.25
    registry.registration("awsdns-08.net")      # same registry, 0.25s later: waits the rest
    registry.registration("awsdns-16.net")      # asked already: cached, no ask, no wait
    assert waits == [0.75]


def test_a_retry_after_that_isnt_seconds_falls_back_to_the_doubling_wait(monkeypatch):
    answers = iter([FakeResp(429, {"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}), FakeResp(200)])
    waits = []
    monkeypatch.setattr(registry.time, "sleep", waits.append)
    monkeypatch.setattr(requests, "get", lambda *a, **k: next(answers))
    assert registry.registration("awsdns-02.net")[0] == registry.REGISTERED
    assert waits == [registry.RATE_LIMIT_WAIT]


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
