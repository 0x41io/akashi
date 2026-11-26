"""The dangling_ns proof (v0.7.0). Every network step is replaced with a fake:
the DoH re-check, finding the parent zone's nameserver, the one direct query,
and RDAP. So each test is one outcome, and nothing leaves the machine."""

import pytest

from akashi import verify
from akashi.proofs import dangling_ns, registry
from akashi.verdict import INCONCLUSIVE, RULED_OUT

CUT = "dev.example.com"
ROUTE53_LAME = {"detail": "EDE(23): Network Error [2600:9000:5307:c200::1]:53 returned REFUSED",
                "ede": [22, 23], "ns_ips": []}
OTHER_LAME = {"detail": "EDE(22): No Reachable Authority", "ede": [22], "ns_ips": []}


def item():
    return {"id": "L2", "rule": "dangling_ns",
            "targets": {"cut": CUT, "hosts": ["a.dev.example.com"], "ns_ips": [], "grade": "investigate"}}


def fake(monkeypatch, lame=ROUTE53_LAME, names=("ns-1.awsdns-01.org",), rcode="NOERROR",
         registered=True, parent_error=None):
    asked = []
    monkeypatch.setattr(dangling_ns.dnscheck, "lame_delegation", lambda name: lame)

    def parent(cut):
        if parent_error:
            raise parent_error
        return "ns1.example.com", "192.0.2.53"

    def ask(cut, ip):
        asked.append((cut, ip))
        return rcode, sorted(names)
    monkeypatch.setattr(dangling_ns, "parent_server", parent)
    monkeypatch.setattr(dangling_ns, "ask_parent", ask)
    status = registry.REGISTERED if registered else registry.UNKNOWN
    monkeypatch.setattr(registry, "registration",
                        lambda domain: (status, f"RDAP says {domain} is {'registered' if registered else 'unknown'}"))
    return asked


def test_a_fixed_delegation_is_ruled_out(monkeypatch):
    asked = fake(monkeypatch, lame=None)
    v = verify.prove(item())
    assert v.status == RULED_OUT and "no longer a broken delegation" in v.headline
    assert asked == []  # nothing more is asked once it's fixed


def test_still_broken_on_route53_is_unclear_and_says_why(monkeypatch):
    asked = fake(monkeypatch)
    v = verify.prove(item())
    assert v.status == INCONCLUSIVE
    assert "ns-1.awsdns-01.org (AWS Route 53)" in v.headline and "large pool" in v.headline
    assert asked == [(CUT, "192.0.2.53")]  # exactly one direct query
    assert any("asked ns1.example.com (192.0.2.53) once, non-recursively" in e for e in v.evidence)


def test_a_nameserver_on_an_unregistered_domain_is_the_dangerous_case(monkeypatch):
    fake(monkeypatch, lame=OTHER_LAME, names=("ns1.gone-dns-zz9.com",), registered=False)
    v = verify.prove(item())
    # never "confirmed, go claim it": a free answer is confirm-by-hand
    assert v.status == INCONCLUSIVE
    assert "no registration was found for gone-dns-zz9.com" in v.headline
    assert "whoever registers it answers DNS for every name under dev.example.com" in v.headline
    assert "Confirm by hand" in v.headline


def test_nameservers_under_the_targets_own_domain_are_never_free(monkeypatch):
    fake(monkeypatch, lame=OTHER_LAME, names=("ns1.example.com", "ns2.example.com"), registered=False)
    v = verify.prove(item())
    assert v.status == INCONCLUSIVE and "no registration was found" not in v.headline
    assert any("only its owner can create that name" in e for e in v.evidence)


def test_unknown_provider_on_registered_domains_says_what_wasnt_checked(monkeypatch):
    fake(monkeypatch, lame=OTHER_LAME, names=("a.ns.somehost.net",))
    v = verify.prove(item())
    assert v.status == INCONCLUSIVE
    assert "can't be had by registering one" in v.headline and "wasn't checked" in v.headline


def test_when_the_parent_cant_be_asked_it_says_so_and_never_guesses(monkeypatch):
    fake(monkeypatch, parent_error=OSError("port 53 blocked"))
    v = verify.prove(item())
    assert v.status == INCONCLUSIVE
    assert "couldn't be learned from the parent zone" in v.headline and "(AWS Route 53)" in v.headline
    assert any("port 53 blocked" in e for e in v.evidence)


def test_a_parent_that_names_no_nameservers_is_unclear(monkeypatch):
    fake(monkeypatch, names=(), rcode="NXDOMAIN")
    v = verify.prove(item())
    assert v.status == INCONCLUSIVE and "names no nameservers" in v.headline


@pytest.mark.parametrize("ns,who", [
    ("ns-1036.awsdns-01.org", "AWS Route 53"), ("ns1-01.azure-dns.com", "Azure DNS"),
    ("a1-64.akam.net", "Akamai"), ("ns1.digitalocean.com", "DigitalOcean"), ("ns1.example.net", None),
])
def test_provider_of(ns, who):
    assert dangling_ns.provider_of(ns) == who


def test_the_direct_query_is_non_recursive_and_reads_the_referral(monkeypatch):
    """ask_parent() itself, with dnspython's network call faked: RD is off, and
    NS names come from the authority section (a referral) for the cut only."""
    import dns.message
    import dns.rrset
    sent = {}

    def udp(q, ip, timeout):
        sent["rd"], sent["ip"], sent["timeout"] = bool(q.flags & dns.flags.RD), ip, timeout
        r = dns.message.make_response(q)
        r.authority.append(dns.rrset.from_text(CUT + ".", 300, "IN", "NS", "ns-9.awsdns-09.net.",
                                               "ns-1.awsdns-01.org."))
        r.authority.append(dns.rrset.from_text("other.example.com.", 300, "IN", "NS", "x.example.org."))
        return r
    monkeypatch.setattr(dangling_ns.dns.query, "udp", udp)
    rcode, names = dangling_ns.ask_parent(CUT, "192.0.2.53")
    assert sent == {"rd": False, "ip": "192.0.2.53", "timeout": dangling_ns.QUERY_TIMEOUT}
    assert rcode == "NOERROR" and names == ["ns-1.awsdns-01.org", "ns-9.awsdns-09.net"]


def test_the_yes_prompt_names_the_parent_zone_question(tmp_path, monkeypatch, capsys):
    """verify's typed-yes prompt says a broken-delegation check asks the parent
    zone's nameserver one question, instead of "never contacts the target"."""
    import conftest
    from akashi import cli
    monkeypatch.setattr(cli, "_ask", lambda prompt: "no")
    cli.main(["verify", conftest.dangling_ns_scan(tmp_path)])
    out = capsys.readouterr().out
    assert "1 of them also ask the parent zone's nameserver one DNS question" in out
    assert "never contact the target" not in out
    assert "Cancelled. Nothing was sent." in out
