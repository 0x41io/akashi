"""Shared test helpers: real Monomi scans, built and saved the way Monomi
does it, so Akashi is tested against genuine output, not hand-written JSON."""

import json
import socket

import pytest
from monomi import cli as monomi_cli
from monomi import evidence
from monomi.paths import build_paths

T = "2026-11-08T12:00:00+00:00"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Fail any test that tries to reach the network. Tests must stub DNS,
    email and HTTP. A blocked call raises inside the code (which may turn it
    into an "inconclusive" verdict and still pass), so the attempt is also
    recorded and the test fails at the end, naming where it tried to go."""
    tried = []

    def blocked(self, address, *rest):
        tried.append(str(address))
        raise OSError(f"test tried to reach the network: {address}")

    def blocked_sendto(self, data, *rest):
        return blocked(self, rest[-1] if rest else "?")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket.socket, "sendto", blocked_sendto)
    yield
    assert not tried, f"test tried to reach the network: {sorted(set(tried))}"


def _save(results, tmp_path, name="scan.json"):
    """Run results through Monomi's evidence + paths, then save like --json
    (which stamps monomi_version). Returns the saved file's path."""
    results["evidence"] = evidence.build_evidence(results)
    results["paths"] = build_paths(results, results["evidence"])
    path = tmp_path / name
    monomi_cli.save_json(results, str(path))
    return str(path)


def takeover_scan(tmp_path):
    """A scan with a claimable takeover (rule takeover, a finding) and an
    unknown-service dangling CNAME (rule takeover_unknown, a lead)."""
    hosts = ["old-app.takeover.test", "legacy-cdn.takeover.test", "www.takeover.test"]
    results = {
        "target": "takeover.test",
        "sources": {"hosts file": {"source": "hosts file", "subdomains": hosts, "collected_at": T}},
        "errors": {},
        "subdomains": sorted(hosts),
        "takeover": {
            "leads": [
                {"host": "old-app.takeover.test", "cname": "old-app-zz9.azurewebsites.net",
                 "service": "Azure App Service", "claimable": True,
                 "nxdomain_confirmed_by": ["Cloudflare", "Google"], "collected_at": T},
                {"host": "legacy-cdn.takeover.test", "cname": "gone-zz9.unknownhost.test",
                 "service": None, "claimable": False,
                 "nxdomain_confirmed_by": ["Cloudflare", "Google"], "collected_at": T},
            ],
            "stale": [],
            "results": {h: {"status": "lead" if h != "www.takeover.test" else "no_cname",
                            "cname": None} for h in hosts},
            "checked": 3, "errors": {}, "collected_at": T},
    }
    return _save(results, tmp_path, "takeover.json")


def _host(ip, provider):
    return {"ips": [ip], "dns": "live", "private_ips": [], "provider": provider}


def _ip(hosts, provider, edge, ports=(80, 443)):
    return {"ports": list(ports), "vulns": [], "tags": [], "cpes": [],
            "hosts": hosts, "provider": provider, "shared_edge": edge, "risky": []}


def cdn_and_email_scan(tmp_path):
    """A scan with a go-around-the-CDN lead and an email-spoofing finding:
    www behind Cloudflare, the apex on its own origin answering web requests,
    and no DMARC."""
    names = ["origins.test", "www.origins.test"]
    results = {
        "target": "origins.test",
        "sources": {"certspotter": {"source": "certspotter", "subdomains": names, "collected_at": T}},
        "errors": {},
        "subdomains": sorted(names),
        "enrichment": {"hosts": {
            "www.origins.test": _host("198.51.100.40", "Cloudflare"),
            "origins.test": _host("203.0.113.10", "DigitalOcean"),
        }, "private_ip_hosts": [], "collected_at": T},
        "exposure": {"ips": {
            "198.51.100.40": _ip(["www.origins.test"], "Cloudflare", True),
            "203.0.113.10": _ip(["origins.test"], "DigitalOcean", False),
        }, "nothing_seen": {}, "collected_at": T},
        "email": {
            "spf": {"record": None, "issues": [{"problem": "missing", "detail": "no SPF"}]},
            "dmarc": {"record": None, "policy": None, "issues": [{"problem": "missing", "detail": "no DMARC"}]},
            "dkim": {"record": None, "selectors": [], "issues": [{"problem": "not-confirmed", "detail": "none"}]},
            "verdict": {"verdict": "spoofable", "summary": "no DMARC enforcement", "notes": []},
            "collected_at": T},
    }
    return _save(results, tmp_path, "cdn.json")


def dangling_ns_scan(tmp_path):
    """A scan with a lame (dangling NS) delegation (rule dangling_ns, new in
    Monomi v1.17): a subzone delegated to AWS Route 53 nameservers that
    refuse it, with two hosts under it. Akashi can't prove it yet."""
    hosts = ["app.lame.lame-ns.test", "www.lame.lame-ns.test"]
    results = {
        "target": "lame-ns.test",
        "sources": {"hosts file": {"source": "hosts file", "subdomains": hosts, "collected_at": T}},
        "errors": {},
        "subdomains": sorted(hosts),
        "takeover": {
            "leads": [], "stale": [],
            "results": {h: {"status": "servfail", "cname": None} for h in hosts},
            "checked": 2, "errors": {h: "DNS-over-HTTPS servers returned SERVFAIL" for h in hosts},
            "ns_delegations": [{
                "cut": "lame.lame-ns.test", "hosts": hosts, "ns_ips": ["205.251.192.0"],
                "detail": "EDE(22): No Reachable Authority at delegation lame.lame-ns.test",
                "collected_at": T, "grade": "theoretical", "provider": "AWS Route 53"}],
            "collected_at": T},
    }
    return _save(results, tmp_path, "lame.json")


def write_scope(tmp_path, text):
    path = tmp_path / "scope.txt"
    path.write_text(text, encoding="utf-8")
    return str(path)


def many_origins_scan(tmp_path, origins=3):
    """cdn_and_email_scan plus more origin candidates (mønømi v1.24 groups them
    into one around-the-CDN lead): api1..apiN, each on its own server answering
    web requests, ranked by IP as numbers after the apex's 203.0.113.10."""
    path = cdn_and_email_scan(tmp_path)
    results = json.loads(open(path).read())
    for n in range(1, origins):
        host, ip = f"api{n}.origins.test", f"203.0.113.{10 + n}"
        results["subdomains"].append(host)
        results["sources"]["certspotter"]["subdomains"].append(host)
        results["enrichment"]["hosts"][host] = _host(ip, "DigitalOcean")
        results["exposure"]["ips"][ip] = _ip([host], "DigitalOcean", False)
    return _save(results, tmp_path, "many.json")
