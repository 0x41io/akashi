"""One around-the-CDN lead with several origins (v0.4.0, mønømi v1.24): what
the plan lists, what is sent, how the verdicts combine, and the lead key.
Driven by a fake sender: no request is ever made."""

import json

from monomi import scope as scope_mod

from akashi import fixes, plan
from akashi.proofs import around_cdn
from akashi.proofs.around_cdn import Fetched
from akashi.scan import lead_key, provable
from akashi.verdict import CONFIRMED, INCONCLUSIVE, RULED_OUT
import conftest

SITE = "<title>Origins test site</title>hello"


def _lead(tmp_path, origins=3):
    scan = json.loads(open(conftest.many_origins_scan(tmp_path, origins)).read())
    return next(it for it in provable(scan) if it["rule"] == "around_cdn")


def _scope(tmp_path):
    return scope_mod.load(conftest.write_scope(tmp_path, "origins.test\n*.origins.test\n"))


def _sender(answers):
    """answers: {origin ip: Fetched-ish (status, body) or an error string}."""
    seen = []

    def send(url, headers, verify):
        seen.append(url)
        if "Host" not in headers:
            return Fetched(url, 200, {}, SITE)              # through the CDN
        ip = url.split("//")[1].strip("/")
        a = answers.get(ip, (404, "nope"))
        return Fetched(url, error=a) if isinstance(a, str) else Fetched(url, a[0], {}, a[1])
    send.seen = seen
    return send


def test_mønømi_groups_the_origins_into_one_lead(tmp_path):
    lead = _lead(tmp_path)
    assert [o["ip"] for o in lead["targets"]["origins"]] == ["203.0.113.10", "203.0.113.11", "203.0.113.12"]


def test_the_plan_lists_one_request_per_origin_in_order(tmp_path):
    step = plan.step_for(_lead(tmp_path), _scope(tmp_path))
    assert step.ready and step.requests == [
        "GET https://www.origins.test/  (through the CDN)",
        "GET the origin 203.0.113.10 with Host: www.origins.test  (reached via origins.test)",
        "GET the origin 203.0.113.11 with Host: www.origins.test  (reached via api1.origins.test)",
        "GET the origin 203.0.113.12 with Host: www.origins.test  (reached via api2.origins.test)"]
    assert "any of 3 origins (203.0.113.10, 203.0.113.11, 203.0.113.12)" in step.summary


def test_what_is_sent_is_exactly_what_the_plan_listed(tmp_path):
    lead, s = _lead(tmp_path), _scope(tmp_path)
    send = _sender({})
    around_cdn.prove(lead, scope=s, send=send)
    planned = [r.split("  (")[0] for r in plan.step_for(lead, s).requests]
    sent = ["GET " + u if i == 0 else f"GET the origin {u.split('//')[1].strip('/')} with Host: www.origins.test"
            for i, u in enumerate(send.seen)]
    assert sent == planned


def test_one_origin_serving_the_site_confirms_and_names_it(tmp_path):
    v = around_cdn.prove(_lead(tmp_path), scope=_scope(tmp_path),
                         send=_sender({"203.0.113.11": (200, SITE)}))
    assert v.status == CONFIRMED and "203.0.113.11" in v.headline and "1 of 3 origins" in v.headline
    assert v.facts["confirmed_origins"] == ["203.0.113.11"]
    steps, _ = fixes.for_rule("around_cdn", _lead(tmp_path)["targets"], v.facts)
    assert steps[0].startswith("Stop 203.0.113.11 from answering")


def test_ruled_out_only_when_every_origin_refuses(tmp_path):
    lead, s = _lead(tmp_path), _scope(tmp_path)
    v = around_cdn.prove(lead, scope=s, send=_sender({}))           # every origin: 404
    assert v.status == RULED_OUT and "none of the 3 origins" in v.headline
    v = around_cdn.prove(lead, scope=s, send=_sender({"203.0.113.12": "Read timed out"}))
    assert v.status == INCONCLUSIVE and "1 of 3 origins didn't clearly answer" in v.headline


def test_origins_past_the_cap_are_named_and_never_ruled_out(tmp_path):
    lead, s = _lead(tmp_path, origins=plan.MAX_ORIGINS + 2), _scope(tmp_path)
    step = plan.step_for(lead, s)
    assert len(step.requests) == 1 + plan.MAX_ORIGINS
    assert "2 more aren't" in step.summary
    v = around_cdn.prove(lead, scope=s, send=_sender({}))           # every tried origin: 404
    assert v.status == INCONCLUSIVE and "weren't tried" in v.headline
    assert any(e.startswith("not tried") for e in v.evidence)


def test_an_origin_without_an_in_scope_name_is_never_sent_to(tmp_path):
    lead = _lead(tmp_path)
    s = scope_mod.load(conftest.write_scope(tmp_path, "www.origins.test\norigins.test\n"))
    tried, extra = plan.origins_to_try(lead, s)
    assert [o["ip"] for o in tried] == ["203.0.113.10"] and extra == []


def test_the_lead_key_survives_origin_ips_changing(tmp_path):
    lead = _lead(tmp_path)
    before = lead_key(lead)
    moved = json.loads(json.dumps(lead))
    moved["targets"]["origins"][1]["ip"] = "203.0.113.99"
    moved["targets"]["ips"][1] = "203.0.113.99"
    assert lead_key(moved) == before == "around_cdn:www.origins.test>cloudflare"


def test_an_older_one_origin_lead_still_works(tmp_path):
    # Before mønømi v1.24: no "origins", one IP per lead
    lead = _lead(tmp_path)
    old = json.loads(json.dumps(lead))
    old["targets"] = {"hosts": ["api1.origins.test"], "ips": ["203.0.113.11"],
                      "fronted": ["www.origins.test"], "cdn": "Cloudflare"}
    assert lead_key(old) == "around_cdn:www.origins.test>203.0.113.11"
    step = plan.step_for(old, _scope(tmp_path))
    assert step.requests[1] == ("GET the origin 203.0.113.11 with Host: www.origins.test  "
                                "(reached via api1.origins.test)")
    assert "directly at the origin 203.0.113.11, around the CDN" in step.summary
