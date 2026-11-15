"""The around_cdn active proof, driven by a fake sender so no request is ever
made. Covers confirm / rule-out / inconclusive and the scope gate."""

import json

import pytest
from monomi import scope as scope_mod

from akashi.proofs import around_cdn
from akashi.proofs.around_cdn import Fetched
from akashi.research import Research
from akashi.scan import provable
import conftest


def _item(tmp_path):
    scan = json.loads(open(conftest.cdn_and_email_scan(tmp_path)).read())
    return next(it for it in provable(scan) if it["rule"] == "around_cdn")


def _scope(tmp_path):
    return scope_mod.load(conftest.write_scope(tmp_path, "origins.test\n*.origins.test\n"))


def _sender(*, status=200, origin_body="<title>App</title>hello",
            cdn_body="<title>App</title>hello", error=""):
    """A stand-in for the network. The origin request is the one with a Host
    header; the CDN request is the plain one."""
    seen = []

    def send(url, headers, verify):
        seen.append((url, headers, verify))
        if "Host" in headers:                       # the origin probe
            return Fetched(url, error=error) if error else Fetched(url, status, {}, origin_body)
        return Fetched(url, 200, {}, cdn_body)       # through the CDN

    send.seen = seen
    return send


def test_confirmed_when_origin_serves_the_same_site(tmp_path):
    v = around_cdn.prove(_item(tmp_path), scope=_scope(tmp_path), send=_sender())
    assert v.status == "confirmed" and "can be bypassed" in v.headline


def test_ruled_out_when_origin_refuses_the_host_by_status(tmp_path):
    send = _sender(status=403, origin_body="<title>nginx</title>default")
    v = around_cdn.prove(_item(tmp_path), scope=_scope(tmp_path), send=send)
    assert v.status == "ruled_out" and "declines" in v.headline


def test_ruled_out_when_origin_connection_refused(tmp_path):
    send = _sender(error="Connection refused")
    v = around_cdn.prove(_item(tmp_path), scope=_scope(tmp_path), send=send)
    assert v.status == "ruled_out" and "does not answer" in v.headline


def test_inconclusive_on_timeout(tmp_path):
    send = _sender(error="Read timed out")
    v = around_cdn.prove(_item(tmp_path), scope=_scope(tmp_path), send=send)
    assert v.status == "inconclusive"


def test_inconclusive_when_origin_answers_but_differs(tmp_path):
    send = _sender(status=200, origin_body="<title>Something else</title>")
    v = around_cdn.prove(_item(tmp_path), scope=_scope(tmp_path), send=send)
    assert v.status == "inconclusive" and "didn't clearly serve" in v.headline


def test_fail_closed_without_scope_sends_nothing(tmp_path):
    send = _sender()
    v = around_cdn.prove(_item(tmp_path), scope=None, send=send)
    assert v.status == "inconclusive" and "not in the approved scope" in v.headline
    assert send.seen == []            # nothing was sent


def test_research_header_is_sent_on_active_requests(tmp_path):
    send = _sender()
    research = Research({"X-Bug-Bounty": "ok-handle"}, "deadbeef" * 8, "research.txt")
    v = around_cdn.prove(_item(tmp_path), scope=_scope(tmp_path), research=research, send=send)
    assert any("research header sent" in e for e in v.evidence)
    # every request carried the header
    assert all(h.get("X-Bug-Bounty") == "ok-handle" for _, h, _ in send.seen)
