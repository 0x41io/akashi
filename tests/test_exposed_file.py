"""The exposed_file active proof (v0.6.0). The scan is a real Monomi v1.27
scan, and the network is faked at requests.get only, so Monomi's own
recheck_file() runs for real: its scope check, its made-up paths and its
file check (judge_file), never a copy of them."""

import json

import pytest
import requests
from monomi import content, scope as scope_mod

from akashi import activelog, plan, verify
from akashi.proofs import exposed_file
from akashi.scan import lead_key, provable
import conftest

HOST = "staging.files.test"
ENV = b"APP_NAME=lab\nDB_HOST=localhost\nDB_PASSWORD=not-a-real-one\n"
GIT = b"ref: refs/heads/main\n"
NOT_FOUND = (404, b"<html>Not Found</html>")


class Page:
    """Just enough of a streamed requests.Response for monomi.content."""

    def __init__(self, status, body):
        self.status_code, self.headers, self._body, self._at = status, {"Content-Type": "text/plain"}, body, 0
        self.raw = self

    def read1(self, size, decode_content=True):
        chunk = self._body[self._at:self._at + size]
        self._at += len(chunk)
        return chunk

    def close(self):
        pass


@pytest.fixture(autouse=True)
def fixed_token(monkeypatch):
    monkeypatch.setattr(content, "TOKEN", lambda: "madeup0123")


def fake_site(monkeypatch, pages, default=NOT_FOUND):
    """pages: {path: (status, body) or an exception class}. Returns the URLs sent."""
    sent = []

    def get(url, **kw):
        assert kw["allow_redirects"] is False
        sent.append(url)
        out = pages.get(requests.utils.urlparse(url).path, default)
        if isinstance(out, type):
            raise out("fake")
        return Page(*out)
    monkeypatch.setattr(content.requests, "get", get)
    return sent


def item(tmp_path, **kw):
    scan = json.loads(open(conftest.files_scan(tmp_path, **kw)).read())
    return next(it for it in provable(scan) if it["rule"] == "exposed_file")


def lab_scope(tmp_path, text="files.test\n*.files.test\n"):
    return scope_mod.load(conftest.write_scope(tmp_path, text))


def test_monomi_builds_the_path_akashi_reads(tmp_path):
    it = item(tmp_path)
    assert it["where"] == "path" and it["targets"]["hosts"] == [HOST]
    assert [f["path"] for f in it["targets"]["files"]] == ["/.env", "/.git/HEAD"]
    assert lead_key(it) == f"exposed_file:{HOST}"


def test_confirmed_when_both_files_are_still_served(tmp_path, monkeypatch):
    sent = fake_site(monkeypatch, {"/.env": (200, ENV), "/.git/HEAD": (200, GIT)})
    v = exposed_file.prove(item(tmp_path), scope=lab_scope(tmp_path))
    assert v.status == "confirmed"
    assert v.headline == f"{HOST} still serves /.env, /.git/HEAD to anyone (2 of 2 files asked)"
    assert v.facts == {"still_served": ["/.env", "/.git/HEAD"], "secrets": ["/.env"], "source": ["/.git/HEAD"]}
    # each file: three made-up paths, then the file
    assert len(sent) == 2 * content.RECHECK_REQUESTS and sent[3] == f"https://{HOST}/.env"


def test_the_evidence_never_holds_the_file(tmp_path, monkeypatch):
    fake_site(monkeypatch, {"/.env": (200, ENV), "/.git/HEAD": (200, GIT)})
    v = exposed_file.prove(item(tmp_path), scope=lab_scope(tmp_path))
    text = " ".join(v.evidence) + v.headline
    assert "not-a-real-one" not in text and "refs/heads/main" not in text
    assert any(e.startswith("/.env (secrets): still_served:") for e in v.evidence)


def test_ruled_out_when_every_file_is_gone(tmp_path, monkeypatch):
    fake_site(monkeypatch, {"/.git/HEAD": (403, b"Forbidden")})   # .env removed, .git blocked on its own
    v = exposed_file.prove(item(tmp_path), scope=lab_scope(tmp_path))
    assert v.status == "ruled_out" and "no longer serves any of the 2 files" in v.headline


def test_one_file_still_served_is_enough_to_confirm(tmp_path, monkeypatch):
    fake_site(monkeypatch, {"/.git/HEAD": (200, GIT)})
    v = exposed_file.prove(item(tmp_path), scope=lab_scope(tmp_path))
    assert v.status == "confirmed" and v.facts["still_served"] == ["/.git/HEAD"] and v.facts["secrets"] == []


def test_inconclusive_when_one_is_gone_and_one_times_out(tmp_path, monkeypatch):
    fake_site(monkeypatch, {"/.git/HEAD": requests.Timeout})
    v = exposed_file.prove(item(tmp_path), scope=lab_scope(tmp_path))
    assert v.status == "inconclusive" and "/.git/HEAD gave no clear answer" in v.headline


def test_inconclusive_when_the_host_blocks_everything(tmp_path, monkeypatch):
    fake_site(monkeypatch, {}, default=(403, b"Forbidden"))
    assert exposed_file.prove(item(tmp_path), scope=lab_scope(tmp_path)).status == "inconclusive"


def test_files_past_the_cap_keep_it_from_being_ruled_out(tmp_path, monkeypatch):
    files = [(f"/backup{n}.zip", "zip", "source", "a zip archive") for n in range(7)]
    sent = fake_site(monkeypatch, {})
    it = item(tmp_path, files=files)
    v = exposed_file.prove(it, scope=lab_scope(tmp_path))
    assert len(sent) == exposed_file.MAX_FILES * content.RECHECK_REQUESTS
    assert v.status == "inconclusive" and "2 more past the cap weren't asked" in v.headline


def test_out_of_scope_host_sends_nothing(tmp_path, monkeypatch):
    sent = fake_site(monkeypatch, {"/.env": (200, ENV)})
    logged = []
    v = exposed_file.prove(item(tmp_path), scope=lab_scope(tmp_path, "files.test\n"),
                           log=lambda h, u, rule: logged.append(rule))
    assert v.status == "inconclusive" and v.headline.startswith("refused:")
    assert sent == [] and logged == [None]   # logged as a refusal, nothing sent


def test_a_file_url_on_another_host_is_never_asked(tmp_path, monkeypatch):
    # A hand-edited scan pointing one file somewhere else: refused, the rest still run
    it = item(tmp_path)
    it["targets"]["files"][0]["url"] = "https://elsewhere.files.test/.env"
    sent = fake_site(monkeypatch, {})
    v = exposed_file.prove(it, scope=lab_scope(tmp_path))
    assert all("elsewhere" not in u for u in sent)
    assert v.status == "inconclusive" and "1 couldn't be asked" in v.headline


def test_the_plan_lists_every_request_and_is_blocked_without_scope(tmp_path):
    it = item(tmp_path)
    step = plan.step_for(it, lab_scope(tmp_path))
    assert step.active and step.ready and len(step.requests) == 4
    assert step.requests[1] == f"GET https://{HOST}/.env  (the env file, read up to 16 KB, never followed)"
    assert not plan.step_for(it, None).ready
    blocked = plan.step_for(it, lab_scope(tmp_path, "files.test\n"))
    assert not blocked.ready and blocked.blocked == f"{HOST} is out of scope"


def test_verify_logs_every_request_under_its_rule_and_adds_the_fix(tmp_path, monkeypatch):
    monkeypatch.setenv("AKASHI_HOME", str(tmp_path))
    fake_site(monkeypatch, {"/.env": (200, ENV)})
    v = verify.prove_active(item(tmp_path), scope=lab_scope(tmp_path))
    assert v.status == "confirmed" and v.key == f"exposed_file:{HOST}"
    lines = [json.loads(x) for x in open(activelog.path())]
    assert len(lines) == 2 * content.RECHECK_REQUESTS
    assert {x["tool"] for x in lines} == {"exposed_file"} and {x["event"] for x in lines} == {"request"}
    assert v.owner == "web app team and server / infrastructure admin"
    assert v.fix[0].startswith(f"Remove /.env from {HOST}'s web root")
    assert any("change every password, API key and token" in s for s in v.fix)
    assert v.fix[-1].startswith("Then run `akashi recheck`")
