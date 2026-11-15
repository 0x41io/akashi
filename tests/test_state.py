"""The proof history is append-only and per target."""

import pytest

from akashi import home, state
from akashi.verdict import CONFIRMED, RULED_OUT, Verdict


@pytest.fixture(autouse=True)
def akashi_home(monkeypatch, tmp_path):
    # history goes to a throwaway folder, never the real one or the repo
    monkeypatch.setenv(home.ENV_VAR, str(tmp_path))


def test_record_then_read_back():
    v = Verdict("P1", "takeover", CONFIRMED, "still dangling", ["ev1"], "2026-11-14T18:00:00+00:00")
    state.record("example.test", v)
    rows = state.history("example.test")
    assert len(rows) == 1
    assert rows[0]["id"] == "P1" and rows[0]["status"] == CONFIRMED
    assert rows[0]["target"] == "example.test" and rows[0]["evidence"] == ["ev1"]


def test_history_is_append_only():
    v1 = Verdict("P1", "takeover", CONFIRMED, "dangling", [], "2026-11-14T18:00:00+00:00")
    v2 = Verdict("P1", "takeover", RULED_OUT, "fixed", [], "2026-11-15T18:00:00+00:00")
    state.record("example.test", v1)
    state.record("example.test", v2)
    rows = state.history("example.test")
    assert [r["status"] for r in rows] == [CONFIRMED, RULED_OUT]  # both kept, in order


def test_separate_file_per_target():
    state.record("a.test", Verdict("P1", "takeover", CONFIRMED, "x", [], "t"))
    state.record("b.test", Verdict("P1", "takeover", CONFIRMED, "y", [], "t"))
    assert len(state.history("a.test")) == 1 and len(state.history("b.test")) == 1


def test_messy_target_name_is_made_safe():
    state.record("weird/../name .test", Verdict("P1", "takeover", CONFIRMED, "x", [], "t"))
    assert len(state.history("weird/../name .test")) == 1  # same safe name both ways


def test_history_empty_for_unknown_target():
    assert state.history("never-seen.test") == []
