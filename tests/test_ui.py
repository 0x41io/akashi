"""The banner: the big ʌkʌshi wordmark, or one line on narrow terminals."""

import os

from akashi import __version__, ui


def _width(monkeypatch, cols):
    monkeypatch.setattr(ui.shutil, "get_terminal_size", lambda fallback: os.terminal_size((cols, 24)))


def test_wide_terminal_gets_the_big_logo_with_the_version(monkeypatch):
    _width(monkeypatch, 120)
    out = ui.banner()
    assert ui.LOGO[0] in out and f"v{__version__}" in out


def test_logo_rows_are_all_the_same_width():
    # the tag is lined up under the right edge, so every row must be as wide
    assert {len(row) for row in ui.LOGO} == {ui.LOGO_WIDTH}


def test_narrow_terminal_gets_one_line(monkeypatch):
    _width(monkeypatch, 60)
    out = ui.banner()
    assert "ʌkʌshi" in out and f"v{__version__}" in out
    assert ui.LOGO[0] not in out and out.strip().count("\n") == 0
