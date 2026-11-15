"""The fix text: built from rule + targets, confirmed verdicts only."""

from akashi import fixes, verify
from akashi.verdict import Verdict


def test_around_cdn_fix_names_origin_and_cdn():
    steps, owner = fixes.for_rule("around_cdn",
                                  {"ips": ["203.0.113.9"], "fronted": ["www.x.test"], "cdn": "Cloudflare"})
    assert steps and "203.0.113.9" in steps[0] and "Cloudflare" in steps[0]
    assert "server" in owner


def test_email_fix_mentions_dmarc():
    steps, owner = fixes.for_rule("email_spoofing", {"hosts": ["x.test"]})
    assert any("DMARC" in s for s in steps) and owner == "DNS admin"


def test_takeover_fix_says_remove_the_cname():
    steps, owner = fixes.for_rule("takeover", {"hosts": ["old.x.test"], "cname": "gone.y.test"})
    assert "Remove the dangling CNAME" in steps[0] and owner == "DNS admin"


def test_unknown_rule_has_no_fix():
    assert fixes.for_rule("something_new", {}) == ([], "")


def test_only_confirmed_verdicts_get_a_fix():
    item = {"rule": "around_cdn",
            "targets": {"ips": ["203.0.113.9"], "fronted": ["www.x.test"], "cdn": "Cloudflare"}}
    confirmed = verify._with_fix(item, Verdict("L1", "around_cdn", "confirmed", "x"))
    inconclusive = verify._with_fix(item, Verdict("L1", "around_cdn", "inconclusive", "x"))
    assert confirmed.fix and confirmed.owner
    assert inconclusive.fix == [] and inconclusive.owner == ""
