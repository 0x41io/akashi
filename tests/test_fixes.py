"""The fix text: built from rule + targets, confirmed verdicts only."""

from monomi import emailauth

from akashi import fixes, verify
from akashi.proofs.email import email_facts
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


# ---------- v0.1.3: the email fix is built from what the live check found ----------

D = "example" + ".test"


def real(spf_txt, dmarc_txt, selectors):
    """A check_email() result built by Monomi's own parsers from raw records."""
    spf, dmarc = emailauth.check_spf(spf_txt), emailauth.check_dmarc(dmarc_txt)
    dkim = {"record": ", ".join(selectors) or None, "selectors": selectors, "issues": []}
    return {"spf": spf, "dmarc": dmarc, "dkim": dkim,
            "verdict": emailauth.email_verdict(spf, dmarc, dkim)}


BAYC_LIKE = real(["v=spf1 include:_spf.google.com include:_spf.atlassian.net ~all"],
                 ["v=DMARC1;p=none"], ["google"])


def steps_for(result):
    return fixes.for_rule("email_spoofing", {"hosts": [D]}, email_facts(result))


def test_facts_from_a_real_bayc_like_setup():
    f = email_facts(BAYC_LIKE)
    assert f == {"spf": "present", "spf_all": "~all",
                 "spf_includes": ["_spf.google" + ".com", "_spf.atlassian" + ".net"],
                 "spf_only_all": False, "dkim": ["google"], "dmarc": "present",
                 "dmarc_policy": "none", "dmarc_rua": False}


def test_sends_mail_with_spf_and_dkim_asks_for_reports_first_and_names_the_senders():
    steps, owner = steps_for(BAYC_LIKE)
    assert steps[0].startswith("Add a reporting address to the DMARC record (rua=")
    assert "SPF and DKIM (google) are already in place" in steps[1]
    assert "_spf.atlassian" in steps[1]
    assert "p=quarantine, then p=reject" in steps[2] and "akashi recheck" in steps[3]
    assert owner == fixes.EMAIL_OWNERS
    assert not any("Make sure SPF and DKIM are in place" in s for s in steps)  # the old generic line


def test_reports_already_set_says_read_them():
    steps, _ = steps_for(real(["v=spf1 include:mailgun.org -all"],
                              ["v=DMARC1; p=none; rua=mailto:d@example.test"], ["k1"]))
    assert steps[0].startswith("Read the DMARC reports you already collect")


def test_no_spf_and_no_dkim_gives_both_paths():
    steps, owner = steps_for(real([], [], []))
    assert 'If it sends no mail, publish "v=spf1 -all"' in steps[0]
    assert "If it does send mail" in steps[1] and owner == fixes.EMAIL_OWNERS


def test_a_domain_that_sends_no_mail_goes_straight_to_reject():
    steps, owner = steps_for(real(["v=spf1 -all"], ["v=DMARC1; p=none"], []))
    assert "says it sends no mail" in steps[0] and "p=reject" in steps[0]
    assert len(steps) == 2 and owner == fixes.DNS_ADMIN


def test_missing_dmarc_and_missing_dkim_are_named():
    steps, _ = steps_for(real(["v=spf1 include:mailgun.org ~all"], [], []))
    assert steps[0].startswith("Publish a DMARC record") and "p=none with a reporting" in steps[0]
    assert any(s.startswith("Turn on DKIM signing") for s in steps)


def test_plus_all_and_multiple_spf_records_get_their_own_step():
    plus, _ = steps_for(real(["v=spf1 include:mailgun.org +all"], ["v=DMARC1; p=none"], ["k1"]))
    assert any("Replace '+all'" in s for s in plus)
    multi, _ = steps_for(real(["v=spf1 -all", "v=spf1 ~all"], ["v=DMARC1; p=none"], ["k1"]))
    assert any(s.startswith("Merge the SPF records into one") for s in multi)


def test_only_hostname_like_includes_reach_the_fix():
    # the SPF record comes from the target: odd or hostile include: values are dropped
    f = email_facts(real(["v=spf1 include:ok.example.test include:\x1b[2Jbad include:a;b ~all"],
                         ["v=DMARC1; p=none"], ["google", "bad\x1bsel"]))
    assert f["spf_includes"] == ["ok.example.test"] and f["dkim"] == ["google"]


def test_history_without_facts_keeps_the_general_fix():
    steps, owner = fixes.for_rule("email_spoofing", {"hosts": [D]})
    assert "Make sure SPF and DKIM are in place first" in steps[1] and owner == fixes.DNS_ADMIN


def test_facts_only_change_the_email_fix():
    t = {"ips": ["203.0.113.9"], "fronted": ["www.x.test"], "cdn": "Cloudflare"}
    assert fixes.for_rule("around_cdn", t, {"anything": 1}) == fixes.for_rule("around_cdn", t)
