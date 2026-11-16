"""
Akashi as a library (v0.2): what the 0x41 pipeline (`0x41 run`) calls.

Three functions, all quiet (they print nothing). They use the same scope
loading, plan and proofs as the `akashi` command, so the two can't drift:

    from akashi import api
    p = api.plan("scan.json", scope_path="scope.txt")        # sends nothing
    out = api.prove_passive("scan.json")                      # DNS/registry only
    out = api.prove_active("scan.json", "scope.txt", approved_ids=["L2"])

The safety rules, and where they live:
- prove_passive() runs without asking: its checks only query public DNS
  resolvers and domain registries, never the target. (The `akashi verify`
  command still asks first; the pipeline is what decides to run these.)
- prove_active() never decides anything on its own. It needs a usable scope
  file, and it runs only the leads the caller lists in approved_ids, which
  must be ones the plan marked ready. The caller is responsible for showing
  the plan and getting a person's yes first; the 0x41 command does that.
- Every verdict is recorded in the proof history, like `akashi verify`, so
  `akashi recheck` works on leads proven through here.

What these return is a contract: tests/test_api.py locks the keys. Add keys
freely; renaming or removing one needs API_VERSION bumped and the pipeline
updated.
"""

from dataclasses import asdict

from akashi import __version__, plan as plan_mod, state, verify
from akashi.cli import _load_research, _load_scope
from akashi.scan import load_scan, provable, scan_version, unhandled

API_VERSION = 1


def _header(scan: dict) -> dict:
    return {"akashi_version": __version__, "api_version": API_VERSION,
            "target": scan.get("target", "unknown"),
            "monomi_version": ".".join(map(str, scan_version(scan)))}


def _unhandled(scan: dict) -> list:
    return [{"id": it.get("id", "?"), "rule": it.get("rule", "?"), "where": it.get("where", "lead")}
            for it in unhandled(scan)]


def plan(scan_path: str, scope_path: str | None = None) -> dict:
    """What Akashi would check for each lead. Sends nothing.

    Returns the header (akashi_version, api_version, target, monomi_version)
    plus "scope" {"loaded", "problem"}, "steps" (one per provable lead: id,
    rule, where, kind, summary, looks_up, requests, ready, blocked, active)
    and "unhandled" (leads Akashi can't prove yet, so none is dropped
    silently). Raises akashi.scan.ScanError for a scan it can't use.
    """
    scan = load_scan(scan_path)
    scope, problem = _load_scope(scope_path)
    steps = [dict(asdict(s), active=s.active) for s in plan_mod.build(provable(scan), scope)]
    return {**_header(scan), "scope": {"loaded": scope is not None, "problem": problem},
            "steps": steps, "unhandled": _unhandled(scan)}


def _run(target: str, verdicts: list, record: bool) -> dict:
    history = None
    for v in verdicts:
        if record:
            history = state.record(target, v)
    tally = {"confirmed": 0, "ruled_out": 0, "inconclusive": 0}
    for v in verdicts:
        tally[v.status] = tally.get(v.status, 0) + 1
    return {"verdicts": [asdict(v) for v in verdicts], "tally": tally, "history": history}


def prove_passive(scan_path: str, record: bool = True) -> dict:
    """Run every passive proof in the scan (DNS / registry, never the target).

    Returns the header plus "verdicts" (each as recorded in the proof history:
    id, rule, status, headline, evidence, fix, owner, key, reason, facts...),
    "tally" and "history" (the history file written, or None).
    """
    scan = load_scan(scan_path)
    items = [it for it in provable(scan) if verify.is_passive(it)]
    verdicts = [verify.prove(it) for it in items]
    return {**_header(scan), **_run(scan.get("target", "unknown"), verdicts, record)}


def prove_active(scan_path: str, scope_path: str, approved_ids: list,
                 research_path: str | None = None, record: bool = True) -> dict:
    """Run the active proofs a person approved, inside scope.

    Only leads that are both in approved_ids AND marked ready by the plan
    (active, in scope) run; any other approved id is returned in "skipped"
    with the reason. Without a usable scope file nothing runs: ValueError.
    Returns the same keys as prove_passive() plus "skipped".
    """
    scan = load_scan(scan_path)
    scope, problem = _load_scope(scope_path)
    if scope is None:
        raise ValueError(f"active proofs need a usable scope file ({problem or 'none given'})")
    research, research_problem = _load_research(research_path)
    if research_path and research is None:
        raise ValueError(f"the research header file isn't usable: {research_problem}")

    items = provable(scan)
    steps = {s.id: s for s in plan_mod.build(items, scope)}
    approved = list(dict.fromkeys(approved_ids or []))
    run, skipped = [], []
    for lead_id in approved:
        step = steps.get(lead_id)
        if step is None:
            skipped.append({"id": lead_id, "reason": "no provable lead with this id in the scan"})
        elif not step.active:
            skipped.append({"id": lead_id, "reason": "passive: use prove_passive()"})
        elif not step.ready:
            skipped.append({"id": lead_id, "reason": step.blocked or "not ready"})
        else:
            run.append(next(it for it in items if it.get("id") == lead_id))

    verdicts = [verify.prove_active(it, scope=scope, research=research) for it in run]
    return {**_header(scan), **_run(scan.get("target", "unknown"), verdicts, record), "skipped": skipped}
