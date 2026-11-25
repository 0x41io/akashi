"""
Akashi's command line: `plan` reads a saved Monomi scan and prints what
Akashi would check to prove each lead (it sends nothing and changes nothing),
`verify` runs those checks after a typed yes, and `recheck` re-runs a
confirmed lead after the fix to see if it's closed.
"""

import argparse
import sys

from monomi import scope as scope_mod

from akashi import __version__, plan, state, verify
from akashi.research import ResearchError
from akashi.research import load as load_research
from akashi.scan import PROVABLE, ScanError, lead_key, load_scan, provable, scan_version, unhandled
from akashi.scan import items as all_items
from akashi.ui import banner
from akashi.verdict import ORIGIN_SILENT


def _load_scope(path: str):
    """(Scope or None, problem text or None). A missing/empty scope isn't an
    error for `plan` — it just means the active checks would be blocked."""
    if not path:
        return None, None
    scope = scope_mod.load(path)
    problem = scope.error or (scope.problem() if hasattr(scope, "problem") else None)
    if problem:
        return None, problem
    return scope, None


def _load_research(path: str):
    """(Research or None, problem text or None). Optional: without it, active
    requests just carry the Akashi User-Agent and no research header."""
    if not path:
        return None, None
    try:
        return load_research(path), None
    except ResearchError as e:
        return None, str(e)


def _print_unhandled(scan):
    """Name the leads Akashi can't prove yet, so none is dropped silently."""
    left = unhandled(scan)
    if not left:
        return
    print("Not handled yet (Akashi proves " + ", ".join(PROVABLE) + "):")
    for item in left:
        rule = item.get("rule", "?")
        print(f"  [{item.get('id', '?')}] {rule}  ({item.get('where', 'lead')})")
    print()


PLAN_FOOTER = "`plan` sends nothing. `akashi verify` (after a typed yes) runs the ready checks."
RECHECK_FOOTER = "`recheck` re-runs these checks after a typed yes to see if the fix closed them."


def _print_plan(scan, version, scope, scope_problem, steps, footer=PLAN_FOOTER):
    target = scan.get("target", "?")
    print(f"Akashi plan for {target}  (from Monomi {'.'.join(map(str, version))})")
    if scope is not None:
        rules = len(getattr(scope, "rules", []) or [])
        print(f"Scope: {scope.path}  (sha256 {scope.sha256[:12]}…, {rules} rule(s))")
    elif scope_problem:
        print(f"Scope: none usable — {scope_problem}")
    else:
        print("Scope: none given (active checks would be blocked)")
    print()

    if not steps:
        # Two different situations, so two different lines: a clean scan, or
        # leads that are only of types Akashi doesn't prove yet (listed next).
        if any(True for _ in all_items(scan)):
            print("No leads Akashi can prove yet in this scan (listed below).")
        else:
            print("Monomi found no leads in this scan: nothing to verify.")
        return

    active_ready = active_blocked = passive = 0
    for s in steps:
        mark = "·"
        if s.active:
            mark = "→" if s.ready else "×"
        print(f"  [{s.id}] {s.rule}  ({s.where})")
        print(f"      {mark} {s.summary}")
        if s.active:
            if s.ready:
                for r in s.requests:
                    print(f"        would send: {r}")
                active_ready += 1
            else:
                print(f"        blocked: {s.blocked}")
                active_blocked += 1
        else:
            print(f"        passive {s.kind}: looks up {', '.join(s.looks_up)}")
            passive += 1
        print()

    bits = [f"{passive} passive (DNS/registry, never touches the target)"]
    if active_ready:
        bits.append(f"{active_ready} active ready")
    if active_blocked:
        bits.append(f"{active_blocked} active blocked by scope")
    print("Would check: " + ", ".join(bits) + ".")
    print(footer)


def cmd_plan(args) -> int:
    try:
        scan = load_scan(args.scan)
        version = scan_version(scan)
    except ScanError as e:
        print(f"akashi: {e}", file=sys.stderr)
        return 2
    scope, scope_problem = _load_scope(args.scope)
    steps = plan.build(provable(scan), scope)
    _print_plan(scan, version, scope, scope_problem, steps)
    _print_unhandled(scan)
    return 0


def _ask(prompt: str) -> str:
    """Read the person's confirmation. Split out so tests can stand in for it."""
    try:
        return input(prompt)
    except EOFError:
        return ""


def cmd_verify(args) -> int:
    try:
        scan = load_scan(args.scan)
        version = scan_version(scan)
    except ScanError as e:
        print(f"akashi: {e}", file=sys.stderr)
        return 2
    scope, scope_problem = _load_scope(args.scope)
    research, research_problem = _load_research(args.research)
    items = provable(scan)
    steps = plan.build(items, scope)
    _print_plan(scan, version, scope, scope_problem, steps)
    _print_unhandled(scan)
    if research is not None:
        print(f"Research header: {research.summary}  (sha256 {research.sha256[:12]}…)")
    elif research_problem:
        print(f"Research header: none usable — {research_problem}")

    # Sort the provable leads into what will actually run. Active checks run
    # only when scope made their plan step ready; the rest are reported blocked.
    ready = {s.id for s in steps if s.active and s.ready}
    passive = [it for it in items if verify.is_passive(it)]
    active = [it for it in items if verify.is_active(it) and it.get("id") in ready]
    blocked = sum(1 for it in items if verify.is_active(it) and it.get("id") not in ready)
    if blocked:
        print(f"\n{blocked} active check(s) are blocked by scope and will not run.")
    if not passive and not active:
        if steps:  # there were leads, but every one is blocked (the plan said so above)
            print("Nothing to verify in this scan.")
        return 0

    # The typed yes: the person has seen the whole plan above (every request),
    # and now confirms. The prompt says plainly whether anything active will be
    # sent. --yes never skips it; the plan shown is the only thing sent.
    bits = []
    if passive:
        bits.append(f"{len(passive)} passive (DNS/registry, never contact the target)")
    if active:
        bits.append(f"{len(active)} active (the requests listed above, inside scope)")
    print(f"\nRun {len(passive) + len(active)} check(s) now? " + "; ".join(bits) + ".")
    if _ask("Type yes to run, anything else to cancel: ").strip().lower() != "yes":
        print("Cancelled. Nothing was sent.")
        return 0

    print()
    target = scan.get("target", "unknown")
    tally = {"confirmed": 0, "ruled_out": 0, "inconclusive": 0}
    path = None

    def run(verdict):
        nonlocal path
        print(verdict.line())
        for e in verdict.evidence:
            print(f"      {e}")
        if verdict.fix:
            owner = f"  (owner: {verdict.owner})" if verdict.owner else ""
            print(f"      fix:{owner}")
            for n, step in enumerate(verdict.fix, 1):
                print(f"        {n}. {step}")
        path = state.record(target, verdict)
        tally[verdict.status] = tally.get(verdict.status, 0) + 1

    for item in passive:                       # passive first: nothing is sent
        run(verify.prove(item))
    for item in active:                        # then the active checks
        run(verify.prove_active(item, scope=scope, research=research))

    print(f"\n{tally['confirmed']} confirmed, {tally['ruled_out']} ruled out, "
          f"{tally['inconclusive']} inconclusive.")
    if path:
        print(f"Saved to the proof history: {path}")
    return 0


def _transition(verdict):
    """How a re-checked verdict reads against the fix: it was confirmed before,
    so ruled-out now means the fix worked."""
    if verdict.status == "ruled_out":
        return "✓", "fixed", "closed since the last check"
    if verdict.status == "confirmed":
        return "✗", "still open", "the fix hasn't closed this (or wasn't applied yet)"
    if verdict.reason == ORIGIN_SILENT:
        return "?", "unclear (likely firewalled)", (
            "the origin no longer answers direct requests, it just goes silent. That's "
            "what a firewall that drops non-CDN traffic looks like, but a timeout can't "
            "prove it, so re-checking again will read the same. To make it provable, set "
            "the firewall to reject instead of drop (ufw: `reject` instead of `deny`) and "
            "re-check: a refused connection reads as fixed")
    return "?", "unclear", "couldn't confirm the fix right now; re-check again"


def cmd_recheck(args) -> int:
    try:
        scan = load_scan(args.scan)
        version = scan_version(scan)
    except ScanError as e:
        print(f"akashi: {e}", file=sys.stderr)
        return 2
    scope, scope_problem = _load_scope(args.scope)
    research, research_problem = _load_research(args.research)
    target = scan.get("target", "unknown")

    # Only re-check leads whose latest recorded verdict was "confirmed": those
    # are the ones you proved, then set out to fix. Matched by each lead's
    # stable key (rule + targets), so a fresh scan works even if Monomi
    # renumbered the leads.
    pending = [it for it in provable(scan)
               if (state.latest(target, it.get("rule"), it.get("id"), lead_key(it)) or {})
               .get("status") == "confirmed"]

    print(f"Akashi re-check for {target}  (from Monomi {'.'.join(map(str, version))})")
    if not pending:
        print("No confirmed leads to re-check. Run `akashi verify` first, apply a fix, "
              "then re-check.")
        return 0
    print()

    steps = plan.build(pending, scope)
    _print_plan(scan, version, scope, scope_problem, steps, footer=RECHECK_FOOTER)
    if research is not None:
        print(f"Research header: {research.summary}  (sha256 {research.sha256[:12]}…)")

    ready = {s.id for s in steps if s.active and s.ready}
    passive = [it for it in pending if verify.is_passive(it)]
    active = [it for it in pending if verify.is_active(it) and it.get("id") in ready]
    blocked = sum(1 for it in pending if verify.is_active(it) and it.get("id") not in ready)
    if blocked:
        print(f"\n{blocked} active re-check(s) are blocked by scope and will not run.")
    if not passive and not active:
        print("Nothing to re-check (the confirmed leads need scope for their active checks).")
        return 0

    bits = []
    if passive:
        bits.append(f"{len(passive)} passive (DNS/registry, never contact the target)")
    if active:
        bits.append(f"{len(active)} active (the requests listed above, inside scope)")
    print(f"\nRe-run {len(passive) + len(active)} check(s) now? " + "; ".join(bits) + ".")
    if _ask("Type yes to run, anything else to cancel: ").strip().lower() != "yes":
        print("Cancelled. Nothing was sent.")
        return 0

    print()
    fixed = still_open = unclear = 0
    path = None
    for item in passive + active:
        v = verify.prove(item) if verify.is_passive(item) else \
            verify.prove_active(item, scope=scope, research=research)
        mark, label, detail = _transition(v)
        print(f"[{v.id}] {v.rule}: {mark} {label} — {detail}")
        for e in v.evidence:
            print(f"      {e}")
        path = state.record(target, v)
        fixed += v.status == "ruled_out"
        still_open += v.status == "confirmed"
        unclear += v.status == "inconclusive"

    print(f"\n{fixed} fixed, {still_open} still open, {unclear} unclear.")
    if path:
        print(f"Saved to the proof history: {path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="akashi", description="0x41 / akashi - prove Monomi's leads, then fix and re-check")
    parser.add_argument("--version", action="version", version=f"akashi {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("plan", help="show what would be checked to prove a scan's leads; send nothing")
    p.add_argument("scan", help="a saved Monomi scan (monomi --json ...), v1.15.0 or newer")
    p.add_argument("--scope", help="scope file (same format as Monomi's): active checks stay inside it")
    p.set_defaults(func=cmd_plan)

    v = sub.add_parser("verify", help="run the checks after a typed yes (active ones need scope)")
    v.add_argument("scan", help="a saved Monomi scan, v1.15.0 or newer")
    v.add_argument("--scope", help="scope file (same format as Monomi's): active checks stay inside it")
    v.add_argument("--research", help="research-header file (Name: value per line); sent on active requests")
    v.set_defaults(func=cmd_verify)

    r = sub.add_parser("recheck", help="re-run the checks for leads confirmed before, to see if the fix closed them")
    r.add_argument("scan", help="the Monomi scan you verified, v1.15.0 or newer")
    r.add_argument("--scope", help="scope file (same format as Monomi's)")
    r.add_argument("--research", help="research-header file (Name: value per line); sent on active requests")
    r.set_defaults(func=cmd_recheck)

    from akashi.app import commands as app_commands
    app_commands.register(sub)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    print(banner())
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
