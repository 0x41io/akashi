"""
Akashi's command line. v0.1 has one command, `plan`, which reads a saved
Monomi scan and prints what Akashi would check to prove each lead. It sends
nothing and changes nothing: it's the safe first look before `verify` (later)
does the checks after a typed yes.
"""

import argparse
import sys

from monomi import scope as scope_mod

from akashi import __version__, plan
from akashi.scan import PROVABLE, ScanError, load_scan, provable, scan_version, unhandled


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


def _print_unhandled(scan):
    """Name the leads Akashi can't prove yet, so none is dropped silently."""
    left = unhandled(scan)
    if not left:
        return
    print("Not handled yet (Akashi v0.1 proves " + ", ".join(PROVABLE) + "):")
    for item in left:
        rule = item.get("rule", "?")
        print(f"  [{item.get('id', '?')}] {rule}  ({item.get('where', 'lead')})")
    print()


def _print_plan(scan, version, scope, scope_problem, steps):
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
        print("No leads Akashi can prove yet in this scan.")
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
    print("`plan` sends nothing. `akashi verify` (after a typed yes) runs the ready checks.")


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="akashi", description="0x41 / akashi - prove Monomi's leads, then fix and re-check")
    parser.add_argument("--version", action="version", version=f"akashi {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("plan", help="show what would be checked to prove a scan's leads; send nothing")
    p.add_argument("scan", help="a saved Monomi scan (monomi --json ...), v1.15.0 or newer")
    p.add_argument("--scope", help="scope file (same format as Monomi's): active checks stay inside it")
    p.set_defaults(func=cmd_plan)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
