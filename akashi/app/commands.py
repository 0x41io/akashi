"""
The `akashi app` commands: plan, verify and recheck for app-logic cases.

Kept beside the app-logic code (not in the big cli.py) so the main parser
only has to register one subcommand group. The flow mirrors the lead commands:
`plan` sends nothing, `verify` runs after a typed yes, `recheck` re-runs a
confirmed case after the fix.

Milestone 1 handles one case type, access_between_accounts (case.py). Its
proof (proofs/access.py) is active, so verify and recheck are fail-closed on
scope and need the creds file; plan needs neither (it sends nothing).
"""

from akashi import activelog, state
from akashi.app import case as case_mod
from akashi.app import creds as creds_mod
from akashi.proofs import access
from akashi.verdict import CONFIRMED, RULED_OUT


def _key(case) -> str:
    """A stable id for this case, so recheck finds the same check across runs."""
    return f"access_between_accounts:{case.host}:{case.resource}:{case.actor}>{case.owner}"


def _plan_lines(case) -> list:
    """The exact requests the check would send, host by host, for the person
    to read before any yes. No password is shown."""
    r = case.resource_url
    login = case.login_url
    return [
        f"access check: can {case.actor} read {case.owner}'s {case.resource} at {case.host}?",
        f"  POST {login}      log in as {case.owner}",
        f"  GET  {r}          {case.owner} reads it (baseline, must be 200)",
        f"  GET  {r}          with no login (is it simply public?)",
        f"  POST {login}      log in as {case.actor}",
        f"  GET  {r}          {case.actor} tries to read it",
        "  5 requests total, GET only to the resource and POST only to the login path, "
        "no redirects followed, 1 request/second.",
    ]


def _load_case_scope_research(args, need_scope):
    """Shared loading for verify/recheck. Returns (case, scope, research) or
    raises a ValueError subclass with a message the command prints."""
    # imported here to reuse the main CLI's loaders without a circular import
    from akashi.cli import _load_research, _load_scope
    case = case_mod.load(args.case)
    scope, problem = _load_scope(args.scope)
    if need_scope and scope is None:
        raise case_mod.CaseError(problem or "an active check needs a --scope file")
    research, rproblem = _load_research(args.research)
    if rproblem:
        raise case_mod.CaseError(f"research file: {rproblem}")
    return case, scope, research


def _make_log(scope):
    sha = getattr(scope, "sha256", None)

    def log(host, url, rule):
        if rule is None:
            activelog.refused("access_between_accounts", "host not in approved scope", host, sha)
        else:
            activelog.request("access_between_accounts", host, url, rule, sha)
    return log


def _build_item(case, passwords):
    return {"id": "A1", "targets": {"case": case, "passwords": passwords}}


def cmd_plan(args) -> int:
    try:
        case = case_mod.load(args.case)
    except case_mod.CaseError as e:
        print(f"akashi: {e}")
        return 2
    for line in _plan_lines(case):
        print(line)
    print("\nNothing was sent. To run it: akashi app verify "
          f"{args.case} --scope scope.txt --creds creds.json")
    return 0


def cmd_verify(args) -> int:
    from akashi.cli import _ask
    try:
        case, scope, research = _load_case_scope_research(args, need_scope=True)
        passwords = creds_mod.load(args.creds, case.accounts)
    except (case_mod.CaseError, creds_mod.CredsError) as e:
        print(f"akashi: {e}")
        return 2

    for line in _plan_lines(case):
        print(line)
    if _ask("\nType yes to run this check: ").strip().lower() != "yes":
        print("Not run. Nothing was sent.")
        return 1

    item = _build_item(case, passwords)
    with activelog.context(via="cli"):
        verdict = access.prove(item, scope=scope, research=research, log=_make_log(scope))
    verdict.key = _key(case)
    path = state.record(case.host, verdict)
    print("\n" + verdict.line())
    for fact in verdict.evidence:
        print(f"    {fact}")
    if verdict.status == CONFIRMED:
        print("\n  Fix:")
        for step in verdict.fix:
            print(f"    - {step}")
    print(f"\n  Recorded to {path}")
    return 0


def cmd_recheck(args) -> int:
    try:
        case, scope, research = _load_case_scope_research(args, need_scope=True)
        passwords = creds_mod.load(args.creds, case.accounts)
    except (case_mod.CaseError, creds_mod.CredsError) as e:
        print(f"akashi: {e}")
        return 2

    before = state.latest(case.host, "access_between_accounts", "A1", _key(case))
    if not before or before.get("status") != CONFIRMED:
        print(f"akashi: no confirmed access finding to re-check for {case.resource} "
              f"on {case.host}. Run `akashi app verify` first.")
        return 2

    item = _build_item(case, passwords)
    with activelog.context(via="cli"):
        verdict = access.prove(item, scope=scope, research=research, log=_make_log(scope))
    verdict.key = _key(case)
    state.record(case.host, verdict)

    if verdict.status == RULED_OUT:
        print(f"\n✓ fixed — {case.actor} can no longer read {case.owner}'s {case.resource}")
    elif verdict.status == CONFIRMED:
        print(f"\n✗ still open — {case.actor} can still read {case.owner}'s {case.resource}")
    else:
        print(f"\n? unclear — {verdict.headline}")
    for fact in verdict.evidence:
        print(f"    {fact}")
    return 0


def register(sub) -> None:
    """Add the `app` subcommand group to akashi's parser."""
    app = sub.add_parser("app", help="prove application-logic flaws (access control, milestone 1)")
    app_sub = app.add_subparsers(dest="app_command", required=True)

    p = app_sub.add_parser("plan", help="show the requests an app-logic case would send; send nothing")
    p.add_argument("case", help="a case file (TOML): one suspected flaw to prove")
    p.set_defaults(func=cmd_plan)

    v = app_sub.add_parser("verify", help="run the case after a typed yes (needs --scope and --creds)")
    v.add_argument("case", help="a case file (TOML)")
    v.add_argument("--scope", required=True, help="scope file: the check refuses any host outside it")
    v.add_argument("--creds", required=True, help="creds file (JSON, chmod 600): your test-account logins")
    v.add_argument("--research", help="research-header file; sent on every request")
    v.set_defaults(func=cmd_verify)

    r = app_sub.add_parser("recheck", help="re-run a confirmed case after the fix: fixed / still open / unclear")
    r.add_argument("case", help="the case file you verified")
    r.add_argument("--scope", required=True, help="scope file")
    r.add_argument("--creds", required=True, help="creds file (JSON, chmod 600)")
    r.add_argument("--research", help="research-header file")
    r.set_defaults(func=cmd_recheck)
