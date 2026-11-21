# AGENTS.md: how we work on Akashi

Read this before changing anything. It applies to every AI agent working on
this repo (Claude, Grok, or anyone else). Roi (øk) owns 0x41 and makes the
final call on every change.

## What Akashi is

**Monomi finds. Akashi proves. Kaidoku explains.** Akashi takes a lead from a
saved Monomi scan, confirms or rules it out with evidence, gives the exact fix,
and re-checks it after the fix: **prove, fix, re-check.**

Akashi is not an autonomous pentester. It never picks its own targets, never
runs exploits or destructive payloads, and never changes anything on a target
(no claiming a resource, no writes). It is read-only: the only state it ever
creates is a login session, and only for the user's own test accounts in an
app-logic check (below).

## Guardrails (non-negotiable)

- **Scope first, fail closed.** An active check runs only against a host an
  approved scope file allows (same format and hashing as Monomi's), or a domain
  proven owned by a DNS TXT record. No scope → no active check.
- **A human approves every run.** Before anything is sent, Akashi prints the
  full plan (every host, every request) and needs a typed `yes`. `--yes` never
  skips it. The plan that was shown is the only thing sent: no newly discovered
  hosts, no extra URLs, no following redirects out of the plan.
- **Passive by default.** DNS and registry (RDAP) lookups ask public services
  about a name; they never contact the target, so they need no scope. Only a
  check that sends a request to the target or its origin is "active".
- **Inconclusive is the default.** A partial or unclear result is never
  stretched to "confirmed". Verdicts are confirmed / ruled out / inconclusive,
  each carrying its own evidence (the exact requests, DNS answers, timestamps).
- **Identifying traffic.** Active requests carry an honest Akashi User-Agent and
  the research header a program asks for (set by the user, locked like scope).
- **Code decides, the LLM narrates.** Verdicts come from deterministic checks.
  Any AI summary (later, or via Kaidoku) only explains, and cites the evidence.

### App-logic checks (since v0.3: `akashi app`)
These prove application-layer flaws, so they log in and send real requests.
Extra rules on top of the ones above:
- **The user's own test accounts only.** Credentials come from a separate creds
  file (JSON, refused unless 600), never the case file, never logged, never put
  in an AI prompt. A finding between two accounts is always two accounts the
  user controls — never anyone else's.
- **One case, no sweeps.** A case file names one exact resource (no pattern, no
  id range). The check sends a fixed, short set of requests and **stops at
  proof**: one record as evidence, never enumeration or paging through data.
- **Keep a hash, not the data.** A confirmed finding rests on a response
  fingerprint (sha256), so no user data is stored in the verdict or history.
- **Read-only.** GET only for the resource, POST only to the login path; no
  writes, deletes, payments or state changes; no redirects followed.

## The contract with Monomi

- Akashi reads a saved Monomi scan (`monomi --json`), v1.15.0 or newer. It picks
  leads by their `rule` and builds every request from their `targets`, **never**
  from the title or step text, which can change between Monomi releases.
- It refuses a scan whose `monomi.common.scan_version` is `None` or below
  `(1, 15, 0)`, instead of guessing.
- Monomi pins to a released tag in `pyproject.toml`. The fields Akashi reads are
  locked by `monomi/tests/test_contract.py`. If Akashi needs something Monomi
  doesn't expose, add it to Monomi first, behind that contract test, and bump
  the pin — never copy Monomi's code here.

## Code layout

- All code is in the `akashi/` package. `cli.py` is the command line; `scan.py`
  reads and validates a scan; `plan.py` turns leads into a plan (pure data, no
  network); proof modules live under `akashi/proofs/` (added per rule). App-logic checks
live under `akashi/app/` (case file, creds file, the `app` commands), with their
proof in `akashi/proofs/`.
- `plan.py` never touches the network. Only the `verify` path does, and only
  after the typed yes, and only the requests the plan listed.
- Install for development with `pip install -e .` (editable).

## Branches, tags, releases

- Work on a branch, never directly on `main`. Name the branch differently from
  the tag it will get.
- **Nothing is merged into `main` or tagged until Claude has reviewed it.**
- Release checklist: `__version__` in `akashi/__init__.py` bumped; a test for
  every behavior touched (and a plan/verify change proven by a test that fails
  without it); full suite passes; `pycodestyle` clean; `git diff --check` clean;
  README updated.

## Handing code to Roi

Roi is learning as he goes and applies every change himself.

- Explain in depth what each piece of code does and why, and exactly where it
  goes. His keyboard has no Home or End key.
- Preferred: patch files made with `git format-patch -M`, saved to Downloads and
  applied with `git am` from `/mnt/c/Users/17203/Downloads`, then `pytest`.
- No real domain names in pasted code (his chat app turns them into links). Use
  `.test` / `.invalid` names or build them from pieces.
