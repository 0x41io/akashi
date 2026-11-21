<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/0x41io/akashi/main/assets/akashi-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/0x41io/akashi/main/assets/akashi-light.png">
    <img src="https://raw.githubusercontent.com/0x41io/akashi/main/assets/akashi-banner.png" alt="ʌkʌshi by 0x41" width="357">
  </picture>
</p>

**Monomi finds. Akashi proves. Kaidoku explains.**

Akashi is the third tool in the [0x41](https://0x41.sh) security suite. It takes
a lead from a [Monomi](https://github.com/0x41io/monomi) scan, confirms or rules
it out with evidence, gives the exact fix, and re-checks it after the fix:
**prove, fix, re-check.**

It is not an autonomous pentester. It never picks its own targets, never runs
exploits, and never changes anything on a target. Every active check stays
inside an approved scope and waits for a typed `yes`.

## Only reports what it can prove

AI security tools have a reputation problem: reports full of flaws that turn
out not to exist. Akashi is built the other way around.

- **Unproven until proven.** Every verdict starts as **inconclusive**. Only
  evidence from a check moves it to **confirmed** or **ruled out**, and a
  partial result never counts as confirmed.
- **Every verdict carries its evidence.** The DNS answers, registry record, or
  HTTP responses behind it are saved to an append-only history, so anyone can
  check how the call was made.
- **No AI makes the call.** Akashi's checks are plain code that give the same
  answer every run. [Kaidoku](https://github.com/0x41io/kaidoku) can explain a
  verdict in plain English, but it never changes one.
- **"Unclear" is an honest answer.** When the evidence can't settle it (a
  timeout, a firewall that drops traffic, a stock default page), Akashi says so
  instead of guessing.
- **A fix isn't done until it's re-checked.** `recheck` runs the same check
  again and records fixed, still open, or unclear.

> Status: **v0.3.0.** The full **prove, fix, re-check** loop is built: `plan`
> (show what would be checked, send nothing), `verify` (run the checks after a
> typed yes), and `recheck` (re-run a confirmed lead after you fix it, to prove
> it's closed). The passive checks (the takeover re-check over DNS, the registry
> (RDAP) lookup for an unknown-service takeover, and the email re-check) never
> touch the target; the one active check (going around the CDN) runs only
> inside scope. A **confirmed** lead prints the exact fix to close it. Since
> v0.2, a library API (`akashi.api`) lets the [0x41](https://github.com/0x41io/0x41)
> pipeline run Akashi too (`0x41 vet`, and from Claude over MCP), with every
> active request logged with who started it and which approval allowed it.
>
> Since v0.3, Akashi also proves one **application-logic** flaw: broken access
> control between two accounts you own (`akashi app plan|verify|recheck`). It
> reads a small case file naming one resource and two of your own test
> accounts, checks whether the second can read the first's resource, and stops
> at proof — one record, never a sweep. Fail-closed on scope, a typed yes, and
> it keeps only a hash of the response, never the data.

## What it proves

Akashi reads the typed fields Monomi writes since v1.15.0, so it knows what each
lead is without reading its text.

| Monomi lead | How Akashi proves it | Touches the target? |
|---|---|---|
| `takeover` (claimable service) | Re-check now that the dangling CNAME still points at the deleted target and that the target still doesn't exist, on both DoH resolvers. Never claims the name. | No — DNS only |
| `takeover_unknown` | The same DNS re-check, plus a registry (RDAP) lookup: if the target's domain is registered, an attacker can't claim it (ruled out); otherwise inconclusive, since claiming a domain is a human decision | No — DNS + registry |
| `around_cdn` | One request to the fronted host through the CDN, one to the origin IP with the same `Host` header; compare the responses. A stock default page or a short generic title never counts as a match | Yes — one request each |
| `email_spoofing` | Fresh SPF / DMARC / DKIM lookup. The evidence names the SPF `all` rule, the DKIM selectors found and whether DMARC reports (`rua=`) are collected, and the fix is built from that setup (v0.1.3): reports first, what's already in place, the senders SPF lists, then enforce | No — DNS only |

Every verdict is **confirmed**, **ruled out**, or **inconclusive** (the default),
and carries its evidence.

**Fixes fit the target (v0.1.3).** An email fix is built from what the live
check found, by code: a domain with SPF and DKIM but no DMARC reports is told to
collect reports first and that SPF and DKIM are already in place; a domain that
says it sends no mail (`v=spf1 -all`, no DKIM) can go straight to `p=reject`; a
domain with neither is given both paths. Only hostname-like `include:` names
from the target's SPF record ever reach the fix text. The facts behind a fix are
saved on the verdict (`facts`) in the proof history; history from before v0.1.3
keeps the general steps.

## Install

Requires Python 3.14+. Akashi imports Monomi as a library, pinned to the release
whose contract test locks the fields Akashi reads.

```bash
git clone https://github.com/0x41io/akashi.git
cd akashi
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -e .
```

## Use

```bash
# Show what would be checked to prove a scan's leads. Sends nothing.
akashi plan scan.json --scope scope.txt

# Run the checks after a typed yes. The passive ones always run; the active
# one (around the CDN) runs only for hosts the scope allows. Records each
# verdict, with its evidence, to an append-only history per target.
akashi verify scan.json --scope scope.txt

# Some bug bounty programs want an identifying header on active traffic. Put it
# in a file (one "Name: value" per line); it's hashed, shown in the plan, and
# sent on the active requests only.
akashi verify scan.json --scope scope.txt --research research.txt

# After fixing a confirmed lead, re-run its check to prove it's closed. Only
# leads that were confirmed before are re-checked; each reports fixed, still
# open, or unclear, and the result is appended to the proof history. Leads are
# matched by what they're about (rule + targets), not their id, so a fresh scan
# taken after the fix works too.
akashi recheck scan.json --scope scope.txt
```

`scan.json` is a Monomi scan saved with `monomi --json`, from Monomi v1.15.0 or
newer. `--scope` is a scope file in Monomi's format; the active check (going
around the CDN) only runs against hosts it allows, and is shown as blocked
without it. The passive checks (DNS and registry) never contact the target, so
they need no scope.

### As a library (v0.2)

The 0x41 pipeline (`0x41 vet`) calls Akashi directly. All three functions are
quiet (they print nothing) and use the same scope, plan and proofs as the
`akashi` command:

```python
from akashi import api

p = api.plan("scan.json", scope_path="scope.txt")      # what it would check; sends nothing
out = api.prove_passive("scan.json")                    # DNS / registry only, never the target
out = api.prove_active("scan.json", "scope.txt", approved_ids=["L2"])
```

`prove_passive()` runs without asking, because its checks never contact the
target; the `akashi verify` command still asks first. `prove_active()` never
decides anything itself: it needs a usable scope file and runs only the leads
the caller lists in `approved_ids` that the plan marked ready, so the caller
must show the plan and get a person's yes first. Every verdict goes into the
proof history, so `akashi recheck` works on them. What these return is locked
by `tests/test_api.py`.

`prove_active(..., via="mcp", approval="<id>")` (v0.2.2) marks every
`scans/active.log` line of that run with where it came from: 0x41 uses it for
an active proof an agent asked for and a person approved in a terminal
(`0x41 approve`), so the log ties each request to its approval. The default is
`via="cli"`, with no approval.

## Known limits

- **Origins that require SNI.** The origin request goes to a bare IP, so it can't
  send the site's name during the TLS handshake. Origins that insist on it fail
  the handshake, and the verdict is **inconclusive** ("check by hand"), never
  ruled out. A real bypass can hide here.
- **Firewalls that drop.** The usual fix for going around the CDN is a firewall
  that only lets the CDN in. If it *drops* other traffic, the origin just goes
  silent, and a timeout can't prove anything (a slow server looks the same), so
  re-check says **unclear (likely firewalled)** instead of fixed. Set the
  firewall to *reject* instead (ufw: `reject`, not `deny`): a refused
  connection reads as **fixed**.
- **Default pages.** If the origin answers with a stock page ("Welcome to
  nginx!"), Akashi can't tell whether it would serve the site, so it says
  inconclusive instead of guessing either way.

## Guardrails

- Active checks are fail-closed: no scope, no active check.
- The plan is shown in full and sent only after a typed `yes`.
- Only the approved plan is sent — no newly found hosts, no extra URLs.
- Every active request is logged to `scans/active.log` before it goes out,
  with `via` (`cli`, or `mcp` plus the approval id when 0x41 ran it).
- A partial result is **inconclusive**, never "confirmed".
- Through the library, active checks run only for lead IDs a person approved
  (`approved_ids`), only inside scope, and never without a scope file.

## License

MIT. See [LICENSE](LICENSE).
