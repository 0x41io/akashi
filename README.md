# akashi

**Monomi finds. Akashi proves. Kaidoku explains.**

Akashi is the third tool in the [0x41](https://0x41.sh) security suite. It takes
a lead from a [Monomi](https://github.com/0x41io/monomi) scan, confirms or rules
it out with evidence, gives the exact fix, and re-checks it after the fix:
**prove, fix, re-check.**

It is not an autonomous pentester. It never picks its own targets, never runs
exploits, and never changes anything on a target. Every active check stays
inside an approved scope and waits for a typed `yes`.

> Status: **v0.1, in progress.** `plan` (show what would be checked, send
> nothing) and `verify` for the **passive** checks are built: the takeover
> re-check over DNS, the registry (RDAP) lookup that settles an unknown-service
> takeover, and the email re-check, all after a typed yes. The one active check
> (going around the CDN), the fixes, and `recheck` are next.

## What it proves (v0.1)

Akashi reads the typed fields Monomi writes since v1.15.0, so it knows what each
lead is without reading its text.

| Monomi lead | How Akashi proves it | Touches the target? |
|---|---|---|
| `takeover` (claimable service) | Re-check now that the dangling CNAME still points at the deleted target and that the target still doesn't exist, on both DoH resolvers. Never claims the name. | No — DNS only |
| `takeover_unknown` | The same DNS re-check, plus a registry (RDAP) lookup: if the target's domain is registered, an attacker can't claim it (ruled out); otherwise inconclusive, since claiming a domain is a human decision | No — DNS + registry |
| `around_cdn` | One request to the fronted host through the CDN, one to the origin IP with the same `Host` header; compare the responses | Yes — one request each |
| `email_spoofing` | Fresh SPF / DMARC / DKIM lookup | No — DNS only |

Every verdict is **confirmed**, **ruled out**, or **inconclusive** (the default),
and carries its evidence.

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

# Run the passive checks (DNS/registry) after a typed yes. Records each
# verdict, with its evidence, to an append-only history per target.
akashi verify scan.json --scope scope.txt
```

`scan.json` is a Monomi scan saved with `monomi --json`, from Monomi v1.15.0 or
newer. `--scope` is a scope file in Monomi's format; the active check (going
around the CDN) only runs against hosts it allows, and is shown as blocked
without it. The passive checks (DNS and registry) never contact the target, so
they need no scope.

## Guardrails

- Active checks are fail-closed: no scope, no active check.
- The plan is shown in full and sent only after a typed `yes` (in `verify`, next).
- Only the approved plan is sent — no newly found hosts, no extra URLs.
- A partial result is **inconclusive**, never "confirmed".

## License

MIT. See [LICENSE](LICENSE).
