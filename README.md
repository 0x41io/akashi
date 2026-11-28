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

> Status: **v0.7.4.** The full **prove, fix, re-check** loop is built: `plan`
> (show what would be checked, send nothing), `verify` (run the checks after a
> typed yes), and `recheck` (re-run a confirmed lead after you fix it, to prove
> it's closed). The passive checks (the takeover re-check over DNS, the registry
> (RDAP) lookup for an unknown-service takeover, and the email re-check) never
> touch the target; the active checks (going around the CDN, and since v0.6.0
> exposed files) run only inside scope. A **confirmed** lead prints the exact fix to close it. Since
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
>
> Since v0.3.1 the library API covers app checks too (`akashi.api.app_plan()`,
> `akashi.api.prove_app()`), so [0x41](https://github.com/0x41io/0x41) can run one Claude asked for, after a
> person's typed yes in a terminal.
>
> v0.3.2 to v0.3.5 only move Akashi onto [mønømi](https://github.com/0x41io/monomi) v1.22.0 (new
> `management` hostname category), v1.22.1 (Microsoft 365 and Google's front end count as third-party
> hosting) and v1.23.0 (the target's own server decided by CNAME too, vendor hosts out of around-the-CDN
> leads, ranked leads) and v1.23.1 (CVEs on someone else's server never count as the
> target's), so 0x41 can pin both to the same mønømi. Nothing Akashi proves changes; a fix for
> a lead behind Azure Front Door now names it instead of "the CDN".
>
> v0.4.0 proves mønømi v1.24's grouped **go around the CDN** leads: one lead per CDN with every
> origin candidate in it, ranked. The plan lists one request through the CDN and one per origin
> (the first 5 reachable through an in-scope name), and the verdict is **confirmed** if any origin
> serves the site (naming which), **ruled out** only if every origin was tried and none does, and
> **inconclusive** otherwise, including when origins past the cap weren't tried. The lead's key
> (its re-check history) is now its fronted hosts and CDN, not its origin IPs, which rotate. A
> lead from an older mønømi scan, with one origin, works exactly as before.
>
> v0.5.0 widens the **application-logic** checks in two ways. The login step now keeps a session the
> way real web apps do: set `login.session = "cookie"` in a case and Akashi carries the login's
> `Set-Cookie` on every later request, instead of only reading a bearer token from a JSON body
> (`session = "token"`, still the default). And a second check type, `privileged_function`, proves
> missing **function-level** access control: can a low-privilege account (`actor`) reach an admin-only
> endpoint that the `privileged` account can? Same shape as the object-level (IDOR) check — one
> endpoint, two of your own accounts, fail-closed on scope, a typed yes, only a hash of the response
> kept — and conservative on purpose: it confirms only when the actor gets the privileged account's
> exact response and the endpoint refuses an anonymous request, and stays inconclusive otherwise.
>
> v0.5.1 is a safety fix. A case file's `base` must now name one clear host: no `@` (a login
> inside the URL) and no backslash. Before, `https://evil.test\@app.example.com` read as
> `app.example.com` to the scope check while `requests` connected to `evil.test`, so the login,
> with your test account's password, would have gone there. Every request the app checks send
> is also checked one last time, right before sending: the host it will really connect to must
> be the one the URL names, or nothing is sent. Akashi now pins [mønømi](https://github.com/0x41io/monomi)
> v1.25.0 (whose scope check got the same fix), and `requirements.txt` agrees with
> `pyproject.toml` again (a test keeps them in step).
>
> v0.6.0 proves mønømi v1.27's **exposed files**: the files `--content` found on a host (a Git
> folder, an `.env`, a backup zip...), one path per host. For each file Akashi asks again, right
> now: three made-up paths first, to see what the host's "not found" looks like today, then the
> file itself, and the same content check Monomi used (it calls mønømi's `content.recheck_file()`,
> so the two tools never disagree on what "the real file" is). **Confirmed** if any file is still
> served, naming each; **ruled out** only when every file is gone (removed, or refused for that path
> alone, which is the fix); **inconclusive** otherwise: a timeout, a host that refuses every path, a
> catch-all page, or files past the cap of 5 not asked. The evidence says what a file is, never
> what it holds. A confirmed secrets file's fix says to change everything in it, not just remove it.
> Akashi now pins [mønømi](https://github.com/0x41io/monomi) v1.27.0, and every active log line
> names the rule it was for (`exposed_file` or `around_cdn`).
>
> v0.6.1 says exactly what a registered vendor domain rules out: a dangling CNAME at an unknown
> service whose domain is registered is ruled out because it "can't be claimed by registering the
> domain", no longer "an attacker can't claim it" (a claim inside the vendor's own platform isn't
> tested). It pins [mønømi](https://github.com/0x41io/monomi) v1.28.0, which stops sending leads for
> names nobody on the internet can create (`*.internal.aws` and other brand or private TLDs) and
> lists around-the-CDN origins likeliest first, so the five Akashi tries go to the best candidates.
> Licensed AGPL-3.0-only from this version on; earlier versions stay MIT.
>
> v0.7.0 proves mønømi's **broken DNS delegations** (`dangling_ns`), until now listed as "not
> handled yet": a zone delegated to nameservers that refuse it. Akashi re-checks it's still broken,
> asks one of the parent zone's own nameservers, once, which nameservers the zone is delegated to
> (the question every resolver asks while looking a name up, sent to the DNS provider, never to the
> target's web servers), and looks up whether their domains are registered. A nameserver on a domain
> with no registration found is the dangerous case, since whoever registers it answers DNS for the
> whole zone, and like every "free" answer it's **inconclusive: confirm by hand**, never "go claim
> it". Pins [mønømi](https://github.com/0x41io/monomi) v1.28.1 (Route 53 delegations graded right).
> The registry check now tells "no registration found" (HTTP 404) apart from "couldn't check" (a
> rate limit, an error): only the first can raise the confirm-by-hand alarm, for takeovers too. Each
> domain is asked once per run, and a rate limit waits once, as the registry asks, before trying again.
>
> v0.7.1 pins [mønømi](https://github.com/0x41io/monomi) v1.29.2 (BBOT import, every own server
> checked on Shodan InternetDB, OpenSearch endpoints graded stale), so the suite installs together.
>
> v0.7.2 pins mønømi v1.29.3. Registry (RDAP) lookups are paced, about one a second per registry, and a rate limit waits as
> long as the registry asks (up to 30 seconds, twice) before giving up. A vet with five Route 53
> delegations asks about 20 awsdns domains, and one was left "couldn't be checked" before.
> A broken delegation's verdict also carries a reason code (`pooled_registered`, `ns_registered`,
> `ns_unregistered`, `registry_unchecked`, `parent_unreachable`, `delegation_elsewhere`), since every
> outcome but "fixed" is inconclusive: the code tells them apart without reading the headline.
>
> v0.7.3 pins mønømi v1.29.4 (API Gateway and ServiceNow servers are no longer read as the target's own).
>
> v0.7.4 pins mønømi v1.30.0 (a server named only through another domain's CNAME is "likely a vendor's platform" everywhere; the target's own network and DNS-only steering like Akamai GTM keep a server the target's, so around-the-CDN leads can list those servers as origins).

## What it proves

Akashi reads the typed fields Monomi writes since v1.15.0, so it knows what each
lead is without reading its text.

| Monomi lead | How Akashi proves it | Touches the target? |
|---|---|---|
| `takeover` (claimable service) | Re-check now that the dangling CNAME still points at the deleted target and that the target still doesn't exist, on both DoH resolvers. Never claims the name. | No — DNS only |
| `takeover_unknown` | The same DNS re-check, plus a registry (RDAP) lookup: if the target's domain is registered, an attacker can't claim it (ruled out); otherwise inconclusive, since claiming a domain is a human decision | No — DNS + registry |
| `around_cdn` | One request to the fronted host through the CDN, one to the origin IP with the same `Host` header; compare the responses. A stock default page or a short generic title never counts as a match | Yes — one request each |
| `exposed_file` (v0.6.0) | For each file found (up to 5): three made-up paths on the host, then the file, judged by mønømi's own content check. Confirmed if any is still the real file; ruled out only when all are gone | Yes — four requests per file |
| `dangling_ns` (v0.7.0) | Re-check over DoH that the zone is still a broken delegation (fixed: ruled out). Then one non-recursive NS query to a nameserver of the parent zone, for the exact nameservers it's delegated to, and an RDAP lookup of each one's domain. Never confirmed: a nameserver on an unregistered domain is inconclusive with "confirm by hand", and registered ones say who runs them (Route 53: a large pool, impractical) | No — DNS + registry, plus one query to the parent zone's nameserver (named in the evidence) |
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

- **Exposed files behind a WAF.** A host that refuses Akashi on every path
  (made-up ones too) can't show whether a file was removed, so the verdict is
  **inconclusive**, never ruled out. Run it with the research header the
  program asks for, or check by hand.

## Guardrails

- Active checks are fail-closed: no scope, no active check.
- The plan is shown in full and sent only after a typed `yes`.
- Only the approved plan is sent — no newly found hosts, no extra URLs.
- Every active request is logged to `scans/active.log` before it goes out,
  with `via` (`cli`, or `mcp` plus the approval id when 0x41 ran it).
- A partial result is **inconclusive**, never "confirmed".
- Through the library, active checks run only for lead IDs a person approved
  (`approved_ids`), only inside scope, and never without a scope file.

## Licensing

Copyright (c) 2026 0x41.

From v0.6.1 on, akashi is licensed under the **GNU Affero General Public License v3.0 only** (AGPL-3.0-only); see [LICENSE](LICENSE). Versions before v0.6.1 were released under the MIT License and stay under it.

In short: you can use, study, change and share it. If you share a changed version, or run one as a network service other people use, you must make its source available to them under the same license. This is a summary; the LICENSE text is what counts.

Outside contributions need a contributor license agreement (CLA), so 0x41 can keep licensing the project as a whole. Open an issue and ask before sending a pull request.
