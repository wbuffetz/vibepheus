# vibepheus

**A security audit for AI-built web apps, as a Claude skill.**

The name is vibe + Morpheus: take the red pill and see what's really going on behind your vibe-coded app.

People ship apps built with AI without knowing the security mistakes that come with them: API keys in the browser, databases anyone can read, admin endpoints with no login check. vibepheus finds those mistakes, explains each one in plain language, and fixes the ones you approve, using your own Claude.

```
> is my app secure?

🔴 4 critical · 🟠 7 high · 🟡 1 medium

Fix these first:
1. Your Supabase admin key is in the browser bundle: anyone can read or wipe your database.
2. A Stripe live secret key is hardcoded in app/api/checkout/route.ts.
3. Anyone on the internet can call DELETE /api/admin/users.
```

## How it works

1. **A scanner finds candidates.** `scan.mjs` is a dependency-free Node script with checks written for the stacks AI tools generate most: Next.js, Supabase, Firebase, Stripe. If Semgrep, Gitleaks or osv-scanner are installed, it uses them too.
2. **Claude checks each finding.** It opens the code, discards false positives, and looks for problems a pattern cannot catch: server actions without auth, prices sent from the client, missing rate limits.
3. **You get a report in plain language.** Each finding covers what an attacker could do and how to fix it.
4. **Claude fixes what you approve,** then re-runs the scan to confirm.

**Your code stays on your machine.** The scanner runs locally. Claude sees the code through your own Claude account, the same way it does whenever you code with it. Nothing is uploaded to a third-party service. The only network call is the optional `npm audit` (skip it with `--offline`).

## What it checks

| Rule | What it catches |
|---|---|
| `HARDCODED_SECRET` | Stripe, AWS, OpenAI, Anthropic, GitHub, Slack, SendGrid keys, private keys and Supabase service_role JWTs in code |
| `SECRET_IN_GIT_HISTORY` | Keys deleted from the code but still in old commits |
| `SECRET_IN_PUBLIC_ENV` | Secrets in `NEXT_PUBLIC_` / `VITE_` / `REACT_APP_` / `EXPO_PUBLIC_` variables (shipped to every browser) |
| `ENV_FILE_NOT_IGNORED` | `.env` files that are committed or not covered by `.gitignore` |
| `SERVICE_ROLE_IN_CLIENT` | Supabase admin key in browser code (follows imports from `'use client'` files) |
| `RLS_DISABLED` | Supabase tables without Row Level Security |
| `RLS_PERMISSIVE_POLICY` | Policies with `using (true)` that let everyone in |
| `FIREBASE_OPEN_RULES` | `allow read, write: if true`, test-mode rules, open Realtime Database |
| `API_ROUTE_NO_AUTH` | Next.js API routes with no authentication check |
| `PAID_API_UNPROTECTED` | **Denial of wallet:** routes and server actions that call paid AI, email or SMS APIs (OpenAI, Anthropic, Gemini, Twilio, Resend... 15 SDKs and API hosts) without a login check or rate limit. Tells apart the owner's key from users' own keys |
| `WEBHOOK_NO_SIGNATURE` | Webhooks that accept unsigned events |
| `POSSIBLE_IDOR` | Routes that load a record by ID without checking who owns it |
| `CORS_WILDCARD` | `Access-Control-Allow-Origin: *`, especially with credentials |
| `XSS_UNSANITIZED_HTML` | `dangerouslySetInnerHTML`, `v-html`, `{@html}`, `innerHTML` with unsanitized content |
| `VULNERABLE_DEPENDENCY` | Known critical Next.js/React CVEs built in; full coverage via osv-scanner or npm audit |
| Semgrep rules | SQL/command/code injection, open redirects, unverified JWTs, insecure cookies, weak random tokens |

## Install

**Claude Code (plugin):**
```
/plugin marketplace add wbuffetz/vibepheus
/plugin install vibepheus@vibepheus
```
Or from a local folder: `/plugin marketplace add ./vibepheus`.

Then, in any project, ask *"run a security audit"* or *"is my app secure?"*.

**Claude apps (skill upload):** zip the `skills/vibepheus` folder and upload it under Settings → Capabilities → Skills. (Not yet tested there.)

**Standalone / CI:**
```bash
node skills/vibepheus/scripts/scan.mjs path/to/project                 # markdown report
node skills/vibepheus/scripts/scan.mjs path/to/project --json          # JSON
node skills/vibepheus/scripts/scan.mjs . --fail-on high                # exit 1 if any high+ finding
```
Optional extra coverage: `brew install semgrep gitleaks osv-scanner`.

## Benchmark

### Test app

`fixtures/vulnerable-app` is a deliberately insecure Next.js + Supabase app with 14 planted vulnerabilities and 15 safe look-alikes (a server-only admin client, a server action, an OAuth callback, auth through a helper, a webhook that verifies signatures, sanitized HTML...) to measure false positives. All keys in it are fake.

```bash
node tests/benchmark.mjs
```
```
Detected 14/14 planted vulnerabilities, 0 false positive(s) at medium or above, 4 low/info note(s).
```

### Real open-source projects

The test app was written alongside the scanner, so its score is optimistic. To find out how the scanner does on real code, I ran it on four public projects and checked every finding by hand:

| Project | v0.1 findings | After fixes (medium+) | Notes |
|---|---|---|---|
| Next.js + Supabase + Stripe starter | 11 | 1 (+4 low) | the one remaining finding is real (outdated Next.js with a known CVE) |
| Next.js AI chatbot template | 6 | 0 (+3 low) | |
| Next.js + Supabase open-source chat app | 24 | 4 (+1 low) | 2 real issues, 2 overrated (Claude downgraded them) |
| Supabase SQL extension | 0 | 0 | |

Project names and details of unpatched issues are left out on purpose: they get reported privately to the maintainers first.

**End to end with Claude:** on the chat app, the full skill (scanner, then Claude's verification and manual review) took 28 turns and produced a 14-finding report. Claude correctly downgraded the two overrated findings and found several real issues the scanner cannot see, such as a database function the anonymous key can call and an admin-client query that trusts IDs sent by the client. I checked those claims against the code by hand.

**The first version mostly produced false positives on real code: about 41 findings, only a handful real.** Each false positive pointed to a missing rule, which is now a regression case in the test app:

- `'use server'` files imported by client components run on the server, not in the browser
- auth checks wrapped in helpers (`getServerProfile()`, `requireUser()`) count as auth
- OAuth callbacks and explicitly cacheable public routes are public by design
- `.env.local.example` is an example file, and `env(...)` in `supabase/config.toml` is a placeholder
- public read access on tables with no private-looking columns (a product catalog) is reported as low, not high
- the publicly known Supabase local-dev key is reported as low
- middleware only counts as protection if it actually redirects or returns 401/403

The remaining findings still need judgement. For example, a route that uses the admin client without auth is flagged high even if it only returns public usernames. Deciding that is the job of Claude's verification step (see `SKILL.md`). See [`fixtures/sample-report.md`](fixtures/sample-report.md) for the scanner's raw output.

## How this was built

I built vibepheus with Claude Code, and the first version of the code was largely written by Claude. Here is what I did, and what the process taught me.

**The problem.** My degree is in cybersecurity. Many websites are now built with AI by people who don't know the security mistakes that come with it, because nobody told them, not because they're careless. I wanted a tool that works for them: plain language, fixes included, no security background needed.

**The design decisions.**
- **Code scanning first, not URL scanning.** Probing websites you don't own is illegal in most countries. Scanning your own code avoids that, and it finds the serious bugs (missing auth checks, open database rules) that a URL scan can't see.
- **A Claude skill, not a hosted service.** It runs inside the user's own Claude, so they pay for their own usage and their code is never uploaded to a third-party server.
- **Proven tools for detection, Claude for judgement.** Pattern matching finds candidates and Claude verifies them, because a language model alone misses bugs and reports bugs that aren't there.

**What testing taught me.** The first version scored 12 out of 12 on a test app with planted bugs. That score was meaningless, because the test app and the scanner were written together. So I ran the scanner on four real open-source projects and checked every finding by hand. **Out of about 41 findings, only around 5 were real.** Each false positive pointed to something real apps do that my test app didn't (server actions, auth helpers, OAuth callbacks...). Each one became a fix plus a regression test. After that, findings at medium or above dropped to 6, most of them real. The full skill, run end to end, also found issues the scanner can't, and I checked each of them against the code.

**What I took from it:**
- A benchmark you design yourself mostly confirms your own assumptions. Real-world data is the real test.
- False positives decide whether people trust a security tool. One that cries wolf 35 times gets ignored.
- When you find vulnerabilities in other people's projects, report them privately to the maintainers before publishing details. That's why the projects in the results table aren't named.

**From here,** I'm writing the new features myself: testing the Semgrep, Gitleaks and osv-scanner integrations, adding Supabase Storage checks, and supporting more frameworks. The commit history shows who wrote what.

## Limits

- Pattern-based checks miss things and can be wrong, which is why Claude verifies every finding. A clean result means these checks passed, **not** that the app is secure.
- Strongest on Next.js + Supabase/Firebase. Other frameworks get the secret, dependency, CORS and XSS checks, plus Claude's manual review.
- It does not scan live websites. Testing a site you do not own without permission is illegal in most countries. A passive URL check with ownership verification is on the roadmap.

## Roadmap

- [ ] Benchmark on real open-source projects; publish detection and false-positive rates
- [ ] Passive URL check (security headers, TLS, keys leaked in public JS bundles) with domain ownership verification
- [ ] More stacks: SvelteKit, Nuxt, Express, Prisma, Clerk/NextAuth-specific checks
- [ ] Supabase Storage bucket and `security definer` function checks

## License

MIT
