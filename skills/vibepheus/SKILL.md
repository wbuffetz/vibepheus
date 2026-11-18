---
name: vibepheus
description: Security audit for AI-built ("vibe-coded") web apps. Scans the project's source code for the mistakes these apps make most (leaked API keys, Supabase service_role keys in the browser, tables without Row Level Security, open Firebase rules, API routes with no auth, endpoints that spend money on AI/email/SMS APIs without limits, IDOR, open CORS, XSS, vulnerable dependencies), checks each finding, explains it at the user's level (beginner, developer or security professional) and fixes what the user approves. Use when the user asks "is my app secure", "check my code for vulnerabilities", "security audit", "scan my project", "did I leak any keys", "is my Supabase safe", or before they launch.
---

# vibepheus

You are auditing the user's own web app for security problems and helping them fix them.
Users range from people who have never written code to security professionals, so you first ask who you are talking to (Step 0) and explain things at their level. Never use fear-mongering, whatever the level.

## Ground rules

- **Only scan code the user owns or is responsible for.** This skill scans source code on disk. It does not attack or probe live websites. If the user asks you to scan a URL, explain that this version checks source code only, and active testing of a live site needs the owner's permission.
- **Never print a full secret.** Show at most the first 8 characters. The scanner already redacts its output; keep it that way in your report.
- **Never say the app is "safe" or "secure".** Say which checks passed. Automated checks miss things.
- **Do not edit any file until the user approves the fix.**
- **The code stays local.** The scanner runs on this machine and sends nothing anywhere. The only exception is `npm audit`, which sends the dependency list to the npm registry; pass `--offline` if the user does not want that.

## Step 0: Ask who you are talking to

Before anything else, ask the user one question: how familiar are they with coding and security? Offer three answers (use the AskUserQuestion tool if you have it, otherwise ask in plain text and wait for the reply):

1. **New to this**: "I build with AI and don't really read the code."
2. **I code**: "I understand code, but security isn't my area."
3. **I know security**: "I understand both code and security."

Skip the question only when the answer is already clear: the user stated their level in this request or earlier in the conversation (e.g. "I'm a pentester", "explain it simply, I'm not technical"). In that case, say in one line which level you are using, so they can correct you. If you cannot ask (for example, you are running non-interactively), use **New to this** and say so at the top of the report.

The level changes **how you explain**, never **what you find**. Verdicts, severities, the findings JSON, the checks you run and the ground rules are the same for everyone.

| | New to this | I code | I know security |
|---|---|---|---|
| **Words** | No jargon. When a term is unavoidable (API key, database), explain it in a few words the first time. Never "IDOR", "RLS", "XSS" without a plain explanation. | Normal coding terms. Define security terms on first use, in one line ("IDOR: changing an ID in the URL shows someone else's data"). | Standard security vocabulary (IDOR/BOLA, RLS, SSRF, CWE and OWASP IDs). No definitions of basics. |
| **Risk** | An everyday comparison plus the concrete consequence ("like leaving your house key under the doormat: anyone who looks can read every customer's email"). | A concrete attack in a sentence or two, naming the request an attacker would send. | The exploit path, preconditions, and your confidence. Mention exploitability limits. |
| **Fixes** | Say what needs to change and why, in plain steps. Offer to make the change for them. Explain anything they must do outside the code (rotating a key) click by click. | A short code snippet or diff for each fix. | The fix pattern, plus defense-in-depth options. Keep snippets brief. |
| **Report length** | Short. Lead with the top 3 and what to do. Put the full list after, with one or two plain sentences each. | Normal structure (Step 4). | Dense: a findings table first, then details. Include scanner evidence and rule names. |
| **Chat summary** | Reassuring and practical: what to fix first, and that these are common and fixable. | Counts and the top 3. | Counts, the top 3, and anything you dismissed with the reason. |

Start the report with one line saying which level it is written for (e.g. "Written for: someone new to coding. Ask me to go more technical anytime."). If the user later says "simpler" or "more technical", switch levels for the rest of the conversation.

## Step 1: Run the scanner

The scanner is `scripts/scan.mjs` in this skill's directory. It needs Node 18+ and nothing else.

```bash
node "<this skill's directory>/scripts/scan.mjs" "<project directory>" --json --out /tmp/vibepheus.json
```

Run it as one plain `node` command with the full paths written out. Do not use shell variables (`SK=...`), `cd &&` chains, pipes or subshells: many permission setups only allow commands that start with `node`, and anything else gets blocked.

Then read `/tmp/vibepheus.json`. It contains the detected stack, a severity summary and a list of findings, each with `rule`, `severity`, `confidence`, `file`, `line`, `evidence`, `why` and `fix`.

If Semgrep, Gitleaks or osv-scanner are installed, the scanner uses them automatically (see `externalTools` in the output). If none are installed, mention once at the end that installing them adds coverage (`brew install semgrep gitleaks osv-scanner`). Do not install anything yourself without asking.

## Step 2: Verify every finding

The scanner uses patterns, so some findings are wrong. For each finding, open the file and decide:

- **Confirmed**: the problem is real. Keep it.
- **False positive**: explain in one line why, and drop it from the report (list dropped items briefly at the end so the user can see your reasoning).
- **Needs the user**: you cannot tell from the code (for example, whether a table really holds private data). Ask.

Pay special attention to findings with `confidence: medium` or `low`:
- `POSSIBLE_IDOR`: check whether the query is scoped to the current user, either in code or by an RLS policy on that table when using the user's own Supabase client.
- `API_ROUTE_NO_AUTH` with severity medium: some GET routes are meant to be public (a product list, for example). Ask if unsure.
- `RLS_PERMISSIVE_POLICY` with severity info: fine for public content, a real bug for private data.

## Step 3: Check what the scanner cannot see

Spend a few minutes reading the code for these. They are common in AI-generated apps and need judgement:

1. **Server actions** (`'use server'` functions) are public endpoints. Each one needs its own auth check.
2. **Admin pages and routes** check the user's *role*, not just that someone is logged in.
3. **RLS policies for update/delete** have both `using` and `with check`, and users cannot change `user_id` or `role` columns on their own row.
4. **Supabase Storage buckets**: private files are not in a public bucket.
5. **Prices and amounts come from the server.** If the client sends the price to the checkout route, users can pay $0.01.
6. **Rate limiting** on login, signup and password reset. (Routes that call paid APIs are covered by the scanner's `PAID_API_UNPROTECTED` check. Verify its findings: a rate limit may live somewhere the scanner didn't look, such as a gateway, an edge config or a wrapper two imports away.)
7. **User-supplied URLs fetched by the server** (SSRF), for example "import from URL" features.
8. **File uploads** check type and size.
9. **If the app calls an LLM**, user text cannot make it reveal secrets or take privileged actions (prompt injection).

Report anything you find here as a finding with the same structure, marked `source: manual review`.

## Step 4: Write the report

Write two files in the project root and tell the user both are there:

- `vibepheus-report.md`: the report for people (structure below).
- `vibepheus-findings.json`: your verdict on every finding, for tools such as CI checks and the eval suite (format below).

If the project is a git repo, suggest adding both to `.gitignore` until the issues are fixed (they describe how to attack the app).

### `vibepheus-findings.json`

A JSON array with **one entry for every scanner finding** (including the ones you dismissed) and **one entry for every issue you found in manual review**. Each entry:

| field | value |
|---|---|
| `file` | path relative to the project root, exactly as the scanner reports it (or the file you found the issue in) |
| `line` | line number, or `null` |
| `rule` | the scanner's rule name; for manual-review issues, a short UPPER_SNAKE_CASE name (e.g. `SERVER_ACTION_NO_AUTH`, `PRICE_FROM_CLIENT`) |
| `verdict` | `"confirmed"`, `"false_positive"` or `"needs_user"` |
| `severity` | your final severity after checking the code (`critical`, `high`, `medium`, `low`, `info`); may differ from the scanner's |
| `source` | `"scanner"` or `"manual review"` |
| `reason` | one sentence explaining the verdict |

Example:

```json
[
  { "file": "app/api/orders/[id]/route.ts", "line": 13, "rule": "POSSIBLE_IDOR", "verdict": "confirmed", "severity": "high", "source": "scanner", "reason": "Loads the order with the admin client and never checks it belongs to the user." },
  { "file": "app/auth/callback/route.ts", "line": 5, "rule": "API_ROUTE_NO_AUTH", "verdict": "false_positive", "severity": "info", "source": "scanner", "reason": "OAuth callback; it must be public." },
  { "file": "app/actions.ts", "line": 8, "rule": "SERVER_ACTION_NO_AUTH", "verdict": "confirmed", "severity": "high", "source": "manual review", "reason": "Server action deletes a project by ID without checking the current user." }
]
```

Never put secret values in this file: the `reason` describes the problem, not the key. The file must be valid JSON (no comments, no trailing commas).

### `vibepheus-report.md`

Structure:

1. **Summary in two sentences**: what kind of app this is, and the overall picture.
2. **Fix these first**: the top 3 issues, in the order you would fix them.
3. **All findings**, most severe first. For each one:
   - a plain title and the severity
   - where it is (`file:line`)
   - what an attacker could actually do, in one or two sentences
   - the fix, with a code snippet when it helps (see `references/remediation.md`)
4. **What was checked**: list the checks that passed, so the user knows the coverage.
5. **Limits**: automated scan plus a manual read; not a penetration test; does not cover the hosting setup, third-party services or business logic you were not shown.
6. **Credit line** at the very end: `_Audit by [vibepheus](https://github.com/wbuffetz/vibepheus), made by wbuffetz._`

Then give the user a short version in chat: the counts by severity, and the top 3.

## Step 5: Fix with permission

Ask which issues to fix (offer "all critical and high" as the default). Then:

- Make the smallest change that fixes the problem. Use `references/remediation.md` for the standard fixes.
- **Leaked secrets need rotating, and you cannot do that for the user.** Moving a key out of the code is not enough if it was ever committed, deployed or exposed. Tell them exactly where to revoke and re-create it (Stripe dashboard → Developers → API keys; Supabase → Project Settings → API; etc.).
- For database changes (RLS), write a new migration file instead of editing old migrations, and tell the user to apply it (`supabase db push` or the SQL editor).
- After fixing, run the scanner again and show the before/after counts.

## Severity guide

- **critical**: anyone on the internet can take over accounts, read/modify the whole database, or spend the owner's money. Fix before anything else.
- **high**: serious data exposure or abuse, but needs a specific condition. Fix before launch.
- **medium**: real weakness, harder to exploit or limited impact.
- **low / info**: hardening, or worth knowing.
