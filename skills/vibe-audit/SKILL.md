---
name: vibe-audit
description: Security audit for AI-built ("vibe-coded") web apps. Scans the project's source code for the mistakes these apps make most (leaked API keys, Supabase service_role keys in the browser, tables without Row Level Security, open Firebase rules, API routes with no auth, IDOR, open CORS, XSS, vulnerable dependencies), checks each finding, explains it in plain language and fixes what the user approves. Use when the user asks "is my app secure", "check my code for vulnerabilities", "security audit", "scan my project", "did I leak any keys", "is my Supabase safe", or before they launch.
---

# vibe-audit

You are auditing the user's own web app for security problems and helping them fix them.
The user is often not a security person. Explain everything in plain language, without jargon or fear-mongering.

## Ground rules

- **Only scan code the user owns or is responsible for.** This skill scans source code on disk. It does not attack or probe live websites. If the user asks you to scan a URL, explain that this version checks source code only, and active testing of a live site needs the owner's permission.
- **Never print a full secret.** Show at most the first 8 characters. The scanner already redacts its output; keep it that way in your report.
- **Never say the app is "safe" or "secure".** Say which checks passed. Automated checks miss things.
- **Do not edit any file until the user approves the fix.**
- **The code stays local.** The scanner runs on this machine and sends nothing anywhere. The only exception is `npm audit`, which sends the dependency list to the npm registry; pass `--offline` if the user does not want that.

## Step 1: Run the scanner

The scanner is `scripts/scan.mjs` in this skill's directory. It needs Node 18+ and nothing else.

```bash
node "<this skill's directory>/scripts/scan.mjs" "<project directory>" --json --out /tmp/vibe-audit.json
```

Then read `/tmp/vibe-audit.json`. It contains the detected stack, a severity summary and a list of findings, each with `rule`, `severity`, `confidence`, `file`, `line`, `evidence`, `why` and `fix`.

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
6. **Rate limiting** on login, signup, password reset and any route that calls a paid API (OpenAI, Anthropic, email, SMS). Without it, one script can run up a large bill.
7. **User-supplied URLs fetched by the server** (SSRF), for example "import from URL" features.
8. **File uploads** check type and size.
9. **If the app calls an LLM**, user text cannot make it reveal secrets or take privileged actions (prompt injection).

Report anything you find here as a finding with the same structure, marked `source: manual review`.

## Step 4: Write the report

Write the report to `vibe-audit-report.md` in the project root, and tell the user it is there. If the project is a git repo, suggest adding it to `.gitignore` until the issues are fixed (the report describes how to attack the app).

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
