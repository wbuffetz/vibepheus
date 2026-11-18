---
description: Go-live checklist - code checks plus the hosting and account settings an AI tool can't see.
argument-hint: "[project folder]"
allowed-tools: Bash(node:*), Read, Grep, Glob
---

Give the user a "before you launch" security checklist for this project.

1. Project folder: `$ARGUMENTS` if given, otherwise the current working directory. Use the latest `vibepheus-findings.json` if there is one. Otherwise run the scanner, as one plain `node` command:
   ```
   node "${CLAUDE_PLUGIN_ROOT}/skills/vibepheus/scripts/scan.mjs" "<project folder>" --offline --json --out /tmp/vibepheus-prelaunch.json
   ```
   Open the files behind any critical or high scanner finding to confirm it before marking it ❌.
2. Look at the project's stack (framework, Supabase/Firebase, Stripe, AI or email APIs, hosting config) and include only the items that apply.
3. Write the checklist in chat, grouped like this. Mark each item ✅ (checked in the code and fine), ❌ (problem found, with `file:line`), or ❓ (can't be checked from code: the user must check it, with where to look).

   **In the code**
   - No secrets in code, in git history, or in public env variables
   - Every table has Row Level Security / Firebase rules aren't open
   - API routes and server actions check who is calling; admin features check the role
   - Paid APIs (AI, email, SMS) need a login and have a rate limit
   - Payment amounts come from the server; webhooks verify signatures
   - Dependencies have no known critical CVEs

   **Outside the code (❓ unless the code proves otherwise)**
   - Environment variables are set in the hosting dashboard, and any key that was ever committed has been rotated
   - Spending limits and usage alerts are set on every paid API (OpenAI, Anthropic, Twilio, Resend...)
   - Supabase: email confirmation on, leaked-password protection on, storage buckets private unless meant to be public
   - Backups are enabled and you know how to restore one
   - Error pages don't show stack traces or internal details in production
   - The domain uses HTTPS (most hosts do this automatically)
   - Someone gets an alert if something breaks or usage spikes

4. End with a verdict: the number of ❌ to fix before launch (most important first) and the ❓ items to check. Never say the app is ready, safe or secure; say which checks passed. Suggest `/vibepheus` for a full audit and `/vibepheus:fix` for the ❌ items.

Rules: never print a full secret. Chat only; write no files. Explain at the user's level if you know it from this conversation; otherwise use plain language.

To look at files, use the Read, Glob and Grep tools, not shell commands (`ls`, `cat`, `find`, `cd`): shell commands need extra permission prompts and many setups block them.
