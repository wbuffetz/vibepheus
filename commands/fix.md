---
description: Fix the findings from the last vibepheus report, with your approval, then re-scan.
argument-hint: "[what to fix, e.g. \"critical and high\" or \"VP-003\"]"
---

Fix issues found by the last vibepheus audit.

1. Read `vibepheus-findings.json` in the project root (and `vibepheus-report.md` for context). If they don't exist, tell the user to run `/vibepheus` first and stop.
2. Decide what to fix:
   - If `$ARGUMENTS` names findings or a level (e.g. "critical and high", "VP-003", "number 2", "the Firebase rules"), use that.
   - Otherwise list the confirmed findings, most severe first, and ask which to fix. Offer "all critical and high" as the default.
   Only fix findings with verdict `confirmed`. Skip `false_positive`; ask about `needs_user`.
3. **Before editing, show the plan**: for each fix, the file(s) and a one-line description of the change. Wait for the user's OK.
4. Fix following Step 5 of `${CLAUDE_PLUGIN_ROOT}/skills/vibepheus/SKILL.md` and the patterns in `${CLAUDE_PLUGIN_ROOT}/skills/vibepheus/references/remediation.md`:
   - make the smallest change that fixes the problem
   - for database rules, write a **new** migration file; never edit old migrations
   - **leaked keys must be rotated by the user**: tell them exactly where, step by step. Moving a key out of the code is not enough.
5. Re-run the scanner, as one plain `node` command:
   ```
   node "${CLAUDE_PLUGIN_ROOT}/skills/vibepheus/scripts/scan.mjs" "<project folder>" --offline --json --out /tmp/vibepheus-after.json
   ```
   Show the before and after counts, and list anything still open, including things only the user can do (rotating keys, applying migrations, setting spending limits).

Rules: never print a full secret. Never say the app is now "safe" or "secure". Explain at the user's level if you know it from this conversation; otherwise ask the level question from Step 0 of `SKILL.md`.

To look at files, use the Read, Glob and Grep tools, not shell commands (`ls`, `cat`, `find`, `cd`): shell commands need extra permission prompts and many setups block them.
