---
description: Explain one finding in depth - what it is, how an attacker would use it, how to fix it.
argument-hint: "<finding ID, number from the report, or description>"
allowed-tools: Read, Grep, Glob
---

Explain one vibepheus finding in depth: `$ARGUMENTS`

1. Find it. Look in `vibepheus-report.md` and `vibepheus-findings.json` in the project root, matching `$ARGUMENTS` as a finding ID (e.g. `VP-003`), a number from the report, a rule name, a file, or a description. If several match, ask which. If there is no report, or `$ARGUMENTS` is empty, ask which issue the user means (or suggest running `/vibepheus` first).
2. Open the code it points to and read enough around it to be accurate.
3. Explain, at the user's level (known from this conversation, otherwise ask the level question from Step 0 of `${CLAUDE_PLUGIN_ROOT}/skills/vibepheus/SKILL.md`):
   - **What it is**, in one or two sentences, with the general name of this kind of bug.
   - **Why it is in this code**: point to the exact lines.
   - **How an attacker would find and use it**: describe the steps and the impact in words. Do not write a working exploit, attack script or ready-to-run payload against the app.
   - **How bad it is here** and why (who can reach it, what data or money is at stake). If you now think the original verdict or severity was wrong, say so.
   - **The fix**: the concrete change for this code (see `${CLAUDE_PLUGIN_ROOT}/skills/vibepheus/references/remediation.md`), plus how to check it worked.
   - **How to avoid it next time**, e.g. what to tell the AI tool when building the next feature.
4. Offer to fix it (`/vibepheus:fix`). Do not edit anything yourself.

Rules: never print a full secret, at most its first 8 characters. Chat only; write no files.

To look at files, use the Read, Glob and Grep tools, not shell commands (`ls`, `cat`, `find`, `cd`): shell commands need extra permission prompts and many setups block them.
