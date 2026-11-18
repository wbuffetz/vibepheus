---
description: Check only for leaked secrets (API keys, tokens, .env files), including old git commits.
argument-hint: "[project folder]"
allowed-tools: Bash(node:*), Read, Grep, Glob
---

Check this project for leaked secrets only.

1. Project folder: `$ARGUMENTS` if given, otherwise the current working directory.
2. Run exactly this, as one plain `node` command with the full paths written out (no shell variables, `cd`, pipes or subshells):
   ```
   node "${CLAUDE_PLUGIN_ROOT}/skills/vibepheus/scripts/scan.mjs" "<project folder>" --only secrets --offline --json --out /tmp/vibepheus-keys.json
   ```
   This covers keys written in code, keys in old git commits, secrets in public (`NEXT_PUBLIC_`, `VITE_`...) variables, `.env` files git doesn't ignore, and the Supabase admin key reaching the browser.
3. Read `/tmp/vibepheus-keys.json`. Open each flagged file and decide if it is a real secret or a false alarm (example files, placeholders, keys that are public by design such as a Firebase web key or the Supabase anon key).
4. Reply in chat (write no files). For each real leak:
   - which service the key belongs to, and where it is (`file:line`)
   - who can see it now (anyone visiting the site? anyone with repo access? anyone who ever cloned it?)
   - **how to rotate it**: removing it from the code is not enough once it has leaked. Give the exact place in that service's dashboard (see `${CLAUDE_PLUGIN_ROOT}/skills/vibepheus/references/remediation.md`).
   - how to stop it happening again (env variable without a public prefix, `.gitignore`).
   If nothing was found, say which checks ran and that they found nothing. Do not say the project has no secrets.

Rules: **never print a full secret**, at most its first 8 characters. Do not edit files unless the user asks; if they ask, follow the fix rules in `${CLAUDE_PLUGIN_ROOT}/skills/vibepheus/SKILL.md` (Step 5). Explain at the user's level if you know it from this conversation; otherwise use plain language and offer to go more technical.

To look at files, use the Read, Glob and Grep tools, not shell commands (`ls`, `cat`, `find`, `cd`): shell commands need extra permission prompts and many setups block them.
