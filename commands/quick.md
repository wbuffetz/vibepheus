---
description: Fast scanner-only check. No Claude review, results in seconds.
argument-hint: "[project folder]"
allowed-tools: Bash(node:*), Read
---

Run a quick vibepheus scan. This is the scanner alone: fast and cheap, but its findings are **not verified**, so some may be false alarms.

1. Project folder: `$ARGUMENTS` if given, otherwise the current working directory.
2. Run exactly this, as one plain `node` command with the full paths written out (no shell variables, `cd`, pipes or subshells):
   ```
   node "${CLAUDE_PLUGIN_ROOT}/skills/vibepheus/scripts/scan.mjs" "<project folder>" --offline --json --out /tmp/vibepheus-quick.json
   ```
3. Read `/tmp/vibepheus-quick.json` and reply in chat only (write no files):
   - the counts by severity
   - a short table of findings: ID, severity, title, `file:line`
   - one line saying these are unverified scanner results, and that `/vibepheus` checks each one and explains the fixes.
   - if `externalTools` shows tools as `not installed`, one line saying `/vibepheus:setup` can install them. Do not offer to install them here: this command is meant to be quick.

Rules: never print a full secret (the scanner already redacts them; keep it that way). Never say the app is "safe" or "secure". Do not edit any file. Do not open the flagged files: this command is meant to be quick.
