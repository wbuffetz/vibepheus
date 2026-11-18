---
description: Check which optional extra tools (Semgrep, Gitleaks, osv-scanner) are installed, and offer to install the missing ones.
---

Help the user set up vibepheus's optional extra tools. Follow `${CLAUDE_PLUGIN_ROOT}/skills/vibepheus/references/extra-tools.md`.

1. Check which are installed by running each of these on its own (one plain command each, no pipes or `&&`): `semgrep --version`, `gitleaks version`, `osv-scanner --version`. A "command not found" error means it is missing. Also check `node --version` (vibepheus needs Node 18 or newer) and, on macOS, `brew --version`.
2. Show a short table: each tool, installed or missing, and what it adds.
3. If anything is missing, ask the user whether to install the missing tools now or skip (use the AskUserQuestion tool if you have it). Give the size and time from `extra-tools.md`. Let them pick only some of the tools if they want.
4. On a yes, install only what they chose, using the method in `extra-tools.md` for their system. Without Homebrew, or on Linux or Windows, give the official instructions and let them install it themselves. Never use unofficial sources or `curl ... | sh`.
5. Check each one runs, then say they're ready: the next `/vibepheus` or `/vibepheus:quick` will use them automatically. If an install failed, say which and why in one sentence, and don't retry in a loop.

Never install anything without the user's yes in this conversation. Explain at the user's level if you know it from this conversation; otherwise use plain language.
