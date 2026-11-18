# Extra tools: Semgrep, Gitleaks, osv-scanner

vibepheus works without these. When they are installed, the scanner runs them automatically and merges their results.

| Tool | Adds | Useful when the project has |
|---|---|---|
| **Semgrep** | SQL, command and code injection, open redirects, unverified JWTs, insecure cookies, weak random tokens | server code: API routes, server actions, an Express/Node backend, database queries |
| **Gitleaks** | Hundreds of secret formats, in the files and in every git commit | any code, especially a git repo |
| **osv-scanner** | Every known vulnerability in the dependencies, not just the built-in Next.js/React list | a `package.json` with a lockfile (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`) |

## When to ask

Ask only if at least one missing tool is useful for this project (table above). Skip the question, and just mention `/vibepheus:setup` in one line, when none would help: for example a single static HTML file, or a project with no dependencies, no server code and no git history.

## The question

Name only the missing tools that would help, say what each adds in a few words, and give the size and time. Example:

> Two optional tools aren't installed: **Gitleaks** (finds hundreds more kinds of leaked keys, including in old commits) and **osv-scanner** (checks every package you use against known vulnerabilities). Installing takes 1 to 2 minutes and about 100 MB. Install them now, or skip for now? You can always install later with `/vibepheus:setup`.

Answers: **Install them** / **Skip for now**. Match the wording to the user's level (Step 0 of `SKILL.md`).

Approximate sizes: Semgrep about 400 MB (it bundles Python), Gitleaks about 20 MB, osv-scanner about 40 MB.

## How to install

Install only the missing tools. Tell the user the command before running it: their permission setup may ask them to approve it.

**macOS with Homebrew** (check with `brew --version`):
```bash
brew install semgrep gitleaks osv-scanner
```
(list only the missing ones)

**macOS without Homebrew, Linux, or Windows**: do not install a package manager for them. Give the official instructions instead, and let them install it themselves:
- Semgrep: `python3 -m pip install semgrep` or `pipx install semgrep` (see https://semgrep.dev/docs/getting-started/)
- Gitleaks: https://github.com/gitleaks/gitleaks#installing (Homebrew, Docker, or a release download; on Windows `winget install gitleaks`)
- osv-scanner: https://google.github.io/osv-scanner/installation/ (release download, or `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest`)

Only use these official sources. Never download install scripts from anywhere else, and never pipe a download into a shell (`curl ... | sh`).

## After installing

Check each tool runs (`semgrep --version`, `gitleaks version`, `osv-scanner --version`), then re-run the scanner. In `externalTools`, each should now say `ran (...)`.

## If something fails

- Install fails or is denied: say which tool and why in one sentence, continue the audit with what works, and do not retry in a loop.
- A tool is installed but `externalTools` says `failed: ...`: report the message to the user and continue. The built-in checks still ran.
- Privacy: vibepheus runs Semgrep with its own local rules (`rules/semgrep.yml`) and `--metrics=off`, so it sends nothing. Gitleaks and osv-scanner's file scan run locally too. osv-scanner looks up the package names and versions in Google's OSV vulnerability database, never the code itself; mention that if the user asked for nothing to leave their machine.
