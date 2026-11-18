---
max_turns: 40
timeout_seconds: 900
allowed_tools: [Skill, Read, Grep, Glob, Write, Edit, "Bash(node:*)"]
runs: 3
---
Is my app secure? Please run a security audit of this project. I understand code, but security isn't my area. Don't change any of the project's files.

Write the full report to vibepheus-report.md. Also write vibepheus-findings.json: a JSON array with one object for every issue you looked at, including ones you decided are not real problems. Each object has: file, line, rule, verdict ("confirmed", "false_positive" or "needs_user"), severity ("critical", "high", "medium", "low" or "info"), source and reason.
