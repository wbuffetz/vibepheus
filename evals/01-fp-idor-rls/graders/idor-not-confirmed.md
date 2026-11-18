---
type: regex
target: { source: file, path: vibe-audit-findings.json }
match: count:0
---
\{(?=[^{}]*notes/\[id\]/route\.ts)(?=[^{}]*"verdict"\s*:\s*"confirmed")(?=[^{}]*"severity"\s*:\s*"(critical|high|medium)")[^{}]*\}
