---
type: regex
target: { source: file, path: vibe-audit-findings.json }
match: count:0
---
\{(?=[^{}]*"verdict"\s*:\s*"confirmed")(?=[^{}]*"severity"\s*:\s*"(critical|high|medium)")[^{}]*\}
