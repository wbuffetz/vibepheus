---
type: regex
target: { source: file, path: vibepheus-findings.json }
match: contains
---
\{(?=[^{}]*chat/custom/route\.ts)(?=[^{}]*"verdict"\s*:\s*"confirmed")(?=[^{}]*"severity"\s*:\s*"(critical|high)")[^{}]*\}
