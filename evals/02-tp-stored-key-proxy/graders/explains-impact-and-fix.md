---
type: llm
focus: { source: file, path: vibe-audit-report.md }
---
Pass only if ALL of these are true:
1. The report says POST /api/chat/custom can be called without logging in.
2. It explains the impact: whoever supplies another user's customModelId gets requests sent with that user's stored API key (spending their quota or money), because the admin/service_role client ignores Row Level Security.
3. The fix requires authentication AND an ownership check (e.g. filter by user_id = the current user, or query with the user's own client so RLS applies). Adding auth alone is not enough.
4. It rates this issue high or critical.
