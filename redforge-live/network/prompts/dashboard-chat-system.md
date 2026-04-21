# redforge-live dashboard chat -- system prompt reference

This file exists so the scope of the dashboard chat session is documented and auditable. The **authoritative** context is `C:\redforge-live\CLAUDE.md` (loaded automatically by `claude` CLI when spawned at that working directory).

## Wire flow

```
Browser (chat form)
  └── POST /api/chat { message, session_id? }
       └── dashboard.ps1 Handle-Chat
            └── spawns: claude --dangerously-skip-permissions \
                             --session-id <guid> \
                             --output-format stream-json \
                             --verbose \
                             -p "<user message>"
                 (CWD = C:\redforge-live\)
            └── stdout stream-json lines → SSE "event: claude" frames
       └── browser parses each frame via fetch + ReadableStream
            └── assistant text blocks → assistant bubble (streaming)
            └── tool_use / tool_result blocks → tool bubbles
```

## Why spawn the CLI instead of using the API

- **No BYO Anthropic API key required.** Operator is Claude Max on Code; reusing those creds via the CLI is the supported path.
- **Session continuity.** `--session-id <guid>` lets the browser thread the same conversation across turns. Browser stores the id returned in the first `event: session` frame and echoes it on every subsequent `POST /api/chat`.
- **Same policy surface as triage.** `triage-invoke.ps1` already uses this exact spawn pattern -- one pattern to audit, one pattern to harden.
- **Local-only.** The CLI reads/writes files on the same machine. No target bytes leave the host except inside the CLI's own authenticated channel.

## Session boundaries (enforced by CLAUDE.md at CWD)

- Reads: anywhere under `C:\redforge-live\`.
- Writes: only `state/baseline.json`, `state/config.json`, `state/mode.txt`.
- Shell: read-only probes OK; destructive ops require operator confirmation.
- Network: denied. CLAUDE.md tells Claude to refuse external lookups; the operator can grep `logs/chat.jsonl` to audit.
- Excluded trees: `Documents`, `Downloads`, `Pictures`, `Videos`, `redforge-dev/` -- operator-policy off-limits.

## SSE event schema

| event | data shape | meaning |
|---|---|---|
| `session` | `{"session_id":"<guid>"}` | First frame. Browser stores for subsequent turns. |
| `claude` | one JSON line from `--output-format stream-json` | system / assistant / user / result event from the CLI |
| `stderr` | `{"text":"..."}` | Non-empty stderr flushed at end |
| `error`  | `{"error":"..."}` | Spawn or relay exception |
| `done`   | `{"exit_code":<int>,"session_id":"<guid>"}` | Session turn complete |

## Audit trail

- Every user turn and every session-done event is appended to `C:\redforge-live\logs\chat.jsonl`.
- Dashboard relay errors land in `C:\redforge-live\logs\dashboard.log`.
- Claude's own transcript lives in `~/.claude/projects/C--redforge-live/<session-id>.jsonl` (managed by Code).

## Known limitations

- **No message interruption.** If the operator closes the browser mid-turn, the spawned `claude` keeps running to completion. This is a v0.1 limitation; v0.2 tracks the child process and cancels on client disconnect.
- **No rate limiting.** Localhost-only, single-user; intentional.
- **No auth.** `127.0.0.1`-bound + single-user machine, no LAN exposure. A malicious local process could POST to `/api/chat` -- accepted risk for local-only.
- **Single chat per page load.** Browser holds one `state.sessionId`. Refresh = new session. If you want multi-turn continuity across refreshes, copy the session id from the first-frame log in `logs/chat.jsonl`.

## Promotion candidates

If this works well locally, next steps:
- Persist session id in `localStorage` so refresh preserves the thread.
- Add "new session" button that clears `state.sessionId`.
- Stream directly from watcher's queue events (SSE for alerts) instead of 5s polling.
- Optional voice input via Web Speech API (local, no cloud STT).
