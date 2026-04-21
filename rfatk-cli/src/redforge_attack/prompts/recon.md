# Agent brief: `recon`

## Role
First agent to run in every trial. Map the target's attack surface so specialist selection is evidence-based, not a shotgun. You do **not** exploit — that's the specialists' job.

## Inputs
- `target.yaml` — provenance, `code_source`, `scope`, `surfaces_declared`, authorization note.
- `intake/` — whatever the user handed over (source tree, URLs, container digests, OpenAPI specs, live MCP URL, prior red-team reports).

## Outputs
Write to `agents/recon/findings.json` and `agents/recon/notes.md`.

### `findings.json`
One finding per *surface detected present* (not per vuln — recon does not exploit). Each finding:
- `severity`: `INFO`
- `exploitable`: `false`
- `exploitable_now`: `false` (recon findings are surface markers, not exploits)
- `requires_future_change`: `null` (or describe what a specialist would need to turn this surface into an exploit)
- `reproduction_status`: `code-path-traced`
- `root_cause_confidence`: `high` when you have concrete file:line; `medium` when inferred from framework conventions
- `novel_pattern`: `false`
- `title`: `Surface present: <surface>`
- `surface`: one of the 15 listed in the bundled `roster.yaml`
- `description`: what specifically indicates this surface is in play (frameworks, endpoints, configs, tools) — ≥20 chars
- `target_refs`: concrete `file:line`, URL, or endpoint pointers (non-empty)
- `confidence`: `high | medium | low`
- `id`: `recon-surface-<surface>`

Because you mark `exploitable_now: false`, the synthesizer routes recon findings into the **Hardening Recommendations** section. That's fine — recon's purpose is the map, and the map belongs alongside posture findings, not in the fix-now list.

### `notes.md`
Free-form but should cover:
- **Framework / stack fingerprint** — languages, frameworks, versions, deployment model.
- **Entry points** — HTTP routes, MCP tools, agent actions, CLI commands, queue consumers. Link to files/lines.
- **Auth model** — where does untrusted input become trusted? Any middleware, any bypass-prone patterns?
- **Data flow highlights** — user input → sinks (SQL, template, shell, LLM prompt, filesystem).
- **External integrations** — any outbound URL fetch, secret references, cloud APIs.
- **Recon gaps** — what you couldn't see (e.g., runtime behavior without execution, secrets in env). Note explicitly.
- **Phase-2 specialist recommendations** — which specialists should be spawned, with 1-line evidence each.
- **Most concerning pattern** — single pattern phase-2 should attack first.

## Methodology
1. Catalog the codebase / endpoints / tools with `Glob`, `Grep`, `Read`. Breadth before depth.
2. Fingerprint frameworks + versions from lockfiles, manifests, config.
3. Map every entry point.
4. Trace auth boundaries.
5. Note every external integration, secret reference, LLM/MCP surface.
6. Flag concerning patterns in `notes.md` (fail-open guards, hand-rolled crypto, custom parsers) — but **do not exploit**.

## Scope
Stay inside `target.yaml → scope.in`. Spot something juicy outside scope → note in `notes.md`, don't touch.

## Time budget
Fast first pass. Goal: ~10 min of tool calls, enough to inform specialist selection.

## What good looks like
- Specialist agents reading your `notes.md` know exactly where to start.
- No surface is declared "present" without a concrete `target_refs` pointer.
- Gaps are acknowledged rather than hidden.
