# Default specialist agent roster

My default roster for REDFORGE trials. User delegated selection — I pick which of these to spawn per target based on recon and declared surfaces in `target.yaml`.

All independent agents are spawned in a single message so they run concurrently. `recon` runs first (its output informs which others are relevant); `synthesizer` runs last.

## Meta

| id | role |
|---|---|
| `recon` | Asset discovery, surface mapping, framework/stack fingerprinting, entry-point enumeration. Runs first. Output: surfaces-present list that gates the rest of the roster. |
| `synthesizer` | Aggregates per-agent `findings.json` → `report.md` raw bundle. Cross-agent attack-chain detection. Flags `novel_pattern: true` findings for auto-promotion. Runs last. |

## Web application

| id | surface | covers |
|---|---|---|
| `auth-session` | auth | authn, session mgmt, OAuth/OIDC flows, JWT forgery, MFA bypass, password reset, remember-me tokens, session fixation, cookie flags |
| `authz-idor` | idor | IDOR, horizontal/vertical privilege escalation, broken access control, mass assignment |
| `injection` | injection | SQL/NoSQL/LDAP/XPath/command/template injection, XXE, deserialization |
| `ssrf-network` | ssrf | SSRF, cloud-metadata abuse, DNS rebinding, network-pivot primitives |
| `xss-client` | xss | reflected/stored/DOM XSS, CSRF, clickjacking, prototype pollution, postMessage abuse |
| `file-handling` | file-handling | upload validation, path traversal, archive (zip-slip, tar), polyglot content, ImageMagick-class |
| `business-logic` | business-logic | race conditions (TOCTOU), workflow bypass, price/quota manipulation, rate-limit gaps, coupon stacking |
| `api-surface` | api | REST/GraphQL abuse, over-fetching, introspection, batching attacks, undocumented/debug endpoints |

## AI / agentic

| id | surface | covers |
|---|---|---|
| `prompt-injection` | prompt-injection | direct prompt injection, indirect (tool-returned content, RAG poisoning, file-contents attacks), jailbreaks, instruction-hierarchy abuse |
| `mcp-tool-abuse` | mcp-tool-abuse | over-scoped tool perms, tool-name confusion, schema-field abuse, result-trust chains, allowlist bypass |
| `agent-autonomy` | agent-autonomy | unauthorized action initiation, budget/loop exhaustion, goal-drift, scope expansion beyond declared, persistence across sessions |
| `llm-output-trust` | injection | LLM output consumed by downstream systems without sanitization — XSS/SSRF/command injection via LLM output, confused-deputy patterns |

## Infra / supply chain

| id | surface | covers |
|---|---|---|
| `secrets-hunt` | secrets | hardcoded secrets, env leakage, config exposure, client-side secret references, git history (if local), .well-known exposure |
| `ci-cd` | ci-cd | workflow permissions (`write-all`, `pull-request-target`), runner abuse, artifact tampering, poisoned caches, tag/branch protection gaps, PR-gated secrets |
| `container-infra` | container | Dockerfile (root user, ADD-from-URL, build-arg secrets), runtime capabilities, K8s RBAC, cloud IAM (over-permissive roles, AssumeRole chains) |
| `dependency-supply` | dependency | typosquatting/confusion, malicious transitive deps, unpinned versions, lock-file integrity, registry override attacks, install-scripts |

## Selection rules

- `recon` always runs. Output is consumed before the rest are spawned.
- For each `surface` `recon` detects as present, spawn at least one agent that covers it.
- `synthesizer` always runs last. It reads every `agents/<id>/findings.json` and produces `report.md`.
- If user declares a surface in `target.yaml` → `surfaces_declared` that `recon` didn't detect, spawn the agent anyway (user knows something I don't yet).
- Attack-chain potential: if two agents' findings could chain (e.g., SSRF + IDOR, or prompt-injection + mcp-tool-abuse), `synthesizer` must call it out explicitly.
