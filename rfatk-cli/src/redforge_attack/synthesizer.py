"""Aggregate specialist findings into report.md.

Why this exists
---------------
This is the synthesizer role described in `prompts/synthesizer.md`. It runs
last in every trial, turning per-agent findings.json files into the raw
bundle the user consumes when authoring the final report.

Partition rules (from trial-#1 review 2026-04-20):
- Main findings: explicit `exploitable_now: true` OR missing (backward-compat).
- Hardening Recommendations: explicit `exploitable_now: false`.
- Fix-These-First candidate list: CRITICAL + exploitable_now=true, capped at 12.
  Synthesizer AGENT applies full §1 criteria (unauth/single-session + direct
  impact) when curating the final cut in its notes.md.
- Suspected duplicate clusters: surface-scoped token-overlap (≥3 shared
  significant tokens). Advisory only — findings are NOT deduplicated
  automatically; the synthesizer agent picks a primary per cluster in notes.md.
- Cross-agent attack chains: via the `attack_chain` field on findings.

Differences from the dev-workspace ancestor (`redforge-dev/tools/synthesize.py`)
-------------------------------------------------------------------------------
1. Removed the `QUEUE` global and `draft_promotions()` function entirely.
   Auto-promotion to a detector ruleset queue is a dev-workspace-private
   concept; the CLI surfaces `novel_pattern: true` findings in `report.md`
   and leaves rule authoring to downstream tooling.
2. Exposed as `synthesize(target: Path) -> dict` callable for cli.py.
3. No `if __name__ == "__main__"` block.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

SEV = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
CONF = {"high": 0, "medium": 1, "low": 2}

STOPWORDS: set[str] = {
    "the", "a", "an", "of", "in", "on", "at", "to", "for", "with", "by", "from",
    "and", "or", "but", "not", "no", "is", "are", "was", "were", "be", "been",
    "this", "that", "these", "those", "it", "its", "any", "all", "via", "as",
    "can", "has", "had", "have", "when", "where", "what", "which", "who",
    "api", "route", "routes", "field", "fields", "missing", "without",
    "using", "user", "users", "found", "also", "more", "many", "much",
    "one", "two", "three", "some", "other", "same", "across", "per",
    "into", "onto", "upon", "then", "than", "only", "every", "each",
    "does", "doing", "done", "make", "makes", "made", "use", "uses", "used",
}


def _tokenize(s: str | None) -> list[str]:
    return [
        t for t in re.findall(r"[a-z0-9][a-z0-9_-]{2,}", (s or "").lower())
        if t not in STOPWORDS
    ]


def is_exploitable_now(f: dict) -> bool:
    """Prefer exploitable_now; fall back to exploitable for backward-compat."""
    if "exploitable_now" in f:
        return bool(f["exploitable_now"])
    return bool(f.get("exploitable", False))


def is_hardening(f: dict) -> bool:
    """Strict opt-in: explicit exploitable_now=false routes to Hardening.

    Backward-compat: findings without the field stay in main.
    """
    return f.get("exploitable_now") is False


def load_findings(target: pathlib.Path) -> list[dict]:
    findings: list[dict] = []
    agents_root = target / "agents"
    if not agents_root.exists():
        return findings
    for agent_dir in sorted(agents_root.iterdir()):
        if not agent_dir.is_dir():
            continue
        fp = agent_dir / "findings.json"
        if not fp.exists():
            continue
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            print(f"skipping bad JSON in {fp}: {e}", file=sys.stderr)
            continue
        if not isinstance(data, list):
            continue
        for f in data:
            if isinstance(f, dict):
                f["_agent_id"] = agent_dir.name
                findings.append(f)
    return findings


def target_meta(target: pathlib.Path) -> dict[str, str]:
    """Shallow YAML parse — top-level scalar fields only.

    Avoids a PyYAML dependency for a simple read. target.yaml is append-only
    scalars for the fields we care about.
    """
    meta: dict[str, str] = {}
    tfile = target / "target.yaml"
    if not tfile.exists():
        return meta
    for line in tfile.read_text(encoding="utf-8").splitlines():
        if line.startswith(" "):
            continue
        m = re.match(r"(\w+):\s*(.*)", line)
        if m and m.group(2):
            meta[m.group(1)] = m.group(2).strip()
    return meta


def detect_chains(findings: list[dict]) -> list[tuple[dict, list[dict]]]:
    by_id = {f.get("id"): f for f in findings if f.get("id")}
    chains: list[tuple[dict, list[dict]]] = []
    for f in findings:
        refs = f.get("attack_chain") or []
        links = [by_id[r] for r in refs if r in by_id]
        if not links:
            continue
        agents = {f["_agent_id"]} | {l["_agent_id"] for l in links}
        if len(agents) > 1:
            chains.append((f, links))
    return chains


def detect_duplicate_clusters(
    findings: list[dict], min_token_overlap: int = 3
) -> list[dict]:
    """Surface-scoped token-overlap clustering. Advisory, not destructive."""
    by_surface: dict[str, list[dict]] = {}
    for f in findings:
        s = f.get("surface", "?")
        by_surface.setdefault(s, []).append(f)

    clusters: list[dict] = []
    for surf, group in by_surface.items():
        token_sets = [
            (f, set(_tokenize(f.get("title", ""))) | set(_tokenize(f.get("description", ""))))
            for f in group
        ]
        assigned = [False] * len(token_sets)
        for i in range(len(token_sets)):
            if assigned[i]:
                continue
            fi, ti = token_sets[i]
            cluster_members = [fi]
            cluster_overlap = set(ti)
            for j in range(i + 1, len(token_sets)):
                if assigned[j]:
                    continue
                fj, tj = token_sets[j]
                overlap = ti & tj
                if len(overlap) >= min_token_overlap:
                    cluster_members.append(fj)
                    cluster_overlap &= tj
                    assigned[j] = True
            if len(cluster_members) > 1:
                clusters.append({
                    "surface": surf,
                    "members": cluster_members,
                    "shared_tokens": sorted(cluster_overlap)[:8],
                })
                assigned[i] = True
    return clusters


def fix_these_first_candidates(findings: list[dict], limit: int = 12) -> list[dict]:
    """CRITICAL + exploitable_now=true. Synthesizer agent applies the full
    three-criterion §1 rule (unauth/single-session + direct impact) when
    curating the final cut in notes.md.
    """
    cands = [
        f for f in findings
        if f.get("severity") == "CRITICAL" and is_exploitable_now(f)
    ]
    cands.sort(key=lambda f: (CONF.get(f.get("confidence", "low"), 3),))
    return cands[:limit]


def _fmt_finding(f: dict) -> list[str]:
    out: list[str] = []
    sev = f.get("severity", "INFO")
    tags: list[str] = []
    if is_exploitable_now(f):
        tags.append("EXPLOITABLE-NOW")
    elif f.get("exploitable"):
        tags.append("EXPLOITABLE")
    if f.get("novel_pattern"):
        tags.append("NOVEL")
    if f.get("hardening_plan"):
        tags.append("HARDENING")
    rs = f.get("reproduction_status")
    if rs and rs != "code-path-traced":
        tags.append(rs.upper())
    tag_str = (" " + " ".join(tags)) if tags else ""
    out.append(f"### [{sev}]{tag_str} {f.get('title', '(no title)')}")

    meta_bits = [
        f"`{f.get('id', 'n/a')}`",
        f"agent `{f['_agent_id']}`",
        f"surface `{f.get('surface', '?')}`",
        f"conf `{f.get('confidence', '?')}`",
    ]
    if f.get("root_cause_confidence"):
        meta_bits.append(f"root-cause `{f['root_cause_confidence']}`")
    out.append("- " + " · ".join(meta_bits))

    refs = f.get("target_refs") or []
    if refs:
        out.append("- refs: " + ", ".join(f"`{r}`" for r in refs))

    rfc = f.get("requires_future_change")
    if rfc:
        out.append(f"- requires_future_change: {rfc}")

    if f.get("description"):
        out.append("")
        out.append(f["description"])
    if f.get("impact"):
        out.append("")
        out.append(f"**Impact:** {f['impact']}")
    if f.get("reproduction"):
        out.append("")
        out.append("**Reproduction:**")
        out.append("```")
        out.append(f["reproduction"])
        out.append("```")
    ev = f.get("evidence_paths") or []
    if ev:
        out.append("")
        out.append("**Evidence:** " + ", ".join(f"`{e}`" for e in ev))
    if f.get("remediation"):
        out.append("")
        out.append(f"**Remediation:** {f['remediation']}")
    cwes = f.get("cwe") or []
    if cwes:
        out.append("")
        out.append("**CWE:** " + ", ".join(cwes))
    return out


EFFORT_ORDER = {"minutes": 0, "hours": 1, "days": 2, "weeks": 3}


def hardening_plan_section(main: list[dict], hardening: list[dict]) -> list[str]:
    """Build a 'Hardening Plan (prioritized)' block from findings that carry a
    `hardening_plan` subobject (added in M7+ for host-scan trials)."""
    all_findings = main + hardening
    plans: list[tuple[dict, dict]] = []  # (finding, hardening_plan)
    for f in all_findings:
        hp = f.get("hardening_plan")
        if isinstance(hp, dict) and hp:
            plans.append((f, hp))
    if not plans:
        return []

    def sort_key(entry: tuple[dict, dict]) -> tuple:
        f, hp = entry
        effort = hp.get("estimated_effort", "days")
        return (
            EFFORT_ORDER.get(effort, 99),
            SEV.get(f.get("severity", "INFO"), 5),
            0 if is_exploitable_now(f) else 1,
        )

    plans.sort(key=sort_key)

    out: list[str] = []
    out.append("")
    out.append("## Hardening Plan (prioritized)")
    out.append("")
    out.append(
        "_Grouped by estimated effort; within each bucket sorted by severity "
        "and exploitable-now. `immediate` columns are copy-paste commands._"
    )

    current_bucket = None
    for f, hp in plans:
        bucket = hp.get("estimated_effort", "unknown")
        if bucket != current_bucket:
            out.append("")
            out.append(f"### Effort: {bucket}")
            current_bucket = bucket

        sev = f.get("severity", "INFO")
        title = f.get("title", "(no title)")
        fid = f.get("id", "n/a")
        immediate = hp.get("immediate", "(no immediate command provided)")
        out.append("")
        out.append(f"- **[{sev}]** {title} — `{fid}`")
        if immediate and immediate != "N/A — suppressed as verified noise.":
            out.append(f"    - Immediate: `{immediate}`")
        if hp.get("configuration"):
            out.append(f"    - Durable: {hp['configuration']}")
        if hp.get("monitoring"):
            out.append(f"    - Monitor: {hp['monitoring']}")
        if hp.get("compensating_controls"):
            out.append(f"    - Compensating: {hp['compensating_controls']}")
    return out


def write_report(
    target: pathlib.Path,
    meta: dict[str, str],
    main: list[dict],
    hardening: list[dict],
    chains: list[tuple[dict, list[dict]]],
    ftf: list[dict],
    clusters: list[dict],
) -> None:
    out: list[str] = []
    out.append(f"# Trial report (raw bundle) — {meta.get('target_id', target.name)}")
    out.append("")
    out.append(f"**Provenance:** {meta.get('provenance', '?')}  ")
    out.append(f"**Folder:** `{target.name}`  ")
    out.append(f"**Main findings:** {len(main)}  ")
    out.append(f"**Hardening recommendations:** {len(hardening)}  ")
    out.append(f"**Cross-agent chains:** {len(chains)}  ")
    out.append(f"**Suspected duplicate clusters:** {len(clusters)} (synthesizer to resolve)  ")
    out.append(f"**Fix-These-First candidates:** {len(ftf)}")
    out.append("")

    # Hardening Plan (prioritized) section — placed BEFORE Fix These First so
    # the full remediation story is right at the top. Empty for code-scan
    # trials (no hardening_plan field), populated for host-scan trials.
    out.extend(hardening_plan_section(main, hardening))
    out.append("")

    out.append("## Fix These First (candidates)")
    out.append("")
    out.append(
        "_Candidate list — CRITICAL + `exploitable_now: true`. Synthesizer "
        "agent curates the final cut in `agents/synthesizer/notes.md` applying "
        "all three §1 criteria (exploitable today, unauth/single-session, "
        "direct impact)._"
    )
    out.append("")
    if not ftf:
        out.append("_(no CRITICAL + exploitable_now=true findings in this trial)_")
    else:
        for f in ftf:
            title = f.get("title", "(no title)")
            fid = f.get("id", "n/a")
            agent = f["_agent_id"]
            refs = f.get("target_refs") or []
            ref_hint = refs[0] if refs else "(no ref)"
            out.append(f"- **[CRITICAL]** {title} — `{fid}` — agent `{agent}` — `{ref_hint}`")
    out.append("")

    agents = sorted({f["_agent_id"] for f in main + hardening})
    out.append("## Agents run")
    for aid in agents:
        n_main = sum(1 for f in main if f["_agent_id"] == aid)
        n_hard = sum(1 for f in hardening if f["_agent_id"] == aid)
        c = sum(1 for f in main if f["_agent_id"] == aid and f.get("severity") == "CRITICAL")
        h = sum(1 for f in main if f["_agent_id"] == aid and f.get("severity") == "HIGH")
        out.append(f"- `{aid}` — {n_main} main (C:{c} H:{h}) + {n_hard} hardening")
    out.append("")

    out.append("## Findings (main)")
    out.append("")
    out.append("_Sorted severity → exploitable-now → confidence._")
    for f in main:
        out.append("")
        out.extend(_fmt_finding(f))

    out.append("")
    out.append("## Hardening Recommendations")
    out.append("")
    out.append(
        "_Findings where no current attacker action produces impact. Remediation "
        "is a posture improvement. Still important — just not in the fix-now list._"
    )
    if not hardening:
        out.append("")
        out.append("_(none opted in via `exploitable_now: false`.)_")
    else:
        for f in hardening:
            out.append("")
            out.extend(_fmt_finding(f))

    if chains:
        out.append("")
        out.append("## Cross-agent attack chains")
        for root, links in chains:
            path = " → ".join(
                [f"`{root.get('id')}` ({root['_agent_id']})"]
                + [f"`{l.get('id')}` ({l['_agent_id']})" for l in links]
            )
            out.append(f"- {path}")

    if clusters:
        out.append("")
        out.append("## Suspected duplicate clusters (synthesizer to resolve)")
        out.append("")
        out.append(
            "_Surface-scoped token-overlap clustering (≥3 shared significant tokens). "
            "Advisory only — findings NOT deduplicated automatically. Synthesizer agent "
            "picks one primary per cluster and folds others into `notes.md` as "
            "\"consequences from other lens.\"_"
        )
        for i, c in enumerate(clusters, 1):
            out.append("")
            out.append(
                f"### Cluster {i} · surface `{c['surface']}` · shared: "
                + ", ".join(f"`{t}`" for t in c['shared_tokens'])
            )
            for f in c["members"]:
                out.append(
                    f"- `{f.get('id', 'n/a')}` — agent `{f['_agent_id']}` — "
                    f"severity `{f.get('severity', '?')}` — \"{f.get('title', '(no title)')}\""
                )

    (target / "report.md").write_text("\n".join(out) + "\n", encoding="utf-8")


def synthesize(target: pathlib.Path) -> dict:
    """Run the full synthesis pipeline against a target folder.

    Returns a stats dict: {
        total, main, hardening, chains, clusters, ftf_candidates
    }
    Raises FileNotFoundError if `target_dir/target.yaml` is missing.
    """
    target = pathlib.Path(target).resolve()
    if not (target / "target.yaml").exists():
        raise FileNotFoundError(f"not a target folder (missing target.yaml): {target}")

    meta = target_meta(target)
    all_findings = load_findings(target)

    main_findings = [f for f in all_findings if not is_hardening(f)]
    hardening = [f for f in all_findings if is_hardening(f)]

    main_findings.sort(key=lambda f: (
        SEV.get(f.get("severity", "INFO"), 5),
        0 if is_exploitable_now(f) else 1,
        CONF.get(f.get("confidence", "low"), 3),
    ))
    hardening.sort(key=lambda f: (
        SEV.get(f.get("severity", "INFO"), 5),
        CONF.get(f.get("confidence", "low"), 3),
    ))

    chains = detect_chains(all_findings)
    clusters = detect_duplicate_clusters(all_findings)
    ftf = fix_these_first_candidates(main_findings)

    write_report(target, meta, main_findings, hardening, chains, ftf, clusters)

    return {
        "total": len(all_findings),
        "main": len(main_findings),
        "hardening": len(hardening),
        "chains": len(chains),
        "clusters": len(clusters),
        "ftf_candidates": len(ftf),
    }
