"""Target folder scaffolding.

Why this exists
---------------
Every trial needs the same skeleton (target.yaml, intake/, agents/, evidence/,
placeholder report.md). Hand-creating is error-prone, and the synthesizer
assumes exact paths. This module is the single source of truth for the intake
contract declared in `prompts/targets_schema.md` (packaged with the CLI).

Differences from the dev-workspace ancestor (`redforge-dev/tools/new_target.py`)
-------------------------------------------------------------------------------
1. The target-folder *parent* is now explicit (`targets_dir` parameter) instead
   of being derived from `__file__`. The CLI passes either the `--targets-dir`
   flag, a value from `redforge.toml`, or the default `./targets/` (cwd-relative).
2. The logic is exposed as a callable `create_target(...) -> Path` so it can be
   invoked from `cli.py`'s `init` subcommand without a subprocess.
3. No `if __name__ == "__main__"` block — the CLI entry point is `rfatk init`.
"""

from __future__ import annotations

import datetime
import pathlib
import re


def target_metadata(target_dir: pathlib.Path) -> dict[str, str]:
    """Shallow-parse `target_dir/target.yaml`, returning top-level scalar fields.

    Kept deliberately simple (regex on the scalar lines) to avoid a PyYAML
    dep. The nested structures (scope.in/out, authorization, surfaces_declared)
    are not returned here — use the full file via read_text() if needed.
    """
    yaml_path = pathlib.Path(target_dir) / "target.yaml"
    if not yaml_path.exists():
        raise FileNotFoundError(f"target.yaml not found under {target_dir}")
    meta: dict[str, str] = {}
    for line in yaml_path.read_text(encoding="utf-8").splitlines():
        if line.startswith(" "):
            continue
        m = re.match(r"(\w+):\s*(.*)", line)
        if m and m.group(2):
            meta[m.group(1)] = m.group(2).strip()
    return meta


def slugify(name: str) -> str:
    """Normalize a free-form target name to a filesystem-safe slug."""
    return re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-")


def _yaml_list(items: list[str], indent: int) -> str:
    pad = " " * indent
    if not items:
        return f"{pad}[]"
    return "\n".join(f"{pad}- {x}" for x in items)


def create_target(
    *,
    name: str,
    provenance: str,
    source: str,
    targets_dir: pathlib.Path,
    scope_in: list[str] | None = None,
    scope_out: list[str] | None = None,
    granted_by: str = "user",
    auth_note: str = "owner of assets under test",
    surfaces: list[str] | None = None,
    notes: str = "",
    target_type: str = "code",
) -> pathlib.Path:
    """Create a new target trial folder. Returns the absolute Path to the folder.

    Raises:
        ValueError: if `provenance` is not in {vibe, human, mixed, unknown}.
        FileExistsError: if the computed folder already exists (one folder =
            one trial; re-running against the same target creates a NEW
            timestamped folder).
    """
    if provenance not in {"vibe", "human", "mixed", "unknown"}:
        raise ValueError(
            f"provenance must be one of vibe|human|mixed|unknown, got {provenance!r}"
        )
    if target_type not in {"code", "host"}:
        raise ValueError(
            f"target_type must be one of code|host, got {target_type!r}"
        )

    slug = slugify(name)
    if not slug:
        raise ValueError(f"name {name!r} slugifies to empty string")

    now = datetime.datetime.now(datetime.timezone.utc)
    ts = now.strftime("%Y%m%dT%H%M%SZ")
    folder = targets_dir.resolve() / f"{slug}-{ts}"

    if folder.exists():
        raise FileExistsError(f"target folder already exists: {folder}")

    for sub in ("intake", "agents", "evidence"):
        (folder / sub).mkdir(parents=True)

    target_yaml = f"""target_id: {slug}
timestamp: {ts}
target_type: {target_type}
provenance: {provenance}
code_source: {source}
scope:
  in:
{_yaml_list(scope_in or [], 4)}
  out:
{_yaml_list(scope_out or [], 4)}
authorization:
  granted_by: {granted_by}
  granted_at: {now.isoformat()}
  note: {auth_note}
surfaces_declared:
{_yaml_list(surfaces or [], 2)}
notes: |
  {notes or "(none)"}
"""
    (folder / "target.yaml").write_text(target_yaml, encoding="utf-8")

    (folder / "report.md").write_text(
        f"# Trial report (raw bundle) — {slug}\n\n"
        "**Status:** pending — agents not yet run.\n\n"
        "Populated by the synthesizer after specialist agents complete "
        "(run `rfatk attack <this-folder>` or `rfatk report <this-folder>`).\n",
        encoding="utf-8",
    )

    return folder
