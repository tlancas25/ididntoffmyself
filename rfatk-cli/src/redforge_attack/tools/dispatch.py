"""Tool dispatch — name -> sandbox impl, error wrapping.

Why this exists
---------------
The agent loop receives `ToolCall` objects from the provider and needs to
execute them. We have a few candidate impls (read_file, glob, grep, run_bash),
each returning structured data that must be turned into a single string for
the tool_result block the model reads next turn.

The other critical job: errors never crash the loop. A SandboxViolation or
FileNotFoundError becomes `ToolResult(is_error=True, content="...")` so the
model sees "that path was outside intake/" and can self-correct, instead of
the whole trial dying on one bad tool call.
"""

from __future__ import annotations

import json

from redforge_attack.schema import ToolCall, ToolResult
from redforge_attack.tools import sandbox


def dispatch(call: ToolCall, ctx: sandbox.ToolContext) -> ToolResult:
    """Route one ToolCall to the right sandbox impl. Never raises."""
    try:
        handler = _HANDLERS.get(call.name)
        if handler is None:
            return ToolResult(
                tool_call_id=call.id,
                content=(
                    f"unknown tool: {call.name!r}. "
                    f"Available: {sorted(_HANDLERS.keys())}."
                ),
                is_error=True,
            )
        result = handler(ctx, call.arguments)
        return ToolResult(tool_call_id=call.id, content=result, is_error=False)
    except sandbox.SandboxViolation as e:
        return ToolResult(tool_call_id=call.id, content=f"sandbox_violation: {e}", is_error=True)
    except FileNotFoundError as e:
        return ToolResult(tool_call_id=call.id, content=f"file_not_found: {e}", is_error=True)
    except TypeError as e:
        return ToolResult(tool_call_id=call.id, content=f"bad_arguments: {e}", is_error=True)
    except Exception as e:  # pragma: no cover — belt-and-suspenders
        return ToolResult(
            tool_call_id=call.id,
            content=f"internal_error: {type(e).__name__}: {e}",
            is_error=True,
        )


# -----------------------------------------------------------------------------
# Per-tool wrappers (ctx + args_dict -> string content)
# -----------------------------------------------------------------------------


def _h_read_file(ctx: sandbox.ToolContext, args: dict) -> str:
    path = _require_str(args, "path")
    return sandbox.read_file(ctx, path)


def _h_glob(ctx: sandbox.ToolContext, args: dict) -> str:
    pattern = _require_str(args, "pattern")
    results = sandbox.glob(ctx, pattern)
    if not results:
        return f"(no matches for {pattern!r})"
    header = f"{len(results)} match(es) for {pattern!r}:\n"
    return header + "\n".join(results)


def _h_grep(ctx: sandbox.ToolContext, args: dict) -> str:
    pattern = _require_str(args, "pattern")
    path_glob = args.get("path_glob", "**/*")
    case_insensitive = bool(args.get("case_insensitive", False))
    if not isinstance(path_glob, str):
        raise TypeError("path_glob must be a string")
    results = sandbox.grep(ctx, pattern, path_glob=path_glob, case_insensitive=case_insensitive)
    if not results:
        return f"(no matches for {pattern!r} in {path_glob!r})"
    header = f"{len(results)} match(es) for {pattern!r} in {path_glob!r}:\n"
    return header + "\n".join(results)


def _h_run_bash(ctx: sandbox.ToolContext, args: dict) -> str:
    cmd = _require_str(args, "cmd")
    return sandbox.run_bash(ctx, cmd)


def _h_submit_finding(ctx: sandbox.ToolContext, args: dict) -> str:
    if not isinstance(args, dict) or "finding" not in args:
        raise TypeError("missing required argument 'finding'")
    finding = args["finding"]
    if not isinstance(finding, dict):
        raise TypeError(f"finding must be an object, got {type(finding).__name__}")
    return sandbox.submit_finding(ctx, finding)


def _h_write_notes(ctx: sandbox.ToolContext, args: dict) -> str:
    content = _require_str(args, "content")
    return sandbox.write_notes(ctx, content)


# -----------------------------------------------------------------------------
# Host-scan tool handlers — only functional when ctx is a HostToolContext.
# They use duck-typed field access so the dispatch table stays flat. Non-host
# contexts return a clear error the model can self-correct from.
# -----------------------------------------------------------------------------


def _h_run_system_query(ctx, args: dict) -> str:
    # Lazy import to avoid circular dependency chains.
    from redforge_attack.tools import host_sandbox

    if not isinstance(ctx, host_sandbox.HostToolContext):
        raise sandbox.SandboxViolation(
            "run_system_query is only available in host-scan trials "
            "(target.yaml target_type=host)."
        )
    cmd = _require_str(args, "cmd")
    return host_sandbox.run_system_query(ctx, cmd)


def _h_capture_baseline(ctx, args: dict) -> str:
    from redforge_attack.tools import host_sandbox

    if not isinstance(ctx, host_sandbox.HostToolContext):
        raise sandbox.SandboxViolation(
            "capture_baseline is only available in host-scan trials "
            "(target.yaml target_type=host)."
        )
    return host_sandbox.capture_baseline(ctx)


def _require_str(args: dict, key: str) -> str:
    if not isinstance(args, dict):
        raise TypeError(f"arguments must be an object, got {type(args).__name__}")
    if key not in args:
        raise TypeError(f"missing required argument {key!r}")
    v = args[key]
    if not isinstance(v, str):
        raise TypeError(f"argument {key!r} must be a string, got {type(v).__name__}")
    return v


_HANDLERS: dict = {
    # Code-scan tools
    "read_file": _h_read_file,
    "glob": _h_glob,
    "grep": _h_grep,
    "run_bash": _h_run_bash,
    # Output tools (shared across trial types)
    "submit_finding": _h_submit_finding,
    "write_notes": _h_write_notes,
    # Host-scan tools
    "run_system_query": _h_run_system_query,
    "capture_baseline": _h_capture_baseline,
}


def parse_arguments(raw: str | dict) -> dict:
    """Providers sometimes hand us JSON strings for arguments (OpenAI), sometimes
    parsed dicts (Anthropic). Normalize to dict."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        if raw.strip() == "":
            return {}
        return json.loads(raw)
    raise TypeError(f"tool arguments must be str or dict, got {type(raw).__name__}")
