"""OpenAI-format JSONSchemas for agent tools.

Why this exists
---------------
The agent loop is provider-agnostic: it passes a canonical *OpenAI-function-
call-shape* list of tools to the provider, and each provider adapter maps
that shape to its native format on entry and back on exit. Defining these
schemas here (the lowest common denominator) keeps tool definitions in one
place and guarantees every provider sees the same parameter contract.

The four tools:
- `read_file` — read one file from the target's intake/ directory
- `glob`     — list matching paths under intake/
- `grep`     — search content across intake/ files
- `run_bash` — execute a bash command with cwd=target; disabled by default,
               enabled via `--allow-shell` (and even then only on disposable
               VMs; `--allow-shell` is explicitly dangerous).
"""

from __future__ import annotations

READ_FILE: dict = {
    "type": "function",
    "function": {
        "name": "read_file",
        "description": (
            "Read a UTF-8 text file from the target's intake/ directory. "
            "Paths are resolved inside intake/; absolute paths, paths containing "
            "'..' that escape the root, and symlinks pointing outside intake/ "
            "are rejected. Binary files and files over 2 MB are rejected."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path relative to intake/, e.g. 'src/app.py' or 'Dockerfile'.",
                },
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
}

GLOB: dict = {
    "type": "function",
    "function": {
        "name": "glob",
        "description": (
            "List paths under intake/ matching a glob pattern. "
            "Use '**/*.py' to recurse. Patterns starting with '/' or containing "
            "'..' are rejected. Results are capped at 500."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Glob pattern, e.g. '**/*.py', 'src/**/*.ts', 'Dockerfile*'.",
                },
            },
            "required": ["pattern"],
            "additionalProperties": False,
        },
    },
}

GREP: dict = {
    "type": "function",
    "function": {
        "name": "grep",
        "description": (
            "Search intake/ for a regex pattern. Returns up to 100 matching "
            "(file:line: match) lines per file, capped at 1000 matches total. "
            "Use path_glob to restrict search scope (e.g. '**/*.py')."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Python regex pattern. Case-sensitive by default.",
                },
                "path_glob": {
                    "type": "string",
                    "description": "Optional glob restricting which files to search (default '**/*').",
                },
                "case_insensitive": {
                    "type": "boolean",
                    "description": "If true, match case-insensitively. Default false.",
                },
            },
            "required": ["pattern"],
            "additionalProperties": False,
        },
    },
}

SUBMIT_FINDING: dict = {
    "type": "function",
    "function": {
        "name": "submit_finding",
        "description": (
            "Append one finding object to your findings.json file. Call this "
            "once per distinct root-cause bug. See the bundled targets_schema.md "
            "for the required shape (id, title, surface, severity, exploitable, "
            "exploitable_now, confidence, target_refs, description, etc.). "
            "Follow the §1 CRITICAL reserve, §2 dedupe, §3 NOVEL rules."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "finding": {
                    "type": "object",
                    "description": "One finding object per the schema.",
                    "additionalProperties": True,
                },
            },
            "required": ["finding"],
            "additionalProperties": False,
        },
    },
}

WRITE_NOTES: dict = {
    "type": "function",
    "function": {
        "name": "write_notes",
        "description": (
            "Append free-form text to your notes.md file. Use for hypotheses, "
            "dead-ends, cross-lens consequences of other agents' findings, "
            "methodology gaps, phase-2 specialist recommendations."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "Text to append (markdown formatting fine).",
                },
            },
            "required": ["content"],
            "additionalProperties": False,
        },
    },
}

RUN_BASH: dict = {
    "type": "function",
    "function": {
        "name": "run_bash",
        "description": (
            "Execute a bash command with cwd=target folder, timeout 30s, "
            "PATH restricted to /usr/bin:/bin, HOME=/tmp/redforge-home. "
            "DISABLED by default. Available ONLY when the trial is run with "
            "--allow-shell AND the operator has confirmed the target is on a "
            "disposable VM. Output is truncated to 64 KiB."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "cmd": {
                    "type": "string",
                    "description": "Bash command string. Runs with `bash -c '<cmd>'`.",
                },
            },
            "required": ["cmd"],
            "additionalProperties": False,
        },
    },
}


def default_tools(*, allow_shell: bool = False) -> list[dict]:
    """Return the list of tool schemas the agent loop exposes.

    By default, `run_bash` is NOT included — agents cannot even know the tool
    exists unless the operator explicitly opts in with --allow-shell.
    """
    tools = [READ_FILE, GLOB, GREP, SUBMIT_FINDING, WRITE_NOTES]
    if allow_shell:
        tools.append(RUN_BASH)
    return tools
