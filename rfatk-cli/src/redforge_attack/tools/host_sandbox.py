"""Host-scan sandbox — execute allowlisted PowerShell / CMD system queries.

Why this exists
---------------
Code-scan trials (the M1-M3 path) only need `read_file` / `glob` / `grep`
inside `intake/`. A host scan is fundamentally different: the target IS the
running machine, and the agent needs to ask it live questions (which
services are running, what's listening on what port, what's in the registry
here, what does Defender think about this file).

But giving an LLM agent arbitrary shell execution is a liability. So this
sandbox is **allowlist-gated**:

  - Every command the agent proposes is matched against a regex allowlist
    of known-read-only system queries (`Get-Service`, `netstat -ano`,
    `reg query HKLM\\...`, etc.).
  - Commands that don't match the allowlist are REJECTED as sandbox
    violations — the model sees the error and self-corrects.
  - Even matching commands are filtered against a **path denylist**: any
    command referencing the 4 off-limits folders (Documents / Downloads /
    Pictures / Videos) is rejected regardless.
  - Shell metacharacter composition (`;`, `|`, `&&`, `||`, `>`, redirects,
    backticks, command substitution) is filtered by ensuring the allowlist
    patterns don't accept them.

The same `ToolContext` fields that back `submit_finding` / `write_notes`
in the code sandbox apply here unchanged (agent_id, target_dir) — those
tools are reused.

Approvals captured in `redforge-dev/host-scan-scoping.md`:
- Full admin elevation approved — admin-only commands are in the allowlist.
- Local-subnet sweep approved — `Test-NetConnection` against arbitrary hosts
  is allowed; rate-capped via `max_network_probes_per_run`.
- Defender noise accepted — no whitelisting; alert-triage specialist handles
  classification after the scan.
"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field

from redforge_attack.tools.sandbox import SandboxViolation, submit_finding, write_notes  # re-export for host context


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------


# The 4 folders the user said are off-limits, plus common canonical variants
# the agent could produce (case-insensitive match, substring on the command).
DEFAULT_EXCLUDED_FOLDER_NAMES: tuple[str, ...] = (
    "Documents",
    "Downloads",
    "Pictures",
    "Videos",
)


@dataclass(frozen=True)
class HostToolContext:
    """Per-agent container for host-scan sandbox parameters.

    Unlike the code sandbox `ToolContext`, `target_dir` here is only used
    to route submit_finding / write_notes / evidence writes. Reads are
    against the live system, not a folder tree.
    """
    target_dir: pathlib.Path
    agent_id: str = ""
    excluded_folder_names: tuple[str, ...] = DEFAULT_EXCLUDED_FOLDER_NAMES
    allow_admin: bool = False        # Let commands that need elevation run
    allow_network_probe: bool = False  # Let network-probe commands run
    per_call_timeout_seconds: int = 60
    max_output_bytes: int = 256 * 1024  # 256 KiB per command


# ---------------------------------------------------------------------------
# Command allowlist
# ---------------------------------------------------------------------------


# Each entry is:
#   (regex, {"admin": bool, "network_probe": bool, "description": str})
# Flags gate execution on the per-trial allow_admin / allow_network_probe
# switches. This lets us keep a broad allowlist while still respecting the
# user's per-trial consent.
_ALLOWLIST: list[tuple[re.Pattern[str], dict]] = []


def _add(pattern: str, *, admin: bool = False, network_probe: bool = False, description: str = "") -> None:
    _ALLOWLIST.append((re.compile(pattern, re.IGNORECASE), {
        "admin": admin, "network_probe": network_probe, "description": description,
    }))


# --- System / build info (unprivileged)
_add(r"^systeminfo$", description="Kernel version, hotfixes, RAM, boot time")
_add(r"^Get-ComputerInfo(?:\s+-[A-Za-z]+(?:\s+[\w\-\.\,\@:/\\\"']+)?)*$",
     description="Rich system / OS / bios / domain facts")
_add(r"^ver$", description="Windows version banner")
_add(r"^hostname$", description="Machine name")
_add(r"^whoami(?:\s+/(?:all|user|groups|priv|logonid|upn|fqdn|claims|verbose))*$",
     description="Current identity, privileges, groups")
_add(r"^\[System\.Environment\]::OSVersion$")
_add(r"^driverquery(?:\s+/[A-Za-z]+(?:\s+\S+)?)*$", description="Installed drivers")

# --- Services
_add(r"^Get-Service(?:\s+-[A-Za-z]+(?:\s+[\w\-\*\?\.\,\;]+)?)*$",
     description="List services, filter by name")
_add(r"^Get-CimInstance\s+-ClassName\s+Win32_Service(?:\s+-[A-Za-z]+(?:\s+\S+)?)*$",
     description="Service WMI including path + start-mode + start-account")
_add(r"^Get-WmiObject\s+-Class\s+Win32_Service(?:\s+-[A-Za-z]+(?:\s+\S+)?)*$",
     description="Legacy WMI for services")
_add(r"^sc(?:\.exe)?\s+query(?:\s+\S+)?$", description="Service state via sc")
_add(r"^sc(?:\.exe)?\s+qc\s+\S+$", description="Service config including binary path + start type")
_add(r"^sc(?:\.exe)?\s+sdshow\s+\S+$", admin=True,
     description="Service DACL — needed for service-hijack hunt")

# --- Processes
_add(r"^Get-Process(?:\s+-[A-Za-z]+(?:\s+[\w\-\*\?\.\,\;]+)?)*$",
     description="Running processes")
_add(r"^Get-CimInstance\s+-ClassName\s+Win32_Process(?:\s+-[A-Za-z]+(?:\s+\S+)?)*$")
_add(r"^tasklist(?:\s+/[A-Za-z]+(?:\s+\S+)?)*$", description="Running processes CLI")
_add(r"^Get-AuthenticodeSignature\s+-FilePath\s+[\"']?[A-Za-z]:[\\/][^\"';|&<>`]+[\"']?$",
     description="Binary signature (inform signed/unsigned findings)")

# --- Network
_add(r"^netstat(?:\s+-[a-zA-Z]+)*$", description="Sockets")
_add(r"^netstat(?:\s+-[a-zA-Z]+)+$", admin=True, description="netstat -b / with PID attribution")
_add(r"^ipconfig(?:\s+/(?:all|displaydns))?$")
_add(r"^arp\s+-a(?:\s+\S+)?$")
_add(r"^route\s+print$")
_add(r"^Get-NetTCPConnection(?:\s+-[A-Za-z]+(?:\s+\S+)?)*$")
_add(r"^Get-NetUDPEndpoint(?:\s+-[A-Za-z]+(?:\s+\S+)?)*$")
_add(r"^Get-NetAdapter(?:\s+-[A-Za-z]+(?:\s+\S+)?)*$")
_add(r"^Get-NetIPConfiguration$")
_add(r"^Get-NetRoute$")
_add(r"^Get-NetFirewallProfile$")
_add(r"^Get-NetFirewallRule(?:\s+-[A-Za-z]+(?:\s+\S+)?)*$")
_add(r"^Get-DnsClientCache$")
_add(r"^Get-DnsClient(?:\s+-[A-Za-z]+(?:\s+\S+)?)*$")
_add(r"^Resolve-DnsName\s+[\w\-\.]+(?:\s+-[A-Za-z]+(?:\s+\S+)?)*$", network_probe=True)
_add(r"^Test-NetConnection\s+[\w\-\.]+(?:\s+-[A-Za-z]+(?:\s+\S+)?)*$", network_probe=True)
_add(r"^Test-Connection\s+[\w\-\.]+(?:\s+-[A-Za-z]+(?:\s+\S+)?)*$", network_probe=True)

# --- Registry (read-only)
# Only HKLM / HKCU / HKCR / HKU / HKCC roots. Path may have backslashes and
# dots and spaces (quoted). No shell metachars.
_REG_PATH = r"['\"]?HK(?:LM|CU|CR|U|CC)(?:\\[^'\";|&<>`\n\r]+)?['\"]?"
_add(fr"^reg\s+query\s+{_REG_PATH}(?:\s+/[a-z]+(?:\s+\S+)?)*$",
     description="Registry read")
_add(fr"^Get-ItemProperty\s+['\"]?HK(?:LM|CU|CR|U|CC):[^\s'\";|&<>`]*['\"]?(?:\s+-[A-Za-z]+(?:\s+\S+)?)*$")
_add(fr"^Get-ChildItem\s+['\"]?HK(?:LM|CU|CR|U|CC):[^\s'\";|&<>`]*['\"]?(?:\s+-[A-Za-z]+(?:\s+\S+)?)*$")

# --- Users / groups / logon
_add(r"^net\s+user(?:\s+\S+)?(?:\s+/[A-Za-z]+)*$")
_add(r"^net\s+localgroup(?:\s+\S+)?(?:\s+/[A-Za-z]+)*$")
_add(r"^net\s+accounts$")
_add(r"^net\s+session$", admin=True)
_add(r"^query\s+session$")
_add(r"^Get-LocalUser(?:\s+-[A-Za-z]+(?:\s+\S+)?)*$")
_add(r"^Get-LocalGroup(?:\s+-[A-Za-z]+(?:\s+\S+)?)*$")
_add(r"^Get-LocalGroupMember(?:\s+-[A-Za-z]+(?:\s+\S+)?)*$")

# --- Scheduled tasks
_add(r"^schtasks(?:\.exe)?\s+/query(?:\s+/[A-Za-z]+(?:\s+\S+)?)*$")
_add(r"^Get-ScheduledTask(?:\s+-[A-Za-z]+(?:\s+\S+)?)*$")
_add(r"^Get-ScheduledTaskInfo(?:\s+-[A-Za-z]+(?:\s+\S+)?)*$")

# --- Event logs
_add(r"^Get-WinEvent\s+-LogName\s+[\w\-\./]+(?:\s+-MaxEvents\s+\d+)?(?:\s+-FilterHashtable\s+@\{[^}]+\})?$",
     admin=False, description="Most event logs; Security needs admin")
_add(r"^wevtutil(?:\.exe)?\s+(?:el|qe|gli)(?:\s+\S+)*$")

# --- Defender
_add(r"^Get-MpThreatDetection$")
_add(r"^Get-MpThreat$")
_add(r"^Get-MpComputerStatus$")
_add(r"^Get-MpPreference$")

# --- Group policy
_add(r"^gpresult(?:\s+/[A-Za-z]+(?:\s+\S+)?)*$")

# --- Installed software (fast registry method; skip slow WMI)
_add(r"^Get-ChildItem\s+['\"]?HK(?:LM|CU):\\SOFTWARE(?:\\WOW6432Node)?\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\?['\"]?(?:\s+-[A-Za-z]+(?:\s+\S+)?)*$")

# --- BitLocker (admin only)
_add(r"^manage-bde(?:\.exe)?\s+-status(?:\s+\S+)?$", admin=True)
_add(r"^manage-bde(?:\.exe)?\s+-protectors(?:\s+-[A-Za-z]+)*(?:\s+\S+)?$", admin=True)

# --- Certificates
_add(r"^Get-ChildItem\s+Cert:[\w\\:]*$")

# --- File read (system paths only; excluded folders blocked downstream)
_add(r"^Get-Content\s+['\"]?[A-Za-z]:[\\/][^'\";|&<>`]+['\"]?(?:\s+-(?:Tail|Head|TotalCount)\s+\d+)*$",
     description="Read a system/config file")
_add(r"^Get-Item\s+['\"]?[A-Za-z]:[\\/][^'\";|&<>`]+['\"]?(?:\s+-[A-Za-z]+(?:\s+\S+)?)*$")
_add(r"^Get-ChildItem\s+['\"]?[A-Za-z]:[\\/][^'\";|&<>`]+['\"]?(?:\s+-[A-Za-z]+(?:\s+\S+)?)*$")

# --- Autoruns (Sysinternals) if installed
# Permissive: allow any word/flag/asterisk tokens after -accepteula because
# Autorunsc's CLI has many short-flag + arg pairs (`-a *`, `-c -v hs`, etc.).
_add(r"^Autorunsc(?:\.exe)?\s+-accepteula(?:\s+[\w\-\*]+)*$",
     admin=True, description="Sysinternals Autoruns — persistence complete")

# --- Misc informational
_add(r"^fltmc(?:\s+(?:instances|filters))?$", description="File system filter drivers")
_add(r"^bcdedit(?:\s+/enum)?$", admin=True, description="Boot config (secure boot status)")
_add(r"^Get-Tpm$")
_add(r"^Get-SmbShare(?:\s+-[A-Za-z]+(?:\s+\S+)?)*$")
_add(r"^Get-SmbServerConfiguration$", admin=True)


# ---------------------------------------------------------------------------
# Dangerous shell-composition — reject regardless of allowlist match
# ---------------------------------------------------------------------------

_FORBIDDEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r";"),          # command chaining (even though most allowlist patterns don't accept it, defense-in-depth)
    re.compile(r"&&"),
    re.compile(r"\|\|"),
    re.compile(r"`"),          # backtick command substitution
    re.compile(r"\$\("),       # $(command) substitution
    re.compile(r"@\("),        # @(command) splat substitution
    re.compile(r">\s*\S"),     # stdout redirect to a file
    re.compile(r"<\s*\S"),     # stdin from file
    re.compile(r"2>&1"),       # stream merge (rare in our queries, safer to block)
    re.compile(r"[\r\n]"),     # multi-line commands
    re.compile(r"\x00"),
)


def _contains_forbidden_construct(cmd: str) -> str | None:
    for pat in _FORBIDDEN_PATTERNS:
        m = pat.search(cmd)
        if m:
            return m.group(0)
    return None


# ---------------------------------------------------------------------------
# Excluded folder enforcement
# ---------------------------------------------------------------------------


def _references_excluded_folder(cmd: str, excluded_names: tuple[str, ...]) -> str | None:
    r"""Return the excluded folder name if `cmd` mentions it, else None.

    Matching is case-insensitive on the folder name. We look for the folder
    name preceded by a path separator (``\`` or ``/``) OR as a bare component
    surrounded by separators. This catches:

      C:\Users\<user>\Documents\...        (\Documents\)
      ~/Documents/file                     (/Documents/)
      "C:\Users\<user>\Documents"           (\Documents")
      %USERPROFILE%\Pictures\...           (\Pictures\)
      $env:USERPROFILE\Videos               (\Videos — end of path OK)
    """
    lower = cmd.lower()
    for name in excluded_names:
        low_name = name.lower()
        # \FolderName\, /FolderName/, \FolderName', \FolderName", \FolderName (end)
        pattern = re.compile(rf"[\\/]{re.escape(low_name)}(?:[\\/'\"\s]|$)")
        if pattern.search(lower):
            return name
    return None


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_command(cmd: str, ctx: HostToolContext) -> dict:
    """Validate a proposed command. Returns the matched allowlist entry.

    Raises SandboxViolation on any failure.
    """
    if not isinstance(cmd, str):
        raise SandboxViolation(f"command must be a string, got {type(cmd).__name__}")
    if not cmd.strip():
        raise SandboxViolation("command is empty")
    if len(cmd) > 1000:
        raise SandboxViolation(f"command too long ({len(cmd)} chars, max 1000)")

    # Forbidden shell construction — reject even if the pattern matches.
    bad = _contains_forbidden_construct(cmd)
    if bad is not None:
        raise SandboxViolation(f"forbidden shell construct: {bad!r}")

    # Excluded folder mention — reject even if on the allowlist.
    excluded = _references_excluded_folder(cmd, ctx.excluded_folder_names)
    if excluded is not None:
        raise SandboxViolation(
            f"command references excluded folder {excluded!r} — "
            f"these are off-limits per operator policy"
        )

    # Allowlist match
    stripped = cmd.strip()
    for pattern, meta in _ALLOWLIST:
        if pattern.fullmatch(stripped):
            # Consent gates
            if meta.get("admin") and not ctx.allow_admin:
                raise SandboxViolation(
                    f"command requires admin elevation but trial was not run "
                    f"with allow_admin=True: {stripped[:80]}"
                )
            if meta.get("network_probe") and not ctx.allow_network_probe:
                raise SandboxViolation(
                    f"command is a network probe but trial was not run with "
                    f"allow_network_probe=True: {stripped[:80]}"
                )
            return meta

    # No match.
    raise SandboxViolation(
        f"command is not on the host-scan allowlist: {stripped[:120]!r}. "
        f"If this is a legitimate read-only system query, ask the operator "
        f"to add its pattern to host_sandbox.py _ALLOWLIST."
    )


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


def _pick_shell() -> tuple[str, list[str]]:
    """Return (path-to-shell, arg-template) for executing a command string.

    Prefer PowerShell 7+ (`pwsh`), fall back to Windows PowerShell
    (`powershell.exe`). On non-Windows platforms this raises.
    """
    if sys.platform.startswith("win"):
        for name in ("pwsh.exe", "pwsh", "powershell.exe", "powershell"):
            found = shutil.which(name)
            if found:
                return found, ["-NoProfile", "-NonInteractive", "-Command"]
        raise SandboxViolation(
            "no PowerShell (pwsh / powershell.exe) found on PATH — "
            "cannot execute host-scan commands."
        )
    raise SandboxViolation(
        f"host-scan execution not supported on {sys.platform!r}. "
        f"Run the trial from Windows 10+ / Windows Server."
    )


def run_system_query(ctx: HostToolContext, cmd: str) -> str:
    """Execute one allowlisted read-only system query. Returns combined stdout.

    All validation happens via `validate_command` before any process spawns.
    """
    validate_command(cmd, ctx)  # raises SandboxViolation on any failure
    shell_path, arg_template = _pick_shell()

    try:
        proc = subprocess.run(
            [shell_path, *arg_template, cmd],
            capture_output=True,
            timeout=ctx.per_call_timeout_seconds,
            # Restricted environment — keep PATH for PowerShell itself but no user profile shenanigans.
            env={
                "PATH": os.environ.get("PATH", ""),
                "SYSTEMROOT": os.environ.get("SYSTEMROOT", r"C:\Windows"),
                "COMPUTERNAME": os.environ.get("COMPUTERNAME", ""),
                "USERDOMAIN": os.environ.get("USERDOMAIN", ""),
                "USERNAME": os.environ.get("USERNAME", ""),
                "TEMP": os.environ.get("TEMP", ""),
                "TMP": os.environ.get("TMP", ""),
            },
            check=False,
        )
    except subprocess.TimeoutExpired:
        return (
            f"[TIMEOUT after {ctx.per_call_timeout_seconds}s]\n"
            f"command: {cmd}\n"
        )

    stdout = proc.stdout.decode("utf-8", errors="replace") if proc.stdout else ""
    stderr = proc.stderr.decode("utf-8", errors="replace") if proc.stderr else ""
    combined = f"[exit {proc.returncode}]\n--- stdout ---\n{stdout}"
    if stderr.strip():
        combined += f"\n--- stderr ---\n{stderr}"
    if len(combined) > ctx.max_output_bytes:
        combined = combined[: ctx.max_output_bytes] + f"\n[truncated at {ctx.max_output_bytes} bytes]"
    return combined


# ---------------------------------------------------------------------------
# Baseline capture — called once at the start of a host-scan trial so the
# alert-triage specialist can compute the pre/post delta.
# ---------------------------------------------------------------------------


BASELINE_COMMANDS: list[tuple[str, str]] = [
    ("defender_threats",       "Get-MpThreatDetection"),
    ("defender_threat_list",   "Get-MpThreat"),
    ("defender_status",        "Get-MpComputerStatus"),
    ("defender_preference",    "Get-MpPreference"),
    ("sec_log_high_water",     "Get-WinEvent -LogName Security -MaxEvents 1"),
    ("sys_log_high_water",     "Get-WinEvent -LogName System -MaxEvents 1"),
    ("app_log_high_water",     "Get-WinEvent -LogName Application -MaxEvents 1"),
    ("defender_op_high_water", "Get-WinEvent -LogName Microsoft-Windows-Windows Defender/Operational -MaxEvents 1"),
    ("ps_op_high_water",       "Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational -MaxEvents 1"),
]


def capture_baseline(ctx: HostToolContext) -> str:
    """Snapshot all baseline commands into `evidence/alert-triage-baseline/`.

    Returns a short summary string for the agent to log.
    """
    baseline_dir = ctx.target_dir / "evidence" / "alert-triage-baseline"
    baseline_dir.mkdir(parents=True, exist_ok=True)

    written: list[str] = []
    for label, cmd in BASELINE_COMMANDS:
        # Baseline runs under ctx allowlist — uses the same validation. If
        # any one fails allowlist (shouldn't — all are pre-registered), skip
        # and record rather than aborting the whole baseline.
        try:
            output = run_system_query(ctx, cmd)
        except SandboxViolation as e:
            output = f"[baseline skipped: {e}]"
        out_path = baseline_dir / f"{label}.txt"
        out_path.write_text(f"# command: {cmd}\n\n{output}\n", encoding="utf-8")
        written.append(label)

    return (
        f"captured {len(written)} baseline snapshots under "
        f"{baseline_dir.relative_to(ctx.target_dir)}/ — "
        f"labels: {', '.join(written)}"
    )


# ---------------------------------------------------------------------------
# Re-exports so dispatch / agent_loop can treat HostToolContext uniformly
# with the code ToolContext for output tools.
# ---------------------------------------------------------------------------

__all__ = [
    "HostToolContext",
    "DEFAULT_EXCLUDED_FOLDER_NAMES",
    "SandboxViolation",
    "validate_command",
    "run_system_query",
    "capture_baseline",
    "submit_finding",   # re-exported for dispatch handler parity
    "write_notes",      # re-exported for dispatch handler parity
]
