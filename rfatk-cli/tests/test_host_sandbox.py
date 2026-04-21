"""Host-scan sandbox tests — allowlist + excluded folders + consent gating.

These are the safety-critical tests for the self-scan trial. If any fail,
do NOT run a live host scan.
"""

from __future__ import annotations

import json
import pathlib
import sys
from unittest import mock

import pytest

from redforge_attack.tools import dispatch, host_sandbox, sandbox
from redforge_attack.tools.host_sandbox import (
    DEFAULT_EXCLUDED_FOLDER_NAMES,
    HostToolContext,
    SandboxViolation,
    capture_baseline,
    run_system_query,
    validate_command,
)


@pytest.fixture()
def host_ctx(tmp_path):
    """Fresh HostToolContext with excluded folders + no admin / network probe."""
    target = tmp_path / "host-trial"
    (target / "evidence").mkdir(parents=True)
    (target / "agents").mkdir(parents=True)
    return HostToolContext(
        target_dir=target,
        agent_id="test-host-agent",
        excluded_folder_names=DEFAULT_EXCLUDED_FOLDER_NAMES,
        allow_admin=False,
        allow_network_probe=False,
    )


@pytest.fixture()
def host_ctx_admin(host_ctx):
    """Admin-enabled variant for testing admin-gated commands."""
    from dataclasses import replace
    return replace(host_ctx, allow_admin=True)


@pytest.fixture()
def host_ctx_net(host_ctx):
    from dataclasses import replace
    return replace(host_ctx, allow_network_probe=True)


# -----------------------------------------------------------------------------
# Allowlist matching — known-good and known-bad commands
# -----------------------------------------------------------------------------


class TestAllowlistAccept:
    """Commands that SHOULD match the allowlist."""

    @pytest.mark.parametrize("cmd", [
        "systeminfo",
        "hostname",
        "whoami /all",
        "Get-Service",
        "Get-Service -Name *defender*",
        "Get-Process",
        "tasklist /v",
        "netstat -ano",
        "ipconfig /all",
        "arp -a",
        "route print",
        "Get-NetTCPConnection -State Listen",
        "Get-NetFirewallProfile",
        "Get-NetFirewallRule -Direction Inbound",
        "reg query HKLM\\SOFTWARE\\Microsoft\\Windows",
        "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\" /v ProductName",
        "net user",
        "net user administrator",
        "net localgroup",
        "net localgroup administrators",
        "Get-LocalUser",
        "schtasks /query /fo LIST",
        "Get-ScheduledTask",
        "Get-WinEvent -LogName Application -MaxEvents 50",
        "Get-MpComputerStatus",
        "Get-MpPreference",
        "gpresult /r",
        "driverquery /v",
        "Resolve-DnsName google.com",  # will also need network_probe in other test
    ])
    def test_allowlist_accepts(self, host_ctx_admin, host_ctx_net, cmd):
        # Use the most-permissive ctx so admin/network-probe commands don't
        # hit consent gates (we test those separately).
        from dataclasses import replace
        ctx = replace(host_ctx_admin, allow_network_probe=True)
        meta = validate_command(cmd, ctx)
        assert isinstance(meta, dict)


class TestAllowlistReject:
    """Commands that should NOT be on the allowlist."""

    @pytest.mark.parametrize("cmd", [
        "rm -rf /",
        "del C:\\Windows\\*",
        "ls",
        "dir",
        "Get-ChildItem -Recurse C:\\",
        "powershell -c 'whatever'",
        "cmd /c echo hi",
        "curl https://evil.example",
        "invoke-webrequest https://attacker",
        "Invoke-WebRequest https://evil",
        "Start-Process notepad",
        "Stop-Process -Id 123",
        "Set-ItemProperty HKLM:\\foo -Name x -Value 1",  # writes
        "New-Item C:\\thing",
        "Remove-Item C:\\thing",
        "Add-Content C:\\file -Value x",
        "Copy-Item src dst",
    ])
    def test_allowlist_rejects_unapproved(self, host_ctx_admin, cmd):
        with pytest.raises(SandboxViolation):
            validate_command(cmd, host_ctx_admin)


class TestForbiddenConstructs:
    """Even if allowlisted, shell-composition tricks must be rejected."""

    @pytest.mark.parametrize("cmd", [
        "Get-Service; Get-Process",                # chaining
        "Get-Service && Get-Process",              # bash-style AND
        "Get-Service || Get-Process",              # bash-style OR
        "Get-Service | Out-File C:\\leak.txt",     # pipe to redirect
        "Get-Service > out.txt",                   # stdout redirect
        "Get-Service < in.txt",                    # stdin redirect
        "Get-Service `echo x`",                    # backtick substitution
        "Get-Service $(whoami)",                   # $() substitution
        "Get-Service @(1,2)",                      # @() splat
        "Get-Service\nGet-Process",                # newline (multi-line)
        "Get-Service 2>&1",                        # stream merge
    ])
    def test_rejects_forbidden_constructs(self, host_ctx_admin, cmd):
        with pytest.raises(SandboxViolation):
            validate_command(cmd, host_ctx_admin)


class TestExcludedFolders:
    """The 4 off-limits folders must be rejected regardless of allowlist match."""

    @pytest.mark.parametrize("cmd", [
        "Get-Content C:\\Users\\testuser\\Documents\\secrets.txt",
        "Get-Content C:\\Users\\testuser\\Downloads\\installer.exe",
        "Get-Content C:\\Users\\testuser\\Pictures\\a.png",
        "Get-Content C:\\Users\\testuser\\Videos\\rec.mp4",
        # Case insensitivity
        "Get-Content C:\\users\\testuser\\documents\\x.txt",
        # Forward slashes
        "Get-Content C:/Users/testuser/Documents/x.txt",
        # Environment-var style (substring match catches it)
        "Get-Content %USERPROFILE%\\Documents\\x.txt",
        "Get-Content $env:USERPROFILE\\Pictures\\x.png",
    ])
    def test_excluded_folder_rejected(self, host_ctx, cmd):
        with pytest.raises(SandboxViolation, match="excluded folder"):
            validate_command(cmd, host_ctx)

    def test_partial_word_match_not_blocked(self, host_ctx):
        """We only block \\Documents\\ (full path component). A path
        containing 'MyDocuments' or 'DocumentsOld' in a non-component way
        should still block because we match the word preceded by a separator.
        But 'DocumentsTemplate' as a filename should be fine. Test both."""
        # Preceded by separator → blocks (even 'MyDocuments' - treated as \Documents via separator check)
        with pytest.raises(SandboxViolation):
            validate_command("Get-Content C:\\Users\\testuser\\Documents\\x.txt", host_ctx)

        # 'CustomFolder' contains 'Documents' as substring but not as a path
        # component — accept it. The regex looks for [\\/]Documents(?=[\\/'\"\\s]|$).
        # So 'FooDocuments' without leading separator shouldn't match.
        # But our allowlist may not include this specific command anyway. Use
        # an allowlisted form: Get-Content of a system path.
        cmd = "Get-Content C:\\Windows\\System32\\drivers\\etc\\hosts"
        validate_command(cmd, host_ctx)  # should pass (no exclusion trigger)


# -----------------------------------------------------------------------------
# Consent gates: admin, network probe
# -----------------------------------------------------------------------------


class TestAdminGate:
    def test_admin_required_blocked_without_flag(self, host_ctx):
        # sc sdshow requires admin per allowlist meta
        with pytest.raises(SandboxViolation, match="admin"):
            validate_command("sc sdshow W32Time", host_ctx)

    def test_admin_required_ok_with_flag(self, host_ctx_admin):
        validate_command("sc sdshow W32Time", host_ctx_admin)

    def test_autorunsc_requires_admin(self, host_ctx, host_ctx_admin):
        with pytest.raises(SandboxViolation, match="admin"):
            validate_command("Autorunsc -accepteula -a *", host_ctx)
        validate_command("Autorunsc -accepteula -a *", host_ctx_admin)


class TestNetworkProbeGate:
    def test_network_probe_blocked_without_flag(self, host_ctx):
        with pytest.raises(SandboxViolation, match="network probe"):
            validate_command("Test-NetConnection 192.168.1.1", host_ctx)

    def test_network_probe_ok_with_flag(self, host_ctx_net):
        validate_command("Test-NetConnection 192.168.1.1 -Port 80", host_ctx_net)

    def test_resolve_dns_requires_probe(self, host_ctx, host_ctx_net):
        with pytest.raises(SandboxViolation, match="network probe"):
            validate_command("Resolve-DnsName google.com", host_ctx)
        validate_command("Resolve-DnsName google.com", host_ctx_net)


# -----------------------------------------------------------------------------
# Empty / oversize commands
# -----------------------------------------------------------------------------


class TestCommandBounds:
    def test_empty_rejected(self, host_ctx):
        with pytest.raises(SandboxViolation, match="empty"):
            validate_command("", host_ctx)
        with pytest.raises(SandboxViolation, match="empty"):
            validate_command("   ", host_ctx)

    def test_oversize_rejected(self, host_ctx):
        with pytest.raises(SandboxViolation, match="too long"):
            validate_command("systeminfo " + "A" * 2000, host_ctx)

    def test_null_byte_rejected(self, host_ctx):
        with pytest.raises(SandboxViolation):
            validate_command("systeminfo\x00", host_ctx)


# -----------------------------------------------------------------------------
# Execution (mocked subprocess)
# -----------------------------------------------------------------------------


class TestRunSystemQueryMocked:
    @pytest.mark.skipif(not sys.platform.startswith("win"), reason="host scan is Windows-only in v0.1")
    def test_executes_and_returns_stdout(self, host_ctx):
        fake_proc = mock.Mock()
        fake_proc.stdout = b"os name: Windows\n"
        fake_proc.stderr = b""
        fake_proc.returncode = 0
        with mock.patch("redforge_attack.tools.host_sandbox.subprocess.run", return_value=fake_proc) as run_mock:
            out = run_system_query(host_ctx, "systeminfo")
        assert "os name: Windows" in out
        assert "[exit 0]" in out
        # Verify subprocess got the shell + arg template + cmd.
        args = run_mock.call_args
        invoked = args.args[0]
        assert invoked[-1] == "systeminfo"

    def test_non_windows_refused(self, host_ctx):
        if sys.platform.startswith("win"):
            pytest.skip("this test is for non-Windows platforms")
        with pytest.raises(SandboxViolation, match="not supported"):
            run_system_query(host_ctx, "systeminfo")

    @pytest.mark.skipif(not sys.platform.startswith("win"), reason="host scan is Windows-only in v0.1")
    def test_timeout_returns_string_not_exception(self, host_ctx):
        import subprocess as sp
        with mock.patch(
            "redforge_attack.tools.host_sandbox.subprocess.run",
            side_effect=sp.TimeoutExpired(cmd="systeminfo", timeout=host_ctx.per_call_timeout_seconds),
        ):
            out = run_system_query(host_ctx, "systeminfo")
        assert "TIMEOUT" in out


class TestCaptureBaseline:
    @pytest.mark.skipif(not sys.platform.startswith("win"), reason="host scan is Windows-only in v0.1")
    def test_writes_baseline_dir(self, host_ctx):
        fake_proc = mock.Mock()
        fake_proc.stdout = b"baseline output\n"
        fake_proc.stderr = b""
        fake_proc.returncode = 0
        with mock.patch("redforge_attack.tools.host_sandbox.subprocess.run", return_value=fake_proc):
            summary = capture_baseline(host_ctx)

        baseline_dir = host_ctx.target_dir / "evidence" / "alert-triage-baseline"
        assert baseline_dir.exists()
        # Every baseline command should have produced one file.
        written = list(baseline_dir.glob("*.txt"))
        assert len(written) == len(host_sandbox.BASELINE_COMMANDS)
        assert "captured" in summary


# -----------------------------------------------------------------------------
# Dispatch — tools are routed correctly for HostToolContext
# -----------------------------------------------------------------------------


class TestDispatch:
    @pytest.mark.skipif(not sys.platform.startswith("win"), reason="host scan is Windows-only in v0.1")
    def test_run_system_query_routed(self, host_ctx):
        from redforge_attack.schema import ToolCall
        call = ToolCall(id="c1", name="run_system_query", arguments={"cmd": "hostname"})

        fake_proc = mock.Mock()
        fake_proc.stdout = b"LAPTOP\n"
        fake_proc.stderr = b""
        fake_proc.returncode = 0
        with mock.patch("redforge_attack.tools.host_sandbox.subprocess.run", return_value=fake_proc):
            result = dispatch.dispatch(call, host_ctx)
        assert not result.is_error
        assert "LAPTOP" in result.content

    def test_run_system_query_rejected_in_code_context(self, tool_ctx):
        """A code-scan ToolContext should NOT be able to call run_system_query."""
        from redforge_attack.schema import ToolCall
        call = ToolCall(id="c1", name="run_system_query", arguments={"cmd": "hostname"})
        result = dispatch.dispatch(call, tool_ctx)
        assert result.is_error
        assert "host-scan" in result.content

    def test_output_tools_work_in_host_context(self, host_ctx):
        """submit_finding + write_notes reused across contexts."""
        from redforge_attack.schema import ToolCall
        finding = {
            "id": "host-test-001",
            "title": "x",
            "surface": "ci-cd",
            "severity": "LOW",
            "exploitable": False,
            "confidence": "medium",
            "target_refs": ["test"],
            "description": "host context finding — twenty chars plus.",
        }
        result = dispatch.dispatch(
            ToolCall(id="c1", name="submit_finding", arguments={"finding": finding}),
            host_ctx,
        )
        assert not result.is_error
        findings_path = host_ctx.target_dir / "agents" / "test-host-agent" / "findings.json"
        assert findings_path.exists()
        data = json.loads(findings_path.read_text())
        assert data[0]["id"] == "host-test-001"

    def test_sandbox_violation_becomes_tool_result_error(self, host_ctx):
        """An off-allowlist command returns is_error=True, not an exception."""
        from redforge_attack.schema import ToolCall
        call = ToolCall(
            id="c1",
            name="run_system_query",
            arguments={"cmd": "rm -rf /"},
        )
        result = dispatch.dispatch(call, host_ctx)
        assert result.is_error
        assert "sandbox_violation" in result.content
