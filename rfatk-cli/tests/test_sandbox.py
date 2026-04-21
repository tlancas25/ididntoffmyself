"""Sandbox containment tests — the critical safety piece.

If any of these fail, do NOT ship. The whole point of the sandbox is that a
prompt-injected or buggy specialist agent cannot escape `intake/` no matter
what path shape it invents.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

from redforge_attack.tools import sandbox


# -----------------------------------------------------------------------------
# Path containment
# -----------------------------------------------------------------------------


class TestReadFile:
    def test_reads_legit_file(self, tool_ctx):
        content = sandbox.read_file(tool_ctx, "app.py")
        assert "Flask" in content
        assert "/login" in content

    def test_rejects_absolute_path(self, tool_ctx):
        with pytest.raises(sandbox.SandboxViolation, match="absolute paths"):
            sandbox.read_file(tool_ctx, "/etc/passwd")

    def test_rejects_windows_absolute_path(self, tool_ctx):
        with pytest.raises(sandbox.SandboxViolation):
            sandbox.read_file(tool_ctx, "C:/Windows/System32/drivers/etc/hosts")

    def test_rejects_traversal(self, tool_ctx):
        # `..` must canonicalize out-of-scope AND raise SandboxViolation — not
        # FileNotFoundError (which would leak existence info and send the
        # wrong signal to the model about scope).
        with pytest.raises(sandbox.SandboxViolation, match="escapes"):
            sandbox.read_file(tool_ctx, "../../etc/passwd")

    def test_rejects_null_byte(self, tool_ctx):
        with pytest.raises(sandbox.SandboxViolation, match="NUL"):
            sandbox.read_file(tool_ctx, "app.py\x00.txt")

    def test_rejects_missing_file(self, tool_ctx):
        with pytest.raises(FileNotFoundError):
            sandbox.read_file(tool_ctx, "does-not-exist.py")

    def test_rejects_directory(self, tool_ctx):
        # "." resolves to intake root itself — a directory.
        with pytest.raises(sandbox.SandboxViolation, match="directory"):
            sandbox.read_file(tool_ctx, ".")

    def test_rejects_binary_file(self, tool_ctx, tiny_target):
        # Drop a binary file into intake and try to read it.
        bad = tiny_target / "intake" / "bad.bin"
        bad.write_bytes(b"\x00\x01\x02\x03" * 4)
        with pytest.raises(sandbox.SandboxViolation, match="binary"):
            sandbox.read_file(tool_ctx, "bad.bin")

    def test_rejects_oversize_file(self, tool_ctx, tiny_target):
        huge = tiny_target / "intake" / "huge.txt"
        huge.write_bytes(b"A" * (sandbox.MAX_FILE_BYTES + 1))
        with pytest.raises(sandbox.SandboxViolation, match="exceeds"):
            sandbox.read_file(tool_ctx, "huge.txt")

    @pytest.mark.skipif(sys.platform.startswith("win"), reason="symlinks require admin on Windows")
    def test_rejects_symlink_escape(self, tool_ctx, tiny_target, tmp_path):
        # Create a symlink INSIDE intake/ pointing to a file OUTSIDE intake.
        outside = tmp_path / "secret.txt"
        outside.write_text("top secret")
        link = tiny_target / "intake" / "escape.txt"
        os.symlink(str(outside), str(link))
        with pytest.raises(sandbox.SandboxViolation, match="escapes"):
            sandbox.read_file(tool_ctx, "escape.txt")


class TestGlob:
    def test_matches_intake_files(self, tool_ctx):
        results = sandbox.glob(tool_ctx, "*.py")
        assert "app.py" in results
        assert "db.py" in results
        assert "users.py" in results

    def test_recursive_glob(self, tool_ctx):
        all_py = sandbox.glob(tool_ctx, "**/*.py")
        assert set(all_py) >= {"app.py", "db.py", "users.py"}

    def test_rejects_leading_slash(self, tool_ctx):
        with pytest.raises(sandbox.SandboxViolation, match="absolute glob"):
            sandbox.glob(tool_ctx, "/etc/*")

    def test_rejects_dotdot(self, tool_ctx):
        with pytest.raises(sandbox.SandboxViolation, match="'..'"):
            sandbox.glob(tool_ctx, "../../*")

    def test_rejects_null_byte(self, tool_ctx):
        with pytest.raises(sandbox.SandboxViolation, match="NUL"):
            sandbox.glob(tool_ctx, "foo\x00bar")

    def test_no_match_returns_empty(self, tool_ctx):
        assert sandbox.glob(tool_ctx, "*.nonexistent") == []


class TestGrep:
    def test_finds_known_pattern(self, tool_ctx):
        results = sandbox.grep(tool_ctx, r"def find_user_by_email")
        assert any("db.py" in r for r in results)

    def test_case_insensitive(self, tool_ctx):
        results = sandbox.grep(tool_ctx, "FLASK", case_insensitive=True)
        assert any("app.py" in r for r in results)

    def test_rejects_bad_regex(self, tool_ctx):
        with pytest.raises(sandbox.SandboxViolation, match="invalid regex"):
            sandbox.grep(tool_ctx, "(unclosed")

    def test_path_glob_restricts(self, tool_ctx):
        results = sandbox.grep(tool_ctx, "def ", path_glob="db.py")
        # Only db.py should be searched; no app.py / users.py matches.
        assert all("db.py" in r for r in results)
        assert results  # non-empty

    def test_rejects_escape_in_path_glob(self, tool_ctx):
        with pytest.raises(sandbox.SandboxViolation, match="'..'"):
            sandbox.grep(tool_ctx, "anything", path_glob="../**/*")


# -----------------------------------------------------------------------------
# Output tools (submit_finding, write_notes) — scoped to agent_dir, not intake/
# -----------------------------------------------------------------------------


class TestSubmitFinding:
    def test_appends_to_findings_json(self, tool_ctx, tiny_target):
        finding = {
            "id": "test-001",
            "title": "smoke",
            "surface": "injection",
            "severity": "HIGH",
            "exploitable": True,
            "confidence": "high",
            "target_refs": ["db.py:1"],
            "description": "smoke test finding for unit test coverage.",
        }
        msg1 = sandbox.submit_finding(tool_ctx, finding)
        msg2 = sandbox.submit_finding(tool_ctx, {**finding, "id": "test-002"})
        assert "1" in msg1 and "2" in msg2

        path = tiny_target / "agents" / "test-agent" / "findings.json"
        data = json.loads(path.read_text())
        assert len(data) == 2
        assert data[0]["id"] == "test-001"
        assert data[1]["id"] == "test-002"

    def test_rejects_non_object(self, tool_ctx):
        with pytest.raises(TypeError, match="finding must be"):
            sandbox.submit_finding(tool_ctx, "not a dict")  # type: ignore[arg-type]

    def test_requires_agent_id(self, tiny_target):
        from redforge_attack.tools.sandbox import ToolContext
        ctx = ToolContext(
            target_dir=tiny_target,
            intake_dir=tiny_target / "intake",
            agent_id="",  # missing
        )
        with pytest.raises(sandbox.SandboxViolation, match="agent_id"):
            sandbox.submit_finding(ctx, {"id": "x"})


class TestWriteNotes:
    def test_appends(self, tool_ctx, tiny_target):
        sandbox.write_notes(tool_ctx, "first note")
        sandbox.write_notes(tool_ctx, "second note")
        content = (tiny_target / "agents" / "test-agent" / "notes.md").read_text()
        assert "first note" in content
        assert "second note" in content

    def test_rejects_non_string(self, tool_ctx):
        with pytest.raises(TypeError, match="must be a string"):
            sandbox.write_notes(tool_ctx, 123)  # type: ignore[arg-type]


# -----------------------------------------------------------------------------
# run_bash — DISABLED by default
# -----------------------------------------------------------------------------


class TestRunBash:
    def test_disabled_by_default(self, tool_ctx):
        with pytest.raises(sandbox.SandboxViolation, match="disabled"):
            sandbox.run_bash(tool_ctx, "echo hi")
