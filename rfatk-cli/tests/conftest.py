"""pytest fixtures shared across the redforge-attack test suite."""

from __future__ import annotations

import pathlib
import shutil

import pytest


FIXTURES_DIR = pathlib.Path(__file__).parent / "fixtures"


@pytest.fixture()
def tiny_target(tmp_path):
    """Copy the frozen tests/fixtures/tiny-target/ into a tmp dir and yield the path.

    Tests get a fresh, writable target folder each run — sandbox tests create
    agent subdirs, symlinks, evidence files, etc. without polluting the
    committed fixture.
    """
    src = FIXTURES_DIR / "tiny-target"
    dst = tmp_path / "tiny-target"
    shutil.copytree(src, dst)
    return dst


@pytest.fixture()
def tool_ctx(tiny_target):
    """A sandbox.ToolContext wired to the tmp tiny-target."""
    from redforge_attack.tools.sandbox import ToolContext
    return ToolContext(
        target_dir=tiny_target,
        intake_dir=tiny_target / "intake",
        agent_id="test-agent",
    )
