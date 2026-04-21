"""Orchestrator tests — trial pipeline, parallel fan-out, partial failure.

Uses a thread-safe scripted provider to drive recon + N specialists + synth
through the full pipeline without burning API tokens. Asserts order
(recon first, synthesizer last), parallel execution of specialists,
partial-failure recovery, and correct TrialResult aggregation.
"""

from __future__ import annotations

import re
import threading
import time

import pytest

from redforge_attack.orchestrator import TrialResult, run_trial
from redforge_attack.providers.base import LLMProvider
from redforge_attack.schema import AssistantTurn


def _parse_agent_id(messages: list[dict]) -> str:
    """Pull the agent id out of the user kickoff message."""
    if not messages:
        return "(unknown)"
    content = messages[0].get("content", "")
    if not isinstance(content, str):
        return "(unknown)"
    m = re.search(r"`([a-z][a-z0-9-]*)` agent", content)
    return m.group(1) if m else "(unknown)"


class ThreadSafeProvider(LLMProvider):
    """Provider that always returns a clean end_turn — validates orchestration
    without exercising tool-use loop (tested separately in test_agent_loop)."""

    name = "end-turn-test"

    def __init__(self, sleep_per_call: float = 0.0, fail_for: set[str] | None = None):
        self._sleep = sleep_per_call
        self._fail_for = fail_for or set()
        self._lock = threading.Lock()
        self.agents_called: list[str] = []
        self.call_starts: list[float] = []  # For parallel-timing assertions
        self.call_ends: list[float] = []

    def chat(self, *, model, system, messages, tools, max_tokens, temperature=0.0):
        agent_id = _parse_agent_id(messages)

        with self._lock:
            self.agents_called.append(agent_id)
            self.call_starts.append(time.monotonic())

        if agent_id in self._fail_for:
            raise RuntimeError(f"scripted failure for {agent_id}")

        if self._sleep:
            time.sleep(self._sleep)

        with self._lock:
            self.call_ends.append(time.monotonic())

        return AssistantTurn(
            text=f"(completed {agent_id})",
            tool_calls=[],
            stop_reason="end_turn",
            usage={"input_tokens": 10, "output_tokens": 5},
        )

    def capabilities(self) -> dict:
        return {"parallel_tool_calls": True, "native_tool_use": True, "max_context": 200_000}


class TestOrchestratorOrder:
    def test_recon_runs_first_then_specialists_then_synthesizer(self, tiny_target):
        provider = ThreadSafeProvider()
        specialist_ids = ["injection", "authz-idor", "xss-client"]

        result = run_trial(
            target_dir=tiny_target,
            provider=provider,
            model_recon="m-recon",
            model_specialist="m-spec",
            model_synthesizer="m-synth",
            specialist_ids=specialist_ids,
            max_parallel=3,
            max_turns=5,
            max_tokens_budget=10_000,
        )

        assert result.recon is not None
        assert result.synthesizer is not None
        assert len(result.specialists) == 3
        assert not result.failures

        called = provider.agents_called
        # Recon must be first.
        assert called[0] == "recon"
        # Synthesizer must be last.
        assert called[-1] == "synthesizer"
        # Specialists must all be in between, in some order.
        middle = set(called[1:-1])
        assert middle == set(specialist_ids)

    def test_no_recon_skips_recon(self, tiny_target):
        provider = ThreadSafeProvider()
        result = run_trial(
            target_dir=tiny_target,
            provider=provider,
            model_recon="m",
            model_specialist="m",
            model_synthesizer="m",
            specialist_ids=["injection"],
            run_recon=False,
            max_parallel=1,
        )
        assert result.recon is None
        assert provider.agents_called[0] == "injection"

    def test_no_synthesizer_agent(self, tiny_target):
        provider = ThreadSafeProvider()
        result = run_trial(
            target_dir=tiny_target,
            provider=provider,
            model_recon="m",
            model_specialist="m",
            model_synthesizer="m",
            specialist_ids=["injection"],
            run_synthesizer_agent=False,
            max_parallel=1,
        )
        assert result.synthesizer is None
        # But mechanical synth still happens — stats populated.
        assert "total" in result.synth_stats
        # And synthesizer agent NOT called.
        assert "synthesizer" not in provider.agents_called


class TestOrchestratorParallelism:
    def test_specialists_run_in_parallel(self, tiny_target):
        """With max_parallel=4 and 4 specialists each sleeping 0.3s, the full
        specialist phase should take ~0.3s, not 1.2s. We allow slack for
        thread startup / Python overhead."""
        SLEEP = 0.3
        provider = ThreadSafeProvider(sleep_per_call=SLEEP)
        specialist_ids = ["injection", "authz-idor", "xss-client", "secrets-hunt"]

        t0 = time.monotonic()
        result = run_trial(
            target_dir=tiny_target,
            provider=provider,
            model_recon="m",
            model_specialist="m",
            model_synthesizer="m",
            specialist_ids=specialist_ids,
            max_parallel=4,
            run_recon=False,            # Recon would serialize first
            run_synthesizer_agent=False,  # Synth would serialize last
        )
        elapsed = time.monotonic() - t0

        assert not result.failures
        assert len(result.specialists) == 4
        # 4 specialists in parallel, each ~0.3s -> ~0.3s total, not 1.2s.
        # Allow 2x slack for the test to be reliable across machines.
        assert elapsed < SLEEP * 2.0, (
            f"specialists didn't run in parallel: elapsed={elapsed:.2f}s, "
            f"expected <{SLEEP * 2:.2f}s (single-threaded would be ~{SLEEP * 4:.2f}s)"
        )

    def test_max_parallel_caps_concurrency(self, tiny_target):
        """With max_parallel=2 and 4 specialists each sleeping 0.2s, the
        phase should take at least ~0.4s (two waves of 2)."""
        SLEEP = 0.2
        provider = ThreadSafeProvider(sleep_per_call=SLEEP)

        t0 = time.monotonic()
        run_trial(
            target_dir=tiny_target,
            provider=provider,
            model_recon="m",
            model_specialist="m",
            model_synthesizer="m",
            specialist_ids=["a1", "a2", "a3", "a4"],
            max_parallel=2,
            run_recon=False,
            run_synthesizer_agent=False,
        )
        elapsed = time.monotonic() - t0

        # Two waves of 2 specialists: ~0.4s minimum. Don't be strict on upper
        # bound; Python thread scheduling has jitter.
        assert elapsed >= SLEEP * 1.5, (
            f"max_parallel=2 with 4 agents should take ~2 waves: elapsed={elapsed:.2f}s"
        )


class TestOrchestratorPartialFailure:
    def test_one_specialist_fails_others_continue(self, tiny_target):
        provider = ThreadSafeProvider(fail_for={"injection"})

        result = run_trial(
            target_dir=tiny_target,
            provider=provider,
            model_recon="m",
            model_specialist="m",
            model_synthesizer="m",
            specialist_ids=["injection", "authz-idor", "xss-client"],
            max_parallel=3,
        )

        # injection failed; others should have run.
        assert len(result.failures) == 1
        assert result.failures[0][0] == "injection"
        assert "scripted failure" in result.failures[0][1]

        succeeded = {r.agent_id for r in result.specialists}
        assert succeeded == {"authz-idor", "xss-client"}

        # Recon + synthesizer still ran.
        assert result.recon is not None
        assert result.synthesizer is not None

    def test_recon_failure_does_not_abort_trial(self, tiny_target):
        provider = ThreadSafeProvider(fail_for={"recon"})

        result = run_trial(
            target_dir=tiny_target,
            provider=provider,
            model_recon="m",
            model_specialist="m",
            model_synthesizer="m",
            specialist_ids=["injection"],
            max_parallel=1,
        )

        assert result.recon is None
        assert any(f[0] == "recon" for f in result.failures)
        # Trial still completed — specialists and synthesizer ran.
        assert len(result.specialists) == 1
        assert result.synthesizer is not None


class TestOrchestratorAggregation:
    def test_token_usage_aggregated_across_agents(self, tiny_target):
        provider = ThreadSafeProvider()  # each call returns 10+5 tokens

        result = run_trial(
            target_dir=tiny_target,
            provider=provider,
            model_recon="m",
            model_specialist="m",
            model_synthesizer="m",
            specialist_ids=["injection", "xss-client"],
            max_parallel=2,
        )

        # 1 recon + 2 specialists + 1 synthesizer = 4 agents × (10 + 5) tokens
        assert result.total_input_tokens == 4 * 10
        assert result.total_output_tokens == 4 * 5
        assert result.total_tool_calls == 0  # Scripted provider returns no tool calls
        assert result.total_sandbox_violations == 0

    def test_missing_target_yaml_raises(self, tmp_path):
        # Point at a dir without target.yaml.
        (tmp_path / "intake").mkdir()
        provider = ThreadSafeProvider()
        with pytest.raises(FileNotFoundError, match="target.yaml"):
            run_trial(
                target_dir=tmp_path,
                provider=provider,
                model_recon="m",
                model_specialist="m",
                model_synthesizer="m",
                specialist_ids=["injection"],
            )
