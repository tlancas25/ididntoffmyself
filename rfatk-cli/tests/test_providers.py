"""Provider message / tool shape conversion tests.

The hardest part of provider adapters is the shape conversion between
OpenAI-canonical (our internal LCD) and each vendor's native format. These
tests exercise the pure converter functions directly — no SDK needed.

Each test builds a concrete message or tool dict, runs it through the
converter, and asserts the output shape. Regression-safe.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from redforge_attack.providers import anthropic as anth_mod
from redforge_attack.providers import openai_compat as oc_mod
from redforge_attack.providers import registry
from redforge_attack.schema import ToolCall


# -----------------------------------------------------------------------------
# Anthropic adapter — shape conversion
# -----------------------------------------------------------------------------


class TestAnthropicToolConversion:
    def test_openai_tool_to_anthropic(self):
        oai = [{
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read a file.",
                "parameters": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
            },
        }]
        anth = anth_mod._openai_tools_to_anthropic(oai)
        assert len(anth) == 1
        assert anth[0]["name"] == "read_file"
        assert anth[0]["description"] == "Read a file."
        assert anth[0]["input_schema"]["properties"]["path"]["type"] == "string"

    def test_drops_non_function_tools(self):
        # If someone slips in a non-"function" tool (future OpenAI types), skip it.
        oai = [
            {"type": "retrieval", "retrieval": {}},
            {"type": "function", "function": {"name": "glob", "parameters": {}}},
        ]
        anth = anth_mod._openai_tools_to_anthropic(oai)
        assert len(anth) == 1
        assert anth[0]["name"] == "glob"

    def test_empty_tools(self):
        assert anth_mod._openai_tools_to_anthropic([]) == []


class TestAnthropicMessageConversion:
    def test_user_message_passthrough(self):
        msgs = [{"role": "user", "content": "hello"}]
        anth = anth_mod._openai_messages_to_anthropic(msgs)
        assert anth == [{"role": "user", "content": "hello"}]

    def test_assistant_text_only(self):
        msgs = [{"role": "assistant", "content": "thinking..."}]
        anth = anth_mod._openai_messages_to_anthropic(msgs)
        assert anth == [{"role": "assistant", "content": [{"type": "text", "text": "thinking..."}]}]

    def test_assistant_with_tool_calls_becomes_content_list(self):
        msgs = [{
            "role": "assistant",
            "content": "let me check",
            "tool_calls": [{
                "id": "call_1",
                "type": "function",
                "function": {"name": "read_file", "arguments": '{"path":"app.py"}'},
            }],
        }]
        anth = anth_mod._openai_messages_to_anthropic(msgs)
        assert len(anth) == 1
        content = anth[0]["content"]
        assert content[0] == {"type": "text", "text": "let me check"}
        assert content[1]["type"] == "tool_use"
        assert content[1]["id"] == "call_1"
        assert content[1]["name"] == "read_file"
        assert content[1]["input"] == {"path": "app.py"}

    def test_tool_results_go_in_user_message(self):
        msgs = [
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "c1", "type": "function", "function": {"name": "glob", "arguments": "{}"}}
            ]},
            {"role": "tool", "tool_call_id": "c1", "content": "app.py\ndb.py"},
        ]
        anth = anth_mod._openai_messages_to_anthropic(msgs)
        # Expect: assistant with tool_use, then user with tool_result
        assert anth[0]["role"] == "assistant"
        assert anth[1]["role"] == "user"
        assert anth[1]["content"][0]["type"] == "tool_result"
        assert anth[1]["content"][0]["tool_use_id"] == "c1"
        assert anth[1]["content"][0]["content"] == "app.py\ndb.py"
        assert anth[1]["content"][0]["is_error"] is False

    def test_consecutive_tool_results_collapsed(self):
        msgs = [
            {"role": "assistant", "tool_calls": [
                {"id": "c1", "type": "function", "function": {"name": "glob", "arguments": "{}"}},
                {"id": "c2", "type": "function", "function": {"name": "read_file", "arguments": '{"path":"x"}'}},
            ]},
            {"role": "tool", "tool_call_id": "c1", "content": "listing"},
            {"role": "tool", "tool_call_id": "c2", "content": "contents"},
        ]
        anth = anth_mod._openai_messages_to_anthropic(msgs)
        # The two tool results should collapse into ONE user message with both tool_result blocks.
        assert anth[1]["role"] == "user"
        assert len(anth[1]["content"]) == 2
        ids = [b["tool_use_id"] for b in anth[1]["content"]]
        assert ids == ["c1", "c2"]

    def test_tool_result_is_error_propagated(self):
        msgs = [
            {"role": "assistant", "tool_calls": [
                {"id": "c1", "type": "function", "function": {"name": "read_file", "arguments": "{}"}}
            ]},
            {"role": "tool", "tool_call_id": "c1", "content": "sandbox_violation: ...", "is_error": True},
        ]
        anth = anth_mod._openai_messages_to_anthropic(msgs)
        assert anth[1]["content"][0]["is_error"] is True

    def test_empty_assistant_message_skipped(self):
        # Anthropic rejects empty content blocks — we should filter.
        msgs = [
            {"role": "user", "content": "q"},
            {"role": "assistant", "content": "", "tool_calls": []},
            {"role": "user", "content": "q2"},
        ]
        anth = anth_mod._openai_messages_to_anthropic(msgs)
        assert [m["role"] for m in anth] == ["user", "user"]


class TestAnthropicResponseToTurn:
    def test_text_only_response(self):
        resp = SimpleNamespace(
            content=[SimpleNamespace(type="text", text="final answer")],
            stop_reason="end_turn",
            usage=SimpleNamespace(input_tokens=50, output_tokens=10),
        )
        turn = anth_mod._response_to_turn(resp)
        assert turn.text == "final answer"
        assert turn.tool_calls == []
        assert turn.stop_reason == "end_turn"
        assert turn.usage == {"input_tokens": 50, "output_tokens": 10}

    def test_tool_use_response(self):
        resp = SimpleNamespace(
            content=[
                SimpleNamespace(type="text", text="let me look"),
                SimpleNamespace(type="tool_use", id="toolu_1", name="read_file", input={"path": "app.py"}),
            ],
            stop_reason="tool_use",
            usage=SimpleNamespace(input_tokens=100, output_tokens=20),
        )
        turn = anth_mod._response_to_turn(resp)
        assert turn.text == "let me look"
        assert len(turn.tool_calls) == 1
        assert turn.tool_calls[0] == ToolCall(id="toolu_1", name="read_file", arguments={"path": "app.py"})
        assert turn.stop_reason == "tool_use"

    def test_parallel_tool_use(self):
        resp = SimpleNamespace(
            content=[
                SimpleNamespace(type="tool_use", id="t1", name="glob", input={"pattern": "**/*.py"}),
                SimpleNamespace(type="tool_use", id="t2", name="read_file", input={"path": "app.py"}),
            ],
            stop_reason="tool_use",
            usage=SimpleNamespace(input_tokens=50, output_tokens=30),
        )
        turn = anth_mod._response_to_turn(resp)
        assert len(turn.tool_calls) == 2
        assert {c.name for c in turn.tool_calls} == {"glob", "read_file"}


# -----------------------------------------------------------------------------
# OpenAI-compat adapter — shape conversion
# -----------------------------------------------------------------------------


class TestOpenAICompatResponseConversion:
    def test_text_only(self):
        # Emulate openai SDK response shape.
        msg = SimpleNamespace(content="the answer", tool_calls=None)
        choice = SimpleNamespace(message=msg, finish_reason="stop")
        resp = SimpleNamespace(
            choices=[choice],
            usage=SimpleNamespace(prompt_tokens=120, completion_tokens=15),
        )
        turn = oc_mod._assistant_turn_from_openai(resp)
        assert turn.text == "the answer"
        assert turn.tool_calls == []
        assert turn.stop_reason == "end_turn"  # normalized from "stop"
        assert turn.usage == {"input_tokens": 120, "output_tokens": 15}

    def test_tool_calls_normalized(self):
        fn = SimpleNamespace(name="read_file", arguments='{"path": "db.py"}')
        tc = SimpleNamespace(id="call_abc", function=fn)
        msg = SimpleNamespace(content=None, tool_calls=[tc])
        choice = SimpleNamespace(message=msg, finish_reason="tool_calls")
        resp = SimpleNamespace(
            choices=[choice],
            usage=SimpleNamespace(prompt_tokens=80, completion_tokens=20),
        )
        turn = oc_mod._assistant_turn_from_openai(resp)
        assert turn.stop_reason == "tool_use"  # normalized from "tool_calls"
        assert turn.tool_calls == [ToolCall(id="call_abc", name="read_file", arguments={"path": "db.py"})]

    def test_finish_reason_length_becomes_max_tokens(self):
        msg = SimpleNamespace(content="truncated...", tool_calls=None)
        choice = SimpleNamespace(message=msg, finish_reason="length")
        resp = SimpleNamespace(choices=[choice], usage=None)
        turn = oc_mod._assistant_turn_from_openai(resp)
        assert turn.stop_reason == "max_tokens"

    def test_system_message_prepended(self):
        msgs = [{"role": "user", "content": "hi"}]
        out = oc_mod._messages_with_system("you are a test agent", msgs)
        assert out[0] == {"role": "system", "content": "you are a test agent"}
        assert out[1] == {"role": "user", "content": "hi"}

    def test_no_system_means_no_system_message(self):
        msgs = [{"role": "user", "content": "hi"}]
        out = oc_mod._messages_with_system("", msgs)
        assert out == msgs


# -----------------------------------------------------------------------------
# Registry — name -> factory mapping
# -----------------------------------------------------------------------------


class TestRegistry:
    def test_known_names_present(self):
        names = registry.known_provider_names()
        for expected in ("anthropic", "openai", "openrouter", "gemini", "moonshot", "ollama", "llamacpp"):
            assert expected in names

    def test_unknown_provider_raises(self):
        with pytest.raises(ValueError, match="unknown provider"):
            registry.build_provider("not-a-real-vendor")

    def test_default_model_lookup(self):
        assert registry.default_model_for("anthropic", "synthesizer") == "claude-sonnet-4-5"
        assert registry.default_model_for("openrouter", "specialist").startswith("anthropic/")
        assert registry.default_model_for("gemini", "recon") == "gemini-2.5-flash"
        assert registry.default_model_for("nonexistent", "recon") == ""

    def test_user_defined_provider_requires_base_url(self):
        with pytest.raises(ValueError, match="base_url"):
            registry.build_provider(
                "mycorp",
                config_overrides={"mycorp": {"kind": "openai_compat"}},
            )

    def test_anthropic_requires_key(self, monkeypatch):
        # Ensure env var is not set — should raise.
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(RuntimeError, match="No Anthropic API key"):
            registry.build_provider("anthropic")

    def test_openrouter_requires_key(self, monkeypatch):
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        with pytest.raises(RuntimeError, match="No API key"):
            registry.build_provider("openrouter")
