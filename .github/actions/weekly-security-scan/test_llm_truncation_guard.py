"""A truncated or empty AI-review completion must not be treated as a clean scan.

infra-commons/security#815: `call_claude()`/`call_openai()` had no `stop_reason`/
`finish_reason` guard at all — unlike `adversarial-review.py`'s `call_openai()`,
which already raises on an empty completion or `finish_reason == "length"` with
the comment "An empty or truncated completion must NOT read as 'no findings':
that is a silent fail-open... Raise instead." A mid-scan cutoff here would
otherwise degrade through `parse_ai_findings()`'s JSON-repair path to a single
LOW "parse error" placeholder, silently discarding every CRITICAL/HIGH finding
the model had already fully described before the cutoff. These tests pin the
fail-closed direction directly against the real `anthropic`/`openai` SDKs
(monkeypatched at the class level, matching the modules' own lazy-import shape).
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import anthropic
import openai
import pytest

_ACTION_DIR = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("security_scan", _ACTION_DIR / "security-scan.py")
scan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scan)


class _FakeAnthropicMessages:
    def __init__(self, response):
        self._response = response

    def create(self, **kwargs):
        return self._response


class _FakeAnthropicClient:
    def __init__(self, response, **kwargs):
        self.messages = _FakeAnthropicMessages(response)


def _anthropic_response(text, stop_reason="end_turn"):
    content = [SimpleNamespace(text=text)] if text else []
    return SimpleNamespace(content=content, stop_reason=stop_reason)


def test_call_claude_raises_on_max_tokens_truncation(monkeypatch):
    response = _anthropic_response('{"findings": [{"severity": "critical"', stop_reason="max_tokens")
    monkeypatch.setattr(
        anthropic, "Anthropic",
        lambda **kw: _FakeAnthropicClient(response))
    with pytest.raises(RuntimeError, match="max_tokens"):
        scan.call_claude("key", "app", "codebase")


def test_call_claude_raises_on_empty_completion(monkeypatch):
    response = _anthropic_response("", stop_reason="refusal")
    monkeypatch.setattr(
        anthropic, "Anthropic",
        lambda **kw: _FakeAnthropicClient(response))
    with pytest.raises(RuntimeError, match="empty completion"):
        scan.call_claude("key", "app", "codebase")


def test_call_claude_returns_content_on_a_clean_completion(monkeypatch):
    response = _anthropic_response('{"findings": []}', stop_reason="end_turn")
    monkeypatch.setattr(
        anthropic, "Anthropic",
        lambda **kw: _FakeAnthropicClient(response))
    assert scan.call_claude("key", "app", "codebase") == '{"findings": []}'


class _FakeOpenAIChoice:
    def __init__(self, content, finish_reason):
        self.message = SimpleNamespace(content=content)
        self.finish_reason = finish_reason


class _FakeOpenAICompletions:
    def __init__(self, choice):
        self._choice = choice
        self.last_kwargs: dict = {}

    def create(self, **kwargs):
        self.last_kwargs = kwargs
        return SimpleNamespace(choices=[self._choice])


class _FakeOpenAIClient:
    def __init__(self, choice, **kwargs):
        self.chat = SimpleNamespace(completions=_FakeOpenAICompletions(choice))


def test_call_openai_raises_on_length_truncation(monkeypatch):
    choice = _FakeOpenAIChoice('{"findings": [{"severity": "critical"', "length")
    monkeypatch.setattr(openai, "OpenAI", lambda **kw: _FakeOpenAIClient(choice))
    with pytest.raises(RuntimeError, match="finish_reason='length'"):
        scan.call_openai("key", "app", "codebase")


def test_call_openai_raises_on_empty_completion(monkeypatch):
    choice = _FakeOpenAIChoice(None, "content_filter")
    monkeypatch.setattr(openai, "OpenAI", lambda **kw: _FakeOpenAIClient(choice))
    with pytest.raises(RuntimeError, match="empty completion"):
        scan.call_openai("key", "app", "codebase")


def test_call_openai_returns_content_on_a_clean_completion(monkeypatch):
    choice = _FakeOpenAIChoice('{"findings": []}', "stop")
    monkeypatch.setattr(openai, "OpenAI", lambda **kw: _FakeOpenAIClient(choice))
    assert scan.call_openai("key", "app", "codebase") == '{"findings": []}'


def test_call_openai_never_sends_max_tokens(monkeypatch):
    """Reasoning models reject `max_tokens` outright with a 400.

    This file's OpenAI call carried `max_tokens=4096` for as long as the pin was
    `gpt-4o`, which is not a reasoning model. Bumping the pin without moving to
    `max_completion_tokens` would have 400'd every openai-provider scan on the first
    run — so this is the regression test for the parameter, not for the pin.

    The budget must also be far larger than the visible output wanted, because internal
    reasoning tokens are charged against it; a too-small budget returns empty content,
    which the guards above would then correctly and permanently raise on."""
    client = _FakeOpenAIClient(_FakeOpenAIChoice('{"findings": []}', "stop"))
    monkeypatch.setattr(openai, "OpenAI", lambda **kw: client)
    scan.call_openai("key", "app", "codebase")

    sent = client.chat.completions.last_kwargs
    assert "max_tokens" not in sent, "reasoning models 400 on max_tokens"
    assert sent["max_completion_tokens"] >= 16384
    assert sent["model"] == scan._OPENAI_MODEL
