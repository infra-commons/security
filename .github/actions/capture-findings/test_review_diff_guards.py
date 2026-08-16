"""Tests for review_diff()'s empty/truncated-completion guard.

This is the CRITICAL-only gate for post-merge diffs (see capture.py's module
docstring). security#109 added the guard — an empty or truncated completion
must raise rather than let parse_findings() silently degrade to `[]`, which
would read as "job passes, nothing filed" on a diff that was never actually
reviewed — but shipped no tests for it. These close that gap, mirroring the
same guard's tests in the sibling adversarial-review action
(test_adversarial_review.py's "Anthropic completion guards" section).
"""
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

_ACTION_DIR = Path(__file__).resolve().parent
# Load by path rather than `import capture`, same idiom as test_repo_context.py
# and test_suppression_matching.py in this directory (the module has no package).
_spec = importlib.util.spec_from_file_location("capture", _ACTION_DIR / "capture.py")
capture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(capture)


def _fake_anthropic(monkeypatch, *, content_blocks, stop_reason="end_turn"):
    """Install a fake Anthropic client returning a single chosen message."""
    message = SimpleNamespace(content=content_blocks, stop_reason=stop_reason)

    class _Messages:
        def create(self, **kwargs):
            _Messages.kwargs = kwargs
            return message

    class _Client:
        def __init__(self, api_key=None, timeout=None):
            self.messages = _Messages()

    import anthropic

    monkeypatch.setattr(anthropic, "Anthropic", _Client)
    return _Messages


def test_review_diff_returns_content_on_success(monkeypatch):
    _fake_anthropic(monkeypatch, content_blocks=[SimpleNamespace(text='{"findings": []}')])
    out = capture.review_diff("k", "diff", "ctx", "")
    assert "findings" in out


def test_review_diff_empty_completion_raises_rather_than_reading_as_clean(monkeypatch):
    # The failure this guards: message.content comes back an empty list, content
    # resolves to "", parse_findings("") logs a warning and returns [] — the
    # CRITICAL gate would then pass having reviewed nothing.
    _fake_anthropic(monkeypatch, content_blocks=[])
    with pytest.raises(RuntimeError, match="empty completion"):
        capture.review_diff("k", "diff", "ctx", "")


def test_review_diff_whitespace_only_completion_raises(monkeypatch):
    _fake_anthropic(monkeypatch, content_blocks=[SimpleNamespace(text="   \n  ")])
    with pytest.raises(RuntimeError, match="empty completion"):
        capture.review_diff("k", "diff", "ctx", "")


def test_review_diff_truncated_completion_raises(monkeypatch):
    _fake_anthropic(
        monkeypatch,
        content_blocks=[SimpleNamespace(text='{"findings": [{"severity": "CRITICAL"')],
        stop_reason="max_tokens",
    )
    with pytest.raises(RuntimeError, match="token budget"):
        capture.review_diff("k", "diff", "ctx", "")
