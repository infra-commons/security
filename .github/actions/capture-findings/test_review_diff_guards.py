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


# ── Thinking-block responses (2026-08-31) ───────────────────────────────────────
#
# claude-sonnet-5 returns a ThinkingBlock FIRST, and it has no `.text`, so the
# previous `content[0].text` raised `AttributeError: 'ThinkingBlock' object has
# no attribute 'text'`. That took capture-findings down at every caller two
# minutes after the moving tag delivered the model swap, and the same idiom was
# live in three other composites here. Thinking is not emitted on every call, so
# it presents as flakiness rather than as a break — which is why the regression
# is pinned explicitly rather than left to the empty-completion guard above to
# catch incidentally.


def _thinking_block(text="deliberating"):
    """Shaped like the SDK's ThinkingBlock: carries `.thinking`, never `.text`."""
    return SimpleNamespace(type="thinking", thinking=text)


def _text_block(text):
    return SimpleNamespace(type="text", text=text)


def test_review_diff_reads_past_a_leading_thinking_block(monkeypatch):
    _fake_anthropic(
        monkeypatch,
        content_blocks=[_thinking_block(), _text_block('{"findings": []}')],
    )
    assert "findings" in capture.review_diff("k", "diff", "ctx", "")


def test_review_diff_joins_text_split_across_blocks(monkeypatch):
    # Taking the first text block rather than joining would silently truncate the
    # review, and a shorter findings list reads as a cleaner diff — not an error.
    _fake_anthropic(
        monkeypatch,
        content_blocks=[_thinking_block(), _text_block('{"find'), _text_block('ings": []}')],
    )
    assert capture.review_diff("k", "diff", "ctx", "") == '{"findings": []}'


def test_review_diff_raises_when_the_response_is_thinking_only(monkeypatch):
    # Fail closed: no text block at all must not read as "reviewed, nothing found".
    _fake_anthropic(monkeypatch, content_blocks=[_thinking_block()])
    with pytest.raises(RuntimeError, match="empty completion"):
        capture.review_diff("k", "diff", "ctx", "")


# ── parse_findings: the other half of the same guard ────────────────────────────
#
# review_diff() has failed closed on an empty/truncated completion since
# security#109. parse_findings() did not: both failure paths returned `[]` after a
# stderr warning, which downstream reads as a clean review. On 2026-09-02 meta#1280
# merged carrying a HIGH and a MEDIUM both PR-time reviewers had reported, and this
# pass logged `Parsed 0` and filed nothing — a genuine zero nothing could confirm.

def test_output_with_no_json_object_raises():
    with pytest.raises(capture.ReviewParseError, match="no JSON object"):
        capture.parse_findings("I reviewed the diff and found nothing of concern.")


def test_malformed_json_raises():
    with pytest.raises(capture.ReviewParseError, match="JSON parse error"):
        capture.parse_findings('{"findings": [ {"severity": "HIGH",, } ]}')


def test_an_object_without_a_findings_list_raises():
    # SYSTEM_PROMPT is explicit that an empty result is `{"findings": []}`, so an
    # object lacking the key means the model answered a different question.
    with pytest.raises(capture.ReviewParseError, match="no `findings` list"):
        capture.parse_findings('{"summary": "looks fine"}')


def test_an_explicitly_empty_findings_list_is_not_an_error():
    """The one shape that legitimately means "reviewed, nothing found"."""
    findings, dropped = capture.parse_findings('{"findings": []}')
    assert findings == []
    assert dropped == 0


def test_prose_containing_a_brace_before_the_json_is_rescued():
    """The recoverable shape that must NOT go red: the greedy slice dies here, and
    failing closed on it would red-run every caller over a brace in a preamble."""
    text = (
        'Note: the workflow interpolates an expression unsafely: {0} is unquoted.\n'
        '{"findings": [{"severity": "HIGH", "location": "a.py:1", '
        '"title": "t", "description": "d", "category": "injection"}]}'
    )
    findings, dropped = capture.parse_findings(text)
    assert [f["severity"] for f in findings] == ["HIGH"]
    assert dropped == 0


def test_a_code_fenced_object_still_parses():
    findings, _ = capture.parse_findings('```json\n{"findings": []}\n```')
    assert findings == []


def test_an_unusable_severity_is_dropped_and_counted():
    """The count is the instrumentation: without it, `{"findings": []}` and a list
    whose severities were all rejected both render as `Parsed 0`."""
    text = (
        '{"findings": ['
        '{"severity": "INFO", "location": "a.py:1", "title": "t", '
        '"description": "d", "category": "infra"},'
        '{"severity": "HIGH", "location": "b.py:2", "title": "u", '
        '"description": "d", "category": "infra"}]}'
    )
    findings, dropped = capture.parse_findings(text)
    assert [f["severity"] for f in findings] == ["HIGH"]
    assert dropped == 1
