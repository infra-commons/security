"""Repo-wide negative control: no composite may index an LLM response by position.

The defect this exists to stop recurring, in full, because the fix itself is a
one-liner and the reason is the only part worth keeping:

`msg.content[0].text` was the idiom at five call sites across four composite
actions. It is correct only for a model that never emits a non-text block. A
thinking-capable model returns a `ThinkingBlock` first, and it has no `.text`,
so block 0 raises `AttributeError: 'ThinkingBlock' object has no attribute
'text'`. On 2026-08-31 the moving tags delivered a `claude-sonnet-5` swap and
capture-findings started failing at every caller two minutes later.

Three properties made it expensive out of proportion to its size, and each is a
reason to assert the class rather than trust the fix:

1. **It is intermittent.** Thinking is not emitted on every call, so the family
   read as flaky rather than broken — the shape that gets re-run rather than
   diagnosed.
2. **It is silent in one of the four composites.** `daily-health-check` wraps
   both of its call sites in `except Exception`, so the crash degraded to a
   heuristic fallback that looks like a real diagnosis.
3. **It reappears by copy.** Each composite is standalone with no shared import
   path, so the idiom spread by being pasted, and nothing compared them.

This is an AST check, not a grep, so it cannot be satisfied by rewording a
docstring and cannot be fooled by a comment quoting the bad idiom — both of
which a text scan gets wrong, since the fix's own docstrings quote it verbatim.
"""
import ast
from pathlib import Path

import pytest

_ACTIONS = Path(__file__).resolve().parents[1] / "actions"
_REPO = Path(__file__).resolve().parents[2]


def _python_files():
    return sorted(p for p in _ACTIONS.rglob("*.py") if "__pycache__" not in p.parts)


def _positional_content_access(tree):
    """Every `<expr>.content[<int>]` subscript in the tree, as (line, source)."""
    hits = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Subscript):
            continue
        value = node.value
        if not (isinstance(value, ast.Attribute) and value.attr == "content"):
            continue
        index = node.slice
        if isinstance(index, ast.Constant) and isinstance(index.value, int):
            hits.append((node.lineno, ast.unparse(node)))
    return hits


@pytest.mark.parametrize("path", _python_files(), ids=lambda p: p.name)
def test_no_composite_indexes_a_response_content_list_by_position(path):
    hits = _positional_content_access(ast.parse(path.read_text()))
    assert not hits, (
        f"{path.relative_to(_REPO)} indexes a response's content list by position at "
        f"{hits!r}. Select text blocks by type instead — see the _response_text() "
        "helper in this action, and this file's module docstring for why block 0 is "
        "not safe."
    )


def test_the_check_actually_detects_the_defect_it_names():
    """Negative control on the negative control.

    A structural assertion that cannot fail is worse than none, because its green
    runs get believed. Prove this one fires on the exact code that was live.
    """
    live_defect = ast.parse('content = msg.content[0].text if msg.content else ""')
    assert _positional_content_access(live_defect) == [(1, "msg.content[0]")]

    # And that the shipped replacement does not trip it.
    fixed = ast.parse(
        'x = "".join(b.text for b in (blocks or []) '
        'if getattr(b, "type", "text") == "text" and hasattr(b, "text"))'
    )
    assert _positional_content_access(fixed) == []


def test_every_composite_that_calls_anthropic_has_the_shared_helper():
    """The fix is a duplicated idiom, so assert every copy is present.

    These actions have no shared import path — duplication is the architecture
    here — which is exactly how the original defect spread. Naming the expected
    copies makes a new composite that calls Anthropic without one a failing test
    rather than a silent fifth instance.
    """
    expected = {
        "adversarial-review/adversarial-review.py",
        "capture-findings/capture.py",
        "daily-health-check/health-check.py",
        "weekly-security-scan/security-scan.py",
    }
    missing = {
        rel for rel in expected
        if "def _response_text(" not in (_ACTIONS / rel).read_text()
    }
    assert not missing, f"composites missing the _response_text() helper: {sorted(missing)}"
