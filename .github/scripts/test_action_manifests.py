"""Tests for the composite action manifest context checker.

The assertions that matter here are the negative ones. A checker that goes green
on this repo proves nothing on its own — the repo was green, by every check it
had, on the day it shipped a manifest no runner could load. So the load-bearing
tests are the ones that pin the checker to the exact string that broke
(`test_rejects_the_2026_08_27_regression_verbatim`) and to the shapes a future
edit might slip past it.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_action_manifests as check  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]

# The literal text of the description that broke every caller of
# weekly-security-scan/v1 between 2026-08-27 and its fix. Kept verbatim so the
# negative control cannot quietly stop testing the real thing.
REGRESSION_2026_08_27 = (
    "  run-degraded:\n"
    "    description: >-\n"
    "      Pass the caller's own job outcomes, e.g.\n"
    "      `${{ contains(needs.*.result, 'failure') || "
    "contains(needs.*.result, 'cancelled') }}`.\n"
)


# ── the negative controls ─────────────────────────────────────────────────────


def test_rejects_the_2026_08_27_regression_verbatim():
    violations = check.scan_text(REGRESSION_2026_08_27, "action.yml")
    assert [v.context for v in violations] == ["needs"]
    assert violations[0].line == 4


def test_the_regression_is_caught_inside_a_description_not_only_in_a_run_block():
    """The break was in prose. Backticks and `description:` are not a shield —
    the runner template-evaluates the manifest's text either way."""
    in_prose = check.scan_text(
        "inputs:\n  x:\n    description: \"see `${{ needs.a.result }}`\"\n", "action.yml"
    )
    in_code = check.scan_text(
        "runs:\n  steps:\n    - run: echo ${{ needs.a.result }}\n", "action.yml"
    )
    assert [v.context for v in in_prose] == ["needs"]
    assert [v.context for v in in_code] == ["needs"]


def test_rejects_the_other_workflow_only_contexts():
    for context in ("jobs", "matrix", "strategy", "job", "secrets", "vars"):
        violations = check.scan_text("${{ %s.thing }}" % context, "action.yml")
        assert [v.context for v in violations] == [context], context


def test_a_repo_with_no_manifests_is_an_error_not_a_pass(tmp_path, monkeypatch):
    """A checker that finds nothing to check must not report success — that is
    the shape that lets a rename silently disarm a guard."""
    script = REPO_ROOT / ".github" / "scripts" / "check_action_manifests.py"
    empty = tmp_path / "repo" / ".github" / "scripts"
    empty.mkdir(parents=True)
    (empty / script.name).write_text(script.read_text(encoding="utf-8"), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(empty / script.name)], capture_output=True, text=True
    )
    assert result.returncode == 2, result.stderr


def test_main_exits_non_zero_on_a_violation(tmp_path):
    script = REPO_ROOT / ".github" / "scripts" / "check_action_manifests.py"
    root = tmp_path / "repo"
    (root / ".github" / "scripts").mkdir(parents=True)
    (root / ".github" / "actions" / "broken").mkdir(parents=True)
    (root / ".github" / "scripts" / script.name).write_text(
        script.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (root / ".github" / "actions" / "broken" / "action.yml").write_text(
        REGRESSION_2026_08_27, encoding="utf-8"
    )
    result = subprocess.run(
        [sys.executable, str(root / ".github" / "scripts" / script.name)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "needs" in result.stderr
    assert "action.yml" in result.stderr


# ── the positive cases, so the guard is not a blanket ban on expressions ──────


def test_accepts_the_contexts_a_composite_manifest_may_read():
    text = (
        "${{ inputs.mode }} ${{ steps.x.outputs.y }} ${{ github.repository }} "
        "${{ env.FOO }} ${{ runner.os }}\n"
    )
    assert check.scan_text(text, "action.yml") == []


def test_a_function_call_is_not_read_as_a_context():
    """`contains(...)` and `format(...)` are functions. Only an identifier at the
    head of a property or index chain is a context reference."""
    assert check.scan_text("${{ contains(inputs.tags, 'x') }}", "action.yml") == []
    assert check.scan_text("${{ format('{0}.{1}', inputs.a, inputs.b) }}", "action.yml") == []
    assert check.scan_text("${{ hashFiles('**/*.lock') }}", "action.yml") == []


def test_a_dotted_string_literal_is_not_read_as_a_context():
    assert check.scan_text("${{ format('a.b', inputs.x) }}", "action.yml") == []


def test_an_index_chain_is_read_as_a_context():
    assert [v.context for v in check.scan_text("${{ needs['a'].result }}", "action.yml")] == [
        "needs"
    ]


def test_one_expression_naming_a_bad_context_twice_is_one_violation():
    violations = check.scan_text(
        "${{ contains(needs.*.result, 'failure') || contains(needs.*.result, 'cancelled') }}",
        "action.yml",
    )
    assert len(violations) == 1


# ── this repo, now ────────────────────────────────────────────────────────────


def test_every_manifest_in_this_repo_is_clean():
    violations = check.scan_repo(REPO_ROOT)
    assert violations == [], "\n".join(str(v) for v in violations)


def test_the_checker_actually_sees_this_repos_manifests():
    """Guards the denominator: a green sweep over an empty file list is not a pass.
    Every composite action directory must contribute a manifest."""
    manifests = check.manifest_paths(REPO_ROOT)
    action_dirs = sorted(
        p.name for p in (REPO_ROOT / ".github" / "actions").iterdir() if p.is_dir()
    )
    assert [p.parent.name for p in manifests] == action_dirs
    assert len(manifests) >= 7
