"""Tests for the adversarial-review gate's three-state decision.

Every repo that consumes this action makes `gate` a required, fails-closed
status check, so the cost of each result is asymmetric and worth stating:

  a wrong `blocked`  freezes every merge in the repo until a human intervenes
  a wrong `clear`    merges a change nobody reviewed, silently

The degraded path is the one that had never been exercised by a test before
this file existed, and it is the one that decides between those two costs. It
is covered here from both directions: the pass it must allow, and each nearby
state it must NOT collapse into a pass.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

_MODULE_PATH = Path(__file__).parent / "gate.py"
_spec = importlib.util.spec_from_file_location("adversarial_review_gate", _MODULE_PATH)
gate = importlib.util.module_from_spec(_spec)
# Registered before execution: the module defines dataclasses, and
# `@dataclass` resolves annotations through `sys.modules[cls.__module__]`.
sys.modules[_spec.name] = gate
_spec.loader.exec_module(gate)


def reviewer(name, *, required=True, result="success", has_critical="false", outcome="reviewed"):
    return gate.Reviewer(
        name=name,
        required=required,
        result=result,
        has_critical=has_critical,
        outcome=outcome,
    )


def both(claude, openai):
    return gate.evaluate([claude, openai])


NOT_ASKED = dict(required=False, result="skipped", has_critical="", outcome="")
ERRORED = dict(result="failure", has_critical="", outcome="")
CANCELLED = dict(result="cancelled", has_critical="", outcome="")
FAILED_OPEN = dict(result="success", has_critical="false", outcome="api-error")
FOUND_CRITICAL = dict(result="success", has_critical="true", outcome="reviewed")


# ── The fix: one provider down must degrade, not freeze ───────────────────────

def test_one_reviewer_errors_and_the_other_is_clear_passes_degraded():
    # The whole point. A provider outage used to block here, on a PR that a
    # complete review had already cleared.
    decision = both(reviewer("claude", **ERRORED), reviewer("openai"))
    assert decision.result == gate.DEGRADED
    assert decision.blocks is False
    assert decision.reason == "reviewer-unavailable"


def test_degraded_names_the_reviewer_that_did_not_answer():
    # A degraded pass that does not say who was missing is indistinguishable
    # from a full pass to everyone downstream of it.
    decision = both(reviewer("claude", **ERRORED), reviewer("openai"))
    assert any("claude" in m and "::warning::" in m for m in decision.messages)


def test_either_reviewer_can_be_the_one_that_is_down():
    decision = both(reviewer("claude"), reviewer("openai", **ERRORED))
    assert decision.result == gate.DEGRADED


def test_a_cancelled_job_degrades_the_same_way_a_failed_one_does():
    decision = both(reviewer("claude", **CANCELLED), reviewer("openai"))
    assert decision.result == gate.DEGRADED


def test_a_reviewer_that_failed_open_does_not_count_as_a_review():
    # `has_critical=false` from a fail-open is not a verdict. If it were counted
    # as one, a run where both providers were unreachable would report `clear`.
    decision = both(reviewer("claude", **FAILED_OPEN), reviewer("openai"))
    assert decision.result == gate.DEGRADED
    assert decision.states["claude"] == gate.FAILED_OPEN


# ── Negative controls: the states a degraded pass must NOT swallow ────────────

def test_no_reviewer_completes_blocks():
    # The genuine "the gate could not run" state. This must never collapse into
    # a pass — with no verdict from anyone there is no evidence either way.
    decision = both(reviewer("claude", **ERRORED), reviewer("openai", **ERRORED))
    assert decision.result == gate.BLOCKED
    assert decision.reason == "no-reviewer-completed"


def test_single_provider_repo_still_blocks_when_its_reviewer_errors():
    # With `run-openai` off there is no second opinion to fall back to, so the
    # degraded path must not apply. This is the configuration most consumers
    # run, and it is exactly where a wrong `clear` would be worst.
    decision = both(reviewer("claude", **ERRORED), reviewer("openai", **NOT_ASKED))
    assert decision.result == gate.BLOCKED
    assert decision.reason == "no-reviewer-completed"


def test_critical_blocks_even_when_the_other_reviewer_is_clear():
    decision = both(reviewer("claude", **FOUND_CRITICAL), reviewer("openai"))
    assert decision.result == gate.BLOCKED
    assert decision.reason == "critical-findings"


def test_critical_blocks_even_when_the_other_reviewer_is_down():
    # The dangerous composition: half the evidence is missing and the half that
    # arrived says stop. "Degraded" must not outrank a finding.
    decision = both(reviewer("claude", **ERRORED), reviewer("openai", **FOUND_CRITICAL))
    assert decision.result == gate.BLOCKED
    assert decision.reason == "critical-findings"


def test_a_critical_from_a_reviewer_that_was_not_required_still_blocks():
    # Not being *required* to review is a reason not to demand a verdict, never
    # a reason to discard one that arrived saying the change is unsafe.
    decision = both(
        reviewer("claude", required=False, result="success", has_critical="true", outcome="reviewed"),
        reviewer("openai", **NOT_ASKED),
    )
    assert decision.result == gate.BLOCKED
    assert decision.reason == "critical-findings"


def test_a_reviewer_asked_to_run_that_was_skipped_blocks():
    # A skip is a configuration fault (missing key, wrong `if`), not an outage.
    # No other reviewer's verdict makes an unconfigured gate safe, so this does
    # not degrade even though a complete review is sitting right next to it.
    decision = both(
        reviewer("claude", result="skipped", has_critical="", outcome=""),
        reviewer("openai"),
    )
    assert decision.result == gate.BLOCKED
    assert decision.reason == "reviewer-skipped"


def test_success_without_a_verdict_is_not_a_pass():
    # A job that completes but publishes no `has_critical` decided nothing.
    # Reading the empty string as "false" would pass the PR on an absence.
    decision = both(
        reviewer("claude", result="success", has_critical="", outcome=""),
        reviewer("openai", **NOT_ASKED),
    )
    assert decision.states["claude"] == gate.ERRORED
    assert decision.result == gate.BLOCKED


def test_an_unrecognised_job_result_fails_safe():
    decision = both(
        reviewer("claude", result="something-new", has_critical="", outcome=""),
        reviewer("openai", **NOT_ASKED),
    )
    assert decision.states["claude"] == gate.ERRORED
    assert decision.result == gate.BLOCKED


# ── The states that should pass cleanly ───────────────────────────────────────

def test_both_reviewers_clear_is_clear_not_degraded():
    decision = both(reviewer("claude"), reviewer("openai"))
    assert decision.result == gate.CLEAR_RESULT
    assert decision.reason == "all-reviewers-clear"


def test_single_provider_repo_is_clear_when_its_reviewer_is_clear():
    decision = both(reviewer("claude"), reviewer("openai", **NOT_ASKED))
    assert decision.result == gate.CLEAR_RESULT


def test_nothing_to_review_is_a_clean_pass_not_a_degraded_one():
    # An empty diff is not reduced coverage; there was nothing to cover.
    decision = both(
        reviewer("claude", outcome="no-diff"),
        reviewer("openai", outcome="no-diff"),
    )
    assert decision.result == gate.CLEAR_RESULT


def test_fork_and_bot_prs_are_not_required():
    decision = both(reviewer("claude", **NOT_ASKED), reviewer("openai", **NOT_ASKED))
    assert decision.result == gate.NOT_REQUIRED_RESULT
    assert decision.blocks is False


def test_an_older_reviewer_action_that_reports_no_outcome_passes_but_says_so():
    # Backward compatibility with a pin that predates the `outcome` output. It
    # counts as a review — the alternative would freeze every consumer that has
    # not bumped — but the doubt is stated rather than hidden.
    decision = both(
        reviewer("claude", outcome=""),
        reviewer("openai", **NOT_ASKED),
    )
    assert decision.result == gate.CLEAR_RESULT
    assert decision.states["claude"] == gate.UNKNOWN_OUTCOME
    assert any("older pinned reviewer action" in m for m in decision.messages)


# ── Env plumbing ──────────────────────────────────────────────────────────────

def test_build_reviewers_reads_the_workflow_env(monkeypatch):
    for key in (
        "IS_DEPENDABOT", "IS_FORK", "RUN_OPENAI",
        "CLAUDE_RESULT", "CLAUDE_HAS_CRITICAL", "CLAUDE_OUTCOME",
        "OPENAI_RESULT", "OPENAI_HAS_CRITICAL", "OPENAI_OUTCOME",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("RUN_OPENAI", "true")
    monkeypatch.setenv("CLAUDE_RESULT", "failure")
    monkeypatch.setenv("OPENAI_RESULT", "success")
    monkeypatch.setenv("OPENAI_HAS_CRITICAL", "false")
    monkeypatch.setenv("OPENAI_OUTCOME", "reviewed")

    decision = gate.evaluate(gate.build_reviewers())
    assert decision.result == gate.DEGRADED


def test_run_openai_absent_means_openai_is_not_required(monkeypatch):
    for key in (
        "IS_DEPENDABOT", "IS_FORK", "RUN_OPENAI",
        "CLAUDE_RESULT", "CLAUDE_HAS_CRITICAL", "CLAUDE_OUTCOME",
        "OPENAI_RESULT", "OPENAI_HAS_CRITICAL", "OPENAI_OUTCOME",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("CLAUDE_RESULT", "success")
    monkeypatch.setenv("CLAUDE_HAS_CRITICAL", "false")
    monkeypatch.setenv("CLAUDE_OUTCOME", "reviewed")

    reviewers = gate.build_reviewers()
    assert [r.required for r in reviewers] == [True, False]
    assert gate.evaluate(reviewers).result == gate.CLEAR_RESULT


@pytest.mark.parametrize("bad", ["TRUE", "yes", "1", "unknown", "False"])
def test_an_unrecognised_has_critical_value_exits_rather_than_guessing(bad):
    with pytest.raises(SystemExit) as exc:
        gate._validate_has_critical([reviewer("claude", has_critical=bad)])
    assert exc.value.code == 1


@pytest.mark.parametrize("good", ["true", "false", ""])
def test_the_three_recognised_has_critical_values_are_accepted(good):
    # Negative control for the check above: if it ever rejects everything, the
    # gate blocks every PR in every consuming repo and the test above still passes.
    gate._validate_has_critical([reviewer("claude", has_critical=good)])


def test_env_values_are_stripped_before_they_are_compared(monkeypatch):
    # A trailing newline from a `${{ }}` substitution must not be read as an
    # unrecognised verdict and freeze the repo.
    for key in ("IS_DEPENDABOT", "IS_FORK", "RUN_OPENAI",
                "OPENAI_RESULT", "OPENAI_HAS_CRITICAL", "OPENAI_OUTCOME"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("CLAUDE_RESULT", "success\n")
    monkeypatch.setenv("CLAUDE_HAS_CRITICAL", " false ")
    monkeypatch.setenv("CLAUDE_OUTCOME", "reviewed\n")

    reviewers = gate.build_reviewers()
    gate._validate_has_critical(reviewers)
    assert gate.evaluate(reviewers).result == gate.CLEAR_RESULT


def test_main_exits_nonzero_only_when_blocked(monkeypatch, tmp_path):
    output = tmp_path / "out"
    summary = tmp_path / "summary"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv("RUN_OPENAI", "true")
    monkeypatch.setenv("CLAUDE_RESULT", "failure")
    monkeypatch.setenv("CLAUDE_HAS_CRITICAL", "")
    monkeypatch.setenv("CLAUDE_OUTCOME", "")
    monkeypatch.setenv("OPENAI_RESULT", "success")
    monkeypatch.setenv("OPENAI_HAS_CRITICAL", "false")
    monkeypatch.setenv("OPENAI_OUTCOME", "reviewed")

    gate.main()  # degraded — must not raise SystemExit

    written = output.read_text()
    assert "result=degraded" in written
    assert "degraded=true" in written
    assert "unavailable=claude" in written
    assert "DEGRADED" in summary.read_text()


def test_main_exits_one_when_no_reviewer_completed(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out"))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary"))
    monkeypatch.setenv("RUN_OPENAI", "true")
    monkeypatch.setenv("CLAUDE_RESULT", "failure")
    monkeypatch.setenv("CLAUDE_HAS_CRITICAL", "")
    monkeypatch.setenv("CLAUDE_OUTCOME", "")
    monkeypatch.setenv("OPENAI_RESULT", "failure")
    monkeypatch.setenv("OPENAI_HAS_CRITICAL", "")
    monkeypatch.setenv("OPENAI_OUTCOME", "")

    with pytest.raises(SystemExit) as exc:
        gate.main()
    assert exc.value.code == 1
