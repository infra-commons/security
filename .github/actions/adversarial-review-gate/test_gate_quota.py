"""Tests for the gate's quota-exhaustion escalation: fail open once, then block.

This is the only place the gate tightens on a *repeat*, so the tests that matter
most are the ones proving it tightens on the right repeat and nothing else:

  a wrong block on a rate limit   freezes every merge during an ordinary outage,
                                  which is the failure the fail-open posture exists
                                  to prevent
  a wrong pass on an exhausted    merges unreviewed changes, green, for the rest
  budget                          of the billing period

A test that only checked "quota blocks" would pass while the gate blocked on
every transient error too. So each escalation assertion here has a sibling that
holds the neighbouring state to the old behaviour.
"""
import importlib.util
import sys
from pathlib import Path

_MODULE_PATH = Path(__file__).parent / "gate.py"
_spec = importlib.util.spec_from_file_location("adversarial_review_gate_quota", _MODULE_PATH)
gate = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = gate
_spec.loader.exec_module(gate)


def reviewer(name, *, required=True, result="success", has_critical="false", outcome="reviewed"):
    return gate.Reviewer(
        name=name, required=required, result=result,
        has_critical=has_critical, outcome=outcome,
    )


QUOTA = dict(result="success", has_critical="false", outcome="quota-exhausted")
RATE_LIMIT = dict(result="success", has_critical="false", outcome="api-error")
NOT_ASKED = dict(required=False, result="skipped", has_critical="", outcome="")


def only_claude(marker_open, **kw):
    """Single-provider repo — the common fleet configuration."""
    return gate.evaluate(
        [reviewer("claude", **kw), reviewer("openai", **NOT_ASKED)],
        quota_marker_open=marker_open,
    )


# ── the escalation itself ─────────────────────────────────────────────────────


def test_the_first_quota_exhausted_pr_passes_degraded():
    """Holding up the change the moment billing lapses is the cost the fail-open
    posture exists to avoid. The first one still goes through."""
    decision = only_claude(False, **QUOTA)
    assert decision.result == gate.DEGRADED
    assert decision.reason == "quota-exhausted-first"
    assert not decision.blocks


def test_the_second_quota_exhausted_pr_is_blocked():
    """The tracking issue from the first is still open, so nothing has been
    topped up and nothing has been reviewed since."""
    decision = only_claude(True, **QUOTA)
    assert decision.result == gate.BLOCKED
    assert decision.reason == "quota-exhausted-repeat"
    assert decision.blocks


def test_the_block_message_says_what_actually_clears_it():
    """'Re-run once the provider is available' is useless advice for a spend cap.
    An alarm nobody can act on trains the reader to ignore it."""
    decision = only_claude(True, **QUOTA)
    text = " ".join(decision.messages)
    assert "does not clear by itself" in text
    assert "top up" in text.lower()
    assert "close the tracking issue" in text.lower()


# ── the neighbouring states it must NOT collapse into ─────────────────────────


def test_a_repeat_rate_limit_still_passes_degraded():
    """THE test. An ordinary provider outage lasts many PRs; escalating it the
    way quota escalates would freeze every consuming repo, which is precisely
    what the three-state gate was built to prevent."""
    decision = only_claude(True, **RATE_LIMIT)
    assert decision.result == gate.DEGRADED
    assert decision.reason == "no-reviewer-produced-a-verdict"
    assert not decision.blocks


def test_quota_does_not_block_when_another_reviewer_actually_reviewed():
    """Narrow by design: if a second provider produced a verdict, the change WAS
    reviewed and blocking buys nothing — the same reasoning as reviewer-unavailable."""
    decision = gate.evaluate(
        [reviewer("claude", **QUOTA), reviewer("openai", outcome="reviewed")],
        quota_marker_open=True,
    )
    assert decision.result == gate.DEGRADED
    assert not decision.blocks


def test_quota_on_a_fork_or_bot_pr_is_not_required_and_does_not_block():
    decision = gate.evaluate(
        [reviewer("claude", required=False, **QUOTA), reviewer("openai", **NOT_ASKED)],
        quota_marker_open=True,
    )
    assert not decision.blocks


def test_a_critical_still_outranks_an_exhausted_quota():
    """A finding is a finding regardless of what the other reviewer's billing did."""
    decision = gate.evaluate(
        [reviewer("claude", has_critical="true"), reviewer("openai", **QUOTA)],
        quota_marker_open=False,
    )
    assert decision.result == gate.BLOCKED
    assert decision.reason == "critical-findings"


def test_a_crash_is_still_a_crash_not_a_quota_block():
    """No reviewer completed at all — no PR comment, no record. That must keep
    reporting as `no-reviewer-completed`, not be relabelled as a quota repeat."""
    decision = only_claude(True, result="failure", has_critical="", outcome="")
    assert decision.result == gate.BLOCKED
    assert decision.reason == "no-reviewer-completed"


# ── the default, and the classification ───────────────────────────────────────


def test_the_default_marker_state_preserves_todays_behaviour():
    """A caller that has not wired the lookup must not start blocking on a
    signal it never supplies."""
    decision = gate.evaluate([reviewer("claude", **QUOTA), reviewer("openai", **NOT_ASKED)])
    assert not decision.blocks


def test_quota_exhausted_is_classified_distinctly_not_as_an_unknown_outcome():
    """Guards the release-ordering hazard. `UNKNOWN_OUTCOME` counts as a
    completed review (deliberately, for older pinned actions), so if this
    mapping were removed a quota-exhausted run would read as CLEAR — worse than
    the behaviour being replaced."""
    assert gate.classify(reviewer("claude", **QUOTA)) == gate.QUOTA_EXHAUSTED
    assert gate.classify(reviewer("claude", **QUOTA)) != gate.UNKNOWN_OUTCOME
    assert gate.QUOTA_EXHAUSTED not in gate._VERDICT


def test_quota_counts_as_reduced_coverage_in_the_unavailable_output():
    assert gate.QUOTA_EXHAUSTED in gate._MISSING


# ── wiring ────────────────────────────────────────────────────────────────────


def _run_main(monkeypatch, tmp_path, env):
    out = tmp_path / "out"
    out.write_text("")
    for key in ("CLAUDE_RESULT", "CLAUDE_HAS_CRITICAL", "CLAUDE_OUTCOME",
                "OPENAI_RESULT", "OPENAI_HAS_CRITICAL", "OPENAI_OUTCOME",
                "RUN_OPENAI", "IS_FORK", "IS_DEPENDABOT", "QUOTA_MARKER_OPEN"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    code = 0
    try:
        gate.main()
    except SystemExit as exc:
        code = exc.code or 0
    return code, dict(
        line.split("=", 1) for line in out.read_text().splitlines() if "=" in line
    )


_QUOTA_ENV = {
    "CLAUDE_RESULT": "success",
    "CLAUDE_HAS_CRITICAL": "false",
    "CLAUDE_OUTCOME": "quota-exhausted",
    "OPENAI_RESULT": "skipped",
}


def test_main_publishes_quota_exhausted_so_the_caller_can_open_the_marker(monkeypatch, tmp_path):
    code, outputs = _run_main(monkeypatch, tmp_path, _QUOTA_ENV)
    assert code == 0
    assert outputs["quota_exhausted"] == "true"
    assert outputs["result"] == "degraded"


def test_main_publishes_quota_exhausted_on_the_blocked_path_too(monkeypatch, tmp_path):
    """If the marker were ever closed while the budget is still exhausted, the
    next run has to be able to re-open it rather than reverting to one free
    pass forever."""
    code, outputs = _run_main(
        monkeypatch, tmp_path, {**_QUOTA_ENV, "QUOTA_MARKER_OPEN": "true"}
    )
    assert code == 1
    assert outputs["quota_exhausted"] == "true"
    assert outputs["result"] == "blocked"


def test_main_does_not_claim_quota_on_an_ordinary_review(monkeypatch, tmp_path):
    code, outputs = _run_main(
        monkeypatch, tmp_path,
        {"CLAUDE_RESULT": "success", "CLAUDE_HAS_CRITICAL": "false",
         "CLAUDE_OUTCOME": "reviewed", "OPENAI_RESULT": "skipped"},
    )
    assert code == 0
    assert outputs["quota_exhausted"] == "false"


def test_the_marker_env_var_is_read_and_stripped(monkeypatch, tmp_path):
    code, _ = _run_main(
        monkeypatch, tmp_path, {**_QUOTA_ENV, "QUOTA_MARKER_OPEN": "  true  "}
    )
    assert code == 1, "a padded 'true' must still block, as elsewhere in this gate"
