"""Bind the reusable workflow's gate job to the gate action's contract.

The decision logic above this file is only as good as the values that reach it,
and those come across a YAML boundary no unit test crosses. Every signal the
gate reads is optional at the action's boundary — it has to be, so an older
reviewer pin still works — which means a dropped or misspelled `with:` key
degrades silently into "that reviewer said nothing" instead of failing loudly.

A missing `claude-outcome` would be the worst case: the gate would classify a
fail-open as a real review and report a clean review that never happened.
"""
import re
from pathlib import Path

import pytest
import yaml

_ROOT = Path(__file__).resolve().parents[3]
_WORKFLOW = _ROOT / ".github/workflows/adversarial-review-reusable.yml"
_GATE_ACTION = Path(__file__).parent / "action.yml"
_REVIEW_ACTION = _ROOT / ".github/actions/adversarial-review/action.yml"

_GATE_ACTION_REF = "infra-commons/security/.github/actions/adversarial-review-gate@"


def _load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _gate_step():
    jobs = _load(_WORKFLOW)["jobs"]
    for step in jobs["gate"]["steps"]:
        if _GATE_ACTION_REF in str(step.get("uses", "")):
            return step
    raise AssertionError("the gate job does not call the adversarial-review-gate action")


def test_the_gate_job_uses_the_gate_action():
    step = _gate_step()
    assert step.get("id") == "evaluate", "later steps read steps.evaluate.outputs.*"


def test_every_input_the_gate_action_declares_is_supplied_by_the_workflow():
    # The action cannot mark these required (the openai ones are absent when the
    # second reviewer is off), so nothing but this test notices a dropped key.
    declared = set(_load(_GATE_ACTION)["inputs"])
    supplied = set(_gate_step()["with"])
    assert declared == supplied, f"unwired: {sorted(declared - supplied)}"


def test_each_signal_is_wired_to_the_matching_job_and_not_its_twin():
    # A copy-paste that points `openai-has-critical` at the claude job would
    # make the second reviewer echo the first, and every test above would pass.
    with_block = _gate_step()["with"]
    for reviewer in ("claude", "openai"):
        for key, expr in (
            (f"{reviewer}-result", f"needs.{reviewer}.result"),
            (f"{reviewer}-has-critical", f"needs.{reviewer}.outputs.has_critical"),
            (f"{reviewer}-outcome", f"needs.{reviewer}.outputs.outcome"),
        ):
            assert expr in str(with_block[key]), f"{key} is not wired to {expr}"


def test_both_reviewer_jobs_publish_the_outcome_the_gate_reads():
    # `outcome` is what separates a fail-open from a clean review. A job that
    # does not publish it makes every one of its runs read as UNKNOWN_OUTCOME,
    # which the gate counts as a review.
    jobs = _load(_WORKFLOW)["jobs"]
    for name in ("claude", "openai"):
        outputs = jobs[name].get("outputs", {})
        assert "outcome" in outputs, f"the {name} job does not publish `outcome`"
        assert "outputs.outcome" in str(outputs["outcome"])


def _emitted_outcomes() -> set:
    script = (_ROOT / ".github/actions/adversarial-review/adversarial-review.py").read_text()
    return set(re.findall(r'set_github_output\("outcome", "([a-z-]+)"\)', script))


def test_the_reviewer_action_publishes_outcome_and_the_script_sets_it():
    assert "outcome" in _load(_REVIEW_ACTION)["outputs"]
    # Every path that leaves main() having written has_critical must also say
    # what it did; a path that writes one and not the other is the silent case.
    assert _emitted_outcomes() == {
        "reviewed", "no-diff", "api-error", "quota-exhausted"
    }, _emitted_outcomes()


def test_the_gate_understands_every_outcome_the_reviewer_can_emit():
    """The release-ordering hazard, as an assertion.

    The reviewer and the gate ship as two separate moving tags. If the reviewer
    starts emitting an outcome the gate has no branch for, `classify()` falls
    through to UNKNOWN_OUTCOME — which counts as a *completed review*. A new
    outcome meaning "this was not reviewed" would then read as "reviewed",
    which is worse than the behaviour it replaced and completely silent.

    Pinning both halves of the vocabulary together is what makes that a red
    test here rather than a green merge and a discovery in production.
    """
    gate_source = (_ROOT / ".github/actions/adversarial-review-gate/gate.py").read_text()
    understood = set(re.findall(r'reviewer\.outcome == "([a-z-]+)"', gate_source))
    missing = _emitted_outcomes() - understood
    assert not missing, (
        f"the reviewer emits {sorted(missing)} but the gate has no branch for it, "
        f"so it would be classified as a completed review"
    )


def test_the_degraded_record_step_is_conditioned_on_the_gate_output():
    steps = _load(_WORKFLOW)["jobs"]["gate"]["steps"]
    recorder = [s for s in steps if s.get("name") == "Record a degraded pass"]
    assert recorder, "a degraded pass leaves no durable record"
    condition = str(recorder[0]["if"])
    assert "steps.evaluate.outputs.degraded == 'true'" in condition
    assert "always()" in condition, "the step is skipped unless it runs after a failing step"


def test_the_gate_job_can_file_the_issues_it_creates():
    # Both issue-filing steps run in the gate job; without this permission they
    # fail at runtime and the record the degraded path depends on never appears.
    assert _load(_WORKFLOW)["jobs"]["gate"]["permissions"]["issues"] == "write"


def _step_run(name: str) -> str:
    steps = _load(_WORKFLOW)["jobs"]["gate"]["steps"]
    matches = [s for s in steps if s.get("name") == name]
    assert matches, f"no gate step named {name!r}"
    return str(matches[0]["run"])


# A title is plain text: anyone who can open an issue in the caller repo can write
# one with this exact string, before the gate ever runs, for a PR number they only
# have to guess. If the gate's own "does this already exist" check matches on the
# title alone, the squatter's issue satisfies it, the real issue is never created,
# and closing the squatter's issue afterwards leaves a clean, COMPLETE, empty
# result for anything reading these issues back — see
# infra-commons/meta#566's scripts/merge-ready.py, which does exactly that to
# decide whether a PR merges unread. A title match is not enough; the dedupe must
# also require a label that only this job's own token can attach.
@pytest.mark.parametrize("step_name, label", [
    ("Record a degraded pass", "security:degraded-pass"),
    ("Create tracking issue for critical findings", "security:critical-findings"),
])
def test_the_issue_filing_steps_dedupe_on_a_label_the_step_itself_applies(step_name, label):
    run = _step_run(step_name)
    assert f'LABEL="{label}"' in run, (
        f"{step_name!r} does not assign LABEL={label!r} — the checks below "
        f"read $LABEL, so a missing/renamed assignment would silently defeat them"
    )
    assert 'label:\\"${LABEL}\\"' in run, (
        f"{step_name!r}'s existence check matches on title text alone — "
        f"an issue with the right title but no {label!r} label (which an "
        f"unprivileged issue-opener cannot attach) would satisfy it and "
        f"suppress the real issue"
    )
    assert '--label "$LABEL"' in run, (
        f"{step_name!r} never applies {label!r} to the issue it creates, so "
        f"its own dedupe above could never find its own past issues"
    )


def test_the_degraded_pass_title_still_matches_the_downstream_consumer_contract():
    # infra-commons/meta#566 added a consumer (sharedinfra/scripts/merge-ready.py,
    # `_DEGRADED_ISSUE_TITLE_RE`) that parses the PR number out of this exact
    # title shape. The label-based dedupe added alongside this test must never
    # change the title — that is what keeps the fix backward-compatible with a
    # consumer this repo cannot see or edit from here. If this test goes red,
    # the change belongs in a coordinated PR against sharedinfra, not here.
    run = _step_run("Record a degraded pass")
    assert 'TITLE="[security] Adversarial review passed degraded on PR #${PR_NUMBER}"' in run
