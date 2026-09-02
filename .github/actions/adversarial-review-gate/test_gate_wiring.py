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
    ("Record that the provider quota is exhausted", "security:quota-exhausted"),
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


# infra-commons/security#81 — the quota marker has the same title-squat exposure
# #80 fixed above, but with one difference: nothing outside this workflow reads it.
# The "Look up the quota tracking issue" step reads back what "Record that the
# provider quota is exhausted" wrote, on the *next* PR, to decide fail-open-once
# vs. block. A squatted, then closed, title-only issue makes the write step skip
# creating the real marker and the read step then sees nothing open — silently
# defeating the one thing this mechanism exists to guarantee (see #81 for the
# full walkthrough). Both sides must require the same label, or the fix on one
# side is invisible to the other.
def test_the_quota_lookup_also_requires_the_label_not_just_the_title():
    run = _step_run("Look up the quota tracking issue")
    assert 'label:\\"${LABEL}\\"' in run, (
        "the lookup step matches on title text alone — a squatted-then-closed "
        "title-only issue would make this read 'open=false' even the run right "
        "after a real exhaustion recorded a properly labelled marker"
    )


def test_the_quota_lookup_and_recorder_agree_on_the_label():
    lookup = _step_run("Look up the quota tracking issue")
    record = _step_run("Record that the provider quota is exhausted")
    lookup_label = re.search(r'LABEL="([^"]+)"', lookup)
    record_label = re.search(r'LABEL="([^"]+)"', record)
    assert lookup_label and record_label, "both steps must assign a LABEL"
    assert lookup_label.group(1) == record_label.group(1), (
        "the read and write sides disagree on the label — a marker written "
        "under one label is invisible to a lookup gated on the other, which "
        "is a silent, permanent fail-open, not a loud one"
    )


def test_the_quota_marker_title_is_identical_on_both_sides():
    lookup = _step_run("Look up the quota tracking issue")
    record = _step_run("Record that the provider quota is exhausted")
    title_re = re.search(r'TITLE="([^"]+)"', lookup)
    assert title_re and title_re.group(1) in record, (
        "the lookup and recorder titles have drifted apart — the lookup would "
        "never find what the recorder writes"
    )


def test_the_quota_recorder_has_no_unlabeled_fallback():
    # Unlike "Record a degraded pass", there is no external, title-only reader of
    # the quota marker to stay backward-compatible with — the only reader is the
    # lookup step above, in this same job, which this fix also gates on the label.
    # A "create without the label if the labelled create fails" fallback here
    # would not preserve compatibility with anything; it would create a durable
    # record the next run's lookup can never find, silently reverting to
    # indefinite fail-open — the exact failure this fix closes. A hard failure
    # of this step (and therefore the job/required check) on that path is the
    # correct, safe-direction behaviour instead, and matches how the sibling
    # "Create tracking issue for critical findings" step already behaves when
    # its own issue-create fails outright.
    run = _step_run("Record that the provider quota is exhausted")
    assert run.count("gh issue create") == 1, (
        "an unlabeled fallback `gh issue create` call would be reachable via "
        "the next run's label-gated lookup only by luck, not by design — see "
        "this test's comment for why that's the wrong failure mode here"
    )


# ── every `gh` call must name the repo explicitly ─────────────────────────────
#
# infra-commons/meta#1092/#1094 (2026-08-27): the quota recorder failed with
# `could not add label: 'security:quota-exhausted' not found`, no tracking issue
# was ever filed, and the gate therefore never converged on "marker open →
# block" — every subsequent run repeated the same broken attempt.
#
# ONE of the two causes was a missing flag. The `gate` job has NO
# `actions/checkout` step (it does not need the source — it reads job outputs
# and files issues), so GITHUB_WORKSPACE is an empty directory. `gh` resolves
# its target repo from `--repo`, then `GH_REPO`, then the git remotes of the
# working directory; with no flag, no `GH_REPO` in this job's env, and no
# checkout, it finds none and dies with "not a git repository". On the
# `gh label create` calls that error was swallowed by their trailing `|| true`,
# so the label was silently never created and the *next* command,
# `gh issue create --label "$LABEL"`, failed on a label nothing had provisioned.
#
# Every other `gh` call in these steps already passed `--repo "$REPO"`; the
# three label creates were the only ones that did not, which is why this read as
# a permissions or provisioning problem rather than the one-flag omission.
#
# CORRECTION (infra-commons/security#149). This comment used to say "the cause
# was one missing flag", and #135 fixed on that basis. It was not the whole
# cause: the same three calls also passed a `--description` of 172/142/142
# characters against GitHub's 100-character cap, so each returned a 422 and
# created nothing whether or not `--repo` was present. That had been true since
# #80/#99 added the descriptions, so these creates had never once succeeded on
# any repo, and #135 could not have restored the label. Both causes reach the
# same end state — label absent, labelled create fails, no marker filed — which
# is why the single-cause account looked complete. It also means the defect was
# unreachable code in the canonical workflow, NOT a provisioning gap in the
# caller repos: no caller was ever required to hand-create these labels, and
# hand-creating them is what masked the defect wherever it had been done. The
# second cause is now covered by
# `test_each_provisioned_label_description_is_within_githubs_limit` below.
#
# This is asserted over every `gh`-using step rather than a fixed list, so a
# step added later is covered without anyone remembering to extend this test.

_GH_CALL_RE = re.compile(r"\bgh\s+[a-z]")
_REPO_FLAG_RE = re.compile(r'--repo\s+"\$\{?REPO\}?"')


def _shell_code(run: str) -> str:
    """`run:` text with whole-line shell comments removed.

    The comments in these steps quote the commands they explain (`gh issue
    create` appears in prose in two of them), so counting `gh` invocations over
    the raw text over-counts and the assertion below would be unfalsifiable.
    """
    return "\n".join(
        line for line in run.splitlines() if not line.strip().startswith("#")
    )


def _gh_steps():
    steps = _load(_WORKFLOW)["jobs"]["gate"]["steps"]
    found = [s for s in steps if _GH_CALL_RE.search(_shell_code(str(s.get("run", ""))))]
    assert len(found) >= 4, (
        f"only {len(found)} `gh`-using gate steps discovered — the lookup, the two "
        f"recorders and the critical-findings step are all expected, so this "
        f"test has stopped covering what it was written to cover"
    )
    return found


@pytest.mark.parametrize("step", _gh_steps(), ids=lambda s: s["name"])
def test_every_gh_call_in_the_gate_job_names_the_repo_explicitly(step):
    code = _shell_code(str(step["run"]))
    calls = len(_GH_CALL_RE.findall(code))
    flagged = len(_REPO_FLAG_RE.findall(code))
    assert calls == flagged, (
        f"{step['name']!r} makes {calls} `gh` call(s) but only {flagged} pass "
        f'--repo "$REPO". The gate job never checks out, so a bare `gh` has no '
        f"git remote to infer a repo from and fails with 'not a git repository' "
        f"— behind `|| true` that failure is silent (infra-commons/meta#1092)"
    )


# Nothing else asserts these calls exist at all. Without them the gate depends on
# each of 13+ caller repos having been given the label by hand, which is exactly
# the state that produced #1092 — and the failure is invisible until a provider's
# budget actually lapses, which may be months after the regression lands.
@pytest.mark.parametrize("step_name", [
    "Record that the provider quota is exhausted",
    "Record a degraded pass",
    "Create tracking issue for critical findings",
])
def test_each_recording_step_provisions_its_own_label(step_name):
    code = _shell_code(_step_run(step_name))
    assert 'gh label create "$LABEL" --repo "$REPO"' in code, (
        f"{step_name!r} does not self-provision its label against $REPO — the "
        f"labelled `gh issue create` below it then fails in any caller repo that "
        f"has never been given the label by hand"
    )
    assert "--force" in code, (
        f"{step_name!r}'s label create is not idempotent; without --force it "
        f"errors on the second run in every repo that already has the label"
    )


# The safe-direction behaviour of `test_the_quota_recorder_has_no_unlabeled_fallback`
# is kept, but it must not be *opaque*: in #1092 the job reported FAILURE with a
# bare `could not add label` and nothing said that blocking was deliberate or
# what would clear it, which is what sent the first investigation at the fallback
# the sibling step uses (that fallback would have re-opened #81's fail-open).
def test_the_quota_recorders_hard_fail_path_says_why_it_is_failing():
    code = _shell_code(_step_run("Record that the provider quota is exhausted"))
    assert code.count("gh issue create") == 1, (
        "the hard-fail path must stay a hard fail — see "
        "test_the_quota_recorder_has_no_unlabeled_fallback for why an unlabeled "
        "fallback here is worse than the failure it would hide"
    )
    assert "::error::" in code, (
        "the create's failure branch emits no ::error:: annotation, so the step "
        "fails the required check with no statement of what failed or why it "
        "does not fall back"
    )
    assert "exit 1" in code, "the failure branch must still fail the step"


# ── the label creates must be calls GitHub will actually accept ───────────────
#
# infra-commons/security#149: `--repo` was ONE of two independent causes of
# #1092/#1094, and #135 fixed only that one. All three of these calls also
# passed a `--description` of 172/142/142 characters against GitHub's
# 100-character cap, so each returned a 422 and created nothing regardless of
# `--repo`. The descriptions were over the cap from the day they landed
# (366933b/#80: 172; ab86114/#99: 142 and 142), so these creates had never once
# succeeded on any repo, and `--repo` alone could not have restored the label.
# Both causes reach the same end state — label absent, the labelled create below
# fails, no marker filed — which is why the first attribution looked complete.
# That end state was unreachable code in THIS workflow, not a provisioning gap
# in the caller repos; hand-creating the label is what masked it where it had
# been done. Asserted statically rather than left to the runtime warning below
# because the failure is 100% deterministic: it belongs at PR time.
_LABEL_DESCRIPTION_LIMIT = 100
_LABEL_CREATE_RE = re.compile(r"gh label create\b[^\n]*")
_DESCRIPTION_RE = re.compile(r'--description\s+"([^"]*)"')

_RECORDING_STEPS = [
    "Record that the provider quota is exhausted",
    "Record a degraded pass",
    "Create tracking issue for critical findings",
]


def _joined_shell(run: str) -> str:
    """`_shell_code` with line continuations folded, so one command is one line.

    The `--description` these tests read sits on a continuation line, and the
    command regexes below are deliberately `[^\\n]*` rather than `.*?` with
    DOTALL so a match can never run from one command into the next.
    """
    return re.sub(r"\\\n\s*", " ", _shell_code(run))


@pytest.mark.parametrize("step_name", _RECORDING_STEPS)
def test_each_provisioned_label_description_is_within_githubs_limit(step_name):
    creates = _LABEL_CREATE_RE.findall(_joined_shell(_step_run(step_name)))
    assert creates, f"{step_name!r} makes no label-create call to check"
    for create in creates:
        for description in _DESCRIPTION_RE.findall(create):
            assert len(description) <= _LABEL_DESCRIPTION_LIMIT, (
                f"{step_name!r} asks for a {len(description)}-character label "
                f"description; GitHub rejects anything over "
                f"{_LABEL_DESCRIPTION_LIMIT} with a 422, so the label is never "
                f"provisioned and the labelled create below it then fails on a "
                f"label that does not exist: {description!r}"
            )


# Failing OPEN on this call is deliberate and stays: with `--force` it is a
# create-or-update, so on a repo that already has the label the call is
# redundant and a transient blip on it must not fail a required check; and where
# the label genuinely is absent, the labelled create two commands down already
# fails loudly and specifically. Failing open is not a licence to be SILENT,
# though. `>/dev/null 2>&1 || true` is what let a 100%-reproducible 422 run
# unnoticed on every repo for months, and it makes the quota recorder's own
# ::error:: — which tells the reader to "check that the label create above
# succeeded" — impossible to act on.
@pytest.mark.parametrize("step_name", _RECORDING_STEPS)
def test_a_failed_label_create_is_announced_rather_than_discarded(step_name):
    code = _joined_shell(_step_run(step_name))
    create = _LABEL_CREATE_RE.search(code)
    assert create, f"{step_name!r} makes no label-create call to check"
    assert "/dev/null" not in create.group(0), (
        f"{step_name!r} discards its label create's output, so a failure to "
        f"provision the label leaves no trace anywhere in the run — the state "
        f"that hid a 422 on every repo for months"
    )
    assert "::warning::" in code, (
        f"{step_name!r} does not annotate a failed label create. Fail-open here "
        f"is correct; failing open silently is not"
    )
