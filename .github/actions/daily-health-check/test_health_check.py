"""Tests for the daily health-check's failure-reporting and auto-close rules.

This action files `severity:high` issues, and an open unaccepted `severity:high`
on any prod repo blocks every client's production release. So the difference
between "reports a real failure" and "reports a failure that fixed itself ten
hours ago" is the difference between a useful check and one that gates
production on noise. It also *closes* issues, which is the other direction of
the same risk: a false clear hides a failure that is still real.

The action reaches every consuming repo through the `daily-health-check/v1`
moving tag, so nothing between an edit here and 13+ repos' scheduled runs
reviews it. These tests are that review.

Covers the three defects in rolliq-com/solution-recruitment-reference-check#888:
  1. superseded failures were reported anyway
  2. auto-close was skipped entirely on a green day, and keyed on the absence of
     a failure rather than the presence of a pass
  3. the workflow-file lookup was fed the RUN name, so it never matched any
     workflow that sets `run-name:`
  4. every consumer head-sliced the job log, so the diagnosis model was shown
     runner provisioning rather than the failure
"""
import importlib.util
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

# The module filename contains a dash, so it cannot be imported by name.
_MODULE_PATH = Path(__file__).parent / "health-check.py"
_spec = importlib.util.spec_from_file_location("health_check", _MODULE_PATH)
hc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hc)


NOW = datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc)
CUTOFF = NOW - timedelta(hours=25)

# The two run names from the real incident. Both come from the SAME workflow
# file; they differ only by the client slug that `run-name:` interpolates.
STAGING_ROLLIQ_TEST = "🧪 STAGING release → rolliq-test"
STAGING_KIN = "🧪 STAGING release → kin"
WORKFLOW_NAME = "Release — STAGING (build once + test)"


def _run(run_id, name, when, *, workflow_name=WORKFLOW_NAME):
    return {
        "databaseId": run_id,
        "name": name,
        "workflowName": workflow_name,
        "event": "schedule",
        "createdAt": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "url": f"https://github.com/o/r/actions/runs/{run_id}",
        "_ts": when,
    }


# ── _latest_success_by_run_name ────────────────────────────────────────────────

def test_latest_success_takes_the_most_recent_per_run_name():
    runs = [
        _run(1, STAGING_ROLLIQ_TEST, NOW - timedelta(hours=10)),
        _run(2, STAGING_ROLLIQ_TEST, NOW - timedelta(hours=2)),
        _run(3, STAGING_KIN, NOW - timedelta(hours=5)),
    ]
    latest = hc._latest_success_by_run_name(runs)
    assert latest[STAGING_ROLLIQ_TEST] == NOW - timedelta(hours=2)
    assert latest[STAGING_KIN] == NOW - timedelta(hours=5)


def test_latest_success_ignores_runs_without_a_parsed_timestamp():
    bad = {"databaseId": 9, "name": STAGING_ROLLIQ_TEST}  # no _ts
    assert hc._latest_success_by_run_name([bad]) == {}


# ── _collect_runs ──────────────────────────────────────────────────────────────

def test_collect_runs_drops_unparseable_timestamps_rather_than_defaulting():
    """A run whose timestamp cannot be parsed must be dropped, not treated as now.

    Treating it as "now" would let a malformed success supersede a real failure,
    which fails in the silent direction.
    """
    payload = [
        {"databaseId": 1, "name": "A", "createdAt": "not-a-date", "url": "u"},
        {"databaseId": 2, "name": "A",
         "createdAt": (NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"), "url": "u"},
    ]
    calls = []

    def fake_gh_json(*args):
        calls.append(args)
        return payload if "schedule" in args else []

    hc._gh_json = fake_gh_json
    out = hc._collect_runs("o/r", "failure", CUTOFF)
    assert [r["databaseId"] for r in out] == [2]


def test_collect_runs_requests_workflow_name_so_the_file_lookup_can_work():
    """`workflowName` must be in the --json field list or defect 3 silently returns."""
    captured = {}

    def fake_gh_json(*args):
        captured["args"] = args
        return []

    hc._gh_json = fake_gh_json
    hc._collect_runs("o/r", "failure", CUTOFF)
    json_fields = captured["args"][captured["args"].index("--json") + 1]
    assert "workflowName" in json_fields
    assert "name" in json_fields


# ── Defect 3: the workflow-file lookup ─────────────────────────────────────────

def test_find_workflow_file_matches_the_workflow_name_not_the_run_name(tmp_path, monkeypatch):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "release-staging.yml").write_text(
        f"name: {WORKFLOW_NAME}\n"
        f"run-name: {STAGING_ROLLIQ_TEST}\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    # The workflow name resolves.
    assert hc._find_workflow_file(WORKFLOW_NAME) == ".github/workflows/release-staging.yml"
    # The run name does not, which is exactly why it must not be passed here.
    assert hc._find_workflow_file(STAGING_ROLLIQ_TEST) is None


# ── Defect 2: auto-close ───────────────────────────────────────────────────────

@pytest.fixture
def close_recorder(monkeypatch):
    closed = []

    def fake_gh(*args, **kwargs):
        if args[:2] == ("issue", "close"):
            closed.append(int(args[2]))
        return ""

    monkeypatch.setattr(hc, "_gh", fake_gh)
    return closed


def test_auto_close_closes_an_issue_whose_workflow_has_passed_again(close_recorder):
    n = hc.auto_close_resolved_issues(
        "o/r",
        open_issues={STAGING_ROLLIQ_TEST: 885},
        still_failing=set(),
        latest_success={STAGING_ROLLIQ_TEST: NOW - timedelta(hours=1)},
        health_run_url="u",
    )
    assert n == 1 and close_recorder == [885]


def test_auto_close_leaves_an_issue_open_while_it_is_still_failing(close_recorder):
    n = hc.auto_close_resolved_issues(
        "o/r",
        open_issues={STAGING_ROLLIQ_TEST: 885},
        still_failing={STAGING_ROLLIQ_TEST},
        latest_success={STAGING_ROLLIQ_TEST: NOW - timedelta(hours=9)},
        health_run_url="u",
    )
    assert n == 0 and close_recorder == []


def test_auto_close_does_not_falsely_clear_a_workflow_that_simply_never_RAN(close_recorder):
    """No passing run => no close. This is the false-clear guard.

    Closing on the mere absence of a failure means a workflow that did not run at
    all in the lookback window gets its issue closed with nothing fixed. For a
    weekly or dispatch-only workflow that is every single day.
    """
    n = hc.auto_close_resolved_issues(
        "o/r",
        open_issues={STAGING_ROLLIQ_TEST: 885},
        still_failing=set(),
        latest_success={},          # never ran, so never passed
        health_run_url="u",
    )
    assert n == 0 and close_recorder == []


def test_auto_close_is_per_client_so_one_clients_pass_cannot_close_anothers_issue(close_recorder):
    """`release-staging.yml` is shared across clients; the run name is not."""
    n = hc.auto_close_resolved_issues(
        "o/r",
        open_issues={STAGING_ROLLIQ_TEST: 885},
        still_failing=set(),
        latest_success={STAGING_KIN: NOW - timedelta(hours=1)},  # a DIFFERENT client passed
        health_run_url="u",
    )
    assert n == 0 and close_recorder == []


# ── triage_failed_runs: supersession + the green-day early return ──────────────

@pytest.fixture
def triage_harness(monkeypatch):
    """Drive triage_failed_runs with canned run lists, recording side effects."""
    state = {"failures": [], "successes": [], "open_issues": {},
             "filed": [], "closed": []}

    def fake_collect(repo, status, cutoff):
        return list(state["failures"] if status == "failure" else state["successes"])

    def fake_gh(*args, **kwargs):
        if args[:2] == ("issue", "close"):
            state["closed"].append(int(args[2]))
        return ""

    monkeypatch.setattr(hc, "_collect_runs", fake_collect)
    monkeypatch.setattr(hc, "_gh", fake_gh)
    monkeypatch.setattr(hc, "ensure_labels", lambda repo: None)
    monkeypatch.setattr(hc, "get_open_health_issues", lambda repo: dict(state["open_issues"]))
    monkeypatch.setattr(hc, "_gh_api", lambda path: {"jobs": [
        {"id": 1, "name": "job", "conclusion": "failure",
         "steps": [{"name": "step", "conclusion": "failure"}]}]})
    monkeypatch.setattr(hc, "get_job_logs", lambda job_id, repo: "boom")
    monkeypatch.setattr(hc, "diagnose_with_claude", lambda *a, **k: {
        "root_cause": "rc", "fix": "f", "severity": "high",
        "is_transient": False, "mechanical": False})

    def fake_file(**kwargs):
        state["filed"].append(kwargs["workflow_name"])
        return 900

    monkeypatch.setattr(hc, "file_or_update_issue", fake_file)
    return state


def test_a_failure_superseded_by_a_later_success_is_not_reported(triage_harness):
    """The #885 incident: failed 01:03Z, passed 01:28Z, filed at 11:16Z anyway."""
    triage_harness["failures"] = [
        _run(30228879580, STAGING_ROLLIQ_TEST, NOW - timedelta(hours=11))]
    triage_harness["successes"] = [
        _run(30229880483, STAGING_ROLLIQ_TEST, NOW - timedelta(hours=10, minutes=35))]

    result = hc.triage_failed_runs("o/r", 25, "u", dry_run=False)

    assert result["filed"] == 0
    assert triage_harness["filed"] == []


def test_a_failure_with_no_later_success_is_still_reported(triage_harness):
    """The guard must not swallow live failures. Success PRECEDES the failure here."""
    triage_harness["failures"] = [
        _run(2, STAGING_ROLLIQ_TEST, NOW - timedelta(hours=2))]
    triage_harness["successes"] = [
        _run(1, STAGING_ROLLIQ_TEST, NOW - timedelta(hours=9))]

    result = hc.triage_failed_runs("o/r", 25, "u", dry_run=False)

    assert result["filed"] == 1
    assert triage_harness["filed"] == [STAGING_ROLLIQ_TEST]


def test_another_clients_success_does_not_supersede_this_clients_failure(triage_harness):
    triage_harness["failures"] = [
        _run(1, STAGING_ROLLIQ_TEST, NOW - timedelta(hours=11))]
    triage_harness["successes"] = [
        _run(2, STAGING_KIN, NOW - timedelta(hours=4))]

    result = hc.triage_failed_runs("o/r", 25, "u", dry_run=False)

    assert result["filed"] == 1


def test_auto_close_still_runs_on_a_day_with_zero_failures(triage_harness):
    """The early-return bug: auto-close sat AFTER `if not all_runs: return`.

    So an issue could only ever be closed on a day something else failed. On a
    fully green repo -- the case where closing is exactly what should happen --
    nothing was closed at all.
    """
    triage_harness["failures"] = []
    triage_harness["successes"] = [
        _run(1, STAGING_ROLLIQ_TEST, NOW - timedelta(hours=1))]
    triage_harness["open_issues"] = {STAGING_ROLLIQ_TEST: 885}

    result = hc.triage_failed_runs("o/r", 25, "u", dry_run=False)

    assert result["closed"] == 1
    assert triage_harness["closed"] == [885]


def test_a_superseded_failure_also_gets_its_open_issue_closed(triage_harness):
    """Supersession and closing must agree, or #885 is dropped from the report
    while its issue stays open forever -- reported-then-orphaned."""
    triage_harness["failures"] = [
        _run(1, STAGING_ROLLIQ_TEST, NOW - timedelta(hours=11))]
    triage_harness["successes"] = [
        _run(2, STAGING_ROLLIQ_TEST, NOW - timedelta(hours=10))]
    triage_harness["open_issues"] = {STAGING_ROLLIQ_TEST: 885}

    result = hc.triage_failed_runs("o/r", 25, "u", dry_run=False)

    assert result["filed"] == 0
    assert result["closed"] == 1
    assert triage_harness["closed"] == [885]


def test_the_file_lookup_is_called_with_the_WORKFLOW_name_not_the_run_name(
    triage_harness, monkeypatch
):
    """Covers the call-site wiring, not just `_find_workflow_file` in isolation.

    Testing the helper alone passes whichever name the caller actually hands it,
    so it cannot detect defect 3 at all. This asserts what the caller passes.
    """
    seen = []
    monkeypatch.setattr(hc, "_find_workflow_file", lambda name: seen.append(name))
    monkeypatch.setattr(hc, "diagnose_with_claude", lambda *a, **k: {
        "root_cause": "rc", "fix": "f", "severity": "high",
        "is_transient": False, "mechanical": True})
    triage_harness["failures"] = [
        _run(1, STAGING_ROLLIQ_TEST, NOW - timedelta(hours=2))]

    hc.triage_failed_runs("o/r", 25, "u", dry_run=False)

    assert seen == [WORKFLOW_NAME], (
        f"expected the workflow name, got {seen!r}; the run name never matches a file"
    )


def test_the_file_lookup_falls_back_to_the_run_name_when_workflowName_is_absent(
    triage_harness, monkeypatch
):
    """Old `gh` versions, or a cached payload, may not carry `workflowName`."""
    seen = []
    monkeypatch.setattr(hc, "_find_workflow_file", lambda name: seen.append(name))
    monkeypatch.setattr(hc, "diagnose_with_claude", lambda *a, **k: {
        "root_cause": "rc", "fix": "f", "severity": "high",
        "is_transient": False, "mechanical": True})
    run = _run(1, STAGING_ROLLIQ_TEST, NOW - timedelta(hours=2))
    del run["workflowName"]
    triage_harness["failures"] = [run]

    hc.triage_failed_runs("o/r", 25, "u", dry_run=False)

    assert seen == [STAGING_ROLLIQ_TEST]


def test_dry_run_neither_files_nor_closes(triage_harness):
    triage_harness["failures"] = [
        _run(1, STAGING_ROLLIQ_TEST, NOW - timedelta(hours=2))]
    triage_harness["open_issues"] = {STAGING_KIN: 999}
    triage_harness["successes"] = [
        _run(2, STAGING_KIN, NOW - timedelta(hours=1))]

    hc.triage_failed_runs("o/r", 25, "u", dry_run=True)

    assert triage_harness["filed"] == []
    assert triage_harness["closed"] == []


# ── Defect 4: the diagnosis never saw the failure ─────────────────────────────
#
# Measured on the real job log behind
# rolliq-com/solution-recruitment-reference-check#885 (job 89864053280,
# 179 511 chars): the endpoint returns PLAIN TEXT, so the ZIP branch never ran
# and the `BadZipFile` fallback head-sliced to 30 000 chars; the diagnosis then
# sliced that to 12 000. The first `##[error]` sits at char 135 168 (75% in),
# so the model saw 6.7% of the log, all of it runner provisioning, and
# truthfully reported "the log is truncated, the failure is not visible".

BOILERPLATE = "".join(
    f"2026-07-27T01:04:{i % 60:02d}.0000000Z Runner provisioning line {i}\n"
    for i in range(3_000)
)
TERRAFORM_ERROR = (
    "2026-07-27T01:09:12.0000000Z Error: a resource with the ID "
    '".../deployments/gpt-5.5" already exists - to be managed via Terraform '
    "this resource needs to be imported into the State\n"
    "2026-07-27T01:09:12.0000000Z ##[error]Terraform exited with code 1\n"
)
TRAILER = "".join(
    f"2026-07-27T01:09:{i % 60:02d}.0000000Z Post job cleanup {i}\n"
    for i in range(500)
)
DEPLOY_LOG = BOILERPLATE + TERRAFORM_ERROR + TRAILER


def test_excerpt_of_a_short_log_is_the_whole_log():
    assert hc.select_log_excerpt("short log", 12_000) == "short log"


def test_excerpt_contains_the_failure_not_the_runner_boilerplate():
    # The whole point: a head slice of this log is `Runner provisioning line …`.
    excerpt = hc.select_log_excerpt(DEPLOY_LOG, 12_000)

    assert "already exists" in excerpt
    assert "needs to be imported into the State" in excerpt
    assert "##[error]" in excerpt
    assert "Runner provisioning line 0\n" not in excerpt


def test_excerpt_never_exceeds_the_caller_s_budget():
    # Callers size these against a prompt budget, and the truncation markers
    # are part of what gets sent.
    for limit in (500, 8_000, 12_000, 30_000):
        assert len(hc.select_log_excerpt(DEPLOY_LOG, limit)) <= limit


def test_excerpt_keeps_context_BEFORE_the_error_because_the_cause_precedes_it():
    excerpt = hc.select_log_excerpt(DEPLOY_LOG, 12_000)
    before = excerpt.index("##[error]")
    # Terraform prints the offending resource, then announces the failure.
    assert before > len(excerpt) * 0.4


def test_excerpt_falls_back_to_the_TAIL_when_nothing_annotated_the_failure():
    # A tool that died without an `Error:` line or a runner annotation still
    # leaves its last words at the end, never at the beginning.
    unannotated = BOILERPLATE + "2026-07-27T01:09:12.0000000Z the last words\n"
    excerpt = hc.select_log_excerpt(unannotated, 2_000)

    assert "the last words" in excerpt
    assert "Runner provisioning line 0\n" not in excerpt


def test_the_runner_annotation_outranks_an_earlier_bare_error_line():
    # `##[error]` is GitHub's own annotation and effectively never a false
    # positive; a bare `Error:` printed by a tool that then RECOVERED is.
    log = (
        "Error: retrying, this one recovered\n"
        + "x" * 40_000
        + "\n##[error]this is the one that killed the job\n"
        + "y" * 5_000
    )
    excerpt = hc.select_log_excerpt(log, 6_000)

    assert "this is the one that killed the job" in excerpt
    assert "this one recovered" not in excerpt


def test_an_anchor_at_the_very_end_still_spends_the_whole_budget():
    log = "z" * 40_000 + "\n##[error]died at the last line\n"
    excerpt = hc.select_log_excerpt(log, 4_000)

    assert "died at the last line" in excerpt
    # Without reclaiming the unused forward half, this would be ~2 400 chars.
    assert len(excerpt) > 3_500


def test_get_job_logs_returns_the_log_WHOLE(monkeypatch):
    # The structural guard. Truncating here puts a head slice upstream of every
    # consumer and silently re-introduces this defect no matter what
    # `select_log_excerpt` does.
    class _Result:
        returncode = 0
        stdout = DEPLOY_LOG.encode("utf-8")

    monkeypatch.setattr(hc.subprocess, "run", lambda *a, **k: _Result())

    assert hc.get_job_logs(1, "o/r") == DEPLOY_LOG


def test_zip_entries_are_ordered_naturally_so_step_10_follows_step_2():
    names = ["10_Deploy.txt", "2_Checkout.txt", "1_Set up job.txt"]
    assert sorted(names, key=hc._natural_key) == [
        "1_Set up job.txt", "2_Checkout.txt", "10_Deploy.txt"]


# ── Defect 4, at the CALL SITES ───────────────────────────────────────────────
#
# Asserting `select_log_excerpt` in isolation cannot detect a caller that still
# head-slices, which is exactly how the defect-3 test passed its own negative
# control. These assert what the callers actually put in front of the model.

@pytest.fixture
def prompt_recorder(monkeypatch):
    prompts: list[str] = []

    _REPLY = ('{"is_transient": false, "root_cause": "r", "fix": "f", '
              '"severity": "high", "mechanical": false}')

    class _FakeMessages:
        def create(self, **kwargs):
            prompts.append(kwargs["messages"][0]["content"])
            block = type("Block", (), {"text": _REPLY})()
            return type("Msg", (), {"content": [block]})()

    class _FakeClient:
        def __init__(self, **kwargs):
            self.messages = _FakeMessages()

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(hc, "anthropic_sdk",
                        type("SDK", (), {"Anthropic": _FakeClient}))
    return prompts


def test_the_diagnosis_prompt_carries_the_failure_region(prompt_recorder):
    hc.diagnose_with_claude("wf", "job", "step", DEPLOY_LOG, "o/r")

    assert len(prompt_recorder) == 1
    prompt = prompt_recorder[0]
    assert "needs to be imported into the State" in prompt
    assert "Runner provisioning line 0\n" not in prompt


def test_the_autofix_prompt_carries_the_failure_region(prompt_recorder, tmp_path,
                                                      monkeypatch):
    monkeypatch.chdir(tmp_path)
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "deploy.yml").write_text("name: deploy\n")

    hc.try_autofix(
        repo="o/r",
        workflow_name="wf",
        workflow_file_path=".github/workflows/deploy.yml",
        log_excerpt=DEPLOY_LOG,
        diagnosis={"root_cause": "r", "fix": "f"},
        health_run_url="u",
        dry_run=True,
    )

    assert len(prompt_recorder) == 1
    assert "needs to be imported into the State" in prompt_recorder[0]


def test_the_transient_scan_looks_at_the_failure_region_not_the_head(monkeypatch):
    # A rate-limit that appears at the failure is the one worth re-running on.
    # Scanning `logs[:5_000]` meant this override could effectively never fire.
    log = BOILERPLATE + "2026-07-27T01:09:12.0000000Z ##[error]API rate limit exceeded\n"
    window = hc.select_log_excerpt(log, 30_000)

    assert any(re.search(p, window, re.IGNORECASE) for p in hc._TRANSIENT_PATTERNS)
    assert not any(re.search(p, log[:5_000], re.IGNORECASE)
                   for p in hc._TRANSIENT_PATTERNS)
