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
"""
import importlib.util
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
