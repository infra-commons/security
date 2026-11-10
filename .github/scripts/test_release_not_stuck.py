"""Tests for the stuck-release-approval check.

This guards a mechanism whose failure mode is silence: a release run waiting on
`fleet-release` reports nothing anywhere, and the repo reads as shipped while
every composite merged behind it is unreleased. So the assertions that matter
most are the negative ones — that the check actually goes red on a held run,
and that an empty or unreadable run list fails rather than passing vacuously.

The real 2026-08-07 incident is reproduced as a fixture at the bottom, because
a detector should be tested against the failure it exists to catch and not only
against a healthy system.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_release_not_stuck as check  # noqa: E402

NOW = datetime(2026, 8, 7, 12, 0, 0, tzinfo=timezone.utc)


def _run(run_id: int, status: str, age_hours: float, **extra):
    created = NOW - timedelta(hours=age_hours)
    return {
        "id": run_id,
        "status": status,
        "created_at": created.isoformat().replace("+00:00", "Z"),
        "html_url": f"https://github.com/infra-commons/security/actions/runs/{run_id}",
        **extra,
    }


def _errors(messages):
    return [m for m in messages if m.startswith("::error::")]


def _warnings(messages):
    return [m for m in messages if m.startswith("::warning::")]


# ── the failure the check exists to catch ─────────────────────────────────────


def test_a_run_waiting_past_the_threshold_is_stuck():
    stuck, messages = check.evaluate([_run(1, "waiting", 30)], NOW)
    assert [r["id"] for r in stuck] == [1]
    # Since the approval gate went (2026-11-10): named as a warning, never a failure.
    assert not _errors(messages), "a held run must warn, not fail, now there is no gate"
    assert _warnings(messages) and "30h" in messages[0]


def test_a_run_queued_behind_the_group_past_the_threshold_is_stuck():
    """`waiting` is the approval gate; `queued`/`pending` is the concurrency
    group. Both mean the release has not happened and nothing says so."""
    for status in ("queued", "pending", "action_required", "requested"):
        stuck, _ = check.evaluate([_run(2, status, 48)], NOW)
        assert [r["id"] for r in stuck] == [2], f"{status} held 48h should be stuck"


def test_the_threshold_is_a_boundary_not_a_suggestion():
    assert check.evaluate([_run(3, "waiting", 23.9)], NOW)[0] == []
    assert check.evaluate([_run(3, "waiting", 24.1)], NOW)[0] != []


def test_every_stuck_run_is_reported_not_just_the_first():
    """One held run must not mask another — the same property
    `test_one_stale_family_does_not_mask_another` guards next door."""
    stuck, messages = check.evaluate(
        [_run(10, "waiting", 30), _run(11, "queued", 40)], NOW
    )
    assert sorted(r["id"] for r in stuck) == [10, 11]
    assert len(_warnings(messages)) == 2


# ── states that must NOT trip it ──────────────────────────────────────────────


def test_a_completed_run_is_never_stuck_however_old():
    stuck, messages = check.evaluate([_run(4, "completed", 24 * 365)], NOW)
    assert stuck == [] and not _errors(messages)


def test_an_in_progress_run_is_not_stuck():
    """A long build is a slow release, not an unapproved one."""
    stuck, _ = check.evaluate([_run(5, "in_progress", 72)], NOW)
    assert stuck == []


def test_a_recently_waiting_run_is_not_stuck():
    """Overnight is ordinary — the reviewer is asleep, not absent."""
    stuck, messages = check.evaluate([_run(6, "waiting", 8)], NOW)
    assert stuck == [] and not _errors(messages)


# ── the dead-filter guard ─────────────────────────────────────────────────────


def test_an_empty_run_list_is_an_error_not_a_pass():
    """The check's own input. A filter that never matched and a filter that
    correctly found nothing render identically; this is the difference."""
    stuck, messages = check.evaluate([], NOW)
    assert stuck == []
    assert _errors(messages), "no runs must fail loudly, not report healthy"
    assert "no" in messages[0].lower()


def test_a_healthy_list_says_how_many_it_actually_looked_at():
    """A pass that does not state its denominator cannot be distinguished from
    a pass over an empty set by anyone reading the log later."""
    _, messages = check.evaluate([_run(7, "completed", 1), _run(8, "completed", 2)], NOW)
    assert "2 run(s) checked" in messages[0]


# ── the real incident, as a regression fixture ────────────────────────────────


def test_the_2026_08_07_incident_is_caught():
    """Run 31058866599 sat `waiting` on `fleet-release` from 2026-08-06T00:11:04Z
    and was still holding the concurrency group 32h later, cancelling each
    night's heartbeat. Nothing reported it; this is what would have."""
    incident_now = datetime(2026, 8, 7, 8, 17, 34, tzinfo=timezone.utc)
    runs = [
        {
            "id": 31058866599,
            "status": "waiting",
            "created_at": "2026-08-06T00:11:04Z",
            "html_url": "https://github.com/infra-commons/security/actions/runs/31058866599",
        },
        {"id": 31045139305, "status": "completed", "created_at": "2026-08-05T20:39:50Z"},
    ]
    stuck, messages = check.evaluate(runs, incident_now)

    assert [r["id"] for r in stuck] == [31058866599]
    assert _warnings(messages) and not _errors(messages)
    # The message has to name the run and tell the reader what to do with it,
    # or it is an alarm nobody can act on.
    assert "31058866599" in messages[0]
    assert "cancel it" in messages[0]


def test_the_incident_would_not_have_fired_on_its_first_night():
    """The same run, 8h in. Alarming here would train the operator to ignore it."""
    early = datetime(2026, 8, 6, 8, 0, 0, tzinfo=timezone.utc)
    runs = [{"id": 31058866599, "status": "waiting", "created_at": "2026-08-06T00:11:04Z"}]
    assert check.evaluate(runs, early)[0] == []


# ── the diagnosis must not be withheld by the alarm threshold ─────────────────
# This check is bolted to the tag-staleness check as its EXPLANATION (the workflow
# step's own `if: always()` comment says so). But the threshold used to gate reporting
# as well as failing, so on 2026-08-16 19:34 it printed a green "nothing held longer
# than 24h" in the very run that failed on tag staleness — while the ~15h held run
# sitting right there was the entire reason. A nightly heartbeat can never see 24h on
# the night a run is first held, so the explanation was structurally unreachable.


def _notices(messages):
    return [m for m in messages if m.startswith("::notice::")]


def test_a_held_run_below_the_threshold_is_still_named():
    """The regression. Not an error — but it must not be silent either."""
    stuck, messages = check.evaluate([_run(9, "waiting", 15)], NOW)
    assert stuck == [], "15h is under the alarm threshold and must not fail the check"
    assert not _errors(messages)
    notices = _notices(messages)
    assert notices, (
        "a run held 15h was not mentioned at all — this is the state the check was in "
        "when it reported green against a tag-staleness failure it could have explained"
    )
    assert "9" in notices[0] and "15h" in notices[0]


def test_the_below_threshold_notice_names_the_tag_staleness_connection():
    """It has to be readable AS the explanation by someone looking at the failing step
    above it, not just a stray line about a run id."""
    _, messages = check.evaluate([_run(10, "waiting", 15)], NOW)
    text = " ".join(_notices(messages))
    assert "THIS IS WHY" in text and "moves no tags" in text


def test_the_green_line_no_longer_claims_health_while_a_run_is_held():
    """The exact sentence that misled: a summary saying nothing exceeded the threshold,
    with no hint that something IS held."""
    _, messages = check.evaluate([_run(11, "waiting", 15)], NOW)
    summary = messages[-1]
    assert "IS held" in summary, summary
    assert not summary.endswith("✅"), "a run is held; this must not read as a clean pass"


def test_a_genuinely_clear_list_still_reads_clean():
    """Behaviour-preservation control: the healthy case must stay unambiguous, or the
    change just trades one misleading line for another."""
    _, messages = check.evaluate([_run(12, "completed", 5)], NOW)
    assert not _notices(messages) and not _errors(messages)
    assert messages[-1].endswith("✅")


def test_two_held_runs_warn_that_the_oldest_holds_the_slot():
    """Measured 2026-08-17: the oldest held run blocks the rest. Every run releases
    main's tip (meta#1661), so the advice is to cancel the stale ones."""
    _, messages = check.evaluate([_run(13, "waiting", 15), _run(14, "queued", 2)], NOW)
    text = " ".join(_notices(messages))
    assert "OLDEST holds the slot" in text
    assert "cancelling the stale ones" in text


def test_one_held_run_does_not_emit_the_concurrency_warning():
    """It only applies when runs are actually contending; otherwise it is noise."""
    _, messages = check.evaluate([_run(15, "waiting", 15)], NOW)
    assert "OLDEST holds the slot" not in " ".join(_notices(messages))


# ── a failed release is the failure that remains (since 2026-11-10) ──────────


def _rel(run_id, conclusion, age_hours, event="workflow_run"):
    return _run(run_id, "completed", age_hours, conclusion=conclusion, event=event)


def test_the_newest_release_failing_is_an_error():
    errors = check.evaluate_last_release([_rel(20, "failure", 2), _rel(19, "success", 30)])
    assert len(errors) == 1 and errors[0].startswith("::error::") and "20" in errors[0]


def test_a_newer_success_clears_an_older_failure():
    assert check.evaluate_last_release([_rel(21, "success", 2), _rel(20, "failure", 30)]) == []


def test_a_cancelled_newest_release_is_not_a_failure():
    """Superseded runs are cancelled by the concurrency group; the tag check judges effect."""
    assert check.evaluate_last_release([_rel(22, "cancelled", 2), _rel(21, "success", 30)]) == []


def test_heartbeat_runs_are_not_releases():
    """A red nightly verify must not read as a failed release, or it would latch itself."""
    runs = [_rel(23, "failure", 1, event="schedule"), _rel(21, "success", 30)]
    assert check.evaluate_last_release(runs) == []


def test_an_in_flight_release_defers_to_the_last_completed_one():
    runs = [_run(24, "in_progress", 0.1, event="workflow_run"), _rel(20, "timed_out", 30)]
    assert check.evaluate_last_release(runs)
