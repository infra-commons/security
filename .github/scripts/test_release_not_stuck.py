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


# ── the failure the check exists to catch ─────────────────────────────────────


def test_a_run_waiting_past_the_threshold_is_stuck():
    stuck, messages = check.evaluate([_run(1, "waiting", 30)], NOW)
    assert [r["id"] for r in stuck] == [1]
    assert _errors(messages), "a run held 30h must produce an error, not a warning"
    assert "30h" in messages[0]


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
    assert len(_errors(messages)) == 2


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
    assert _errors(messages)
    # The message has to name the run and tell the reader what to do with it,
    # or it is an alarm nobody can act on.
    assert "31058866599" in messages[0]
    assert "fleet-release" in messages[0]
    assert "Approve or cancel" in messages[0]


def test_the_incident_would_not_have_fired_on_its_first_night():
    """The same run, 8h in. Alarming here would train the operator to ignore it."""
    early = datetime(2026, 8, 6, 8, 0, 0, tzinfo=timezone.utc)
    runs = [{"id": 31058866599, "status": "waiting", "created_at": "2026-08-06T00:11:04Z"}]
    assert check.evaluate(runs, early)[0] == []
