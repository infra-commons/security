#!/usr/bin/env python3
"""Fail when the newest release run failed; name (warn on) any held release run.

Since 2026-11-10
----------------
`release-composites.yml` no longer gates `release` on the `fleet-release`
environment. The operator's merge is the ship decision, and green Tests after it
release automatically. A long-held run is therefore no longer an approval
nobody gave, so it warns instead of failing. A stale tag behind it still fails
`check_composite_tags_released.py`. What fails here instead is a release that
ran and failed (`evaluate_last_release`).

Why this exists
---------------
Until 2026-11-10, a release waited on the `fleet-release` environment. What
that lacked was any alarm for the state
"nobody has approved for N days": a run sits in `waiting` indefinitely, `main`
is green, the PR reads as shipped, and the only way to find out is for somebody
to open the Actions tab and go looking.

That is the same shape as the thing the release automation was built to end.
An unreleased fix is indistinguishable from a released one from inside the
repository; an unapproved release is indistinguishable from an approved one
unless something reads the run list and says otherwise. The `verify` job proves
the tags landed. This proves nothing is silently queued up behind a human who
did not notice they were being asked.

It ran alongside a second defect worth recording, because this check is partly
the fix for it: `verify` and `release` shared one workflow-level concurrency
group, and `cancel-in-progress: false` queues later runs rather than cancelling
the leader. Only one run may be queued per group, so each nightly heartbeat was
the queued run that the next arrival cancelled — an unapproved release
suppressed the check that reports releases are not happening. Measured on
2026-08-07: run 31135680681 was created at 00:44:22Z, sat 7h33m, and started
three seconds after the blocking run was cancelled at 08:17:34Z. The runs it
cancelled (30949226585, 31058866599) have zero jobs in the API, which is the
tell: the run existed and never reached a single step.

Splitting the concurrency group stops the heartbeat being cancelled. This stops
the *approval* going unnoticed, which the split alone does not address.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

GITHUB_API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
WORKFLOW_FILE = "release-composites.yml"

# A run in one of these has been created and is not running: it is either held
# by a deployment protection rule (`waiting`) or held behind the concurrency
# group (`queued` / `pending`). Both mean the release has not happened, and
# neither reports itself anywhere.
_HELD_STATUSES = frozenset({"waiting", "queued", "pending", "action_required", "requested"})

# A release that nobody has approved overnight is ordinary — the reviewer is
# asleep. A day later it is not, and by then a composite fix merged behind it
# has been unreleased for a day with every symptom reading as shipped.
#
# (Written under the 2026-11-10-removed approval gate. The threshold now governs
# the WARNING; it never fails the check.)
#
# The threshold governs FAILING, and deliberately nothing else. It used to gate
# reporting too, which made this check structurally unable to do the job the
# workflow step attaches it to. This runs on a nightly heartbeat, so a run held
# since the previous morning is ~15h old — under 24h. On 2026-08-16 19:34 it
# printed `No run has been held longer than 24h ✅` in the very run that failed
# on tag staleness, while the ~15h held run sitting right there was the whole
# explanation. A diagnostic whose silence threshold outlives its own cadence can
# never explain the failure it is bolted to.
#
# The fix is NOT to lower this number. An ordinary overnight wait would then fail
# the heartbeat on most nights, and a guard that fires on the healthy case trains
# the override reflex just as effectively as one that is absent — a failure mode
# this fleet has already recorded. Held runs are now always NAMED, at any age;
# only crossing this threshold turns the check red.
DEFAULT_THRESHOLD_HOURS = 24


def _parse_ts(value: str) -> datetime:
    """Parse a GitHub API timestamp into an aware UTC datetime."""
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def evaluate(runs, now: datetime, threshold_hours: float = DEFAULT_THRESHOLD_HOURS):
    """Pure decision step, so every failure mode is unit-testable without the API.

    `runs` is the API's run list (dicts with at least `id`, `status`,
    `created_at`). Returns (stuck, messages).

    An empty `runs` is an ERROR, never a pass. This check's whole input is the
    run list; finding none means the query broke, the workflow was renamed, or
    the token lost `actions: read` — not that the release path is healthy. A
    detector that reports "nothing wrong" when it looked at nothing is the
    failure it exists to catch, one level up.
    """
    messages: list[str] = []

    if not runs:
        messages.append(
            f"::error::Found no `{WORKFLOW_FILE}` runs at all. This check reads the "
            f"Actions run list; no runs means the query, the workflow name, or the "
            f"`actions: read` permission changed — not that the release path is "
            f"healthy. Fix or delete this check deliberately."
        )
        return [], messages

    stuck = []
    held_below = []
    for run in runs:
        if run.get("status") not in _HELD_STATUSES:
            continue
        created = _parse_ts(run["created_at"])
        held_hours = (now - created).total_seconds() / 3600
        if held_hours < threshold_hours:
            # Named, not skipped. Below the threshold this is not yet an alarm, but it IS
            # the answer to "why are the tags stale?" — and that question is being asked in
            # this very run, by the step above.
            held_below.append(run)
            messages.append(
                f"::notice::Release run {run['id']} is `{run['status']}`, held "
                f"{held_hours:.0f}h (since {run['created_at']}) — under the "
                f"{threshold_hours:.0f}h alarm threshold, so this is not yet a failure. "
                f"If a tag-staleness check failed in this run, THIS IS WHY: a held "
                f"release moves no tags. {run.get('html_url', '(no url)')}"
            )
            continue
        stuck.append(run)
        # A warning, not an error (since 2026-11-10): with no approval gate a held
        # run is not waiting on a human, and the tag check fails on its effect.
        messages.append(
            f"::warning::Release run {run['id']} has been `{run['status']}` for "
            f"{held_hours:.0f}h (since {run['created_at']}). With no approval gate "
            f"this should not happen; a held release moves no tags, so check the "
            f"runners and the concurrency group, or cancel it: "
            f"{run.get('html_url', '(no url)')}"
        )

    if len(stuck) + len(held_below) > 1:
        # Measured 2026-08-17 under the old gate; the slot semantics still hold.
        messages.append(
            f"::notice::{len(stuck) + len(held_below)} release runs are held at once. "
            f"They share one concurrency group, so the OLDEST holds the slot and the "
            f"others cannot proceed until it finishes. Each run releases main's tip "
            f"(infra-commons/meta#1661), so cancelling the stale ones loses nothing."
        )

    if not stuck and not held_below:
        messages.append(
            f"No `{WORKFLOW_FILE}` run is held at all ({len(runs)} run(s) checked). ✅"
        )
    elif not stuck:
        messages.append(
            f"No `{WORKFLOW_FILE}` run has been held longer than {threshold_hours:.0f}h, "
            f"but {len(held_below)} IS held and named above ({len(runs)} run(s) checked)."
        )
    return stuck, messages


# Conclusions that mean the release job ran and did not finish its work. A
# `cancelled` run is excluded: superseded runs are cancelled by the concurrency
# group, and the tag check catches any effect of a cancel that mattered.
_FAILED_CONCLUSIONS = frozenset({"failure", "timed_out", "startup_failure"})


def evaluate_last_release(runs):
    """Error messages if the newest completed release run failed, else [].

    Only `workflow_run` runs release; `schedule`/`workflow_dispatch` runs are
    this heartbeat. A newer success clears an older failure, so only the newest
    completed release run counts.
    """
    releases = [
        r for r in runs if r.get("event") == "workflow_run" and r.get("status") == "completed"
    ]
    if not releases:
        return []
    newest = max(releases, key=lambda r: _parse_ts(r["created_at"]))
    if newest.get("conclusion") not in _FAILED_CONCLUSIONS:
        return []
    return [
        f"::error::The newest release run {newest['id']} concluded "
        f"`{newest['conclusion']}` (created {newest['created_at']}). Tags may be partly "
        f"moved, or a family was refused for a lagging inner pin (PR the pin bump). "
        f"Read its log: {newest.get('html_url', '(no url)')}"
    ]


def fetch_runs(repo: str, token: str, per_page: int = 50):
    """The most recent runs of this workflow. Raises rather than returning []."""
    url = (
        f"{GITHUB_API}/repos/{repo}/actions/workflows/{WORKFLOW_FILE}/runs"
        f"?per_page={per_page}"
    )
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response).get("workflow_runs", [])


def main() -> int:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    if not repo or not token:
        print(
            "::error::GITHUB_REPOSITORY and GITHUB_TOKEN are required. Without them "
            "this check cannot read the run list, and it must not pass on that basis.",
            file=sys.stderr,
        )
        return 1

    try:
        runs = fetch_runs(repo, token)
    except (urllib.error.URLError, ValueError, KeyError) as exc:
        # Deliberately not a pass. An unreachable API is an unknown, and this
        # check exists precisely because an unknown was being read as fine.
        print(f"::error::Could not read the {WORKFLOW_FILE} run list: {exc}", file=sys.stderr)
        return 1

    stuck, messages = evaluate(runs, datetime.now(timezone.utc))
    messages += evaluate_last_release(runs)
    for message in messages:
        print(message)

    return 1 if any(m.startswith("::error::") for m in messages) else 0


if __name__ == "__main__":
    sys.exit(main())
