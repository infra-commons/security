"""Pin the `board-token` step's permission scope (infra-commons/meta#661).

`create-github-app-token` replaces the App install's full grant with exactly the `permission-*`
inputs given — it does not narrow additively. The `board-token` step used to request only
`organization-projects: write`, so the minted token had zero `issues` scope, and
`addProjectV2ItemById`'s `contentId` (the issue this same job just created) could never resolve.
That failed as `NOT_FOUND` on a node that plainly exists, one log line, job still exits 0 —
indistinguishable from "no findings this run," and no board-add succeeded for as long as it held.

THAT CONDITION IS CLOSED, and this paragraph is history, not a live outage: the step below now
requests `permission-issues: read` alongside `permission-organization-projects: write`, and board
adds land. Re-verified 2026-09-02 while widening `BOARD_ADD_SEVERITIES` to include CRITICAL —
"is the credential still broken?" decides whether such a change ships behaviour or a no-op, so it
was checked rather than assumed. Left in place because the shape is what the tests below pin.

This test exists so a future edit to this step can drop `permission-issues` again (e.g. while
"cleaning up" the `with:` block) without anyone noticing until the same silent failure recurs.
"""
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[3]
_WORKFLOW = _ROOT / ".github/workflows/capture-findings-reusable.yml"


def _board_token_step():
    jobs = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))["jobs"]
    for job in jobs.values():
        for step in job.get("steps", []):
            if step.get("id") == "board-token":
                return step
    raise AssertionError("no step with id 'board-token' found in capture-findings-reusable.yml")


def test_board_token_requests_organization_projects_write():
    with_block = _board_token_step()["with"]
    assert with_block.get("permission-organization-projects") == "write", (
        "the board-add mutation needs write access to the org Project"
    )


def test_board_token_also_requests_issues_read():
    # The regression this test exists to catch: this key silently disappearing while
    # `permission-organization-projects` above stays intact.
    with_block = _board_token_step()["with"]
    assert with_block.get("permission-issues") == "read", (
        "without this, addProjectV2ItemById cannot resolve the issue node it was just handed, "
        "and fails as NOT_FOUND indistinguishable from a genuinely absent node"
    )


def test_board_token_also_requests_pull_requests_read():
    """The PR-time review ingest's only guaranteed credential (infra-commons/meta#1187).

    This job's `github.token` can never carry `pull-requests`: a called workflow's token
    is capped by the CALLER's `permissions:` block, and callers grant `contents: read` +
    `issues: write` only. Widening the job's own `permissions:` block would not help —
    it would hard-fail every caller that had not first edited its own workflow.

    Dropping this key does not break anything loudly. capture.py falls back to
    resolving pull requests from commit subjects, which misses every squash merge whose
    subject carries no trailing `(#N)` — so the ingest quietly gets thinner rather than
    stopping, which is the failure shape #1187 exists to remove.
    """
    with_block = _board_token_step()["with"]
    assert with_block.get("permission-pull-requests") == "read", (
        "without this, capture.py cannot read the PR-time reviewers' comments through the "
        "App token and silently degrades to commit-subject PR resolution"
    )
