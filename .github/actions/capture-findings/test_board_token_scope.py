"""Pin the `board-token` step's permission scope (infra-commons/meta#661).

`create-github-app-token` replaces the App install's full grant with exactly the `permission-*`
inputs given — it does not narrow additively. The `board-token` step used to request only
`organization-projects: write`, so the minted token had zero `issues` scope, and
`addProjectV2ItemById`'s `contentId` (the issue this same job just created) could never resolve.
That failed as `NOT_FOUND` on a node that plainly exists, one log line, job still exits 0 —
indistinguishable from "no findings this run." No board-add has ever succeeded because of it.

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
