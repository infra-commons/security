"""Board intake (Projects v2): put a newly-filed issue on its org's board at Status `Inbox`.

Extracted from capture.py for infra-commons/meta#1656 so every filer in this repo can use the one
mechanism #661 built and tested, instead of each growing its own. An issue that is not on a board
is invisible to every dispatch surface (the consoles' Inbox->Doing drain, /blocked, /doing-watch).

The credential is an App installation token carrying `organization_projects: write` +
`issues: read` (see capture-findings-reusable.yml's `board-token` step for why both). No
`permissions:` block can grant that to the default Actions token.

Every function here returns/degrades rather than raises. A board-add rides on top of a filing
that has ALREADY happened; it is never a precondition for one. An issue that failed to file
because a board was down is worse than an issue that is off-board.

Stdlib only (no httpx), so a job that has not pip-installed anything can run the CLI:

    python board_intake.py --owner <org> <issue-url> [<issue-url> ...]

The CLI always exits 0 and prints one `::warning::` per issue it could not board.

Deliberately a copy-per-composite module, not a cross-directory import: a family's released
surface is its own action directory plus its reusable (release_composites.surface_paths), so a
file reached through `../` would ship at whatever that other family last released.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

# Mirrors sharedinfra's scripts/projects_topology.py (the control-plane's own copy of the same
# fact) — kept in sync by hand. Five entries, changes rarely; not worth a cross-repo fetch for.
OWNER_PROJECT_NUMBER: dict[str, int] = {
    "infra-commons": 1,
    "rolliq-com": 5,
    "cashbucket-com": 1,
    "klsjapan-com": 1,
    "chargingblindly-com": 1,
}

NO_TOKEN_MESSAGE = (
    "no board App token (INFRA_COMMONS_BOT_PRIVATE_KEY not forwarded, or the mint failed) — "
    "this issue is OFF the board"
)

_GRAPHQL_URL = "https://api.github.com/graphql"
_TIMEOUT_S = 30

_BOARD_FIELDS_Q = """
query($owner: String!, $number: Int!) {
  repositoryOwner(login: $owner) {
    ... on ProjectV2Owner {
      projectV2(number: $number) {
        id
        closed
        fields(first: 50) {
          nodes {
            __typename
            ... on ProjectV2SingleSelectField { id name options { id name } }
          }
        }
      }
    }
  }
}
"""

_ISSUE_NODE_Q = """
query($url: URI!) { resource(url: $url) { __typename ... on Issue { id } } }
"""

_ADD_ITEM_M = """
mutation($project: ID!, $content: ID!) {
  addProjectV2ItemById(input: { projectId: $project, contentId: $content }) { item { id } }
}
"""

_SET_STATUS_M = """
mutation($project: ID!, $item: ID!, $field: ID!, $option: String!) {
  updateProjectV2ItemFieldValue(input: {
    projectId: $project, itemId: $item, fieldId: $field,
    value: { singleSelectOptionId: $option }
  }) { projectV2Item { id } }
}
"""


def _board_graphql(token: str, query: str, variables: dict) -> dict | None:
    """POST one GraphQL query/mutation; return `data`, or None on any failure (logged, never raised)."""
    req = urllib.request.Request(
        _GRAPHQL_URL,
        data=json.dumps({"query": query, "variables": variables}).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            payload = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        print(f"  board: graphql error: HTTP {exc.code}", file=sys.stderr)
        return None
    except Exception as exc:
        print(f"  board: graphql request failed: {exc}", file=sys.stderr)
        return None
    if payload.get("errors"):
        print(f"  board: graphql error: {str(payload['errors'])[:300]}", file=sys.stderr)
        return None
    return payload.get("data")


def issue_node_id(token: str, issue_url: str) -> str | None:
    """The GraphQL node id of the issue at `issue_url` — a gh-CLI filer gets only the URL back."""
    data = _board_graphql(token, _ISSUE_NODE_Q, {"url": issue_url})
    resource = (data or {}).get("resource") or {}
    return resource.get("id") if resource.get("__typename") == "Issue" else None


def add_to_board(token: str, owner: str, issue_node_id: str) -> tuple[bool, str]:
    """Add `issue_node_id` to `owner`'s org Project and set Status = Inbox.

    Returns (ok, message) — `message` is a human-readable reason on failure, or a short success
    note. Never raises: every failure path here is something a caller logs and continues past.
    """
    if not token:
        return False, NO_TOKEN_MESSAGE
    number = OWNER_PROJECT_NUMBER.get(owner)
    if number is None:
        return False, f"owner {owner!r} not in the board topology table"

    # Unreadable is its own message, never "no board, skip": None here means the read failed.
    data = _board_graphql(token, _BOARD_FIELDS_Q, {"owner": owner, "number": number})
    proj = ((data or {}).get("repositoryOwner") or {}).get("projectV2")
    if not proj:
        return False, f"could not read project #{number} field map for {owner!r}"
    if proj.get("closed"):
        return False, f"project #{number} for {owner!r} is closed"

    status_field = next(
        (n for n in proj["fields"]["nodes"] if n and n.get("name") == "Status"), None
    )
    if not status_field:
        return False, f"no Status field on {owner!r}'s project"
    inbox_option = next(
        (o["id"] for o in status_field.get("options", []) if o["name"] == "Inbox"), None
    )
    if inbox_option is None:
        return False, f"no Inbox option on {owner!r}'s Status field"

    project_id = proj["id"]
    add_data = _board_graphql(
        token, _ADD_ITEM_M, {"project": project_id, "content": issue_node_id}
    )
    item = (add_data or {}).get("addProjectV2ItemById", {}).get("item")
    if not item:
        return False, "addProjectV2ItemById failed"

    set_data = _board_graphql(
        token,
        _SET_STATUS_M,
        {
            "project": project_id,
            "item": item["id"],
            "field": status_field["id"],
            "option": inbox_option,
        },
    )
    if set_data is None:
        return False, "added to board but failed to set Status = Inbox"
    return True, "added to board Inbox"


def board_issue(token: str, owner: str, *, node_id: str = "", url: str = "") -> tuple[bool, str]:
    """Board one just-filed issue, by node id or URL. Never raises — a bug here returns (False, why)."""
    try:
        if not token:
            return False, NO_TOKEN_MESSAGE
        if not node_id and url:
            node_id = issue_node_id(token, url) or ""
            if not node_id:
                return False, f"could not resolve {url} to an issue node"
        if not node_id:
            return False, "no issue node id or URL to board"
        return add_to_board(token, owner, node_id)
    except Exception as exc:  # noqa: BLE001 — a board-add bug must never sink the filing
        return False, f"unexpected error: {exc}"


def report(ok: bool, msg: str, what: str) -> None:
    """One line per board attempt. A failure is a `::warning::`, so it is loud in the run summary."""
    if ok:
        print(f"  ✓ {what}: {msg}")
    else:
        print(f"::warning::board-add failed for {what}: {msg}")


def main(argv: list[str] | None = None) -> int:
    import os

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--owner", required=True, help="org login that owns the board")
    ap.add_argument("urls", nargs="*", help="URLs of issues just filed")
    args = ap.parse_args(argv)
    token = os.environ.get("BOARD_APP_TOKEN", "")
    for url in args.urls:
        ok, msg = board_issue(token, args.owner, url=url)
        report(ok, msg, url)
    return 0


if __name__ == "__main__":
    sys.exit(main())
