#!/usr/bin/env python3
"""Release every composite action whose moving tag is behind `main`.

This is the step that used to be manual, documented in the README as
`git tag -f <family>/v1 <sha> && git push -f origin <family>/v1`, and forgotten
for six of the seven families as of 2026-07-31. Moving a tag by hand is not a
process anybody should have to remember, so this does it.

For each composite whose `.github/actions/<family>/` tree at HEAD differs from
the tree at its `<family>/vN` moving tag, this:

  1. cuts an immutable `<family>/vN.M.0` release tag at HEAD, so every release
     stays individually addressable and a bad one can be pinned away from; then
  2. moves `<family>/vN` to HEAD.

Safety properties, in the order they matter:

* **Post-merge only, and only main's tip.** The job checks out `main`, not the
  triggering run's commit, so HEAD is always a merged commit. Moving a tag onto
  a pre-merge commit is the 2026-07-21 hazard and is structurally impossible
  here; there is no input by which a caller can point it at a branch. An
  *older* main commit is never tagged either: a run approved after main moved
  failed that way (infra-commons/meta#1661, run 36792586886), because GitHub
  rejects an App-token tag push whose commit's workflow files differ from
  main's unless the token holds `workflows`, which it deliberately does not.
* **Tests first.** The calling workflow gates this on every composite test job
  passing. These tags reach 13+ repos' merge gates with no per-caller pin bump
  to review them, so the tests are the only thing between an edit and the fleet.
* **Content, not refs.** Staleness is decided by comparing the git *tree* of the
  action directory, so a tag already pointing at equivalent content is left
  alone and the job is a no-op on the overwhelming majority of pushes.
* **Idempotent.** Re-running on an unchanged `main` releases nothing.

It deliberately does not release a family whose shipped surface is unchanged,
even if other files moved, because the moving tag's only promise is about the
code its consumers execute.

That surface is BOTH the composite action and the reusable workflow the family
owns (`.github/workflows/<family>-reusable.yml`) — see `surface_paths`. It was
the action directory alone until infra-commons/security#63, which held the
promise for consumers pinning the action and broke it for consumers resolving
the reusable at the same tag. A reusable-only change advanced nothing, and
nothing anywhere said so.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_composite_tags_released import (  # noqa: E402
    ACTIONS_DIR,
    discover_families,
    discover_pins,
    git,
    surface_hashes,
    surface_paths,
    tree_at,
)

GITHUB_API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
TESTS_WORKFLOW = "tests.yml"

_VERSION_TAG_RE = re.compile(r"^(?P<family>[A-Za-z0-9._-]+)/v(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)$")


def existing_versions(family: str, major: int, root: Path) -> list[tuple[int, int]]:
    """(minor, patch) pairs already released for this family's major line."""
    out = git("tag", "--list", f"{family}/v{major}.*", cwd=root)
    versions = []
    for line in out.splitlines():
        match = _VERSION_TAG_RE.match(line.strip())
        if match and match.group("family") == family and int(match.group("major")) == major:
            versions.append((int(match.group("minor")), int(match.group("patch"))))
    return sorted(versions)


def next_version(family: str, moving_tag: str, root: Path) -> str:
    """The next minor release on this family's major line."""
    major = int(moving_tag.rsplit("/v", 1)[1])
    versions = existing_versions(family, major, root)
    next_minor = (versions[-1][0] + 1) if versions else 0
    return f"{family}/v{major}.{next_minor}.0"


def version_tag_at(family: str, moving_tag: str, sha: str, root: Path) -> str | None:
    """An immutable release tag on this major line already pointing at `sha`.

    A run that pushed the release tag and then died before moving the moving tag
    leaves exactly this behind. Reusing it keeps the rerun clean instead of
    cutting a second version for the same commit.
    """
    major = int(moving_tag.rsplit("/v", 1)[1])
    for minor, patch in reversed(existing_versions(family, major, root)):
        tag = f"{family}/v{major}.{minor}.{patch}"
        if git("rev-parse", f"{tag}^{{commit}}", cwd=root) == sha:
            return tag
    return None


def remote_main_sha(root: Path) -> str:
    """main's tip on the remote right now, not at checkout."""
    out = git("ls-remote", "origin", "refs/heads/main", cwd=root)
    return out.split()[0] if out else ""


def tests_passed(sha: str, repo: str, token: str) -> bool:
    """Whether the Tests workflow has a successful `push` run on `sha`.

    Raises on any API failure. An unreadable answer is an unknown, and releasing
    untested code on an unknown is the one thing this job must never do.
    """
    query = urllib.parse.urlencode(
        {"head_sha": sha, "event": "push", "branch": "main", "status": "success"}
    )
    request = urllib.request.Request(
        f"{GITHUB_API}/repos/{repo}/actions/workflows/{TESTS_WORKFLOW}/runs?{query}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return int(json.load(response)["total_count"]) > 0


def defer(reason: str) -> None:
    """Hand the release to a newer run. `deferred=true` stops the verify step
    reporting the deliberately untagged HEAD as a failed release."""
    print(f"::notice::{reason}")
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write("deferred=true\n")


def main() -> int:
    root = Path(
        os.environ.get("GITHUB_WORKSPACE")
        or git("rev-parse", "--show-toplevel", cwd=Path.cwd())
    )
    dry_run = os.environ.get("DRY_RUN", "").lower() in {"1", "true", "yes"}

    head = git("rev-parse", "HEAD", cwd=root)
    trigger = os.environ.get("TRIGGER_SHA", "")
    if trigger and trigger != head:
        # The run that fired this one tested an older commit; main has moved
        # since (usually a run left waiting on `fleet-release` while more merged).
        # Release the tip instead, but only on the strength of the tip's OWN
        # green Tests run: the triggering run's success says nothing about it.
        print(
            f"::notice::Triggered by {trigger[:12]}, but main's tip is now "
            f"{head[:12]}. Releasing main's tip, not the triggering commit."
        )
        if not dry_run:
            try:
                green = tests_passed(
                    head,
                    os.environ.get("GITHUB_REPOSITORY", ""),
                    os.environ.get("GITHUB_TOKEN", ""),
                )
            except (OSError, ValueError, KeyError) as exc:
                print(f"::error::Could not confirm Tests passed on {head[:12]}: {exc}")
                return 1
            if not green:
                defer(
                    f"Tests have not passed on {head[:12]} (yet). Releasing "
                    "nothing; that commit's own Tests run triggers its own release."
                )
                return 0

    pins = discover_families(root)
    if not pins:
        print(
            "::error::Found no releasable families. Refusing to run: a release "
            "job that silently releases nothing is worse than one that fails."
        )
        return 1

    released: list[str] = []
    deferred = False
    for family, moving_tag in sorted(pins.items()):
        paths = surface_paths(family, root)
        head_tree = surface_hashes("HEAD", family, root, paths)
        tag_tree = surface_hashes(moving_tag, family, root, paths)

        if not paths or all(v is None for v in head_tree.values()):
            print(
                f"::error::{family}: released at `{moving_tag}` but ships nothing at "
                f"HEAD — no {ACTIONS_DIR}/{family} directory and no reusable workflow"
            )
            return 1
        if head_tree == tag_tree:
            print(f"{family}: already released at `{moving_tag}`, nothing to do")
            continue

        existing = version_tag_at(family, moving_tag, head, root)
        version_tag = existing or next_version(family, moving_tag, root)
        state = "does not exist yet" if tag_tree is None else "is behind"
        print(f"{family}: `{moving_tag}` {state}, releasing {version_tag} at {head[:12]}")

        if dry_run:
            released.append(f"{family} -> {version_tag} (dry run)")
            continue

        # Only ever tag main's tip. If main moved during this run, the newer
        # commit's own release run releases it, and whatever is left here.
        remote = remote_main_sha(root)
        if remote != head:
            defer(
                f"main moved to {remote[:12]} during this run. Not tagging "
                f"{head[:12]}; the newer commit's own release run releases the rest."
            )
            deferred = True
            break

        # The immutable release tag is created, never forced. `protect-immutable-tags`
        # has no bypass actor at all, so an attempt to move one is rejected by the
        # server; failing loudly on a local collision is the same answer, sooner.
        if existing:
            print(f"{family}: {version_tag} already tags {head[:12]}, moving `{moving_tag}` only")
        else:
            git("tag", version_tag, head, cwd=root)
            git("push", "origin", version_tag, cwd=root)

        # The moving tag is a force by definition. `protect-moving-tags` permits
        # this only for the App whose token this job runs as.
        git("tag", "-f", moving_tag, head, cwd=root)
        git("push", "-f", "origin", moving_tag, cwd=root)

        # Verify by content, from the remote, not from what we just pushed
        # locally. The whole class of bug this repo keeps hitting is a release
        # that reports success without landing.
        git("fetch", "--force", "origin", f"refs/tags/{moving_tag}:refs/tags/{moving_tag}", cwd=root)
        landed = surface_hashes(moving_tag, family, root, paths)
        if landed != head_tree:
            print(
                f"::error::{family}: pushed `{moving_tag}` but the remote tag still "
                f"resolves to different content. The release did not land."
            )
            return 1

        released.append(f"{family} -> {version_tag}")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if released:
        lines = ["### Composites released", ""] + [f"- `{line}`" for line in released]
    elif deferred:
        lines = ["### Composites released", "", "None. main moved; deferred to the newer run."]
    else:
        lines = ["### Composites released", "", "None. Every moving tag already matched `main`."]
    print("\n".join(lines))
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
