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

* **Post-merge only.** It runs on `push` to `main`, so HEAD is always a merged
  commit. Moving a tag onto a pre-merge commit is the 2026-07-21 hazard and is
  structurally impossible here; there is no input by which a caller can point it
  at a branch.
* **Tests first.** The calling workflow gates this on every composite test job
  passing. These tags reach 13+ repos' merge gates with no per-caller pin bump
  to review them, so the tests are the only thing between an edit and the fleet.
* **Content, not refs.** Staleness is decided by comparing the git *tree* of the
  action directory, so a tag already pointing at equivalent content is left
  alone and the job is a no-op on the overwhelming majority of pushes.
* **Idempotent.** Re-running on an unchanged `main` releases nothing.

It deliberately does not release a family whose directory is unchanged, even if
other files moved, because the moving tag's only promise is about the code its
consumers execute.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_composite_tags_released import (  # noqa: E402
    ACTIONS_DIR,
    discover_pins,
    git,
    tree_at,
)

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


def main() -> int:
    root = Path(
        os.environ.get("GITHUB_WORKSPACE")
        or git("rev-parse", "--show-toplevel", cwd=Path.cwd())
    )
    dry_run = os.environ.get("DRY_RUN", "").lower() in {"1", "true", "yes"}

    head = git("rev-parse", "HEAD", cwd=root)
    pins = discover_pins(root)
    if not pins:
        print(
            "::error::Found no own-composite moving-tag pins. Refusing to run: a "
            "release job that silently releases nothing is worse than one that fails."
        )
        return 1

    released: list[str] = []
    for family, moving_tag in sorted(pins.items()):
        head_tree = tree_at("HEAD", f"{ACTIONS_DIR}/{family}", root)
        tag_tree = tree_at(moving_tag, f"{ACTIONS_DIR}/{family}", root)

        if head_tree is None:
            print(f"::error::{family}: pinned at `{moving_tag}` but has no directory at HEAD")
            return 1
        if head_tree == tag_tree:
            print(f"{family}: already released at `{moving_tag}`, nothing to do")
            continue

        version_tag = next_version(family, moving_tag, root)
        state = "does not exist yet" if tag_tree is None else "is behind"
        print(f"{family}: `{moving_tag}` {state}, releasing {version_tag} at {head[:12]}")

        if dry_run:
            released.append(f"{family} -> {version_tag} (dry run)")
            continue

        # The immutable release tag is created, never forced. `protect-immutable-tags`
        # has no bypass actor at all, so an attempt to move one is rejected by the
        # server; failing loudly on a local collision is the same answer, sooner.
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
        landed = tree_at(moving_tag, f"{ACTIONS_DIR}/{family}", root)
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
    else:
        lines = ["### Composites released", "", "None. Every moving tag already matched `main`."]
    print("\n".join(lines))
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
