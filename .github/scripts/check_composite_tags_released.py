#!/usr/bin/env python3
"""Fail when a composite action's moving tag is behind the code on this branch.

Why this exists
---------------
`check-action-pins.sh` deliberately exempts this repo's own composite actions
from the SHA-pin rule, because each composite ships fixes by *moving* its
`<family>/v1` tag (see README, "Reusables' internal composite pins"). That
exemption is what makes the release possible; nothing checked that the release
actually happened.

The README calls that design an improvement on the pre-2026-07-02 failure mode,
where a reusable's inner SHA pin silently lagged a composite fix "because
bumping it was a separate, easy-to-forget manual step". Moving the tag is also a
separate, easy-to-forget manual step, and it is *less* visible than the one it
replaced: a stale inner SHA at least appeared in a diff, whereas an unmoved tag
appears nowhere. On 2026-07-31 six of the seven families were behind `main`,
one of them by two weeks.

An unreleased fix and a released one are indistinguishable from inside the
repository. `main` is green either way, the tests pass either way, the PR reads
as shipped either way, and every consumer keeps running the old code. This check
is the only difference between those two worlds.

`release-composites.yml` now moves these tags automatically after the tests
pass, so in normal operation this check has nothing to report. That is the
point: it is the assertion that the automation did what it claims, and it fails
if the automation is broken, disabled, or silently skipped. A release mechanism
that reports its own success is not evidence; this reads the tags.

What it asserts
---------------
For every family this repo releases at a `<family>/vN` moving tag, the content
of everything that family *ships* must be identical at that tag and at HEAD.
Content hashes are compared, not refs: a tag repointed to a different commit
whose shipped content is identical is correctly treated as released.

A family's shipped surface is BOTH of:

  .github/actions/<family>/                    the composite action, if any
  .github/workflows/<family>-reusable.yml      the reusable workflow, if any

The reusable half was added for infra-commons/security#63. Comparing only the
action directory held the moving tag's promise for consumers who pin the
*action* and broke it for consumers who resolve the *reusable workflow* at the
same tag — and some do. A change to a reusable alone advanced nothing, while
`main` stayed green and the PR read as shipped: the same unreleased-fix failure
this whole mechanism exists to end, displaced one hop sideways.

That also means a family can exist with a reusable and NO action directory.
`dependabot-auto-merge` is exactly that: `dependabot-auto-merge-reusable.yml`
documents callers to pin it at `@dependabot-auto-merge/v1`, and because
`discover_pins()` only sees `uses:` refs into `.github/actions/`, neither the
release nor this check could see the family at all. It was unreleasable and
unverifiable at once, and both reported success. `discover_families()` finds it
from its moving tag instead.

It is meaningful only on `main`. A pull request that changes a composite *must*
be behind its tag until it merges, because moving a tag onto a pre-merge commit
is the hazard recorded on 2026-07-21, so running this on a PR would demand the
one thing that must not happen.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

REPO = "infra-commons/security"
ACTIONS_DIR = ".github/actions"
WORKFLOWS_DIR = ".github/workflows"
REUSABLE_SUFFIX = "-reusable.yml"

# `uses: infra-commons/security/.github/actions/<family>@<family>/v1`
_USES_RE = re.compile(
    r"uses:\s*['\"]?"
    + re.escape(REPO)
    + r"/"
    + re.escape(ACTIONS_DIR)
    + r"/(?P<family>[A-Za-z0-9._-]+)"
    r"@(?P<tag>[A-Za-z0-9._/-]+)"
)
# Only moving major tags are our release mechanism. A raw SHA pin is somebody
# deliberately opting out, and is not this check's business.
_MOVING_TAG_RE = re.compile(r"^[A-Za-z0-9._-]+/v\d+$")


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


def discover_pins(root: Path) -> dict[str, str]:
    """Map family -> moving tag, for every own-composite pin in the repo.

    Scans the same directories `check-action-pins.sh` scans, so the two guards
    cannot disagree about what counts as a pin.
    """
    pins: dict[str, str] = {}
    for base in (".github/workflows", ACTIONS_DIR):
        base_path = root / base
        if not base_path.is_dir():
            continue
        for path in sorted(base_path.rglob("*")):
            if path.suffix not in {".yml", ".yaml"} or not path.is_file():
                continue
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.lstrip().startswith("#"):
                    continue
                match = _USES_RE.search(line)
                if not match:
                    continue
                if not _MOVING_TAG_RE.match(match.group("tag")):
                    continue
                pins[match.group("family")] = match.group("tag")
    return pins


def reusable_path(family: str) -> str:
    return f"{WORKFLOWS_DIR}/{family}{REUSABLE_SUFFIX}"


def surface_paths(family: str, root: Path) -> list[str]:
    """Everything `<family>/vN` ships, as repo-relative paths.

    Both halves are optional independently: `adversarial-review-gate` is an
    action with no reusable, `dependabot-auto-merge` is a reusable with no
    action. A family with neither is an error, reported by `evaluate`.
    """
    paths = []
    if (root / ACTIONS_DIR / family).is_dir():
        paths.append(f"{ACTIONS_DIR}/{family}")
    if (root / reusable_path(family)).is_file():
        paths.append(reusable_path(family))
    return paths


def moving_tag_for(family: str, root: Path) -> str | None:
    """The family's moving tag, read from the tags that actually exist.

    Used only for families no `uses:` line can reveal — a reusable with no
    action directory. Reading the tag list is what makes such a family visible
    at all; there is nothing else in the repo that names it outside a comment,
    and a delivery contract that lives in a comment is not one this can rely on.
    """
    try:
        out = git("tag", "--list", f"{family}/v*", cwd=root)
    except subprocess.CalledProcessError:
        return None
    moving = sorted(t.strip() for t in out.splitlines() if _MOVING_TAG_RE.match(t.strip()))
    return moving[-1] if moving else None


def discover_families(root: Path) -> dict[str, str]:
    """Every family this repo releases -> its moving tag.

    Union of two sources, because neither alone is complete:
      * `uses:` pins into `.github/actions/` — families consumed as actions;
      * a `<family>-reusable.yml` carrying a moving tag — families consumed as
        reusable workflows, which no `uses:` line in this repo mentions.
    """
    families = discover_pins(root)
    workflows = root / WORKFLOWS_DIR
    if workflows.is_dir():
        for path in sorted(workflows.glob(f"*{REUSABLE_SUFFIX}")):
            family = path.name[: -len(REUSABLE_SUFFIX)]
            if family in families:
                continue
            tag = moving_tag_for(family, root)
            if tag:
                families[family] = tag
    return families


def tree_at(ref: str, path: str, root: Path) -> str | None:
    """Content hash of `path` at `ref`, or None if it does not exist there.

    Works for a directory (tree hash) and a single file (blob hash) alike, which
    is what lets one comparison cover both halves of a family's surface.
    """
    try:
        return git("rev-parse", f"{ref}:{path}", cwd=root)
    except subprocess.CalledProcessError:
        return None


def surface_hashes(ref: str, family: str, root: Path, paths: list[str]) -> dict:
    """path -> content hash at `ref`, None where the path is absent there."""
    return {path: tree_at(ref, path, root) for path in paths}


def evaluate(pins: dict[str, str], head_trees: dict, tag_trees: dict):
    """Pure decision step, so every failure mode is unit-testable.

    `head_trees` / `tag_trees` map family -> {path: content hash or None}, so a
    family's whole shipped surface is compared, not just its action directory.

    Returns (stale, errors).
    """
    stale: list[str] = []
    errors: list[str] = []

    for family, tag in sorted(pins.items()):
        head = head_trees.get(family) or {}
        tagged = tag_trees.get(family) or {}

        if not head or all(v is None for v in head.values()):
            errors.append(
                f"{family}: released at `{tag}` but ships nothing at HEAD — no "
                f"{ACTIONS_DIR}/{family} directory and no {reusable_path(family)}"
            )
            continue
        if not tagged or all(v is None for v in tagged.values()):
            errors.append(
                f"{family}: tag `{tag}` does not exist, or ships nothing at that "
                f"tag. Every consumer of this pin is broken until it does."
            )
            continue

        # Any part of the surface differing means the tag does not deliver what
        # HEAD says it does. A path present at HEAD and absent at the tag counts
        # as differing — that is the reusable-only change this check was blind to.
        differing = sorted(p for p in head if head.get(p) != tagged.get(p))
        if differing:
            stale.append(family)

    return stale, errors


def main() -> int:
    root = Path(
        os.environ.get("GITHUB_WORKSPACE")
        or git("rev-parse", "--show-toplevel", cwd=Path.cwd())
    )

    pins = discover_families(root)
    if not pins:
        # The families are this check's input. Finding none means discovery
        # broke, not that the repo stopped using composites. A silent pass here
        # would be the same failure this check exists to catch, one level up.
        print(
            "::error::Found no releasable families to check. This check reads "
            "`uses:` refs from .github/workflows and .github/actions, plus "
            "`*-reusable.yml` workflows carrying a moving tag; if the release "
            "mechanism changed, update or delete this check deliberately."
        )
        return 1

    surfaces = {f: surface_paths(f, root) for f in pins}
    head_trees = {f: surface_hashes("HEAD", f, root, p) for f, p in surfaces.items()}
    tag_trees = {
        f: surface_hashes(pins[f], f, root, p) for f, p in surfaces.items()
    }

    stale, errors = evaluate(pins, head_trees, tag_trees)

    for family in stale:
        differing = sorted(
            p for p in head_trees[family]
            if head_trees[family].get(p) != tag_trees[family].get(p)
        )
        print(
            f"::error::`{family}` is unreleased: {', '.join(differing)} on this "
            f"branch differs from the content at `{pins[family]}`, so every consumer "
            f"is still running the old version. release-composites.yml should have "
            f"moved this tag; check whether it ran."
        )
    for line in errors:
        print(f"::error::{line}")

    if stale or errors:
        print(
            f"\n{len(stale)} unreleased composite(s), {len(errors)} error(s). "
            f"Moving the tag is the release; merging is not."
        )
        return 1

    print(f"All {len(pins)} composite moving tag(s) match the code on this branch. ✅")
    return 0


if __name__ == "__main__":
    sys.exit(main())
