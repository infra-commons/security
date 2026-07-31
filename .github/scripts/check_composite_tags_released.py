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
For every `uses:` in this repo that pins one of our own composite actions at a
`<family>/vN` moving tag, the tree of `.github/actions/<family>/` at that tag
must equal the tree at HEAD. Tree hashes are compared, so this is a comparison
of content, not of refs: a tag repointed to a different commit whose action
content is identical is correctly treated as released.

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


def tree_at(ref: str, path: str, root: Path) -> str | None:
    """Content hash of `path` at `ref`, or None if it does not exist there."""
    try:
        return git("rev-parse", f"{ref}:{path}", cwd=root)
    except subprocess.CalledProcessError:
        return None


def evaluate(pins: dict[str, str], head_trees: dict, tag_trees: dict):
    """Pure decision step, so every failure mode is unit-testable.

    Returns (stale, errors).
    """
    stale: list[str] = []
    errors: list[str] = []

    for family, tag in sorted(pins.items()):
        head = head_trees.get(family)
        tagged = tag_trees.get(family)
        if head is None:
            errors.append(
                f"{family}: pinned at `{tag}` but {ACTIONS_DIR}/{family} does not "
                f"exist at HEAD"
            )
            continue
        if tagged is None:
            errors.append(
                f"{family}: tag `{tag}` does not exist, or has no "
                f"{ACTIONS_DIR}/{family} directory. Every consumer of this pin is "
                f"broken until it does."
            )
            continue
        if head != tagged:
            stale.append(family)

    return stale, errors


def main() -> int:
    root = Path(
        os.environ.get("GITHUB_WORKSPACE")
        or git("rev-parse", "--show-toplevel", cwd=Path.cwd())
    )

    pins = discover_pins(root)
    if not pins:
        # The pins are this check's input. Finding none means discovery broke,
        # not that the repo stopped using composites. A silent pass here would
        # be the same failure this check exists to catch, one level up.
        print(
            "::error::Found no own-composite moving-tag pins to check. This check "
            "reads `uses:` refs from .github/workflows and .github/actions; if the "
            "release mechanism changed, update or delete this check deliberately."
        )
        return 1

    head_trees = {f: tree_at("HEAD", f"{ACTIONS_DIR}/{f}", root) for f in pins}
    tag_trees = {f: tree_at(t, f"{ACTIONS_DIR}/{f}", root) for f, t in pins.items()}

    stale, errors = evaluate(pins, head_trees, tag_trees)

    for family in stale:
        print(
            f"::error::`{family}` is unreleased: {ACTIONS_DIR}/{family} on this "
            f"branch differs from the code at `{pins[family]}`, so every consumer "
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
