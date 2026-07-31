"""Tests for the composite release automation and its verifier.

These guard a mechanism whose failure mode is silence: an unreleased composite
looks exactly like a released one from inside this repo. So the assertions that
matter most are the negative ones: that the checker actually goes red when a
tag is behind, and that discovery going wrong fails rather than passes vacuously.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_composite_tags_released as check  # noqa: E402
import release_composites as release  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]


# ── discover_pins ─────────────────────────────────────────────────────────────


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_discovers_a_moving_tag_pin(tmp_path):
    _write(
        tmp_path,
        ".github/workflows/x.yml",
        "jobs:\n  a:\n    steps:\n"
        "      - uses: infra-commons/security/.github/actions/adversarial-review"
        "@adversarial-review/v1\n",
    )
    assert check.discover_pins(tmp_path) == {"adversarial-review": "adversarial-review/v1"}


def test_ignores_sha_pinned_own_composite(tmp_path):
    """A raw SHA pin is a deliberate opt-out of the moving-tag mechanism."""
    _write(
        tmp_path,
        ".github/workflows/x.yml",
        "      - uses: infra-commons/security/.github/actions/thing@" + "a" * 40 + "\n",
    )
    assert check.discover_pins(tmp_path) == {}


def test_ignores_commented_out_pins(tmp_path):
    _write(
        tmp_path,
        ".github/workflows/x.yml",
        "      # - uses: infra-commons/security/.github/actions/thing@thing/v1\n",
    )
    assert check.discover_pins(tmp_path) == {}


def test_this_repo_still_has_pins_to_check():
    """The check's own input. If discovery silently returns nothing, the check
    passes while measuring zero families, the failure it exists to catch."""
    pins = check.discover_pins(REPO_ROOT)
    assert pins, "no own-composite moving-tag pins discovered in this repo"
    assert "adversarial-review" in pins


# ── evaluate ──────────────────────────────────────────────────────────────────


def test_matching_trees_are_released():
    stale, errors = check.evaluate({"f": "f/v1"}, {"f": "tree1"}, {"f": "tree1"})
    assert stale == [] and errors == []


def test_differing_trees_are_stale():
    """The negative control. If this ever stops going red, the whole check is
    decorative, which is precisely the state the repo was in before it."""
    stale, errors = check.evaluate({"f": "f/v1"}, {"f": "new"}, {"f": "old"})
    assert stale == ["f"]
    assert errors == []


def test_missing_tag_is_an_error_not_a_pass():
    stale, errors = check.evaluate({"f": "f/v1"}, {"f": "new"}, {"f": None})
    assert stale == []
    assert len(errors) == 1 and "does not exist" in errors[0]


def test_missing_directory_at_head_is_an_error():
    stale, errors = check.evaluate({"f": "f/v1"}, {"f": None}, {"f": "old"})
    assert stale == []
    assert len(errors) == 1 and "does not exist at HEAD" in errors[0]


def test_one_stale_family_does_not_mask_another():
    stale, _ = check.evaluate(
        {"a": "a/v1", "b": "b/v1"},
        {"a": "new", "b": "new"},
        {"a": "old", "b": "new"},
    )
    assert stale == ["a"]


# ── version numbering ─────────────────────────────────────────────────────────


def _git_repo(tmp_path: Path) -> Path:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=tmp_path, check=True)
    (tmp_path / "f").write_text("x", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "c"], cwd=tmp_path, check=True)
    return tmp_path


def test_first_release_of_a_family_is_v1_0_0(tmp_path):
    root = _git_repo(tmp_path)
    assert release.next_version("fam", "fam/v1", root) == "fam/v1.0.0"


def test_next_release_bumps_the_minor(tmp_path):
    root = _git_repo(tmp_path)
    for tag in ("fam/v1.0.0", "fam/v1.1.0"):
        subprocess.run(["git", "tag", tag], cwd=root, check=True)
    assert release.next_version("fam", "fam/v1", root) == "fam/v1.2.0"


def test_version_numbering_ignores_other_families(tmp_path):
    root = _git_repo(tmp_path)
    subprocess.run(["git", "tag", "other/v1.9.0"], cwd=root, check=True)
    assert release.next_version("fam", "fam/v1", root) == "fam/v1.0.0"


def test_version_numbering_ignores_other_major_lines(tmp_path):
    root = _git_repo(tmp_path)
    subprocess.run(["git", "tag", "fam/v2.5.0"], cwd=root, check=True)
    assert release.next_version("fam", "fam/v1", root) == "fam/v1.0.0"


def test_version_numbering_survives_a_junk_tag(tmp_path):
    """A hand-cut tag that does not parse must not crash the release or, worse,
    silently reset the version line."""
    root = _git_repo(tmp_path)
    for tag in ("fam/v1.0.0", "fam/v1.x", "fam/v1-rc1"):
        subprocess.run(["git", "tag", tag], cwd=root, check=True)
    assert release.next_version("fam", "fam/v1", root) == "fam/v1.1.0"


# ── the property the whole thing exists for ───────────────────────────────────


def test_release_and_check_agree_on_what_stale_means():
    """The releaser and the verifier must not disagree about staleness, or the
    release loop can oscillate: one releases, the other calls it unreleased."""
    assert release.discover_pins is check.discover_pins
    assert release.tree_at is check.tree_at
