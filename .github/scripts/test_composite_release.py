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


def _action(family: str, h):
    return {f"{check.ACTIONS_DIR}/{family}": h}


def _both(family: str, action_h, reusable_h):
    """A family shipping BOTH an action directory and a reusable workflow."""
    return {
        f"{check.ACTIONS_DIR}/{family}": action_h,
        check.reusable_path(family): reusable_h,
    }


def test_matching_trees_are_released():
    stale, errors = check.evaluate({"f": "f/v1"}, {"f": _action("f", "t1")},
                                   {"f": _action("f", "t1")})
    assert stale == [] and errors == []


def test_differing_trees_are_stale():
    """The negative control. If this ever stops going red, the whole check is
    decorative, which is precisely the state the repo was in before it."""
    stale, errors = check.evaluate({"f": "f/v1"}, {"f": _action("f", "new")},
                                   {"f": _action("f", "old")})
    assert stale == ["f"]
    assert errors == []


def test_missing_tag_is_an_error_not_a_pass():
    stale, errors = check.evaluate({"f": "f/v1"}, {"f": _action("f", "new")},
                                   {"f": _action("f", None)})
    assert stale == []
    assert len(errors) == 1 and "does not exist" in errors[0]


def test_missing_surface_at_head_is_an_error():
    stale, errors = check.evaluate({"f": "f/v1"}, {"f": _action("f", None)},
                                   {"f": _action("f", "old")})
    assert stale == []
    assert len(errors) == 1 and "ships nothing at HEAD" in errors[0]


def test_a_family_with_no_surface_at_all_is_an_error_not_a_pass():
    """An empty surface must never read as 'nothing differs, so it is released'."""
    stale, errors = check.evaluate({"f": "f/v1"}, {"f": {}}, {"f": {}})
    assert stale == [] and len(errors) == 1


def test_one_stale_family_does_not_mask_another():
    stale, _ = check.evaluate(
        {"a": "a/v1", "b": "b/v1"},
        {"a": _action("a", "new"), "b": _action("b", "new")},
        {"a": _action("a", "old"), "b": _action("b", "new")},
    )
    assert stale == ["a"]


# ── #63: the reusable half of a family's surface ──────────────────────────────


def test_a_reusable_only_change_is_stale():
    """THE regression. The action directory is identical and only the reusable
    moved — which used to report released while every caller resolving the
    reusable at that tag kept running the old one."""
    stale, errors = check.evaluate(
        {"f": "f/v1"},
        {"f": _both("f", "same", "new-reusable")},
        {"f": _both("f", "same", "old-reusable")},
    )
    assert stale == ["f"] and errors == []


def test_an_action_only_change_is_still_stale():
    """The half that already worked must keep working."""
    stale, _ = check.evaluate(
        {"f": "f/v1"},
        {"f": _both("f", "new", "same")},
        {"f": _both("f", "old", "same")},
    )
    assert stale == ["f"]


def test_a_family_matching_on_both_halves_is_released():
    stale, errors = check.evaluate(
        {"f": "f/v1"},
        {"f": _both("f", "a", "b")},
        {"f": _both("f", "a", "b")},
    )
    assert stale == [] and errors == []


def test_a_reusable_added_after_the_tag_was_cut_is_stale():
    """Present at HEAD, absent at the tag. Consumers resolving the reusable at
    that tag get nothing, so this is unreleased, not 'no change'."""
    stale, _ = check.evaluate(
        {"f": "f/v1"},
        {"f": _both("f", "same", "brand-new")},
        {"f": _both("f", "same", None)},
    )
    assert stale == ["f"]


def test_a_reusable_only_family_with_no_action_directory_is_evaluated():
    """`dependabot-auto-merge`'s shape: a reusable and no action directory. It
    must be comparable rather than erroring or being skipped."""
    head = {check.reusable_path("f"): "new"}
    tagged = {check.reusable_path("f"): "old"}
    stale, errors = check.evaluate({"f": "f/v1"}, {"f": head}, {"f": tagged})
    assert stale == ["f"] and errors == []


# ── #63: discovery ────────────────────────────────────────────────────────────


def test_discover_families_finds_a_reusable_only_family(tmp_path):
    """No `uses:` line in this repo names such a family — only its tag does. If
    discovery misses it, the family is unreleasable AND unverifiable, and both
    report success."""
    root = _git_repo(tmp_path)
    _write(root, ".github/workflows/depbot-reusable.yml", "on: workflow_call\n")
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "add reusable"], cwd=root, check=True)
    subprocess.run(["git", "tag", "depbot/v1"], cwd=root, check=True)

    assert check.discover_families(root).get("depbot") == "depbot/v1"


def test_a_reusable_without_a_moving_tag_is_not_a_family(tmp_path):
    """Not every `*-reusable.yml` is independently released — most are delivered
    inside a family that also has an action. Inventing families from filenames
    would make the release try to cut tags nobody asked for."""
    root = _git_repo(tmp_path)
    _write(root, ".github/workflows/orphan-reusable.yml", "on: workflow_call\n")
    assert "orphan" not in check.discover_families(root)


def test_this_repo_has_a_reusable_only_family_to_find():
    """The positive control for the discovery above, against the real repo. If
    this stops holding, the widening silently covers nothing."""
    families = check.discover_families(REPO_ROOT)
    assert "dependabot-auto-merge" in families, (
        "dependabot-auto-merge is a reusable with no action directory; it is the "
        "case #63 was filed about"
    )
    assert "dependabot-auto-merge" not in check.discover_pins(REPO_ROOT), (
        "if the old discovery can see it, this test is no longer measuring anything"
    )


def test_surface_paths_covers_both_halves_where_both_exist():
    paths = check.surface_paths("adversarial-review", REPO_ROOT)
    assert f"{check.ACTIONS_DIR}/adversarial-review" in paths
    assert check.reusable_path("adversarial-review") in paths


def test_surface_paths_omits_the_half_that_does_not_exist():
    gate = check.surface_paths("adversarial-review-gate", REPO_ROOT)
    assert gate == [f"{check.ACTIONS_DIR}/adversarial-review-gate"]
    depbot = check.surface_paths("dependabot-auto-merge", REPO_ROOT)
    assert depbot == [check.reusable_path("dependabot-auto-merge")]


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
    # Added with #63: widening one side's notion of a family's surface and not
    # the other is exactly how that oscillation would start.
    assert release.discover_families is check.discover_families
    assert release.surface_paths is check.surface_paths
    assert release.surface_hashes is check.surface_hashes


def test_the_releaser_actually_releases_a_reusable_only_family(tmp_path, monkeypatch, capsys):
    """Behavioural, because the identity assertions above are not enough.

    Those check that the releaser *imports* the shared helpers. Swapping
    `main()` back to `discover_pins` leaves every one of them green — the import
    is still there, it is just unused. A mutation proved exactly that. This runs
    the releaser and asserts on what it decides, which is the property that
    matters.
    """
    root = _git_repo(tmp_path)
    _write(root, ".github/workflows/depbot-reusable.yml", "on: workflow_call\n# v1\n")
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "reusable"], cwd=root, check=True)
    subprocess.run(["git", "tag", "depbot/v1"], cwd=root, check=True)

    # A reusable-only change: nothing under .github/actions/ moves at all.
    _write(root, ".github/workflows/depbot-reusable.yml", "on: workflow_call\n# v2\n")
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "change the reusable only"], cwd=root, check=True)

    monkeypatch.setenv("GITHUB_WORKSPACE", str(root))
    monkeypatch.setenv("DRY_RUN", "1")
    assert release.main() == 0

    out = capsys.readouterr().out
    assert "depbot" in out, "the reusable-only family was not even discovered"
    assert "releasing depbot/v1.0.0" in out, (
        f"a reusable-only change did not trigger a release:\n{out}"
    )
