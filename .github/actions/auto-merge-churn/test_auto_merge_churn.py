"""Tests for the auto-merge-churn eligibility decision.

This action decides which PRs get auto-approved and auto-merged across 13+
repos, and it had no tests at all until infra-commons/security#61 — while the
release automation added in #60 means an edit here reaches every one of those
repos as soon as the tag advances. The costs are asymmetric:

  a wrong `eligible`      auto-approves and merges a change nobody read, and the
                          approval satisfies `reviews: 1` so nothing else stops it
  a wrong `not eligible`  a churn PR waits for a human, which is only the old
                          behaviour and costs nothing but time

So the assertions below lean on the first: every guardrail is tested from the
direction that would let something through, and the eligible cases are pinned
narrowly enough that widening them fails here first.
"""
import importlib.util
from pathlib import Path

import pytest

_MODULE_PATH = Path(__file__).parent / "auto-merge-churn.py"
_spec = importlib.util.spec_from_file_location("auto_merge_churn", _MODULE_PATH)
churn = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(churn)

REPO = "rolliq-com/platform-iac"
BOT = "infra-commons-bot"
SUPPRESSION = ".github/adversarial-review-suppressions.yml"
ALLOWED_FILE = ".github/confidential-terms-allow.txt"


def decide(files, *, repo=REPO, author=BOT, labels=(), globs=()):
    return churn.decide(repo, author, files, labels, globs)


# ── author allowlist ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("author", ["rolliqdotcom", "infra-commons-bot", "dependabot[bot]"])
def test_the_three_allowed_authors_are_eligible(author):
    assert decide([ALLOWED_FILE], author=author).eligible is True


@pytest.mark.parametrize("author", ["kev-rolliq", "attacker", "", "Infra-Commons-Bot"])
def test_any_other_author_is_rejected(author):
    """Including a case variant: GitHub logins are case-insensitive to humans but
    this comparison is not, and matching loosely here would widen the set of
    identities that can auto-approve."""
    assert decide([ALLOWED_FILE], author=author).eligible is False


# ── hard exclusions: the self-privilege-escalation guard ──────────────────────


@pytest.mark.parametrize("path", [
    ".github/workflows/tier-a.yml",
    ".github/workflows/nested/deep.yml",
    "branch-rulesets.json",
    "infra/branch-rulesets.json",
    "CODEOWNERS",
    ".github/CODEOWNERS",
    "docs/CODEOWNERS",
    "scripts/apply-branch-rulesets.sh",
])
def test_every_hard_exclusion_blocks_eligibility(path):
    """A workflow file is how this action would grant itself more power, so this
    guard is the one that must not be loosened by any allowlist.

    The `autofix:security` label is applied deliberately, and it is what makes
    this a test of the *guardrail*. Without it these paths are also outside the
    path allowlist, so the PR is rejected either way — deleting the
    hard-exclusion check entirely left this test green (found by mutation).
    With the label, the allowlist can no longer be the reason for rejection, so
    only the guardrail can be.
    """
    assert decide([path], labels=["autofix:security"]).eligible is False


def test_a_hard_exclusion_wins_even_with_the_autofix_label():
    """The label is an escape hatch for the path allowlist, never for the
    guardrails. If the label could override this, any labelled PR could edit a
    workflow and auto-merge it."""
    assert decide(
        [".github/workflows/tier-a.yml"], labels=["autofix:security"]
    ).eligible is False


def test_a_hard_exclusion_wins_even_when_every_other_file_is_allowed():
    """One bad file in an otherwise clean PR must sink the whole PR — the check
    is over the file set, not a majority vote."""
    assert decide([ALLOWED_FILE, ".github/workflows/x.yml"]).eligible is False


def test_a_hard_exclusion_wins_even_via_a_caller_supplied_glob():
    """A caller cannot widen its way into the workflow directory."""
    assert decide(
        [".github/workflows/x.yml"], globs=[".github/**"]
    ).eligible is False


def test_the_clients_config_repo_is_excluded_entirely():
    assert decide([ALLOWED_FILE], repo="rolliq-com/clients-config").eligible is False


# ── the path allowlist and the label escape hatch ─────────────────────────────


def test_a_file_outside_the_allowlist_without_the_label_is_not_eligible():
    assert decide(["src/app.py"]).eligible is False


def test_the_autofix_label_admits_files_outside_the_allowlist():
    assert decide(["src/app.py"], labels=["autofix:security"]).eligible is True


def test_a_caller_supplied_glob_widens_the_allowlist():
    assert decide(["docs/changelog.md"], globs=["docs/*.md"]).eligible is True


def test_all_files_must_be_allowed_not_merely_one():
    assert decide([ALLOWED_FILE, "src/app.py"]).eligible is False


def test_an_empty_file_list_is_never_eligible():
    """No evidence is not evidence of harmlessness. An API hiccup returning no
    files must not read as 'this PR changes nothing dangerous'."""
    assert decide([]).eligible is False


def test_a_star_glob_does_not_cross_a_directory_separator():
    """`.github/*-suppressions.yml` must not match a nested path — otherwise the
    allowlist reaches further than it reads."""
    assert decide([".github/nested/x-suppressions.yml"]).eligible is False


# ── the suppression-PR exclusion (the rrc#711 trap) ───────────────────────────


def test_a_suppression_pr_is_eligible_but_auto_merge_stays_off():
    """THE regression. A suppression documenting an accepted CRITICAL leaves the
    gate red BY DESIGN; enabling native auto-merge hides GitHub's manual
    "merge without waiting for requirements" button and strands the PR against a
    gate that will never go green.

    Asserted on the effect — `enable_auto_merge is False` — not on which branch
    was taken, because the branch is not what stranded rrc#711."""
    decision = decide([SUPPRESSION])
    assert decision.eligible is True, "suppression PRs are still auto-approved"
    assert decision.enable_auto_merge is False
    assert decision.suppression_files == (SUPPRESSION,)


def test_a_non_suppression_pr_does_get_auto_merge_enabled():
    """The other direction. Without this the exclusion could widen to everything
    and every test above would still pass — auto-merge would simply never be
    enabled, silently."""
    decision = decide([ALLOWED_FILE])
    assert decision.eligible is True
    assert decision.enable_auto_merge is True


def test_one_suppression_file_among_others_still_disables_auto_merge():
    decision = decide([ALLOWED_FILE, SUPPRESSION])
    assert decision.eligible is True and decision.enable_auto_merge is False


@pytest.mark.parametrize("path", [
    ".github/adversarial-review-suppressions.yml",
    ".github/legal-review-suppressions.yml",
    ".github/pentest-suppressions.yml",
])
def test_every_suppression_flavour_disables_auto_merge(path):
    assert decide([path]).enable_auto_merge is False


def test_a_suppression_pr_admitted_by_the_label_also_keeps_auto_merge_off():
    """The label changes eligibility, never the bypass-button protection."""
    decision = decide([SUPPRESSION, "src/app.py"], labels=["autofix:security"])
    assert decision.eligible is True and decision.enable_auto_merge is False


# ── precheck / decide agreement ───────────────────────────────────────────────


@pytest.mark.parametrize("repo,author", [
    ("rolliq-com/clients-config", BOT),
    (REPO, "stranger"),
])
def test_precheck_and_decide_agree_on_the_cheap_rejections(repo, author):
    """`main()` calls `precheck` to skip the API call. If the two ever disagree,
    production would take a path no test covers."""
    assert churn.precheck(repo, author) is not None
    assert churn.decide(repo, author, [ALLOWED_FILE], ()).eligible is False


def test_precheck_passes_a_normal_pr_through():
    assert churn.precheck(REPO, BOT) is None


# ── main(): auto-merge must not get armed on a genuine approve failure ───────────
#
# infra-commons/security#815: the reusable workflow documents "if the approver App
# is omitted, the approve step fails soft (the PR simply waits for a human)" — i.e.
# a real approval failure must leave auto-merge OFF. A prior version enabled
# `gh pr merge --auto` unconditionally after a failed approve, silently arming
# auto-merge for the next incidental human approval.

def _set_main_env(monkeypatch, repo=REPO, num="1", author=BOT, run_url="http://run"):
    monkeypatch.setenv("GH_REPO", repo)
    monkeypatch.setenv("PR_NUMBER", num)
    monkeypatch.setenv("PR_AUTHOR", author)
    monkeypatch.setenv("RUN_URL", run_url)
    monkeypatch.delenv("ALLOWED_GLOBS", raising=False)


def test_main_does_not_enable_auto_merge_when_approve_fails(monkeypatch):
    _set_main_env(monkeypatch)
    monkeypatch.setattr(churn, "gh_json",
                        lambda *a: {"files": [{"path": ALLOWED_FILE}], "labels": []})

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:3] == ["gh", "pr", "review"]:
            raise churn.subprocess.CalledProcessError(
                1, cmd, output="", stderr="HTTP 403: token lacks approve permission")
        raise AssertionError(f"must not reach: {cmd}")

    monkeypatch.setattr(churn.subprocess, "run", fake_run)
    churn.main()
    assert not any(cmd[:3] == ["gh", "pr", "merge"] for cmd in calls)


@pytest.mark.parametrize("stderr", ["already approved", "you can't approve your own PR"])
def test_main_still_enables_auto_merge_when_already_approved(monkeypatch, stderr):
    _set_main_env(monkeypatch)
    monkeypatch.setattr(churn, "gh_json",
                        lambda *a: {"files": [{"path": ALLOWED_FILE}], "labels": []})

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:3] == ["gh", "pr", "review"]:
            raise churn.subprocess.CalledProcessError(1, cmd, output="", stderr=stderr)
        class R:
            returncode = 0
            stdout = ""
            stderr = ""
        return R()

    monkeypatch.setattr(churn.subprocess, "run", fake_run)
    churn.main()
    assert any(cmd[:3] == ["gh", "pr", "merge"] for cmd in calls)
