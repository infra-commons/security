#!/usr/bin/env python3
"""
Evaluate a single PR for auto-merge-churn eligibility and, if eligible,
approve it and enable native auto-merge.

This is DETECTION + APPROVAL, not a merge itself: it only calls `gh pr review
--approve` and `gh pr merge --auto`, so the full required-check gauntlet
(adversarial, legal, tests, pin-check) still gates the actual merge exactly
as it does for a human-reviewed PR.

── Eligibility (ALL must hold) ─────────────────────────────────────────────
  1. PR author is in { rolliqdotcom, infra-commons-bot, dependabot[bot] }
  2. NONE of the changed files hit a hard-exclusion guardrail (below)
  3. EITHER every changed file matches the path allowlist
     (suppressions + confidential-terms, plus any caller-supplied globs)
     OR the PR carries the label `autofix:security`
Anything else is a silent no-op — the PR simply waits for Kevin as before.

── Hard exclusions (cannot be overridden by any allowlist) ─────────────────
  - .github/workflows/**   <- self-privilege-escalation guard. NOTE: this is why
    "action-pin sync" PRs (pins live inside workflow files) are NOT auto-merged
    -- they fall through to Kevin by design.
  - **/branch-rulesets.json, **/CODEOWNERS, scripts/apply-branch-rulesets.sh
  - clients-config repo entirely (belt-and-braces; callers also simply omit it)
  - dependabot major bumps never match the allowlist or carry the label, so
    they naturally fall through (daily-health-check already handles the
    minor/patch dependabot lane; dependabot is listed here only for parity).

── Why the decision is a pure function ─────────────────────────────────────
`decide()` takes everything it needs as arguments and touches neither the
environment nor the network, so every branch is reachable from a unit test.
This action decides which PRs get auto-approved and auto-merged across 13+
repos, and until infra-commons/security#61 it had no tests at all: the module
read `os.environ[...]` at import, so it could not even be imported without a
full CI environment. The same split is used by adversarial-review-gate/gate.py
for the same reason.

Required env vars:
  GH_TOKEN       gh CLI token (approve + merge rights; caller resolves App vs
                 GITHUB_TOKEN fallback before invoking this script)
  GH_REPO        owner/repo slug
  PR_NUMBER      pull request number to evaluate
  PR_AUTHOR      login of the PR author
  RUN_URL        workflow-run URL, included in the approval comment (optional)
  ALLOWED_GLOBS  newline-separated extra path globs (optional)
"""
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field

ALLOWED_AUTHORS = {"rolliqdotcom", "infra-commons-bot", "dependabot[bot]"}

# Hard exclusions — self-privilege-escalation surface. Never auto-merged
# even if an allowlist glob would otherwise match.
HARD_EXCLUDE = [
    ".github/workflows/**",
    "**/branch-rulesets.json", "branch-rulesets.json",
    "**/CODEOWNERS", "CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS",
    "scripts/apply-branch-rulesets.sh",
]
# Built-in path allowlist — the low-risk sync-managed churn files.
DEFAULT_ALLOW = [
    ".github/*-suppressions.yml",
    ".github/confidential-terms-allow.txt",
]

EXCLUDED_REPOS = {"clients-config"}


def glob_to_re(pat: str) -> "re.Pattern":
    # ** -> any (incl. /); * -> any except /; ? -> single non-/.
    out, i = ["^"], 0
    while i < len(pat):
        if pat[i:i + 2] == "**":
            out.append(".*"); i += 2; continue
        c = pat[i]
        if c == "*":   out.append("[^/]*")
        elif c == "?": out.append("[^/]")
        else:          out.append(re.escape(c))
        i += 1
    out.append("$")
    return re.compile("".join(out))


HARD_RE = [glob_to_re(p) for p in HARD_EXCLUDE]

# Suppression files carry accepted-risk edits. When one documents an accepted
# CRITICAL, the legal/adversarial gate stays red BY DESIGN — a suppression
# cannot green a genuine CRITICAL; that needs a repo-owner bypass merge, and the
# bypass IS the sign-off. Enabling native auto-merge on such a PR HIDES GitHub's
# manual "merge without waiting for requirements" button, stranding the PR
# against a gate that will never go green (this bit us on the consent-removal
# suppression, rolliq solution-rrc #711). So we still auto-APPROVE suppression
# PRs (they satisfy reviews:1 and merge in one click when green), but never
# auto-ENABLE auto-merge on them — the human keeps the bypass button.
SUPPRESSION_RE = glob_to_re(".github/*-suppressions.yml")


@dataclass(frozen=True)
class Decision:
    """What to do with this PR, and why.

    `eligible` gates the approval. `enable_auto_merge` is a SEPARATE decision:
    a suppression PR is approved but must never have auto-merge enabled, so the
    two must not be collapsed into one boolean.
    """
    eligible: bool
    reason: str
    basis: str = ""
    enable_auto_merge: bool = False
    suppression_files: tuple = field(default_factory=tuple)


def precheck(repo: str, author: str):
    """The rejections that need no API call, or None to keep going.

    Split out so `main()` can skip the `gh pr view` for an unlisted author
    without re-implementing the test — two copies of this rule could disagree,
    and the copy that runs in production would be the one nobody tested.
    """
    if repo.split("/")[-1] in EXCLUDED_REPOS:
        return Decision(False, "clients-config is excluded entirely")
    if author not in ALLOWED_AUTHORS:
        return Decision(False, f"author {author!r} not in allowlist")
    return None


def decide(repo: str, author: str, files, labels, extra_globs=()) -> Decision:
    """Pure eligibility decision. No environment, no network, no side effects."""
    early = precheck(repo, author)
    if early is not None:
        return early

    files = list(files)
    if not files:
        # An empty file list means the API told us nothing, not that the PR is
        # harmless. Approving on no evidence is the one thing this must not do.
        return Decision(False, "no changed files reported")

    hit = next((f for f in files for rx in HARD_RE if rx.match(f)), None)
    if hit:
        return Decision(False, f"guardrail: changed file {hit!r} is a hard-exclusion")

    allow_re = [glob_to_re(p) for p in list(DEFAULT_ALLOW) + list(extra_globs)]
    all_allowed = all(any(rx.match(f) for rx in allow_re) for f in files)
    has_autofix = "autofix:security" in set(labels)
    if not (all_allowed or has_autofix):
        offending = [f for f in files if not any(rx.match(f) for rx in allow_re)]
        return Decision(
            False,
            "not eligible — no autofix:security label and these files are "
            f"outside the allowlist: {offending}",
        )

    basis = "autofix:security label" if has_autofix else "all files within path allowlist"
    supp = tuple(f for f in files if SUPPRESSION_RE.match(f))
    return Decision(
        eligible=True,
        reason=f"eligible ({basis})",
        basis=basis,
        # See SUPPRESSION_RE: approve, but leave the manual bypass button intact.
        enable_auto_merge=not supp,
        suppression_files=supp,
    )


def gh_json(*args):
    r = subprocess.run(["gh", *args], capture_output=True, text=True, check=True)
    return json.loads(r.stdout)


def main() -> None:
    repo = os.environ["GH_REPO"]
    num = os.environ["PR_NUMBER"]
    author = os.environ["PR_AUTHOR"]
    run_url = os.environ.get("RUN_URL", "")
    extra = [g.strip() for g in os.environ.get("ALLOWED_GLOBS", "").splitlines() if g.strip()]

    # Cheap checks first, so a PR from an unlisted author costs no API call.
    early = precheck(repo, author)
    if early is not None:
        print(f"auto-merge-churn: NO-OP — {early.reason}")
        return

    data = gh_json("pr", "view", num, "--repo", repo, "--json", "files,labels")
    files = [f["path"] for f in data.get("files", [])]
    labels = [lbl["name"] for lbl in data.get("labels", [])]

    decision = decide(repo, author, files, labels, extra)
    if not decision.eligible:
        print(f"auto-merge-churn: NO-OP — {decision.reason}")
        return

    print(f"auto-merge-churn: ELIGIBLE ({decision.basis}) — approving #{num} in {repo}")

    # Approve (satisfies reviews:1; bot != PR author so it counts).
    try:
        subprocess.run(
            ["gh", "pr", "review", num, "--repo", repo, "--approve", "--body",
             f"Auto-approved by auto-merge-churn ({decision.basis}). "
             f"Required checks still gate the merge. Run: {run_url}"],
            capture_output=True, text=True, check=True)
        print("  approved")
    except subprocess.CalledProcessError as exc:
        err = (exc.stderr or "").lower()
        if "already" in err or "can't approve" in err or "cannot approve" in err:
            print("  already approved")
        else:
            print(f"  WARNING: approval failed: {exc.stderr.strip()[:120]}", file=sys.stderr)

    if not decision.enable_auto_merge:
        print(f"  suppression file(s) touched ({list(decision.suppression_files)}); leaving "
              "auto-merge OFF so the manual bypass button stays available. Approved only.")
        return

    # Enable native auto-merge — merges only once required checks pass.
    try:
        subprocess.run(
            ["gh", "pr", "merge", num, "--repo", repo, "--auto", "--squash"],
            capture_output=True, text=True, check=True)
        print("  auto-merge enabled (squash)")
    except subprocess.CalledProcessError as exc:
        print(f"  WARNING: could not enable auto-merge: {exc.stderr.strip()[:120]}; "
              f"PR is approved — Kevin can merge manually", file=sys.stderr)


if __name__ == "__main__":
    main()
