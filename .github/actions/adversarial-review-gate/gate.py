"""Decide the adversarial-review gate result from the reviewer jobs' outcomes.

The gate exists to stop a merge when an adversarial reviewer finds a CRITICAL
issue. It must not stop a merge merely because a provider was unreachable — a
required, fails-closed check that treats "the vendor is down" the same as "the
vendor found a problem" freezes every merge in the repo for as long as the
outage lasts, and arming a *second* provider under a boolean AND doubles the
number of vendors able to cause that freeze rather than providing a fallback.

So the result is three-state, not boolean:

  blocked       a reviewer found a CRITICAL, a reviewer that was asked to run
                was skipped, or every reviewer crashed
  degraded      passed, but with less review than the repo is configured for
  clear         every reviewer that was asked to run returned a verdict

`degraded` still passes the check. It is a pass with a named deficit, and it is
reported loudly (annotation + job summary + a machine-readable `result` output
the caller workflow records), because a degraded pass that renders identically
to a full pass is how a missing review becomes invisible.

What each reviewer contributes is classified from three signals it publishes:

  result        the job's own conclusion (success / failure / cancelled / skipped)
  has_critical  the reviewer's verdict, set only when the job completed
  outcome       what the reviewer actually did — `reviewed`, `no-diff`,
                `api-error`, or `quota-exhausted` (it fails open on transient
                provider errors, so "completed with no CRITICAL" does not by
                itself mean "reviewed")

The `outcome` signal is what keeps this honest. Without it a reviewer that
failed open is indistinguishable from one that read the diff and found nothing,
and the gate would report a clean review that never happened. An older pinned
reviewer action does not publish it; that is reported as unknown rather than
assumed to be a real review.

── Quota exhaustion is the one repeat that tightens ──────────────────────────
Failing open on a rate limit and failing open on an exhausted budget are not
the same trade. A rate limit is transient: the next run reviews the change, so
the cost is a delay. An exhausted budget is not — once hit, every subsequent PR
would pass unreviewed and green for as long as the billing period lasts, which
turns a deliberate temporary degradation into an indefinite silent absence of
review.

So `quota-exhausted` degrades on its first occurrence and BLOCKS thereafter:
the first change is not held up, and the tenth is not merged unreviewed. The
memory that distinguishes first from thereafter is a tracking issue in the
consuming repo, passed in as `quota_marker_open` — a job has no state of its
own, and a durable marker a human can see and close is better than one it
cannot. Closing that issue is what re-arms the single free pass.

The block is deliberately narrow: it requires that NO reviewer produced a
verdict. If a second provider reviewed the change, the change was reviewed, and
blocking would buy nothing.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass

# ── Per-reviewer states ───────────────────────────────────────────────────────

CRITICAL = "critical"            # completed, found a CRITICAL — always blocks
CLEAR = "clear"                  # completed, reviewed the diff, found nothing
NO_DIFF = "no-diff"              # completed, there was nothing to review
UNKNOWN_OUTCOME = "unknown"      # completed clean, but did not say what it did
FAILED_OPEN = "failed-open"      # completed clean *because* the provider errored
QUOTA_EXHAUSTED = "quota-exhausted"  # completed clean *because* the budget ran out
ERRORED = "errored"              # the job did not complete
SKIPPED = "skipped"              # asked to run and did not — a configuration fault
NOT_REQUIRED = "not-required"    # never asked to run (fork / bot / not enabled)

# A verdict: this reviewer looked (or had nothing to look at) and said so.
_VERDICT = frozenset({CLEAR, NO_DIFF, UNKNOWN_OUTCOME})
# Completed, but deliberately without a verdict. The reviewer action fails open
# on transient provider errors and posts a PR comment saying the change was not
# reviewed. That posture predates this gate and is not overturned here: it is
# what stops a broad provider outage from freezing every consuming repo. It
# counts as "the job did not fail", never as "the change was reviewed".
_FAILED_OPEN = frozenset({FAILED_OPEN})
# Also completed without a verdict, but for a cause that does not clear itself.
# Held separately from _FAILED_OPEN because it is the only state whose second
# occurrence is treated differently from its first — see `evaluate`.
_QUOTA = frozenset({QUOTA_EXHAUSTED})
# Asked to run and produced nothing at all, not even a fail-open.
_ERRORED = frozenset({ERRORED})
# Everything the gate must report as reduced coverage.
_MISSING = _FAILED_OPEN | _QUOTA | _ERRORED

# ── Gate results ──────────────────────────────────────────────────────────────

BLOCKED = "blocked"
DEGRADED = "degraded"
CLEAR_RESULT = "clear"
NOT_REQUIRED_RESULT = "not-required"

_VALID_HAS_CRITICAL = frozenset({"true", "false", ""})


@dataclass(frozen=True)
class Reviewer:
    """One reviewer job's reported signals."""

    name: str
    required: bool
    result: str
    has_critical: str
    outcome: str


@dataclass(frozen=True)
class Decision:
    result: str
    reason: str
    states: dict
    messages: tuple

    @property
    def blocks(self) -> bool:
        return self.result == BLOCKED


def classify(reviewer: Reviewer) -> str:
    """Reduce one reviewer's three signals to a single state."""
    # A CRITICAL outranks everything, including "this reviewer was not required".
    # If a reviewer ran anyway and found a problem, the problem is real; a fork
    # or bot author is a reason not to *demand* a review, never a reason to
    # discard one that happened. Checked first so no later branch swallows it.
    if reviewer.has_critical == "true":
        return CRITICAL

    if not reviewer.required:
        return NOT_REQUIRED

    if reviewer.result == "skipped":
        # The job was expected to run and its `if` said otherwise. That is a
        # workflow/secrets misconfiguration, not an outage, and no other
        # reviewer's verdict makes it safe to ignore.
        return SKIPPED

    if reviewer.result != "success":
        # failure, cancelled, or anything unrecognised. Fail safe.
        return ERRORED

    if reviewer.has_critical != "false":
        # Completed but published no verdict. Nothing was decided.
        return ERRORED

    if reviewer.outcome == "quota-exhausted":
        return QUOTA_EXHAUSTED
    if reviewer.outcome == "api-error":
        return FAILED_OPEN
    if reviewer.outcome == "no-diff":
        return NO_DIFF
    if reviewer.outcome == "reviewed":
        return CLEAR
    return UNKNOWN_OUTCOME


def evaluate(reviewers, quota_marker_open: bool = False) -> Decision:
    """Combine the reviewers' states into the gate's three-state result.

    `quota_marker_open` is the durable memory this decision needs and cannot
    hold itself: True when a tracking issue for a previous quota-exhausted run
    is still open in this repo. It is what makes "fail open once, then block"
    expressible in a job that has no state of its own. The caller supplies the
    fact; the decision stays here, where a unit test can reach it.
    """
    states = {r.name: classify(r) for r in reviewers}
    messages = []

    critical = sorted(n for n, s in states.items() if s == CRITICAL)
    if critical:
        for name in critical:
            messages.append(
                f"::error::CRITICAL findings from the {name} review — "
                "see the PR comment before merging."
            )
        return Decision(BLOCKED, "critical-findings", states, tuple(messages))

    skipped = sorted(n for n, s in states.items() if s == SKIPPED)
    if skipped:
        for name in skipped:
            messages.append(
                f"::error::The {name} adversarial review was expected to run and was "
                "skipped — check the workflow inputs and that its API key reaches the "
                "reusable workflow, then re-run."
            )
        return Decision(BLOCKED, "reviewer-skipped", states, tuple(messages))

    required = [n for n, s in states.items() if s != NOT_REQUIRED]
    if not required:
        messages.append(
            "Adversarial review is not required on this pull request "
            "(fork or bot author) — gate passed."
        )
        return Decision(NOT_REQUIRED_RESULT, "not-required", states, tuple(messages))

    verdicts = sorted(n for n in required if states[n] in _VERDICT)
    failed_open = sorted(n for n in required if states[n] in _FAILED_OPEN)
    quota = sorted(n for n in required if states[n] in _QUOTA)
    missing = sorted(n for n in required if states[n] in _MISSING)

    if not verdicts and not failed_open and not quota:
        # Every reviewer that was asked to run crashed. Nothing completed, no
        # warning comment was posted on the PR, and there is no record anywhere
        # that the change went unreviewed. This is the genuine "the gate could
        # not run" state and it must never collapse into a silent pass.
        for name in missing:
            messages.append(
                f"::error::The {name} adversarial review did not complete "
                f"({states[name]}) — check the job logs."
            )
        messages.append(
            "::error::No adversarial reviewer completed, so this PR has not been "
            "reviewed at all. Re-run once the provider is available, or obtain a "
            "manual security review."
        )
        return Decision(BLOCKED, "no-reviewer-completed", states, tuple(messages))

    if not verdicts and quota and quota_marker_open:
        # The second PR onward, once a budget is exhausted. The first one was
        # let through and left a tracking issue open; that issue is still open,
        # so nothing has been topped up and nothing has been reviewed since.
        #
        # This is the only place the gate tightens on a repeat, and it is
        # deliberately narrow: it needs `not verdicts`, so if any other
        # reviewer produced a verdict the PR *was* reviewed and this does not
        # fire. Blocking then would buy nothing, exactly as in the
        # `reviewer-unavailable` branch below.
        messages.append(
            f"::error::The adversarial reviewer's provider quota is exhausted "
            f"({', '.join(quota)}) and a previous PR already passed unreviewed on that "
            "basis. Blocking rather than merging another unreviewed change. Unlike a "
            "rate limit this does not clear by itself — top up the provider account or "
            "raise its spend cap, then close the tracking issue to re-arm the one-time "
            "pass. A manual security review is the other way through."
        )
        return Decision(BLOCKED, "quota-exhausted-repeat", states, tuple(messages))

    if not verdicts:
        # Every reviewer failed open. The reviewer action already passes in this
        # state and comments on the PR to say the change was not reviewed; that
        # is deliberate, and tightening it would freeze every consuming repo
        # during a broad provider outage. Preserved, and no longer silent.
        if quota:
            # First PR after the budget ran out. It passes — holding up the
            # change the moment billing lapses is the cost the fail-open
            # posture exists to avoid — but it is the *last* one that will.
            messages.append(
                f"::warning::The adversarial reviewer's provider quota is exhausted "
                f"({', '.join(quota)}) — this PR has NOT been reviewed. The gate passes "
                "for this first occurrence only; a tracking issue is being opened, and "
                "while it stays open subsequent PRs will be BLOCKED rather than merged "
                "unreviewed. Top up the provider account to restore review."
            )
            return Decision(DEGRADED, "quota-exhausted-first", states, tuple(messages))
        messages.append(
            "::warning::Every adversarial reviewer failed open on a provider error "
            f"({', '.join(failed_open)}) — this PR has NOT been reviewed. The gate "
            "passes so a provider outage does not freeze the repo; re-run the "
            "workflow once the provider is available."
        )
        return Decision(DEGRADED, "no-reviewer-produced-a-verdict", states, tuple(messages))

    if missing:
        for name in missing:
            messages.append(
                f"::warning::The {name} adversarial review produced no verdict "
                f"({states[name]}) — this PR was reviewed by "
                f"{', '.join(verdicts)} only."
            )
        messages.append(
            "::warning::Adversarial review gate passed DEGRADED — fewer reviewers "
            "than configured produced a verdict. Blocking here would buy nothing: "
            "the reviewer that did not complete produced no finding to weigh."
        )
        return Decision(DEGRADED, "reviewer-unavailable", states, tuple(messages))

    unknown = sorted(n for n in required if states[n] == UNKNOWN_OUTCOME)
    if unknown:
        messages.append(
            "::warning::"
            + ", ".join(unknown)
            + " did not report what it did (an older pinned reviewer action). It is "
            "being counted as a completed review; bump the pin to remove the doubt."
        )
    messages.append("No critical findings — adversarial review gate passed.")
    return Decision(CLEAR_RESULT, "all-reviewers-clear", states, tuple(messages))


# ── Wiring ────────────────────────────────────────────────────────────────────

def _env(name: str) -> str:
    return os.environ.get(name, "").strip()


def _validate_has_critical(reviewers) -> None:
    """Reject a verdict that is neither true, false, nor absent.

    Any other value means the reviewer script wrote something the gate does not
    understand. Fail rather than guess: an unrecognised verdict read as "false"
    would pass a PR on a value that might have meant the opposite.
    """
    for reviewer in reviewers:
        if reviewer.has_critical not in _VALID_HAS_CRITICAL:
            print(
                f"::error::{reviewer.name} published has_critical="
                f"'{reviewer.has_critical}' — must be 'true', 'false', or empty",
                file=sys.stderr,
            )
            sys.exit(1)


def quota_marker_is_open() -> bool:
    return _env("QUOTA_MARKER_OPEN") == "true"


def build_reviewers() -> list:
    skip_ok = _env("IS_DEPENDABOT") == "true" or _env("IS_FORK") == "true"
    run_openai = _env("RUN_OPENAI") == "true"
    return [
        Reviewer(
            name="claude",
            required=not skip_ok,
            result=_env("CLAUDE_RESULT"),
            has_critical=_env("CLAUDE_HAS_CRITICAL"),
            outcome=_env("CLAUDE_OUTCOME"),
        ),
        Reviewer(
            name="openai",
            required=run_openai and not skip_ok,
            result=_env("OPENAI_RESULT"),
            has_critical=_env("OPENAI_HAS_CRITICAL"),
            outcome=_env("OPENAI_OUTCOME"),
        ),
    ]


def _write_output(key: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT", "")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(f"{key}={value}\n")


_SUMMARY_HEADING = {
    BLOCKED: "❌ Adversarial review gate — blocked",
    DEGRADED: "⚠️ Adversarial review gate — passed DEGRADED",
    CLEAR_RESULT: "✅ Adversarial review gate — passed",
    NOT_REQUIRED_RESULT: "➖ Adversarial review gate — not required",
}


def _write_summary(decision: Decision) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if not path:
        return
    lines = [f"### {_SUMMARY_HEADING[decision.result]}", ""]
    lines.append(f"Result: `{decision.result}` (`{decision.reason}`)")
    lines.append("")
    lines.append("| reviewer | state |")
    lines.append("|---|---|")
    for name in sorted(decision.states):
        lines.append(f"| {name} | `{decision.states[name]}` |")
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def main() -> None:
    reviewers = build_reviewers()
    _validate_has_critical(reviewers)
    decision = evaluate(reviewers, quota_marker_open=quota_marker_is_open())

    for message in decision.messages:
        print(message)

    _write_output("result", decision.result)
    _write_output("reason", decision.reason)
    _write_output("degraded", "true" if decision.result == DEGRADED else "false")
    _write_output(
        "unavailable",
        ",".join(sorted(n for n, s in decision.states.items() if s in _MISSING)),
    )
    # Drives the tracking issue the *next* run reads back as `quota_marker_open`.
    # Written on the blocked path too: if the marker were ever closed while the
    # budget is still exhausted, the next run must be able to re-open it rather
    # than silently reverting to one-free-pass forever.
    _write_output(
        "quota_exhausted",
        "true" if any(s == QUOTA_EXHAUSTED for s in decision.states.values()) else "false",
    )
    _write_summary(decision)

    if decision.blocks:
        sys.exit(1)


if __name__ == "__main__":  # pragma: no cover
    main()
