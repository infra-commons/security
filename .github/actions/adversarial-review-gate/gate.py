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
  outcome       what the reviewer actually did — `reviewed`, `no-diff`, or
                `api-error` (it fails open on transient provider errors, so
                "completed with no CRITICAL" does not by itself mean "reviewed")

The `outcome` signal is what keeps this honest. Without it a reviewer that
failed open is indistinguishable from one that read the diff and found nothing,
and the gate would report a clean review that never happened. An older pinned
reviewer action does not publish it; that is reported as unknown rather than
assumed to be a real review.
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
# Asked to run and produced nothing at all, not even a fail-open.
_ERRORED = frozenset({ERRORED})
# Everything the gate must report as reduced coverage.
_MISSING = _FAILED_OPEN | _ERRORED

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

    if reviewer.outcome == "api-error":
        return FAILED_OPEN
    if reviewer.outcome == "no-diff":
        return NO_DIFF
    if reviewer.outcome == "reviewed":
        return CLEAR
    return UNKNOWN_OUTCOME


def evaluate(reviewers) -> Decision:
    """Combine the reviewers' states into the gate's three-state result."""
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
    missing = sorted(n for n in required if states[n] in _MISSING)

    if not verdicts and not failed_open:
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

    if not verdicts:
        # Every reviewer failed open. The reviewer action already passes in this
        # state and comments on the PR to say the change was not reviewed; that
        # is deliberate, and tightening it would freeze every consuming repo
        # during a broad provider outage. Preserved, and no longer silent.
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
    decision = evaluate(reviewers)

    for message in decision.messages:
        print(message)

    _write_output("result", decision.result)
    _write_output("reason", decision.reason)
    _write_output("degraded", "true" if decision.result == DEGRADED else "false")
    _write_output(
        "unavailable",
        ",".join(sorted(n for n, s in decision.states.items() if s in _MISSING)),
    )
    _write_summary(decision)

    if decision.blocks:
        sys.exit(1)


if __name__ == "__main__":  # pragma: no cover
    main()
