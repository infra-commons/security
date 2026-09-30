# Informational notice filing — meta#1656 ask 3, measured before acting

**Ruling (operator, 2026-09-29):** stop filing `degraded-pass`, `quota-exhausted` and
`draft-stage-failed` as GitHub issues; surface them in dashboards only. CRITICAL/HIGH and the
MEDIUM/LOW digest are out of scope and unchanged.

**Outcome of this pass: no filing path was removed.** Both classes filed from this repo turn out
to be *state that code reads back*, not notices, and no dashboard shows either one without the
issue. The third class is not filed from this repo. Per the brief (2026-09-03 harness freeze: no
new detectors), both in-repo classes keep filing, and the gaps are handed back below.

## Where each class is filed, and who reads it

| Class | Filer | Reader of the issue | Surface without the issue |
|---|---|---|---|
| quota-exhausted | `.github/workflows/adversarial-review-reusable.yml`, step "Record that the provider quota is exhausted" | The gate itself: step "Look up the quota tracking issue" → `quota-marker-open` → `gate.py evaluate(quota_marker_open=)`, which BLOCKS a repeat exhaustion only while the issue is open | None |
| degraded-pass | same file, step "Record a degraded pass" | `sharedinfra/scripts/merge-ready.py` `fetch_degraded_pass_prs` (T2 hold in `/merge`); also `pipeline_status.py`, `pipeline_calibrate.py`. `sharedinfra/tests/test_merge_policy_degraded_review.py` fetches this workflow and asserts the degraded `TITLE=` line exists | None: `/merge` and `/pipeline` read the issue |
| draft-stage-failed | **not here, not in marketing-engine.** `cashbucket-com/marketing/.github/workflows/generate-draft.yml:194` (title `:196`); `rolliq-com/marketing/.github/workflows/generate-draft.yml:389` (title `:391`), verified at default branch 2026-09-30. No klsjapan-com or chargingblindly-com repo has a `marketing` repo | out of scope for this repo |

"Surface without the issue" was checked in `sharedinfra/scripts/`: `securitymon_web.py` (port 8788),
`monitor_status.py`, `security_scan.py`, `devops-audit.py`, `generate-devops-md.py` and
`board-coverage.py` contain no reference to either class. The only other trace is per-run:
`gate.py`'s `::warning::` annotations and job step summary, which nobody opens and which do not
persist across runs.

## Why each in-repo class is kept

- **quota-exhausted:** the issue *is* the gate's memory. A job has no state of its own, so "fail
  open once, then block" depends on it. Remove it and every quota-exhausted PR takes the first-time
  free pass, so PRs merge unreviewed for the whole billing period. That is the exact failure the
  mechanism (security#81, meta#1092/#1094) exists to prevent.
- **degraded-pass:** the issue is the merge policy's input. Without it, `fetch_degraded_pass_prs`
  returns an empty *complete* set, the PR classifies T0/T1, and `/merge --select all` merges it
  unread. Removing it also turns sharedinfra's cross-repo contract test red.

Both are now pinned by
`test_the_state_bearing_notice_recorders_are_not_removable_as_informational` in
`.github/actions/adversarial-review-gate/test_gate_wiring.py`, whose failure message says why.

## Gaps: what would be needed to carry out the ruling for these two classes

1. **quota-exhausted needs a non-issue store for the gate's memory**, e.g. a repo or org Actions
   variable written by the gate job, or a lookup of the previous gate run's outcome. Either is
   new state plumbing rather than surfacing, so it needs an operator ruling past the freeze. The
   store must also keep the property the issue gives today: a human re-arms it after topping up.
2. **degraded-pass needs the consumer to move first.** `merge-ready.py` would read the degraded
   result from the gate's own check run (its title/summary, or a job output), which the
   `fetch_verified_gate_prs` rollup read already touches. Order matters: that sharedinfra change
   lands and releases *before* this step is removed, or `/merge` is blind in between.
3. **draft-stage-failed is each marketing lane's change**, in the two files above. It is the one
   class that really is informational: nothing reads it back. Its dashboard surface is still
   unverified: whether `/devops` or the marketing dashboard shows a failed Tuesday draft run
   without the issue was not measured here.

## Fleet census of open issues in these classes (2026-09-30)

Method: `infra-commons-bot` App token per org, every installed repo (infra-commons 9, rolliq-com 12,
cashbucket-com 8, klsjapan-com 6, chargingblindly-com 9 = 44 repos), all open issues matched on the
exact filer titles. **0 repos unreadable**, so this is a count, not a floor.

| Class | Org | Open | Detail |
|---|---|---|---|
| quota-exhausted | klsjapan-com | 1 | `klsjapan-com/meta#123`, opened 2026-08-31 |
| degraded-pass | klsjapan-com | 1 | `klsjapan-com/meta#122`, opened 2026-08-29, its PR is **merged** |
| draft-stage-failed | all | 0 | |
| any class | infra-commons, rolliq-com, cashbucket-com, chargingblindly-com | 0 | |

The ~31 notices meta#1656 measured on cashbucket-com on 2026-09-28 are gone; cashbucket's
offboard sweep cleared them.

**Recommendation (not acted on):**
- `klsjapan-com/meta#122` (degraded-pass, PR already merged) can be closed. Its only reader
  is the T2 hold, which is moot for a merged PR.
- `klsjapan-com/meta#123` (quota-exhausted) must **not** be closed as a notice. While it is open,
  a further quota-exhausted PR in that repo is blocked; closing it re-arms the free pass. It
  should be closed only by the klsjapan lane after confirming that repo's provider budget is
  restored and a review has run.
