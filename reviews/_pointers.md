# Review pointer — infra-commons fleet code-review scoping

State for `infra-commons/meta#815`'s fleet code-review scoping work. Extends the pattern used by the
rolliq platform cadence (`docs/reviews-rolliq/_pointers.md` in `sharedinfra`) with an org column,
since this pass spans repos rather than staying inside one.

A session **reads** this file to know what has already been reviewed and at which SHA, and **writes**
a row back before it ends. Nothing else records that a review happened.

Tier 1 (`security`, `legal`, `devops`) is tracked at reusable-workflow-family granularity — the
composite-action level, not per-repo — per meta#815. Tier 2 (control-plane repos) will be added here
per-repo if/when that tier starts.

| org | repo | area | last-reviewed SHA | date | findings |
|---|---|---|---|---|---|
| `infra-commons` | `security` | `adversarial-review` family (`adversarial-review/`, `adversarial-review-gate/`) | `5db28e5` | 2026-08-16 | [2026-08-16-tier1-adversarial-review-815.md](2026-08-16-tier1-adversarial-review-815.md) |
| `infra-commons` | `security` | `capture-findings` | `5db28e5` | 2026-08-16 | [2026-08-16-tier1-adversarial-review-815.md](2026-08-16-tier1-adversarial-review-815.md) |

**Not yet started (this pass):** `legal/legal-review`, `devops/*` — explicitly out of scope for this
pass per meta#815 (separate passes). Tier 2 control-plane repos are unstarted; meta#815 notes it is
unverified whether they're already covered by routine session activity or genuinely unreviewed.
