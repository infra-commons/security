# Review pointers

Tracks the last SHA each area was reviewed at, so a future pass can tell what's already
covered without re-reading everything. One row per reviewed unit. Extend this table rather
than starting a new pointer file per org (`infra-commons/meta#815`'s judgment call).

| org | repo | area | last-reviewed SHA | date | findings-doc link |
|---|---|---|---|---|---|
| infra-commons | security | adversarial-review family (adversarial-review/, adversarial-review-gate/) | 5db28e5 | 2026-08-16 | [reviews/2026-08-16-tier1-adversarial-review-815.md](2026-08-16-tier1-adversarial-review-815.md) |
| infra-commons | security | auto-merge-churn | 5db28e5 | 2026-08-16 | [reviews/2026-08-16-tier1-security-composites-815.md](2026-08-16-tier1-security-composites-815.md) |
| infra-commons | security | capture-findings | 5db28e5 | 2026-08-16 | [reviews/2026-08-16-tier1-adversarial-review-815.md](2026-08-16-tier1-adversarial-review-815.md) |
| infra-commons | security | daily-health-check | 5db28e5 | 2026-08-16 | [reviews/2026-08-16-tier1-security-composites-815.md](2026-08-16-tier1-security-composites-815.md) |
| infra-commons | security | dast-scan | 5db28e5 | 2026-08-16 | [reviews/2026-08-16-tier1-security-composites-815.md](2026-08-16-tier1-security-composites-815.md) |
| infra-commons | security | pentest-scan | 5db28e5 | 2026-08-16 | [reviews/2026-08-16-tier1-security-composites-815.md](2026-08-16-tier1-security-composites-815.md) |
| infra-commons | security | secret-scan | 5db28e5 | 2026-08-16 | confirmed clean, no separate doc entry — see reviews/2026-08-16-tier1-security-composites-815.md |
| infra-commons | security | suppression-audit | 5db28e5 | 2026-08-16 | [reviews/2026-08-16-tier1-security-composites-815.md](2026-08-16-tier1-security-composites-815.md) |
| infra-commons | security | weekly-security-scan | 5db28e5 | 2026-08-16 | [reviews/2026-08-16-tier1-security-composites-815.md](2026-08-16-tier1-security-composites-815.md) |

<!--
This file is created new by both PR #110 and PR #112 (they share no common
ancestor that already has it). #110 is intended to merge first; the two rows
above for "adversarial-review family" and "capture-findings" carry #110's
row content (its SHA and doc link, not a placeholder), so after #110 merges
main already matches these two rows exactly and there is nothing left to
reconcile — no conflict, no judgment call about whose row wins. See the
comment on both PRs for the full explanation.
-->
