# infra-commons/security

Canonical security workflows shared across all entity orgs (rolliq-com, cashbucket-com, chargingblindly, klsjapan-com, bpnz).

## Reusable workflows

### `adversarial-review-reusable.yml` — AI adversarial security review

Runs an adversarial AI security review on every PR diff. Supports two independent model families:

- **Claude** (Anthropic, `claude-sonnet-4-6`) — always runs.
- **OpenAI** (`gpt-5.5-2026-04-23`) — optional; enabled per-caller with `run-openai: true`. Requires `OPENAI_API_KEY` org secret.

The gate job blocks merge if either enabled reviewer finds a CRITICAL finding and opens a tracking issue in the caller's repo.

**Inputs:**

| Input | Type | Default | Description |
|---|---|---|---|
| `run-openai` | boolean | `false` | Also run the OpenAI reviewer alongside Claude. |

**Secrets** (pass via `secrets: inherit` or explicitly):

| Secret | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | Yes (for Claude job) | Org secret. Not available in Dependabot/fork contexts — Claude skips automatically. |
| `OPENAI_API_KEY` | Only when `run-openai: true` | Org secret. Must be set with `visibility: private` (same trust boundary as `ANTHROPIC_API_KEY`). |

**Resulting checks:**

- `<caller-job-name> / claude` — Claude adversarial review
- `<caller-job-name> / openai` — OpenAI adversarial review (only when `run-openai: true`)
- `<caller-job-name> / gate` — **set this as the required branch-protection status check**

**Draft gate:** Callers must exclude draft PRs via their `on.pull_request.types` trigger (include `ready_for_review`) and an `if: !github.event.pull_request.draft` guard on the job. The reusable skips Dependabot and fork PRs automatically (no secret access).

#### Caller pattern (from an entity security repo)

```yaml
# In your entity security repo's reusable shim, or direct caller:
adversarial-review:
  if: >-
    github.event_name == 'pull_request' &&
    !github.event.pull_request.draft
  uses: infra-commons/security/.github/workflows/adversarial-review-reusable.yml@52ee5a8afff43bf86cefd2f2c330373ccdda3f5e
  with:
    run-openai: true   # omit or set false to run Claude only
  secrets: inherit
```

> **SHA pin:** Always pin to a full commit SHA, not `@main`. The required status check `pin-check` on `infra-commons/security` rejects any PR that references a mutable ref inside this repo.

#### Adopting the OpenAI reviewer in a new org

1. Set an `OPENAI_API_KEY` org secret with `visibility: private` in the org (same pattern as `ANTHROPIC_API_KEY`).
2. Add `run-openai: true` to the caller job's `with:` block.
3. Make sure `OPENAI_API_KEY` flows through `secrets: inherit` (or is forwarded explicitly in any intermediate shim).
4. Add `<caller-job-name> / gate` as a required branch-protection status check (this single check gates both reviewers).

Cross-org rollout and secret provisioning are out of scope for this reusable — they are a manual per-org step.

### Other reusables

| Workflow | Purpose |
|---|---|
| `capture-findings-reusable.yml` | Post-merge capture of HIGH/MEDIUM/LOW security findings as GitHub Issues |
| `secret-scan-reusable.yml` | Gitleaks secret scanning |
| `daily-health-check-reusable.yml` | Daily repo health check (Dependabot triage, failed-run diagnosis, auto-merged-in-last-24h visibility) |
| `weekly-security-scan-reusable.yml` | Weekly full-repo security scan |
| `auto-merge-churn-reusable.yml` | Auto-approve + enable auto-merge for low-risk bot churn PRs (Plan 1c) |
| `tier-a.yml` / `tier-b.yml` / `tier-c.yml` | Tiered security posture bundles |

#### Reusables' internal composite pins — per-family moving tags, not raw SHAs

Unlike every other `uses:` in this repo, each reusable's own composite-action pin is
pinned to a **per-family moving major tag** rather than a 40-char SHA:

| Composite | Moving pin |
|---|---|
| `.github/actions/auto-merge-churn` | `@auto-merge-churn/v1` |
| `.github/actions/capture-findings` | `@capture-findings/v1` |
| `.github/actions/daily-health-check` | `@daily-health-check/v1` |
| `.github/actions/suppression-audit` | `@suppression-audit/v1` |
| `.github/actions/weekly-security-scan` | `@weekly-security-scan/v1` |

**Exception: `adversarial-review` and `adversarial-review-gate`.** These two used to be in
this table too, until infra-commons/security#95: a caller's SHA pin on
`adversarial-review-reusable.yml` only fixes the orchestration file if the composites it
calls are *also* pinned, since the moving tag re-resolves identically for every caller and
every pin, including one from years ago. Both `uses:` lines inside that reusable are now
pinned to commit SHAs instead — see its own header comment for the full rationale and the
manual bump procedure. `release-composites.yml` still cuts `adversarial-review/vX.Y.Z`
immutable release tags (useful as the SHA source for the next bump) but no longer delivers
either composite via a moving tag.

`pin-check.yml` carries a narrow, deliberate exception for own-repo `.github/actions/*`
refs on a `<family>/vN` tag (see `.github/scripts/check-action-pins.sh`); our own
*reusable-workflow* calls and every third-party `uses:` still require an immutable SHA.
These are the internal pins we own end-to-end, so the risk a SHA pin protects against
(a third party rewriting history under us) doesn't apply.

**To ship a composite fix: merge it, then approve the release.**
`release-composites.yml` cuts the immutable `<family>/vX.Y.Z` release tag and moves
`<family>/v1` for you, on `main`, once the `Tests` workflow passes — but the `release` job
runs in the `fleet-release` environment, which requires a reviewer, so it waits in
*Waiting* until a human approves it. There are **zero** edits to the reusable or any
consumer, and no manual tag step. Every caller that pins the reusable at a post-adoption
SHA (or `@main`) picks up the fix on its next run *after that approval*.

The approval is the only deliberate act left on this path, which is why it exists. These
tags reach 13+ repos' merge gates with no per-caller pin bump to review them, and
`protect-moving-tags` keeps only its `deletion` rule, so nothing else stands between an
edit here and the fleet. `Tests` passing is a statement about this repo; it is not a
decision to ship to everyone consuming it. Automating the tag move removed a step that was
being forgotten — it should not also remove the step that was being *decided*.

This used to be a manual step, documented here as
`git tag -f capture-findings/v1 <new-sha> && git push -f origin capture-findings/v1`. It
was introduced to replace the pre-2026-07-02 failure mode (PRs #20/#21) where a reusable's
inner SHA pin silently lagged a composite fix "because bumping it was a separate,
easy-to-forget manual step", and it reproduced that failure mode exactly, because moving
a tag by hand is also a separate, easy-to-forget manual step, and a *less* visible one: a
stale inner SHA at least showed up in a diff, whereas an unmoved tag shows up nowhere. By
2026-07-31 six of the seven families were behind `main`, one of them by two weeks, and
nothing anywhere was red.

Two mechanisms now hold the property, deliberately separate:

| | What it does | When |
|---|---|---|
| `release-composites.yml` (`release` job) | moves the tags | after `Tests` passes on `main`, **and** a `fleet-release` reviewer approves |
| `check_composite_tags_released.py` (`verify` job) | asserts every `<family>/vN` tag's action directory is byte-identical to `main`'s | after each release, plus daily and on demand |

The verifier is not decoration. A release mechanism reporting its own success is the
mechanism vouching for itself; the verifier re-reads the tags from the remote and compares
content. It also runs on a schedule, so if the release chain breaks (`Tests` renamed,
disabled, or no longer running on `main`) that is caught within a day rather than
presenting as the same silence as everything working.

Note the one overlap with the approval gate: while a release is waiting to be approved the
tags genuinely do not match `main`, so a scheduled `verify` run in that window fails, and
it is right to. It means "a release is outstanding", not "the release mechanism is broken"
— the two are distinguishable by whether a run of `release-composites.yml` is sitting in
*Waiting*. Approving it clears the failure.

**Tags are never moved before merge.** The release runs on `push` to `main`, so the commit
a tag lands on is always merged. Repointing a moving tag at a pre-merge commit is a
recorded hazard (2026-07-21) and is structurally unreachable here.

**There is no manual fallback, by design.** Two active tag rulesets enforce this:

| Ruleset | Applies to | Restricts | Bypass |
|---|---|---|---|
| `protect-moving-tags` | `refs/tags/*/v1` | deletion | `infra-commons-bot` |
| `protect-immutable-tags` | every other tag | update, deletion, non-fast-forward | nobody at all |

So `git push -f origin <family>/v1` from a laptop is rejected, whoever runs it, and has
been since the rulesets were created on 2026-07-29. There is no hand fallback and there is
not meant to be one.

Neither ruleset restricts tag **creation**, so cutting a new `<family>/vX.Y.Z` needs no
permission beyond `contents: write`.

**The integrity guarantee lives in the immutable tags, not the moving one.** A released
`<family>/vX.Y.Z` can never be moved or deleted by anyone, which is what makes "pin away
from a bad release" a real option rather than a hope. The moving tag is a pointer that is
supposed to move, so it keeps only its `deletion` rule: it cannot vanish and break every
consumer at once, but the release job can advance it.

That shape exists because this repo is **public** and so cannot read the organisation's
private-visibility secrets, which rules out running the release as an App without putting
an App private key in a public repo's secret scope. GitHub Actions cannot be granted a
ruleset bypass either, since it is not an installed org integration. Running as
`GITHUB_TOKEN` keeps the release secretless, and the only other principals who can move a
moving tag are the two accounts that already have admin on this repo.

## `pentest/` — internal penetration-test toolkit

A standalone, locally-runnable toolkit (not a workflow) that actively probes a
running solution API (auth/HMAC bypass, IDOR, rate-limit evasion, payload limits,
prompt injection, info disclosure) and statically scans IaC / client config. It
fills the gap the weekly Nuclei DAST deliberately leaves (active testing) and emits
findings in the standard `security` + `severity:*` + `source:pentest` model.

It is shared here because the controls it verifies come from the shared
solution-template middleware and platform-iac modules; it is **config-driven** via a
per-solution `pentest-profile.yml` (see `pentest/config.example.yml`), so the engine
stays generic. See `pentest/README.md` for usage and the non-negotiable safety rules
(target allowlist, non-destructive, rate-limited, dry-by-default). Entity `security`
repos stay code-free and consume it via the `pentest-scan-reusable.yml` workflow
(to be added) at a pinned SHA.

## Usage pattern

Entity org security repos call these reusable workflows via SHA-pinned refs:

```yaml
uses: infra-commons/security/.github/workflows/<name>.yml@<full-SHA>
```

All third-party actions inside this repo are pinned to full commit SHAs. The `pin-check` CI workflow enforces this on every PR.
