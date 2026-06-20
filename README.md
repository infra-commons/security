# infra-commons/security

Canonical security workflows shared across all entity orgs (rolliq-com, cashbucket-com, chargingblindly, klsjapan-com, bpnz).

## Reusable workflows

### `adversarial-review-reusable.yml` — AI adversarial security review

Runs an adversarial AI security review on every PR diff. Supports two independent model families:

- **Claude** (Anthropic, `claude-sonnet-4-6`) — always runs.
- **OpenAI** (`gpt-4o`) — optional; enabled per-caller with `run-openai: true`. Requires `OPENAI_API_KEY` org secret.

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
| `legal-review-reusable.yml` | AI legal clause review on PRs |
| `legal-capture-findings-reusable.yml` | Post-merge capture of legal findings as GitHub Issues |
| `secret-scan-reusable.yml` | Gitleaks secret scanning |
| `daily-health-check-reusable.yml` | Daily repo health check |
| `weekly-security-scan-reusable.yml` | Weekly full-repo security scan |
| `tier-a.yml` / `tier-b.yml` / `tier-c.yml` | Tiered security posture bundles |

## Usage pattern

Entity org security repos call these reusable workflows via SHA-pinned refs:

```yaml
uses: infra-commons/security/.github/workflows/<name>.yml@<full-SHA>
```

All third-party actions inside this repo are pinned to full commit SHAs. The `pin-check` CI workflow enforces this on every PR.
