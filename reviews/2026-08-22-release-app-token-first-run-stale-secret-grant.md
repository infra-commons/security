# First App-token `release-composites.yml` run failed on a stale secret grant (2026-08-22)

## What happened

Following `#124` (mint an App installation token instead of `GITHUB_TOKEN` for the moving-tag
push) and the operator granting `infra-commons/security` access to
`INFRA_COMMONS_BOT_PRIVATE_KEY` (`selected_repositories` PUT, confirmed live), the first
`workflow_run`-triggered run to actually exercise the new path — run `32545051851` (#67) — still
failed at the mint step:

```
Error: The 'private-key' input must be set to a non-empty string.
```

## Cause: the run predated the grant

Run #67 was **created at 02:00:35Z**, sat `waiting` on the `fleet-release` environment approval
for ~21h45m, and only executed at **23:46:36Z** — 40 seconds after the secret grant's
`updated_at` (`23:45:56Z`). The grant landed and was independently verified via the API well
before the job actually ran, but the job still could not read the secret. The evidence points to
GitHub resolving a `visibility: selected` org secret's eligibility for a `workflow_run`-triggered
run at the time the run is **created**, not at the time it finally **executes** — so a run queued
before a grant does not pick the grant up no matter how long it waits or when it's approved.

## Fix: no code or grant change — just a fresh run

Both `#124` and the secret grant are correct as-is. What was needed was a `workflow_run` event
created *after* the grant, which this PR's own merge (triggering `Tests` → `release-composites.yml`
on `main`) provides. Confirm the resulting run in `repos/infra-commons/security/actions/workflows/
release-composites.yml/runs?event=workflow_run` mints and pushes cleanly before treating Step 1½
of `reviews/2026-08-22-protect-moving-tags-ruleset-revert.md` (infra-commons/meta) as verified.

## Worth remembering

If a future `visibility: selected` org-secret grant needs to reach a workflow that fires on
`workflow_run`, don't trust a long-`waiting` run that predates the grant to pick it up once
approved — treat the grant as effective only for runs *created* after it landed, and trigger a
fresh one if none is already in flight.
