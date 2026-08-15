# Blast radius of #103 — `tier-b.yml`'s non-blocking Semgrep step

**Scope:** measurement only. No workflow file was changed to produce this report, and none of the
numbers below required running Semgrep locally — every finding count is read from the log of a
real, already-completed workflow run, using the config/version each caller actually invokes.

## The defect, restated

`tier-b.yml`'s `semgrep` job ends `semgrep scan … --text || true` — non-zero exit is swallowed, so
the `SAST (Semgrep)` check is green regardless of findings, even though callers make it a required
status check and the file's own header claims it blocks. `tier-a.yml` genuinely blocks (`--error`,
no `|| true`). `security#104` (merged today, 07:51:43 UTC, commit `9be91a5`) fixed a *different* bug
in the same job — a `skipped`-run race — and did not touch line 107. This report exists to answer
#103's own opening question: how many findings would suddenly become merge blockers if `|| true`
were promoted to `--error`.

## Method

Static per-org PATs (`gh-rolliq`, `gh-cashbucket`, `gh-klsjapan`) are unreliable this week — some
404 on their target org outright, others resolve to the wrong org. All reads below used a GitHub
App installation token minted fresh per org via `scripts/gh-app-token.sh <org>`
(`infra-commons-bot`, App ID 4025350), verified working before use, never logged or printed.

`gh search code` was tried first and rejected — it has under-reported reusable-workflow callers by
org on four separate prior uses (most recently: 12/16 true callers for a different workflow, missing
an entire org with no error). Instead, **every non-archived repo in every org was enumerated
explicitly** and every workflow file in `.github/workflows/` was fetched and grepped, so a zero
is distinguishable from a not-looked-at:

| Org | Repos enumerated | Workflow files read | Files referencing a `tier-[abc].yml` |
|---|---:|---:|---:|
| `infra-commons` | 9 | 61 | 3 *(all inside `security`'s own header-comment examples — no live caller)* |
| `rolliq-com` | 12 | 131 | 4 |
| `cashbucket-com` | 8 | 46 | 7 |
| `klsjapan-com` | 6 | 37 | 7 |
| `chargingblindly-com` | 8 | 25 | 9 |
| **Total** | **43** | **300** | **30** |

For each live `tier-b.yml` caller found, the most recent workflow run whose `SAST (Semgrep)` job
actually executed (not `skipped`) was located via `gh run list` / `gh api .../actions/runs/{id}/jobs`,
and that job's full log was read via the jobs/logs API — this is the exact `--text` output `|| true`
is currently discarding, not a re-scan.

## Re-derived caller set (differs from `security#104`'s own characterization)

`security#104`'s body named 4 live callers (`klsjapan-com/nutrition-tracker`,
`cashbucket-com/marketing`, `rolliq-com/marketing`, `rolliq-com/devops`). Full enumeration found a
**5th that PR missed entirely: `chargingblindly-com/travel-agent-bot`.** This is exactly the
failure mode re-derivation was meant to catch.

| # | Repo | Path to `tier-b.yml` | Pin | Currently delegates to `infra-commons/security@main`? |
|---|---|---|---|---|
| 1 | `rolliq-com/marketing` | direct | `infra-commons/security@5a7abbd` | **No** — pinned to commit `5a7abbd` (PR #32, predates both #102 and #104) |
| 2 | `rolliq-com/devops` | direct | `infra-commons/security@5a7abbd` | **No** — same ancient pin as #1 |
| 3 | `cashbucket-com/marketing` | via `cashbucket-com/security` mirror | mirror pinned `@eebfd3f0` | **No** — that mirror commit is a *self-contained frozen fork* of tier-b.yml's old logic (its own inline `if: pull_request` guard and its own `\|\| true`), not a delegating wrapper. `cashbucket-com/security`'s current `main` *is* a thin delegating wrapper, but this caller isn't pinned to it. |
| 4 | `klsjapan-com/nutrition-tracker` | via `klsjapan-com/security` mirror | mirror pinned `@92631b62` | **Yes** — that commit is the thin `canonical:` wrapper, `uses: infra-commons/security/tier-b.yml@main` unpinned |
| 5 | `chargingblindly-com/travel-agent-bot` | via `chargingblindly-com/security` mirror | mirror pinned `@4f694337` | **Yes** — same thin delegating wrapper |

**This distinction matters more than it looks:** editing `infra-commons/security/tier-b.yml` today
only reaches callers #4 and #5 (through their unpinned mirrors). Callers #1–#3 are wired to frozen,
independent copies of the same defect and would not be touched by any change made in this repo —
they'd need their own pin bump or direct edit. The "fix the canonical file" action and "fix the
fleet" outcome are not the same thing here.

## Per-repo findings

| Repo | Run measured | Semgrep config | Findings | Blocking / Non-blocking split |
|---|---|---|---:|---|
| `rolliq-com/marketing` | [run 31746703491](https://github.com/rolliq-com/marketing/actions/runs/31746703491), `pull_request`, 2026-08-13T21:40Z | `p/python p/security-audit` | **12** | 12 / 0 |
| `rolliq-com/devops` | [run 31668806729](https://github.com/rolliq-com/devops/actions/runs/31668806729), `pull_request`, 2026-08-13T05:00Z | `p/github-actions p/python` | **2** | 2 / 0 |
| `cashbucket-com/marketing` | [run 31872910885](https://github.com/cashbucket-com/marketing/actions/runs/31872910885), `pull_request`, 2026-08-15T07:48Z | `p/python p/security-audit` | **5** | 5 / 0 |
| `klsjapan-com/nutrition-tracker` | [run 31874285885](https://github.com/klsjapan-com/nutrition-tracker/actions/runs/31874285885), `push`, 2026-08-15T08:21Z (post-#104) | `p/javascript p/typescript p/security-audit` | **0** | — |
| `chargingblindly-com/travel-agent-bot` | [run 31660897779](https://github.com/chargingblindly-com/travel-agent-bot/actions/runs/31660897779), `pull_request`, 2026-08-13T02:27Z | `p/python p/security-audit` | **0** | — |
| **Total** | | | **19** | **19 / 0** |

Every measured repo ran `semgrep==1.163.0` (the version `tier-b.yml` pins) and the exact
`semgrep scan … --text \|\| true` invocation currently in the file (or an earlier version with
identical semantics — see caller-set table above). None of these numbers required guessing at
config; each is the config that repo's own caller workflow passes today.

**Severity spread:** Semgrep's `--text` output at this version doesn't print ERROR/WARNING/INFO
per finding — it prints a binary "Blocking" / "Non-blocking" tag instead. All 19 findings across
all 3 non-clean repos are tagged **Blocking**. That's the full severity information the logs carry;
getting a finer ERROR/WARNING/INFO breakdown would need `--json`, which none of these runs used
(so not claimed here). Practically, it also means a severity-based gate wouldn't give any of these
three repos relief — none of the current findings are the kind such a gate would let through.

### What the findings are

- **`rolliq-com/marketing` (12/12)** — one rule,
  `generic.html-templates.security.unquoted-attribute-var`, repeated across 4 design-system HTML
  template files (unquoted `{{ }}` interpolation in an attribute). Same root cause, not 12
  independent issues.
- **`rolliq-com/devops` (2/2)** — two distinct rules:
  `yaml.github-actions.security.github-actions-mutable-action-tag` (an action pinned by tag,
  `actions/checkout@v6`, not a SHA) and `yaml.github-actions.security.run-shell-injection`
  (`${{ inputs.wrangler_version }}` interpolated directly into a `run:` shell command).
- **`cashbucket-com/marketing` (5/5)** — one rule,
  `python.lang.security.audit.dynamic-urllib-use-detected`, across 4 files (dynamic value passed to
  `urllib`/`urlopen`).

## The answer #103 asked for

**Not cheap — flipping `tier-b.yml`'s exit code would immediately break 3 of the 5 live callers
this session could reach (19 findings total), and it wouldn't even reach the other 2 measured-clean
callers' actual defect the way it looks like it would:**

- Editing `infra-commons/security/tier-b.yml` alone (the "obvious" fix) is *cheap and safe* for what
  it actually touches today — its only two unpinned-delegating live reachers,
  `klsjapan-com/nutrition-tracker` and `chargingblindly-com/travel-agent-bot`, are both at 0
  findings right now. That edit could ship immediately with zero caller breakage.
- But it does **nothing** for the 19 findings, because all of them sit in the 3 callers that don't
  delegate to current `main` at all: `rolliq-com/marketing` (12), `rolliq-com/devops` (2),
  `cashbucket-com/marketing` (5). Those three are running frozen, independent copies of the same
  `\|\| true` logic — two via an ancient direct SHA pin, one via a mirror pinned to a
  non-delegating forked copy. Fixing the canonical file changes none of their behavior.
- If the goal is "Tier B's required SAST gate can actually fail" fleet-wide (which is what #103 is
  really asking), the real move set is: (a) land the canonical `--error` fix — safe now, per above —
  and (b) separately get each of the 3 stale callers current, at which point their combined 19
  findings become simultaneous merge blockers unless triaged first. Per the issue's own menu, a
  **baseline-commit** (`--baseline-commit` against merge base) or a **per-caller `semgrep_blocking`
  opt-in flag** fits this shape well: it lets each of the 3 repos re-pin and go blocking only once
  its existing findings are triaged, rather than freezing all three the moment they catch up to
  `main`. A severity gate would not help here — every found issue is already "Blocking."

## Surfaced but not filed

Per instructions, these are reported for the operator's call, not opened as issues:

1. **`chargingblindly-com/travel-agent-bot` is a live Tier B caller `security#104` never accounted
   for.** Its blast-radius section only named 4 repos; this one was missed. Worth folding into
   whatever tracks the caller inventory, so the next person doesn't have to re-derive it from
   scratch again.
2. **`cashbucket-com/marketing`'s pin points to a fully frozen, non-delegating fork of `tier-b.yml`**
   inside `cashbucket-com/security` (commit `eebfd3f0`) — distinct from, and in a sense opposite to,
   the already-known unpinned-`@main` hazard on that same mirror repo's `main` branch. A future fix
   to `infra-commons/security` will never reach this caller without a caller-side pin bump or a
   direct edit to the frozen copy.
3. **`rolliq-com/devops` still has no tracking issue** for its exposure to the same stale-pin problem
   `rolliq-com/marketing#215` already tracks for marketing — `security#104`'s body flagged this and
   it's still true today.
4. Both `rolliq-com/marketing` and `rolliq-com/devops` are still pinned to commit `5a7abbd` (PR #32),
   which predates *both* `#102`'s skipped-run race fix and `#104`'s merge — meaning those two repos
   currently carry the *original* required-check race defect as well as `#103`'s, unresolved by
   anything landed in `infra-commons/security` to date.
