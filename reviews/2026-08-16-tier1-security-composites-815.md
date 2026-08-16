# Tier 1 review — remaining `infra-commons/security` composites (`meta#815`)

**Scope:** `auto-merge-churn`, `daily-health-check`, `dast-scan`, `pentest-scan`,
`secret-scan`, `suppression-audit`, `weekly-security-scan`. `adversarial-review` and
`capture-findings` were already covered (PR #110, #111, merged;
`reviews/2026-08-16-tier1-adversarial-review-815.md`).

`main` at review time: `5db28e5`. Fixes below landed as a follow-up branch off that SHA
— see the PR for the exact commit.

## Method

`/code-review <path>` is confirmed broken in this environment: invoked as `/code-review
<path> high` it silently reviews the ambient worktree diff instead of the path argument.
This worktree's `HEAD` is byte-identical to `origin/main` (reconfirmed live this session by
a user-run `/code-review .github/actions/weekly-security-scan high`, which correctly
self-detected "no diff to review" rather than fabricating findings), so an argument-less run
also has nothing to review. Used an ordinary hand review instead: 3 parallel passes, each
reading every production file in full (not excerpts) and answering two known-defect-class
questions — (1) is there a missing truncation/stop-reason guard on any LLM call, read as a
complete/clean result; (2) is any PR- or issue-comment-controlled input trusted to influence
a merge/suppress/close decision without authenticating who produced it — plus general
fail-open correctness. Every finding below was then personally re-read and verified against
the actual source (not taken on an agent's report alone) before being acted on or written up.

**Overlap with PR #109** (same #326 follow-up sweep, already merged): `pentest-scan-
reusable.yml`'s `--fail-on-critical` unreachability (fixed there), `dast-scan-reusable.yml`'s
`|| true` re: severity-gate capability (checked there, no finding on that specific angle —
see finding 3 below for a different angle this pass found), `weekly-security-scan`'s
missing-artifact-reads-as-clean auto-close (written up for the operator there, not
duplicated here — see finding 6).

## Fixed in this PR (5) — self-evident, low-risk, mirrors an existing sibling pattern

Full detail and code excerpts are in the PR body; summarized here for the record.

1. **`security-scan.py` `call_claude()`/`call_gpt4o()`** (weekly-security-scan) — no
   `stop_reason`/`finish_reason` guard at all, and no try/except around either call site or
   its caller. A refusal raised an unhandled `IndexError`; ordinary truncation degraded
   through `parse_ai_findings()` to a single LOW "parse error" placeholder, silently
   discarding every real finding — including CRITICAL/HIGH — the model had already fully
   described before the cutoff. This is the 4th and 5th instance of the family's missing-
   truncation-guard defect (after `adversarial-review.py`, `capture-findings/capture.py`,
   and independently `infra-commons/legal`'s reviewer). Fix mirrors `adversarial-review.py`'s
   `call_openai()` exactly: raise on empty/refused content or `stop_reason=="max_tokens"` /
   `finish_reason=="length"`.
2. **`health-check.py` `diagnose_with_claude()`/`try_autofix()`** — same missing explicit
   guard, previously masked only incidentally by a broad `except Exception` + required-key
   JSON validation. Added the same explicit check so the safety property doesn't depend on
   truncated JSON happening to fail to parse.
3. **`pentest/triage.py` `triage()`** — auto-closed every open `source:pentest` issue on an
   empty findings run, with no guard. Verified end-to-end: `pentest-scan-reusable.yml`
   defaults `min_severity: medium`; `run.py`'s `_safe_run()` demotes every probe crash to an
   info-severity finding; `run.py` filters those out before `triage()` is even called — so if
   every probe crashes (target down, network blip, a bug), `triage()` receives `[]` and its
   close loop closed **every** currently-open pentest issue with "No longer detected...
   closing," regardless of whether anything was actually fixed. Sibling `dast/triage.py`
   already solved this exact ambiguity (its own history references "closes #90") with a
   guard before its close loop. Fix ports the equivalent guard into `pentest/triage.py`.
4. **`auto-merge-churn.py` `main()`** — auto-merge got armed even when the approve step
   genuinely failed, contradicting the reusable workflow's own documented contract ("the
   approve step fails soft — the PR simply waits for a human"). There was no return/guard
   between a genuine approve failure and the unconditional `gh pr merge --auto --squash`
   call, which doesn't need approve rights to arm auto-merge given the job's own
   `contents:write`+`pull-requests:write` token. So the very next incidental human-review
   approval would fire the merge immediately, defeating the intended distinct-4th-identity
   manual gate. Fix tracks whether approve actually succeeded (or was already-approved) and
   skips enabling auto-merge otherwise.
5. **5 spots across 3 `pentest/probes/*.py` files** (`auth.py:_check_docs`,
   `disclosure.py:_check_cors`, `disclosure.py:_check_server_header`,
   `injection.py:_check_verb_tampering`, `injection.py:_check_header_crlf`) silently
   swallowed transport exceptions (`except Exception: pass`/`return []`/`continue`) instead
   of using the `_probe_error()` helper already defined and used by every other check in the
   same files. Each now reports an info-severity "inconclusive" finding, mirroring the
   established sibling pattern.

**What a Group A caller experiences:** nothing changes on any run that wasn't already
silently mis-behaving today. All 5 fixes only change behavior on an already-broken path (an
LLM truncation/refusal, a total probe-crash run, a genuine approve failure, or a probe that
can't reach its target) — the caller now sees a loud failure or an honest "inconclusive"
result where it previously saw a false "clean."

Verification: every touched composite's existing pytest suite passes (227 tests total across
`pentest/tests/`, `test_health_check.py`, `weekly-security-scan/`, `test_auto_merge_churn.py`,
`suppression-audit`, `capture-findings`), plus new regression tests added alongside each fix
pinning the fail-closed direction (empty/truncated LLM response raises; empty findings don't
close open issues; a failed approve doesn't arm auto-merge; an unreachable target reports
inconclusive, not clean).

## Non-trivial findings — not fixed here, each needs a design/judgment call

6. **`suppression-audit.py`** (`load_suppressions()` lines 86-91, `main()` lines 433-437) — a
   missing or mistyped `suppressions-path` reads identically to "repo legitimately has no
   suppressions file," and a clean/no-op run actively **closes** any existing open
   "suppression expiry audit" issue. Needs a decision distinguishing "no file, expected
   default" from "an explicitly-configured path that's missing" (e.g. only default-path-
   missing is a true no-op; an explicitly-set-but-missing path should warn/fail instead).
7. **`dast-scan-reusable.yml`** — both Nuclei run steps and the merge step end in a bare
   `|| true`, which masks a genuine scan crash/network failure as "0 findings." This is a
   different angle from #109's already-recorded assessment (severity-gate capability was
   never there, so nothing was lost on that front) — this is about a real scan failure
   reading as a clean scan with no visible signal anywhere in the run. It does **not** cause
   wrongful issue-closing, unlike finding 3 above, because `dast/triage.py`'s existing guard
   also skips the close loop on zero parsed findings. So the impact is silent loss of DAST
   coverage visibility, not silent issue closure. Fix shape: distinguish a genuine "0
   findings, scan ran fine" exit from a crash/timeout/malformed-output exit (e.g. check
   Nuclei's own exit code semantics rather than blanket-swallowing all of them).
8. **`pentest` family — target-controlled response headers flow unsanitized into GitHub
   issue bodies.** `dast/triage.py` has an explicit `_sanitise()` applied to every
   Nuclei-sourced string before it reaches an issue (its own history: "closes #90");
   `pentest/findings.py` has no equivalent — `_clip()` truncates but doesn't sanitize, and is
   only applied to `title`/`location`, never `evidence`. `disclosure.py`'s
   `_check_server_header` and `_check_cors` embed raw `Server`/`X-Powered-By`/
   `Access-Control-Allow-Origin` response header values (via Python `!r`, which escapes
   quotes and control characters but not backticks) directly into `evidence`, which
   `triage.py` wraps in a bare markdown code fence. A compromised/malicious scan target could
   set a header value containing a backtick sequence to break the fence and inject markdown
   into an auto-filed issue. Fix shape: port `dast/triage.py`'s `_sanitise()` into
   `pentest/findings.py` or `pentest/triage.py` and apply it to `evidence`/`description`, not
   just `title`/`location` — a real change across multiple call sites, not a one-liner.
9. **`security-scan.py` `fetch_open_security_issues()`** — open issues are indexed by title
   text only (`is_scanner_authored_title()` is a plain prefix check on that same untrusted-
   reachable title, with no author/bot-identity check anywhere in the reconcile loop). An
   actor with issue-create + `security` label-write permission (a narrower trust boundary
   than an anonymous PR, but still real on any repo where non-admins can label issues) could
   craft a colliding `[Security][...]` title that shadows a real scanner-authored issue in
   the reconcile dict, orphaning the real one from future create/close cycles. Related, lower
   -severity echo in the same file: `build_issue_title()`'s 256-char truncation can itself
   collapse two distinct findings at the same location to an identical title, causing the
   same collision non-adversarially. Fix shape: an author/bot check plus a collision-
   resistant key (e.g. a hash of the untruncated content) instead of the truncated display
   string — needs a design decision on which identity to trust, not a one-liner.
10. **`health-check.py` `_is_major_bump()`** — the regex requires a literal `from vX.Y to
    vX.Y` in the PR title. Dependabot's grouped-update titles ("bump the frontend-
    dependencies group with 5 updates") carry no version numbers, so an unparseable title
    reads as "not major" (fail-open) rather than "unknown, be conservative" — if checks pass
    and no workflow files are touched, the health-check can auto-approve and enable
    auto-merge for what could include an un-flagged major/breaking bump inside the group.
    Fix shape: needs a decision on how to classify grouped-update PRs (parse the PR body's
    changelog table, or default unparseable titles to "treat as major" instead of "not
    major").
11. **Referenced, not duplicated: `weekly-security-scan`'s missing-artifact-reads-as-clean
    auto-close gap**, already on record from #109. Finding 1 above (the explicit truncation
    guard) is a partial mitigation — an LLM failure now fails loud instead of silently
    degrading to a placeholder — but the deeper "this scanner's artifact never arrived this
    run" vs "this scanner ran and found nothing" ambiguity in `create-issues`/auto-close is
    unchanged, and stays with the operator per #109's own write-up.

## Confirmed clean / not applicable (recorded so it isn't re-checked next pass)

- **`secret-scan-reusable.yml`** — clean. Pinned+digested Gitleaks image, `--exit-code`
  passed straight through to the job's exit status, minimal `permissions:`, no custom
  parsing logic to have a fail-open path in.
- **`auto-merge-churn.py` / `suppression-audit.py`** — no LLM calls (defect class 1 N/A);
  every merge/audit-decision input traces to trusted GitHub event/API data, never PR-authored
  free text (defect class 2 N/A) — `audit-canonical-suppressions.yml` has no `pull_request`
  trigger at all.
- **`dast-scan` / `pentest-scan` / `secret-scan`** — no LLM calls anywhere in the family
  (defect class 1 N/A, grep+read confirmed across every production file); suppression
  matching in both `triage.py`s keys only on fixed scanner/probe metadata (template-id,
  category, location), never raw target response content (defect class 2 N/A there).
- **`pentest-scan-reusable.yml`** — no blanket `|| true` around the probe-run step; a hard
  crash there does propagate and fail the job (contrast with dast, finding 7 above).

## Classification summary

| # | Finding | Class | Status |
|---|---|---|---|
| 1 | `security-scan.py` missing LLM truncation guard | CRITICAL/security-shaped | **Fixed** |
| 2 | `health-check.py` missing explicit LLM truncation guard | cheap/mirror | **Fixed** |
| 3 | `pentest/triage.py` auto-close-all on empty findings | CRITICAL/security-shaped | **Fixed** |
| 4 | `auto-merge-churn.py` arms auto-merge despite failed approve | CRITICAL/security-shaped | **Fixed** |
| 5 | 5x silent exception swallowing in pentest probes | cheap/mechanical | **Fixed** |
| 6 | `suppression-audit.py` missing-path auto-closes tracking issue | non-trivial | Written up |
| 7 | `dast-scan-reusable.yml` `\|\| true` masks scan errors | non-trivial | Written up |
| 8 | pentest family: unsanitized evidence into issue bodies | non-trivial | Written up |
| 9 | `security-scan.py` title-only issue indexing, no author check | non-trivial | Written up |
| 10 | `health-check.py` grouped-Dependabot-bump fail-open | non-trivial | Written up |
| 11 | weekly-security-scan missing-artifact auto-close (ref #109) | non-trivial, on record | Not duplicated |
