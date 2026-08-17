# Composite-action pin posture: a producer-side decision (handoff item 2)

**Scope:** this repo's own delivery mechanism for the composites
`.github/actions/adversarial-review` and `.github/actions/adversarial-review-gate`, and how it
relates to three positions raised across the fleet:

- **(a)** `rolliq-com/solution-recruitment-reference-check#1266` — measured that
  `adversarial-review-reusable.yml` resolves both composites from moving `.../v1` tags at
  every ref examined, filed as "not fixable from any Rolliq repo."
- **(b)** rolliq-com ADR 0008 (Accepted, 2026-08-16) — shared security composites reach the
  fleet by moving tag, decided deliberately.
- **(c)** `infra-commons/legal#23` OPEN-2 — the same question for the legal lineage.

This is a written position, not a code change. Three changes are implied by the analysis
below; each is named and left for explicit sign-off rather than made here.

## What was verified, live, in this repo (not taken from either issue's prose)

**1. The mechanism is real and current.** `adversarial-review-reusable.yml` resolves both
composites via moving tags:

```
.github/actions/adversarial-review@adversarial-review/v1            (lines 91, 118)
.github/actions/adversarial-review-gate@adversarial-review-gate/v1  (line 190)
```

A force-fetch of tags (`git fetch --tags --force origin`) confirms both are genuinely moving
aliases: `adversarial-review/v1` == `adversarial-review/v1.7.0`, `adversarial-review-gate/v1`
== `adversarial-review-gate/v1.3.0`, each having been re-pointed release over release (`v1.0.0`
through `v1.7.0` on eight distinct commits for `adversarial-review` alone).

**2. The tag moved *during this exact investigation window*.** `adversarial-review/v1`
resolved to a different commit when #1266 was written (2026-08-13) than it does today
(2026-08-17, commit `c948fba`). Between those two points it advanced across four more commits
of review/gate-logic changes (`eca4b3f`, `a54cac7`, `5db28e5`, `01fff5e`) — real CRITICAL
fail-open fixes — with zero action from any caller repo. That is the tag working exactly as
designed, and it is also exactly the exposure #1266 describes. Both are true at once, which is
why this needed a decision rather than a fix.

**3. The caller's SHA pin covers only the orchestration file.** The reusable's own header
comment says "pin to immutable SHA," and that pin genuinely fixes which version of
`adversarial-review-reusable.yml` runs. It does not fix which version of the two composites
runs — those are tag-resolved unconditionally, on every run, regardless of the caller's pin.

**4. The tag's integrity rests entirely on this repo's own ruleset — and that ruleset is
weaker than its sibling's.** Checked live against the GitHub API:

| | `infra-commons/security` (`protect-moving-tags`, id 19945090) | `infra-commons/legal` (`protect-moving-tags`, per `legal#23`'s own thread) |
|---|---|---|
| Target | `refs/tags/*/v1` | `refs/tags/*/v1` |
| Rules | `deletion` only | `update` + `deletion` + `non_fast_forward` |
| Who can move it | Any collaborator with push access, via a plain `git push -f` | Only the App (sole bypass actor) — no human, including an org owner |

`infra-commons/security` currently has 2 collaborators with write/admin access. Either can
retarget `adversarial-review/v1` or `adversarial-review-gate/v1` to an arbitrary commit today,
bypassing PR review, required status checks, and branch protection entirely — those all gate
`main`, not a tag ref push.

This means the CRITICAL our own gate raised against the legal-lineage caller PRs — "anyone
with write access can force-push the tag to an attacker-controlled commit" — is **false for
`infra-commons/legal`** (verified: no human can move that tag) but **true, today, for
`infra-commons/security`'s own tags**. The finding was correct in substance; it landed on the
wrong repo.

**5. No visibility detector exists.** Neither composite's `action.yml` records which commit of
itself actually ran anywhere a caller can read back — no resolved-SHA output, no line in the
PR comment. A caller has no way to notice the tag moved under it, even if it wanted to check.

**6. This repo's own canonical suppression file already asserts the thing #1266 falsifies.**
`.github/adversarial-review-suppressions.yml`'s `sha-pin-first-party-workflows` entry says "the
SHA is the supply-chain pin... these are not `@main` refs... permanent architectural
decision." That's accurate at the reusable-file level. It's not accurate once the reusable's
own internal composite references are moving tags — the reasoning text doesn't distinguish the
two, and needs to. Not changed in this pass.

**7. ADR 0008's Decision 1 text and what actually shipped in `infra-commons/legal` diverge —
a real gap, not just phrasing.** ADR 0008, as quoted in the handoff, says callers continue to
pin reusables by SHA, composites are reached via moving tag, and no caller-side change is
proposed. What shipped: 13 caller PRs (9 `rolliq-com`, 3 `cashbucket-com`, 1
`chargingblindly-com`), of which `rolliq-com/operations#264` and `rolliq-com/website#169` are
already merged, tag-pin the **reusable itself** — `legal-review-reusable.yml@legal-review/v1`
— for the `legal-review` lineage. That is the opposite of "callers continue to pin reusables
by SHA," and unambiguously a caller-side change. It was authorized by a separate operator
ruling recorded in the `legal#23` thread ("ADR 0008 was accepted... keep the moving tag... So
the four blocked PRs... implement an accepted decision"), which invokes ADR 0008 as its
justification without ADR 0008's own text covering or cross-referencing this broader move. A
reader of ADR 0008 alone would conclude no caller has repinned any reusable; that's false for
15 `legal-review` call sites today. This is a document gap in a rolliq-com artifact this lane
doesn't own — named here, not edited.

**8. `legal#23`'s OPEN-2 is decided in substance, not open.** The console thread shows an
operator ruling extending ADR 0008 to `legal-review`, a release mechanism built and exercised
(`legal-review/v1` advanced `8f2fb005` → `b752b17e`, verified against the remote), and 11 of 15
`legal-review` call sites already migrated. The GitHub issue is still open only because of a
tracked residual — 5 call sites not yet migrated, canonical-suppression consolidation not yet
done — not because the tag-vs-SHA question itself is unsettled. Treating it as open the same
way #1266 is open overstates how unresolved it is.

## The position

**(a) and (b) do not contradict at the policy level.** ADR 0008 already accepted, deliberately,
the exact mechanism #1266 measured. The apparent contradiction is that the reviewer/gate that
produced #1266-shaped CRITICALs on the legal-lineage caller PRs doesn't know ADR 0008 exists —
it treats an accepted trade-off as a fresh, blocking vulnerability. That's a producer-side gap:
the suppression that would tell it otherwise doesn't exist, and per the legal lineage's own
note, only a canonical entry *here* (not N per-caller entries) closes it for every caller at
once.

**The tradeoff, stated plainly:**

- **What moving-tag delivery buys:** one tag move ships a review/gate fix fleet-wide with zero
  caller PRs. This repo's own release history (`v1.0.0` → `v1.7.0`) shows that cadence is real
  and has already delivered several CRITICAL fail-open fixes to every SHA-pinning caller
  without asking any of them to act.
- **What it costs:** the caller's SHA pin on the reusable is, for the part of the system that
  actually produces the pass/fail verdict, not a supply-chain control — it's cosmetic. Every
  caller inherits this repo's tag-push exposure silently: no diff, no version bump to review or
  decline, and today no way to even detect the code changed. That exposure is currently bounded
  by a 2-account collaborator list, not by policy — nothing structural stops it from growing.
- **What would have to be true to change it:**
  - *(i)* The reusable pins its own composite references by SHA too. This reverses the
    zero-caller-PR propagation property ADR 0008 was written to keep — every future fix would
    need a reusable-file bump plus every caller's own SHA-bump PR, the exact per-caller cost
    ADR 0008 decided against paying. That's a policy reversal, and belongs back at ADR 0008,
    not decided here.
  - *(ii)* Moving-tag delivery is kept, but the tag ref itself is hardened to match
    `infra-commons/legal`'s ruleset — `update` + `non_fast_forward`, single bypass actor. This
    closes the "any collaborator, zero review, zero trace" hole without touching the
    propagation model, and is orthogonal to the ADR's tag-vs-SHA choice either way: it's worth
    doing regardless of how that policy question resolves.

## Named, not made, in this pass

1. **A canonical suppression entry** in `.github/adversarial-review-suppressions.yml`, keyed
   precisely (not on prose alone — the legal lineage's own record shows a prose-keyed entry
   silently swallows a genuine sibling finding), citing ADR 0008, scoped to "moving
   major-version tag on a first-party composite action." Without it, this repo's own gate will
   keep raising this as CRITICAL, fleet-wide, on every future caller PR that surfaces the
   pattern — the same thing that just happened to the `legal-review` caller PRs.
2. **Hardening `protect-moving-tags`** (ruleset 19945090) to add `update` + `non_fast_forward`
   with a single bypass actor, matching `infra-commons/legal`. This is a live security-control
   change on a public repo and needs explicit sign-off, not silent action.
3. **An ADR 0008 addendum/cross-reference**, owned by rolliq-com, acknowledging the `legal#23`
   reusable-level tag-pin as a sanctioned extension of Decision 1 — or a ruling that it wasn't
   sanctioned and those PRs need reconciling. This lane doesn't write to that document; handing
   it back.

## Explicitly not done

No code or config change. No edit to ADR 0008 or any rolliq-com/entity-org file. No new GitHub
issue opened for the ruleset gap or the ADR cross-reference — both are carried in the handoff
report for the operator to decide whether they become cards. No PR opened or touched outside
`infra-commons/security`. No merge of anything.
