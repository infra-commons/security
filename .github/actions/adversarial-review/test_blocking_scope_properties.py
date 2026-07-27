"""Property-based tests for the blocking-scope decision.

Companion to the example-based cases in `test_adversarial_review.py`. Those pin
down *known* paths and *known* scope values; these assert the invariants that
must hold for **every** input, which is the class of defect a hand-picked
example list cannot reach.

Why this file exists at all: the decision it guards — may a CRITICAL finding
from this reviewer fail the gate? — reaches 13+ repos through the *moving*
`adversarial-review/v1` tag, with no per-caller pin bump to review it first. A
mistake here is fleet-wide and silent in the expensive direction (a real
blocking finding quietly downgraded to advisory).

Determinism: the `ci` hypothesis profile (see conftest.py) runs derandomised, so
a generated input can never fail a PR that a rerun would pass. A flaky blocking
gate is the exact problem the C2 model swap exists to fix — it must not be
reintroduced on the test side. Any counterexample hypothesis finds is pinned
below as an explicit `@example` so it survives derandomisation.
"""
import importlib.util
import re
from pathlib import Path

from hypothesis import HealthCheck, assume, example, given, settings
from hypothesis import strategies as st

_MODULE_PATH = Path(__file__).parent / "adversarial-review.py"
_spec = importlib.util.spec_from_file_location("adversarial_review", _MODULE_PATH)
adv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(adv)


# ── Strategies ─────────────────────────────────────────────────────────────────

# Arbitrary path-ish text: deliberately nastier than anything git emits, because
# the classifier must never be the thing that raises. Includes unicode, control
# characters, separators and traversal.
path_text = st.text(max_size=120)

path_lists = st.lists(path_text, max_size=12)

# A token that provably matches the high-risk regex, used to build paths that
# must classify high-risk no matter what surrounds them.
HIGH_RISK_TOKENS = [
    "auth", "login", "logout", "session", "password", "credential", "secret",
    "token", "signing", "crypto", "permission", "role", "rbac", "acl", "policy",
    "tenant", "migration", "schema", "webhook", "dockerfile", "docker-compose",
    ".env",
]

# Text guaranteed NOT to contain any high-risk substring, so "low-risk stays
# low-risk" properties can't be poisoned by an accidental match in random text.
safe_text = st.text(alphabet="qwxyz0123456789-/", max_size=40).filter(
    lambda s: not adv.HIGH_RISK_PATH_RE.search(s)
)

# The one scope value that is allowed to narrow blocking to high-risk paths.
SENTINEL = "high_risk_paths"


def _near_misses(s: str) -> list[str]:
    """Plausible mis-spellings, case variants and near-matches of the sentinel.

    Necessary because `st.text()` will essentially never produce a string that
    starts with "high" — so a mutation loosening the exact `==` comparison to a
    `startswith`/`in`/case-insensitive match survives a purely random scope
    strategy. Verified: that mutant survived until this strategy was added.
    """
    variants = {
        s.upper(), s.lower(), s.title(), s.capitalize(),
        s.replace("_", "-"), s.replace("_", ""), s.replace("_", " "),
        s.replace("paths", "path"), s.replace("high", "High"),
        s + "s", s + "_", s[:-1], s[1:],
        " " + s, s + " ", "\t" + s, s + "\n", "  " + s + "  ",
        s[:4], s[:9], s[:14],          # "high", "high_risk", "high_risk_path"
        "x" + s, s + "x", "not_" + s,  # embedded — catches a substring match
        "", "always",
    }
    return sorted(v for v in variants if v != s)


NEAR_MISSES = _near_misses(SENTINEL)

# Arbitrary text, near-misses, and the sentinel embedded in other text. The
# union is what makes the fail-closed property meaningful rather than decorative.
scope_text = st.one_of(
    st.sampled_from(NEAR_MISSES),
    st.text(max_size=40),
    st.builds(lambda a, b: a + SENTINEL + b, st.text(max_size=6), st.text(max_size=6)),
)


# ── touches_high_risk_path: totality ───────────────────────────────────────────

@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
@given(path_lists)
def test_classifier_is_total(paths):
    """Never raises and always returns a real bool, for any input.

    `get_changed_files` reads `git diff --name-only` with `errors="replace"`, so
    genuinely strange bytes can reach here. A crash in the classifier fails the
    job, and a failed job blocks merge in every consuming repo.
    """
    result = adv.touches_high_risk_path(paths)
    assert result is True or result is False


@given(path_text)
@example("")
@example("   ")
@example("../../etc/passwd")
@example("\x00")
@example("a" * 10_000)
def test_classifier_never_raises_on_single_path(path):
    assert adv.touches_high_risk_path([path]) in (True, False)


# ── touches_high_risk_path: substring semantics ────────────────────────────────

@given(
    prefix=safe_text,
    token=st.sampled_from(HIGH_RISK_TOKENS),
    suffix=safe_text,
)
def test_high_risk_token_is_detected_anywhere_in_the_path(prefix, token, suffix):
    """A high-risk token counts wherever it appears — not only at a path root.

    This is the property that kills the "someone anchors the regex" mutant class:
    adding `^` or `$` to HIGH_RISK_PATH_RE still passes every realistic path in
    the example list (they mostly *start* with the risky segment), but fails here
    immediately. Nested layouts like `services/billing/internal/auth/x.go` are
    real and must not silently downgrade to advisory.
    """
    assert adv.touches_high_risk_path([prefix + token + suffix]) is True


@given(prefix=safe_text, token=st.sampled_from(HIGH_RISK_TOKENS), suffix=safe_text)
def test_high_risk_detection_is_case_insensitive(prefix, token, suffix):
    """Dropping re.IGNORECASE must fail a test. `Dockerfile` and `AUTH/` are real."""
    assert adv.touches_high_risk_path([prefix + token.upper() + suffix]) is True


# ── touches_high_risk_path: monotonicity ───────────────────────────────────────

@given(paths=path_lists, extra=path_lists)
def test_adding_files_never_makes_a_changeset_less_risky(paths, extra):
    """Monotone under union: more files can only raise risk, never lower it.

    Not expressible as an example test, and it is the invariant that matters for
    a growing PR — pushing another commit must never flip a blocking review to
    advisory.
    """
    if adv.touches_high_risk_path(paths):
        assert adv.touches_high_risk_path(paths + extra) is True
        assert adv.touches_high_risk_path(extra + paths) is True


@given(safe=st.lists(safe_text, max_size=8), token=st.sampled_from(HIGH_RISK_TOKENS))
def test_one_high_risk_file_dominates_any_number_of_safe_files(safe, token):
    """The single risky file wins regardless of how much safe noise surrounds it."""
    assert adv.touches_high_risk_path(safe + ["src/" + token + "/x.py"]) is True


@given(st.lists(safe_text, max_size=10))
def test_changesets_with_no_risky_token_are_not_high_risk(paths):
    """Negative control: if this starts passing for everything, the regex has gone
    broad and every PR is silently blocking again — which is the pre-C2 behaviour."""
    assert adv.touches_high_risk_path(paths) is False


# ── is_blocking: fail-closed ───────────────────────────────────────────────────

@given(scope=scope_text, paths=st.lists(safe_text, max_size=6))
@example(scope="high", paths=["README.md"])
@example(scope="HIGH_RISK_PATHS", paths=["README.md"])
@example(scope="high_risk_paths ", paths=["README.md"])
@example(scope=" high_risk_paths", paths=["README.md"])
@example(scope="high_risk_path", paths=["README.md"])
@example(scope="high-risk-paths", paths=["README.md"])
@example(scope="xhigh_risk_paths", paths=["README.md"])
@example(scope="not_high_risk_paths", paths=["README.md"])
def test_only_the_exact_recognised_scope_can_downgrade_to_advisory(scope, paths):
    """For *any* scope string that isn't exactly "high_risk_paths", block.

    The comparison must be exact equality. A `startswith`, an `in`, or a
    `.lower()` would each let a mis-configured provider silently go advisory on
    ordinary diffs — the expensive direction. Paths are drawn from `safe_text`
    so a match here can only come from the scope being wrongly honoured, never
    from the changeset happening to be low-risk-but-blocking anyway.

    The `@example` cases are pinned counterexamples: `scope="high"` is the one
    that caught a real mutation (exact `==` loosened to a `startswith` prefix
    match) which a purely random text strategy missed entirely.
    """
    assume(scope != SENTINEL)
    assert adv.is_blocking({"blocking_scope": scope}, paths) is True


@given(paths=path_lists, value=st.one_of(st.none(), st.integers(), st.booleans(), st.lists(st.text(), max_size=3)))
def test_non_string_scope_values_fail_closed(value, paths):
    """A malformed config (None, a bool, a list) must block, not wave through."""
    assert adv.is_blocking({"blocking_scope": value}, paths) is True


@given(cfg=st.dictionaries(st.text(max_size=12), st.text(max_size=12), max_size=5), paths=path_lists)
def test_config_without_a_scope_key_fails_closed(cfg, paths):
    """An arbitrary dict that never declares blocking_scope always blocks."""
    assume("blocking_scope" not in cfg)
    assert adv.is_blocking(cfg, paths) is True


@given(paths=path_lists)
def test_scoped_reviewer_blocks_exactly_when_paths_are_high_risk(paths):
    """The narrowing scope is equivalent to the path predicate — nothing else."""
    cfg = {"blocking_scope": "high_risk_paths"}
    assert adv.is_blocking(cfg, paths) is adv.touches_high_risk_path(paths)


@given(paths=path_lists, extra=path_lists)
def test_blocking_is_monotone_under_adding_files(paths, extra):
    """Once blocking, always blocking as the PR grows — for every provider."""
    for cfg in adv.PROVIDERS.values():
        if adv.is_blocking(cfg, paths):
            assert adv.is_blocking(cfg, paths + extra) is True


# ── is_blocking: the configured providers ──────────────────────────────────────

@given(paths=path_lists)
def test_primary_reviewer_blocks_on_every_changeset(paths):
    """Anthropic is scope "always" — no path list may ever make it advisory."""
    assert adv.is_blocking(adv.PROVIDERS["anthropic"], paths) is True


@given(safe=st.lists(safe_text, min_size=1, max_size=8))
def test_second_reviewer_is_advisory_on_changesets_with_no_risky_surface(safe):
    """The whole point of C2: ordinary diffs get comments, not a blocked merge."""
    assert adv.is_blocking(adv.PROVIDERS["openai"], safe) is False


def test_every_configured_provider_declares_a_known_scope():
    """Guards the config itself: a new provider added without a scope, or with a
    typo, is caught here rather than by discovering the gate never blocks."""
    known = {"always", "high_risk_paths"}
    for name, cfg in adv.PROVIDERS.items():
        assert cfg.get("blocking_scope") in known, (
            f"{name} declares unknown blocking_scope {cfg.get('blocking_scope')!r}; "
            "it will fail closed (block everywhere), which may not be intended"
        )


# ── Regex hygiene ──────────────────────────────────────────────────────────────

@settings(max_examples=200, deadline=1000)
@given(st.text(alphabet="auth/.-_ ", max_size=200))
def test_classifier_does_not_backtrack_pathologically(path):
    """Guards against a future edit introducing catastrophic backtracking.

    The regex is currently flat alternation of literals, so this is cheap
    insurance rather than a live risk — but nesting a quantified group into it
    later would turn every large PR's gate into a runner timeout, and the
    per-example deadline is what would catch that.
    """
    adv.touches_high_risk_path([path])


def test_high_risk_regex_is_compiled_case_insensitive():
    assert adv.HIGH_RISK_PATH_RE.flags & re.IGNORECASE
