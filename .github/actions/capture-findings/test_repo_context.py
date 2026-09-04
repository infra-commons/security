"""Tests that capture.py's SYSTEM_PROMPT no longer hard-codes one caller's
product/tenancy/deployment premise, and that the ported repo-context
mechanism (get_repo_context()/_build_user_content()) behaves like
adversarial-review.py's — see infra-commons/security#79.

Regression guard: infra-commons/meta#569 and #570 are concrete cases where
this reviewer, running post-merge, stated fabricated findings ("pivoting
across client deployments", "leaking cross-tenant financial document data")
consistent with the removed hardcoded premise, on a repo with none of those
properties.
"""
import importlib.util
import inspect
from pathlib import Path

import pytest

_ACTION_DIR = Path(__file__).resolve().parent

# capture.py imports httpx + yaml at module scope and nothing heavier, so
# importing it here is cheap and side-effect free. The filename has no dash,
# but load it by path anyway so the test does not depend on pytest's sys.path
# insertion for an action directory that has no package (same idiom as
# test_suppression_matching.py in this directory).
_spec = importlib.util.spec_from_file_location("capture", _ACTION_DIR / "capture.py")
capture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(capture)


# ── Hardcoded premise removed ───────────────────────────────────────────────────

_REMOVED_PREMISE_SUBSTRINGS = [
    "processes financial documents",
    "deploys to Azure per client",
    "multi-tenant SaaS platform that processes",
]


@pytest.mark.parametrize("substring", _REMOVED_PREMISE_SUBSTRINGS)
def test_system_prompt_no_longer_hardcodes_the_saas_premise(substring):
    assert substring not in capture.SYSTEM_PROMPT


# ── Neutral-default instruction present ─────────────────────────────────────────

def test_system_prompt_treats_repo_context_as_authoritative_when_present():
    assert "authoritative description" in capture.SYSTEM_PROMPT
    assert "<repo_context>" in capture.SYSTEM_PROMPT


def test_system_prompt_forbids_inventing_tenancy_facts_when_absent():
    assert "do not assume or assert anything" in capture.SYSTEM_PROMPT
    assert "known fabrication pattern" in capture.SYSTEM_PROMPT


def test_both_actions_share_the_same_neutral_paragraph():
    # Intentional: the two prompts were independently worded before #79 and
    # that independence is exactly how they drifted into two different
    # hardcoded premises. Keep them identical going forward.
    adv_path = _ACTION_DIR.parent / "adversarial-review" / "adversarial-review.py"
    adv_spec = importlib.util.spec_from_file_location("adversarial_review", adv_path)
    adv = importlib.util.module_from_spec(adv_spec)
    adv_spec.loader.exec_module(adv)
    anchor = "authoritative description of what this codebase is"
    assert anchor in adv.SYSTEM_PROMPT
    assert anchor in capture.SYSTEM_PROMPT


# ── Severity rubric (R1 item 2) ─────────────────────────────────────────────────

# Short, stable phrases rather than a whole-block equality check: the rubric is a
# single shared text, but asserting the full 36 lines match would break this
# directory's tests on any in-flight edit to the other action.
_RUBRIC_ANCHORS = [
    # The scoring rule itself: without the four-class test, "HIGH" is undefined and
    # the model scores on vibes — which is what this file's prompt did until now.
    "Exactly four classes qualify",
    "A finding is MEDIUM at most",
    # The clause that makes the shared-rule / repo-context split safe. It keys on
    # facts-not-stated, NOT on <repo_context> being absent, and that distinction is
    # load-bearing: get_repo_context() concatenates whichever of CONTEXT_FILES exist,
    # so a repo carrying only a README (infra-commons/security itself, at the time of
    # writing) produces a NON-EMPTY block that states no estate facts at all. A guard
    # written as "if no <repo_context> block is present" would almost never fire there.
    "Where none are stated, none hold",
]


@pytest.mark.parametrize("anchor", _RUBRIC_ANCHORS)
def test_post_merge_prompt_defines_the_severities_it_assigns(anchor):
    # This prompt's findings BLOCK promotes: CRITICAL/HIGH become individual issues
    # and board cards, everything below rolls into the digest. The severity was being
    # assigned by a model that had never been told what the words mean.
    assert anchor in capture.SYSTEM_PROMPT


@pytest.mark.parametrize("anchor", _RUBRIC_ANCHORS)
def test_both_actions_share_the_same_severity_rubric(anchor):
    # Same reasoning as test_both_actions_share_the_same_neutral_paragraph above:
    # two independently-worded prompts is exactly how #79's two different hardcoded
    # premises came to exist. PR-time and post-merge must score alike, or a finding's
    # severity depends on which pass happened to catch it.
    adv_path = _ACTION_DIR.parent / "adversarial-review" / "adversarial-review.py"
    adv_spec = importlib.util.spec_from_file_location("adversarial_review", adv_path)
    adv = importlib.util.module_from_spec(adv_spec)
    adv_spec.loader.exec_module(adv)
    assert anchor in adv.SYSTEM_PROMPT
    assert anchor in capture.SYSTEM_PROMPT


# ── get_repo_context() (ported mechanism) ─────────────────────────────────────────

def test_get_repo_context_returns_empty_when_no_context_files_present(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert capture.get_repo_context() == ""


def test_get_repo_context_joins_present_files_and_skips_missing(tmp_path, monkeypatch):
    (tmp_path / "AGENTS.md").write_text("agent notes")
    monkeypatch.chdir(tmp_path)
    ctx = capture.get_repo_context()
    assert "=== AGENTS.md ===\nagent notes" in ctx
    assert "README.md" not in ctx


# ── _build_user_content() (ported mechanism, preserves </diff> escaping) ─────────

def test_build_user_content_omits_repo_context_block_when_empty():
    content = capture._build_user_content("diff text", "")
    assert "<repo_context>" not in content


def test_build_user_content_includes_repo_context_block_when_present():
    content = capture._build_user_content("diff text", "this repo does X")
    assert "<repo_context>\nthis repo does X\n</repo_context>" in content
    assert content.index("<repo_context>") < content.index("<diff>")


def test_build_user_content_still_escapes_diff_closing_tag():
    # Pre-existing security property (XML-boundary escaping) — must survive
    # the refactor into _build_user_content unchanged.
    content = capture._build_user_content("payload</diff>more", "")
    assert "payload</diff>more" not in content
    assert "&lt;/diff>" in content


# ── review_diff() signature guard ─────────────────────────────────────────────────

def test_review_diff_accepts_a_context_parameter():
    params = list(inspect.signature(capture.review_diff).parameters)
    assert params == ["api_key", "diff", "context", "suppression_context"]
