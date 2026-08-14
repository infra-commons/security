"""Tests that the reviewer's SYSTEM_PROMPT no longer hard-codes one caller's
product/tenancy/deployment premise, and that get_repo_context()/
_build_user_content() correctly surface repo-supplied context instead.

Regression guard for infra-commons/security#79: the old hardcoded premise
("multi-tenant SaaS platform ... deploys to Azure, one subscription per
client") caused the reviewer to fabricate specific findings — e.g.
infra-commons/meta#570 reported "leaking cross-tenant financial document
data" on a repo with no tenants at all. These tests guard against that
premise (or an equivalent one) silently reappearing, and against the
existing repo-context mechanism regressing.
"""
import importlib.util
from pathlib import Path

import pytest

# The module filename contains a dash, so it cannot be imported by name.
_MODULE_PATH = Path(__file__).parent / "adversarial-review.py"
_spec = importlib.util.spec_from_file_location("adversarial_review", _MODULE_PATH)
adv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(adv)


# ── Hardcoded premise removed ───────────────────────────────────────────────────

# Exact substrings from the removed sentence, chosen so they don't overlap
# with the (intentionally untouched) "Focus on" checklist vocabulary — e.g.
# bare "multi-tenant" alone would false-positive against checklist item 2
# ("multi-tenant data isolation failures"), which is not the bug.
_REMOVED_PREMISE_SUBSTRINGS = [
    "builds AI workflow",
    "one subscription per client",
    "multi-tenant SaaS platform that builds",
]


@pytest.mark.parametrize("substring", _REMOVED_PREMISE_SUBSTRINGS)
def test_system_prompt_no_longer_hardcodes_the_saas_premise(substring):
    assert substring not in adv.SYSTEM_PROMPT


# ── Neutral-default instruction present ─────────────────────────────────────────

def test_system_prompt_treats_repo_context_as_authoritative_when_present():
    assert "authoritative description" in adv.SYSTEM_PROMPT
    assert "<repo_context>" in adv.SYSTEM_PROMPT


def test_system_prompt_forbids_inventing_tenancy_facts_when_absent():
    assert "do not assume or assert anything" in adv.SYSTEM_PROMPT
    assert "known fabrication pattern" in adv.SYSTEM_PROMPT


# ── get_repo_context() ───────────────────────────────────────────────────────────

def test_get_repo_context_returns_empty_when_no_context_files_present(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert adv.get_repo_context() == ""


def test_get_repo_context_joins_present_files_and_skips_missing(tmp_path, monkeypatch):
    (tmp_path / "README.md").write_text("this repo does X")
    (tmp_path / "SOLUTION.yaml").write_text("solution: Y")
    monkeypatch.chdir(tmp_path)
    ctx = adv.get_repo_context()
    assert "=== README.md ===\nthis repo does X" in ctx
    assert "=== SOLUTION.yaml ===\nsolution: Y" in ctx
    assert "REQUIREMENTS.md" not in ctx
    assert "AGENTS.md" not in ctx


# ── _build_user_content() ────────────────────────────────────────────────────────

def test_build_user_content_omits_repo_context_block_when_empty():
    content = adv._build_user_content("diff text", "")
    assert "<repo_context>" not in content


def test_build_user_content_includes_repo_context_block_when_present():
    content = adv._build_user_content("diff text", "this repo does X")
    assert "<repo_context>\nthis repo does X\n</repo_context>" in content
    assert content.index("<repo_context>") < content.index("<pr_diff>")


# ── Cache-comment sanity (#79 design note) ───────────────────────────────────────

def test_system_prompt_still_comfortably_clears_the_cache_minimum():
    # Guards the accuracy of the cache_control comment in call_anthropic():
    # SYSTEM_PROMPT should stay well above the ~1,024-token Sonnet cache
    # minimum. Rough 4-chars-per-token estimate, same one used when that
    # comment was written.
    assert len(adv.SYSTEM_PROMPT) // 4 > 1024
