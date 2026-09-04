"""Tests for the CRITICAL suppression carve-out and its visibility.

`apply_suppressions` never suppresses a finding inside the reviewer's
`### CRITICAL` section. That is deliberate, fail-closed design and the first test
below is the lock on it. Until infra-commons/security#117 it was also completely
SILENT: an entry whose patterns matched a CRITICAL was never consulted, so it was
never reported as matched-and-skipped either — the suppressions file accepted an
entry the gate would never honour and the author found out at the next red gate.

These tests cover both halves: the carve-out still holds, and a match against it
is now reported without any finding being filtered that was not filtered before.
"""
import importlib.util
from pathlib import Path

# The module filename contains a dash, so it cannot be imported by name.
_MODULE_PATH = Path(__file__).parent / "adversarial-review.py"
_spec = importlib.util.spec_from_file_location("adversarial_review", _MODULE_PATH)
adv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(adv)


OIDC_ENTRY = {
    "id": "deploy-platform-pr-trigger-oidc",
    "file_pattern": r".*\.github/workflows/deploy-platform\.ya?ml(:\d+(-\d+)?)?$",
    "finding_pattern": r"(OIDC|pull_request_target|federated credential)",
    "reason": "PR-time Azure identity is read-only; see ADR-0008.",
}

CRITICAL_FINDING = (
    "- [.github/workflows/deploy-platform.yml:42] pull_request_target grants an "
    "OIDC token to fork code."
)
HIGH_FINDING = (
    "- [.github/workflows/deploy-platform.yml:88] OIDC federated credential scope "
    "is broader than the job needs."
)


def _review(critical_lines, high_lines=("- None.",)):
    return "\n".join(
        ["### CRITICAL", *critical_lines, "", "### HIGH", *high_lines, "", "### Summary", "Done."]
    )


# ── The carve-out itself (this must never loosen) ──────────────────────────────

def test_critical_matching_a_suppression_is_still_not_suppressed():
    """The lock. A matching entry must not remove a CRITICAL from the review."""
    review = _review([CRITICAL_FINDING])

    filtered, suppressed, _ = adv.apply_suppressions(review, [OIDC_ENTRY])

    assert CRITICAL_FINDING in filtered
    assert suppressed == []
    # And the gate signal computed from the filtered text is unchanged.
    assert adv.has_critical_findings(filtered) is True


def test_filtered_output_is_byte_identical_to_no_suppressions_for_a_critical_only_review():
    """Reporting must not change what is filtered — only what is said about it."""
    review = _review([CRITICAL_FINDING])

    with_entry, _, _ = adv.apply_suppressions(review, [OIDC_ENTRY])
    without_entry, _, _ = adv.apply_suppressions(review, [])

    assert with_entry == without_entry == review


# ── The visibility (this is the fix) ───────────────────────────────────────────

def test_a_suppression_matching_a_critical_is_reported(capsys):
    review = _review([CRITICAL_FINDING])

    _, _, inert = adv.apply_suppressions(review, [OIDC_ENTRY])

    assert len(inert) == 1
    entry_id, excerpt = inert[0]
    assert entry_id == "deploy-platform-pr-trigger-oidc"
    assert "deploy-platform.yml:42" in excerpt
    # And the job log carries it too, for the paths where no comment is posted
    # (cache hit, failed comment POST).
    assert "deploy-platform-pr-trigger-oidc" in capsys.readouterr().err


def test_the_notice_names_the_entry_and_is_not_hidden_in_a_details_block():
    note = adv.render_inert_suppression_notice(
        [("deploy-platform-pr-trigger-oidc", "[deploy-platform.yml:42] OIDC token to fork code.")]
    )

    assert "deploy-platform-pr-trigger-oidc" in note
    assert "NOT applied" in note
    # The `<details>` trail is titled "acknowledged false positives"; an entry that
    # was NOT applied is the opposite claim, and burying it costs the author the one
    # line they need on the run where the gate is red.
    assert "<details>" not in note
    # Rendered as a blockquote continuation, like the advisory note.
    assert note.startswith(">\n")


def test_no_inert_entries_renders_nothing():
    assert adv.render_inert_suppression_notice([]) == ""


# ── No false alarms ────────────────────────────────────────────────────────────

def test_an_empty_critical_section_does_not_trigger_the_notice():
    """`- None.` is a placeholder, not a finding — a `.*` pattern matches its empty
    file-ref, so without the shared finding-line guard this fires on clean reviews."""
    catch_all = {
        "id": "catch-all",
        "file_pattern": ".*",
        "finding_pattern": ".*",
        "reason": "Deliberately broad, for this test.",
    }
    review = _review(["- None."], high_lines=["- None."])

    filtered, _, inert = adv.apply_suppressions(review, [catch_all])

    assert inert == []
    assert adv.has_critical_findings(filtered) is False


def test_a_critical_matching_no_suppression_is_not_reported():
    unrelated = {
        "id": "unrelated",
        "file_pattern": r"^src/vendor/.*",
        "finding_pattern": "hardcoded credential",
        "reason": "Vendored fixture.",
    }
    review = _review([CRITICAL_FINDING])

    _, _, inert = adv.apply_suppressions(review, [unrelated])

    assert inert == []


def test_no_suppressions_at_all_reports_nothing():
    review = _review([CRITICAL_FINDING])

    filtered, suppressed, inert = adv.apply_suppressions(review, [])

    assert (filtered, suppressed, inert) == (review, [], [])


# ── The ordinary path is untouched ─────────────────────────────────────────────

def test_the_same_entry_still_suppresses_a_high():
    """The asymmetry the notice warns about, proven: the entry works below CRITICAL."""
    review = _review(["- None."], high_lines=[HIGH_FINDING])

    filtered, suppressed, inert = adv.apply_suppressions(review, [OIDC_ENTRY])

    assert HIGH_FINDING not in filtered
    assert len(suppressed) == 1
    assert "deploy-platform-pr-trigger-oidc" in suppressed[0]
    assert inert == []


def test_inert_criticals_do_not_consume_the_suppression_budget():
    """An inert match suppresses nothing, so charging it to the cap would let
    CRITICALs starve real suppressions."""
    criticals = [
        f"- [.github/workflows/deploy-platform.yml:{n}] OIDC token to fork code."
        for n in range(1, 6)
    ]
    highs = [
        f"- [.github/workflows/deploy-platform.yml:{n}] OIDC federated credential scope."
        for n in range(100, 100 + adv.MAX_SUPPRESSIONS_PER_REVIEW)
    ]
    review = _review(criticals, high_lines=highs)

    filtered, suppressed, inert = adv.apply_suppressions(review, [OIDC_ENTRY])

    assert len(suppressed) == adv.MAX_SUPPRESSIONS_PER_REVIEW
    assert len(inert) == len(criticals)
    for line in criticals:
        assert line in filtered
    assert adv.has_critical_findings(filtered) is True


def test_the_inert_list_is_capped():
    criticals = [
        f"- [.github/workflows/deploy-platform.yml:{n}] OIDC token to fork code."
        for n in range(1, adv.MAX_SUPPRESSIONS_PER_REVIEW + 6)
    ]
    review = _review(criticals)

    filtered, _, inert = adv.apply_suppressions(review, [OIDC_ENTRY])

    assert len(inert) == adv.MAX_SUPPRESSIONS_PER_REVIEW
    # Capping the REPORT must never cap the carve-out: every CRITICAL is still there.
    for line in criticals:
        assert line in filtered


def test_the_excerpt_is_truncated():
    long_finding = (
        "- [.github/workflows/deploy-platform.yml:42] OIDC " + ("very long detail " * 60)
    )
    review = _review([long_finding])

    _, _, inert = adv.apply_suppressions(review, [OIDC_ENTRY])

    assert len(inert[0][1]) == adv._INERT_EXCERPT_CHARS
