"""Guards the comment format capture-findings parses against the reviewer that writes it.

capture-findings ingests the PR-time reviewers' comments (infra-commons/meta#1187), but
the format of those comments is defined in a DIFFERENT composite action —
`.github/actions/adversarial-review/`. Nothing but this test connects the two. If the
reviewer's markers, mandated section headers or suppressed-block wrapper change, the
parser here would keep running and quietly find nothing, which is precisely the
"no signal distinguishing 'no finding' from 'the model never ran'" failure #1187
exists to remove.

**If this test fails, the fix belongs on the capture-findings side.** Update the
parser and these anchors to match what the reviewer now emits. Do not change
`adversarial-review.py` to satisfy this test — this file is READ-ONLY on that action,
and the reviewer's output format is that action's to decide.

The reviewer source is read as TEXT, never imported: importing it would couple this
test job to adversarial-review's own dependency set, which the capture-findings test
job does not install.

The right long-term fix is for the reviewer to emit a machine-readable findings block
alongside the human-readable one, which would delete the parser this test protects.
That is a change to the adversarial-review action, tracked separately.
"""
import importlib.util
from pathlib import Path

import pytest

_ACTION_DIR = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("capture", _ACTION_DIR / "capture.py")
capture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(capture)

_REVIEWER_SOURCE = _ACTION_DIR.parent / "adversarial-review" / "adversarial-review.py"


@pytest.fixture(scope="module")
def reviewer_text() -> str:
    if not _REVIEWER_SOURCE.exists():
        pytest.skip(f"adversarial-review action not present at {_REVIEWER_SOURCE}")
    return _REVIEWER_SOURCE.read_text(encoding="utf-8")


def test_both_reviewer_markers_still_exist(reviewer_text):
    """Each marker identifies one reviewer's comment. A renamed marker = a blind door."""
    for marker in capture._PR_COMMENT_MARKERS:
        assert marker in reviewer_text, (
            f"capture-findings looks for the marker {marker!r}, which the reviewer no "
            "longer emits — that reviewer's findings are now invisible to the ingest."
        )


def test_trusted_comment_author_matches(reviewer_text):
    """Authorship is the only real provenance check; a marker can be pasted by anyone."""
    assert f'"{capture.TRUSTED_COMMENT_AUTHOR}"' in reviewer_text


def test_mandated_section_headers_still_specified(reviewer_text):
    """The severity headers the parser splits on are set by the reviewer's system prompt."""
    assert "## Security findings" in reviewer_text
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        assert f"### {severity} —" in reviewer_text, (
            f"the reviewer no longer mandates a '### {severity} —' section header"
        )
    assert "### Summary" in reviewer_text


def test_bullet_shape_still_specified(reviewer_text):
    """`- [file:line] Description.` is what _BULLET_STRICT_RE matches."""
    assert "- [file:line]" in reviewer_text


def test_suppressed_block_wrapper_still_matches(reviewer_text):
    """The wrapper the parser cuts on, so already-suppressed findings stay suppressed."""
    assert "<summary>Suppressed findings (acknowledged false positives)</summary>" in reviewer_text


def test_parser_reads_a_body_built_from_the_reviewers_own_strings(reviewer_text):
    """End-to-end over anchors lifted from the reviewer source, not hand-copied text."""
    marker = next(iter(capture._PR_COMMENT_MARKERS))
    body = (
        f"{marker}\n"
        "## Adversarial AI Security Review (Claude claude-sonnet-5)\n\n"
        "> Commit: `abcd1234`\n\n"
        "## Security findings\n\n"
        "### CRITICAL — exploit-ready, must fix before merge\n"
        '_(or "None")_\n\n'
        "### HIGH — serious, must fix before production\n"
        "- [src/app.py:12] A real finding.\n\n"
        "### Summary\nNothing else.\n"
    )
    result = capture.parse_review_comment(body, "Claude")
    assert result["status"] == "parsed"
    assert [(f["severity"], f["location"]) for f in result["findings"]] == [("HIGH", "src/app.py:12")]
