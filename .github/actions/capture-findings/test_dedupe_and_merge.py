"""Tests for collapsing findings that arrive through both doors (infra-commons/meta#1187).

Adding the PR-time ingest gave this action a second source of findings, and the two
sources describe the same real finding differently. If they do not collapse, the fix
files two or three issues per finding — noisier than the gap it closes, and the kind of
regression that gets a useful control turned off.

Two separate mechanisms, tested separately because they fail differently:

  * `merge_candidates` collapses findings BEFORE anything is filed, on severity + file
    path. It exists because the sources disagree about line numbers by construction.
  * The filing loop's `existing` / `existing_location_keys` sets collapse anything that
    survives, against issues already open AND against issues filed earlier in the same
    run. The in-run half was a live bug before this change: the sets were built once
    and never updated.
"""
import importlib.util
from pathlib import Path

_ACTION_DIR = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("capture", _ACTION_DIR / "capture.py")
capture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(capture)


def _finding(severity, location, title, description="", sources=None, category="unknown"):
    f = {
        "severity": severity, "location": location, "title": title,
        "description": description or title, "category": category,
    }
    if sources is not None:
        f["sources"] = sources
    return f


# ── merge_candidates ────────────────────────────────────────────────────────────

def test_same_file_different_line_numbers_collapse():
    """The whole reason the merge key drops the line number.

    A PR-time reviewer numbers against the PR diff; the post-merge pass numbers
    against the merged tree. Exact `file:line` matching — which is what
    `_location_key` does for issue titles — would file this finding twice.
    """
    merged = capture.merge_candidates(
        [_finding("HIGH", "src/app.py:12", "Token exposed", sources=["PR-time OpenAI review of #7"])],
        [_finding("HIGH", "src/app.py:15", "Credential in env")],
    )
    assert len(merged) == 1
    assert merged[0]["sources"] == ["PR-time OpenAI review of #7", "post-merge review pass"]


def test_pr_time_location_and_title_win():
    """PR-time findings go in first: they carry named-reviewer provenance."""
    merged = capture.merge_candidates(
        [_finding("HIGH", "src/app.py:12", "Token exposed", sources=["PR-time Claude review of #7"])],
        [_finding("HIGH", "src/app.py:15", "Credential in env")],
    )
    assert merged[0]["location"] == "src/app.py:12"
    assert merged[0]["title"] == "Token exposed"


def test_both_descriptions_are_kept():
    """Nothing is lost to the merge — that is what makes dropping the line number safe."""
    merged = capture.merge_candidates(
        [_finding("HIGH", "src/app.py:12", "A", description="postinstall exfiltration path")],
        [_finding("HIGH", "src/app.py:15", "B", description="job-level env var scope")],
    )
    assert "postinstall exfiltration path" in merged[0]["description"]
    assert "job-level env var scope" in merged[0]["description"]


def test_different_severities_do_not_collapse():
    """A HIGH and a MEDIUM in one file are different findings with different urgency."""
    merged = capture.merge_candidates(
        [_finding("HIGH", "src/app.py:12", "A")],
        [_finding("MEDIUM", "src/app.py:12", "B")],
    )
    assert len(merged) == 2


def test_different_files_do_not_collapse():
    merged = capture.merge_candidates(
        [_finding("HIGH", "src/app.py:12", "A")],
        [_finding("HIGH", "src/other.py:12", "B")],
    )
    assert len(merged) == 2


def test_path_normalisation_collapses_leading_dot_slash_and_case():
    assert capture._merge_key(_finding("HIGH", "./src/App.py:12", "x")) == \
           capture._merge_key(_finding("HIGH", "src/app.py:99", "x"))


def test_a_real_category_beats_unknown():
    """An ingested finding has no category; the post-merge pass supplies one."""
    merged = capture.merge_candidates(
        [_finding("HIGH", "src/app.py:12", "A", category="unknown")],
        [_finding("HIGH", "src/app.py:15", "B", category="secrets-exposure")],
    )
    assert merged[0]["category"] == "secrets-exposure"


def test_post_merge_only_findings_get_a_default_source():
    merged = capture.merge_candidates([], [_finding("HIGH", "src/app.py:1", "A")])
    assert merged[0]["sources"] == ["post-merge review pass"]


def test_merge_is_order_stable():
    merged = capture.merge_candidates(
        [_finding("HIGH", "b.py:1", "B"), _finding("HIGH", "a.py:1", "A")], [],
    )
    assert [f["location"] for f in merged] == ["b.py:1", "a.py:1"]


# ── Issue-title dedupe keys ─────────────────────────────────────────────────────

def test_ingested_findings_keep_the_shared_title_prefix():
    """A distinct prefix would break `_location_key`, and with it the memory of every
    finding a human already closed as not-planned — those would be re-filed."""
    title = capture.issue_title(_finding("HIGH", "src/app.py:12", "Token exposed"))
    assert title.startswith("[Security][adversarial-ai][HIGH] ")
    assert capture._location_key(title) == "[Security][adversarial-ai][HIGH] src/app.py:12"


def test_provenance_reaches_the_issue_body():
    body = capture.issue_body(
        _finding("HIGH", "src/app.py:12", "T", sources=["PR-time OpenAI review of #7",
                                                        "post-merge review pass"]),
        "c" * 40, "o/r", "https://example.invalid/run",
    )
    assert "**Reported by:** PR-time OpenAI review of #7; post-merge review pass" in body


def test_issue_body_without_sources_still_renders():
    """Older call sites and the digest path do not set `sources`."""
    body = capture.issue_body(
        _finding("HIGH", "src/app.py:12", "T"), "c" * 40, "o/r", "https://example.invalid/run",
    )
    assert "**Reported by:** post-merge review pass" in body
