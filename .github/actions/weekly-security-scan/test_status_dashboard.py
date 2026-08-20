"""build_status_body() must count every open `security` issue, not a projection of it.

infra-commons/security#96: `total_by_sev` (the headline "Open findings by severity" table) used
to be computed by summing the "Open findings by source" table over a hardcoded five-source list —
`total_by_sev = {s: sum(counts[src][s] for src in sources) for s in sevs}` — so an issue the source
table couldn't attribute was dropped from *both* tables, not just the source breakdown. Four
distinct paths did this, all filed with a synthetic label table in the issue:

  1. no `source:` label at all
  2. a `source:` outside the hardcoded five (e.g. `source:pentest`, `source:health-check`)
  3. a `severity:` outside the four canonical names (e.g. the fleet's own `severity:proposed-*`)
  4. two `severity:`/`source:` labels resolved by `next()` over a `set` — order not guaranteed,
     so a disposition label like `severity:accepted-for-release` could win the slot and drop the
     issue, and which label won could vary between runs with nothing underneath it changing

Measured live: 10 of 11 open `security` issues on one consumer repo were dropped this way,
rendering a false all-clean `0/0/0/0` dashboard. These tests drive the real `build_status_body()`
(it's a pure function — no mocking needed) rather than a helper in isolation, so a fix that reintroduces
the projection would fail here exactly as it would in the rendered dashboard.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_ACTION_DIR = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("security_scan", _ACTION_DIR / "security-scan.py")
scan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scan)


def _issue(number: int, labels: list[str]) -> dict:
    return {"number": number, "title": f"issue #{number}", "labels": [{"name": n} for n in labels]}


def test_no_source_label_at_all_is_still_counted_in_severity_totals():
    """Path 1: a hand-filed issue with a severity but no source label."""
    all_open = {"a": _issue(1, ["security", "severity:medium"])}
    body = scan.build_status_body("org/repo", "https://x", all_open)
    assert "| 🟡 MEDIUM | 1 |" in body
    assert "1 of 1 open security issues counted by severity." in body


def test_a_source_outside_the_historical_five_is_counted_and_gets_its_own_row():
    """Path 2: source:pentest is not one of the five hardcoded sources."""
    all_open = {"a": _issue(1, ["security", "severity:critical", "source:pentest"])}
    body = scan.build_status_body("org/repo", "https://x", all_open)
    assert "| 🔴 CRITICAL | 1 |" in body
    assert "2 of 2" not in body  # sanity: only one issue in this fixture
    assert "1 of 1 open security issues counted by severity." in body
    pentest_rows = [l for l in body.splitlines() if l.startswith("| Pentest")]
    assert pentest_rows, f"expected a dynamically-derived 'Pentest' row in:\n{body}"
    assert pentest_rows[0] == "| Pentest | 1 | 0 | 0 | 0 | 0 |"


def test_a_non_canonical_severity_is_not_dropped():
    """Path 3: severity:proposed-high uppercases to PROPOSED-HIGH, not a canonical name."""
    all_open = {"a": _issue(1, ["security", "severity:proposed-high", "source:semgrep"])}
    body = scan.build_status_body("org/repo", "https://x", all_open)
    assert "| ❔ OTHER _(no recognised `severity:` label)_ | 1 |" in body
    assert "0 of 1 open security issues counted by severity." in body
    assert "1 issue(s) could not be matched to a recognised `severity:` label" in body
    # Still attributed to its source, with the OTHER column carrying the count.
    semgrep_rows = [l for l in body.splitlines() if l.startswith("| Semgrep")]
    assert semgrep_rows[0] == "| Semgrep SAST | 0 | 0 | 0 | 0 | 1 |"


def test_multi_label_severity_resolution_is_deterministic_not_a_coin_flip():
    """Path 4: severity:high + severity:accepted-for-release must always resolve HIGH.

    The old code picked whichever `next()` over a `set` produced first, which varied by
    PYTHONHASHSEED. The fix filters to ALLOWED_SEVERITIES before resolving, so the disposition
    label can never win the slot — no seed-dependence to test, just a single deterministic result.
    """
    all_open = {
        "a": _issue(1, ["security", "severity:high", "severity:accepted-for-release", "source:semgrep"])
    }
    body = scan.build_status_body("org/repo", "https://x", all_open)
    assert "| 🟠 HIGH | 1 |" in body
    assert "| ❔ OTHER _(no recognised `severity:` label)_ | 0 |" in body
    assert "1 of 1 open security issues counted by severity." in body


def test_an_issue_with_neither_source_nor_severity_is_still_visible():
    """The issue's explicit ask: feed build_status_body() an issue it cannot attribute at all
    and assert it is still visible somewhere, not silently dropped from every count."""
    all_open = {"a": _issue(1, ["security"])}
    body = scan.build_status_body("org/repo", "https://x", all_open)
    assert "0 of 1 open security issues counted by severity." in body
    assert "1 issue(s) could not be matched to a recognised `severity:` label" in body
    assert "| ❔ OTHER _(no recognised `severity:` label)_ | 1 |" in body
    other_source_rows = [l for l in body.splitlines() if l.startswith("| Other / unattributed")]
    assert other_source_rows[0] == "| Other / unattributed | 0 | 0 | 0 | 0 | 1 |"


def test_fully_attributed_issues_across_known_sources_match_by_hand():
    """Behaviour-preservation control: the historically-supported shape still renders correctly
    and the positive control reports full attribution with no warning."""
    all_open = {
        "a": _issue(1, ["security", "severity:critical", "source:semgrep"]),
        "b": _issue(2, ["security", "severity:high", "source:trivy"]),
        "c": _issue(3, ["security", "severity:high", "source:trivy"]),
        "d": _issue(4, ["security", "severity:medium", "source:gitleaks"]),
    }
    body = scan.build_status_body("org/repo", "https://x", all_open)
    assert "| 🔴 CRITICAL | 1 |" in body
    assert "| 🟠 HIGH | 2 |" in body
    assert "| 🟡 MEDIUM | 1 |" in body
    assert "| 🔵 LOW | 0 |" in body
    assert "| ❔ OTHER _(no recognised `severity:` label)_ | 0 |" in body
    assert "4 of 4 open security issues counted by severity." in body
    assert "could not be matched" not in body
    semgrep_rows = [l for l in body.splitlines() if l.startswith("| Semgrep")]
    assert semgrep_rows[0] == "| Semgrep SAST | 1 | 0 | 0 | 0 | 0 |"
    trivy_rows = [l for l in body.splitlines() if l.startswith("| Trivy")]
    assert trivy_rows[0] == "| Trivy SCA/Container | 0 | 2 | 0 | 0 | 0 |"


def test_truncated_flag_renders_a_distinct_warning():
    all_open = {"a": _issue(1, ["security", "severity:high", "source:semgrep"])}
    body = scan.build_status_body("org/repo", "https://x", all_open, truncated=True)
    assert "hit the API page cap" in body
    not_truncated = scan.build_status_body("org/repo", "https://x", all_open, truncated=False)
    assert "hit the API page cap" not in not_truncated


def test_no_open_issues_renders_a_clean_message_not_an_empty_table():
    body = scan.build_status_body("org/repo", "https://x", {})
    assert "0 of 0 open security issues counted by severity." in body
    assert "could not be matched" not in body
    assert "_No open `security`-labelled issues._" in body
    assert "| Source | CRITICAL |" not in body


# ── Regressions found in review of the fix itself ───────────────────────────────

def test_a_known_source_with_zero_open_issues_still_gets_a_row():
    """A scanner reporting cleanly must read as clean, not vanish the way a scanner that
    didn't run at all would (the same distinction test_autoclose_scope.py draws for
    auto-close). Only `semgrep` has an open issue here; `trivy`/`gitleaks`/etc. must still
    render an explicit all-zero row rather than being absent from the table."""
    all_open = {"a": _issue(1, ["security", "severity:high", "source:semgrep"])}
    body = scan.build_status_body("org/repo", "https://x", all_open)
    trivy_rows = [l for l in body.splitlines() if l.startswith("| Trivy")]
    assert trivy_rows, f"expected an all-zero Trivy row, found none in:\n{body}"
    assert trivy_rows[0] == "| Trivy SCA/Container | 0 | 0 | 0 | 0 | 0 |"
    gitleaks_rows = [l for l in body.splitlines() if l.startswith("| Gitleaks")]
    assert gitleaks_rows[0] == "| Gitleaks _(config repo secret scan)_ | 0 | 0 | 0 | 0 | 0 |"


def test_a_source_label_containing_a_pipe_cannot_break_the_table():
    """A `source:*` label is live, attacker/mislabel-controlled text (anyone with label-write
    access on the repo can set it). Unescaped, a `|` in it would split the rendered row into
    extra Markdown table cells and corrupt every row after it. sanitize() is this file's
    existing discipline for exactly that — see its `|` -> `&#124;` escape, commented
    'prevent Markdown table row injection'."""
    all_open = {"a": _issue(1, ["security", "severity:high", "source:foo|bar"])}
    body = scan.build_status_body("org/repo", "https://x", all_open)
    assert "|bar" not in body
    assert "&#124;" in body
    # The by-source table stays well-formed: every data row has exactly 7 "|" dividers
    # (6 columns: Source, CRITICAL, HIGH, MEDIUM, LOW, OTHER).
    source_section = body.split("### Open findings by source", 1)[1].split("### Quick links", 1)[0]
    row_lines = [
        l for l in source_section.splitlines()
        if l.startswith("|") and l != "| Source | CRITICAL | HIGH | MEDIUM | LOW | OTHER |"
        and not l.startswith("|---")
    ]
    assert row_lines, "expected at least one source-table data row"
    for l in row_lines:
        assert l.count("|") == 7, f"malformed row (expected 7 '|', found {l.count('|')}): {l!r}"


def test_source_label_casing_does_not_split_a_source_into_two_rows():
    """source:Trivy and source:trivy must be the same source, not two separate rows —
    severity labels are already case-normalised (.upper()); source labels must be too."""
    all_open = {
        "a": _issue(1, ["security", "severity:high", "source:trivy"]),
        "b": _issue(2, ["security", "severity:medium", "source:Trivy"]),
    }
    body = scan.build_status_body("org/repo", "https://x", all_open)
    trivy_rows = [l for l in body.splitlines() if l.startswith("| Trivy")]
    assert len(trivy_rows) == 1, f"expected exactly one Trivy row, found {len(trivy_rows)} in:\n{body}"
    assert trivy_rows[0] == "| Trivy SCA/Container | 0 | 1 | 1 | 0 | 0 |"


def test_missing_source_label_renders_its_own_warning_distinct_from_severity():
    """Symmetric with the severity-unattributed warning: an issue with a valid severity but no
    source label must not only be visible in the Other/unattributed row, but also called out by
    a warning line of its own — otherwise an operator scanning only for the severity ⚠️ misses it."""
    all_open = {"a": _issue(1, ["security", "severity:high"])}
    body = scan.build_status_body("org/repo", "https://x", all_open)
    assert "1 of 1 open security issues counted by severity." in body  # severity IS attributed
    assert "could not be matched to a recognised `severity:` label" not in body
    assert "1 issue(s) have no recognised `source:` label" in body
