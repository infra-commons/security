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


# ── A degraded run must not render as a healthy one ────────────────────────────
#
# Three separate paths let a *degraded* run render identically to a clean one, which is the
# same class of fail-open as #96 above: the dashboard is read at a glance, so a number that
# cannot be distinguished from a healthy number IS a false all-clear.
#
#   1. the run writing the dashboard failed           -> `run_degraded`
#   2. a scanner produced no artifact this run        -> `unreported_sources`
#   3. an issue carries a severity but not `security` -> counted, and called out
#
# Every test below asserts BOTH directions — the degraded render differs, and the healthy
# render is untouched — because a banner that fires on the healthy case is one operators
# learn to override, which disarms it just as thoroughly as never firing at all.


def _row(body: str, prefix: str) -> str:
    rows = [l for l in body.splitlines() if l.startswith(prefix)]
    assert rows, f"expected a row starting {prefix!r} in:\n{body}"
    return rows[0]


def _source_rows(body: str) -> list[str]:
    section = body.split("### Open findings by source", 1)[1].split("### Quick links", 1)[0]
    return [
        l for l in section.splitlines()
        if l.startswith("|") and l != "| Source | CRITICAL | HIGH | MEDIUM | LOW | OTHER |"
        and not l.startswith("|---")
    ]


# ── 1. The run that wrote the dashboard failed ─────────────────────────────────

def test_a_degraded_run_says_so_above_the_first_number():
    """Both callers run under `if: always()`, so the dashboard-writing job writes just as
    happily on a run where every scanner job above it failed. The banner has to sit above the
    severity table: a reader who takes only the headline numbers must not be able to miss it."""
    all_open = {"a": _issue(1, ["security", "severity:high", "source:semgrep"])}
    body = scan.build_status_body("org/repo", "https://x", all_open, run_degraded=True)
    lines = body.splitlines()
    banner = [i for i, l in enumerate(lines) if "did not complete cleanly" in l]
    heading = [i for i, l in enumerate(lines) if l == "### Open findings by severity"]
    assert banner, f"no degraded banner rendered in:\n{body}"
    assert banner[0] < heading[0], "the degraded banner renders below the severity table"


def test_a_healthy_run_carries_no_degraded_banner():
    """The other direction, and the reason `run_degraded` defaults to False: a banner on every
    run is worth exactly as much as no banner."""
    all_open = {"a": _issue(1, ["security", "severity:high", "source:semgrep"])}
    for body in (
        scan.build_status_body("org/repo", "https://x", all_open),
        scan.build_status_body("org/repo", "https://x", all_open, run_degraded=False),
    ):
        assert "did not complete cleanly" not in body


def test_the_degraded_banner_is_distinct_from_the_page_cap_warning():
    """Two different degradations, two different sentences — an operator must be able to tell
    'the run broke' from 'the issue list was truncated' without reading the workflow logs."""
    all_open = {"a": _issue(1, ["security", "severity:high", "source:semgrep"])}
    degraded = scan.build_status_body("org/repo", "https://x", all_open, run_degraded=True)
    capped = scan.build_status_body("org/repo", "https://x", all_open, truncated=True)
    assert "hit the API page cap" not in degraded
    assert "did not complete cleanly" not in capped


# ── 2. A scanner that did not report is not a scanner that found nothing ───────

def test_a_scanner_that_did_not_report_is_not_rendered_as_clean():
    """The defect: `run_create_issues` already computes `unreported` and uses it to protect
    auto-close, but never passed it here — so a failed Gitleaks read rendered the same all-zero
    row as a Gitleaks run that scanned cleanly. Zero must not mean both 'nothing found' and
    'nothing measured'."""
    all_open = {"a": _issue(1, ["security", "severity:high", "source:semgrep"])}
    clean = scan.build_status_body("org/repo", "https://x", all_open)
    degraded = scan.build_status_body(
        "org/repo", "https://x", all_open, unreported_sources={"gitleaks"}
    )
    assert _row(clean, "| Gitleaks") != _row(degraded, "| Gitleaks"), (
        "a scanner that produced no artifact renders identically to one that reported clean"
    )
    assert "did not report this run" in _row(degraded, "| Gitleaks")
    assert "1 scanner(s) did not report this run: Gitleaks" in degraded
    assert "not measured" in degraded


def test_a_reporting_scanner_row_is_untouched_when_another_did_not_report():
    """Behaviour-preservation control, and the per-source half of the rule: the marker must land
    on the scanner that failed and on nothing else."""
    all_open = {"a": _issue(1, ["security", "severity:high", "source:semgrep"])}
    clean = scan.build_status_body("org/repo", "https://x", all_open)
    degraded = scan.build_status_body(
        "org/repo", "https://x", all_open, unreported_sources={"gitleaks"}
    )
    assert _row(clean, "| Semgrep") == _row(degraded, "| Semgrep")
    assert "did not report" not in _row(degraded, "| Semgrep")


def test_an_unreported_scanner_with_no_open_issues_still_gets_a_marked_row():
    """The case where the warning matters most: nothing else on the page looks wrong, because
    the scanner has no open issues at all. A source outside the pre-seeded five (it can be any
    string the caller passes) must still be given a row to carry the marker."""
    all_open = {"a": _issue(1, ["security", "severity:high", "source:semgrep"])}
    body = scan.build_status_body(
        "org/repo", "https://x", all_open, unreported_sources={"pentest"}
    )
    row = _row(body, "| Pentest")
    assert "did not report this run" in row
    assert row.count("|") == 7, f"marked row is not a well-formed table row: {row!r}"


def test_no_unreported_sources_renders_no_scanner_warning():
    all_open = {"a": _issue(1, ["security", "severity:high", "source:semgrep"])}
    for kwargs in ({}, {"unreported_sources": set()}, {"unreported_sources": None}):
        body = scan.build_status_body("org/repo", "https://x", all_open, **kwargs)
        assert "did not report this run" not in body


# ── 3. A severity-labelled issue with no `security` label ──────────────────────

def test_an_issue_with_a_severity_but_no_security_label_is_counted_and_flagged():
    """Nothing enforces that a producer applies `security`, so an open severity:high issue can
    be invisible to every `label:security` query — including the dashboard's own. It is counted
    here, and the missing label is named rather than silently absorbed."""
    all_open = {"1": _issue(1, ["severity:high"])}
    body = scan.build_status_body("org/repo", "https://x", all_open)
    assert "| 🟠 HIGH | 1 |" in body
    assert "1 of 1 open security issues counted by severity." in body
    assert "carry a recognised `severity:` label but not `security`" in body
    assert "-label%3Asecurity" in body, "no quick link to the issues missing the label"


def test_a_properly_labelled_issue_does_not_trip_the_missing_label_warning():
    all_open = {"1": _issue(1, ["security", "severity:high", "source:semgrep"])}
    body = scan.build_status_body("org/repo", "https://x", all_open)
    assert "but not `security`" not in body


def test_all_three_degradations_at_once_keep_the_tables_well_formed():
    """They are independent signals and can co-occur — a failed run whose Gitleaks job died and
    whose repo has a mislabelled issue. Each must render, and the Markdown must survive it."""
    all_open = {
        "1": _issue(1, ["security", "severity:high", "source:semgrep"]),
        "2": _issue(2, ["severity:critical"]),
    }
    body = scan.build_status_body(
        "org/repo", "https://x", all_open,
        truncated=True, unreported_sources={"gitleaks"}, run_degraded=True,
    )
    assert "did not complete cleanly" in body
    assert "did not report this run" in body
    assert "but not `security`" in body
    assert "hit the API page cap" in body
    assert "| 🔴 CRITICAL | 1 |" in body and "| 🟠 HIGH | 1 |" in body
    assert "2 of 2 open security issues counted by severity." in body
    for row in _source_rows(body):
        assert row.count("|") == 7, f"malformed row: {row!r}"
