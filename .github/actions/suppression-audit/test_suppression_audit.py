"""Tests for the audit's match check — can each suppression still do its job?

The audit already answered "is this suppression still governed?" (an `expires:` date). It could
not answer "can this suppression still match?", and that is where the damage was: ten of the
fourteen canonical entries had been inert since they were written, and the audit reported them
clean throughout. A file can be 100% expiry-clean and 100% inert at the same time.

The check under test is behavioural — it probes each pattern against the repo's real tracked
files — so these tests are too. Each drives `find_dead_entries` with the pattern shapes that
appear in the real files, plus the shapes that would make the check itself fail open.
"""
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

_MODULE_PATH = Path(__file__).resolve().parent / "suppression-audit.py"
_spec = importlib.util.spec_from_file_location("suppression_audit", _MODULE_PATH)
audit = importlib.util.module_from_spec(_spec)
sys.modules["suppression_audit"] = audit
_spec.loader.exec_module(audit)


PATHS = [
    ".github/workflows/security.yml",
    ".github/workflows/ci.yaml",
    ".github/adversarial-review-suppressions.yml",
    "scripts/deploy.sh",
    "src/storage/retention.py",
]


def entry(pattern, eid="e"):
    return {"id": eid, "file_pattern": pattern, "finding_pattern": "anything"}


def ids_of(entries):
    return [e["id"] for e in entries]


# ── The defect the check exists to catch ──────────────────────────────────────────────────────

def test_bare_dollar_anchor_is_dead():
    """The exact shape that made 10 of 14 canonical entries inert."""
    dead, unverified = audit.find_dead_entries(
        [entry(r".*\.github/workflows/.*\.ya?ml$", "bare-dollar")], PATHS
    )
    assert ids_of(dead) == ["bare-dollar"]
    assert not unverified


def test_the_evidence_names_the_probe_path_and_the_failing_suffix():
    """A finding nobody can act on is close to no finding. The report has to be specific."""
    dead, _ = audit.find_dead_entries([entry(r"scripts/.*\.sh$", "e")], PATHS)
    why = dead[0]["_why"]
    assert "scripts/deploy.sh" in why, why
    assert ":1" in why, why


def test_the_corrected_idiom_is_not_flagged():
    """The fix must actually clear the check, or the check is unusable."""
    dead, unverified = audit.find_dead_entries(
        [entry(r".*\.github/workflows/.*\.ya?ml(:\d+(-\d+)?)?$", "fixed")], PATHS
    )
    assert not dead
    assert not unverified


def test_a_pattern_handling_single_lines_but_not_ranges_is_still_dead():
    """`(:\\d+)?$` reads as fixed and is blind to every `file.sh:44-48` finding.

    This shape is live in legal-review-suppressions.yml, so the check is not merely
    theoretical here — half-fixed has to fail, or the half that is still broken never surfaces.
    """
    dead, _ = audit.find_dead_entries(
        [entry(r".*\.github/workflows/.*\.ya?ml(:\d+)?$", "half-fixed")], PATHS
    )
    assert ids_of(dead) == ["half-fixed"]
    assert ":10-20" in dead[0]["_why"]


# ── Not-dead: the check must not cry wolf ─────────────────────────────────────────────────────

def test_an_unanchored_pattern_is_structurally_immune_and_not_probed():
    """`re.search` is unanchored on the right, so trailing text cannot break the match."""
    dead, unverified = audit.find_dead_entries(
        [entry(r"src/storage/retention\.py", "unanchored")], PATHS
    )
    assert not dead
    assert not unverified


def test_an_anchored_pattern_with_no_matching_file_is_unverified_not_dead():
    """The canonical file is fleet-wide, so it carries entries for paths that exist downstream.

    Failing those would make the audit wrong on healthy input in most repos it runs in, which
    trains the override just as effectively as being silently absent.
    """
    dead, unverified = audit.find_dead_entries(
        [entry(r"app/models/user\.rb$", "downstream-only")], PATHS
    )
    assert not dead
    assert ids_of(unverified) == ["downstream-only"]


def test_an_entry_without_a_file_pattern_is_skipped_not_crashed():
    dead, unverified = audit.find_dead_entries([{"id": "no-pattern"}], PATHS)
    assert not dead and not unverified


# ── A pattern that cannot compile is inert by a different route ───────────────────────────────

def test_an_uncompilable_pattern_is_dead():
    """`is_suppressed` catches `re.error` and moves on, so the entry silently does nothing.

    Same end state as the anchor defect — an entry that reads as active and suppresses
    nothing — so it belongs in the same bucket rather than passing quietly.
    """
    dead, _ = audit.find_dead_entries([entry(r"unclosed(group$", "bad-regex")], PATHS)
    assert ids_of(dead) == ["bad-regex"]
    assert "does not compile" in dead[0]["_why"]


# ── Guarding the guard ────────────────────────────────────────────────────────────────────────

def test_no_probe_paths_yields_unverified_not_a_clean_pass():
    """With nothing to probe against, every anchored entry must read as UNTESTED.

    The tempting implementation returns "no dead entries found" here, which is a false all-clear
    from a check that ran on nothing — the precise failure this whole change exists to remove.
    """
    dead, unverified = audit.find_dead_entries(
        [entry(r".*\.github/workflows/.*\.ya?ml$", "would-be-dead")], []
    )
    assert not dead
    assert ids_of(unverified) == ["would-be-dead"]


def test_probe_paths_reads_real_tracked_files():
    """The probe corpus must be real, or every behavioural assertion above is theatre."""
    paths = audit.probe_paths()
    assert paths, "git ls-files returned nothing in the repo work tree"
    assert ".github/adversarial-review-suppressions.yml" in paths


def test_probe_paths_returns_empty_when_git_fails(monkeypatch):
    """Not a work tree / no git → report unverified, never a silent all-clear."""
    def boom(*a, **kw):
        raise OSError("git not found")
    monkeypatch.setattr(audit.subprocess, "run", boom)
    assert audit.probe_paths() == []


def test_probe_paths_returns_empty_on_nonzero_exit(monkeypatch):
    """A failed `git ls-files` must yield NO corpus, even when it printed some of one.

    Deliberately non-empty stdout: with `stdout=""` this test passes whether or not the exit
    status is checked at all, so it would prove nothing. A mutant that ignored the return code
    survived exactly that version of this test. Partial output is also the realistic shape — a
    truncated listing read as complete is a corpus that silently under-covers, which turns the
    match check into a quiet all-clear.
    """
    monkeypatch.setattr(
        audit.subprocess, "run",
        lambda *a, **kw: subprocess.CompletedProcess(
            a, 128, stdout="README.md\npentest/run.py\n", stderr="fatal: not a git repository"
        ),
    )
    assert audit.probe_paths() == []


# ── This repo's own canonical file ────────────────────────────────────────────────────────────

def test_this_repos_canonical_suppressions_are_all_live():
    """The audit run this change would produce here, asserted directly.

    Fails on the pre-fix file (ten dead entries) and passes on the fixed one, so it is the
    regression test for the data as well as for the checker.
    """
    dead, _ = audit.find_dead_entries(audit.load_suppressions(), audit.probe_paths())
    assert not dead, (
        "canonical suppressions that cannot match a finding: "
        + ", ".join(f"{s['id']} ({s['_why']})" for s in dead)
    )


# ── Report rendering ──────────────────────────────────────────────────────────────────────────

def test_dead_entries_reach_the_issue_body_with_the_fix_spelled_out():
    body = audit.build_body([], [], "http://run", dead=[entry("x$", "dead-one") | {"_why": "w"}])
    assert "Dead — cannot match any finding (1)" in body
    assert "dead-one" in body
    assert r"(:\d+(-\d+)?)?$" in body, "the report must name the fix, not just the fault"


def test_a_clean_run_renders_no_dead_section():
    body = audit.build_body([], [], "http://run", dead=[], unverified=[])
    assert "Dead" not in body


def test_build_body_is_backward_compatible_with_two_positional_args():
    """The expiry-only call shape still works — nothing else in the action passes the new args."""
    assert "Suppression expiry audit" in audit.build_body([], [], "http://run")


# ── Exit contract ─────────────────────────────────────────────────────────────────────────────

def test_main_exits_2_when_an_entry_is_dead(monkeypatch, capsys):
    """The contract change: a proven-dead entry makes the run red.

    Guarded here because the whole point is that a dead entry surfaces *nowhere else* — if this
    silently reverted to exit 0, the class would go back to being invisible.
    """
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("REPO", "o/r")
    monkeypatch.setattr(audit, "load_and_classify", lambda: ([], [], []))
    monkeypatch.setattr(audit, "load_suppressions", lambda: [entry(r"scripts/.*\.sh$", "d")])
    monkeypatch.setattr(audit, "probe_paths", lambda: PATHS)
    monkeypatch.setattr(audit, "find_existing_issue", lambda *a: None)
    monkeypatch.setattr(audit, "find_closed_issue", lambda *a: None)
    monkeypatch.setattr(audit, "create_issue", lambda *a: 1)
    with pytest.raises(SystemExit) as exc:
        audit.main()
    assert exc.value.code == 2


def test_main_exits_0_when_only_expiry_findings_exist(monkeypatch):
    """Expiry stays informational — it already surfaces in PR reviews on its own."""
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("REPO", "o/r")
    expired = [{"id": "old", "_expires": "2020-01-01", "_days_left": -99, "reason": "r."}]
    monkeypatch.setattr(audit, "load_and_classify", lambda: (expired, [], []))
    monkeypatch.setattr(audit, "load_suppressions", list)
    monkeypatch.setattr(audit, "probe_paths", lambda: PATHS)
    monkeypatch.setattr(audit, "find_existing_issue", lambda *a: None)
    monkeypatch.setattr(audit, "find_closed_issue", lambda *a: None)
    monkeypatch.setattr(audit, "create_issue", lambda *a: 1)
    audit.main()  # must not raise SystemExit


def test_main_exits_0_on_a_fully_clean_run(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("REPO", "o/r")
    monkeypatch.setattr(audit, "load_and_classify", lambda: ([], [], []))
    monkeypatch.setattr(audit, "load_suppressions", list)
    monkeypatch.setattr(audit, "probe_paths", lambda: PATHS)
    monkeypatch.setattr(audit, "find_existing_issue", lambda *a: None)
    audit.main()
