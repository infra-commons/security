"""Repo-wide negative control: every file that opens a GitHub issue also puts it on a board.

infra-commons/meta#1656. An issue that is not on its org's Project board is invisible to every
dispatch surface — the consoles' Inbox->Doing drain, /blocked, /doing-watch. The cashbucket lane
censused itself on 2026-09-28 and found 68 open issues off its board, a large share of them
filed by this repo's reusables, which every entity org consumes.

The mechanism is `.github/actions/capture-findings/board_intake.py` (#661's add_to_board,
extracted). This test does not check that a filer calls it correctly — each filer's own tests do
that. It checks the property that let the leak grow unseen: a NEW filer could arrive with no
board-add and nothing would say so. Now it fails here instead.

`PENDING` is the leak that is known and not yet closed, named file by file. It may only shrink:
an entry whose file has since been wired (or no longer files) fails too, so the list cannot go
stale and overstate the gap.
"""
import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_ROOTS = (".github/actions", ".github/workflows", "pentest", "dast")

# Every issue-create idiom this repo uses: `gh issue create` from bash, `_gh("issue", "create",`
# from Python, and a REST `create_issue` helper.
_CREATES_AN_ISSUE = re.compile(r'gh issue create|"issue",\s*"create"|def create_issue\(')
_BOARDS_IT = re.compile(r"board_intake|board-intake")

# Filers not yet wired (infra-commons/meta#1656, split across follow-up PRs for size).
PENDING = {
    ".github/workflows/adversarial-review-reusable.yml",  # quota / degraded-pass / critical notices
    ".github/actions/weekly-security-scan/security-scan.py",
    ".github/actions/suppression-audit/suppression-audit.py",
    ".github/actions/daily-health-check/health-check.py",
    "pentest/triage.py",
    "dast/triage.py",
}


def _filers():
    found = set()
    for root in _ROOTS:
        for path in (_REPO / root).rglob("*"):
            if path.suffix not in {".py", ".yml", ".yaml", ".sh"} or not path.is_file():
                continue
            if path.name.startswith("test_") or "tests" in path.parts or "__pycache__" in path.parts:
                continue
            if _CREATES_AN_ISSUE.search(path.read_text(encoding="utf-8", errors="replace")):
                found.add(path.relative_to(_REPO).as_posix())
    return found


def test_the_scan_finds_the_known_filers():
    # A scan that found nothing would pass everything below vacuously.
    assert ".github/actions/capture-findings/capture.py" in _filers()
    assert len(_filers()) >= 7


@pytest.mark.parametrize("rel", sorted(_filers() - PENDING))
def test_every_filer_boards_what_it_files(rel):
    text = (_REPO / rel).read_text(encoding="utf-8")
    assert _BOARDS_IT.search(text), (
        f"{rel} opens GitHub issues but never board-adds them. Board each issue it files via "
        "capture-findings/board_intake.py (board_issue + report) so it lands at Status Inbox "
        "(infra-commons/meta#1656)."
    )


@pytest.mark.parametrize("rel", sorted(PENDING))
def test_pending_entries_are_still_real_gaps(rel):
    path = _REPO / rel
    assert path.is_file() and rel in _filers(), f"{rel} no longer files issues — drop it from PENDING"
    assert not _BOARDS_IT.search(path.read_text(encoding="utf-8")), (
        f"{rel} now board-adds — drop it from PENDING"
    )
