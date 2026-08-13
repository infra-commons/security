"""Tests that the canonical suppressions can actually match a real finding.

Ten of the fourteen entries in `.github/adversarial-review-suppressions.yml` were dead when this
file was written, and because that file is applied fleet-wide, so were they in every consuming
repo. The cause is a contract two files apart: `capture.py`'s reviewer prompt specifies
`"location": "path/to/file:line_number"`, so a finding's location always carries a `:line` (or
`:line-line`) suffix, while those `file_pattern`s ended in a bare `$` and therefore anchored
*before* it.

Nothing caught it for as long as it existed. `suppression-audit.py` classifies entries purely by
`expires:` date, so it audits whether a suppression is still *governed* — never whether it can
still *match*. A suppression file can be 100% expiry-clean and 100% inert at the same time.

Two deliberate choices about how this tests:

  * It imports the **real** `is_suppressed` from `capture.py` rather than reimplementing it. The
    equivalent test in `infra-commons/meta` (`tests/test_suppression_patterns.py`) has to mirror
    the matcher, because the matcher lives here. Here it does not, so there is no test double and
    no divergence risk.
  * The probe paths come from `git ls-files`, not from a hand-written list. A hand-written list
    stops covering an entry the moment the repo moves under it, and does so silently — which is
    the same failure shape as the defect itself.
"""
import importlib.util
import re
import subprocess
from pathlib import Path

import pytest
import yaml

_ACTION_DIR = Path(__file__).resolve().parent
ROOT = _ACTION_DIR.parent.parent.parent
SUPPRESSIONS = ROOT / ".github" / "adversarial-review-suppressions.yml"

# capture.py imports httpx + yaml at module scope and nothing heavier, so importing it here is
# cheap and side-effect free. The filename has no dash, but load it by path anyway so the test
# does not depend on pytest's sys.path insertion for an action directory that has no package.
_spec = importlib.util.spec_from_file_location("capture", _ACTION_DIR / "capture.py")
capture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(capture)

# The suffix shapes the reviewer actually emits. `:1` is included because a single-digit line is
# the case a lazily-written `(:\d\d+)?` style pattern would miss.
LINE_SUFFIXES = [":1", ":42", ":197", ":44-48"]


def _entries():
    data = yaml.safe_load(SUPPRESSIONS.read_text()) or {}
    return data.get("suppressions") or []


def _tracked_files():
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files"], capture_output=True, text=True, check=True
    )
    return [f for f in out.stdout.split("\n") if f]


ENTRIES = _entries()
IDS = [e.get("id", "<no id>") for e in ENTRIES]

# This file is the *canonical* list: it is applied to every repo that calls the reusables, so most
# of its entries target paths that exist only downstream. `.github/workflows/security.yml` is the
# clearest case — this repo publishes the reusable that a consumer's `security.yml` calls, and so
# has no `security.yml` of its own. Probing against tracked files alone would therefore leave the
# entries aimed at consumers entirely unverified, which is the shape of hole that let the defect
# survive in the first place. These are the real caller paths from the fleet's repos.
CONSUMER_PATHS = [
    ".github/workflows/security.yml",
    ".github/workflows/security.yaml",
    ".github/workflows/legal-codebase-audit.yml",
    ".github/workflows/legal-codebase-scan.yml",
    ".github/workflows/legal-review.yml",
    ".github/workflows/ci.yml",
    ".github/adversarial-review-suppressions.yml",
    "src/storage/retention.py",
    "docs/SECURITY-REVIEW.md",
    "scripts/gh-app-token.sh",
    "plans/deploy.sh",
]

TRACKED = _tracked_files()
PROBE_PATHS = TRACKED + CONSUMER_PATHS


def test_suppressions_file_is_non_empty():
    """A silently empty file suppresses nothing while still reading as coverage."""
    assert ENTRIES, f"no suppressions parsed from {SUPPRESSIONS}"


def test_tracked_file_list_is_non_empty():
    """Guards the guard: an empty probe corpus would make every check below vacuously pass."""
    assert TRACKED, "git ls-files returned nothing — the suffix checks would prove nothing"


@pytest.mark.parametrize("entry", ENTRIES, ids=IDS)
def test_entry_has_the_fields_the_matcher_requires(entry):
    """`is_suppressed` skips an entry missing either pattern — silently, via `continue`."""
    for key in ("id", "file_pattern", "finding_pattern", "reason"):
        assert entry.get(key), f"{entry.get('id', '?')}: missing or empty {key}"


@pytest.mark.parametrize("entry", ENTRIES, ids=IDS)
def test_patterns_compile(entry):
    """A malformed regex is FAIL-OPEN: `is_suppressed` catches `re.error` and moves on.

    The entry stays in the file, reads as active, and suppresses nothing — the same end state as
    the bare-`$` defect, reached by a different route.
    """
    for key in ("file_pattern", "finding_pattern"):
        try:
            re.compile(entry[key])
        except re.error as exc:
            pytest.fail(
                f"{entry.get('id')}: {key} does not compile ({exc}) — capture.py would skip "
                f"this entry silently"
            )
    if entry.get("category_pattern"):
        try:
            re.compile(entry["category_pattern"])
        except re.error as exc:
            pytest.fail(
                f"{entry.get('id')}: category_pattern does not compile ({exc}) — capture.py "
                f"would skip this entry silently"
            )


@pytest.mark.parametrize("entry", ENTRIES, ids=IDS)
def test_file_pattern_is_not_blind_to_the_line_suffix(entry):
    """The defect this file exists for, proven against real paths.

    For every path an entry's `file_pattern` matches, the same path carrying a line suffix must
    match too — that suffixed form is the only shape a real finding ever has.

    Probes are this repo's tracked files plus `CONSUMER_PATHS`, because a canonical entry aimed at
    a downstream caller has no tracked file here to prove it against.
    """
    pat = entry["file_pattern"]
    matched = [f for f in PROBE_PATHS if re.search(pat, f, re.IGNORECASE)]
    if not matched:
        pytest.skip(f"{entry.get('id')}: matches no probe path")
    for path in matched[:40]:
        for suffix in LINE_SUFFIXES:
            assert re.search(pat, path + suffix, re.IGNORECASE), (
                f"{entry.get('id')}: matches {path!r} but NOT {path + suffix!r}. Real findings "
                f"always carry the suffix (capture.py's prompt contract), so this entry is dead. "
                f"End the pattern with '(:\\d+(-\\d+)?)?$' instead of a bare '$'."
            )


def test_every_anchored_entry_was_actually_proven():
    """Every entry that *could* have the defect must be one the check above actually ran on.

    Only an anchored pattern can be line-suffix-blind: `re.search` is unanchored on the right, so
    trailing text is harmless unless a `$` (or `\\Z`) forbids it. So each anchored entry needs at
    least one matching probe path — otherwise the parametrised test above *skipped* it and proved
    nothing, while the suite still reported green. A skip that nobody counts is how this defect
    survived being 'covered' before, so it is counted here.
    """
    unproven = [
        e.get("id")
        for e in ENTRIES
        if ("$" in e.get("file_pattern", "") or "\\Z" in e.get("file_pattern", ""))
        and not any(re.search(e["file_pattern"], f, re.IGNORECASE) for f in PROBE_PATHS)
    ]
    assert not unproven, (
        f"anchored patterns matching no probe path, so the suffix check skipped them and they are "
        f"unverified: {unproven}. Add a representative path to CONSUMER_PATHS, or unanchor them."
    )


# ── End-to-end through the real matcher ───────────────────────────────────────────────────────
# The checks above test the file_pattern in isolation. These drive capture.is_suppressed with
# findings shaped exactly as the reviewer emits them, so a regression anywhere in the matching
# path — not just in the anchor — is caught.

SUPPRESSED_FINDINGS = [
    (
        "sha-pin-first-party-workflows",
        {
            "location": ".github/workflows/tier-a.yml:12",
            "title": "Reusable workflow pinned to an external org commit hash",
            "description": "The workflow references infra-commons/security at a commit hash "
            "without code visibility into that repository.",
        },
    ),
    (
        "security-push-trigger-intentional",
        {
            "location": ".github/workflows/security.yml:7",
            "title": "Workflow push trigger runs on all branches",
            "description": "`push: {}` triggers all branch pushes including forks.",
        },
    ),
    (
        "suppression-file-governed-by-audit",
        {
            "location": ".github/adversarial-review-suppressions.yml:20",
            "title": "Self-authored suppression removes the human oversight gate",
            "description": "An AI agent can suppress its own findings by adding an entry here.",
        },
    ),
    (
        "first-party-reusable-sha-bump",
        # Deliberately worded to avoid "external"/"third-party"/"untrusted": `is_suppressed`
        # returns the FIRST entry that matches, and `first-party-reusable-workflow-trust` sits
        # earlier in the file and catches any of those words. Both would suppress the finding, so
        # a wording that hits both is not a defect — it just makes the reported id ambiguous, and
        # an ambiguous expectation is not a test.
        {
            "location": ".github/workflows/tier-b.yml:31",
            "title": "Reusable workflow SHA bump not documented",
            "description": "The pinned SHA bump for a reusable landed without documented review.",
        },
    ),
]


@pytest.mark.parametrize("expected_id,finding", SUPPRESSED_FINDINGS,
                         ids=[c[0] for c in SUPPRESSED_FINDINGS])
def test_representative_findings_are_suppressed(expected_id, finding):
    hit, sup_id = capture.is_suppressed(finding, ENTRIES)
    assert hit and sup_id == expected_id, (
        f"expected {expected_id!r} to suppress this finding; got {sup_id!r}"
    )


# ── Negative controls ─────────────────────────────────────────────────────────────────────────
# A suppression that swallows more than its class is worse than none, because it reads as
# coverage. Widening the anchors must not have widened what they catch.

NOT_SUPPRESSED = [
    (
        "a real secret committed in a workflow",
        {
            "location": ".github/workflows/tier-a.yml:20",
            "title": "Hardcoded API key committed to repository",
            "description": "A literal Anthropic API key is assigned to ANTHROPIC_API_KEY in the "
            "workflow and committed. Anyone with read access can use it directly.",
        },
    ),
    (
        "command injection in a workflow run block",
        {
            "location": ".github/workflows/tier-b.yml:44",
            "title": "Untrusted event payload interpolated into a run block",
            "description": "github.event.pull_request.title is spliced into a bash run: step, so "
            "a crafted PR title executes arbitrary commands on the runner.",
        },
    ),
    (
        "the SHA-pin finding shape in a file outside the claimed scope",
        {
            "location": "pentest/run.py:12",
            "title": "Dependency pinned to an external org commit hash",
            "description": "Unpinned external reusable referenced without code visibility.",
        },
    ),
    (
        "an unsuffixed location, which the reviewer never emits",
        # Not a regression if this changes — it documents that the widened anchor is optional,
        # so the entry still matches if the contract is ever relaxed to a bare path.
        {
            "location": ".github/workflows/tier-a.yml",
            "title": "Hardcoded API key committed to repository",
            "description": "A literal key was committed.",
        },
    ),
]


@pytest.mark.parametrize("why,finding", NOT_SUPPRESSED, ids=[c[0] for c in NOT_SUPPRESSED])
def test_findings_outside_the_class_are_not_suppressed(why, finding):
    hit, sup_id = capture.is_suppressed(finding, ENTRIES)
    assert not hit, f"{why!r} was wrongly suppressed by {sup_id!r}"


# ── category_pattern as a structural anchor (infra-commons/meta#678) ─────────────────────────
# #197's suppression required `(wildcard|patterns_allowed)` within an 80-char window of a
# qualifying phrase; its recurrence #611 — same underlying finding, reworded — put the nearest
# qualifying phrase ~180 chars away and was filed live instead of suppressed. #679 fixed that one
# entry by widening its window. These three cases test the general lever instead: `category` is
# stable across the same rewording (#197 and #611 were both classified `dependency`), so it can
# anchor a suppression that doesn't need a proximity window at all.
#
# Text is #611's real, verbatim, sanitized title+description — the same constants recorded in
# infra-commons/meta's tests/test_suppression_patterns.py (META_611_TITLE/META_611_DESC) — not a
# paraphrase. The "@" characters render as fullwidth "＠": capture.py's sanitize() replaces "@"
# before is_suppressed() ever sees the text (parse_findings order), so a real finding never
# carries a literal "@" by the time it reaches the matcher.

META_611_TITLE = (
    "Wildcard version pin on third-party org action allows any future tag/SHA to run in CI"
)
META_611_DESC = (
    "The pattern 'rolliq-com/platform-iac＠*' permits any tag, branch, or commit SHA from that "
    "repository to execute in CI workflows. If rolliq-com/platform-iac is compromised, has a "
    "supply-chain incident, or if a malicious collaborator pushes a new tag, the wildcard means "
    "the malicious code will automatically be trusted and executed in pipeline runs—including "
    "deployments to Azure environments. The risk is amplified because (1) this action runs at "
    "build time inside azure-deploy-reusable.yml which has Azure credentials in scope, and (2) "
    "the wildcard bypasses the otherwise SHA-pinning discipline expected of a financial-document "
    "SaaS CI/CD pipeline. A SHA pin or at minimum a tag-locked pattern (e.g. ＠v1) would bound "
    "the exposure."
)
META_611_FINDING = {
    "location": "devops-manifest.yaml:479",
    "title": META_611_TITLE,
    "description": META_611_DESC,
    "category": "dependency",
}

# The exact pre-#679 pattern (infra-commons/meta commit 455c827, entry
# org-actions-policy-wildcard-is-a-repo-allowlist-not-a-version-pin) — a synthetic, standalone
# entry here, not read from either live suppressions file.
PRE_679_PATTERN = (
    r"(wildcard|patterns_allowed).{0,80}"
    r"(no version pinning|any version|malicious.{0,20}(version|tag|release))"
)


def test_pre_679_window_pattern_missed_the_real_611_recurrence():
    """Reproduces the measured defect against the real matcher, not a description of it."""
    entry = {
        "id": "pre-679-synthetic",
        "file_pattern": r"devops-manifest\.yaml(:\d+(-\d+)?)?$",
        "finding_pattern": PRE_679_PATTERN,
    }
    hit, sup_id = capture.is_suppressed(META_611_FINDING, [entry])
    assert not hit, (
        f"expected the pre-#679 window pattern to miss #611's real text (that's the recorded "
        f"defect); it matched via {sup_id!r} instead — the reproduction is wrong"
    )


def test_category_pattern_catches_the_recurrence_with_no_proximity_window():
    """A loose, single-word finding_pattern, safe only because category_pattern anchors it."""
    entry = {
        "id": "category-anchored-synthetic",
        "file_pattern": r"devops-manifest\.yaml(:\d+(-\d+)?)?$",
        "category_pattern": "dependency",
        "finding_pattern": "wildcard",
    }
    hit, sup_id = capture.is_suppressed(META_611_FINDING, [entry])
    assert hit and sup_id == "category-anchored-synthetic"


def test_category_pattern_foil_a_different_class_sharing_file_and_trigger_word():
    """Must NOT be caught — the too-broad direction of error.

    Same file, same trigger word ("wildcard"), but a genuinely different, must-surface finding:
    a hardcoded private-key path for a *.rolliq.com WILDCARD TLS certificate, classified
    `secrets`. A bare `finding_pattern: "wildcard"` is only safe to write because
    `category_pattern` excludes this — proving the anchor actually discriminates, not just that
    it's present.
    """
    foil = {
        "location": "devops-manifest.yaml:88",
        "title": "Wildcard-scoped TLS certificate private key path committed in devops-manifest.yaml",
        "description": "A private key file path for the *.rolliq.com wildcard TLS certificate is "
        "hardcoded in devops-manifest.yaml's `deploy.tls_key_path` field, exposing the "
        "certificate's on-disk location to anyone with read access to this repository.",
        "category": "secrets",
    }
    entry = {
        "id": "category-anchored-synthetic",
        "file_pattern": r"devops-manifest\.yaml(:\d+(-\d+)?)?$",
        "category_pattern": "dependency",
        "finding_pattern": "wildcard",
    }
    hit, sup_id = capture.is_suppressed(foil, [entry])
    assert not hit, f"foil (category=secrets) was wrongly suppressed by {sup_id!r}"


def test_category_pattern_is_a_no_op_for_every_live_entry():
    """The too-narrow direction: no entry in the canonical file sets category_pattern today.

    So the new pre-filter can only ever be inert for the file as it stands — this is the
    regression proof that adding the field didn't change any existing entry's behaviour. If this
    ever fails, some entry started using category_pattern and belongs under its own targeted test
    instead of relying on this blanket absence check.
    """
    assert not any(e.get("category_pattern") for e in ENTRIES), (
        "an entry now sets category_pattern — add a dedicated test for it and update/drop this "
        "one rather than deleting the coverage"
    )
