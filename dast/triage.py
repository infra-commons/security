#!/usr/bin/env python3
"""Triage Nuclei DAST findings: apply suppressions and file / close GitHub Issues.

Usage:
    python3 scripts/dast-triage.py \
        --findings /path/to/nuclei-all.jsonl \
        --suppressions .github/dast-suppressions.yml \
        --repo rolliq-com/solution-recruitment-reference-check \
        --run-url https://github.com/rolliq-com/.../actions/runs/12345

Exit codes:
    0  — triage complete (issues filed or none needed)
    1  — fatal error (bad arguments, unreadable files)

Environment:
    GH_TOKEN  — GitHub token with issues:write (injected by GitHub Actions)

The script uses the `gh` CLI for all GitHub operations so it requires no
additional Python dependencies beyond the stdlib + PyYAML.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("Error: PyYAML not installed. Run: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


# GitHub Issue label names — must exist in the repo before issues are filed.
_LABEL_SECURITY = "security"
_LABEL_SOURCE = "source:dast"


def _sanitise(text: str, max_len: int = 2000) -> str:
    """Strip control characters and truncate Nuclei-sourced strings.

    gh CLI calls use an args list (not shell=True) so there is no shell injection
    risk. This function addresses the residual concern of misleading content in
    GitHub issue bodies from crafted server responses (closes #90):
    - Removes null bytes and non-printable control characters (preserving \\n, \\t).
    - Truncates to max_len to prevent oversized issue bodies.
    """
    # Remove control chars except newline (0x0A) and tab (0x09).
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    return text[:max_len].rstrip()
_SEVERITY_LABELS = {
    "critical": "severity:critical",
    "high":     "severity:high",
    "medium":   "severity:medium",
    "low":      "severity:low",
    "info":     "severity:low",
    "unknown":  "severity:low",
}


# ── Suppression loading ────────────────────────────────────────────────────────

def load_suppressions(path: str) -> list[dict]:
    p = Path(path)
    if not p.exists():
        print(f"Warning: suppression file {path!r} not found — no suppressions applied.",
              file=sys.stderr)
        return []
    data = yaml.safe_load(p.read_text()) or {}
    return data.get("suppressions", [])


def is_suppressed(finding: dict, suppressions: list[dict]) -> tuple[bool, str]:
    """Return (suppressed, suppression_id) for the given finding."""
    template_id = finding.get("template-id", "")
    info_name   = finding.get("info", {}).get("name", "")
    full_text   = f"{template_id} {info_name}".lower()

    today = _today_str()

    for sup in suppressions:
        # Check expiry.
        expires = sup.get("expires", "")
        if expires and expires < today:
            continue  # expired suppression — treat as inactive

        tid_pat = sup.get("template_id_pattern", "")
        if tid_pat and not re.search(tid_pat, template_id, re.IGNORECASE):
            continue

        info_pat = sup.get("info_pattern", "")
        if info_pat and not re.search(info_pat, full_text, re.IGNORECASE):
            continue

        return True, sup.get("id", "unknown")

    return False, ""


def _today_str() -> str:
    from datetime import date
    return date.today().isoformat()


# ── Finding normalisation ──────────────────────────────────────────────────────

def parse_findings(path: str) -> list[dict]:
    """Parse a Nuclei JSONL file into a list of finding dicts."""
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return []

    findings = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError as exc:
            print(f"Warning: could not parse line: {exc}", file=sys.stderr)
    return findings


def issue_title(finding: dict) -> str:
    """Derive a stable, human-readable issue title from a Nuclei finding."""
    severity   = finding.get("info", {}).get("severity", "unknown").upper()
    name       = _sanitise(
        finding.get("info", {}).get("name", finding.get("template-id", "unknown")),
        max_len=120,
    )
    matched_at = finding.get("matched-at", "")

    # Strip the target base URL — keep only the path component.
    path = _sanitise(re.sub(r"^https?://[^/]+", "", matched_at) or "/", max_len=100)

    return f"[Security][dast][{severity}] {name} — {path}"


def issue_body(finding: dict, run_url: str) -> str:
    severity    = finding.get("info", {}).get("severity", "unknown")
    name        = _sanitise(finding.get("info", {}).get("name", ""), max_len=200)
    template_id = _sanitise(finding.get("template-id", ""), max_len=100)
    matched_at  = _sanitise(finding.get("matched-at", ""), max_len=500)
    description = _sanitise(finding.get("info", {}).get("description", ""))
    remediation = _sanitise(finding.get("info", {}).get("remediation", ""))
    references  = finding.get("info", {}).get("reference", [])

    # Only include HTTPS reference URLs to prevent javascript:/data: injection.
    safe_refs = [r for r in (references or [])
                 if isinstance(r, str) and r.startswith("https://") and " " not in r]
    ref_lines = "\n".join(f"- {r[:500]}" for r in safe_refs)

    return (
        f"## {severity.upper()} severity DAST finding\n\n"
        f"**Template:** `{template_id}`\n"
        f"**Finding:** {name}\n"
        f"**Matched at:** `{matched_at}`\n"
        f"**Source:** `nuclei` (weekly DAST scan)\n\n"
        + (f"### Description\n\n{description}\n\n" if description else "")
        + (f"### Remediation\n\n{remediation}\n\n" if remediation else "")
        + (f"### References\n\n{ref_lines}\n\n" if ref_lines else "")
        + f"---\n"
          f"_Captured by the [DAST scan workflow]({run_url})._\n"
          f"_Close this issue when the finding is fixed, or add an entry to "
          f"`.github/dast-suppressions.yml` if it is a false positive._"
    )


# ── GitHub Issue operations (via gh CLI) ───────────────────────────────────────

def _gh(*args: str) -> str:
    result = subprocess.run(
        ["gh"] + list(args),
        capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


def ensure_labels(repo: str) -> None:
    """Create missing labels without failing if they already exist."""
    needed = {
        _LABEL_SECURITY:  ("d93f0b", "All security findings"),
        _LABEL_SOURCE:    ("1d76db", "DAST (Nuclei) scan finding"),
        "severity:critical": ("b60205", "Exploit-ready — must fix immediately"),
        "severity:high":     ("e11d48", "Serious — fix before next deploy"),
        "severity:medium":   ("f97316", "Fix within 90 days"),
        "severity:low":      ("e0e0e0", "Best-practice improvement"),
    }
    existing_raw = subprocess.run(
        ["gh", "label", "list", "--repo", repo, "--json", "name", "--limit", "200"],
        capture_output=True, text=True,
    ).stdout
    existing = {item["name"] for item in json.loads(existing_raw or "[]")}

    for name, (color, desc) in needed.items():
        if name not in existing:
            subprocess.run(
                ["gh", "label", "create", name,
                 "--repo", repo,
                 "--color", color,
                 "--description", desc],
                capture_output=True,
            )


def list_open_dast_issues(repo: str) -> dict[str, int]:
    """Return {title: issue_number} for all open DAST issues."""
    raw = subprocess.run(
        ["gh", "issue", "list",
         "--repo", repo,
         "--label", _LABEL_SOURCE,
         "--state", "open",
         "--json", "number,title",
         "--limit", "500"],
        capture_output=True, text=True,
    ).stdout
    items = json.loads(raw or "[]")
    return {item["title"]: item["number"] for item in items}


def create_issue(repo: str, title: str, body: str, severity: str) -> int:
    # `gh issue create` has never supported --json (unlike `list`/`view`) — it prints
    # the created issue's URL as plain text on success. Parse the number from that.
    severity_label = _SEVERITY_LABELS.get(severity.lower(), "severity:low")
    url = _gh(
        "issue", "create",
        "--repo", repo,
        "--title", title,
        "--body", body,
        "--label", _LABEL_SECURITY,
        "--label", _LABEL_SOURCE,
        "--label", severity_label,
    )
    return _issue_number_from_url(url)


def _issue_number_from_url(url: str) -> int:
    """Extract the trailing issue number from a `gh issue create` URL, e.g.
    'https://github.com/o/r/issues/123' -> 123. Returns 0 if the shape is unexpected.
    """
    try:
        return int(url.strip().rstrip("/").rsplit("/", 1)[-1])
    except (ValueError, IndexError):
        return 0


def close_issue(repo: str, number: int, reason: str) -> None:
    _gh(
        "issue", "close", str(number),
        "--repo", repo,
        "--comment", reason,
    )


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Triage Nuclei DAST findings.")
    parser.add_argument("--findings",     required=True, help="Path to Nuclei JSONL output")
    parser.add_argument("--suppressions", required=True, help="Path to dast-suppressions.yml")
    parser.add_argument("--repo",         required=True, help="GitHub repo (owner/name)")
    parser.add_argument("--run-url",      required=True, help="URL of the Actions run")
    args = parser.parse_args()

    findings     = parse_findings(args.findings)
    suppressions = load_suppressions(args.suppressions)

    print(f"Parsed {len(findings)} finding(s) from Nuclei output.")

    # Deduplicate by template_id + matched_at to avoid filing identical issues.
    seen: set[str] = set()
    unique: list[dict] = []
    for f in findings:
        key = f"{f.get('template-id', '')}:{f.get('matched-at', '')}"
        if key not in seen:
            seen.add(key)
            unique.append(f)

    print(f"Unique findings after dedup: {len(unique)}")

    # Partition into suppressed and active.
    active: list[dict] = []
    suppressed_count = 0
    for f in unique:
        ok, sup_id = is_suppressed(f, suppressions)
        if ok:
            print(f"  SUPPRESSED [{sup_id}]: {f.get('template-id')} — {f.get('info', {}).get('name')}")
            suppressed_count += 1
        else:
            active.append(f)

    print(f"Active (non-suppressed) findings: {len(active)} | Suppressed: {suppressed_count}")

    if not active and len(unique) == 0:
        print("No findings — nothing to do.")
        return

    # Ensure all required labels exist.
    ensure_labels(args.repo)

    # Load existing open DAST issues.
    open_issues = list_open_dast_issues(args.repo)
    print(f"Existing open DAST issues: {len(open_issues)}")

    # File new issues for active findings that don't already have an open issue.
    active_titles: set[str] = set()
    filed = 0
    for f in active:
        title = issue_title(f)
        active_titles.add(title)

        if title in open_issues:
            print(f"  EXISTING #{open_issues[title]}: {title}")
            continue

        severity = f.get("info", {}).get("severity", "unknown")
        body     = issue_body(f, args.run_url)

        number = create_issue(args.repo, title, body, severity)
        print(f"  FILED #{number}: {title}")
        filed += 1

    # Close issues for findings that no longer appear (resolved or no longer detected).
    closed = 0
    for title, number in open_issues.items():
        if title not in active_titles:
            close_issue(
                args.repo, number,
                f"Finding no longer detected by the DAST scan — closing automatically.\n"
                f"Scan run: {args.run_url}"
            )
            print(f"  CLOSED #{number}: {title}")
            closed += 1

    print()
    print(f"Summary: {filed} issue(s) filed, {closed} issue(s) closed, "
          f"{suppressed_count} finding(s) suppressed.")


if __name__ == "__main__":
    main()
