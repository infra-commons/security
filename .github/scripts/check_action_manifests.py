#!/usr/bin/env python3
"""Reject GitHub expressions that a composite action manifest cannot evaluate.

`.github/workflows/workflow-lint.yml` runs actionlint over this repo's *workflow*
files, and its header says why: `capture-findings-reusable.yml` once shipped a
step-level `if: ${{ secrets.X != '' }}` — `secrets` is not available there — and
released cleanly at a moving tag because nothing had ever validated it.

That guard does not cover the file type this checker does. actionlint's project
mode deliberately skips `.github/actions/*/action.yml` (it expects a different
schema there and emits false "on/jobs section missing" noise otherwise), so a
composite *manifest* has no static validation at all. On 2026-08-27 that gap cost
the fleet a working weekly security scan: an input's `description:` carried a
worked example written with the expression wrapper —

    `${{ contains(needs.*.result, 'failure') || ... }}`

— and the runner template-evaluates a manifest's whole `inputs:` block, prose and
backticks notwithstanding. `needs` is not a context available inside a composite
action, so every caller got

    Failed to load .../weekly-security-scan/action.yml
    TemplateValidationException: ... Unrecognized named-value: 'needs'.

at `Set up job`, before any step ran. Not a warning and not a degraded run — the
job could not start. It reached two repos through `weekly-security-scan/v1` with
no caller PR to review it, and stayed there for four days because `Tests`,
`Workflow lint` and `Pin check` were all green on the commit that introduced it.

This is a proxy for the runner's own template validation, not a reimplementation
of it: it checks the one property that broke, which is that every context named
inside a manifest expression is a context a manifest may read.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Contexts a composite action manifest may read.
# https://docs.github.com/en/actions/learn-github-actions/contexts#context-availability
#
# Notably absent, and each one a real load failure rather than a lint opinion:
# `needs` and `jobs` (workflow-level only — this is what broke), `secrets`
# (a composite receives secrets as inputs), `matrix`/`strategy`/`job` (job-level).
ALLOWED_CONTEXTS = frozenset({"github", "inputs", "env", "runner", "steps"})

_EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)

# An identifier in *context* position: at the head of a property or index chain.
# `contains(` and `format(` are function calls, not contexts, so an identifier
# followed by `(` is deliberately not matched.
_CONTEXT_REF = re.compile(r"(?<![A-Za-z0-9_.\-])([A-Za-z_][A-Za-z0-9_\-]*)\s*(?=[.\[])")

# String literals are data, not expressions: `format('{0}.{1}', ...)` must not be
# read as a reference to a context called `0`.
_SINGLE_QUOTED = re.compile(r"'(?:''|[^'])*'")


class Violation(tuple):
    """(path, line, context, expression) — a context the manifest may not read."""

    __slots__ = ()

    def __new__(cls, path: str, line: int, context: str, expression: str):
        return super().__new__(cls, (path, line, context, expression))

    path = property(lambda self: self[0])
    line = property(lambda self: self[1])
    context = property(lambda self: self[2])
    expression = property(lambda self: self[3])

    def __str__(self) -> str:
        return (
            f"{self.path}:{self.line}: expression reads '{self.context}', which a composite "
            f"action manifest cannot evaluate\n"
            f"    ${{{{{self.expression}}}}}"
        )


def scan_text(text: str, path: str = "<text>") -> list[Violation]:
    """Every disallowed context reference in `text`, in file order.

    Reads the raw file rather than parsed YAML on purpose: the runner
    template-evaluates the document's text, so a `${{ ... }}` inside a comment,
    a description, a default or a `run:` block is evaluated all the same. Parsing
    first would drop the comment case and make a description look like inert prose.
    """
    violations: list[Violation] = []
    for match in _EXPRESSION.finditer(text):
        body = match.group(1)
        line = text.count("\n", 0, match.start()) + 1
        seen: set[str] = set()
        for ref in _CONTEXT_REF.findall(_SINGLE_QUOTED.sub("''", body)):
            # One expression naming the same bad context twice is one defect.
            if ref not in ALLOWED_CONTEXTS and ref not in seen:
                seen.add(ref)
                violations.append(Violation(path, line, ref, body))
    return violations


def manifest_paths(repo_root: Path) -> list[Path]:
    return sorted((repo_root / ".github" / "actions").glob("*/action.yml"))


def scan_repo(repo_root: Path) -> list[Violation]:
    violations: list[Violation] = []
    for path in manifest_paths(repo_root):
        rel = path.relative_to(repo_root).as_posix()
        violations.extend(scan_text(path.read_text(encoding="utf-8"), rel))
    return violations


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    manifests = manifest_paths(repo_root)
    if not manifests:
        # A checker that finds nothing to check must not report a pass: this
        # repo's composite actions are the thing it exists to guard.
        print("check_action_manifests: no .github/actions/*/action.yml found", file=sys.stderr)
        return 2

    violations = scan_repo(repo_root)
    if not violations:
        print(f"check_action_manifests: {len(manifests)} manifest(s) OK")
        return 0

    print("Composite action manifests read contexts the runner cannot resolve.", file=sys.stderr)
    print(
        "Each of these is a hard 'Failed to load ... action.yml' at `Set up job` for every\n"
        "caller — including one reached through a moving tag with no caller PR to catch it.\n",
        file=sys.stderr,
    )
    for violation in violations:
        print(f"{violation}\n", file=sys.stderr)
    print(
        "If the expression is meant as documentation, write the expression BODY without the\n"
        f"wrapper and let the caller supply it. If the context genuinely IS available in a\n"
        f"composite manifest, add it to ALLOWED_CONTEXTS in {Path(__file__).name} with a link\n"
        "to the context-availability table — do not silence the check at the call site.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
