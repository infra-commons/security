# dast/

DAST (dynamic application security test) triage that ships with the `dast-scan-reusable.yml` workflow. Complements the active `pentest/` toolkit — DAST is non-intrusive (Nuclei: headers, TLS, exposures, tech fingerprint), pen-test is active (auth bypass, IDOR, rate-limit, HMAC-signed routes).

## triage.py

Consumes a Nuclei JSONL findings file, applies a suppressions YAML, and files/closes GitHub Issues via the `gh` CLI (labels: `security`, `severity:*`, `source:dast`). Stdlib + PyYAML only; `GH_TOKEN` with `issues:write` in the environment.

```
python3 dast/triage.py \
  --findings nuclei-all.jsonl \
  --suppressions .github/dast-suppressions.yml \
  --repo owner/name \
  --run-url https://github.com/owner/name/actions/runs/123
```

The reusable workflow drives this for callers — a solution should not vendor its own copy.

## Consolidation note

`pentest/triage.py` was adapted from this script (same `gh`-CLI approach, label model, dedup-by-title, auto-close). They now live in one repo but still carry separate copies of that shared logic. **Follow-up:** factor the common engine into a single module that takes a source/schema adapter (Nuclei finding dict vs pen-test `Finding`) instead of two near-duplicates. Tracked with the DAST/pen-test reusables promotion (solution-template promotion plan, consolidation items).
