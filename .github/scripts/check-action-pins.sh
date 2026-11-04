#!/usr/bin/env bash
# Fail if any real `uses:` directive in this repo references a mutable ref
# (branch or tag) instead of a 40-char commit SHA.
#
# Why this exists: callers pin our *reusable workflows* to an immutable SHA, but
# a reusable workflow that internally calls its composite action at `@main` re-opens
# the supply-chain hole — the pinned-by-the-caller code can still change underneath
# them. This guard keeps every internal reference SHA-pinned so a caller's pin is real.
#
# Allowed without a SHA: local `./` refs, digest-pinned `docker://...@sha256:` images, and
# own-repo *composite-action* refs on a per-family `<family>/vN` moving tag, but ONLY in a
# workflow that is not a reusable (no `workflow_call:`), which no caller pins. Inside a
# reusable it must be a SHA (infra-commons/meta#1779; see lagging_inner_pins).
#
# `adversarial-review` and `adversarial-review-gate` are explicitly EXCLUDED from that
# relaxation (infra-commons/security#95): they used to ship the same way, but a caller's
# SHA pin on adversarial-review-reusable.yml only meant something once these two also
# resolved to a fixed SHA instead of a moving tag. If either ever shows up again pinned
# to a `<family>/vN` tag, that is a regression back to #95, not a legitimate use of this
# exemption — so it fails loudly here instead of silently passing.
# Runs in CI (pin-check.yml) and locally: `bash .github/scripts/check-action-pins.sh`.
set -euo pipefail

viol=0
while IFS= read -r raw; do
  file="${raw%%:*}"; rest="${raw#*:}"; lineno="${rest%%:*}"; content="${rest#*:}"
  ref="${content#*uses:}"; ref="${ref%%#*}"            # drop inline comment
  ref="$(printf '%s' "$ref" | tr -d "\"'" | xargs)"    # trim quotes/whitespace
  case "$ref" in
    ./*|docker://*@sha256:*) continue ;;
    infra-commons/security/.github/actions/adversarial-review@*/v[0-9]*|infra-commons/security/.github/actions/adversarial-review-gate@*/v[0-9]*)
      echo "::error file=$file,line=$lineno::'$ref' pins by moving tag — adversarial-review and adversarial-review-gate must be SHA-pinned (infra-commons/security#95), not exempted like the other composites"
      viol=$((viol + 1))
      continue
      ;;
    infra-commons/security/.github/actions/*@*/v[0-9]*)
      # Inside a reusable a moving tag defeats the caller's SHA pin (meta#1779).
      if grep -qE '^[[:space:]]*workflow_call:' "$file"; then
        echo "::error file=$file,line=$lineno::'$ref' pins an own composite by moving tag inside a reusable — pin to a 40-char commit SHA with a '# <family>/vN (vX.Y.Z)' comment (infra-commons/meta#1779)"
        viol=$((viol + 1))
      fi
      continue
      ;;
    *@*)
      tail="${ref##*@}"
      if ! printf '%s' "$tail" | grep -qE '^[0-9a-f]{40}$'; then
        echo "::error file=$file,line=$lineno::unpinned action ref '$ref' — pin to a 40-char commit SHA"
        viol=$((viol + 1))
      fi
      ;;
  esac
done < <(grep -rnE '^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*\S' \
           .github/workflows .github/actions 2>/dev/null \
         | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#')

if [ "$viol" -gt 0 ]; then
  echo "Found $viol unpinned action ref(s). Pin each to a 40-char commit SHA."
  exit 1
fi
echo "All action refs are SHA-pinned or local. ✅"
