#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <base-revision> <head-revision>" >&2
  exit 2
fi

base_revision=$1
head_revision=$2

git rev-parse --verify "${base_revision}^{commit}" >/dev/null
git rev-parse --verify "${head_revision}^{commit}" >/dev/null

is_recognized_automation() {
  local author_name=$1
  local author_email=$2

  [[ "$author_name" == "dependabot[bot]" && \
    "$author_email" == "49699333+dependabot[bot]@users.noreply.github.com" ]]
}

failure_count=0
checked_count=0
skipped_count=0

while IFS= read -r commit; do
  [[ -n "$commit" ]] || continue

  author_name=$(git show -s --format=%an "$commit")
  author_email=$(git show -s --format=%ae "$commit")

  if is_recognized_automation "$author_name" "$author_email"; then
    ((skipped_count += 1))
    continue
  fi

  ((checked_count += 1))
  valid_signoff=false

  while IFS= read -r trailer; do
    if [[ "$trailer" =~ ^Signed-off-by:[[:space:]]+.+[[:space:]]+\<([^\<\>[:space:]]+)\>$ ]] && \
      [[ "${BASH_REMATCH[1],,}" == "${author_email,,}" ]]; then
      valid_signoff=true
      break
    fi
  done < <(git show -s --format=%B "$commit" | git interpret-trailers --parse)

  if [[ "$valid_signoff" != true ]]; then
    printf 'DCO check failed for commit %s: add a valid Signed-off-by trailer matching the commit author email.\n' "$commit" >&2
    ((failure_count += 1))
  fi
done < <(git rev-list --reverse --no-merges "${base_revision}..${head_revision}")

if ((failure_count > 0)); then
  printf 'DCO check rejected %d of %d human-authored commit(s). See CONTRIBUTING.md for remediation.\n' \
    "$failure_count" "$checked_count" >&2
  exit 1
fi

printf 'DCO check passed for %d human-authored commit(s); skipped %d recognized automation commit(s).\n' \
  "$checked_count" "$skipped_count"
