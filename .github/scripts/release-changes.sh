#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

# ---------------------------------------------------------------------------
# WRITE THE "WHAT'S CHANGED" HALF OF A RELEASE'S NOTES, ONE LINE PER CHANGE.
#
#   .github/scripts/release-changes.sh <previous-tag> <tag> [owner/repo]
#
# Prints Markdown on stdout: GitHub's generated list of merged pull requests
# since <previous-tag>, followed by every commit in that range that NO
# feature pull request carried, one line each, and then the "Full
# Changelog" link GitHub's list ends with. With no <previous-tag> (the
# first release) it prints GitHub's list alone.
#
# Why both: GitHub's generator lists only pull requests. When work is
# committed straight onto develop, the only pull request in range is the
# develop -> master promotion, and the release says "Release M.N.P" and a
# compare link and nothing else — which is what release-0.9.4 shipped with.
# Every individual change belongs on the page, so the commits GitHub cannot
# see are listed here.
#
# A commit counts as carried by a pull request when GitHub associates it
# with a MERGED one whose head is not develop: a develop -> master
# promotion carries every commit in the release, so counting it would hide
# all of them again. Merge commits are left out (a feature PR's merge, and
# "Merge master into develop", say nothing of their own). If GitHub cannot
# be asked about a commit, it is listed — a duplicate line is better than
# a missing one.
#
# Needs `gh` logged in (GH_TOKEN in a workflow), `jq`, and a clone with the
# history between the two tags (actions/checkout's fetch-depth: 0).
# ---------------------------------------------------------------------------
set -euo pipefail

PREVIOUS="${1:-}"
TAG="${2:?usage: release-changes.sh <previous-tag> <tag> [owner/repo]}"
REPO="${3:-${GITHUB_REPOSITORY:-rcbj/id-proto-debugger}}"

generate_args=(-f "tag_name=${TAG}")
if [ -n "${PREVIOUS}" ]; then
  generate_args+=(-f "previous_tag_name=${PREVIOUS}")
fi
generated="$(gh api --method POST "repos/${REPO}/releases/generate-notes" \
  "${generate_args[@]}" --jq .body)"

if [ -z "${PREVIOUS}" ]; then
  printf '%s\n' "${generated}"
  exit 0
fi

# The commits feature pull requests carried, worked out from git rather
# than asked of GitHub one commit at a time (a release can hold hundreds).
# For a merge commit, what it brought in is <merge>^1..<merge>^2; a squash
# or a single rebased commit IS the merge commit. A rebase of several
# commits leaves the others uncounted, so they are listed twice — never
# zero times.
carried="$(mktemp)"
trap 'rm -f "${carried}"' EXIT
since="$(git log -1 --format=%cs "${PREVIOUS}")"
gh pr list --repo "${REPO}" --state merged --limit 1000 \
    --search "merged:>=${since}" --json headRefName,mergeCommit \
    --jq '.[] | select(.headRefName != "develop" and .mergeCommit != null)
          | .mergeCommit.oid' |
while read -r merge; do
  git cat-file -e "${merge}^{commit}" 2>/dev/null || continue
  git merge-base --is-ancestor "${merge}" "${TAG}" || continue
  if git rev-parse -q --verify "${merge}^2" >/dev/null; then
    git rev-list "${merge}^1..${merge}^2"
  else
    echo "${merge}"
  fi
done | sort -u > "${carried}"

direct=""
while read -r sha; do
  [ -n "${sha}" ] || continue
  if grep -qx "${sha}" "${carried}"; then
    continue
  fi
  subject="$(git log -1 --format=%s "${sha}")"
  login="$(gh api "repos/${REPO}/commits/${sha}" --jq '.author.login // ""' \
    2>/dev/null || true)"
  if [ -n "${login}" ]; then
    by="@${login}"
  else
    by="$(git log -1 --format=%an "${sha}")"
  fi
  direct+="* ${subject} by ${by} in"
  direct+=" https://github.com/${REPO}/commit/${sha}"$'\n'
done < <(git rev-list --no-merges --reverse "${PREVIOUS}..${TAG}")

# GitHub's body ends with the "**Full Changelog**" line; the commits go
# above it, so the page reads: pull requests, commits, compare link.
changes="$(printf '%s\n' "${generated}" | grep -v '^\*\*Full Changelog\*\*')"
changelog="$(printf '%s\n' "${generated}" | grep '^\*\*Full Changelog\*\*' ||
  true)"

printf '%s\n' "${changes}"
if [ -n "${direct}" ]; then
  echo ""
  echo "## Committed without a pull request"
  echo ""
  printf '%s' "${direct}"
fi
if [ -n "${changelog}" ]; then
  echo ""
  printf '%s\n' "${changelog}"
fi
