#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# File: .github/scripts/docs-redirects.sh
#
# ---------------------------------------------------------------------------
# THE ADDRESSES THE UNVERSIONED SITE PUBLISHED KEEP WORKING.
#
#   .github/scripts/docs-redirects.sh
#
# Until the documentation was versioned (docs/CLAUDE.md) every page was at
# /docs/<page>.html, and bookmarks, other sites and the debugger's own
# pages link there. This writes one small page at each such address that
# sends the reader to the same page in the newest documentation version
# that has it: the latest for almost every page, an older version only for
# a page the latest dropped.
#
# THE PAGES ARE COMMITTED, unlike iya-sts's, which its Pages workflow writes
# into the built site: this site is GitHub Pages' legacy branch build
# (master, path /), which runs no step of ours. Only the addresses the
# unversioned site had need one, so this is run when the site is versioned
# and not again; a page added later has no old address. Run it again only
# after deleting docs/*.html and the old directories, to rebuild them.
#
# No script in the page: a meta refresh, a canonical link and a plain link,
# all RELATIVE, so they hold under the project site's base URL. Plain HTML
# with no front matter, so Jekyll copies each as it is. A version's own
# index.md (its README) is not given one: /docs/ is the landing page. The
# versions and their order come from _data/versions.yml, newest first.
# ---------------------------------------------------------------------------
set -u -o pipefail

echo "Entering docs-redirects.sh."
ROOT="$(git rev-parse --show-toplevel)" || exit 1
cd "${ROOT}" || exit 1

FOLDERS="$(grep -E '^- *\{' _data/versions.yml |
           sed -nE 's/.*folder: *"?([A-Za-z0-9._-]+)"?.*/\1/p')"
if [ -z "${FOLDERS}" ];
then
  echo "docs-redirects.sh: no versions in _data/versions.yml" >&2
  exit 1
fi

written=0
kept=0
while IFS= read -r folder;
do
  while IFS= read -r rel;
  do
    if [ "${rel}" = "index.md" ];
    then
      continue
    fi
    base="${rel%.md}"
    case "${base}" in
      */index|index) addr="${base}.html" ;;
      *) addr="${base}.html" ;;
    esac
    target="docs/${addr}"
    if [ -e "${target}" ];
    then
      kept=$((kept + 1))
      continue
    fi
    depth="$(printf '%s' "${addr}" | tr -cd '/' | wc -c)"
    up=""
    for _ in $(seq 1 "${depth}");
    do
      up="../${up}"
    done
    to="${up}${folder}/${addr}"
    case "${addr}" in
      */index.html) to="${up}${folder}/${addr%index.html}" ;;
    esac
    mkdir -p "$(dirname "${target}")" || exit 1
    cat > "${target}" <<EOF
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Moved to ${folder}</title>
<meta http-equiv="refresh" content="0; url=${to}">
<link rel="canonical" href="${to}">
</head>
<body>
<p>This page moved to <a href="${to}">${to}</a>, in the documentation of
${folder}.</p>
</body>
</html>
EOF
    written=$((written + 1))
  done < <(cd "docs/${folder}" && find . -name '*.md' | sed 's#^\./##' |
           sort)
done <<< "${FOLDERS}"

echo "Leaving docs-redirects.sh. ${written} written, ${kept} already there."
