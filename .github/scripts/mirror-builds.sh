#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

# ---------------------------------------------------------------------------
# BUILD THE MIRROR IMAGES THAT HAVE NO UPSTREAM, AND PUSH THEM TO ghcr.io.
#
#   .github/scripts/mirror-builds.sh missing    build only what the mirror
#                                               does not have yet
#   .github/scripts/mirror-builds.sh refresh    build everything again
#
# The list is .github/image-mirror-builds.txt: the Shibboleth side-car's
# archives (a FROM scratch image whose two ADDs are pinned by SHA-256) and
# iya-sts's companion, built from iya-sts's release tag. Each is built with
# `docker buildx build --push`, given one named context per line of
# .github/image-mirror.txt so its FROMs come from the mirror too — which is
# why .github/scripts/mirror-images.sh must have run first.
#
# The images are built for the runner's own platform only (linux/amd64 on
# GitHub's runners), unlike the copies, which keep every platform upstream
# publishes.
#
# Needs a `docker login ghcr.io` that can write packages. IMAGE_MIRROR
# overrides the prefix, and must match the compose files' default.
# ---------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")/../.."

MODE="${1:-missing}"
IMAGE_MIRROR="${IMAGE_MIRROR:-ghcr.io/rcbj/id-proto-debugger/mirror}"
LIST=".github/image-mirror-builds.txt"
COPIES=".github/image-mirror.txt"
ATTEMPTS=3

# The --build-context arguments: each upstream name in image-mirror.txt,
# pointed at its mirror copy. BuildKit looks a FROM up by its familiar name
# with `:latest` dropped, so `ubuntu:latest` is offered as `ubuntu`.
mirrorContextArgs()
{
  echo "Entering mirrorContextArgs()." >&2
  local src path name
  while read -r src path;
  do
    case "${src}" in
      ''|'#'*)
        continue
        ;;
    esac
    name="${src#docker.io/}"
    name="${name#library/}"
    name="${name%:latest}"
    printf -- '--build-context\n%s=docker-image://%s/%s\n' \
      "${name}" "${IMAGE_MIRROR}" "${path}"
  done < "${COPIES}"
  echo "Leaving mirrorContextArgs()." >&2
}

buildImage()
{
  echo "Entering buildImage()."
  local source="$1" dest="$2" n=1
  local -a contexts
  mapfile -t contexts < <(mirrorContextArgs)
  while :
  do
    if docker buildx build --push --tag "${dest}" \
         --label "org.opencontainers.image.source=${source}" \
         "${contexts[@]}" "${source}";
    then
      echo "Leaving buildImage(). Built ${source} -> ${dest}."
      return 0
    fi
    if [ "${n}" -ge "${ATTEMPTS}" ];
    then
      echo "Leaving buildImage(). Gave up on ${source} after ${n} attempts."
      return 1
    fi
    echo "Build of ${source} failed (attempt ${n}); retrying in $((n * 30))s."
    sleep $((n * 30))
    n=$((n + 1))
  done
}

main()
{
  echo "Entering main()."
  case "${MODE}" in
    missing|refresh)
      ;;
    *)
      echo "Usage: $0 missing|refresh" >&2
      echo "Leaving main(). Bad mode '${MODE}'."
      exit 2
      ;;
  esac
  local failed=0 path source dest
  while read -r path source;
  do
    case "${path}" in
      ''|'#'*)
        continue
        ;;
    esac
    dest="${IMAGE_MIRROR}/${path}"
    if [ "${MODE}" = "missing" ] &&
       docker buildx imagetools inspect "${dest}" >/dev/null 2>&1;
    then
      echo "Present: ${dest}"
      continue
    fi
    buildImage "${source}" "${dest}" || failed=1
  done < "${LIST}"
  if [ "${failed}" -ne 0 ];
  then
    echo "Leaving main(). At least one image was not built."
    exit 1
  fi
  echo "Leaving main()."
}

main
