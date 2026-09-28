#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# COPY THE TEST STACK'S THIRD-PARTY IMAGES INTO ghcr.io.
#
#   .github/scripts/mirror-images.sh missing    copy only what the mirror
#                                               does not have yet
#   .github/scripts/mirror-images.sh refresh    copy everything again, so a
#                                               moving tag (ubuntu:latest)
#                                               follows upstream
#
# The list is .github/image-mirror.txt. Each copy is
# `docker buildx imagetools create`, which copies the manifest LIST — every
# platform, so an arm64 laptop pulls the same mirror a runner does — without
# pulling anything into the local image store.
#
# `missing` is what every test run does before building, and it touches only
# ghcr.io when the mirror is complete: the upstream registry is contacted for
# an image that is not there yet and for nothing else. That is the point of
# the mirror — the 2026-09-27 run that died on a reset connection to
# auth.docker.io would have made no request to Docker Hub at all.
#
# Needs a `docker login ghcr.io` that can write packages. IMAGE_MIRROR
# overrides the prefix, and must match the compose file's default.
# ---------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")/../.."

MODE="${1:-missing}"
IMAGE_MIRROR="${IMAGE_MIRROR:-ghcr.io/rcbj/id-proto-debugger/mirror}"
LIST=".github/image-mirror.txt"
ATTEMPTS=4

copyImage()
{
  echo "Entering copyImage()."
  local src="$1" dest="$2" n=1
  while :
  do
    if docker buildx imagetools create --tag "${dest}" "${src}";
    then
      echo "Leaving copyImage(). Copied ${src} -> ${dest}."
      return 0
    fi
    if [ "${n}" -ge "${ATTEMPTS}" ];
    then
      echo "Leaving copyImage(). Gave up on ${src} after ${n} attempts."
      return 1
    fi
    echo "Copy of ${src} failed (attempt ${n}); retrying in $((n * 15))s."
    sleep $((n * 15))
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
  local failed=0 src path dest
  while read -r src path;
  do
    case "${src}" in
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
    copyImage "${src}" "${dest}" || failed=1
  done < "${LIST}"
  if [ "${failed}" -ne 0 ];
  then
    echo "Leaving main(). At least one image was not copied."
    exit 1
  fi
  echo "Leaving main()."
}

main
