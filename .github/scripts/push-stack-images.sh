#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# PUSH THE IMAGES A TEST RUN BUILT TO ghcr.io.
#
#   .github/scripts/push-stack-images.sh [extra-tag]
#
# docker-compose-run-tests.yml names the five images it builds
# ${IMAGE_REGISTRY}/<name>:${IMAGE_TAG}, and common.sh names the mock STS the
# same way. This pushes each one that exists locally under that tag and, when
# given, under a second tag too (tests.yml passes the branch name, so
# `api:develop` is always the last develop build). An image that is not there
# — the build failed before reaching it — is reported and skipped rather than
# failing the step: the run's own failure is the one worth reading.
#
# The packages are created PRIVATE on first push; see
# .github/workflows/mirror-images.yml for why that holds.
# ---------------------------------------------------------------------------
set -euo pipefail

IMAGE_REGISTRY="${IMAGE_REGISTRY:-ghcr.io/rcbj/id-proto-debugger}"
IMAGE_TAG="${IMAGE_TAG:?IMAGE_TAG must be set}"
EXTRA_TAG="${1:-}"
NAMES="api client sts test keycloak-wsfed"

pushImage()
{
  echo "Entering pushImage()."
  local image="$1" target
  if ! docker image inspect "${image}" >/dev/null 2>&1;
  then
    echo "::warning::${image} was not built; not pushed."
    echo "Leaving pushImage(). ${image} absent."
    return 0
  fi
  docker push "${image}"
  if [ -n "${EXTRA_TAG}" ];
  then
    target="${image%:*}:${EXTRA_TAG}"
    docker tag "${image}" "${target}"
    docker push "${target}"
  fi
  echo "Leaving pushImage(). ${image} pushed."
}

for name in ${NAMES};
do
  pushImage "${IMAGE_REGISTRY}/${name}:${IMAGE_TAG}"
done
