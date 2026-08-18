#!/bin/bash
#
# File: sync-to-mock-sts.sh
#
# ---------------------------------------------------------------------------
# Copy the Kerberos codec into the mock STS, which cannot share it.
#
# The KDC needs the same codec the browser uses — it is the other end of the same
# wire — but it lives in the rcbj/mock-sts SUBMODULE, and compose builds that
# service with `context: ./sts`. A Docker build cannot COPY from outside its
# context, so `../common/krb5` is unreachable from there. The alternatives were:
#
#   * publish the codec as a package — too much ceremony for four files;
#   * move the KDC into this repository as a side-car like keycloak-wsfed/ — which
#     works, and was rejected because the mock STS is where every other mock
#     protocol lives; or
#   * vendor a copy, which is this, and which costs a sync step and a test.
#
# **The test is the part that matters.** A vendored codec that drifts still talks
# perfectly well to itself: the KDC and the wallet would each be self-consistent
# and disagree only with each other, and the symptom would be an integrity failure
# that looks like a wrong password. tests/krb5_codec_sync.js loads BOTH copies and
# round-trips messages between them, so divergence fails a test rather than
# surfacing weeks later against a real domain controller.
#
# Usage:
#   common/krb5/sync-to-mock-sts.sh [path-to-mock-sts]
#
# With no argument it tries ../mock-sts (a sibling development checkout) and then
# ./sts (the initialised submodule). Note that writing into ./sts modifies
# somebody else's checkout — `git status` shows it as a modified submodule rather
# than as modified files — so the sibling checkout is preferred and is what the
# development loop uses: edit here, sync, push mock-sts, then bump the gitlink.
# ---------------------------------------------------------------------------
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../.." && pwd)"

# krb5_spnego.js is here for the same reason krb5_gss.js is: the SPNEGO-protected
# resource in the mock STS decodes the very tokens the browser encodes, so the two
# ends must share one RFC 4178 coder or they will agree only with themselves.
MODULES=(krb5_primitives.js krb5_asn1.js krb5_crypto.js krb5_messages.js krb5_gss.js
         krb5_spnego.js krb5_ndr.js krb5_pac.js)

target="${1:-}"
if [[ -z "${target}" ]]; then
  if [[ -d "${REPO_ROOT}/../mock-sts" ]]; then
    target="${REPO_ROOT}/../mock-sts"
  elif [[ -f "${REPO_ROOT}/sts/package.json" ]]; then
    target="${REPO_ROOT}/sts"
    echo "sync-to-mock-sts: no sibling ../mock-sts checkout; writing into the SUBMODULE at sts/." >&2
    echo "  That is somebody else's checkout: git status will report a modified submodule, and the" >&2
    echo "  change has to be committed and pushed in rcbj/mock-sts before this repository's gitlink" >&2
    echo "  can move." >&2
  else
    echo "sync-to-mock-sts: could not find mock-sts. Pass its path, or run" >&2
    echo "  git submodule update --init --recursive sts" >&2
    echo "  (an uninitialised submodule is an EMPTY DIRECTORY, not a missing one)." >&2
    exit 1
  fi
fi

if [[ ! -f "${target}/package.json" ]]; then
  echo "sync-to-mock-sts: ${target} does not look like the mock STS (no package.json)." >&2
  exit 1
fi

changed=0
for module in "${MODULES[@]}"; do
  src="${HERE}/${module}"
  dest="${target}/${module}"
  if [[ ! -f "${src}" ]]; then
    echo "sync-to-mock-sts: ${src} is missing." >&2
    exit 1
  fi
  if [[ -f "${dest}" ]] && cmp -s "${src}" "${dest}"; then
    echo "  unchanged  ${module}"
  else
    cp "${src}" "${dest}"
    echo "  copied     ${module}"
    changed=$((changed + 1))
  fi
done

echo "sync-to-mock-sts: ${changed} file(s) updated in ${target}."
if [[ ${changed} -gt 0 ]]; then
  echo
  echo "Next: run tests/krb5_codec_sync.js to confirm the two copies still agree, then commit and"
  echo "push in mock-sts, then bump this repository's sts/ gitlink. In that order — a COPY of an"
  echo "sts/ file added to a Dockerfile before the gitlink moves breaks the image build."
fi
