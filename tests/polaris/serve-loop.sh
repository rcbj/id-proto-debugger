#!/bin/sh
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# File: serve-loop.sh
#
# ---------------------------------------------------------------------------
# Runs INSIDE the unmodified Polaris image (ghcr.io/egorkhaklin/polaris-oid4vp)
# as its entrypoint, so one container can answer every case of
# tests/vc_presentation_polaris.js. Polaris itself is not changed.
#
# `polaris-oid4vp serve --once` starts ONE request and keeps serving it. The
# Polaris README's own pattern for a test is a container start per case, and
# a tests container has no Docker to start one. So this does the restarting.
# The test and this loop share /data:
#
#   the test writes   issuers.json    the issuer keys Polaris trusts
#                     serve.args      extra `serve` arguments, one per line
#                     next            "start a fresh request now"
#   this writes       pki/            `keygen`'s output, made once
#                     serve.log       `serve`'s stdout and stderr; the test
#                                     reads the launch parameters out of it
#                     result.json     `--result`, Polaris's verdict on the
#                                     request
#
# Environment: POLARIS_PORT (the plain-HTTP listener, default 9080) and
# POLARIS_PUBLIC_BASE_URL (the https origin a wallet reaches it by, which is
# the TLS CORS proxy in front of it, waltid/cors-proxy.js).
# ---------------------------------------------------------------------------
set -u
D=/data
PORT="${POLARIS_PORT:-9080}"
BASE="${POLARIS_PUBLIC_BASE_URL:?POLARIS_PUBLIC_BASE_URL is required}"
HOST="${POLARIS_HOST:-localhost}"

if [ ! -f "$D/pki/client.pem" ]; then
  polaris-oid4vp keygen --out "$D/pki" --host "$HOST" --port "$PORT" ||
    exit 1
fi
echo "serve-loop: ready; waiting for $D/next"

pid=""
while :; do
  while [ ! -f "$D/next" ]; do
    sleep 0.3
  done
  if [ -n "$pid" ]; then
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
  fi
  rm -f "$D/next" "$D/result.json" "$D/serve.log"
  set --
  if [ -f "$D/serve.args" ]; then
    while IFS= read -r a; do
      [ -n "$a" ] && set -- "$@" "$a"
    done < "$D/serve.args"
  fi
  echo "serve-loop: starting a request: $*"
  polaris-oid4vp serve --pki "$D/pki" --host "$HOST" --bind 0.0.0.0 \
    --port "$PORT" --no-local-tls --public-base-url "$BASE" \
    --issuer-jwks "$D/issuers.json" --once --result "$D/result.json" \
    "$@" > "$D/serve.log" 2>&1 &
  pid=$!
done
