#!/bin/sh
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# File: serve-loop.sh
#
# ---------------------------------------------------------------------------
# Runs INSIDE the unmodified Polaris image
# (ghcr.io/egorkhaklin/polaris-oid4vp) as its entrypoint, so one container
# answers every case of tests/vc_presentation_polaris.js. Polaris itself is
# not changed.
#
# polaris-oid4vp 1.2.0 starts a request on POST /control/request, so serve
# does not have to be restarted between cases. This waits until the test has
# written the issuer keys and a control token, then execs `serve` once.
# The test and this script share /data:
#
#   the test writes   issuers.json     the issuer keys Polaris trusts
#                     control-token    bearer token for /control/request
#                     start            "the files above are ready"
#   this writes       pki/             `keygen`'s output, made once
#                     result.json      `--result`, the newest request
#
# Environment: POLARIS_PORT (the plain-HTTP listener, default 9080) and
# POLARIS_PUBLIC_BASE_URL (the https origin a wallet reaches it by, which
# is the TLS CORS proxy in front of it).
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

# A volume reused from an earlier run must not start serve on stale keys.
rm -f "$D/start" "$D/result.json" "$D/control-token" \
  "$D/serve.args" "$D/next" "$D/serve.log"
echo "serve-loop: ready; waiting for $D/start"

while [ ! -f "$D/start" ]; do
  sleep 0.3
done
if [ ! -s "$D/issuers.json" ] || [ ! -s "$D/control-token" ]; then
  echo "serve-loop: start is set but issuers.json or" \
    "control-token is missing" >&2
  exit 1
fi
# 1.2.0 does not check the mode. The notes published with the release
# still say a token file others can read is refused, so this is 0600.
chmod 600 "$D/control-token" || exit 1

echo "serve-loop: starting serve"
exec polaris-oid4vp serve --pki "$D/pki" --host "$HOST" \
  --bind 0.0.0.0 --port "$PORT" --no-local-tls \
  --public-base-url "$BASE" --issuer-jwks "$D/issuers.json" \
  --control-token-file "$D/control-token" --result "$D/result.json"
