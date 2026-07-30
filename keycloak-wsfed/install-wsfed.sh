#!/bin/bash
#
# install-wsfed.sh — install the cloudtrust keycloak-wsfed WildFly module into a
# Keycloak 8.0.1 home.
#
# It delegates to the module's OWN vendored install.sh (shipped in the release
# tarball), which uses xmlstarlet to edit standalone.xml in a NAMESPACE-AWARE way
# — it targets the keycloak-server subsystem's <providers>/<theme> specifically.
# (A naive text insert can land in a different subsystem's <providers> and make
# standalone.xml invalid, which aborts WildFly boot.)
#
# The tarball's top directory is "Keycloak WS-Fed Integration" (with spaces), and
# the vendored install.sh is NOT space-safe internally (unquoted $(dirname $0)),
# so we first move it to a space-free path and run it from there. We then VERIFY
# the install and exit non-zero otherwise — the vendored install.sh has an ERR
# trap that can mask failures, so a broken install must fail the image build
# loudly instead of producing a silently-non-WS-Fed Keycloak.
set -euo pipefail

KC="${1:-/opt/jboss/keycloak}"
SRC="/tmp/wsfed/Keycloak WS-Fed Integration"
PKG="/tmp/wsfed/pkg"
CONF="$KC/standalone/configuration/standalone.xml"
JAR="keycloak-wsfed-8.0.1.jar"
MODDIR="$KC/modules/system/layers/keycloak-wsfed/com/quest/keycloak-wsfed/main"

# Run the vendored installer from a space-free directory (it is not space-safe).
if [ -d "$SRC" ]; then rm -rf "$PKG"; mv "$SRC" "$PKG"; fi
echo "[install-wsfed] running vendored installer against $KC"
bash "$PKG/install.sh" "$KC"

# Verify (the vendored installer can swallow errors via its ERR trap).
test -f "$MODDIR/$JAR"                              || { echo "[install-wsfed] ERROR: jar not installed at $MODDIR"; exit 1; }
grep -q 'module:com.quest.keycloak-wsfed' "$CONF"   || { echo "[install-wsfed] ERROR: provider not registered in standalone.xml"; exit 1; }
grep -q 'keycloak-wsfed' "$KC/modules/layers.conf"  || { echo "[install-wsfed] ERROR: layer not registered in layers.conf"; exit 1; }

echo "[install-wsfed] OK — keycloak-wsfed module installed and registered"
