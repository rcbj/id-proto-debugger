#!/bin/bash
set -x

check_return_code()
{
  rc=$1
  if [  $rc -ne 0 ];
  then
    echo "Non-zero return code. Exiting."
    exit 1
  fi
}

common_setup()
{
  echo "Entering common_setup()."
  REV=/usr/bin/rev
  JQ=/usr/bin/jq
  CURL=/usr/bin/curl
  for COMMAND in ${REV} ${JQ} ${CURL}
  do
    if [ ! -x "${COMMAND}" ];
    then
      echo "Cannot execute ${COMMAND} command."
      exit 1
    fi
  done
  echo "Leaving common_setup()."
}

docker_compose() {
  echo "Entering docker_compose()."
  # Capture the real exit code of the compose command. sudo propagates the
  # child's status, but the trailing echo would reset $?, so stash it first and
  # return it — otherwise a failed `up --exit-code-from tests` (a failing test)
  # is masked and callers (e.g. run-coverage.sh) wrongly see success.
  local rc
  if [ -x ~/.local/bin/docker-compose ];
  then
    sudo CONFIG_FILE=${CONFIG_FILE} docker-compose "$@"
    rc=$?
  elif docker compose version >/dev/null 2>&1; then
    sudo CONFIG_FILE=${CONFIG_FILE} docker compose "$@"
    rc=$?
  elif command -v docker-compose >/dev/null 2>&1; then
    sudo CONFIG_FILE=${CONFIG_FILE} docker-compose "$@"
    rc=$?
  else
    echo "Error: Docker Compose not found." >&2
    return 1
  fi
  echo "Leaving docker_compose(). rc=${rc}"
  return ${rc}
}

# Download the Keycloak SAML IdP descriptor to a local file and export
# SAML_METADATA_FILE, so the SAML tests UPLOAD it into saml_request.html rather
# than having the browser fetch it. Required against a backend-less deployed site
# (e.g. https://test.idptools.com): the HTTPS page can't fetch the local http
# Keycloak descriptor cross-origin (blocked by CORS). Uses
# KEYCLOAK_LOCALHOST_BASE_URL (reachable from THIS shell), not the browser-facing
# KEYCLOAK_BASE_URL. Gated by SAML_METADATA_UPLOAD; called from configureKeycloak
# after the debugger-testing realm exists, so the descriptor resolves.
download_saml_metadata()
{
  echo "Entering download_saml_metadata()."
  local url="${KEYCLOAK_LOCALHOST_BASE_URL}/realms/debugger-testing/protocol/saml/descriptor"
  local dest="${SAML_METADATA_FILE:-${CURRENT_DIR}/saml-idp-metadata.xml}"
  echo "Downloading SAML IdP metadata from ${url} to ${dest}"
  curl -sf "${url}" -o "${dest}"
  check_return_code $?
  if [ ! -s "${dest}" ];
  then
    echo "ERROR: downloaded SAML metadata is empty (${url})." >&2
    exit 1
  fi
  declare -gx SAML_METADATA_FILE="${dest}"
  echo "SAML IdP metadata saved to ${SAML_METADATA_FILE}."
  echo "Leaving download_saml_metadata()."
}

# ---------------------------------------------------------------------------
# The SAML SP key pair used by the SAML tests.
#
# Generated FRESH on every run and never written to the repository: the private
# key exists only in this shell's environment (and the environment of the test
# processes it spawns) for the life of the run. It is created in a temporary
# directory which is deleted immediately after the PEMs are read.
#
# Exports:
#   SAML_SP_PRIVATE_KEY   the private key, PEM (PKCS#1) — the tests sign the
#                         AuthnRequest / LogoutRequest with it, and decrypt an
#                         encrypted assertion with it
#   SAML_SP_CERT          the matching self-signed certificate, PEM
#   SAML_SP_SIGNING_CERT  the same certificate as base64 DER (no PEM armour),
#                         which is the form Keycloak's saml.signing.certificate
#                         attribute takes — configureKeycloak registers it on the
#                         SAML client so it validates the request signature
#
# An outer wrapper may supply SAML_SP_PRIVATE_KEY / SAML_SP_CERT itself; in that
# case they are used as they are and nothing is generated.
# ---------------------------------------------------------------------------
generateSpKeyPair()
{
  echo "Entering generateSpKeyPair()."
  # This script runs under `set -x`, which would echo the private key into the
  # run log (and a CI build log). Trace off for the duration, restored on the way
  # out — only lengths and fingerprints are printed.
  local xtrace_was_on=""
  case "$-" in
    *x*) xtrace_was_on="yes"; set +x ;;
  esac

  if [ -n "${SAML_SP_PRIVATE_KEY:-}" ] && [ -n "${SAML_SP_CERT:-}" ];
  then
    echo "SAML SP key pair was supplied by the caller; using it as-is."
    SAML_SP_SIGNING_CERT=$(echo "${SAML_SP_CERT}" | grep -v -- '-----' | tr -d '\n\r')
    export SAML_SP_PRIVATE_KEY SAML_SP_CERT SAML_SP_SIGNING_CERT
    [ -n "${xtrace_was_on}" ] && set -x
    echo "Leaving generateSpKeyPair()."
    return 0
  fi

  if ! command -v openssl >/dev/null 2>&1;
  then
    echo "ERROR: openssl is required to generate the test SAML SP key pair." >&2
    exit 1
  fi

  local dir
  dir=$(mktemp -d)
  # Two days is plenty for a test run and keeps a stray copy short-lived.
  openssl req -x509 -newkey rsa:2048 -sha256 -days 2 -nodes \
    -keyout "${dir}/sp-key.pem" -out "${dir}/sp-cert.pem" \
    -subj "/CN=OAuth2 OIDC Debugger Test SP" >/dev/null 2>&1
  check_return_code $?
  # PKCS#1 ("BEGIN RSA PRIVATE KEY"), which is what the debugger's key fields
  # have always been given. node-forge reads either form, so this is only for
  # consistency with what a user would paste in by hand.
  if openssl rsa -in "${dir}/sp-key.pem" -traditional -out "${dir}/sp-key-pkcs1.pem" >/dev/null 2>&1;
  then
    mv "${dir}/sp-key-pkcs1.pem" "${dir}/sp-key.pem"
  fi

  SAML_SP_PRIVATE_KEY=$(cat "${dir}/sp-key.pem")
  SAML_SP_CERT=$(cat "${dir}/sp-cert.pem")
  SAML_SP_SIGNING_CERT=$(grep -v -- '-----' "${dir}/sp-cert.pem" | tr -d '\n\r')
  # Off disk immediately — the key lives in the environment only.
  rm -rf "${dir}"
  export SAML_SP_PRIVATE_KEY SAML_SP_CERT SAML_SP_SIGNING_CERT

  if [ -z "${SAML_SP_PRIVATE_KEY}" ] || [ -z "${SAML_SP_SIGNING_CERT}" ];
  then
    [ -n "${xtrace_was_on}" ] && set -x
    echo "ERROR: the generated SAML SP key pair is empty." >&2
    exit 1
  fi
  # A fingerprint identifies the pair in the log without revealing anything.
  local fingerprint
  fingerprint=$(echo "${SAML_SP_CERT}" | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
  [ -n "${xtrace_was_on}" ] && set -x
  echo "Generated a fresh SAML SP key pair for this run: RSA 2048, SHA-256 fingerprint ${fingerprint}."
  echo "Leaving generateSpKeyPair()."
}

# ---------------------------------------------------------------------------
# The walt.id issuer's signing key, generated fresh for each run.
#
# The waltid-issuer container (waltid/config/*.conf) reads its key leaf by leaf
# out of the environment, so that no private key is committed here — the same
# rule generateSpKeyPair() follows for the SAML SP. It signs both the
# credentials it issues and its own access tokens, and its did:jwk — the public
# half of this key, encoded into the identifier — becomes the `iss` of every
# credential it issues.
#
# Exports:
#   WALTID_KEY_D / _X / _Y     the P-256 key, as JWK members
#   WALTID_ISSUER_DID          did:jwk of the public half
#   WALTID_CI_TOKEN_KEY        the same key as the JSON string walt.id's
#                              ciTokenKey field expects
# Honours values supplied by the caller, so a run can pin a key if it needs to.
# ---------------------------------------------------------------------------
generateWaltidIssuerKey()
{
  echo "Entering generateWaltidIssuerKey()."
  # As in generateSpKeyPair: this file runs under `set -x`, and a private key
  # must not be echoed into a run (or CI) log.
  local xtrace_was_on=""
  case "$-" in
    *x*) xtrace_was_on="yes"; set +x ;;
  esac

  if [ -n "${WALTID_KEY_D:-}" ] && [ -n "${WALTID_ISSUER_DID:-}" ] && [ -n "${WALTID_CI_TOKEN_KEY:-}" ];
  then
    export WALTID_KEY_D WALTID_KEY_X WALTID_KEY_Y WALTID_ISSUER_DID WALTID_CI_TOKEN_KEY
    [ -n "${xtrace_was_on}" ] && set -x
    echo "A walt.id issuer key was supplied by the caller; using it as-is."
    echo "Leaving generateWaltidIssuerKey()."
    return 0
  fi

  if ! command -v node >/dev/null 2>&1;
  then
    [ -n "${xtrace_was_on}" ] && set -x
    echo "ERROR: node is required to generate the walt.id issuer key." >&2
    exit 1
  fi

  # One line per exported value, so nothing has to be parsed out of JSON here.
  local generated
  generated=$(node -e '
    var crypto = require("crypto");
    var kp = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    var jwk = kp.privateKey.export({ format: "jwk" });
    var pub = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
    // did:jwk is base64url of the JSON public key, per the did:jwk method.
    var did = "did:jwk:" + Buffer.from(JSON.stringify(pub)).toString("base64url");
    console.log(jwk.d);
    console.log(jwk.x);
    console.log(jwk.y);
    console.log(did);
    console.log(JSON.stringify({ type: "jwk", jwk: { kty: jwk.kty, d: jwk.d, crv: jwk.crv, x: jwk.x, y: jwk.y } }));
  ')
  if [ -z "${generated}" ];
  then
    [ -n "${xtrace_was_on}" ] && set -x
    echo "ERROR: could not generate the walt.id issuer key." >&2
    exit 1
  fi

  WALTID_KEY_D=$(echo "${generated}" | sed -n '1p')
  WALTID_KEY_X=$(echo "${generated}" | sed -n '2p')
  WALTID_KEY_Y=$(echo "${generated}" | sed -n '3p')
  WALTID_ISSUER_DID=$(echo "${generated}" | sed -n '4p')
  WALTID_CI_TOKEN_KEY=$(echo "${generated}" | sed -n '5p')
  export WALTID_KEY_D WALTID_KEY_X WALTID_KEY_Y WALTID_ISSUER_DID WALTID_CI_TOKEN_KEY

  if [ -z "${WALTID_KEY_D}" ] || [ -z "${WALTID_ISSUER_DID}" ];
  then
    [ -n "${xtrace_was_on}" ] && set -x
    echo "ERROR: the generated walt.id issuer key is incomplete." >&2
    exit 1
  fi

  [ -n "${xtrace_was_on}" ] && set -x
  # The DID is public — it is published in every credential this issuer signs.
  echo "Generated a fresh walt.id issuer key for this run: P-256, ${WALTID_ISSUER_DID}."
  echo "Leaving generateWaltidIssuerKey()."
}

# ---------------------------------------------------------------------------
# The walt.id VERIFIER's request-signing key.
#
# verifier-api2 signs Request Objects with this when a session asks for
# signed_request. It is separate from the issuer's key on purpose: they are
# different parties, and a test that shared one key between them would prove
# less than it appears to.
#
# Exports WALTID_VERIFIER_KEY — the {"type":"jwk","jwk":{…}} string walt.id's
# configuration expects — and never echoes it, the same rule
# generateWaltidIssuerKey() and generateSpKeyPair() follow.
# ---------------------------------------------------------------------------
generateWaltidVerifierKey()
{
  echo "Entering generateWaltidVerifierKey()."
  local xtrace_was_on=""
  case "$-" in
    *x*) xtrace_was_on="yes"; set +x ;;
  esac

  if [ -n "${WALTID_VERIFIER_KEY:-}" ];
  then
    export WALTID_VERIFIER_KEY
    [ -n "${xtrace_was_on}" ] && set -x
    echo "A walt.id verifier key was supplied by the caller; using it as-is."
    echo "Leaving generateWaltidVerifierKey()."
    return 0
  fi

  if ! command -v node >/dev/null 2>&1;
  then
    [ -n "${xtrace_was_on}" ] && set -x
    echo "ERROR: node is required to generate the walt.id verifier key." >&2
    exit 1
  fi

  WALTID_VERIFIER_KEY=$(node -e '
    var crypto = require("crypto");
    var kp = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    var jwk = kp.privateKey.export({ format: "jwk" });
    console.log(JSON.stringify({ type: "jwk",
      jwk: { kty: jwk.kty, d: jwk.d, crv: jwk.crv, x: jwk.x, y: jwk.y } }));
  ')
  if [ -z "${WALTID_VERIFIER_KEY}" ];
  then
    [ -n "${xtrace_was_on}" ] && set -x
    echo "ERROR: could not generate the walt.id verifier key." >&2
    exit 1
  fi
  export WALTID_VERIFIER_KEY

  [ -n "${xtrace_was_on}" ] && set -x
  echo "Generated a fresh walt.id verifier request-signing key for this run (P-256)."
  echo "Leaving generateWaltidVerifierKey()."
}

# ---------------------------------------------------------------------------
# Render the walt.id configuration with this run's values written in.
#
# waltid/config/*.conf are templates that name their inputs as ${WALTID_...}.
# They could be mounted as they are and left for the config loader to expand —
# walt.id's own files rely on exactly that — but a third party's expansion rules
# are not something to bet a test run on: when it does not happen the service
# dies before it listens, and all you get is a 502 from the proxy in front of it.
#
# So the values are substituted HERE, and the container mounts the rendered
# copies. Nothing is left to interpret, and when something is wrong the effective
# configuration is a file you can read.
#
# The rendered directory is gitignored: it holds this run's private key.
# ---------------------------------------------------------------------------
renderWaltidConfig()
{
  echo "Entering renderWaltidConfig()."
  local xtrace_was_on=""
  case "$-" in
    *x*) xtrace_was_on="yes"; set +x ;;
  esac

  local repo_root="${1:-.}"
  # Two services, two configuration trees, rendered into two directories: the
  # issuer must not be handed the verifier's files (walt.id's config loader reads
  # whatever is in the directory it is given) and the verifier must not be handed
  # the issuer's.
  local template_dir="${repo_root}/waltid/config"
  local out_dir="${repo_root}/waltid/generated-config"
  local verifier_template_dir="${repo_root}/waltid/verifier-config"
  local verifier_out_dir="${repo_root}/waltid/generated-verifier-config"

  if [ ! -d "${template_dir}" ];
  then
    [ -n "${xtrace_was_on}" ] && set -x
    echo "ERROR: ${template_dir} does not exist; cannot render the walt.id configuration." >&2
    exit 1
  fi
  if [ -z "${WALTID_KEY_D:-}" ] || [ -z "${WALTID_BASE_URL:-}" ];
  then
    [ -n "${xtrace_was_on}" ] && set -x
    echo "ERROR: renderWaltidConfig needs WALTID_BASE_URL and the issuer key. Call generateWaltidIssuerKey first, and set WALTID_BASE_URL to the address the BROWSER uses." >&2
    exit 1
  fi

  rm -rf "${out_dir}"
  mkdir -p "${out_dir}"
  check_return_code $?

  # Only the names this deployment defines are substituted; anything else in the
  # templates — ${defaultIssuerKey} and friends — is HOCON's own referencing and
  # must survive untouched.
  WALTID_TEMPLATE_DIR="${template_dir}" WALTID_OUT_DIR="${out_dir}" node -e '
    var fs = require("fs");
    var path = require("path");
    var names = ["WALTID_BASE_URL", "WALTID_CI_TOKEN_KEY", "WALTID_ISSUER_DID",
                 "WALTID_KEY_D", "WALTID_KEY_X", "WALTID_KEY_Y",
                 "WALTID_KEYCLOAK_AUTHORIZE_URL", "WALTID_KEYCLOAK_TOKEN_URL",
                 "WALTID_KEYCLOAK_CLIENT_ID", "WALTID_KEYCLOAK_CLIENT_SECRET",
                 // and the verifier ones
                 "WALTID_VERIFIER_BASE_URL", "WALTID_VERIFIER_CLIENT_ID",
                 "WALTID_VERIFIER_KEY"];
    var from = process.env.WALTID_TEMPLATE_DIR;
    var to = process.env.WALTID_OUT_DIR;
    var missing = [];
    var rendered = [];
    fs.readdirSync(from).filter(function (f) { return /\.conf$/.test(f); }).forEach(function (f) {
      var text = fs.readFileSync(path.join(from, f), "utf8");
      names.forEach(function (name) {
        if (text.indexOf("${" + name + "}") === -1) return;
        var value = process.env[name];
        if (value === undefined || value === "") {
          if (missing.indexOf(name) === -1) missing.push(name);
          return;
        }
        text = text.split("${" + name + "}").join(value);
      });
      fs.writeFileSync(path.join(to, f), text);
      rendered.push(f);
    });
    if (missing.length) {
      console.error("ERROR: the walt.id configuration references " + missing.join(", ") +
                    ", which are not set.");
      process.exit(1);
    }
    console.log("Rendered " + rendered.length + " walt.id configuration file(s): " + rendered.join(", "));
  '
  local rc=$?
  [ -n "${xtrace_was_on}" ] && set -x
  check_return_code ${rc}

  # The verifier's tree, when this deployment has one. Skipped rather than fatal:
  # a checkout that predates the verifier, or a run that only wants the issuer,
  # should still work.
  if [ -d "${verifier_template_dir}" ] && [ -n "${WALTID_VERIFIER_BASE_URL:-}" ];
  then
    rm -rf "${verifier_out_dir}"
    mkdir -p "${verifier_out_dir}"
    check_return_code $?
    WALTID_TEMPLATE_DIR="${verifier_template_dir}" WALTID_OUT_DIR="${verifier_out_dir}" \
      WALTID_VERIFIER_CLIENT_ID="${WALTID_VERIFIER_CLIENT_ID:-verifier2}" node -e '
      var fs = require("fs");
      var path = require("path");
      var names = ["WALTID_VERIFIER_BASE_URL", "WALTID_VERIFIER_CLIENT_ID", "WALTID_VERIFIER_KEY"];
      var from = process.env.WALTID_TEMPLATE_DIR;
      var to = process.env.WALTID_OUT_DIR;
      var missing = [];
      var rendered = [];
      fs.readdirSync(from).filter(function (f) { return /\.conf$/.test(f); }).forEach(function (f) {
        var text = fs.readFileSync(path.join(from, f), "utf8");
        names.forEach(function (name) {
          if (text.indexOf("${" + name + "}") === -1) return;
          var value = process.env[name];
          if (value === undefined || value === "") {
            if (missing.indexOf(name) === -1) missing.push(name);
            return;
          }
          text = text.split("${" + name + "}").join(value);
        });
        fs.writeFileSync(path.join(to, f), text);
        rendered.push(f);
      });
      if (missing.length) {
        console.error("ERROR: the walt.id verifier configuration references " + missing.join(", ") +
                      ", which are not set.");
        process.exit(1);
      }
      console.log("Rendered " + rendered.length + " walt.id verifier configuration file(s): " +
                  rendered.join(", "));
    '
    local vrc=$?
    check_return_code ${vrc}
    if grep -l '\${WALTID_' "${verifier_out_dir}"/*.conf >/dev/null 2>&1;
    then
      echo "ERROR: the rendered walt.id VERIFIER configuration still contains \${WALTID_...} references:" >&2
      grep -n '\${WALTID_' "${verifier_out_dir}"/*.conf >&2
      exit 1
    fi
  else
    echo "No walt.id verifier configuration to render (WALTID_VERIFIER_BASE_URL unset or ${verifier_template_dir} missing)."
  fi

  # Anything left unexpanded would be read literally by the service, so say so
  # here rather than letting it fail as a connection refused later.
  if grep -l '\${WALTID_' "${out_dir}"/*.conf >/dev/null 2>&1;
  then
    echo "ERROR: the rendered walt.id configuration still contains \${WALTID_...} references:" >&2
    grep -n '\${WALTID_' "${out_dir}"/*.conf >&2
    exit 1
  fi
  echo "Leaving renderWaltidConfig()."
}

# ---------------------------------------------------------------------------
# Wait for the walt.id services to answer.
#
# Both are JVM services that take tens of seconds to start listening. The
# containerized stack waits on compose healthchecks; the local one has only a
# fixed sleep, which is not always enough — and a walt.id job that starts too
# early fails with a connection error that looks nothing like the real cause.
#
# Bounded, and deliberately NOT fatal: a run may legitimately not have these
# containers, and the jobs that need them are skipped or fail on their own with a
# clearer message than this could give.
#
# Takes the compose file as an optional argument, used only to fetch a container's
# log when the wait times out. See reportContainerLog().
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Print the tail of a walt.id container's own log.
#
# Called only after a wait has timed out, and it exists because of how these
# side-cars fail. walt.id loads its configuration with Hoplite, and a value of the
# wrong SHAPE (a JSON object written as a quoted string, say) makes it exit during
# startup, before it ever listens; all that is left then is a 502 from the CORS
# proxy in front of it, which names the proxy rather than the reason. The WS-Fed
# Keycloak can likewise start and exit — `docker compose up -d` reports success
# either way, because it only asks that the container be *created* — and the only
# symptom is that provisioning finds nothing to talk to and the job is skipped.
#
# In both cases the reason is in the container's own log, so print it here rather
# than leaving it for someone to go find.
# ---------------------------------------------------------------------------
reportContainerLog()
{
  local compose_file="$1"
  local service="$2"
  if [ -z "${compose_file}" ] || [ ! -f "${compose_file}" ];
  then
    echo "  No compose file was passed, so ${service}'s log cannot be shown here. Try: docker logs ${service}" >&2
    return 0
  fi

  # Trace off: this function captures a whole container log into a variable, and
  # under `set -x` that assignment echoes the entire log inline before any of it is
  # printed deliberately. Restored on the way out, as in generateSpKeyPair().
  local xtrace_was_on=""
  case "$-" in
    *x*) xtrace_was_on="yes"; set +x ;;
  esac

  echo "  Whether ${service} is running at all:" >&2
  # None of this is gated on exit status: compose prints its own error into this
  # stream if the service is unknown or docker is unreachable, which is as much as
  # this diagnostic needs to convey. `ps -a` is what distinguishes "never created"
  # from "created and exited" — a distinction `up -d` does not report.
  docker_compose -f "${compose_file}" ps -a "${service}" 2>&1 | sed 's/^/    /' >&2

  # The FIRST errors, before the tail. A server that aborts its boot rolls back on
  # the way down, and the rollback is far more verbose than the failure: the last
  # 40 lines of a failed WildFly boot are all "stopping"/"unbound" noise plus one
  # secondary NullPointerException, while the error that actually killed it has
  # long scrolled past. Ask for the cause first, then the tail for context.
  local full
  full=$(docker_compose -f "${compose_file}" logs --no-color "${service}" 2>&1)
  local first_errors
  first_errors=$(printf '%s\n' "${full}" | grep -n -i -E "ERROR|FATAL|SEVERE|Caused by|WFLYCTL0013|WFLYSRV0055" | head -12)
  if [ -n "${first_errors}" ];
  then
    echo "  The first error lines in ${service}'s log (the cause is normally here, not at the end):" >&2
    printf '%s\n' "${first_errors}" | sed 's/^/    /' >&2
  fi
  echo "  The last lines of ${service}'s log (context, and the rollback if it failed to boot):" >&2
  printf '%s\n' "${full}" | tail -40 | sed 's/^/    /' >&2
  [ -n "${xtrace_was_on}" ] && set -x
  return 0
}

# ---------------------------------------------------------------------------
# Report any service in a compose file that is not running after `up`.
#
# `docker compose up -d` asks only that each container be CREATED and started; it
# returns 0 for a container that started and exited a second later. So a side-car
# can be dead for an entire run with nothing saying so — the WS-Federation Keycloak
# was, and the only visible consequence was its test quietly reporting SKIPPED
# because provisioning had nothing to talk to.
#
# Deliberately a warning rather than fatal: which services a run needs depends on
# the run (the interoperability jobs skip when theirs are absent), so this says
# plainly what is down and shows why, and lets the gating decide the rest. Use
# requireComposeServiceRunning() for a service the run cannot do without.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Is one compose service running? Echoes a human state and returns 0/1.
#
# This exists because `docker compose ps` output is NOT portable, and getting it
# wrong made an earlier version of this check declare a perfectly healthy
# container "absent" and stop the run. Two things differ by version:
#
#   * `--format` template FIELD NAMES. The Go template in a v2-era compose has
#     `.Service`; the v1-style table this project's compose prints has
#     `.Name/.Command/.State/.Ports` and no `.Service` at all, so
#     '{{.Service}} {{.State}}' renders as " Up (healthy)" — the service name is
#     empty and the first field is the state.
#   * the STATE WORDING itself: "running" in v2, "Up", "Up (healthy)" or
#     "Up 2 minutes" in v1.
#
# So the primary probe is `ps --services --filter status=running`, which prints
# nothing but service names and is understood by both, and the fallback reads the
# human table for this one service and looks for an Up/running token. Never parse
# a Go template here.
# ---------------------------------------------------------------------------
composeServiceState()
{
  local compose_file="$1"
  local service="$2"
  local running table

  running=$(docker_compose -f "${compose_file}" ps --services --filter status=running 2>/dev/null \
            | grep -v '^Entering\|^Leaving')
  if printf '%s\n' "${running}" | grep -qx -- "${service}";
  then
    echo "running"
    return 0
  fi

  # Either the service is not running, or this compose does not support the filter.
  # Ask about just this service and read the state column.
  table=$(docker_compose -f "${compose_file}" ps -a "${service}" 2>/dev/null \
          | grep -v '^Entering\|^Leaving')
  if printf '%s\n' "${table}" | grep -qE '(Up|running)';
  then
    echo "running"
    return 0
  fi
  if printf '%s\n' "${table}" | grep -qiE 'exit|dead|created|restarting|paused';
  then
    printf '%s\n' "${table}" | grep -iE 'exit|dead|created|restarting|paused' | head -1 \
      | sed 's/  */ /g' | cut -c1-90
    return 1
  fi
  echo "absent"
  return 1
}

# ---------------------------------------------------------------------------
# Require that one compose service is running, and FAIL if it is not.
#
# The other half of verifyComposeServicesRunning(): that one reports and carries
# on, this one returns non-zero so the caller's check_return_code stops the run at
# the point of failure, with the container's own log already printed.
#
# It waits, because "started" and "running a second later" are different questions
# and `up -d` only answers the first: a container that aborts its boot does so
# seconds after being created, so a check made immediately after `up` would see it
# running and pass. COMPOSE_SERVICE_WAIT_SECONDS (default 60) bounds the wait.
#
# "running" is the state asked for, not "healthy": readiness is a separate question
# that each service's own wait answers (waitForWaltid, configureKeycloakWsfed's
# token poll). What this catches is the container not being there at all.
# ---------------------------------------------------------------------------
requireComposeServiceRunning()
{
  echo "Entering requireComposeServiceRunning(). service=${2}"
  local compose_file="$1"
  local service="$2"
  if [ -z "${compose_file}" ] || [ ! -f "${compose_file}" ] || [ -z "${service}" ];
  then
    echo "ERROR: requireComposeServiceRunning() needs a compose file and a service name (got '${compose_file}' '${service}')." >&2
    return 1
  fi

  # Trace off: the poll below would otherwise print the whole ps output on every
  # iteration. Restored on every exit path.
  local xtrace_was_on=""
  case "$-" in
    *x*) xtrace_was_on="yes"; set +x ;;
  esac

  local deadline state waited
  deadline=$(( $(date +%s) + ${COMPOSE_SERVICE_WAIT_SECONDS:-60} ))
  while :;
  do
    state=$(composeServiceState "${compose_file}" "${service}")
    if [ "${state}" = "running" ];
    then
      break
    fi
    waited=$(( $(date +%s) ))
    if [ "${waited}" -ge "${deadline}" ];
    then
      echo "ERROR: the compose service '${service}' is not running (state: ${state:-absent}), so this run cannot" >&2
      echo "       continue. 'docker compose up' reports success for a container that was created and then" >&2
      echo "       exited, which is why this is checked separately." >&2
      reportContainerLog "${compose_file}" "${service}"
      [ -n "${xtrace_was_on}" ] && set -x
      return 1
    fi
    sleep 3
  done

  [ -n "${xtrace_was_on}" ] && set -x
  echo "Leaving requireComposeServiceRunning(). ${service} is running."
  return 0
}

verifyComposeServicesRunning()
{
  echo "Entering verifyComposeServicesRunning()."
  local compose_file="$1"
  if [ -z "${compose_file}" ] || [ ! -f "${compose_file}" ];
  then
    echo "verifyComposeServicesRunning(): no compose file given; nothing to check."
    return 0
  fi

  # This file runs under `set -x`, and the loop below compares two multi-line
  # lists — traced, that prints the whole service list on every iteration and
  # buries the one line that matters. Trace off for the duration, restored on the
  # way out, the same as generateSpKeyPair().
  local xtrace_was_on=""
  case "$-" in
    *x*) xtrace_was_on="yes"; set +x ;;
  esac

  local expected running down_list service
  # docker_compose() echoes Entering/Leaving into stdout, so drop those lines.
  expected=$(docker_compose -f "${compose_file}" config --services 2>/dev/null | grep -v '^Entering\|^Leaving')
  # Service names only, never a Go template — see composeServiceState().
  running=$(docker_compose -f "${compose_file}" ps --services --filter status=running 2>/dev/null \
            | grep -v '^Entering\|^Leaving')
  if [ -z "${expected}" ];
  then
    echo "verifyComposeServicesRunning(): could not read the service list from ${compose_file}; skipping the check." >&2
    [ -n "${xtrace_was_on}" ] && set -x
    return 0
  fi

  down_list=""
  for service in ${expected};
  do
    if echo "${running}" | grep -qx "${service}";
    then
      continue
    fi
    # Not in the filtered list. Confirm per-service before calling it down: if this
    # compose did not understand --filter, that list is empty and EVERY service
    # would look dead.
    if [ "$(composeServiceState "${compose_file}" "${service}")" != "running" ];
    then
      down_list="${down_list} ${service}"
    fi
  done

  if [ -n "${down_list}" ];
  then
    echo "WARNING: these compose services are NOT running after 'up -d':${down_list}" >&2
    echo "         Tests that need them will fail or be skipped. Each one's status and log follows." >&2
    for service in ${down_list};
    do
      reportContainerLog "${compose_file}" "${service}"
    done
  else
    echo "All services in ${compose_file} are running."
  fi
  [ -n "${xtrace_was_on}" ] && set -x
  echo "Leaving verifyComposeServicesRunning()."
  return 0
}

waitForWaltid()
{
  echo "Entering waitForWaltid()."
  local compose_file="${1:-${WALTID_COMPOSE_FILE:-}}"
  local issuer_probe="${WALTID_ISSUER_URL:-}"
  local verifier_probe="${WALTID_VERIFIER_URL:-}"
  local deadline=$(( $(date +%s) + ${WALTID_WAIT_SECONDS:-180} ))

  if [ -n "${issuer_probe}" ];
  then
    echo "Waiting for walt.id's issuer at ${issuer_probe} ..."
    until curl -fsS -o /dev/null --max-time 5 \
            "${issuer_probe}/.well-known/openid-credential-issuer/openid4vci" 2>/dev/null;
    do
      if [ "$(date +%s)" -ge "${deadline}" ];
      then
        echo "WARNING: walt.id's issuer did not answer at ${issuer_probe} within the wait." >&2
        reportContainerLog "${compose_file}" "waltid-issuer-api"
        break
      fi
      sleep 5
    done
  fi

  if [ -n "${verifier_probe}" ];
  then
    echo "Waiting for walt.id's verifier at ${verifier_probe} ..."
    # /livez is what walt.id's service-commons registers for every service.
    until curl -fsS -o /dev/null --max-time 5 "${verifier_probe}/livez" 2>/dev/null;
    do
      if [ "$(date +%s)" -ge "${deadline}" ];
      then
        echo "WARNING: walt.id's verifier did not answer at ${verifier_probe} within the wait." >&2
        reportContainerLog "${compose_file}" "waltid-verifier-api"
        break
      fi
      sleep 5
    done
  fi
  echo "Leaving waitForWaltid()."
}

# ---------------------------------------------------------------------------
# Delete the debugger-testing realm if it exists, so configureKeycloak re-creates
# every client with redirectUris / webOrigins matching the CURRENT
# DEBUGGER_BASE_URL, and re-provisions users from scratch. Two things depend on
# this: (1) switching targets (local -> test -> prod) must not leave stale
# redirect URIs from a previous run; (2) the containerized run relies on a fresh
# Keycloak DB, but its only guarantee of one is docker-run-tests.sh's startup
# `down -v`, which is best-effort (swallowed under docker-compose v1). If that
# leaves a stale realm behind, re-provisioning 409s ("Failed to create SAML
# user"); deleting the realm here makes provisioning idempotent regardless.
resetKeycloakRealm()
{
  echo "Entering resetKeycloakRealm()."
  local token
  token=$(curl -s \
    -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=admin-cli" \
    -d "username=keycloak" \
    -d "password=keycloak" \
    -d "grant_type=password" | jq -r '.access_token')
  if [ -z "${token}" ] || [ "${token}" = "null" ];
  then
    echo "ERROR: could not authenticate to Keycloak at ${KEYCLOAK_LOCALHOST_BASE_URL}." >&2
    echo "       Is Keycloak running there with admin keycloak/keycloak?" >&2
    exit 1
  fi
  # 404 if the realm doesn't exist yet — harmless.
  curl -s -o /dev/null -X DELETE \
    "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing" \
    -H "Authorization: Bearer ${token}"
  echo "Leaving resetKeycloakRealm()."
}

configureKeycloak()
{
  echo "Entering configureKeycloak()."
  # Configure Keycloak
  KEYCLOAK_ACCESS_TOKEN=$(curl \
    -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=admin-cli" \
    -d "username=keycloak" \
    -d "password=keycloak" \
    -d "grant_type=password" |\
    jq -r '.access_token')
  if [ -z "${KEYCLOAK_ACCESS_TOKEN}" ];
  then
    echo "Failed to obtain access token." 
      exit 1
  fi
  
  curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms" \
    -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"realm": "debugger-testing", "enabled": true}'
  check_return_code $?
  
  for FLOW_VARIABLE in CLIENT_CREDENTIALS AUTHORIZATION_CODE_CONFIDENTIAL AUTHORIZATION_CODE_PUBLIC IMPLICIT OIDC_AUTHORIZATION_CODE_CONFIDENTIAL OIDC_AUTHORIZATION_CODE_PUBLIC RESOURCE_OWNER_CREDENTIAL TOKEN_EXCHANGE_TARGET TOKEN_EXCHANGE DEVICE_AUTHORIZATION_GRANT TOKEN_INTROSPECTION
  do
    FLOW_NAME=$(echo ${FLOW_VARIABLE} | tr '[:upper:]' '[:lower:]' | tr '_' '-')

    KEYCLOAK_ACCESS_TOKEN=$(curl \
      -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/realms/master/protocol/openid-connect/token" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "client_id=admin-cli" \
      -d "username=keycloak" \
      -d "password=keycloak" \
      -d "grant_type=password" \
      | jq -r '.access_token')
    if [ -z "${KEYCLOAK_ACCESS_TOKEN}" ];
    then
      echo "KEYCLOAK_ACCESS_TOKEN is blank."
      exit 1
    fi
    curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/client-scopes" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      -H "Content-Type: application/json" \
      -d '{
            "name": "'${FLOW_NAME}'-scope",
            "protocol": "openid-connect",
            "attributes": {
              "display.on.consent.screen": "false",
              "include.in.token.scope": "true"
            }
         }'
    check_return_code $?
    case "${FLOW_VARIABLE}" in
        CLIENT_CREDENTIALS)
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                 "clientId": "'${FLOW_NAME}'",
                 "protocol": "openid-connect",
                 "publicClient": false,
                 "serviceAccountsEnabled": true,
                 "authorizationServicesEnabled": false,
                 "standardFlowEnabled": false,
                 "directAccessGrantsEnabled": false,
                 "clientAuthenticatorType": "client-secret",
                 "webOrigins": ["'${DEBUGGER_BASE_URL}'"]
               }'
            check_return_code $?
            ;;
        AUTHORIZATION_CODE_CONFIDENTIAL)
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                   "clientId": "'${FLOW_NAME}'", 
                   "protocol": "openid-connect", 
                   "publicClient": false, 
                   "serviceAccountsEnabled": false, 
                   "authorizationServicesEnabled": false, 
                   "standardFlowEnabled": true, 
                   "directAccessGrantsEnabled": false, 
                   "clientAuthenticatorType": "client-secret", 
                   "frontchannelLogout": true, 
                   "redirectUris": ["'${DEBUGGER_BASE_URL}/callback'"], 
                   "webOrigins": ["'${DEBUGGER_BASE_URL}'"], 
                   "attributes": {
                     "frontchannel.logout.url": "'${DEBUGGER_BASE_URL}/logout.html'",
                     "post.logout.redirect.uris": "'${DEBUGGER_BASE_URL}/logout.html'",
                     "access.token.lifespan": 3600
                   }
                }'
            check_return_code $?
            ;;
        AUTHORIZATION_CODE_PUBLIC)
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                "clientId": "'${FLOW_NAME}'", 
                "protocol": "openid-connect", 
                "publicClient": true, 
                "serviceAccountsEnabled": false, 
                "authorizationServicesEnabled": false, 
                "standardFlowEnabled": true, 
                "directAccessGrantsEnabled": false, 
                "clientAuthenticatorType": null, 
                "frontchannelLogout": true, 
                "redirectUris": ["'${DEBUGGER_BASE_URL}/callback'"], 
                "webOrigins": ["'${DEBUGGER_BASE_URL}'"], 
                "attributes": {
                  "frontchannel.logout.url": "'${DEBUGGER_BASE_URL}/logout.html'",
                  "post.logout.redirect.uris": "'${DEBUGGER_BASE_URL}/logout.html'",
                  "access.token.lifespan": 3600
                }
             }'
            ;;
        IMPLICIT)
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                "clientId": "'${FLOW_NAME}'",
                "protocol": "openid-connect",
                "publicClient": true,
                "serviceAccountsEnabled": false,
                "authorizationServicesEnabled": false,
                "standardFlowEnabled": true,
                "implicitFlowEnabled": true,
                "directAccessGrantsEnabled": false,
                "clientAuthenticatorType": null,
                "frontchannelLogout": true,
                "redirectUris": ["'${DEBUGGER_BASE_URL}/callback'"],
                "webOrigins": ["'${DEBUGGER_BASE_URL}'"],
                "attributes": {
                  "frontchannel.logout.url": "'${DEBUGGER_BASE_URL}/logout.html'",
                  "post.logout.redirect.uris": "'${DEBUGGER_BASE_URL}/logout.html'",
                  "access.token.lifespan": 3600
                }
             }'
            check_return_code $?
            ;;
        OIDC_AUTHORIZATION_CODE_PUBLIC)
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                "clientId": "'${FLOW_NAME}'",
                "protocol": "openid-connect",
                "publicClient": true,
                "serviceAccountsEnabled": false,
                "authorizationServicesEnabled": false,
                "standardFlowEnabled": true,
                "directAccessGrantsEnabled": false,
                "clientAuthenticatorType": null,
                "frontchannelLogout": true,
                "redirectUris": ["'${DEBUGGER_BASE_URL}/callback'"],
                "webOrigins": ["'${DEBUGGER_BASE_URL}'"],
                "attributes": {
                  "frontchannel.logout.url": "'${DEBUGGER_BASE_URL}/logout.html'",
                  "post.logout.redirect.uris": "'${DEBUGGER_BASE_URL}/logout.html'",
                  "access.token.lifespan": 3600
                }
             }'
            check_return_code $?
            ;;
        OIDC_AUTHORIZATION_CODE_CONFIDENTIAL)
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                   "clientId": "'${FLOW_NAME}'",
                   "protocol": "openid-connect",
                   "publicClient": false,
                   "serviceAccountsEnabled": false,
                   "authorizationServicesEnabled": false,
                   "standardFlowEnabled": true,
                   "directAccessGrantsEnabled": false,
                   "clientAuthenticatorType": "client-secret",
                   "frontchannelLogout": true,
                   "redirectUris": ["'${DEBUGGER_BASE_URL}/callback'"],
                   "webOrigins": ["'${DEBUGGER_BASE_URL}'"],
                   "attributes": {
                     "frontchannel.logout.url": "'${DEBUGGER_BASE_URL}/logout.html'",
                     "post.logout.redirect.uris": "'${DEBUGGER_BASE_URL}/logout.html'",
                     "access.token.lifespan": 3600
                   }
                }'
            check_return_code $?
            ;;
        RESOURCE_OWNER_CREDENTIAL)
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                   "clientId": "'${FLOW_NAME}'",
                   "protocol": "openid-connect",
                   "publicClient": false,
                   "serviceAccountsEnabled": false,
                   "authorizationServicesEnabled": false,
                   "standardFlowEnabled": false,
                   "directAccessGrantsEnabled": true,
                   "clientAuthenticatorType": "client-secret",
                   "frontchannelLogout": true,
                   "redirectUris": ["'${DEBUGGER_BASE_URL}/callback'"],
                   "webOrigins": ["'${DEBUGGER_BASE_URL}'"],
                   "attributes": {
                     "frontchannel.logout.url": "'${DEBUGGER_BASE_URL}/logout.html'",
                     "post.logout.redirect.uris": "'${DEBUGGER_BASE_URL}/logout.html'",
                     "access.token.lifespan": 3600
                   }
                }'
            check_return_code $?
            ;;
        TOKEN_EXCHANGE_TARGET)
            # Audience (target) client for RFC 8693 token exchange. A token
            # exchange request can ask for a token aimed at this client via the
            # "audience" parameter.
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                   "clientId": "'${FLOW_NAME}'",
                   "protocol": "openid-connect",
                   "publicClient": false,
                   "serviceAccountsEnabled": false,
                   "authorizationServicesEnabled": false,
                   "standardFlowEnabled": true,
                   "directAccessGrantsEnabled": false,
                   "clientAuthenticatorType": "client-secret",
                   "frontchannelLogout": true,
                   "redirectUris": ["'${DEBUGGER_BASE_URL}/callback'"],
                   "webOrigins": ["'${DEBUGGER_BASE_URL}'"],
                   "attributes": {
                     "access.token.lifespan": 3600
                   }
                }'
            check_return_code $?
            ;;
        TOKEN_EXCHANGE)
            # Requesting client for RFC 8693 Standard Token Exchange (v2). It
            # obtains a subject token via the Authorization Code flow and then
            # exchanges it. Keycloak requires the requesting client to be in the
            # subject token's audience, so an audience mapper adds this client
            # (and the target client) to the access token's "aud" claim.
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                   "clientId": "'${FLOW_NAME}'",
                   "protocol": "openid-connect",
                   "publicClient": false,
                   "serviceAccountsEnabled": false,
                   "authorizationServicesEnabled": false,
                   "standardFlowEnabled": true,
                   "directAccessGrantsEnabled": true,
                   "clientAuthenticatorType": "client-secret",
                   "frontchannelLogout": true,
                   "redirectUris": ["'${DEBUGGER_BASE_URL}/callback'"],
                   "webOrigins": ["'${DEBUGGER_BASE_URL}'"],
                   "attributes": {
                     "frontchannel.logout.url": "'${DEBUGGER_BASE_URL}/logout.html'",
                     "post.logout.redirect.uris": "'${DEBUGGER_BASE_URL}/logout.html'",
                     "access.token.lifespan": 3600,
                     "standard.token.exchange.enabled": "true"
                   },
                   "protocolMappers": [
                     {
                       "name": "token-exchange-self-audience",
                       "protocol": "openid-connect",
                       "protocolMapper": "oidc-audience-mapper",
                       "config": {
                         "included.client.audience": "'${FLOW_NAME}'",
                         "id.token.claim": "false",
                         "access.token.claim": "true"
                       }
                     },
                     {
                       "name": "token-exchange-target-audience",
                       "protocol": "openid-connect",
                       "protocolMapper": "oidc-audience-mapper",
                       "config": {
                         "included.client.audience": "token-exchange-target",
                         "id.token.claim": "false",
                         "access.token.claim": "true"
                       }
                     }
                   ]
                }'
            check_return_code $?
            ;;
        DEVICE_AUTHORIZATION_GRANT)
            # Public client with the OAuth 2.0 Device Authorization Grant
            # (RFC 8628) enabled. The device flow does not use a browser
            # redirect, so the standard/auth-code flow is disabled.
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                   "clientId": "'${FLOW_NAME}'",
                   "protocol": "openid-connect",
                   "publicClient": true,
                   "serviceAccountsEnabled": false,
                   "authorizationServicesEnabled": false,
                   "standardFlowEnabled": false,
                   "directAccessGrantsEnabled": false,
                   "clientAuthenticatorType": null,
                   "webOrigins": ["'${DEBUGGER_BASE_URL}'"],
                   "attributes": {
                     "oauth2.device.authorization.grant.enabled": "true",
                     "access.token.lifespan": 3600
                   }
                }'
            check_return_code $?
            ;;
        TOKEN_INTROSPECTION)
            # Confidential Authorization Code client used by the Token
            # Introspection test. It is BOTH the client that signs in (via the
            # OIDC Authorization Code flow, to obtain the tokens) AND the client
            # that authenticates the RFC 7662 introspection calls. This is
            # required because Keycloak gates token introspection on the calling
            # client:
            #   - Access tokens: the client must be in the token's "aud", so an
            #     audience mapper adds this client to its own access tokens.
            #   - Refresh tokens: the client must be the one the token was issued
            #     to (azp); no audience mapper or role grants cross-client
            #     refresh-token introspection. A public client cannot call the
            #     introspection endpoint at all.
            # A single confidential client that owns the tokens and is in their
            # audience is therefore the only setup for which all of the debugger's
            # Introspect Token links report "active": true.
            curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
              -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
              -H "Content-Type: application/json" \
              -d '{
                "clientId": "'${FLOW_NAME}'",
                "protocol": "openid-connect",
                "publicClient": false,
                "serviceAccountsEnabled": false,
                "authorizationServicesEnabled": false,
                "standardFlowEnabled": true,
                "directAccessGrantsEnabled": false,
                "clientAuthenticatorType": "client-secret",
                "frontchannelLogout": true,
                "redirectUris": ["'${DEBUGGER_BASE_URL}/callback'"],
                "webOrigins": ["'${DEBUGGER_BASE_URL}'"],
                "attributes": {
                  "frontchannel.logout.url": "'${DEBUGGER_BASE_URL}/logout.html'",
                  "post.logout.redirect.uris": "'${DEBUGGER_BASE_URL}/logout.html'",
                  "access.token.lifespan": 3600
                },
                "protocolMappers": [
                  {
                    "name": "token-introspection-self-audience",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-audience-mapper",
                    "config": {
                      "included.client.audience": "'${FLOW_NAME}'",
                      "id.token.claim": "false",
                      "access.token.claim": "true"
                    }
                  }
                ]
             }'
            check_return_code $?
            ;;
    esac

    CLIENT_ID=$(curl \
      -X GET \
      "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients?clientId=${FLOW_NAME}" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      | jq -r '.[0].id')
    CLIENT_CLIENTID=$(curl \
      -X GET \
      "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients?clientId=${FLOW_NAME}" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      | jq -r '.[0].clientId')
    CLIENT_SECRET=$(curl  \
      -X GET \
     "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients?clientId=${FLOW_NAME}" \
     -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
     | jq -r '.[0].secret')
    SCOPE_ID=$(curl \
      -X GET \
      "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/client-scopes" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      | jq -r '.[] | select(.name=="'${FLOW_NAME}'-scope") | .id')
    SCOPE_NAME=$(curl \
      -X GET \
      "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/client-scopes" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      | jq -r '.[] | select(.name=="'${FLOW_NAME}'-scope") | .name')
    curl \
     -X PUT \
     "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients/${CLIENT_ID}/optional-client-scopes/${SCOPE_ID}" \
     -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}"
    check_return_code $?
    USER_ID=$(curl \
      -X POST \
      "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/users" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      -H "Content-Type: application/json" \
      -d '{ 
            "username": "'${FLOW_NAME}'",
            "firstName": "'${FLOW_NAME}'", 
            "lastName": "'${FLOW_NAME}'", 
            "email": "'${FLOW_NAME}'@iyasec.io", 
            "enabled": true, "emailVerified": true
          }' \
      -i \
      | grep Location \
      | rev \
      | cut -d '/' -f 1 \
      | rev \
      | tr -d ' \n\r')
    if [ -z "${CLIENT_ID}" ] || \
       [ -z "${CLIENT_CLIENTID}" ] || \
       [ -z "${CLIENT_SECRET}" ] || \
       [ -z "${SCOPE_ID}" ] || \
       [ -z "${SCOPE_NAME}" ] || \
       [ -z "${USER_ID}" ];
    then
      echo "Required variable is blank."
      exit 1
    fi 
    curl \
      -X PUT \
      "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/users/${USER_ID}/reset-password" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      -H "Content-Type: application/json" \
      -d '{
            "type": "password",
            "value": "'${FLOW_NAME}'",
            "temporary": false
          }'
    check_return_code $?

    # -gx (export) so child processes — e.g. tests/run-report.js — inherit these
    declare -gx ${FLOW_VARIABLE}_AUDIENCE="${KEYCLOAK_BASE_URL}/realms/debugger-testing"
    declare -gx ${FLOW_VARIABLE}_DISCOVERY_ENDPOINT="${KEYCLOAK_BASE_URL}/realms/debugger-testing/.well-known/openid-configuration"
    declare -gx ${FLOW_VARIABLE}_CLIENT_ID="${CLIENT_CLIENTID}"
    declare -gx ${FLOW_VARIABLE}_CLIENT_SECRET="${CLIENT_SECRET}"
    declare -gx ${FLOW_VARIABLE}_SCOPE="${SCOPE_NAME}"
    declare -gx ${FLOW_VARIABLE}_USER="${USER_ID}"

  done

  # ---- SAML 2.0 client + user -----------------------------------------------
  # Provisioned outside the loop above (which is OIDC-specific: it requires a
  # client secret and attaches OIDC client-scopes). This SAML SP client is used
  # by the SAML Test Tools workflow / tests/saml_sso.js.
  #
  # The client's clientId IS the SP entityID (must equal the AuthnRequest Issuer
  # the client sends — client env spEntityId). Client signature validation is
  # ENABLED: the SP signing certificate generated for THIS run
  # (generateSpKeyPair, provided as SAML_SP_SIGNING_CERT) is registered here, and
  # tests/saml_sso.js signs the AuthnRequest with the matching private key from
  # SAML_SP_PRIVATE_KEY, so Keycloak validates the request signature. No key pair
  # is stored in this repository.
  SAML_SP_ENTITY_ID="${SAML_SP_ENTITY_ID:-http://localhost:3000/saml/sp}"
  SAML_API_BASE_URL="${API_BASE_URL:-http://localhost:4000}"
  # ACS / SLO service URLs registered on the Keycloak client (the endpoints the
  # IdP returns its response to). Default to the api's /samlacs & /samlslo, but
  # allow the run script to override: a BACKENDLESS (static) deployment has no
  # server to receive the response, so remote-run-tests.sh points these at the
  # static saml_response.html page, and the client requests the Redirect binding
  # so the browser reads the response from the URL (no server round-trip).
  SAML_ACS_URL="${SAML_ACS_URL:-${SAML_API_BASE_URL}/samlacs}"
  SAML_SLO_URL="${SAML_SLO_URL:-${SAML_API_BASE_URL}/samlslo}"
  # AuthnRequest signature validation. Enabled by default (registers this run's
  # generated SP signing cert so the signed requests from tests/saml_sso.js
  # validate). Set
  # SAML_SIG_VALIDATION=false (local-run-tests.sh --saml-dev) to turn it off so a
  # browser-generated / unregistered SP key can drive the SAML flow manually.
  SAML_SIG_VALIDATION="${SAML_SIG_VALIDATION:-true}"
  if [ "${SAML_SIG_VALIDATION}" = "false" ] || [ "${SAML_SIG_VALIDATION}" = "0" ]; then
    echo "SAML: AuthnRequest signature validation DISABLED on the Keycloak client."
    SAML_SIG_ATTRS='"saml.authnrequest.signed": "false", "saml.client.signature": "false",'
  else
    if [ -z "${SAML_SP_SIGNING_CERT}" ]; then
      echo "SAML_SP_SIGNING_CERT is blank. The run script must call generateSpKeyPair (common/common.sh) so Keycloak can validate the AuthnRequest signature."
      exit 1
    fi
    SAML_SIG_ATTRS='"saml.authnrequest.signed": "true", "saml.client.signature": "true", "saml.signing.certificate": "'"${SAML_SP_SIGNING_CERT}"'",'
  fi

  KEYCLOAK_ACCESS_TOKEN=$(curl \
    -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=admin-cli" -d "username=keycloak" -d "password=keycloak" \
    -d "grant_type=password" | jq -r '.access_token')
  if [ -z "${KEYCLOAK_ACCESS_TOKEN}" ]; then
    echo "KEYCLOAK_ACCESS_TOKEN is blank (SAML)."
    exit 1
  fi

  curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
    -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
          "clientId": "'"${SAML_SP_ENTITY_ID}"'",
          "name": "saml",
          "protocol": "saml",
          "enabled": true,
          "frontchannelLogout": true,
          "redirectUris": ["'"${SAML_ACS_URL}"'", "'"${SAML_API_BASE_URL}"'/*"],
          "attributes": {
            '"${SAML_SIG_ATTRS}"'
            "saml.server.signature": "true",
            "saml.assertion.signature": "true",
            "saml_name_id_format": "username",
            "saml.force.post.binding": "false",
            "saml_assertion_consumer_url_post": "'"${SAML_ACS_URL}"'",
            "saml_assertion_consumer_url_redirect": "'"${SAML_ACS_URL}"'",
            "saml_single_logout_service_url_post": "'"${SAML_SLO_URL}"'",
            "saml_single_logout_service_url_redirect": "'"${SAML_SLO_URL}"'"
          }
       }'
  check_return_code $?

  SAML_USER_ID=$(curl \
    -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/users" \
    -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{ "username": "saml", "firstName": "saml", "lastName": "saml",
          "email": "saml@iyasec.io", "enabled": true, "emailVerified": true }' \
    -i | grep Location | rev | cut -d '/' -f 1 | rev | tr -d ' \n\r')
  if [ -z "${SAML_USER_ID}" ]; then
    echo "Failed to create SAML user."
    exit 1
  fi
  curl -X PUT \
    "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/users/${SAML_USER_ID}/reset-password" \
    -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{ "type": "password", "value": "saml", "temporary": false }'
  check_return_code $?

  # SAML IdP metadata. By default the SAML tests drive metadata loading BY URL
  # (the page fetches the descriptor itself — directly in the browser, or via the
  # API metadata proxy when a backend is available). When SAML_METADATA_UPLOAD is
  # set, download the descriptor here and hand the tests a local file to UPLOAD
  # instead. That is required against a backend-less deployed target (e.g. the
  # static test.idptools.com site): the HTTPS page has no API proxy and can't
  # fetch the local http Keycloak descriptor cross-origin (blocked by CORS), so
  # an in-browser URL load can never succeed there.
  declare -gx SAML_METADATA_URL="${KEYCLOAK_BASE_URL}/realms/debugger-testing/protocol/saml/descriptor"
  if [ -n "${SAML_METADATA_UPLOAD}" ];
  then
    download_saml_metadata
    check_return_code $?
  fi
  declare -gx SAML_SP_ENTITY_ID
  declare -gx SAML_ACS_URL
  declare -gx SAML_SLO_URL
  declare -gx SAML_USER="saml"

  # ---- SAML 2.0 ENCRYPTED client (saml.encrypt=true) ------------------------
  # A SECOND SAML SP client used by tests/saml_encrypted_sso.js to exercise the
  # SAML Response page's EncryptedAssertion DECRYPTION. saml.encrypt is a
  # per-client attribute (no separate Keycloak needed): this client is identical
  # to the one above but adds saml.encrypt=true + saml.encryption.certificate set
  # to the SAME fixed test SP certificate. Keycloak therefore encrypts the
  # assertion to that cert; the Response page decrypts it with the matching
  # private key generated for this run. Only provisioned when the SP cert is
  # available (i.e. signature validation is enabled).
  SAML_ENC_SP_ENTITY_ID="${SAML_ENC_SP_ENTITY_ID:-${SAML_SP_ENTITY_ID}-enc}"
  if [ -n "${SAML_SP_SIGNING_CERT}" ];
  then
    KEYCLOAK_ACCESS_TOKEN=$(curl \
      -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/realms/master/protocol/openid-connect/token" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "client_id=admin-cli" -d "username=keycloak" -d "password=keycloak" \
      -d "grant_type=password" | jq -r '.access_token')
    if [ -z "${KEYCLOAK_ACCESS_TOKEN}" ]; then
      echo "KEYCLOAK_ACCESS_TOKEN is blank (SAML encrypted client)."
      exit 1
    fi
    curl -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
      -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
      -H "Content-Type: application/json" \
      -d '{
            "clientId": "'"${SAML_ENC_SP_ENTITY_ID}"'",
            "name": "saml-enc",
            "protocol": "saml",
            "enabled": true,
            "frontchannelLogout": true,
            "redirectUris": ["'"${SAML_ACS_URL}"'", "'"${SAML_API_BASE_URL}"'/*"],
            "attributes": {
              '"${SAML_SIG_ATTRS}"'
              "saml.server.signature": "true",
              "saml.assertion.signature": "true",
              "saml.encrypt": "true",
              "saml.encryption.certificate": "'"${SAML_SP_SIGNING_CERT}"'",
              "saml_name_id_format": "username",
              "saml.force.post.binding": "true",
              "saml_assertion_consumer_url_post": "'"${SAML_ACS_URL}"'",
              "saml_assertion_consumer_url_redirect": "'"${SAML_ACS_URL}"'",
              "saml_single_logout_service_url_post": "'"${SAML_SLO_URL}"'",
              "saml_single_logout_service_url_redirect": "'"${SAML_SLO_URL}"'"
            }
         }'
    check_return_code $?
    echo "SAML encrypted client provisioned: ${SAML_ENC_SP_ENTITY_ID}"
  else
    echo "SAML_SP_SIGNING_CERT is blank — skipping the encrypted SAML client (needs the SP encryption certificate)."
  fi
  declare -gx SAML_ENC_SP_ENTITY_ID

  # ---- OIDC Dynamic Client Registration --------------------------------------
  # Mint an initial access token so the Dynamic Client Registration test can
  # create clients. Keycloak requires an initial access token for authenticated
  # registration (anonymous registration is blocked by the default trusted-hosts
  # policy). The test then reads/updates/deletes the client it creates using the
  # registration access token returned at registration (RFC 7592).
  KEYCLOAK_ACCESS_TOKEN=$(curl \
    -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=admin-cli" \
    -d "username=keycloak" \
    -d "password=keycloak" \
    -d "grant_type=password" \
    | jq -r '.access_token')
  if [ -z "${KEYCLOAK_ACCESS_TOKEN}" ];
  then
    echo "KEYCLOAK_ACCESS_TOKEN is blank."
    exit 1
  fi
  DCR_INITIAL_ACCESS_TOKEN=$(curl \
    -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients-initial-access" \
    -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{ "count": 10, "expiration": 86400 }' \
    | jq -r '.token')
  if [ -z "${DCR_INITIAL_ACCESS_TOKEN}" ] || [ "${DCR_INITIAL_ACCESS_TOKEN}" = "null" ];
  then
    echo "Failed to mint a Dynamic Client Registration initial access token."
    exit 1
  fi
  declare -gx DYNAMIC_CLIENT_REGISTRATION_DISCOVERY_ENDPOINT="${KEYCLOAK_BASE_URL}/realms/debugger-testing/.well-known/openid-configuration"
  declare -gx DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN="${DCR_INITIAL_ACCESS_TOKEN}"

  # ---- the client the walt.id issuer authenticates End-Users with ------------
  # walt.id's issuer-api2 never authenticates anyone itself: its authorization
  # endpoint redirects to an external OpenID Provider and issues its own code
  # once that provider returns an id_token. This is that provider's client —
  # confidential, because walt.id makes a back-channel token call with a secret.
  #
  # The secret is a fixed test value, like the keycloak/keycloak admin password
  # this realm already uses: it is a throwaway client in a throwaway realm on a
  # private network, and both sides (this client and waltid/config) have to agree
  # on it before either starts.
  WALTID_KEYCLOAK_CLIENT_ID="${WALTID_KEYCLOAK_CLIENT_ID:-waltid-issuer}"
  WALTID_KEYCLOAK_CLIENT_SECRET="${WALTID_KEYCLOAK_CLIENT_SECRET:-waltid-issuer-test-secret}"
  # Where Keycloak sends the browser back to. It must match the callback route
  # walt.id serves, under whichever base URL that container was given.
  WALTID_ISSUER_BASE_URL="${WALTID_BASE_URL:-http://waltid-issuer:7005}"
  curl \
    -X POST "${KEYCLOAK_LOCALHOST_BASE_URL}/admin/realms/debugger-testing/clients" \
    -H "Authorization: Bearer ${KEYCLOAK_ACCESS_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
          "clientId": "'"${WALTID_KEYCLOAK_CLIENT_ID}"'",
          "name": "walt.id issuer (external authentication)",
          "protocol": "openid-connect",
          "enabled": true,
          "publicClient": false,
          "secret": "'"${WALTID_KEYCLOAK_CLIENT_SECRET}"'",
          "standardFlowEnabled": true,
          "directAccessGrantsEnabled": false,
          "serviceAccountsEnabled": false,
          "redirectUris": [
            "'"${WALTID_ISSUER_BASE_URL}"'/openid4vci/external/oauth/callback",
            "http://waltid-issuer:7005/openid4vci/external/oauth/callback",
            "http://localhost:7005/openid4vci/external/oauth/callback"
          ],
          "webOrigins": ["+"],
          "attributes": { "post.logout.redirect.uris": "+" }
        }'
  check_return_code $?
  echo "Registered the walt.id issuer's Keycloak client ${WALTID_KEYCLOAK_CLIENT_ID} (callback under ${WALTID_ISSUER_BASE_URL})."

  echo "Leaving configureKeycloak()."
}

# ---------------------------------------------------------------------------
# WS-Federation side-car provisioning (Keycloak 8.0.1 + cloudtrust keycloak-wsfed).
#
# A SEPARATE Keycloak used only by the WS-Federation debugger test — the main
# 26.x Keycloak has no WS-Fed support and the extension only targets 8.0.1. This
# provisions a 'wsfed'-protocol client (the relying party; clientId == wtrealm) +
# a test user on a dedicated realm, and exports the WSFED_* vars that
# tests/run-report.js passes to tests/wsfed_sso.js.
#
# It is a NO-OP unless KEYCLOAK_WSFED_LOCALHOST_BASE_URL is set (so every
# non-WS-Fed run is unaffected), and it degrades to a SKIP — warns and returns
# WITHOUT exporting WSFED_METADATA_URL, so the job is skipped rather than the
# suite aborting — on any provisioning failure.
#
# Keycloak 8.0.1 is WildFly-based: the admin REST API is under the /auth base
# path and the admin user comes from the side-car's KEYCLOAK_USER/PASSWORD.
# ---------------------------------------------------------------------------
configureKeycloakWsfed()
{
  if [ -z "${KEYCLOAK_WSFED_LOCALHOST_BASE_URL}" ];
  then
    echo "KEYCLOAK_WSFED_LOCALHOST_BASE_URL not set — skipping WS-Federation side-car provisioning."
    return 0
  fi
  echo "Entering configureKeycloakWsfed()."
  # Only used to fetch the container's log if the side-car never answers.
  WSFED_COMPOSE_FILE="${1:-${WSFED_COMPOSE_FILE:-}}"

  KC_WSFED="${KEYCLOAK_WSFED_LOCALHOST_BASE_URL}/auth"
  KC_WSFED_ADMIN_USER="${KEYCLOAK_WSFED_ADMIN_USER:-keycloak}"
  KC_WSFED_ADMIN_PASS="${KEYCLOAK_WSFED_ADMIN_PASSWORD:-keycloak}"
  WSFED_REALM_NAME="wsfed-testing"
  WSFED_WTREALM="${WSFED_REALM:-urn:wsfed:test:rp}"
  WSFED_API_BASE="${API_BASE_URL:-http://localhost:4000}"
  WSFED_UI_BASE="${DEBUGGER_BASE_URL:-http://localhost:3000}"

  # The 8.0.1 side-car boots slowly; poll its token endpoint before provisioning.
  KC_WSFED_TOKEN=""
  WSFED_TRY=0
  # 40 x 3s by default. Configurable so this function can be exercised without
  # waiting two minutes for a side-car that is known to be absent.
  WSFED_WAIT_TRIES="${WSFED_WAIT_TRIES:-40}"
  while [ ${WSFED_TRY} -lt ${WSFED_WAIT_TRIES} ];
  do
    KC_WSFED_TOKEN=$(curl -s -X POST "${KC_WSFED}/realms/master/protocol/openid-connect/token" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "client_id=admin-cli" -d "username=${KC_WSFED_ADMIN_USER}" \
      -d "password=${KC_WSFED_ADMIN_PASS}" -d "grant_type=password" \
      | jq -r '.access_token')
    if [ -n "${KC_WSFED_TOKEN}" ] && [ "${KC_WSFED_TOKEN}" != "null" ]; then break; fi
    WSFED_TRY=$((WSFED_TRY + 1))
    sleep 3
  done
  if [ -z "${KC_WSFED_TOKEN}" ] || [ "${KC_WSFED_TOKEN}" = "null" ];
  then
    echo "WARNING: the WS-Federation side-car never answered at ${KC_WSFED} (waited $((WSFED_TRY * 3))s), so it" >&2
    echo "         cannot be provisioned and the WS-Federation test will be SKIPPED. This is what a side-car" >&2
    echo "         that was created and then exited looks like: 'docker compose up -d' succeeds either way." >&2
    reportContainerLog "${WSFED_COMPOSE_FILE}" "keycloak-wsfed"
    return 0
  fi

  # Realm (a 409 if it already exists is harmless).
  curl -s -X POST "${KC_WSFED}/admin/realms" \
    -H "Authorization: Bearer ${KC_WSFED_TOKEN}" -H "Content-Type: application/json" \
    -d '{ "realm": "'"${WSFED_REALM_NAME}"'", "enabled": true }' >/dev/null

  KC_WSFED_TOKEN=$(curl -s -X POST "${KC_WSFED}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=admin-cli" -d "username=${KC_WSFED_ADMIN_USER}" \
    -d "password=${KC_WSFED_ADMIN_PASS}" -d "grant_type=password" \
    | jq -r '.access_token')

  # WS-Federation relying-party client. protocol "wsfed"; clientId == wtrealm;
  # redirect URIs cover the debugger's /wsfed landing (the wreply target) and its
  # response page. The token format defaults to SAML 2.0.
  curl -s -X POST "${KC_WSFED}/admin/realms/${WSFED_REALM_NAME}/clients" \
    -H "Authorization: Bearer ${KC_WSFED_TOKEN}" -H "Content-Type: application/json" \
    -d '{
          "clientId": "'"${WSFED_WTREALM}"'",
          "name": "wsfed-rp",
          "protocol": "wsfed",
          "enabled": true,
          "frontchannelLogout": true,
          "redirectUris": [ "'"${WSFED_API_BASE}"'/wsfed", "'"${WSFED_API_BASE}"'/*", "'"${WSFED_UI_BASE}"'/*" ],
          "attributes": {
            "wsfed.saml.assertion.token.format": "SAML2.0",
            "saml.assertion.token.format": "SAML2.0"
          }
       }' >/dev/null

  # Test user (username == password, mirroring the SAML test user).
  WSFED_USER_ID=$(curl -s \
    -X POST "${KC_WSFED}/admin/realms/${WSFED_REALM_NAME}/users" \
    -H "Authorization: Bearer ${KC_WSFED_TOKEN}" -H "Content-Type: application/json" \
    -d '{ "username": "wsfed", "firstName": "wsfed", "lastName": "wsfed",
          "email": "wsfed@iyasec.io", "enabled": true, "emailVerified": true }' \
    -i | grep -i '^Location:' | rev | cut -d '/' -f 1 | rev | tr -d ' \n\r')
  if [ -z "${WSFED_USER_ID}" ];
  then
    echo "WARNING: could not create the WS-Fed test user — WS-Federation test will be skipped."
    return 0
  fi
  curl -s -X PUT \
    "${KC_WSFED}/admin/realms/${WSFED_REALM_NAME}/users/${WSFED_USER_ID}/reset-password" \
    -H "Authorization: Bearer ${KC_WSFED_TOKEN}" -H "Content-Type: application/json" \
    -d '{ "type": "password", "value": "wsfed", "temporary": false }' >/dev/null

  # Verify what was just provisioned, rather than trusting a POST whose status was
  # discarded. Two things can go wrong quietly here and both would leave the test
  # failing for reasons that look nothing like the cause:
  #
  #   * the client is rejected because the server does not know the "wsfed"
  #     protocol — i.e. the cloudtrust module is not registered in the image, which
  #     is a build problem, not a configuration one;
  #   * the realm exists but the client does not, so the wtrealm the test sends is
  #     unknown to the IdP.
  WSFED_CLIENT_COUNT=$(curl -s \
    -G --data-urlencode "clientId=${WSFED_WTREALM}" \
    "${KC_WSFED}/admin/realms/${WSFED_REALM_NAME}/clients" \
    -H "Authorization: Bearer ${KC_WSFED_TOKEN}" | jq -r 'length' 2>/dev/null)
  if [ "${WSFED_CLIENT_COUNT}" != "1" ];
  then
    echo "WARNING: the WS-Federation relying-party client '${WSFED_WTREALM}' was not created on realm" >&2
    echo "         ${WSFED_REALM_NAME} (found: ${WSFED_CLIENT_COUNT:-none}). If the server rejected protocol" >&2
    echo "         \"wsfed\", the cloudtrust module is missing from the rcbj/keycloak-wsfed image — rebuild it" >&2
    echo "         with: docker compose -f <compose file> build --no-cache keycloak-wsfed" >&2
    echo "         The WS-Federation test will be SKIPPED." >&2
    return 0
  fi

  # And the endpoint the test actually drives: the descriptor the module serves.
  # Only the module publishes /protocol/wsfed, so a 404 here is the clearest signal
  # that the extension is not active, even when everything else provisioned fine.
  WSFED_DESCRIPTOR_LOCAL="${KC_WSFED}/realms/${WSFED_REALM_NAME}/protocol/wsfed/descriptor"
  WSFED_DESCRIPTOR_CODE=$(curl -s -o /dev/null -m 20 -w '%{http_code}' "${WSFED_DESCRIPTOR_LOCAL}")
  if [ "${WSFED_DESCRIPTOR_CODE}" != "200" ];
  then
    echo "WARNING: the WS-Federation descriptor at ${WSFED_DESCRIPTOR_LOCAL} answered HTTP" >&2
    echo "         ${WSFED_DESCRIPTOR_CODE}, so the cloudtrust wsfed protocol is not being served even though" >&2
    echo "         the realm and client provisioned. The WS-Federation test will be SKIPPED." >&2
    reportContainerLog "${WSFED_COMPOSE_FILE}" "keycloak-wsfed"
    return 0
  fi
  echo "The WS-Federation side-car is provisioned: realm ${WSFED_REALM_NAME}, relying party ${WSFED_WTREALM}, user wsfed, descriptor HTTP 200."

  # Export the suite vars. The descriptor URL uses the BROWSER/proxy-facing base
  # (KEYCLOAK_WSFED_BASE_URL) so the endpoint the browser navigates to matches.
  declare -gx WSFED_METADATA_URL="${KEYCLOAK_WSFED_BASE_URL:-${KEYCLOAK_WSFED_LOCALHOST_BASE_URL}}/auth/realms/${WSFED_REALM_NAME}/protocol/wsfed/descriptor"
  declare -gx WSFED_REALM="${WSFED_WTREALM}"
  declare -gx WSFED_USER="wsfed"
  echo "Leaving configureKeycloakWsfed(). WSFED_METADATA_URL=${WSFED_METADATA_URL}"
  return 0
}
