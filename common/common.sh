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

# Variables compose itself needs — the ones the compose FILES substitute, plus
# COMPOSE_PROJECT_NAME, which scopes ps/logs/up to the right project when a
# launcher isolates its stack (remote-run-tests.sh does).
#
# They have to be listed because `sudo` RESETS THE ENVIRONMENT: only assignments
# written on its command line survive. For a long time just CONFIG_FILE was
# forwarded, so every other `${...}` in a compose file silently substituted to
# empty — including GIT_COMMIT and BUILD_NUMBER, which stamp the build.
# The LIVE_* trio that used to be here (LIVE_CONFIG_FILE, LIVE_DEBUGGER_BASE_URL,
# LIVE_WSTRUST_STS_URL) was consumed only by docker-compose-live-tests.yml, which
# is gone: the live-site workflows call remote-run-tests.sh directly now, and it
# runs the suite on the host rather than substituting those into a compose file.
# THE THREE THAT TUNE A CONTAINERIZED RUN are here for exactly the same reason
# and each was silently doing nothing before 2026-08-27. TEST_CONCURRENCY sizes
# run-report.js's job pool and STS_LOG_LEVEL turns the mock's per-request debug
# logging down — the two settings a slow containerized run reaches for — and
# both are read by COMPOSE ITSELF (`${TEST_CONCURRENCY:-}` in the tests service,
# the bare `- STS_LOG_LEVEL` on every sts service), which is the environment
# sudo had just emptied. So `TEST_CONCURRENCY=6 ./docker-run-tests.sh` reached
# compose as empty, the pool sized itself from the container's cores as though
# nothing had been asked for, and the run gave no sign either way.
# TEST_JOB_TIMEOUT_MS is the per-job watchdog and joins them so the whole pool
# is tunable from one place. All three are absent from ./local-run-tests.sh's
# problems: that launcher runs run-report.js on the host, where the variables
# are simply inherited.
COMPOSE_FORWARDED_VARS="CONFIG_FILE COMPOSE_PROJECT_NAME OID4VCI_WALLET_URL"
COMPOSE_FORWARDED_VARS="${COMPOSE_FORWARDED_VARS} BUILD_NUMBER GIT_COMMIT"
COMPOSE_FORWARDED_VARS="${COMPOSE_FORWARDED_VARS} TEST_CONCURRENCY TEST_JOB_TIMEOUT_MS"
COMPOSE_FORWARDED_VARS="${COMPOSE_FORWARDED_VARS} TEST_WAIT_TIME_MS"
COMPOSE_FORWARDED_VARS="${COMPOSE_FORWARDED_VARS} STS_LOG_LEVEL"
# The stack TLS pair. Every compose file here mounts the DIRECTORY and
# names the two files inside it, so all three have to cross sudo — and
# STACK_TLS_CA_FILE is what the mock STS is given as NODE_EXTRA_CA_CERTS
# so that it can PUSH a Security Event Token to the api over TLS.
COMPOSE_FORWARDED_VARS="${COMPOSE_FORWARDED_VARS} STACK_TLS_DIR"
COMPOSE_FORWARDED_VARS="${COMPOSE_FORWARDED_VARS} STACK_TLS_CERT_FILE"
COMPOSE_FORWARDED_VARS="${COMPOSE_FORWARDED_VARS} STACK_TLS_KEY_FILE"
COMPOSE_FORWARDED_VARS="${COMPOSE_FORWARDED_VARS} STACK_TLS_CA_FILE"
COMPOSE_FORWARDED_VARS="${COMPOSE_FORWARDED_VARS} STACK_TLS_SPKI_PIN"
# The two per-service CONFIG_FILE knobs docker-compose-run-tests.yml added on
# 2026-08-31. They exist because `CONFIG_FILE` above is EXPORTED by
# docker-run-tests.sh with a default of its own, so a compose-level default for
# the sts and tests services would never be reached — and those two need the
# info-level file where the api and client need their own.
#
# Registering them here is not optional and tests/compose_env_forwarding.js is
# what says so: docker_compose() runs under sudo, which keeps no environment,
# so a variable a compose file reads and this list does not name is seen UNSET.
# `${STS_CONFIG_FILE:-./env/test.js}` would still work by falling back — but
# `STS_CONFIG_FILE=./env/docker-tests.js` on the command line would then do
# NOTHING, silently, which is the whole failure mode that test exists to catch.
# It caught exactly this on the first run after the variables were added.
COMPOSE_FORWARDED_VARS="${COMPOSE_FORWARDED_VARS} STS_CONFIG_FILE TESTS_CONFIG_FILE"

# Does docker on this machine need sudo? Answered by RUNNING it rather than by
# looking for a group in `id -nG`, which is neither necessary (a rootless
# daemon needs no group) nor sufficient (a group added since this shell logged
# in is not in this shell's credentials). It is the same probe clean.sh and
# infra/terraform-local.sh already make, moved here so the four launchers get
# it too.
#
# THE ANSWER IS "" WHENEVER THE DAEMON IS REACHABLE DIRECTLY, and that case is
# what this file did not have: docker_compose() prefixed `sudo`
# unconditionally, so a member of the `docker` group was asked for a password
# anyway, and a run with no terminal to type it into — CI, or anything driving
# these scripts unattended — died at the FIRST compose call with `sudo: a
# password is required`, before one container had been built. That message
# names sudo and not the suite, which is three steps from the thing to fix.
#
# Only PASSWORDLESS sudo is chosen deliberately. If neither probe succeeds the
# answer stays "yes" and sudo prompts exactly as it always did — this is a
# path that is added, never one that is taken away.
#
# Cached, because a run makes a dozen compose calls and each probe is a round
# trip to the daemon.
DOCKER_SUDO="${DOCKER_SUDO-unset}"

resolveDockerSudo()
{
  echo "Entering resolveDockerSudo()."
  if [ "${DOCKER_SUDO}" != "unset" ];
  then
    echo "Leaving resolveDockerSudo(). Cached: '${DOCKER_SUDO}'."
    return 0
  fi
  if docker info > /dev/null 2>&1;
  then
    DOCKER_SUDO=""
    echo "Leaving resolveDockerSudo(). The daemon is reachable directly."
    return 0
  fi
  if sudo -n docker info > /dev/null 2>&1;
  then
    DOCKER_SUDO="yes"
    echo "Leaving resolveDockerSudo(). Using passwordless sudo."
    return 0
  fi
  DOCKER_SUDO="yes"
  echo "Leaving resolveDockerSudo(). Neither probe worked; sudo may prompt."
  return 0
}

docker_compose() {
  echo "Entering docker_compose()."
  # Capture the real exit code of the compose command. sudo propagates the
  # child's status, but the trailing echo would reset $?, so stash it first and
  # return it — otherwise a failed `up --exit-code-from tests` (a failing test)
  # is masked and callers (e.g. run-coverage.sh) wrongly see success.
  local rc
  # Only variables that are actually SET are passed: an empty
  # COMPOSE_PROJECT_NAME makes compose refuse to run, and an empty value is not
  # the same as absent for compose's own substitution warnings. Deliberately
  # unquoted below so the list splits into separate NAME=VALUE arguments — every
  # value here is a URL, a path or a name, none of which contain spaces.
  local env_args="" _v _val
  for _v in ${COMPOSE_FORWARDED_VARS};
  do
    eval "_val=\${${_v}-}"
    if [ -n "${_val}" ];
    then
      env_args="${env_args} ${_v}=${_val}"
    fi
  done
  resolveDockerSudo
  # Which compose. Unquoted where it is used, so that the two words of
  # `docker compose` split into a command and its subcommand.
  local compose_cmd=""
  if [ -x ~/.local/bin/docker-compose ];
  then
    # By FULL PATH when this runs without sudo. sudo builds its own PATH from
    # secure_path and finds the binary there; an ordinary login shell's PATH
    # need not carry ~/.local/bin at all, and a bare `docker-compose` would
    # then be a `command not found` naming compose rather than the PATH.
    if [ -n "${DOCKER_SUDO}" ];
    then
      compose_cmd="docker-compose"
    else
      compose_cmd="${HOME}/.local/bin/docker-compose"
    fi
  elif docker compose version >/dev/null 2>&1;
  then
    compose_cmd="docker compose"
  elif command -v docker-compose >/dev/null 2>&1;
  then
    compose_cmd="docker-compose"
  else
    echo "Error: Docker Compose not found." >&2
    echo "Leaving docker_compose(). rc=1"
    return 1
  fi
  if [ -n "${DOCKER_SUDO}" ];
  then
    sudo ${env_args} ${compose_cmd} "$@"
    rc=$?
  else
    # `env` rather than a bare prefix assignment, because compose_cmd may be
    # two words and `NAME=v docker compose ...` would then set the variable for
    # `docker` only. Same effect as sudo's command-line assignments.
    env ${env_args} ${compose_cmd} "$@"
    rc=$?
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
# The browser extension's unpacked builds. Not committed, because they are
# generated (the version is stamped in) and because the CI build needs to know
# which origin the browser will see the mock STS on — http://sts:8081 inside the
# containerized stack, http://localhost:8081 for a host run. Written before
# compose builds, exactly like renderWaltidConfig: tests/Dockerfile COPYs
# extension/dist/ci, so an absent build fails that COPY with a message about a
# missing path rather than anything about extensions.
#
# The test that loads it will not run against BRANDED Google Chrome — that build
# refuses to side-load an unpacked extension and says so only on stderr — but the
# tests image pins Chrome for Testing, which allows it.
buildBrowserExtension()
{
  echo "Entering buildBrowserExtension()."
  local dir="${1:-.}"
  # The origin the CI build auto-arms MUST be the one the BROWSER will use to
  # reach the mock STS, which is not the same string in every stack:
  #
  #   containerized  http://sts:8081   (the browser is inside the compose network)
  #   host launchers http://localhost:8081
  #
  # Get it wrong and nothing fails loudly: the extension installs, reports its
  # version, and observes an origin the browser never visits — so the shim is
  # never injected and every capture assertion times out with nothing naming the
  # cause. That is exactly what happened on 2026-08-09, when this defaulted to
  # localhost for the containerized run. Each launcher therefore states it.
  local origins="${EXTENSION_AUTOARM_ORIGINS:-}"
  if [ -z "${origins}" ];
  then
    echo "ERROR: buildBrowserExtension needs EXTENSION_AUTOARM_ORIGINS — the origin the browser" >&2
    echo "       will use for the mock STS (http://sts:8081 containerized, http://localhost:8081" >&2
    echo "       on a host run). Refusing to guess: a wrong value costs a silent, empty capture." >&2
    return 1
  fi
  if [ ! -f "${dir}/extension/build.js" ];
  then
    echo "WARNING: ${dir}/extension/build.js is missing; the extension job will fail its own" >&2
    echo "         precondition rather than this build failing here." >&2
    return 0
  fi
  ( cd "${dir}" && EXTENSION_AUTOARM_ORIGINS="${origins}" node extension/build.js )
  check_return_code $?
  echo "Leaving buildBrowserExtension(). autoarm origins: ${origins}"
  return 0
}

# ---------------------------------------------------------------------------
# THE STACK'S TLS CERTIFICATE — ONE PAIR, MADE BEFORE ANYTHING STARTS.
#
# The api and the client both serve https now, and this is where the pair they
# serve comes from. It is generated by common/generate_tls_cert.js, which is a
# caller of THIS PROJECT'S OWN certificate authoring module
# (client/src/x509.js's `tls-server` profile) rather than another encoder — the
# argument is in that file's header and it is the one common/xmldsig.js already
# makes about XML Signature.
#
# ONE PAIR FOR BOTH SERVICES, and the reason is the mock STS. It PUSHES to the
# api (RFC 8935 Shared Signals delivery, POST /ssf/receiver/:id), so that
# container has to be handed the api's anchor in its environment — which is
# impossible for a certificate a service invents at its own startup. One file,
# on disk, before compose. It also makes ONE anchor for node
# (NODE_EXTRA_CA_CERTS names a single file) and ONE SPKI pin for Chrome rather
# than two of each.
#
# IT RUNS ON THE HOST, out of the checkout, for the same reason
# generateSpKeyPair() runs openssl there: client/src/x509.js needs pkijs,
# asn1js and the @noble family, which are the CLIENT's dependencies and are not
# in the api image at all.
#
# Exports STACK_TLS_DIR, STACK_TLS_CERT_FILE, STACK_TLS_KEY_FILE and
# STACK_TLS_SPKI_PIN. The certificate is self-signed, so it is its own anchor:
# STACK_TLS_CA_FILE is the same file under the name a truststore consumer wants
# it by.
#
# $1 optional extra subjectAltName DNS name (a deployed hostname, say). The
# stack's own names — localhost, client, api and the loopback literals — are
# always present; see the SANs note in common/generate_tls_cert.js.
# ---------------------------------------------------------------------------
generateStackTlsCertificate()
{
  echo "Entering generateStackTlsCertificate()."
  # As in generateSpKeyPair(): this runs under `set -x`, and while the key path
  # is not the key, the generator prints assignments that are easier to read
  # unechoed. Trace restored on the way out.
  local xtrace_was_on=""
  case "$-" in
    *x*) xtrace_was_on="yes"; set +x ;;
  esac

  if [ -n "${STACK_TLS_CERT_FILE:-}" ] && [ -n "${STACK_TLS_KEY_FILE:-}" ] &&
     [ -f "${STACK_TLS_CERT_FILE}" ] && [ -f "${STACK_TLS_KEY_FILE}" ];
  then
    echo "The stack TLS pair was supplied by the caller; using it as-is."
    [ -n "${xtrace_was_on}" ] && set -x
    echo "Leaving generateStackTlsCertificate(). Supplied."
    return 0
  fi

  local repo_root="${1:-$(pwd)}"
  local extra_name="${2:-}"

  # client/node_modules is where client/src/x509.js's own requires resolve.
  # Without it the generator dies on `Cannot find module 'pkijs'`, which names
  # a package rather than a missing install, so it is handled here by name.
  #
  # IT IS INSTALLED RATHER THAN ONLY REPORTED, and that is the fix for a red
  # CI run rather than a convenience. This function is called by all four
  # launchers and none of them installs the CLIENT's dependencies — each does
  # `npm install --prefix tests` and no more — so the directory exists only
  # because somebody ran an install in client/ at some earlier point. That is
  # true on a developer's machine and false on a fresh checkout, which is
  # exactly what a GitHub Actions runner is: run 662 of the Selenium Tests
  # workflow died here in eight seconds, in both jobs, before compose was
  # called, having built nothing and run no test. Reporting a missing install
  # is the right thing to do about a missing TOOL; a dependency of this
  # repository that this repository knows how to install is one this function
  # installs, the way requireMockStsCheckout() initialises a submodule.
  #
  # PLAIN `npm ci`, NOT `--omit=dev`. Only the runtime dependencies are needed
  # here (pkijs, asn1js, the @noble family, node-forge, bunyan — every one of
  # them in `dependencies`), so the flag would be correct for this caller and
  # would leave the tree wrong for the next one: `cd client && npm run build`
  # is what clean-artifacts.sh documents as the restore, and it wants
  # browserify and the three minifiers. A half-installed tree fails that with
  # `browserify: not found`, which names a package rather than an omitted
  # flag. Both images install this way too — see the `comments` block in
  # client/package.json. `npm ci` and not `npm install` because the lock is
  # committed and reproducing it is the point.
  if [ ! -d "${repo_root}/client/node_modules" ];
  then
    if ! command -v npm >/dev/null 2>&1;
    then
      echo "ERROR: ${repo_root}/client/node_modules is missing, and" \
           "common/generate_tls_cert.js needs it — client/src/x509.js" \
           "requires pkijs and asn1js. There is no npm on PATH to install" \
           "it with. Install node/npm, or run 'npm ci --prefix client'" \
           "elsewhere and bring the tree with you." >&2
      [ -n "${xtrace_was_on}" ] && set -x
      echo "Leaving generateStackTlsCertificate(). No npm."
      return 1
    fi
    echo "${repo_root}/client/node_modules is missing;" \
         "installing the client's dependencies, which is where" \
         "common/generate_tls_cert.js resolves pkijs and asn1js."
    if ! npm ci --prefix "${repo_root}/client";
    then
      echo "ERROR: 'npm ci --prefix ${repo_root}/client' failed, so" \
           "common/generate_tls_cert.js cannot run and the api and the" \
           "client have no certificate to serve." >&2
      [ -n "${xtrace_was_on}" ] && set -x
      echo "Leaving generateStackTlsCertificate(). Install failed."
      return 1
    fi
  fi

  # A throwaway directory, the shape generateSpKeyPair() and
  # trustStsCertificate() both use, and for the same reasons: this runs from
  # the repository root on a host launcher and from /usr/src/app inside the
  # tests container, so a relative path would have to be right in two places.
  # STACK_TLS_DIR overrides it for anybody who wants to look at what was
  # served. It is 0755 and the key inside it is 0600 — the containers run as
  # uid 10001 and have to READ it (see "Containers run as non-root" in the
  # repo-root CLAUDE.md), so a 0700 directory would be a permission error
  # inside a container naming a path the host can read perfectly well.
  STACK_TLS_DIR="${STACK_TLS_DIR:-$(mktemp -d)}"
  mkdir -p "${STACK_TLS_DIR}"
  chmod 0755 "${STACK_TLS_DIR}"

  local generated=""
  if [ -n "${extra_name}" ];
  then
    generated=$(node "${repo_root}/common/generate_tls_cert.js" \
                  --out-dir "${STACK_TLS_DIR}" --name "${extra_name}")
  else
    generated=$(node "${repo_root}/common/generate_tls_cert.js" \
                  --out-dir "${STACK_TLS_DIR}")
  fi
  if [ -z "${generated}" ];
  then
    echo "ERROR: common/generate_tls_cert.js produced nothing. The api and" \
         "the client are configured for TLS and will refuse to start" \
         "without a certificate." >&2
    [ -n "${xtrace_was_on}" ] && set -x
    echo "Leaving generateStackTlsCertificate(). Not generated."
    return 1
  fi

  # THE GENERATOR'S STDOUT IS PARSED, NOT EVALUATED, AND THAT IS THE SECOND
  # HALF OF A FIX. It prints one KEY=value per line and says everything about
  # itself on stderr — but the modules it requires are ordinary client
  # modules, each with a bunyan logger whose default stream is stdout and
  # whose level comes from CONFIG_FILE, which every launcher exports and both
  # ./env/*.js it can name set to "debug". So a few hundred Entering/Leaving
  # records used to land on the channel this reads, and `eval` applied quote
  # removal and brace expansion to the JSON and reported
  # `name:pqc: command not found` fourteen times, naming a module that had
  # done nothing wrong. common/generate_tls_cert.js now takes stdout away from
  # everything but its own three lines; this reads only assignments it asked
  # for, so no future call site can corrupt the result by adding a log line.
  # Split with parameter expansion rather than `IFS='=' read var value`,
  # which looks equivalent and is not: `read` strips a TRAILING delimiter, so
  # the base64 SPKI pin arrives without its own `=` padding — and a pin that
  # is one character short is not rejected anywhere, it simply never matches,
  # which looks exactly like Chrome ignoring the flag.
  local line=""
  local var=""
  local value=""
  while IFS= read -r line;
  do
    var="${line%%=*}"
    value="${line#*=}"
    case "${var}" in
      STACK_TLS_KEY_FILE|STACK_TLS_CERT_FILE|STACK_TLS_SPKI_PIN)
        printf -v "${var}" '%s' "${value}"
        ;;
    esac
  done <<< "${generated}"

  if [ -z "${STACK_TLS_KEY_FILE:-}" ] || [ -z "${STACK_TLS_CERT_FILE:-}" ] ||
     [ -z "${STACK_TLS_SPKI_PIN:-}" ];
  then
    echo "ERROR: common/generate_tls_cert.js printed no usable" \
         "STACK_TLS_* assignment. It said:" >&2
    echo "${generated}" >&2
    [ -n "${xtrace_was_on}" ] && set -x
    echo "Leaving generateStackTlsCertificate(). Unparseable output."
    return 1
  fi
  # BOTH 0644, INCLUDING THE KEY, and that is a deliberate trade rather than an
  # oversight. Every container here runs as uid 10001 (see "Containers run as
  # non-root" in the repo-root CLAUDE.md) and has to READ this key to serve
  # with it, and the host uid that generated it is 1000 on a developer's
  # machine and 1001 on a GitHub Actions runner — so there is no ownership
  # that is right in both places, exactly as there was none for ./tests/report
  # and ./coverage. What bounds the exposure instead is what the key IS: a
  # throwaway generated per run into a private temp directory, for a
  # certificate that names localhost and two compose service names, discarded
  # when the run ends. It is not a credential for anything outside this stack.
  chmod 0644 "${STACK_TLS_KEY_FILE}" "${STACK_TLS_CERT_FILE}"
  # Self-signed, so the leaf IS the anchor. Named separately because a
  # truststore consumer asks for a CA file and a server asks for its
  # certificate, and one path under two names is clearer at the call sites than
  # one name doing both jobs.
  STACK_TLS_CA_FILE="${STACK_TLS_CERT_FILE}"
  export STACK_TLS_DIR STACK_TLS_CERT_FILE STACK_TLS_KEY_FILE
  export STACK_TLS_CA_FILE STACK_TLS_SPKI_PIN

  echo "The stack TLS certificate is ${STACK_TLS_CERT_FILE}" \
       "(SPKI pin ${STACK_TLS_SPKI_PIN})."
  [ -n "${xtrace_was_on}" ] && set -x
  echo "Leaving generateStackTlsCertificate(). STACK_TLS_DIR=${STACK_TLS_DIR}"
  return 0
}

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
# Make sure the mock STS is on disk before anything tries to build it.
#
# sts/ is a SUBMODULE, not code in this repository: it is
# https://github.com/rcbj/mock-sts.git on branch main, and what this repository
# records is a link to it. Two things then depend on the checkout existing, and
# both fail a long way from the cause when it does not:
#
#   * four compose files build the image with `context: ./sts`, and compose says
#     "failed to read dockerfile" — a message about a path, not about a submodule;
#   * tests/Dockerfile copies sts/common/vendored/bbs2023.js into the tests image so that
#     tests/bbs2023_cryptosuite.js can check the wallet's cryptosuite against the
#     issuer's, and the build says
#     "COPY sts/common/vendored/bbs2023.js: not found".
#
# A `git clone` without --recurse-submodules leaves exactly that state: sts/
# present and EMPTY. So this initialises it when it is missing and refuses the run
# when it cannot, rather than letting either message stand as the explanation.
#
# WHICH COMMIT. By default the one this repository records, which is the point of
# a submodule and is what makes a build repeatable. Set MOCK_STS_TRACK_REMOTE=1 to
# take the tip of the branch .gitmodules names (main) instead — `git submodule
# update --remote` — which resolves the link at build time in the strongest sense,
# at the cost of the run not being repeatable and of leaving the submodule pointer
# showing as modified in `git status`.
# ---------------------------------------------------------------------------
requireMockStsCheckout()
{
  echo "Entering requireMockStsCheckout()."
  local root="${1:-.}"
  local dir="${root}/sts"
  local track_remote="${MOCK_STS_TRACK_REMOTE:-0}"

  # Two FILES, not a directory test: an interrupted `git submodule update`, and
  # compose itself, both leave an empty sts/ behind, so "the directory is there"
  # is precisely the state this exists to catch. The Dockerfile is what compose
  # reads and server.js is what the image runs, so between them they say the
  # checkout is real rather than merely present.
  #
  # THREE files now, and the third is a level down. The mock STS has a submodule
  # of ITS own — node-ldapjs, which its package.json takes as
  # `"ldapjs": "file:node-ldapjs"` — so an sts/ that has a Dockerfile and a
  # server.js can still be half-initialised. An uninitialised submodule is an
  # empty DIRECTORY, so the image builds, npm installs a package with no `main`,
  # and the container dies at startup with `Cannot find module 'ldapjs'`, naming
  # a package. Checking only the first two files here would declare that state
  # good and never run the update that fixes it.
  if [ -f "${dir}/Dockerfile" ] && [ -f "${dir}/server.js" ] && \
     [ -f "${dir}/node-ldapjs/package.json" ] && [ "${track_remote}" != "1" ];
  then
    # The mock STS has a submodule OF ITS OWN — node-ldapjs, which its embedded
    # LDAP directory is built on and which its Dockerfile COPYs before npm runs.
    # `git submodule update --init -- sts` stops one level short of it, so a
    # checkout can be perfectly populated here and still fail the sts image
    # build. Handled separately below rather than by adding --recursive to every
    # call, because the diagnosis differs: an empty sts/ is "the mock is not
    # checked out", an empty sts/node-ldapjs is "the mock is, but its own
    # dependency is not".
    requireNestedLdapjsCheckout "${dir}" || return 1
    echo "Leaving requireMockStsCheckout(). ${dir} is populated."
    return 0
  fi

  if [ ! -d "${root}/.git" ] && [ ! -f "${root}/.git" ];
  then
    echo "ERROR: ${dir} has no checkout of the mock STS in it, and ${root} is not a git" >&2
    echo "       working tree, so the submodule cannot be initialised here. Clone it directly:" >&2
    echo "         git clone -b main https://github.com/rcbj/mock-sts.git ${dir}" >&2
    return 1
  fi
  if [ ! -f "${root}/.gitmodules" ] || ! grep -q '^[[:space:]]*path[[:space:]]*=[[:space:]]*sts[[:space:]]*$' "${root}/.gitmodules";
  then
    echo "ERROR: ${dir} has no checkout of the mock STS in it and ${root}/.gitmodules does not" >&2
    echo "       declare it, so there is nothing to initialise. The STS lives in its own" >&2
    echo "       repository now; see the 'Mock STS' section of CLAUDE.md." >&2
    return 1
  fi

  # --recursive is not optional: see the note above the populated-check.
  local update_args="--init --recursive"
  if [ "${track_remote}" = "1" ];
  then
    # --remote checks out the tip of the branch named in .gitmodules rather than
    # the recorded commit. Deliberately opt-in: see the note above.
    update_args="--init --recursive --remote"
    echo "MOCK_STS_TRACK_REMOTE=1: taking the tip of the branch .gitmodules names, not the recorded commit."
  fi
  echo "Initialising the mock STS submodule in ${dir}."
  git -C "${root}" submodule update ${update_args} -- sts
  if [ $? -ne 0 ];
  then
    echo "ERROR: 'git submodule update ${update_args} -- sts' failed in ${root}." >&2
    echo "       The mock STS is fetched over https from https://github.com/rcbj/mock-sts.git," >&2
    echo "       so this is usually network access or a proxy rather than credentials." >&2
    return 1
  fi

  # Asked again rather than assumed: `git submodule update` exits 0 for a
  # submodule it does not know about, which is the one case that would otherwise
  # walk straight into the compose error this function exists to prevent.
  if [ ! -f "${dir}/Dockerfile" ] || [ ! -f "${dir}/server.js" ];
  then
    echo "ERROR: ${dir} is still empty after 'git submodule update ${update_args} -- sts'." >&2
    echo "       Run 'git submodule status sts' in ${root} to see what it thinks is there." >&2
    return 1
  fi
  requireNestedLdapjsCheckout "${dir}" || return 1
  echo "Leaving requireMockStsCheckout(). ${dir} is populated."
  return 0
}

# ---------------------------------------------------------------------------
# The node-ldapjs submodule INSIDE the mock STS.
#
# The mock's embedded LDAP directory (sts/ldap/ldap_server.js) is built on ldapjs,
# and that dependency is `"ldapjs": "file:node-ldapjs"` — the submodule, pinned
# by commit and used unmodified. sts/Dockerfile COPYs it into the build context
# before npm runs.
#
# It needs its own function because it is a submodule of a submodule, which is
# exactly the level `git submodule update --init -- sts` does not reach. The
# failure without it is not "the file is missing": an UNINITIALISED SUBMODULE IS
# AN EMPTY DIRECTORY, so the COPY succeeds, npm installs a package with no main,
# and the container dies at startup with `Cannot find module 'ldapjs'` — naming
# a package rather than a submodule, from a service whose other eleven protocol
# families were about to work perfectly.
# ---------------------------------------------------------------------------
requireNestedLdapjsCheckout()
{
  echo "Entering requireNestedLdapjsCheckout()."
  local dir="${1:-./sts}"
  local nested="${dir}/node-ldapjs"

  # A FILE, not the directory: see the note in requireMockStsCheckout() about
  # why "the directory is there" is the state these checks exist to catch.
  if [ -f "${nested}/package.json" ];
  then
    echo "Leaving requireNestedLdapjsCheckout(). ${nested} is populated."
    return 0
  fi
  if [ ! -f "${dir}/.gitmodules" ];
  then
    # An older recorded commit of the mock STS, from before it had a directory.
    # Not an error: that build simply has no LDAP in it, and the LDAP jobs skip
    # with their own named reason. Saying so here is what stops it looking like
    # a broken checkout.
    echo "Note: ${dir} declares no submodules, so this commit of the mock STS predates"
    echo "      its embedded LDAP directory. The LDAP jobs will skip."
    echo "Leaving requireNestedLdapjsCheckout(). Nothing to initialise."
    return 0
  fi
  echo "Initialising the node-ldapjs submodule in ${nested}."
  git -C "${dir}" submodule update --init -- node-ldapjs
  if [ $? -ne 0 ];
  then
    echo "ERROR: 'git submodule update --init -- node-ldapjs' failed in ${dir}." >&2
    echo "       It is fetched over https from https://github.com/rcbj/node-ldapjs.git," >&2
    echo "       so this is usually network access or a proxy rather than credentials." >&2
    return 1
  fi
  if [ ! -f "${nested}/package.json" ];
  then
    echo "ERROR: ${nested} is still empty. The mock STS's LDAP directory cannot build" >&2
    echo "       without it, and the failure at runtime is 'Cannot find module ldapjs'." >&2
    return 1
  fi
  echo "Leaving requireNestedLdapjsCheckout(). ${nested} is populated."
  return 0
}

# ---------------------------------------------------------------------------
# The node-ldapjs submodule the API uses, at api/node-ldapjs.
#
# The same library, pinned the same way, on the other side of the exchange: the
# mock is the LDAP server and the api is the client. It is a SECOND submodule
# rather than a shared one because npm installs a `file:` dependency as a
# symlink and then resolves that package's own requires by walking up from where
# the real directory lives — so a copy outside api/ never reaches
# api/node_modules, and the failure is `Cannot find module 'abstract-logging'`
# from inside ldapjs, naming a package nobody here has heard of.
#
# Called before the api image is built. Without it the build succeeds and the
# service dies at startup with `Cannot find module 'ldapjs'`.
# ---------------------------------------------------------------------------
requireApiLdapjsCheckout()
{
  echo "Entering requireApiLdapjsCheckout()."
  local root="${1:-.}"
  local dir="${root}/api/node-ldapjs"

  if [ -f "${dir}/package.json" ];
  then
    echo "Leaving requireApiLdapjsCheckout(). ${dir} is populated."
    return 0
  fi
  if [ ! -d "${root}/.git" ] && [ ! -f "${root}/.git" ];
  then
    echo "ERROR: ${dir} is empty and ${root} is not a git working tree, so the submodule" >&2
    echo "       cannot be initialised here. Clone it directly:" >&2
    echo "         git clone -b master https://github.com/rcbj/node-ldapjs.git ${dir}" >&2
    return 1
  fi
  echo "Initialising the node-ldapjs submodule in ${dir}."
  git -C "${root}" submodule update --init -- api/node-ldapjs
  if [ $? -ne 0 ];
  then
    echo "ERROR: 'git submodule update --init -- api/node-ldapjs' failed in ${root}." >&2
    echo "       It is fetched over https from https://github.com/rcbj/node-ldapjs.git," >&2
    echo "       so this is usually network access or a proxy rather than credentials." >&2
    return 1
  fi
  if [ ! -f "${dir}/package.json" ];
  then
    echo "ERROR: ${dir} is still empty after 'git submodule update --init'." >&2
    echo "       Run 'git submodule status api/node-ldapjs' in ${root} to see what it" >&2
    echo "       thinks is there. The api builds without it and then dies at startup" >&2
    echo "       with 'Cannot find module ldapjs'." >&2
    return 1
  fi
  echo "Leaving requireApiLdapjsCheckout(). ${dir} is populated."
  return 0
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

# ---------------------------------------------------------------------------
# Require that a mock STS is answering on a URL, IN THE SCHEME EXPECTED, and
# fail with the reason if it is not.
#
# requireComposeServiceRunning() asks whether the container is there. This asks
# the different question that a whole run turned on: whether the thing on that
# port is OURS. Under host networking the mock binds host ports directly, so
# anything else already holding one wins — the container throws EADDRINUSE on a
# listen with no error handler and exits, and the suite spends twenty-five
# minutes failing against a stranger.
#
# The scheme is an argument rather than something read off the URL because it is
# the DIAGNOSIS, not a formality. `oauth2.rfc9700` derives `global.https` in
# that service, so an instance in RFC 9700 mode answers HTTPS on the port a
# permissive one answers HTTP on — and a plain request to it does not get an
# error, it gets the connection closed. That failure reaches a test as "fetch
# failed" or "other side closed", which names a socket and never names the
# mode. So when the expected scheme does not answer, this probes the OTHER one
# before reporting, and says which it found.
#
# --insecure on the https probe: the mock's certificate is self-signed and
# regenerated on every start, so nothing can have an anchor for it. This is
# checking that the port answers, not that it is trusted.
#
# $1 scheme ("http" or "https"), $2 URL, $3 the service name, for the message.
# STS_REACHABLE_WAIT_SECONDS (default 60) bounds the wait.
# ---------------------------------------------------------------------------
requireStsReachable()
{
  echo "Entering requireStsReachable(). service=${3} url=${2}"
  local scheme="$1"
  local url="$2"
  local service="$3"
  if [ -z "${scheme}" ] || [ -z "${url}" ] || [ -z "${service}" ];
  then
    echo "ERROR: requireStsReachable() needs a scheme, a URL and a service" \
         "name (got '${scheme}' '${url}' '${service}')." >&2
    return 1
  fi

  # Trace off: the poll would otherwise print a curl line per iteration for a
  # minute. Restored on every exit path, as requireComposeServiceRunning() does.
  local xtrace_was_on=""
  case "$-" in
    *x*) xtrace_was_on="yes"; set +x ;;
  esac

  local deadline code other_url other_scheme other_code sts_port
  # host:port from the URL, then the port alone — ${url##*:} on its own would
  # carry the path with it ("8091/healthcheck") and match nothing in ss output.
  sts_port="${url##*:}"
  sts_port="${sts_port%%/*}"
  deadline=$(( $(date +%s) + ${STS_REACHABLE_WAIT_SECONDS:-60} ))
  while :;
  do
    # `|| true`, not `|| echo "000"`: curl PRINTS "000" itself when it never got
    # a response and THEN exits non-zero, so the fallback would append a second
    # one and report "000000". The empty case (no curl at all) is defaulted
    # below.
    code=$(curl -s -k -m 5 -o /dev/null -w "%{http_code}" "${url}" \
             2>/dev/null || true)
    code="${code:-000}"
    if [ "${code}" = "200" ];
    then
      break
    fi
    if [ "$(date +%s)" -ge "${deadline}" ];
    then
      echo "ERROR: ${service} is not answering ${scheme} on ${url}" \
           "(last status: ${code})." >&2
      # The port may be held by an instance in the OTHER mode. That is the case
      # this exists for, so name it rather than leaving a socket error behind.
      case "${scheme}" in
        http)  other_scheme="https" ;;
        *)     other_scheme="http"  ;;
      esac
      other_url=$(echo "${url}" | sed "s|^${scheme}://|${other_scheme}://|")
      other_code=$(curl -s -k -m 5 -o /dev/null -w "%{http_code}" \
                     "${other_url}" 2>/dev/null || true)
      other_code="${other_code:-000}"
      if [ "${other_code}" = "200" ];
      then
        echo "       SOMETHING IS ANSWERING ${other_scheme} THERE INSTEAD" \
             "(${other_url} -> ${other_code})." >&2
        echo "       In this service the scheme follows the mode:" \
             "oauth2.rfc9700 derives global.https, so an instance in" >&2
        echo "       RFC 9700 mode serves HTTPS on the port a permissive one" \
             "serves HTTP on." >&2
        echo "       The usual cause is a mock STS started BY HAND, outside" \
             "compose, still holding the port — under host" >&2
        echo "       networking it binds this machine's ports directly and" \
             "whoever got there first wins." >&2
        echo "       Find it and stop it BY PID, never by pattern:" >&2
        echo "         ss -ltnp | grep ':${sts_port}'   # then: kill <pid>" >&2
      fi
      reportContainerLog "local-tests.yml" "${service}" 2>/dev/null || true
      [ -n "${xtrace_was_on}" ] && set -x
      echo "Leaving requireStsReachable(). ${service} did not answer."
      return 1
    fi
    sleep 3
  done

  [ -n "${xtrace_was_on}" ] && set -x
  echo "Leaving requireStsReachable(). ${service} answers ${scheme} on ${url}."
  return 0
}

# ---------------------------------------------------------------------------
# INSTALL THE MOCK STS'S CERTIFICATE, FOR NODE AND FOR CHROME.
#
# The mock serves its main port over TLS in every stack here (STS_HTTPS=true in
# local-tests.yml, docker-compose-run-tests.yml and keycloak-tests.yml). That is
# not a preference: the RFC 9700 pass is a TRUST REALM on that one instance now
# rather than a second container, a realm binds no socket of its own, and the
# pass is only honest over TLS — requirement 8.1 is that every configured
# endpoint is https and the debugger enforces it. So the scheme belongs to the
# process, and everything in this suite that talks to the mock talks https.
#
# THE CERTIFICATE IS SELF-SIGNED AND REGENERATED ON EVERY START of that service,
# which is deliberate on its side and is the whole difficulty on ours: nothing
# can hold an anchor for it ahead of time. It cannot be committed, baked into an
# image, or installed by hand — it does not exist until the mock is up. So it is
# fetched, once, here, after the service answers and before anything verifies.
#
# TWO CONSUMERS, TWO MECHANISMS, AND BOTH ARE TRUSTSTORES RATHER THAN SWITCHES:
#
#   node   — NODE_EXTRA_CA_CERTS names a PEM that is ADDED to the default store.
#            Every other certificate every node process here meets is still
#            verified. `NODE_TLS_REJECT_UNAUTHORIZED=0` would have been one line
#            and would also have disarmed api_ssrf_guard.js, api_tls_probe.js
#            and url_safety_schemes.js, which assert refusals — a test that
#            cannot fail is worse than a test that is missing.
#
#   Chrome — --ignore-certificate-errors-spki-list takes the base64 SHA-256 of
#            the certificate's SUBJECT PUBLIC KEY INFO and trusts that key and
#            no other. It is exact-key pinning: a different self-signed
#            certificate — including the one the mock generates on its NEXT
#            start — is still refused with an interstitial. The blunt
#            --ignore-certificate-errors would have accepted anything at all,
#            in a suite where several jobs exist to prove that a bad
#            certificate is refused.
#
#            NSS was the other candidate (certutil -A into ~/.pki/nssdb) and was
#            not taken: it needs libnss3-tools in the tests image, it writes
#            per-user state that survives the run, and Chrome's own verifier
#            wants a trust anchor to look like a CA — this certificate is
#            basicConstraints CA:FALSE, because it is a server certificate and
#            says so.
#
# Exports STS_CA_FILE, NODE_EXTRA_CA_CERTS and STS_SPKI_PIN. browser_flags.js
# reads the last one; everything else is inherited by every child process.
#
# $1 the STS base URL, https, no trailing slash (e.g. https://localhost:8081).
# Non-fatal on failure, and that is deliberate: the jobs that need the mock
# should fail with their own message rather than the launcher stopping the run
# before any of them is scheduled.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# ONE FILE, EVERY ANCHOR THIS RUN TRUSTS.
#
# `NODE_EXTRA_CA_CERTS` takes a SINGLE path and node reads it ONCE, at startup:
# there is no list form and no second variable, so two anchors is a
# concatenation or it is nothing. This run has two — the mock STS's
# certificate, regenerated on that service's every start, and the stack's own
# TLS pair from generateStackTlsCertificate() — and a third would go here the
# same way.
#
# A PEM bundle is just concatenated certificates, so "append" is the whole
# implementation. What it must not do is append the same anchor twice on a
# second call, which is why each one is checked for first: a duplicated
# certificate in a bundle is accepted by OpenSSL and makes the file read as
# though somebody could not tell whether it had run.
#
# It is ADDING to node's default store, not replacing it and not disarming
# verification. `NODE_TLS_REJECT_UNAUTHORIZED=0` would be one line and would
# also silence api_ssrf_guard.js, api_tls_probe.js and url_safety_schemes.js,
# which exist to assert that a bad certificate is REFUSED — see the long note
# above trustStsCertificate().
#
# $1 a PEM file to trust. Exports NODE_EXTRA_CA_CERTS and TRUST_BUNDLE_FILE.
# ---------------------------------------------------------------------------
addTrustAnchor()
{
  echo "Entering addTrustAnchor(). file=${1}"
  local pem="${1}"
  if [ -z "${pem}" ] || [ ! -f "${pem}" ];
  then
    echo "WARNING: addTrustAnchor() was given no readable PEM (${pem})." >&2
    echo "Leaving addTrustAnchor(). Nothing added."
    return 1
  fi

  if [ -z "${TRUST_BUNDLE_FILE:-}" ];
  then
    TRUST_BUNDLE_FILE="$(mktemp -d)/trust-bundle.pem"
    : > "${TRUST_BUNDLE_FILE}"
    chmod 0644 "${TRUST_BUNDLE_FILE}"
  fi

  # Already in the bundle? Compare the certificate rather than the path: the
  # same anchor can arrive under two names (STACK_TLS_CA_FILE and
  # STACK_TLS_CERT_FILE are one file), and a byte comparison settles it
  # without another openssl invocation.
  if [ -s "${TRUST_BUNDLE_FILE}" ] &&
     grep -qFf "${pem}" "${TRUST_BUNDLE_FILE}" 2>/dev/null;
  then
    echo "That anchor is already in ${TRUST_BUNDLE_FILE}."
    export NODE_EXTRA_CA_CERTS="${TRUST_BUNDLE_FILE}"
    export TRUST_BUNDLE_FILE
    echo "Leaving addTrustAnchor(). Already present."
    return 0
  fi

  cat "${pem}" >> "${TRUST_BUNDLE_FILE}"
  export TRUST_BUNDLE_FILE
  export NODE_EXTRA_CA_CERTS="${TRUST_BUNDLE_FILE}"
  echo "Leaving addTrustAnchor(). NODE_EXTRA_CA_CERTS=${NODE_EXTRA_CA_CERTS}"
  return 0
}

trustStsCertificate()
{
  echo "Entering trustStsCertificate(). url=${1}"
  local base="${1%/}"
  if [ -z "${base}" ];
  then
    echo "ERROR: trustStsCertificate() needs the STS base URL." >&2
    echo "Leaving trustStsCertificate(). No URL."
    return 1
  fi

  # A throwaway directory, the same shape generateSpKeyPair() uses and for the
  # same reasons: this runs from the repository root on a host launcher and from
  # /usr/src/app inside the tests container, so a relative path would have to be
  # right in two places, and the certificate is worthless after the mock next
  # restarts. STS_CA_DIR overrides it for anybody who wants to look at what was
  # trusted.
  local dir="${STS_CA_DIR:-$(mktemp -d)}"
  mkdir -p "${dir}"
  STS_CA_FILE="${dir}/sts-ca.pem"

  # -k, and it is the ordinary bootstrap rather than a hole: fetching the PEM
  # over a connection you cannot yet verify is the same act as trusting the PEM
  # it hands back, done one step earlier. The mock's own /tls page says so.
  if ! curl -sk --fail -m 20 -o "${STS_CA_FILE}" \
         "${base}/tls/server-certificate";
  then
    echo "WARNING: could not fetch the mock STS certificate from" \
         "${base}/tls/server-certificate." >&2
    echo "         Every STS-backed job will fail verification" \
         "(DEPTH_ZERO_SELF_SIGNED_CERT in node, an interstitial in Chrome)." >&2
    echo "Leaving trustStsCertificate(). Not fetched."
    return 1
  fi

  # A PEM, not an HTML error page. curl --fail catches a 4xx/5xx, but a proxy
  # or a wrong path can answer 200 with something else entirely, and the
  # failure would then arrive one layer down as a TLS error naming nothing.
  if ! grep -q "BEGIN CERTIFICATE" "${STS_CA_FILE}";
  then
    echo "WARNING: ${base}/tls/server-certificate did not answer with a PEM." >&2
    head -c 200 "${STS_CA_FILE}" >&2
    echo >&2
    echo "Leaving trustStsCertificate(). Not a certificate."
    return 1
  fi

  STS_CA_FILE="$(cd "$(dirname "${STS_CA_FILE}")" && pwd)/$(basename \
      "${STS_CA_FILE}")"
  export STS_CA_FILE
  # NODE_EXTRA_CA_CERTS NAMES ONE FILE AND THERE ARE NOW TWO ANCHORS: this
  # one and the stack's own (the api and the client serve TLS, so every node
  # process here verifies both). node reads the variable ONCE at startup and
  # takes a single path, so the answer is a bundle rather than a second
  # variable — see addTrustAnchor() for why appending is the whole of it.
  addTrustAnchor "${STS_CA_FILE}"

  # The SPKI pin Chrome wants. openssl three times rather than once because the
  # hash is of the DER-encoded SubjectPublicKeyInfo — not of the certificate,
  # and not of the PEM text — and getting that wrong produces a pin that is
  # simply never matched, which looks exactly like no pin at all.
  STS_SPKI_PIN="$(openssl x509 -in "${STS_CA_FILE}" -pubkey -noout \
                    | openssl pkey -pubin -outform der \
                    | openssl dgst -sha256 -binary \
                    | openssl enc -base64)"
  export STS_SPKI_PIN
  if [ -z "${STS_SPKI_PIN}" ];
  then
    echo "WARNING: could not compute the SPKI pin from ${STS_CA_FILE}; the" \
         "browser jobs will meet a certificate interstitial." >&2
  fi

  echo "Leaving trustStsCertificate(). NODE_EXTRA_CA_CERTS=${NODE_EXTRA_CA_CERTS}," \
       "STS_SPKI_PIN=${STS_SPKI_PIN}"
  return 0
}

# ---------------------------------------------------------------------------
# THE RFC 9700 TRUST REALM, WHICH REPLACED A WHOLE SECOND MOCK INSTANCE.
#
# The five RFC 9700 flow jobs run the OAuth2/OIDC matrix a second time with the
# debugger AND the server both enforcing the BCP. That used to need a mock of
# its own — `oauth2.rfc9700` derives `global.https` over there, so it binds the
# main port as TLS, and one process could not serve the permissive pass and the
# compliant one at the same time.
#
# It can now, because that flag is the one setting in that service marked
# `realmRuntime`: restart-only for the PROCESS, settable on a TRUST REALM. The
# reason it is restart-only is a bound socket, and a realm binds none — it
# answers on the port the process already opened, in the scheme that port was
# opened in. So `/oauth2/authorize` stays permissive for the twelve jobs that
# want a server implementing none of this, and `/realm/rfc9700/oauth2/authorize`
# enforces every check for the five that want one that does. Two issuers, two
# signing keys, two sets of codes and tokens, one process.
#
# THE REALM IS IN MEMORY AND GONE ON RESTART, which is why this is a launcher
# step and not a setting in a compose file. There is nowhere to declare it: that
# service persists nothing at all, on purpose.
#
# IT IS ALSO THE CAPABILITY PROBE, and it replaced a worse one. local-run-tests.sh
# used to decide whether to schedule those jobs by looking for `oauth2_bcp.js`
# in the sts/ submodule — a path test, which silently took its else branch and
# printed a confident, wrong explanation when mock-sts reorganised its
# directories. Asking the running service to create the realm answers the same
# question about the code that is actually running, and answers it about REALMS
# too, which that probe could not have seen at all.
#
# $1 the STS base URL, https, no trailing slash. Prints nothing to stdout that a
# caller should parse; returns non-zero when the realm is not there afterwards,
# so the caller can leave RFC9700_STS_URL unset and let run-report.js skip the
# five jobs with a reason.
# ---------------------------------------------------------------------------
configureStsRfc9700Realm()
{
  echo "Entering configureStsRfc9700Realm(). url=${1}"
  local base="${1%/}"
  local realm="${RFC9700_STS_REALM:-rfc9700}"
  if [ -z "${base}" ];
  then
    echo "ERROR: configureStsRfc9700Realm() needs the STS base URL." >&2
    echo "Leaving configureStsRfc9700Realm(). No URL."
    return 1
  fi

  # -k throughout: this runs before trustStsCertificate() has necessarily been
  # called, and it is curl talking to a mock rather than a client under test.
  #
  # `create` carries the override, so the realm is never briefly permissive.
  # That matters more than it looks: a realm created first and configured second
  # would answer /realm/rfc9700/oauth2/authorize permissively for however long
  # the second call takes, and a test that started in that window would pass
  # while proving nothing.
  local body code
  body="$(curl -sk -m 20 -X POST "${base}/admin-api/realms/create" \
            -H 'Content-Type: application/json' \
            -d "{\"id\":\"${realm}\",\"name\":\"RFC 9700 mode\",\"description\":\"The OAuth 2.0 Security Best Current Practice enforced. Created by configureStsRfc9700Realm() in common/common.sh for the five rfc9700_flows.js jobs.\",\"overrides\":{\"oauth2.rfc9700\":true}}" \
            -w '\n%{http_code}' || true)"
  code="$(printf '%s' "${body}" | tail -n 1)"

  # A re-run against a mock that is still up is the ORDINARY case on this
  # project — remote-run-tests.sh reuses a host-run stack — and "already
  # defined" is success, not failure. The realm is asked to carry the override
  # again below either way, so a realm left behind by an older launcher that
  # created it without one is repaired rather than trusted.
  if [ "${code}" != "200" ];
  then
    echo "Note: POST ${base}/admin-api/realms/create answered ${code}." \
         "If the realm already exists that is expected; the set below is what" \
         "decides."
  fi

  body="$(curl -sk -m 20 -X POST "${base}/admin-api/realms/set" \
            -H 'Content-Type: application/json' \
            -d "{\"id\":\"${realm}\",\"key\":\"oauth2.rfc9700\",\"value\":true}" \
            -w '\n%{http_code}' || true)"
  code="$(printf '%s' "${body}" | tail -n 1)"
  if [ "${code}" != "200" ];
  then
    echo "WARNING: could not put the \"${realm}\" realm into RFC 9700 mode:" \
         "${code}." >&2
    printf '%s\n' "${body}" | head -c 500 >&2
    echo >&2
    echo "         The mock STS is probably older than \`realmRuntime\` on" \
         "oauth2.rfc9700 — before that, the setting could only be given to a" >&2
    echo "         whole process. Bump the sts/ submodule. The five RFC 9700" \
         "flow jobs will be SKIPPED rather than run against a permissive" >&2
    echo "         server, which would pass while proving nothing." >&2
    echo "Leaving configureStsRfc9700Realm(). Not configured."
    return 1
  fi

  # ASK THE SERVICE, rather than believing the two calls above. This is the one
  # assertion that covers both of them AND the path: GET /realm/<id>/oauth2/rfc9700
  # is the same document the jobs themselves read to refuse a permissive server,
  # so agreeing with it here is agreeing with them.
  local enabled
  enabled="$(curl -sk -m 20 "${base}/realm/${realm}/oauth2/rfc9700" \
               | tr -d ' \n' | grep -o '"enabled":true' || true)"
  if [ -z "${enabled}" ];
  then
    echo "WARNING: ${base}/realm/${realm}/oauth2/rfc9700 does not report the" \
         "mode as on." >&2
    echo "Leaving configureStsRfc9700Realm(). Not in mode."
    return 1
  fi

  echo "Leaving configureStsRfc9700Realm(). ${base}/realm/${realm} is in RFC 9700 mode."
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
  
  for FLOW_VARIABLE in CLIENT_CREDENTIALS AUTHORIZATION_CODE_CONFIDENTIAL AUTHORIZATION_CODE_PUBLIC IMPLICIT OIDC_AUTHORIZATION_CODE_CONFIDENTIAL OIDC_AUTHORIZATION_CODE_PUBLIC OIDC_ALL_FLOWS_PUBLIC RESOURCE_OWNER_CREDENTIAL TOKEN_EXCHANGE_TARGET TOKEN_EXCHANGE DEVICE_AUTHORIZATION_GRANT TOKEN_INTROSPECTION
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
        OIDC_ALL_FLOWS_PUBLIC)
            # The client tests/oidc_flows_sts.js drives against Keycloak, for all
            # six OIDC authentication flows and for DPoP in both states.
            #
            # ONE client for all twelve jobs, and each part of that is load-bearing:
            #
            #   * standardFlowEnabled AND implicitFlowEnabled. Keycloak gates the
            #     response types on these two together — `code` needs the first,
            #     `id_token`/`id_token token` the second, and the three Hybrids
            #     need BOTH. A client with only the standard flow answers
            #     unsupported_response_type for four of the six, which arrives as
            #     a redirect carrying an error rather than as anything the page
            #     did wrong.
            #   * dpop.bound.access.tokens is deliberately NOT set. In Keycloak
            #     that attribute means "always REQUIRE DPoP" for this client, and
            #     turning it on would make the six DPoP-off jobs fail. Left off,
            #     DPoP is optional exactly as the debugger's own switch is: a
            #     proof binds the token, no proof gets a Bearer token, and both
            #     halves of the matrix run against one client.
            #   * webOrigins must carry the debugger's origin, because these jobs
            #     call the token endpoint from the BROWSER (the api cannot forward
            #     a DPoP proof). Without it the exchange dies in a CORS preflight
            #     with no status, which reads as the OP being down.
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
    # A PUBLIC client has no secret, and Keycloak says so by answering
    # `"secret": null` — which `jq -r` renders as the four characters "null".
    # That string is then exported as ${FLOW_VARIABLE}_CLIENT_SECRET and typed
    # into the debugger's Client Secret field, where it is harmless: a public
    # client is not authenticated and the value is ignored.
    #
    # WHAT IS NOT HARMLESS IS A TEST SEARCHING FOR IT. Since the token history
    # started keeping a redacted copy of each exchange, every stored generation
    # contains `"failure":null`, so tests/oidc_authorization_code.js's "the
    # client secret must not have reached token_history" check matched the JSON
    # null and failed BOTH public jobs on 2026-08-24 — naming a credential that
    # does not exist. The confidential jobs, whose secret is a real one, passed.
    #
    # So the placeholder is made unmistakable instead of removed. It cannot be
    # left EMPTY: every one of these tests asserts CLIENT_SECRET is set, and the
    # blank check below would exit first. It cannot stay "null": that is a
    # substring of ordinary JSON. A name that says what it is keeps the
    # redaction check meaningful on a public client — the field still holds
    # something, it is still sent, and it still must not reach storage.
    if [ "${CLIENT_SECRET}" = "null" ];
    then
      CLIENT_SECRET="public-client-has-no-secret-${FLOW_NAME}"
    fi
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
    # Name the variable that is blank rather than only the fact that one is.
    # Each of these is read out of a curl response, so a blank one is a failed
    # call — and the failure that actually happens is a 409 on the user POST
    # (no Location header, so USER_ID is empty) when a debugger-testing realm
    # survived from a previous run. The old message named nothing and the
    # caller had to re-run the curl by hand to find out which.
    BLANK_VARIABLES=""
    for REQUIRED_VARIABLE in CLIENT_ID CLIENT_CLIENTID CLIENT_SECRET \
                             SCOPE_ID SCOPE_NAME USER_ID
    do
      if [ -z "${!REQUIRED_VARIABLE}" ];
      then
        BLANK_VARIABLES="${BLANK_VARIABLES} ${REQUIRED_VARIABLE}"
      fi
    done
    if [ -n "${BLANK_VARIABLES}" ];
    then
      echo "Required variable is blank, provisioning ${FLOW_NAME}:" \
           "${BLANK_VARIABLES# }" >&2
      echo "A blank USER_ID here is a 409 from Keycloak — the" \
           "debugger-testing realm already holds this user, so the realm" \
           "was not reset before configureKeycloak. See" \
           "resetKeycloakRealm()." >&2
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
    # The name typed at the login screen, which is NOT ${FLOW_VARIABLE}_USER: that
    # one is Keycloak's UUID for the user, which is what appears in a token's
    # `sub`. Both are needed by a test that signs in and then checks who the token
    # describes, and conflating them is easy — the username happens to equal the
    # client id here, so a test that used the wrong variable would still log in.
    declare -gx ${FLOW_VARIABLE}_USERNAME="${FLOW_NAME}"

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
  #
  # webOrigins registers the debugger's origin for CORS, as every client in the
  # main realm does. Be clear about what it can and cannot do here: Keycloak emits
  # CORS headers per ENDPOINT, from a client context, and the cloudtrust extension's
  # metadata endpoint has none — `@GET @Path("descriptor")` in WSFedService returns a
  # bare String, and there is no Cors.add() anywhere in the extension. So a browser
  # on another origin CANNOT fetch /protocol/wsfed/descriptor whatever is configured
  # here; the WS-Fed page's metadata load is best-effort for that reason and the
  # test falls back to the derived sign-in endpoint. This setting is for the
  # endpoints that DO carry a client context, and for consistency with the rest of
  # the provisioning.
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
          "webOrigins": [ "'"${WSFED_UI_BASE}"'", "'"${WSFED_API_BASE}"'" ],
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
