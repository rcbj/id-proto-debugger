#!/usr/bin/env bash
#
# embedded/build.sh --out <dir>
#
# ---------------------------------------------------------------------------
# BUILDS THE DEBUGGER THE MOCK STS EMBEDS, WITHOUT DOCKER.
#
# The mock STS serves this debugger's UI as static files on an origin of its
# own and forks its api as a child on a unix socket (embedded/CLAUDE.md). What
# it consumes is one directory tree, and this script writes it:
#
#   <dir>/ui/            client/build.js, DEPLOYMENT=embedded,
#                        CONFIG_FILE=./env/embedded.js
#   <dir>/api/           a runnable api: `cd <dir>/api && node server.js`
#   <dir>/common/        what the api requires as ../common/...
#   <dir>/version.json   the build's M.N.O, the same record as api/version.json
#
# embedded/Dockerfile runs this same script, so there is ONE description of
# the tree rather than a script and a Dockerfile that can disagree.
#
# ---------------------------------------------------------------------------
# NOTHING IN THE CHECKOUT IS TOUCHED, and that is why the work happens in a
# copy. client/build.js stages common/ modules into client/src and removes
# them; `npm ci` REPLACES node_modules; `node version.js --stamp` writes a
# file; the api's Dockerfile copies four files into api/. Doing any of that in
# the working tree would disturb a stack another session is running from it
# (several run concurrently on one machine), and a failed build would leave
# copies behind. So the sources are copied to a temporary directory, every
# install and build runs there, the finished tree is copied to <dir>, and the
# temporary directory is removed on exit however the script ends.
#
# The copy takes what is ON DISK — tracked, untracked and modified files alike
# — minus node_modules, build output and the per-build files the images write,
# which is what a `docker build` of this checkout would see.
#
# Environment:
#   BUILD_NUMBER   the O of M.N.O; default the UTC instant. Set ONCE here so
#                  the UI's and the api's version.json agree.
#   GIT_COMMIT     default `git rev-parse --short=12 HEAD` when there is a .git.
#   MINIFY         passed to client/build.js; default on.
#   NPM            the npm to run; default `npm`.
# ---------------------------------------------------------------------------
set -euo pipefail

usage() {
  echo "usage: $0 --out <dir>" >&2
}

OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --out)
      if [ $# -lt 2 ]; then
        usage
        exit 2
      fi
      OUT="$2"
      shift 2
      ;;
    --out=*)
      OUT="${1#--out=}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "embedded/build.sh: unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done
if [ -z "${OUT}" ]; then
  usage
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NPM="${NPM:-npm}"

log() {
  echo "[embedded/build.sh] $*"
}

# ---------------------------------------------------------------------------
# Preconditions, each of which otherwise fails far from its cause.
# ---------------------------------------------------------------------------
command -v node >/dev/null 2>&1 || {
  echo "embedded/build.sh: node is not on PATH." >&2
  exit 1
}
command -v "${NPM}" >/dev/null 2>&1 || {
  echo "embedded/build.sh: ${NPM} is not on PATH." >&2
  exit 1
}
# An uninitialised submodule is an EMPTY DIRECTORY: the copy succeeds, npm
# installs a package with no main, and the api dies at startup with
# `Cannot find module 'ldapjs'` — a message naming a package, not a submodule.
if [ ! -f "${REPO_ROOT}/api/node-ldapjs/package.json" ]; then
  echo "embedded/build.sh: api/node-ldapjs is empty. Run" \
       "\`git submodule update --init --recursive\` first." >&2
  exit 1
fi

mkdir -p "${OUT}"
OUT="$(cd "${OUT}" && pwd)"
case "${OUT}" in
  /|"${HOME}"|"${REPO_ROOT}"|"${REPO_ROOT}/api"|"${REPO_ROOT}/client"|\
"${REPO_ROOT}/common")
    echo "embedded/build.sh: refusing --out ${OUT}: its ui/, api/ and" \
         "common/ are replaced." >&2
    exit 1
    ;;
esac

# One build number for the whole tree (see the header).
if [ -z "${BUILD_NUMBER:-}" ]; then
  BUILD_NUMBER="$(date -u +%Y%m%d%H%M%S)"
fi
export BUILD_NUMBER
if [ -z "${GIT_COMMIT:-}" ]; then
  GIT_COMMIT="$(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD 2>/dev/null \
    || true)"
fi
export GIT_COMMIT

WORK="$(mktemp -d "${TMPDIR:-/tmp}/debugger-embedded.XXXXXX")"
cleanup() {
  rm -rf "${WORK}"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. The sources, copied. The excludes are the per-build artifacts: installs,
#    client/dist, the version stamps, and the four files api/Dockerfile copies
#    INTO api/ (a stale one left in a checkout must not be what ships — they
#    are written fresh in step 4). `.git` is the submodule's pointer FILE.
# ---------------------------------------------------------------------------
log "copying sources to ${WORK}/tree"
mkdir -p "${WORK}/tree"
tar -C "${REPO_ROOT}" \
    --exclude=node_modules \
    --exclude=.git \
    --exclude=client/dist \
    --exclude=client/public/version.json \
    --exclude=client/src/data.js \
    --exclude=client/src/xmldsig.js \
    --exclude=api/data.js \
    --exclude=api/xmldsig.js \
    --exclude=api/VERSION \
    --exclude=api/version.js \
    --exclude=api/version.json \
    --exclude=api/sts-ca.pem \
    -cf - VERSION client api common \
  | tar -C "${WORK}/tree" -xf -

# ---------------------------------------------------------------------------
# 2. The UI. `npm ci` includes the devDependencies, which are the bundler and
#    the minifiers — the build needs them and nothing ships them.
# ---------------------------------------------------------------------------
log "installing the client's build dependencies"
(cd "${WORK}/tree/client" && "${NPM}" ci --no-audit --no-fund)
log "building the UI (DEPLOYMENT=embedded)"
(cd "${WORK}/tree/client" && \
  DEPLOYMENT=embedded CONFIG_FILE=./env/embedded.js \
  OUT_DIR="${WORK}/ui" GA_MEASUREMENT_ID="" \
  node build.js)

# ---------------------------------------------------------------------------
# 3. The api's production dependencies, exactly as api/Dockerfile installs
#    them: `npm install --omit=dev` with node-ldapjs INSIDE the package root,
#    because npm links a `file:` dependency and node resolves that package's
#    own requires from where the real directory lives. The link npm writes is
#    relative (node_modules/ldapjs -> ../node-ldapjs), so it survives the copy
#    to <dir> and a `COPY --from` into another image.
# ---------------------------------------------------------------------------
log "installing the api's production dependencies"
(cd "${WORK}/tree/api" && "${NPM}" install --omit=dev --no-audit --no-fund)

# ---------------------------------------------------------------------------
# 4. What api/Dockerfile stages beside the api: data.js and xmldsig.js from
#    common/, the repo-root VERSION and the client's version.js (one
#    implementation of M.N.O), and the stamp.
# ---------------------------------------------------------------------------
log "staging common/data.js, common/xmldsig.js, VERSION and version.js"
cp "${WORK}/tree/common/data.js" "${WORK}/tree/api/data.js"
cp "${WORK}/tree/common/xmldsig.js" "${WORK}/tree/api/xmldsig.js"
cp "${WORK}/tree/VERSION" "${WORK}/tree/api/VERSION"
cp "${WORK}/tree/client/version.js" "${WORK}/tree/api/version.js"
(cd "${WORK}/tree/api" && node version.js --stamp .)

# ---------------------------------------------------------------------------
# 5. The tree. Only the four names this script owns are replaced in <dir>;
#    anything else a caller keeps there is left alone.
# ---------------------------------------------------------------------------
log "writing ${OUT}"
rm -rf "${OUT}/ui" "${OUT}/api" "${OUT}/common" "${OUT}/version.json"
cp -a "${WORK}/ui" "${OUT}/ui"
cp -a "${WORK}/tree/api" "${OUT}/api"
# What the api requires as ../common/... — api/Dockerfile's two COPYs into
# /usr/src/common, and nothing more.
mkdir -p "${OUT}/common"
cp -a "${WORK}/tree/common/tls_listener.js" "${OUT}/common/tls_listener.js"
cp -a "${WORK}/tree/common/spiffe" "${OUT}/common/spiffe"
cp "${OUT}/api/version.json" "${OUT}/version.json"

# ---------------------------------------------------------------------------
# 6. Checks that are cheap here and expensive to discover in the mock STS.
# ---------------------------------------------------------------------------
if ! grep -lq "__STS_EMBED_STS_URL__" "${OUT}"/ui/js/*.js; then
  echo "embedded/build.sh: no bundle under ${OUT}/ui/js carries" \
       "__STS_EMBED_STS_URL__." >&2
  exit 1
fi
for required in server.js env/embedded.js data.js xmldsig.js version.json \
    jwt.xml protos node_modules/ldapjs/package.json; do
  if [ ! -e "${OUT}/api/${required}" ]; then
    echo "embedded/build.sh: ${OUT}/api/${required} is missing." >&2
    exit 1
  fi
done
(cd "${OUT}/api" && node -e "require('ldapjs'); require('@grpc/grpc-js');" \
  ) || {
  echo "embedded/build.sh: the api tree cannot resolve its dependencies." >&2
  exit 1
}

BUILT_VERSION="$(cd "${OUT}" && \
  node -e "process.stdout.write(require('./version.json').version)")"
log "done: ${BUILT_VERSION} in ${OUT}"
