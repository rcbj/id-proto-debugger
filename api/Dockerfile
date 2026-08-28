FROM ubuntu:latest

ARG CONFIG_FILE

# replace shell with bash so we can source files
RUN rm /bin/sh && ln -s /bin/bash /bin/sh

# Create app directory
WORKDIR /usr/src/app

# ONE RUN, deliberately: see the note above the same pair in
# tests/Dockerfile. A cached `RUN apt-get update` layer keeps naming package
# versions the archive pool has already superseded and dropped, and the
# install below then 404s on every -updates/-security package at once — a
# failure that reads as a broken mirror and is not one.
RUN apt-get update \
    && apt-get -y install curl \
        jq \
        wget \
        unzip \
        util-linux \ 
        bsdextrautils
 
# Install NVM
ENV NVM_DIR /usr/local/nvm
ENV NODE_VERSION=24.16.0
RUN mkdir -p ${NVM_DIR}
RUN set -o pipefail && curl -fsSL --retry 5 --retry-all-errors --retry-delay 10 https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.5/install.sh | bash

# Load NVM and install Node.js
RUN . $NVM_DIR/nvm.sh && nvm version && echo -e ". $NVM_DIR/nvm.sh\nexport PATH=\$NVM_DIR/versions/node/\$(nvm version)/bin:\$PATH" >> ~/.bashrc
RUN cat ~/.bashrc

RUN source $NVM_DIR/nvm.sh \
    && nvm install $NODE_VERSION \
    && nvm alias default $NODE_VERSION \
    && nvm use default

# Symlink the node/npm/npx binaries nvm actually installed into a dir that is
# always on PATH. This avoids "npm: command not found" when the hardcoded
# v$NODE_VERSION path below ever drifts from the directory nvm created.
RUN source $NVM_DIR/nvm.sh \
    && ln -sf "$(dirname "$(nvm which default)")"/* /usr/local/bin/

# add node and npm to path so the commands are available
ENV NODE_PATH $NVM_DIR/versions/node/v$NODE_VERSION/lib/node_modules
ENV PATH $NVM_DIR/versions/node/v$NODE_VERSION/bin:$PATH

# confirm installation
RUN node -v
RUN npm -v

# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
# where available (npm@5+)
COPY api/package*.json ./
RUN npm -version
# The LDAP client's library is `"ldapjs": "file:node-ldapjs"` — the git
# SUBMODULE at api/node-ldapjs, pinned by commit and used unmodified — so it has
# to be in the image BEFORE npm runs, and at the path the manifest names.
#
# IT HAS TO SIT INSIDE THE PACKAGE ROOT, and that is not a tidiness choice. npm
# installs a `file:` dependency as a SYMLINK, and node then resolves that
# package's own requires by walking up from where the real directory lives — not
# from the symlink. With the submodule one level above /usr/src/app, the walk
# goes /usr/src/node_modules, /node_modules, and never reaches the
# node_modules the install just wrote. The failure is `Cannot find module
# 'abstract-logging'` from inside ldapjs, which names a package nobody here has
# ever heard of. Keeping it under api/ makes the walk arrive at
# /usr/src/app/node_modules on the first hop. The mock STS holds its copy the
# same way, for the same reason.
#
# An UNINITIALISED SUBMODULE IS AN EMPTY DIRECTORY, and this is where that
# shows up: the COPY succeeds, npm installs a package with no main, and the
# failure arrives at runtime as `Cannot find module 'ldapjs'` from
# api/ldap_client.js — which names a package. `git submodule update --init
# --recursive` is what fixes it; common/common.sh checks for it before building.
#
# .npmrc carries `omit=dev`, and it is load-bearing rather than tidiness: npm
# installs the devDependencies of a `file:` dependency, and ldapjs's are tap and
# eslint — some 200 packages and a dozen advisories that have nothing to do with
# this service. The flag below says the same thing twice on purpose, so a build
# that loses the .npmrc does not quietly start shipping them.
COPY api/.npmrc ./
COPY api/node-ldapjs ./node-ldapjs
RUN npm install --omit=dev
# If you are building your code for production
# RUN npm ci --only=production

# Bundle app source
COPY api/. .
COPY api/env/ /usr/src/app/env/
COPY common/data.js .
# The XML Signature engine. api/server.js signs the SAML redirect binding and
# the enveloped POST binding with it — it used to reach for the `xml-crypto`
# package instead, which made this application's THIRD implementation of XML
# Signature. Requires @xmldom/xmldom, which is already a dependency here.
COPY common/xmldsig.js .
# The SPIFFE ID grammar and the trust-bundle reader. WORKDIR is /usr/src/app, so
# this lands where `require('../common/spiffe/spiffe_id.js')` resolves it — the
# same relative path that works in a bare checkout, which is what keeps this
# from becoming a checked-in copy the way common/data.js had to.
COPY common/spiffe/ /usr/src/common/spiffe/

# Application version: the repo-root VERSION file (M.N) plus the shared stamping
# module, which is the client's — there is one implementation of the scheme and
# both services read it, rather than a second copy that could drift. Without the
# VERSION file the module falls back to 0.0, so this COPY is load-bearing.
COPY VERSION /usr/src/app/VERSION
COPY client/version.js /usr/src/app/version.js

# Fix this image's build number (M.N.O) and ship it in version.json, so the
# User-Agent this service sends names the build it came from and does not change
# when the container restarts. Supplied by CI as --build-arg BUILD_NUMBER=...
ARG BUILD_NUMBER
ARG GIT_COMMIT
RUN BUILD_NUMBER="${BUILD_NUMBER}" GIT_COMMIT="${GIT_COMMIT}" node version.js --stamp . && \
    cat version.json

# ---- Code coverage (opt-in) ----
# When built with --build-arg COVERAGE=true, install c8 so the coverage compose
# override can launch the server under it. No-op for the default build.
ARG COVERAGE=false
RUN if [ "$COVERAGE" = "true" ]; then npm install -g c8; fi

EXPOSE 4000

# ---------------------------------------------------------------------------
# The entrypoint installs the mock STS's certificate in node's truststore when
# STS_CERT_URL names one, and does nothing at all when it does not — see
# api/sts_truststore.sh for why that cannot be done at build time. It ends in
# `exec "$@"`, so CMD below is unchanged and so is docker-compose-coverage.yml's
# `command:` override, which replaces it with c8.
# ---------------------------------------------------------------------------
COPY api/sts_truststore.sh /usr/src/app/sts_truststore.sh
RUN chmod +x /usr/src/app/sts_truststore.sh
ENTRYPOINT [ "/usr/src/app/sts_truststore.sh" ]
CMD [ "npm", "start" ]
