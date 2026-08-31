# Build + deploy image for the static idptools.com site.
#
# Follows the same base pattern as client/Dockerfile (Ubuntu + NVM + Node),
# and additionally installs AWS CLI v2. The container builds the static client
# content and pushes it to S3 + invalidates CloudFront via deploy/entrypoint.sh.
# It is run identically on a developer machine (deploy/deploy-local.sh) and in
# GitHub Actions (.github/workflows/website-deploy.yml).
FROM ubuntu:latest

# replace shell with bash so we can source files
RUN rm /bin/sh && ln -s /bin/bash /bin/sh

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
        ca-certificates \
        util-linux \
        bsdextrautils

# --- AWS CLI v2 (self-contained; no system python conflicts) ---
RUN curl -fsSL --retry 5 --retry-all-errors --retry-delay 10 \
        "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip \
    && unzip -q /tmp/awscliv2.zip -d /tmp \
    && /tmp/aws/install \
    && rm -rf /tmp/aws /tmp/awscliv2.zip \
    && aws --version

# --- Node via NVM (same approach as client/Dockerfile) ---
ENV NVM_DIR=/usr/local/nvm
ENV NODE_VERSION=24.16.0
RUN mkdir -p ${NVM_DIR}
RUN set -o pipefail && curl -fsSL --retry 5 --retry-all-errors --retry-delay 10 \
        https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.5/install.sh | bash

RUN source $NVM_DIR/nvm.sh \
    && nvm install $NODE_VERSION \
    && nvm alias default $NODE_VERSION \
    && nvm use default

ENV NODE_PATH=$NVM_DIR/v$NODE_VERSION/lib/node_modules
ENV PATH=$NVM_DIR/versions/node/v$NODE_VERSION/bin:$PATH

RUN node -v && npm -v

# --- Install client dependencies (cached layer) ---
COPY client/package.json client/package-lock.json /usr/src/app/client/
RUN cd client && npm ci && npm cache clean --force

# --- Bundle sources needed for the build ---
COPY client/ /usr/src/app/client/
COPY common/ /usr/src/app/common/
# The M.N source of truth read by client/version.js during the build.
COPY VERSION /usr/src/app/VERSION
# build.js stages api/jwt.xml -> dist/claimdescription so the static site serves
# the IANA claim registry (the static site has no api backend to serve it).
COPY api/jwt.xml /usr/src/app/api/jwt.xml
COPY deploy/entrypoint.sh /usr/src/app/deploy/entrypoint.sh
RUN chmod +x /usr/src/app/deploy/entrypoint.sh

# ---------------------------------------------------------------------------
# NON-ROOT FROM HERE ON. See the same block in api/Dockerfile for why the UID
# is 10001 rather than 1000 (ubuntu:latest already has an account at 1000).
#
# This image HOLDS AWS CREDENTIALS for the length of a deploy — deploy-local.sh
# resolves the developer's SSO session and hands them over with --env-file, and
# the workflow hands over a role's — so it is the one here where "the process
# is not uid 0" is worth the most and costs the least: it mounts nothing, it
# writes only under /usr/src/app (entrypoint.sh runs `npm run build`, which
# fills client/dist), and it talks to S3 and CloudFront.
#
# HOME matters more here than elsewhere: the AWS CLI writes ~/.aws/cli/cache
# and its SSO/credential caches, and a HOME it cannot write turns a working
# deploy into an error naming a cache directory.
# ---------------------------------------------------------------------------
RUN groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid 10001 --create-home \
        --shell /bin/bash appuser \
    && chown -R appuser:appuser /usr/src/app

ENV HOME=/home/appuser
USER appuser

ENTRYPOINT ["/usr/src/app/deploy/entrypoint.sh"]
