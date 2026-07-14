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

RUN apt-get update
RUN apt-get -y install curl \
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
COPY deploy/entrypoint.sh /usr/src/app/deploy/entrypoint.sh
RUN chmod +x /usr/src/app/deploy/entrypoint.sh

ENTRYPOINT ["/usr/src/app/deploy/entrypoint.sh"]
