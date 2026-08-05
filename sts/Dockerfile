# The mock STS: eight protocol families in one small Node service. See README.md.
#
# Pinned to Node 24.16.0 via nvm rather than an official node image, which is what
# the project this was extracted from does for all of its services.
FROM ubuntu:latest

# replace shell with bash so we can source files
RUN rm /bin/sh && ln -s /bin/bash /bin/sh

# Create app directory
WORKDIR /usr/src/sts

RUN apt-get update
RUN apt-get -y install curl \
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

# add node and npm to path so the commands are available
ENV NODE_PATH $NVM_DIR/v$NODE_VERSION/lib/node_modules
ENV PATH $NVM_DIR/versions/node/v$NODE_VERSION/bin:$PATH

# confirm installation
RUN node -v
RUN npm -v

# Install dependencies (package-lock.json is optional; wildcard copies it when
# present so `npm ci`-style reproducibility works once a lock is committed).
COPY package*.json ./
RUN npm install --omit=dev && npm cache clean --force

# The service is eleven modules, and server.js is only the shell that requires the
# other ten and listens. They are copied as a GROUP for exactly the reason the
# individual COPY lines below exist for their files: a module left out is not a
# missing feature, it is a MODULE_NOT_FOUND at startup, so the container never
# listens and every STS-backed job in the suite fails on a timeout that says
# nothing about the cause. This wildcard is deliberate — a per-file list here
# would have to be edited every time a module is added, and forgetting is silent
# until the containerized run.
COPY *.js ./
# The JSON-LD contexts the bbs-2023 cryptosuite (bbs2023.js, copied above) loads AT
# REQUIRE TIME. Mandatory: the module reads them at module scope, so a missing one is
# not a degraded feature — the service does not start at all. In the parent project
# these live in the client's tree and bbs2023.js looks there first; here they are a
# sibling directory, which is that function's second candidate.
COPY contexts ./contexts
# The service selects its configuration (log level) with CONFIG_FILE, the same
# way api and client do. The compose files override this per stack.
COPY env ./env
ENV CONFIG_FILE=./env/local.js

EXPOSE 8081
CMD [ "node", "server.js" ]
