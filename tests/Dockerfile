#FROM node:lts
FROM ubuntu:latest

# replace shell with bash so we can source files
RUN rm /bin/sh && ln -s /bin/bash /bin/sh

RUN apt-get update
# libxml2-utils supplies xmllint, the XSD validator the WS-Trust schema test
# falls back to when the optional native libxmljs2 binding is unusable (no
# prebuilt binary for this ABI, or one built against a different Node version).
RUN apt-get -y install curl \
        jq \
        openssl \
        libxml2-utils \
        libatomic1 \
        libasound2t64 \
        libatk-bridge2.0-0 \
        libgtk-4-1 \
        libnss3 \
        xdg-utils \
        wget \
        unzip \
        util-linux \
        bsdextrautils
 

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
# where available (npm@5+)
COPY tests/package*.json ./
COPY tests/run-tests-in-container.sh .
COPY common/common.sh .

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

# Bundle app source
COPY tests/oauth2_* tests/oidc_* tests/token_introspection.js tests/jwt_tools.js tests/encoding_tools.js tests/digital_signature.js tests/saml_sso.js tests/saml_logout.js tests/saml_encrypted_sso.js tests/saml_tools.js tests/saml_operation_history.js tests/wstrust_operation_history.js tests/wsfed_sso.js tests/wstrust.js tests/xmlsec_interop.js tests/wstrust_schema_validate.js tests/navigation.js tests/sd_jwt_vc_issuance.js tests/sd_jwt_vc_waltid.js tests/sd_jwt_vc_presentation.js tests/sd_jwt_vc_presentation_waltid.js tests/jose_jwe.js tests/module_paths.js tests/browser_secure_origin.js ./
# The XML Signature/Encryption interop test drives the frontend crypto module
# directly (no browser); copy it next to the test so it can require('./xmldsig.js')
# and resolve its deps (node-forge, etc.) from this image's node_modules. The
# WS-Trust schema test likewise builds messages with the real generator
# (wstrust_msg.js) and validates them against the derived XSD in ./schemas.
COPY client/src/xmldsig.js client/src/wstrust_msg.js client/src/jose_jwe.js ./
COPY tests/schemas ./schemas
COPY tests/run-report.js ./
# Shared test helpers (populateMetadata, ...). The test scripts require it as
# ../common/tests.js; WORKDIR is /usr/src/app, so it must land in /usr/src/common.
COPY common/tests.js /usr/src/common/tests.js
# The SAML SP key pair reader. The pair itself is generated per run inside the
# container (common.sh generateSpKeyPair) and passed through the environment —
# nothing is baked into the image.
COPY common/sp_keypair.js /usr/src/common/sp_keypair.js
# Centralized test config (waitTime, etc.); selected via CONFIG_FILE.
COPY tests/env ./env
# Fixed SP signing key/cert for the SAML signature-validation test + provisioning.
RUN ls
RUN wget -q -O chrome-linux64.zip https://edgedl.me.gvt1.com/edgedl/chrome/chrome-for-testing/121.0.6167.85/linux64/chrome-linux64.zip && \
    unzip chrome-linux64.zip && \
    rm chrome-linux64.zip && \
    mv chrome-linux64 /opt/chrome/ && \
    ln -s /opt/chrome/chrome /usr/local/bin/ && \
    wget -q -O chromedriver-linux64.zip https://edgedl.me.gvt1.com/edgedl/chrome/chrome-for-testing/121.0.6167.85/linux64/chromedriver-linux64.zip && \
    unzip -j chromedriver-linux64.zip chromedriver-linux64/chromedriver && \
    rm chromedriver-linux64.zip && \
    mv chromedriver /usr/local/bin/
RUN . $NVM_DIR/nvm.sh && npm install chromedriver

# Install modules needed for the test scripts
RUN . $NVM_DIR/nvm.sh && npm install

CMD [ "./run-tests-in-container.sh"]
