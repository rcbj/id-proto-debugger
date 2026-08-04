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
COPY tests/oauth2_* tests/oidc_* tests/token_introspection.js tests/jwt_tools.js tests/encoding_tools.js tests/digital_signature.js tests/saml_sso.js tests/saml_logout.js tests/saml_encrypted_sso.js tests/saml_tools.js tests/saml_operation_history.js tests/wstrust_operation_history.js tests/wsfed_sso.js tests/wstrust.js tests/xmlsec_interop.js tests/wstrust_schema_validate.js tests/navigation.js tests/sd_jwt_vc_issuance.js tests/sd_jwt_vc_waltid.js tests/sd_jwt_vc_presentation.js tests/sd_jwt_vc_presentation_waltid.js tests/jose_jwe.js tests/module_paths.js tests/browser_flags.js tests/api_ssrf_guard.js tests/api_connect_timeout.js tests/edge_landing_contract.js tests/jwk_pem.js tests/url_safety.js tests/xml_parse_inert.js tests/keypair_storage_optout.js tests/wait_for.js tests/jwt_vc_json_common.js tests/jwt_vc_json_issuance.js tests/jwt_vc_json_presentation.js tests/jwt_vc_json_issuance_waltid.js tests/jwt_vc_json_presentation_waltid.js tests/metadata_schema_validation.js tests/bbs_crypto.js tests/bbs2023_cryptosuite.js tests/ldp_vc_issuance.js tests/ldp_vc_refresh.js tests/ldp_vc_presentation.js tests/oid4vci_request_encryption.js tests/did_document.js tests/vc_did.js tests/sts_metadata.js tests/did_tools.js tests/dpop.js tests/sts_dpop.js tests/dpop_workflow.js ./
# The XML Signature/Encryption interop test drives the frontend crypto module
# directly (no browser); copy it next to the test so it can require('./xmldsig.js')
# and resolve its deps (node-forge, etc.) from this image's node_modules. The
# WS-Trust schema test likewise builds messages with the real generator
# (wstrust_msg.js) and validates them against the derived XSD in ./schemas.
COPY client/src/xmldsig.js client/src/wstrust_msg.js client/src/jose_jwe.js client/src/edge_landing.js ./
# The JWK -> SPKI PEM encoder, tested the same way (tests/jwk_pem.js requires it
# directly). Note that in this image there is no client/src tree, so that test's
# scan for requires which would pull `elliptic` back into a bundle reports itself
# skipped — the scan runs in a checkout, where the sources are present.
COPY client/src/jwk_pem.js ./
# The scheme allowlist, tested directly by tests/url_safety.js.
COPY client/src/url_safety.js ./
# The metadata schema checker, loaded directly by
# tests/metadata_schema_validation.js. That test is named _validation for a
# reason: this COPY lands the module FLAT beside the test scripts, so a test
# named metadata_schema.js would be overwritten by it (or overwrite it) depending
# on which COPY ran last, and the failure would be silent.
COPY client/src/metadata_schema.js ./
# The BBS implementation, loaded directly by tests/bbs_crypto.js and checked
# there against @digitalbazaar/bbs-signatures.
COPY client/src/bbs.js ./
# The bbs-2023 cryptosuite, BOTH implementations, for tests/bbs2023_cryptosuite.js
# — the wallet's and the STS's. They share a basename and this image copies flat,
# so the STS's is renamed on the way in; the test resolves either layout.
# client/src/bbs2023.js does require("./contexts/..."), so the vendored JSON-LD
# contexts come too: canonicalization must never depend on fetching one.
COPY client/src/bbs2023.js ./
COPY sts/bbs2023.js ./sts_bbs2023.js
COPY client/src/contexts ./contexts
# The wallet's side of OID4VCI, loaded directly by tests/ldp_vc_issuance.js so
# that it covers what the PAGE does with a Credential Response and not only what
# the issuer sends. Those two are not the same check, and the gap between them
# is where ldp_vc broke: an issuer verified correct by this very test, and a
# step 2 that reported "the response carries no credential".
# metadata_client.js, vci_metadata.js and op_metadata.js are not used by the test
# directly — they are what these two require at load time, and a missing one is
# a MODULE_NOT_FOUND at require, i.e. a hard failure rather than a silent skip.
COPY client/src/vci_wallet.js client/src/sd_jwt_vc.js ./
# DPoP (RFC 9449), loaded directly by tests/dpop.js so the thumbprint, htu, ath and
# proof can be checked against the RFCs' own published vectors without a browser.
# Omit this COPY and that test vanishes from the image rather than failing, which is
# the silent outcome this file's other comments warn about.
COPY client/src/dpop.js ./
# The wallet's DID module, loaded directly by tests/did_document.js (which is
# named that way ON PURPOSE: this COPY lands the module flat as did.js, so a test
# called did.js would silently overwrite it or be overwritten by it, depending on
# which COPY ran last) and by tests/vc_did.js, which resolves the issuer's DID
# with the same code the pages use.
COPY client/src/did.js ./
COPY client/src/metadata_client.js client/src/vci_metadata.js client/src/op_metadata.js ./
# The two halves of the edge landings' hand-off contract, which
# tests/edge_landing_contract.js compares: the module deployed to Lambda@Edge by
# Terraform and the client module browserified into the page (copied just above).
# They cannot import each other, so a rename on one side alone is invisible until
# a deployed sign-in reports that nothing arrived — this is where it gets caught,
# before the deploy.
COPY infra/edge/edge_common.js ./
# The api modules tests/api_ssrf_guard.js and tests/api_connect_timeout.js
# exercise. Copied flat, like the client modules above; the tests look for them in
# both layouts. Note that api_connect_timeout.js also reads api/env/*.js and
# api/server.js when they are present, and skips that half of itself when they are
# not — so it is useful here without the whole api tree being staged.
COPY api/ssrf_guard.js ./
COPY api/connect_timeout.js ./
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
