#FROM node:lts
FROM ubuntu:latest
        
ARG CONFIG_FILE

# replace shell with bash so we can source files
RUN rm /bin/sh && ln -s /bin/bash /bin/sh

# Create app directory
WORKDIR /usr/src/app

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
    
# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
# where available (npm@5+)
COPY client/package.json client/package-lock.json /usr/src/app/
RUN npm ci && npm cache clean --force
RUN npm install -g browserify
#RUN npm install -g node-gyp

# If you are building your code for production
# RUN npm ci --only=production

# Bundle app source
COPY client/public/ /usr/src/app/public/
#COPY dist/ /usr/src/app/public/dist/
COPY client/src/env/ /usr/src/app/env/
COPY client/server.js /usr/src/app
COPY client/package.json /usr/src/app
# Application version: the repo-root VERSION file (M.N) plus the stamping module.
COPY VERSION /usr/src/app/VERSION
COPY client/version.js /usr/src/app/version.js
RUN true
COPY client/src/ /usr/src/app/src/
RUN true
COPY client/src/env/ /usr/src/app/public/js/env/
COPY common/data.js /usr/src/app/src
# The Kerberos codec, staged into src/ the same way and for the same reason:
# kerberos_decoder.js requires('./krb5_describe.js'), which requires its siblings,
# so browserify has to find them beside the bundle entry point. They live in
# common/krb5/ because the api's relay and the mock KDC read the same code.
# client/build.js does the equivalent staging for the static deployments — BOTH
# have to be kept in step, which is the same two-places rule as the browserify
# line further down.
COPY common/krb5/ /usr/src/app/src/
RUN browserify src/jwks.js -o public/js/jwks.js --debug --standalone jwks -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/oauth2_oidc_1.js -o public/js/oauth2_oidc_1.js --debug --standalone oauth2_oidc_1 -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/token_detail.js -o public/js/token_detail.js --debug --standalone token_detail -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/oauth2_oidc_2.js -o public/js/oauth2_oidc_2.js --debug --standalone oauth2_oidc_2 -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/userinfo.js -o public/js/userinfo.js --debug --standalone userinfo -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/introspection.js -o public/js/introspection.js --debug --standalone introspection -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]

RUN browserify src/logout.js -o public/js/logout.js --debug --standalone logout -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/jwt_tools.js -o public/js/jwt_tools.js --debug --standalone jwt_tools -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/encoding_tools.js -o public/js/encoding_tools.js --debug --standalone encoding_tools -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/digital_signature.js -o public/js/digital_signature.js --debug --standalone digital_signature -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/encryption_tools.js -o public/js/encryption_tools.js --debug --standalone encryption_tools -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/saml_request.js -o public/js/saml_request.js --debug --standalone saml_request -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/saml_cert.js -o public/js/saml_cert.js --debug --standalone saml_cert -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/saml_tools.js -o public/js/saml_tools.js --debug --standalone saml_tools -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/saml_response.js -o public/js/saml_response.js --debug --standalone saml_response -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/wstrust_tools.js -o public/js/wstrust_tools.js --debug --standalone wstrust_tools -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/wstrust_response.js -o public/js/wstrust_response.js --debug --standalone wstrust_response -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/vc_issuance_0.js -o public/js/vc_issuance_0.js --debug --standalone vcissuance0 -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/vc_issuance_1.js -o public/js/vc_issuance_1.js --debug --standalone vcissuance1 -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/vc_issuance_2.js -o public/js/vc_issuance_2.js --debug --standalone vcissuance2 -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/vc_issuance_3.js -o public/js/vc_issuance_3.js --debug --standalone vcissuance3 -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/vc_issuance_4.js -o public/js/vc_issuance_4.js --debug --standalone vcissuance4 -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/vc_presentation_0.js -o public/js/vc_presentation_0.js --debug --standalone vcpresentation0 -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/vc_presentation_1.js -o public/js/vc_presentation_1.js --debug --standalone vcpresentation1 -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/vc_presentation_2.js -o public/js/vc_presentation_2.js --debug --standalone vcpresentation2 -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
# DID Tools: a general-purpose DID verifier, reached from the VC Tools pane on
# every page of both VC workflows.
RUN browserify src/did_tools.js -o public/js/did_tools.js --debug --standalone didtools -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/webauthn_lab.js -o public/js/webauthn_lab.js --debug --standalone webauthnlab -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/webauthn_analyzer.js -o public/js/webauthn_analyzer.js --debug --standalone webauthnanalyzer -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/vc_presentation_3.js -o public/js/vc_presentation_3.js --debug --standalone vcpresentation3 -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/wsfed_request.js -o public/js/wsfed_request.js --debug --standalone wsfed_request -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/wsfed_response.js -o public/js/wsfed_response.js --debug --standalone wsfed_response -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/kerberos_decoder.js -o public/js/kerberos_decoder.js --debug --standalone kerberos_decoder -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/kerberos.js -o public/js/kerberos.js --debug --standalone kerberos -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/kerberos_tgs.js -o public/js/kerberos_tgs.js --debug --standalone kerberos_tgs -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/kerberos_ap.js -o public/js/kerberos_ap.js --debug --standalone kerberos_ap -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/kerberos_delegation.js -o public/js/kerberos_delegation.js --debug --standalone kerberos_delegation -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
# SPNEGO. Its bundle requires the SAME common/krb5 codec the five pages above
# do — the COPY that stages those modules into src/ is further up and covers
# this too — plus krb5_spnego.js, which is new. A missing staging here is
# "Cannot find module './krb5_spnego.js'" naming a file that exists two
# directories away.
RUN browserify src/spnego.js -o public/js/spnego.js --debug --standalone spnego -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
# LDAP. Like the six Kerberos pages above it cannot work without the api — RFC
# 4511 is BER over a TCP socket — so client/static_site.js keeps it out of the
# static deployments. This line stays regardless: the exclusion is static-only,
# and tests/static_site_exclusions.js fails if the container build loses a page.
RUN browserify src/ldap.js -o public/js/ldap.js --debug --standalone ldap -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/pki.js -o public/js/pki.js --debug --standalone pki -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
RUN browserify src/scim.js -o public/js/scim.js --debug --standalone scim -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ]
#COPY src/debugger2_js.js public/js

# ---- Code coverage (opt-in) ----
# When built with --build-arg COVERAGE=true, re-build the bundles with Istanbul
# instrumentation (babel-plugin-istanbul) and append the coverage beacon so the
# browser ships its coverage to the client server. The default build
# (COVERAGE=false) leaves the bundles produced above completely untouched.
# NOTE: the loop below is a THIRD place every bundle must be listed — after the
# BUNDLES array in build.js and the RUN browserify lines above. Miss it and the
# page still works and still ships; it simply reports no coverage, silently. The
# two webauthn bundles were missing from it until 2026-08-09.
#
# IT IS NO LONGER SHORT, and it is no longer only a comment that says so.
# Until 2026-08-22 seven bundles were missing here — the six Kerberos ones
# (kerberos, kerberos_tgs, kerberos_ap, kerberos_delegation, kerberos_decoder,
# spnego) and pki — so `./run-coverage.sh` reported nothing at all for seven
# pages while every one of them built, shipped and passed its own tests. That
# is the exact failure mode this note warns about, left standing for months
# because a comment is not a check.
#
# `coverageListCoversEveryBundle()` in tests/jwk_pem_encoding.js now reads THIS
# FILE and compares the three lists — the RUN browserify lines above, the loop
# below, and the BUNDLES array in client/build.js — and fails naming the bundle
# that is missing from whichever one. It runs on every ordinary suite run, not
# just under ./run-coverage.sh, which is the point: the plain launchers never
# execute this block, so nothing else can see a gap in it.
#
# So add a bundle in THREE places and the check will tell you which you forgot.
# It reads the loop as a STATEMENT rather than as a line, so wrapping this
# `for` across several lines is safe.
ARG COVERAGE=false
RUN if [ "$COVERAGE" = "true" ]; then \
      npm install --no-save babelify babel-plugin-istanbul @babel/core nyc ; \
    fi
RUN if [ "$COVERAGE" = "true" ]; then \
      for entry in "jwks:jwks" "oauth2_oidc_1:oauth2_oidc_1" "token_detail:token_detail" "oauth2_oidc_2:oauth2_oidc_2" "userinfo:userinfo" "introspection:introspection" "logout:logout" "jwt_tools:jwt_tools" "encoding_tools:encoding_tools" "digital_signature:digital_signature" "encryption_tools:encryption_tools" "saml_request:saml_request" "saml_cert:saml_cert" "saml_tools:saml_tools" "saml_response:saml_response" "wstrust_tools:wstrust_tools" "wstrust_response:wstrust_response" "vc_issuance_0:vcissuance0" "vc_issuance_1:vcissuance1" "vc_issuance_2:vcissuance2" "vc_issuance_3:vcissuance3" "vc_issuance_4:vcissuance4" "vc_presentation_0:vcpresentation0" "vc_presentation_1:vcpresentation1" "vc_presentation_2:vcpresentation2" "vc_presentation_3:vcpresentation3" "did_tools:didtools" "wsfed_request:wsfed_request" "wsfed_response:wsfed_response" "webauthn_lab:webauthnlab" "webauthn_analyzer:webauthnanalyzer" "kerberos_decoder:kerberos_decoder" "kerberos:kerberos" "kerberos_tgs:kerberos_tgs" "kerberos_ap:kerberos_ap" "kerberos_delegation:kerberos_delegation" "spnego:spnego" "ldap:ldap" "pki:pki" "scim:scim" ; do \
        src_name="${entry%%:*}" ; \
        standalone="${entry##*:}" ; \
        browserify src/${src_name}.js -o public/js/${src_name}.js --debug --standalone ${standalone} -t [ envify purge --CONFIG_FILE ${CONFIG_FILE} ] -t [ babelify --plugins [ istanbul ] ] && \
        cat src/coverage_beacon.js >> public/js/${src_name}.js ; \
      done ; \
    fi

# Fix this image's build number (M.N.O) and ship it in public/version.json.
# BUILD_NUMBER (and GIT_COMMIT) can be supplied by CI: --build-arg BUILD_NUMBER=...
ARG BUILD_NUMBER
ARG GIT_COMMIT
RUN BUILD_NUMBER="${BUILD_NUMBER}" GIT_COMMIT="${GIT_COMMIT}" node version.js --stamp public && \
    cat public/version.json

EXPOSE 3000
CMD [ "npm", "start" ]
