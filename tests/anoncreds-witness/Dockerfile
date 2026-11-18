# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

# THE ANONCREDS WITNESS, AS AN IMAGE (#479).
#
# anoncreds-rs is the implementation the AnonCreds ecosystem runs, and the
# only one the debugger's pure-JS AnonCreds (client/src/anoncreds*.js) can be
# held to: the specification publishes no test vectors, and an
# implementation of CL signatures that is checked only against itself can
# agree with itself and interoperate with nothing. So the tests run
# anoncreds-rs as issuer, holder and verifier against the wallet.
#
# Its node binding, @hyperledger/anoncreds-nodejs, fetches the native
# library from GitHub at INSTALL time (scripts/install.js). Here it is
# installed with --ignore-scripts from the lock file beside this
# Dockerfile, and the library is added by ADD --checksum and given the
# version.json the install script would have written, so the binding loads
# it as installed. Built and pushed to the private mirror as
# anoncreds-witness:<binding>-<library> by .github/scripts/mirror-builds.sh
# (.github/image-mirror-builds.txt); tests/Dockerfile copies /anoncreds out
# of it, so no test-image build reaches GitHub or npm's install scripts.
#
# A bump changes package.json and package-lock.json here, the library URL
# and its sha256 below, the tag in image-mirror-builds.txt and the FROM in
# tests/Dockerfile. linux x86_64 only: it is what the suite runs on.
FROM node:24.22.1-bookworm-slim AS build
WORKDIR /opt/anoncreds
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
ADD --checksum=sha256:f54f262dd63422830ce15f3240b82ffb729c3159a225d42ddd9e948d6f5582c9 \
    https://github.com/anoncreds/anoncreds-rs/releases/download/v0.2.3/library-linux-x86_64.tar.gz \
    /tmp/library-linux-x86_64.tar.gz
RUN native=node_modules/@hyperledger/anoncreds-nodejs/native \
 && mkdir -p "$native" \
 && tar -xzf /tmp/library-linux-x86_64.tar.gz -C "$native" \
        --strip-components=1 \
 && echo '{"version":"v0.2.3"}' > "$native/version.json" \
 && test -f "$native/libanoncreds.so"

FROM scratch
COPY --from=build /opt/anoncreds /anoncreds
