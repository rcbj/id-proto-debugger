#FROM node:lts
FROM ubuntu:latest

# replace shell with bash so we can source files
RUN rm /bin/sh && ln -s /bin/bash /bin/sh

RUN apt-get update
# libxml2-utils supplies xmllint, the XSD validator the WS-Trust schema test
# falls back to when the optional native libxmljs2 binding is unusable (no
# prebuilt binary for this ABI, or one built against a different Node version).
#
# fonts-liberation is here for the LAYOUT tests, and is the one thing in this list
# that is about rendering rather than about a tool. This image installed no
# fonts-* package at all, so the app's font stacks — bootstrap's
# `"Helvetica Neue", Helvetica, Arial, sans-serif` and common.css's
# `arial, sans-serif` — had no Arial-metric font to land on and fell through to
# whatever fontconfig happened to pull in transitively, which is wider. A host run
# resolves Arial to Liberation Sans and lays the pages out several pixels
# narrower, so the two environments disagree about geometry and only the
# containerized one trips panesContainTheirContent()'s no-horizontal-scroll
# assertion. Liberation is the metric-compatible substitute for Arial, which is
# what Chrome's own .deb depends on for the same reason.
RUN apt-get -y install curl \
        jq \
        openssl \
        fonts-liberation \
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
COPY tests/oauth2_* tests/oidc_* tests/token_introspection.js tests/jwt_tools.js tests/encoding_tools.js tests/digital_signature.js tests/saml_sso.js tests/saml_logout.js tests/saml_encrypted_sso.js tests/saml_tools.js tests/saml_operation_history.js tests/wstrust_operation_history.js tests/wsfed_sso.js tests/wstrust.js tests/xmlsec_interop.js tests/wstrust_schema_validate.js tests/navigation.js tests/sd_jwt_vc_issuance.js tests/sd_jwt_vc_waltid.js tests/sd_jwt_vc_presentation.js tests/sd_jwt_vc_presentation_waltid.js tests/jose_jwe_encryption.js tests/module_paths.js tests/browser_flags.js tests/api_ssrf_guard.js tests/api_connect_timeout.js tests/edge_landing_contract.js tests/jwk_pem_encoding.js tests/url_safety_schemes.js tests/xml_parse_inert.js tests/keypair_storage_optout.js tests/wait_for.js tests/page_load.js tests/page_load_retry.js tests/jwt_vc_json_common.js tests/jwt_vc_json_issuance.js tests/jwt_vc_json_presentation.js tests/jwt_vc_json_issuance_waltid.js tests/jwt_vc_json_presentation_waltid.js tests/metadata_schema_validation.js tests/bbs_crypto.js tests/bbs2023_cryptosuite.js tests/ldp_vc_issuance.js tests/ldp_vc_refresh.js tests/ldp_vc_presentation.js tests/oid4vci_request_encryption.js tests/did_document.js tests/vc_did.js tests/sts_metadata.js tests/did_tools.js tests/dpop_vectors.js tests/sts_dpop.js tests/dpop_workflow.js ./
# The per-run username minter, required by tests across four protocols (OAuth2,
# RFC 9700, Kerberos, LDAP) and by both mock-KDC page jobs. A SHARED MODULE
# rather than a test, so nothing schedules it and the run-report cross-check in
# jwk_pem_encoding.js cannot notice it missing — a job that requires it and does
# not find it dies with MODULE_NOT_FOUND in a tenth of a second, naming this
# file rather than a build. Its name does not collide with anything under
# client/src or sts/, which is the other thing this directory being flat
# demands.
COPY tests/random_username.js ./

# What the static deployments leave out. The test reads the list itself
# (client/static_site.js), the landing page it greys a card on, the stylesheet
# that greys it, and client/Dockerfile — which must still build the excluded
# pages, because the exclusion is static-only and the container is where the
# Kerberos workflow runs. The Dockerfile comes in RENAMED: this directory is
# flat and already has one of its own.
#
# client/public itself is not copied, so the two directory-wide checks (that
# every excluded file exists, and that no surviving page links to a dropped
# one) say in the log that they skipped. client/build.js runs both over dist/
# on every deploy, and a checkout run does them here.
COPY tests/static_site_exclusions.js ./
COPY client/static_site.js ./
COPY client/public/index.html ./
COPY client/public/css/landing.css ./
COPY client/Dockerfile ./client_Dockerfile

# The XML Signature/Encryption interop test drives the frontend crypto module
# directly (no browser); copy it next to the test so it can require('./xmldsig.js')
# and resolve its deps (node-forge, etc.) from this image's node_modules. The
# WS-Trust schema test likewise builds messages with the real generator
# (wstrust_msg.js) and validates them against the derived XSD in ./schemas.
COPY client/src/xmldsig.js client/src/wstrust_msg.js client/src/jose_jwe.js client/src/edge_landing.js ./
# The JWK -> SPKI PEM encoder, tested the same way (tests/jwk_pem_encoding.js
# requires it directly). Note that in this image there is no client/src tree, so
# that test's scan for requires which would pull `elliptic` back into a bundle
# reports itself skipped — the scan runs in a checkout, where the sources are present.
#
# The TEST is called jwk_pem_encoding.js precisely because of this COPY. It used
# to be tests/jwk_pem.js, which lands flat at the same path this line writes —
# and this line runs second, so the module silently REPLACED the test. `node
# jwk_pem.js` then loaded a module, printed nothing and exited 0, and run-report
# recorded the job as passed. The elliptic scan had not run in a containerized
# build since. Same trap as metadata_schema.js, same remedy: give the test a name
# no module will land on. cose.js requires ./jwk_pem, so the MODULE keeps its name.
COPY client/src/jwk_pem.js ./
# The scheme allowlist, tested directly by tests/url_safety_schemes.js.
COPY client/src/url_safety.js ./
# The metadata schema checker, loaded directly by
# tests/metadata_schema_validation.js. That test is named _validation for a
# reason: this COPY lands the module FLAT beside the test scripts, so a test
# named metadata_schema.js would be overwritten by it (or overwrite it) depending
# on which COPY ran last, and the failure would be silent.
COPY client/src/metadata_schema.js ./
# The BBS implementation, loaded directly by tests/bbs_crypto.js and checked
# there against @digitalbazaar/bbs-signatures — and, for the SHAKE-256
# ciphersuite, against the draft's own published test vectors, which are
# vendored as tests/bbs_vectors.json because a test must not need the network
# to know what the right answer is. tests/digital_signature.js drives the same
# vectors through the page, so BOTH tests fail at load without this file.
COPY client/src/bbs.js ./
COPY tests/bbs_vectors.json ./
# The bbs-2023 cryptosuite, BOTH implementations, for tests/bbs2023_cryptosuite.js
# — the wallet's and the STS's. They share a basename and this image copies flat,
# so the STS's is renamed on the way in; the test resolves either layout.
# client/src/bbs2023.js does require("./contexts/..."), so the vendored JSON-LD
# contexts come too: canonicalization must never depend on fetching one.
#
# The STS's copy comes out of the sts/ SUBMODULE
# (https://github.com/rcbj/mock-sts.git) — the one place outside the compose files
# where this repository reaches into it. An uninitialised submodule fails this
# build with "COPY sts/bbs2023.js: not found", which says nothing about the cause;
# the launchers run requireMockStsCheckout() (common/common.sh) before building so
# it is explained before it happens.
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
# DPoP (RFC 9449), loaded directly by tests/dpop_vectors.js so the thumbprint, htu, ath and
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
# The Kerberos v5 codec, loaded directly by tests/krb5_crypto_vectors.js so the
# RFC 3961/3962/8009 vectors can be checked with no browser and no KDC.
#
# These modules are named krb5_* in common/krb5/ rather than crypto.js /
# primitives.js BECAUSE of this flat copy — a crypto.js landing beside the test
# scripts is the kind of shadowing that fails somewhere else entirely. For the
# same reason the TEST is krb5_crypto_vectors.js and not krb5_crypto.js: two
# files of one name copied here means whichever COPY ran last wins, and the test
# would end up loading itself.
COPY common/krb5/krb5_primitives.js common/krb5/krb5_crypto.js ./
COPY common/krb5/krb5_asn1.js common/krb5/krb5_messages.js ./
COPY common/krb5/krb5_describe.js common/krb5/krb5_keytab.js ./
COPY common/krb5/krb5_gss.js common/krb5/krb5_client.js ./
COPY common/krb5/krb5_ndr.js common/krb5/krb5_pac.js ./
# krb5_ranges.js joined the set when the AS exchange page grew its hex tab: it
# maps each byte to the ASN.1 element that owns it. Required by
# tests/krb5_ranges_offsets.js AND by client/src/kerberos_hex.js, so it is
# bundle source as well as test input.
# The SPNEGO codec, loaded flat beside the tests by krb5_spnego_codec.js and
# krb5_spnego_http.js — and, crucially, by krb5_codec_sync.js, which compares
# this copy byte for byte against the vendored one under sts/. Miss it here and
# that test reports the vendored codec as INCOMPLETE, which reads as a broken
# submodule rather than a missing COPY.
COPY common/krb5/krb5_spnego.js ./
COPY common/krb5/krb5_ranges.js ./
# The field-name table krb5_ranges.js requires. Same two readers: the test
# below and the browser bundle. Without this COPY the ranges module fails to
# load in the image while working perfectly on a host run, which is the trap
# jwk_pem_encoding.js checks for.
COPY common/krb5/krb5_field_names.js ./
COPY tests/krb5_crypto_vectors.js tests/krb5_codec.js tests/krb5_describe_output.js tests/kerberos_decoder_page.js tests/krb5_codec_sync.js tests/kerberos_as_page.js ./
COPY tests/kerberos_tgs_ap_page.js ./
COPY tests/krb5_as_exchange.js tests/krb5_tgs_ap.js tests/krb5_pac_layout.js ./
COPY tests/kerberos_delegation_page.js ./
# The two Windows-interop jobs. krb5_windows_vectors.js needs its CAPTURE as
# well as its script — it asserts a recorded exchange from a real Windows KDC
# and has nothing to do without it — and krb5_real_dc.js is scheduled by
# run-report.js even though it skips unless KRB5_DC_HOST names a live domain
# controller. A scheduled script that is not in the image fails with
# MODULE_NOT_FOUND in 0.0s while passing on every host run, which is the trap
# jwk_pem_encoding.js checks for; it caught exactly this pair.
COPY tests/krb5_windows_vectors.js tests/krb5_real_dc.js ./
# The dual-target delegation test. Its mock half runs in the image, so it is
# not optional here; the Windows half skips without a domain controller.
COPY tests/krb5_delegation_interop.js ./
# The hex view's range arithmetic. Its module is copied by the krb5 block
# above; this is the test that checks the offsets are absolute.
COPY tests/krb5_ranges_offsets.js ./
# The six pages' layout: does each one put the control it exists for on the
# first screen? It needs the site and nothing else — no KDC, no api — which is
# the point of it being its own job rather than an assertion inside the page
# tests that skip without a KDC.
COPY tests/kerberos_page_density.js ./
# SPNEGO: the codec's own byte-level test, the HTTP handshake end to end, and
# the page. The first two are node-only and never skip; the third needs the
# stack. jwk_pem_encoding.js fails the build's own sanity check when a script
# run-report.js schedules is not copied here — which is how this line got
# written, rather than by remembering.
COPY tests/krb5_spnego_codec.js tests/krb5_spnego_http.js ./
COPY tests/kerberos_spnego_page.js ./
# The field names on those ranges. It also reads the PAGES and their bundles as
# text, which arrive through the client/public and client/src COPY lines.
COPY tests/krb5_field_naming.js ./
# The ticket history store. It loads client/src/kerberos_panes.js, which the
# krb5 block above already copies flat beside the codec it requires.
COPY tests/krb5_ticket_history.js ./
COPY client/src/kerberos_panes.js ./
# The Operations History pane. It loads client/src/kerberos_history.js, which
# requires client/src/op_history.js — the store the SAML, WS-Trust and
# WS-Federation logs share — so both come in flat.
COPY tests/krb5_operation_history.js ./
COPY client/src/kerberos_history.js client/src/op_history.js ./
#
# THE WIRING HALF OF BOTH PANE TESTS reads the five pages, their bundles and the
# two partials as TEXT — a page that includes a pane and never mount()s it
# renders an empty div, which no browser test can tell apart from a workflow
# that has done nothing, and no runtime check can see at all. Those tests
# resolve those files as ../client/src and ../client/public relative to
# themselves, so the copies below land in that repository-shaped layout rather
# than flat: WORKDIR is /usr/src/app, so ../client is /usr/src/client. Without
# them both tests fail in the image with "missing from client/src" while
# passing on every host run — the same shape as the krb5_as_exchange.js
# omission the collision check in tests/jwk_pem_encoding.js was written for.
#
# Nothing here is REQUIREd except kerberos_history.js (loadHistory() prefers
# this copy over the flat one), which is why op_history.js and
# kerberos_panes.js are beside it: a relative require resolves against the file,
# not against the test.
COPY client/src/kerberos.js client/src/kerberos_tgs.js client/src/kerberos_ap.js /usr/src/client/src/
COPY client/src/kerberos_delegation.js client/src/kerberos_decoder.js client/src/kerberos_tickets.js /usr/src/client/src/
COPY client/src/kerberos_history.js client/src/kerberos_panes.js client/src/op_history.js /usr/src/client/src/
# kerberos_hex.js is read as TEXT by tests/krb5_field_names.js, which checks the
# two things about the renderer no browser test can see: that the readable
# gutter is per-byte cells carrying a range (so hovering a byte lights its
# character), and that the strip leads with the RFC's field name.
COPY client/src/kerberos_hex.js /usr/src/client/src/
COPY client/public/kerberos.html client/public/kerberos_tgs.html client/public/kerberos_ap.html /usr/src/client/public/
COPY client/public/kerberos_delegation.html client/public/kerberos_decoder.html /usr/src/client/public/
COPY client/public/partials/krb_history.html client/public/partials/krb_tickets.html /usr/src/client/public/partials/
COPY client/public/css/kerberos.css /usr/src/client/public/css/
# The SIXTH page of the workflow, and the one nothing above names, because it is
# the one whose file name does not begin with `kerberos`. Both pane tests list
# spnego.js/spnego.html among the pages they read as TEXT, so without these two
# lines they fail in the image with "spnego.js is missing from client/src" —
# and krb5_field_naming.js, which discovers the pages by the stylesheet they
# load rather than by a list, does not fail at all: it finds five instead of six
# and every assertion below simply has one less page to make.
COPY client/src/spnego.js /usr/src/client/src/
COPY client/public/spnego.html /usr/src/client/public/
COPY tests/captures ./captures
# The mock KDC and the ticket-protected service, out of the sts/ SUBMODULE, so that
# krb5_as_exchange.js and krb5_tgs_ap.js can start them in-process and drive the real
# exchanges with no docker and no running service.
#
# They come in under sts/ rather than flat because krb5_kdc.js requires ./app and
# ./helpers — the submodule's own modules — and those resolve relative to where the
# file sits. Flattening it would break those requires in a way that reads as a missing
# dependency rather than a misplaced file.
#
# **This COPY can only exist once the sts/ gitlink points at a commit containing these
# files.** Added before the bump it fails the build with "COPY sts/krb5_kdc.js: not
# found", which says nothing about submodules; the launchers call
# requireMockStsCheckout() (common/common.sh) for the same reason.
# The set below is the TRANSITIVE closure of what krb5_kdc.js and krb5_service.js
# require, computed rather than guessed: they pull in app.js (the shared express app,
# because requiring a module registers its routes) and helpers.js, and helpers.js pulls
# in bbs2023.js. Recompute it by walking `require('./...')` from those two files if
# either grows a new dependency — and note that the whole submodule is not copied
# instead because there is no .dockerignore here, so `COPY sts/` would drag its
# node_modules into the image.
#
# If this set is ever short, the failure is "Cannot find module './bbs2023.js'" from
# inside the submodule, which names the file but not the reason; tests/krb5_as_exchange.js
# catches that and says which COPY is missing.
COPY sts/krb5_kdc.js sts/krb5_service.js sts/krb5_principals.js ./sts/
COPY sts/app.js sts/helpers.js sts/bbs2023.js ./sts/
# admin_stats.js is the recomputation that paragraph asks for, and the one that
# proves it is not optional: the mock's admin console grew a counters module,
# app.js/krb5_kdc.js/krb5_service.js all require it, and this image did not
# carry it — so all four in-process mock-KDC jobs (krb5_as_exchange,
# krb5_tgs_ap, krb5_spnego_http, krb5_delegation_interop) died at load with
# "Cannot find module './admin_stats'" while every host run stayed green.
COPY sts/admin_stats.js ./sts/
# audit.js is the THIRD recomputation, and it is admin_stats.js's own new
# require — the counters module grew an audit log beside it, so the closure
# above moved without any of these COPY lines changing. Missing, the four
# in-process mock-KDC jobs die at load with "Cannot find module './audit'"
# and a require stack naming sts/admin_stats.js, which is a file this image
# HAS: the line to add is never the one the message names. It requires only
# ./helpers and ./config, both already here, so it closes the set again.
COPY sts/audit.js ./sts/
# config.js is the SECOND such recomputation and it sits UNDER helpers.js rather
# than beside it: the mock's settings moved out of forty-odd `process.env.X ||
# default` expressions into one table, and helpers.js, krb5_kdc.js,
# krb5_service.js and krb5_principals.js all read it now. Missing, the failure
# is "Cannot find module './config'" from inside the submodule at require time
# — before any test has run, and naming a file rather than this line.
#
# It requires only bunyan and process.env.CONFIG_FILE, so it adds nothing to the
# closure. Note what CONFIG_FILE is in this image: the TESTS' config file, which
# carries none of the mock's settings — so every value falls through to the
# built-in default, which is exactly what these jobs had before the table
# existed, and the KRB5_* variables they set still win over it.
COPY sts/config.js ./sts/
# THE FOURTH recomputation, and it arrived the way all of them do: not by any
# line here changing, but by the sts/ gitlink moving. Bumping the submodule to
# the mock-sts commit that carries RFC 9700 support gave app.js a require on
# ./oauth2_bcp, and gave admin_stats.js, krb5_kdc.js and krb5_service.js one on
# ./applications — four files this image ALREADY copies, now reaching for four
# it did not. oauth2_bcp.js pulls in ./client_auth and ./mtls behind it, which
# is why this line carries four names and not two.
#
# The failure is the usual one and reads the usual way: "Cannot find module
# './applications'" at require time, from inside a file this image HAS, before
# a single test has run. The COPY to add is never the one the message names.
#
# The check that catches it is a closure walk, not a list: seed it with every
# sts/*.js copied here, follow each `require("./x")`, and require the result to
# be a subset of what is copied. Run it after every submodule bump — the set
# moves on the mock's schedule, not on this file's.
COPY sts/applications.js sts/client_auth.js sts/mtls.js sts/oauth2_bcp.js ./sts/
COPY sts/krb5_primitives.js sts/krb5_asn1.js sts/krb5_crypto.js sts/krb5_messages.js sts/krb5_gss.js ./sts/
# krb5_ndr.js and krb5_pac.js joined that vendored set in phase 4, when the KDC started
# minting a PAC. **This line is the one the paragraph above is about**: it cannot build
# until the sts/ gitlink points at a mock-sts commit that has both files.
COPY sts/krb5_ndr.js sts/krb5_pac.js ./sts/
# SPNEGO: the mock's protected page (spnego.js) and the RFC 4178 codec it and
# the browser share (krb5_spnego.js, vendored). Both are loaded by
# tests/krb5_spnego_http.js, which requires spnego.js to REGISTER its routes on
# the same express app it then listens on — so app.js above is not optional
# here, and loading them from two different directories would register the
# routes on an app nobody is serving.
#
# **These two COPY lines can only exist once the sts/ gitlink points at a
# commit containing both files.** Added before the bump the image build fails
# with "COPY sts/spnego.js: not found", which says nothing about submodules.
COPY sts/spnego.js sts/krb5_spnego.js ./sts/
# And the submodule's own env/, which is NOT optional: helpers.js does
# require(process.env.CONFIG_FILE), and a RELATIVE CONFIG_FILE ('./env/test.js')
# resolves against the requiring file's own directory — so it means sts/env/test.js
# here, not the tests' copy. Without this the KDC fails to load with
# "Cannot find module './env/test.js'", which names the config rather than the
# missing directory.
COPY sts/env ./sts/env
# ...and sts/contexts, which a Kerberos test has no business needing and needs
# anyway. The submodule has ONE shared helpers.js for eight protocol families, and
# it requires bbs2023.js at load time; bbs2023.js reads its vendored JSON-LD
# contexts at load time too. So loading the KDC in-process drags the BBS stack in
# behind it. 28K of JSON is a cheaper price than restructuring somebody else's
# service, and the coupling is pre-existing rather than something Kerberos
# introduced.
#
# The better fix lives in mock-sts, not here: helpers.js could require bbs2023
# lazily (its only use is already lazy — `if (!bbsKeys) ... generateKeyPair()`), or
# bbs2023.js could read its contexts on first use. Recorded here rather than done,
# because it is a change to a separate repository for a test-plumbing reason.
COPY sts/contexts ./sts/contexts
# The Kerberos relay's modules, loaded directly by tests/api_krb5_relay.js: it
# drives them rather than going over HTTP, so every refusal can be checked with no
# running service. Copied FLAT, like api/ssrf_guard.js below, and the test resolves
# either layout through module_paths.js — the same arrangement every other borrowed
# module here uses. (api/ssrf_guard.js is not repeated: it is already copied
# further down, and copying it twice is how the two lines drift apart.)
COPY api/krb5_relay.js api/krb5_frame.js ./
COPY tests/api_krb5_relay.js ./
# The two LDAP tests. Unlike the Kerberos relay above, NOTHING out of api/ or
# sts/ is copied for them: both drive the running services over HTTP — the api's
# POST /ldap/* endpoints and the mock's GET /ldap views — rather than loading a
# module in-process. That is deliberate, and it is what keeps the LDAP jobs out
# of the class of failure the note above records: a test that loads a module out
# of the sts/ submodule acquires that submodule's own CONFIG_FILE resolution and
# its dependency closure, both of which have broken this image before.
#
# These two lines are not optional and their absence is silent on every host
# run: run-report.js schedules both scripts, and without the COPY each fails in
# the image with MODULE_NOT_FOUND in a tenth of a second while passing
# everywhere else. testsImageHasNoCollidingFilenames() in
# tests/jwk_pem_encoding.js is what catches that, and it caught exactly this
# when the two tests were first written.
COPY tests/api_ldap.js tests/ldap_page.js ./
# The PKI workflow's four jobs, and everything they load.
#
# The three node-only ones drive the modules directly — the certificate
# authoring (client/src/x509.js), the key material and keystore formats
# (client/src/key_material.js) and the TLS probe (api/tls_probe.js) — so those
# modules are copied FLAT beside the tests, like every other borrowed module
# here, and the tests resolve either layout through module_paths.js.
#
# x509.js requires ./key_material, which requires ./jose_jwe (copied further
# up), so the closure is those three plus what jose_jwe already needed. Both
# need `pkijs` and `asn1js`, which is why tests/package.json declares them: a
# borrowed module's own requires resolve from where the module LIVES, and in
# this image that is beside the tests.
#
# openssl is already installed at the top of this file for the WS-Trust schema
# work; pki_x509.js and pki_key_formats.js assert by asking it what it reads,
# and say so rather than skipping if it is absent.
COPY client/src/x509.js client/src/key_material.js client/src/pki_store.js ./
COPY api/tls_probe.js ./
COPY tests/pki_x509.js tests/pki_key_formats.js tests/api_tls_probe.js ./
COPY tests/pki_page.js tests/pki_mutual_tls.js ./
# The WebAuthn decoder, loaded directly by tests/webauthn_decode.js: the CBOR
# reader, the COSE_Key decoder (which requires ./jwk_pem, copied above) and the
# artifact parser/verifier. The vectors beside them are real ceremonies produced
# by this image's own Chrome 121 via the WebDriver virtual authenticator, kept as
# data so the test needs no browser and cannot flake.
COPY client/src/cbor.js client/src/cose.js client/src/webauthn.js ./
# The STS's WebAuthn verifier, for tests/webauthn_cross_impl.js. Renamed on the
# way in because its basename collides with the client's module copied on the
# line above — the same arrangement sts/bbs2023.js is in, and for the same
# reason. It comes out of the sts/ SUBMODULE, so an uninitialised checkout fails
# this build with "COPY sts/webauthn.js: not found", which says nothing about the
# cause; requireMockStsCheckout() in common/common.sh explains it first.
# NOT copied flat, unlike sts/bbs2023.js above: this module has a relative
# require of its own, so it goes in a directory of its own and keeps its name.
# (It falls back to a silent logger when ./helpers is absent, which it is here —
# staging the service's helpers.js instead would drag in its CONFIG_FILE, read
# relative to ITS directory, and the service's dependencies with it.)
COPY sts/webauthn.js ./sts/webauthn.js
COPY tests/webauthn_decode.js tests/webauthn_vectors.json tests/webauthn_analyzer_page.js tests/webauthn_lab_page.js tests/webauthn_cross_impl.js tests/webauthn_oidc_mfa.js tests/webauthn_extension.js ./
# The browser extension's CI build, side-loaded by tests/webauthn_extension.js.
# It is GENERATED, not committed: build.js stamps the version in and bakes the
# origin the browser will see the mock STS on, which differs between the
# containerized stack and a host run. The launchers call buildBrowserExtension()
# (common/common.sh) before compose builds, exactly as they render the walt.id
# configuration — and for the same reason. If this COPY fails with "not found",
# that call did not happen.
COPY extension/dist/ci ./extension-ci
# The shipped build too, and only so that tests/webauthn_extension.js can prove
# the CI build differs from it in exactly one file. Without it that section
# cannot run at all, which would leave the one assertion that stops a test-only
# bypass creeping into the arm path checking nothing.
COPY extension/dist/chrome ./extension-chrome
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
# The suite's own headless-by-default check. It starts no browser: it READS this
# directory, so it needs nothing here except to BE here — and every test script
# copied above has landed flat beside it. Without this COPY the job run-report
# schedules for it fails in the image with MODULE_NOT_FOUND in 0.0s while
# passing on every host run, which is the failure jwk_pem_encoding.js watches
# for and is how it was caught.
# The mock STS's management API at /admin-api. It needs nothing of the mock's
# own in this image — it drives the running service over HTTP, exactly as
# tests/sts_metadata.js does — but it is COPYd on a line of its own so that the
# reason is somewhere: its basename is also a MODULE name in the mock
# (sts/admin_api.js), and the sts/ files above land in ./sts/ rather than flat
# precisely so that a pair like that cannot overwrite each other. Adding it to
# the flat list without noticing would be the collision testsImageHasNoColliding
# Filenames() exists to catch.
# RFC 9700 (OAuth 2.0 Security BCP). Two scripts, and they need each other's
# company here for opposite reasons. rfc9700_flows.js is Selenium and is gated
# on RFC9700_STS_URL, so it does nothing without the second, compliant STS
# instance; rfc9700_client.js needs no browser and no service at all and runs
# on every job list, which is exactly why its absence from this image would
# have shown up as MODULE_NOT_FOUND in 0.0s rather than as a skip.
COPY tests/rfc9700_flows.js tests/rfc9700_client.js ./
COPY tests/admin_api.js ./
# The HTTP tab on the OAuth2/OIDC token exchange and Token Endpoint Results
# panes. It is NOT covered by the `tests/oauth2_*` glob above — the name starts
# with the thing being shown rather than with the workflow showing it — and a
# script run-report.js schedules but this image never copies fails here with
# MODULE_NOT_FOUND in 0.0s while passing on every host run. That is what
# testsImageHasNoCollidingFilenames() in jwk_pem_encoding.js caught, and this
# line is the fix it asked for.
COPY tests/token_http_exchange.js ./
COPY tests/browser_tests_headless.js ./
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
