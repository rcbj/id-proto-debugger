#FROM node:lts
#
# THIS IMAGE IS BUILT IN THREE STAGES, AND THE SPLIT IS A HARD LIMIT RATHER
# THAN A PREFERENCE. Docker's layer store refuses a chain deeper than 125
# layers — `maxDepth` in moby's layer package — and every RUN, COPY and ADD
# adds one. This file is almost entirely COPY: one line per test script, per
# borrowed module and per vendored directory, each with the comment saying why
# it is there, and the count grows with every protocol this suite learns. On
# 2026-08-25 it reached 126 and the build died at `RUN ls` with
#
#   Step 132/136 : RUN ls
#   ...
#   max depth exceeded
#
# — a message that names no instruction, no file and no limit, printed AFTER
# the step's own output had scrolled past, so it reads as the `ls` failing.
#
# The fix keeps every COPY and every comment exactly where it was and moves
# them into two staging stages that are never shipped. Each stage starts its
# own chain from the base image, so each has the full 125 to itself, and the
# final image takes both in with two `COPY --from` lines. Adding a COPY costs
# a layer in ONE staging stage now, not in the image.
#
# THREE RULES FOR ANYTHING ADDED BELOW:
#
#  * A new COPY goes in `files1` or `files2` — never in the final stage, which
#    must stay at its dozen-odd layers. Put it where its neighbours are; the
#    split point is arbitrary (it falls between the client-side Kerberos files
#    and the sts/ submodule block) and carries no meaning.
#  * ORDER STILL DECIDES COLLISIONS. This directory is flat, several COPYs
#    deliberately land on paths an earlier one wrote, and the LAST one wins —
#    which is why the comments throughout warn about a module and a test
#    sharing a basename. That is preserved because `files1` is copied into the
#    image before `files2`, so a later line still wins. A COPY moved BACKWARDS
#    across the stage boundary silently reverses that.
#  * Everything lands under /usr/src — /usr/src/app (the WORKDIR),
#    /usr/src/client and /usr/src/common. The two `COPY --from` lines carry
#    that one directory. A COPY writing outside it would be staged and never
#    reach the image, with no error anywhere.
#
# Nothing about adding one more COPY looks different from the last hundred, so
# the headroom is CHECKED rather than remembered:
# everyDockerfileStaysUnderTheLayerLimit() in tests/jwk_pem_encoding.js counts
# every stage of every Dockerfile in the tree and fails at a budget of 100,
# naming the file and the stage. When it does, add a `files3` beside these two
# rather than merging COPY lines together: the comments here are attached to
# the lines they explain.

# ---------------------------------------------------------------------------
# Staging stage 1 of 2. Not shipped: the final stage copies /usr/src out of it.
# ---------------------------------------------------------------------------
FROM ubuntu:latest AS files1
# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
# where available (npm@5+)
COPY tests/package*.json ./
COPY tests/run-tests-in-container.sh .
COPY common/common.sh .

# Bundle app source
COPY tests/oauth2_* tests/oidc_* tests/token_introspection.js tests/jwt_tools.js tests/encoding_tools.js tests/digital_signature.js tests/encryption_tools.js tests/crypto_engines.js tests/saml_sso.js tests/saml_logout.js tests/saml11_sso.js tests/saml11_options.js tests/sts_saml11.js tests/saml_encrypted_sso.js tests/saml_tools.js tests/saml_operation_history.js tests/wstrust_operation_history.js tests/wsfed_sso.js tests/federation_sso.js tests/federation_chain_sso.js tests/wstrust.js tests/wstrust_delegation_chain.js tests/xmlsec_interop.js tests/wstrust_schema_validate.js tests/navigation.js tests/sd_jwt_vc_issuance.js tests/sd_jwt_vc_waltid.js tests/sd_jwt_vc_presentation.js tests/sd_jwt_vc_presentation_waltid.js tests/jose_jwe_encryption.js tests/module_paths.js tests/browser_flags.js tests/api_ssrf_guard.js tests/api_connect_timeout.js tests/edge_landing_contract.js tests/jwk_pem_encoding.js tests/url_safety_schemes.js tests/xml_parse_inert.js tests/keypair_storage_optout.js tests/wait_for.js tests/page_load.js tests/page_load_retry.js tests/jwt_vc_json_common.js tests/jwt_vc_json_issuance.js tests/jwt_vc_json_presentation.js tests/jwt_vc_json_issuance_waltid.js tests/jwt_vc_json_presentation_waltid.js tests/metadata_schema_validation.js tests/bbs_crypto.js tests/bbs2023_cryptosuite.js tests/ldp_vc_issuance.js tests/ldp_vc_refresh.js tests/ldp_vc_presentation.js tests/oid4vci_request_encryption.js tests/did_document.js tests/vc_did.js tests/sts_metadata.js tests/did_tools.js tests/dpop_vectors.js tests/sts_dpop.js tests/dpop_workflow.js tests/jws_engine.js ./
# The per-run username minter, required by tests across four protocols (OAuth2,
# RFC 9700, Kerberos, LDAP) and by both mock-KDC page jobs. A SHARED MODULE
# rather than a test, so nothing schedules it and the run-report cross-check in
# jwk_pem_encoding.js cannot notice it missing — a job that requires it and does
# not find it dies with MODULE_NOT_FOUND in a tenth of a second, naming this
# file rather than a build. Its name does not collide with anything under
# client/src or sts/, which is the other thing this directory being flat
# demands.
COPY tests/random_username.js ./

# THE APPLICATIONS REGISTRY CLIENT, required by every job that presents an
# identifier to the mock STS — which since 2026-08-27 is most of them: the OAuth
# and OIDC jobs, the OID4VC family, WS-Trust, WS-Federation, both SAML profiles,
# SCIM, SPIFFE, LDAP and the two Kerberos page jobs. A SHARED MODULE rather than
# a test, exactly like random_username.js above, and with the same failure mode
# when this line is missing: a job that requires it dies with MODULE_NOT_FOUND
# in a tenth of a second, naming this file rather than a build, and nothing
# schedules it so no cross-check notices it gone. Its name collides with nothing
# under client/src or sts/, which is what this flat directory demands.
COPY tests/sts_applications.js ./

# THE FEDERATION GRID — one parameterised script that run-report schedules
# forty-nine times, once per combination of application protocol, federation
# protocol and authentication mechanism — and the management-API client it and
# the two federation jobs above share. `federation_admin.js` is REQUIRED by
# federation_matrix_sso.js, so without this line that job fails in the image
# with MODULE_NOT_FOUND in 0.0s while passing on every host run, forty-nine
# times over. tests/jwk_pem_encoding.js asserts the script itself reaches the
# image; the module beside it is caught by the same closure walk that catches a
# missing sts/ dependency.
COPY tests/federation_matrix_sso.js tests/federation_admin.js ./

# ONE APPLICATION, TWO FEDERATION PARTNERS, AND THE PERSON PICKS. The job that
# drives the mock's `/authn/select-idp` chooser: an application naming a SAML
# 2.0 relationship AND an OpenID Connect one, both to the same partner realm.
# It requires `federation_admin.js` above, so it is copied here beside the
# other job that does.
COPY tests/federation_choice_sso.js ./

# CLEARING A SESSION THAT IS NOT ON THE PAGE'S ORIGIN, required by all four
# federation jobs above. It exists because THIS stack is the one where the
# distinction is real: WebDriver's Delete All Cookies acts on the active
# document's origin, and here the client and the mock STS are two different
# HOSTS (`client` and `sts`) rather than two ports on `localhost`. Missing from
# the image, each of those jobs dies with MODULE_NOT_FOUND in a tenth of a
# second while passing on every host run.
COPY tests/session_reset.js ./

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

# What survives `sudo` on the way to compose. docker_compose() in common.sh
# (copied above) runs compose under sudo, which empties the environment, so a
# variable a compose file reads reaches compose only if COMPOSE_FORWARDED_VARS
# names it — and every failure of that is silent, which is why the check exists
# at all. It needs the compose files themselves, and it needs them by name
# rather than by glob: this directory is flat and a glob here would find
# whatever else ends in .yml. The two the launchers actually use come first;
# the remaining three are checked too, since the same rule governs them and a
# `${NAME}` added to any of them has the same silent failure.
#
# A missing file does NOT make the test skip — it fails, because a check that
# compares nothing is the exact shape of bug it is here to catch.
COPY tests/compose_env_forwarding.js ./
COPY docker-compose-run-tests.yml ./
COPY docker-compose-coverage.yml ./
COPY docker-compose.yml ./
COPY local-tests.yml ./
COPY keycloak-tests.yml ./

# The XML Signature/Encryption interop test drives the frontend crypto module
# directly (no browser); copy it next to the test so it can require('./xmldsig.js')
# and resolve its deps (node-forge, etc.) from this image's node_modules. The
# WS-Trust schema test likewise builds messages with the real generator
# (wstrust_msg.js) and validates them against the derived XSD in ./schemas.
COPY common/xmldsig.js ./
COPY client/src/wstrust_msg.js client/src/jose_jwe.js client/src/edge_landing.js ./
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
# The JWS engine, loaded directly by tests/jws_engine.js and checked there
# against node's own OpenSSL (in both directions, for every asymmetric
# algorithm) and against `jsonwebtoken`. The TEST is called jws_engine.js and
# not jws.js for the reason the paragraph above gives: this COPY lands the
# module FLAT beside the test scripts, so a test of that name would silently
# replace it — or be replaced by it — depending on which COPY ran last. The
# module keeps its own name because digital_signature.js requires ./jws.
#
# It requires ./crypto_bytes and ./pk_encryption, both of which are copied
# further down for tests/crypto_engines.js; this test fails at load if either
# COPY is removed.
COPY client/src/jws.js ./
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
# build with "COPY sts/common/vendored/bbs2023.js: not found", which says nothing
# about the cause; the launchers run requireMockStsCheckout() (common/common.sh)
# before building so it is explained before it happens.
#
# NOTE THE PATH. Every module in that repository sat in its root until mock-sts
# 0f986b3 ("Reorganizing source code."), which moved them into subdirectories —
# so every `COPY sts/…` line in this file names a folder now, and a bump across
# that commit fails the build on the first of them. This one is still copied
# FLAT and renamed, because it is loaded on its own and has no relative
# requires; the ones below cannot be, and say why.
COPY client/src/bbs2023.js ./
COPY sts/common/vendored/bbs2023.js ./sts_bbs2023.js
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
# The Encryption / Decryption page's cryptography, loaded directly by
# tests/crypto_engines.js so the RFCs' own vectors can be asserted with no
# browser. All three, because the closure matters: symmetric_crypto.js requires
# ./crypto_bytes and pk_encryption.js requires both — and an uncopied one is a
# MODULE_NOT_FOUND at require rather than a silently smaller run.
#
# Note the NAMES. tests/crypto_engines.js is called that, rather than
# encryption.js or crypto_bytes.js, precisely because these land FLAT beside
# the test scripts: a test sharing a name with a module here means whichever
# COPY ran last wins, silently. Same trap as jwk_pem.js above.
COPY client/src/crypto_bytes.js client/src/symmetric_crypto.js ./
COPY client/src/pk_encryption.js ./
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
# And the SIGN-IN, which is a different door from the protected page the job
# above drives: `/authn/spnego` turns a ticket into a SESSION, and this job then
# completes an OIDC Authorization Code flow on it. It requires
# tests/sts_applications.js — staged further up — because it registers its
# application with `appAuthnMechanism: spnego` before the flow starts.
COPY tests/kerberos_spnego_signin.js ./
# And the same two doors driven by MIT KERBEROS ITSELF — kinit, klist, kvno,
# kdestroy and curl --negotiate — which is the only job here that exercises the
# mock KDC with a client nobody in this project wrote. `krb5-user` in the apt
# list above is what makes it run rather than skip. It needs no browser and no
# api.
COPY tests/krb5_mit_client.js ./
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

# ---------------------------------------------------------------------------
# Staging stage 2 of 2. Same rules as stage 1; see the header. It starts a
# fresh layer chain, which is the whole point — but note that it therefore
# knows nothing of what stage 1 copied, and must not: nothing here reads a
# file, every line is a COPY from the build context.
# ---------------------------------------------------------------------------
FROM ubuntu:latest AS files2
WORKDIR /usr/src/app

# The mock KDC and the ticket-protected service, out of the sts/ SUBMODULE, so that
# krb5_as_exchange.js and krb5_tgs_ap.js can start them in-process and drive the real
# exchanges with no docker and no running service.
#
# They come in under sts/ rather than flat because krb5_kdc.js requires
# ../common/app and ../common/helpers — the submodule's own modules — and those
# resolve relative to where the file sits. Flattening it would break those
# requires in a way that reads as a missing dependency rather than a misplaced
# file.
#
# **AND THE DIRECTORY STRUCTURE IS MIRRORED, not flattened into ./sts/.** Until
# mock-sts 0f986b3 ("Reorganizing source code.") every module in that repository
# was in its root, so `COPY sts/krb5_kdc.js … ./sts/` put a file next to the
# `./app` it asked for. After it, krb5_kdc.js asks for `../common/app` — so a
# copy landing flat in ./sts/ would look for tests/common/app.js, a directory
# belonging to a different repository, and fail with "Cannot find module
# '../common/app'". Each COPY below therefore names the mock's folder on BOTH
# sides.
#
# **This COPY can only exist once the sts/ gitlink points at a commit containing these
# files.** Added before the bump it fails the build with "COPY
# sts/kerberos/krb5_kdc.js: not found", which says nothing about submodules; the
# launchers call requireMockStsCheckout() (common/common.sh) for the same reason.
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
COPY sts/kerberos/krb5_kdc.js sts/kerberos/krb5_service.js sts/kerberos/krb5_principals.js ./sts/kerberos/
COPY sts/common/app.js sts/common/helpers.js ./sts/common/
COPY sts/common/vendored/bbs2023.js ./sts/common/vendored/
# config_file.js is what the reorganisation itself made necessary, and it is
# required at LOAD by both helpers.js and config.js below. Fourteen modules in
# that service do `require(process.env.CONFIG_FILE)` for their log level, and a
# relative CONFIG_FILE ('./env/test.js') used to resolve against the package
# root because every module was IN the root; after the move it would resolve
# against common/, kerberos/ and so on. This module normalises it in one place.
# Without it the four in-process mock-KDC jobs die at load with "Cannot find
# module './config_file'" — from inside a file this image HAS, which is the
# shape every entry in this section has taken.
COPY sts/common/config_file.js ./sts/common/
# admin_stats.js is the recomputation that paragraph asks for, and the one that
# proves it is not optional: the mock's admin console grew a counters module,
# app.js/krb5_kdc.js/krb5_service.js all require it, and this image did not
# carry it — so all four in-process mock-KDC jobs (krb5_as_exchange,
# krb5_tgs_ap, krb5_spnego_http, krb5_delegation_interop) died at load with
# "Cannot find module './admin_stats'" while every host run stayed green.
COPY sts/common/admin_stats.js ./sts/common/
# audit.js is the THIRD recomputation, and it is admin_stats.js's own new
# require — the counters module grew an audit log beside it, so the closure
# above moved without any of these COPY lines changing. Missing, the four
# in-process mock-KDC jobs die at load with "Cannot find module './audit'"
# and a require stack naming sts/admin_stats.js, which is a file this image
# HAS: the line to add is never the one the message names. It requires only
# ./helpers and ./config, both already here, so it closes the set again.
COPY sts/common/audit.js ./sts/common/
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
COPY sts/common/config.js ./sts/common/
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
COPY sts/common/applications.js ./sts/common/
COPY sts/oauth-oidc/client_auth.js sts/oauth-oidc/mtls.js sts/oauth-oidc/oauth2_bcp.js ./sts/oauth-oidc/
# THE FIFTH recomputation, and it arrived on the same schedule as the fourth:
# the sts/ gitlink moved, and three modules this image already carries reached
# for three it did not. realms.js is the mock's multi-realm table and is now
# required by app.js, helpers.js, admin_stats.js, audit.js, client_auth.js and
# oauth2_bcp.js — six files here, all of them already copied; delegation.js is
# krb5_kdc.js's new require; and federation.js is admin_stats.js's, which is why
# a federation module is in a Kerberos-shaped section of this file at all.
#
# The failure is the one every entry above has: "Cannot find module
# './realms'" at require time, from inside a file this image HAS, before a
# single test has run. federation.js lands under ./sts/federation/ rather than
# flat because its own requires are `./../common/config`, `./../common/helpers`
# and `./../common/audit` — a copy landing beside them in ./sts/ would resolve
# those one directory too high and reach outside the image's sts/ tree.
#
# None of the three adds anything further: realms.js takes only bunyan,
# async_hooks and ./config, delegation.js takes ./helpers, ./realms, ./config
# and ./admin_stats, and federation.js takes crypto plus the three common/
# modules named above. The closure walk in tests/jwk_pem_encoding.js is what
# says so, and it is what caught this — run it after every submodule bump.
COPY sts/common/realms.js sts/common/delegation.js ./sts/common/
COPY sts/federation/federation.js ./sts/federation/
COPY sts/kerberos/krb5_primitives.js sts/kerberos/krb5_asn1.js sts/kerberos/krb5_crypto.js sts/kerberos/krb5_messages.js sts/kerberos/krb5_gss.js ./sts/kerberos/
# krb5_ndr.js and krb5_pac.js joined that vendored set in phase 4, when the KDC started
# minting a PAC. **This line is the one the paragraph above is about**: it cannot build
# until the sts/ gitlink points at a mock-sts commit that has both files.
COPY sts/kerberos/krb5_ndr.js sts/kerberos/krb5_pac.js ./sts/kerberos/
# SPNEGO: the mock's protected page (spnego.js) and the RFC 4178 codec it and
# the browser share (krb5_spnego.js, vendored). Both are loaded by
# tests/krb5_spnego_http.js, which requires spnego.js to REGISTER its routes on
# the same express app it then listens on — so app.js above is not optional
# here, and loading them from two different directories would register the
# routes on an app nobody is serving.
#
# **These two COPY lines can only exist once the sts/ gitlink points at a
# commit containing both files.** Added before the bump the image build fails
# with "COPY sts/kerberos/spnego.js: not found", which says nothing about
# submodules.
COPY sts/kerberos/spnego.js sts/kerberos/krb5_spnego.js ./sts/kerberos/
# ...and the acceptor's exchange half, which spnego.js requires as of mock-sts
# 1405318 ("Kerberos sign-in, the federation picture, and UserInfo claims.").
# It was one file until that commit, so this line has nothing to do with a test
# being added here and everything to do with the sts/ gitlink moving: without
# it the image builds and tests/krb5_spnego_http.js dies at load with "Cannot
# find module './spnego_exchange.js'", naming a file this image has never
# heard of. The closure walk in tests/jwk_pem_encoding.js is what catches it.
COPY sts/kerberos/spnego_exchange.js ./sts/kerberos/
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
COPY sts/common/vendored/contexts ./sts/common/vendored/contexts
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
# this build with "COPY sts/authn/webauthn.js: not found", which says nothing
# about the
# cause; requireMockStsCheckout() in common/common.sh explains it first.
# NOT copied flat, unlike sts/bbs2023.js above: this module has a relative
# require of its own, so it goes in a directory of its own and keeps its name.
# (It falls back to a silent logger when ./helpers is absent, which it is here —
# staging the service's helpers.js instead would drag in its CONFIG_FILE, read
# relative to ITS directory, and the service's dependencies with it.)
COPY sts/authn/webauthn.js ./sts/authn/webauthn.js
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
# (sts/mgmt-api/admin_api.js), and the sts/ files above land in ./sts/<dir>/
# rather than flat
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
# ...AND THE CLIENT SOURCE TREE, because rfc9700_client.js is the one test here
# whose subject IS that tree. Two thirds of its checks are lexical — no iframe
# anywhere under client/src or client/public, no postMessage with a '*' target
# origin, no token in a query string, /callback building its Location from
# configuration alone — so a file copied flat beside the test cannot answer any
# of them. It walks directories, and the directories have to be here.
#
# /usr/src/client, because the script computes them as ../client/{src,public}
# from /usr/src/app; the kerberos COPYs further up already land in that
# directory for the same reason. The FLAT copies above are unaffected and stay
# — other tests require those modules by their own name.
#
# What is deliberately NOT copied is client/public/js: those are the browserify
# bundles, they are gitignored, they are 90 MB, and a fresh checkout (CI) does
# not have them either — so leaving them out is what makes this image see the
# same tree a clone sees. The partials are copied because the walk recurses and
# they are markup this application wrote.
#
# Without this the job failed in 0.0s with
#   Error: Cannot find module '/usr/src/client/src/rfc9700.js'
# on a run where every host run had been green: the script was in the image and
# its subject was not.
COPY client/src /usr/src/client/src
COPY client/public/*.html /usr/src/client/public/
COPY client/public/partials /usr/src/client/public/partials
COPY client/server.js /usr/src/client/server.js
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
COPY tests/driver_quit_reachable.js ./
# The authored-markup check. It READS client/public, which this image does not
# carry, so in here it skips by name and does its work on a host run and in CI —
# the same arrangement as xml_parse_inert.js. It is copied anyway, and must be:
# run-report.js schedules it, and a scheduled script that never reaches the
# image dies with MODULE_NOT_FOUND in 0.0s, which reads as a broken test rather
# than as a missing line here.
COPY tests/page_markup_well_formed.js ./
COPY tests/run-report.js ./
# Shared test helpers (populateMetadata, ...). The test scripts require it as
# ../common/tests.js; WORKDIR is /usr/src/app, so it must land in /usr/src/common.
# ---------------------------------------------------------------------------
# SCIM 2.0.
#
# Three test scripts and the three modules they load directly. The modules land
# FLAT beside the test scripts, which is why each of the three tests is named
# scim_<something> and none of them is called scim_client.js or
# scim_proxy.js — two files of one name copied here means whichever COPY ran
# last wins, silently, and the test would end up loading itself. Same trap
# jwk_pem.js and metadata_schema.js above record.
#
# `api/scim_proxy.js` is the first module this image takes from api/ rather
# than from client/src or common/, and it can be taken because it has no axios
# and no network in it — it only DECIDES. That is what lets scim_engine.js
# assert every refusal the backend call path can produce with no api running.
#
# Omit any of these three COPYs and the test does not fail: module_paths.js
# looks for the checkout path first and finds nothing in the image, so the
# whole file throws at load with "could not locate" — which names the module
# rather than this line. Both scim_client.js and scim_scenarios.js are ALSO
# browser bundle source, so a rename on either side has to be made here too.
COPY client/src/scim_client.js client/src/scim_scenarios.js ./
COPY api/scim_proxy.js ./
COPY tests/scim_engine.js tests/scim_protocol.js tests/scim_page.js ./
# ---------------------------------------------------------------------------
# SPIFFE.
#
# Four test scripts and the four modules they load directly, FLAT beside the
# tests — which is why every one of these scripts is named `spiffe_<something>`
# or `api_spiffe.js` and none of them is called `spiffe_id.js`,
# `spiffe_bundle.js` or `spiffe_client.js`. Two files of one name copied here
# means whichever COPY ran last wins, silently, and the test would end up
# loading itself. Same trap the SCIM block above records.
#
# `api/spiffe_client.js` is the second module this image takes from `api/`, and
# it is taken for the opposite reason `scim_proxy.js` is: that one has no
# network in it, and this one is ALL network — but its address rules, its
# catalogue and its conversions are pure, and `spiffe_protocol.js` needs the
# whole thing anyway to call forty-nine methods with no api running.
#
# **`api/protos/` HAS TO COME WITH IT, AND IT IS A DIRECTORY.** That module
# reads the `.proto` files at REQUIRE TIME through
# `path.join(__dirname, 'protos')`, so without this line every SPIFFE test
# throws at load with a message about a service missing from the vendored
# protos — which names the protos and not this COPY. `__dirname` here is
# /usr/src/app, so the directory lands beside the flattened module and the
# join resolves exactly as it does in a checkout.
#
# `common/spiffe/` goes to /usr/src/common/spiffe as well as flat, because
# `api/spiffe_client.js` requires it as `../common/spiffe/spiffe_id.js` while
# the tests find it flat through module_paths.js. Both spellings have to
# resolve or one of the two callers fails at load.
COPY common/spiffe/spiffe_id.js common/spiffe/spiffe_bundle.js ./
COPY common/spiffe/ /usr/src/common/spiffe/
COPY api/spiffe_client.js ./
COPY api/protos/ ./protos/
COPY tests/spiffe_engine.js tests/spiffe_protocol.js ./
COPY tests/api_spiffe.js tests/spiffe_page.js ./
# ---------------------------------------------------------------------------
# The JWKS page. Named jwks_PAGE.js for the same reason as the three above:
# client/src/jwks.js is bundle source and could one day be copied here, and two
# files of one name means whichever COPY ran last wins.
#
# The page had no test at all until 2026-08-23. It was found by the coverage
# report rather than by a failure — the bundle is built and is in the
# Dockerfile's COVERAGE list, so every check that guards the BUILD passed; the
# file was simply absent from the report, because Istanbul reports on files
# that were loaded and nothing had ever loaded this one.
# ---------------------------------------------------------------------------
COPY tests/jwks_page.js ./
COPY common/tests.js /usr/src/common/tests.js
# The SAML SP key pair reader. The pair itself is generated per run inside the
# container (common.sh generateSpKeyPair) and passed through the environment —
# nothing is baked into the image.
COPY common/sp_keypair.js /usr/src/common/sp_keypair.js
# Centralized test config (waitTime, etc.); selected via CONFIG_FILE.
COPY tests/env ./env

# ---------------------------------------------------------------------------
# The image itself. Keep this stage SHORT — it is the only one whose layers
# count against the 125 the header describes.
# ---------------------------------------------------------------------------
FROM ubuntu:latest

# replace shell with bash so we can source files
RUN rm /bin/sh && ln -s /bin/bash /bin/sh

# apt-get update and apt-get install are ONE RUN on purpose, and splitting
# them back apart breaks this build on a schedule nothing in this repository
# controls. A `RUN apt-get update` of its own is a LAYER, and Docker reuses it
# for as long as every instruction above it is unchanged — so the package
# index baked into that layer goes on naming the versions that were current
# the day it was built, while archive.ubuntu.com and security.ubuntu.com drop
# each .deb from the pool the moment a newer one supersedes it. The install
# then asks for versions that no longer exist and every -updates/-security
# package in the list 404s at once:
#
#   E: Failed to fetch .../libssl3t64_3.5.5-1ubuntu3.3_amd64.deb
#      404  Not Found [IP: 91.189.92.22 80]
#
# repeated twenty times, ending in `Unable to fetch some archives, maybe run
# apt update`, and the failing step named in the build log is the INSTALL. It
# reads as a broken mirror, a DNS problem or a VPN, and is none of those: the
# 404s are all for -updates/-security versions and none for a package that
# never moved, which is the signature. Joined into one RUN the two cannot
# disagree — either the layer is cached and neither runs, or both run and the
# index is exactly as fresh as the pool it will fetch from.
#
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
#
# krb5-user supplies kinit, klist, kvno and kdestroy, which
# tests/krb5_mit_client.js drives against the mock KDC. It is the only thing in
# this suite that exercises that KDC with a client NOBODY HERE WROTE, and that
# is the whole point of it: the debugger's client and every other Kerberos test
# send PA-ENC-TIMESTAMP whether the KDC offered it or not, so when the mock
# stopped offering it nothing noticed for as long as the feature had existed —
# and no browser could have signed in with Kerberos at all. Without this
# package that job SKIPS with a reason rather than failing, which is right on a
# developer's machine and would be a silent hole here.
#
# curl above is the GSSAPI HTTP client for the SPNEGO half of the same file.
# Ubuntu's is built with GSS-API and SPNEGO; the test reads `curl -V` for both
# and skips naming them rather than reporting a refusal for a ticket that was
# never offered.
#
# DEBIAN_FRONTEND=noninteractive is here FOR krb5-user. That package configures
# itself through debconf and ASKS for a default realm; without this the build
# either stops on a prompt nobody can answer or hangs until the daemon gives
# up. It is set on the RUN rather than as an ENV so it does not follow the
# image into a running container, where a later interactive apt-get would
# silently take defaults. The realm it picks does not matter: that test writes
# its own krb5.conf and points KRB5_CONFIG at it.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get -y install curl \
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
        bsdextrautils \
        krb5-user
 

# Create app directory
WORKDIR /usr/src/app

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

# Chrome and chromedriver, pinned to 121.0.6167.85 and installed BEFORE the
# staged files rather than after them. Nothing in this step reads anything
# copied out of the staging stages, and putting it above them is what keeps
# ~200 MB of download out of every rebuild: a layer's cache key includes its
# parent, so while this sat below the COPYs, editing one test script
# re-downloaded the browser.
RUN wget -q -O chrome-linux64.zip https://edgedl.me.gvt1.com/edgedl/chrome/chrome-for-testing/121.0.6167.85/linux64/chrome-linux64.zip && \
    unzip chrome-linux64.zip && \
    rm chrome-linux64.zip && \
    mv chrome-linux64 /opt/chrome/ && \
    ln -s /opt/chrome/chrome /usr/local/bin/ && \
    wget -q -O chromedriver-linux64.zip https://edgedl.me.gvt1.com/edgedl/chrome/chrome-for-testing/121.0.6167.85/linux64/chromedriver-linux64.zip && \
    unzip -j chromedriver-linux64.zip chromedriver-linux64/chromedriver && \
    rm chromedriver-linux64.zip && \
    mv chromedriver /usr/local/bin/

# Everything the two staging stages assembled, in their original order so that
# a later COPY still overwrites an earlier one (see the header). /usr/src is
# the whole of it: /usr/src/app is the WORKDIR the tests run in,
# /usr/src/client and /usr/src/common are the repository-shaped layout several
# tests resolve as ../client and ../common.
COPY --from=files1 /usr/src /usr/src
COPY --from=files2 /usr/src /usr/src

# Fixed SP signing key/cert for the SAML signature-validation test + provisioning.
RUN ls
RUN . $NVM_DIR/nvm.sh && npm install chromedriver

# Install modules needed for the test scripts
RUN . $NVM_DIR/nvm.sh && npm install

CMD [ "./run-tests-in-container.sh"]
