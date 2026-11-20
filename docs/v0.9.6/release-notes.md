---
title: Release notes
---

# Release notes

What changed in each release, and what to do about it. The GitHub
release lists every pull request and every commit made without one; this
page describes the changes a user or an operator will notice. How a
release is numbered, built and published is
[Releases, versions and images](releases.md).

## 0.9.6

In development. Changes are described here as they land.

### The test stacks run iya-sts 1.1.0

The compose files, the image mirror and iya-sts's companion name the
1.1.0 release, which replaces 0.9.5's `1.1.0-candidate` pin. Links to
iya-sts's documentation name its `v1.1.0` pages.

## 0.9.5

0.9.5 replaces 0.9.4 with nothing to migrate. The debugger keeps its
state in the browser, and nothing it stored under 0.9.4 is read
differently, with one exception: a `bbs-2023` credential or presentation
in the old format no longer verifies
([`bbs-2023` is the W3C cryptosuite](#bbs-2023-is-the-w3c-cryptosuite)).
Pull the 0.9.5 images, or rebuild, and reload the pages.

**The test stacks need iya-sts 1.1.0.** The WS-Trust encryption jobs,
the `ldp_vc` bbs-2023 jobs, the did:web issuer job and the HAIP mdoc
cases use settings and modules 1.0.0 does not have. Until the release,
point `IYA_STS_IMAGE` and `IYA_STS_COMPANION_IMAGE` at the
`1.1.0-candidate` images ([Testing against the deployed
sites](live-site-testing.md)).

### A configuration file with an unknown key stops the service

The api's and the client's configuration files are held to a schema
generated from `models/` ([The abstract data model](data-model.md)). A key
the schema does not name stops the api at startup, and the client's build,
with a message naming the key. 0.9.4 ignored a misspelt key and ran with
the default, so a setting could be off with nothing to say so.

* **Before upgrading**, check each client configuration file you maintain
  (`cd client && CONFIG_FILE=./env/<file>.js node check_config.js`), and
  start the api once against its own and read its first error.
* A key that names a real setting under an older name has to be renamed.
  The schema lists every setting, with its type and default.

### The api checks each request's shape

Every api route validates its request against the model before the
handler runs. The check refuses only a wrong JSON type or a missing
required member, with a 400 that names the member. A forwarded protocol
message is never constrained, so a malformed token request still reaches
the token endpoint, as it should for a debugger.

* `GET /api-docs.json` serves the OpenAPI 3.1 document the model
  generates, and `GET /api-docs` its index. The `express-swagger-generator`
  page is gone.
* 68 answers changed on purpose. Each is recorded in
  `tests/fixtures/api_model/` with the answer 0.9.4 gave and the reason.

### "SSL Validate: No" turns certificate verification off

On the OAuth 2.0 / OIDC pages, choosing not to validate SSL sent the
string `"false"`, and five api routes (`/token`, `/revoke`,
`/tokenexchange`, `/deviceauthorization`, `/register`) still verified the
certificate. In 0.9.5 `false` and `"false"` both turn verification off on
every route that takes the setting, and anything else, absent included,
leaves it on. A token endpoint with a self-signed certificate that failed
under 0.9.4 with this option chosen now answers.

### The SAML response page verifies the Response signature too

**Validate Signature** is now **Validate Signatures**. It checks the
`<samlp:Response>` signature as well as the assertion's and reports each
on its own line. 0.9.4 checked only the assertion's, so a SAML 1.1
Browser/POST response from Shibboleth, which signs only the Response,
was verified by nothing. SAML 1.1 Browser/POST requires a signed
Response, and the page now says so when one is missing. The signature is
checked against the identity provider's published keys.

### WS-Trust signs with a BinarySecurityToken, and encryption follows the STS

* **Signing.** The WS-Trust page's default key reference is a
  `wsse:BinarySecurityToken` again, and `KeyInfo` carries only the
  `SecurityTokenReference` to it. The `both` key-reference option is
  retired.
* **Encryption.** An encrypted issued token comes back as
  `xenc:EncryptedData`, with its content key in the `EncryptedKey` in
  `wsse:Security`, and the response page decrypts it there. An encrypted
  request is encrypted to the relying party's WS-Trust decryption
  certificate, or to the realm's `KeyDescriptor use="encryption"`. The
  STS's `GET /sts/cert` is its signing certificate and is not used for
  encryption.
* iya-sts's `?encrypt=1` test switch is gone; what is encrypted is set on
  the relying party in iya-sts 1.1.0.

### `bbs-2023` is the W3C cryptosuite

An `ldp_vc` signed with `bbs-2023` follows *W3C Data Integrity BBS
Cryptosuites v1.0* in the wallet and in the Verifier: the base proof, the
derived proof and its selective disclosure, both CBOR forms and Multikey
keys. There is no legacy path. A credential or presentation in the
envelope 0.9.4 and iya-sts 1.0.0 used fails as a "pre-W3C non-standard
bbs-2023 envelope". Issue the credential again from iya-sts 1.1.0.

### The cryptography is pure JavaScript, and works on plain HTTP

Every cryptographic operation the pages perform now goes through one
module, `common/crypto/crypto_provider.js`, written in JavaScript. JOSE,
XML Signature and Encryption, COSE, the PKI page, Kerberos, GNAP, DPoP,
SD-JWT and the key formats all call it. Web Crypto exists only in a
secure context, so under 0.9.4 parts of several pages did nothing on a
page served over plain HTTP. In 0.9.5 they all work there, PKCS#12 and
password-protected PKCS#8 included.

* Web Crypto is an **opt-in** backend (`common/crypto/crypto_webcrypto.js`).
  It is off by default, and where it cannot do an algorithm (secp256k1,
  Ed448, post-quantum, SHA-3) the operation falls back to JavaScript and
  says which engine ran.
* `tests/no_direct_webcrypto_engine.js` fails on any browser module that
  calls Web Crypto outside that backend.

### New: the debugger as the OpenID4VP Verifier

The VC Presentation workflow plays either end. A role selector on
`vc-presentation-0.html` chooses the Wallet, as before, or the Verifier,
`vc-verifier.html`, which asks a wallet for claims and checks the answer,
one row per check ([The Verifier](vc-verifier.md)).

* The request is a DCQL query, delivered by reference or value, with every
  Client Identifier prefix except `openid_federation`, `direct_post` or
  `direct_post.jwt`, the HAIP 1.0 profile, `transaction_data`, and the
  Digital Credentials API (`dc_api`, `dc_api.jwt`, multi-signed requests).
* It checks the IETF Token Status List and the W3C Bitstring Status List,
  and signs a `wallet_nonce` live while the wallet waits.
* The page makes its certificate per run. The api only stores and serves
  the `request_uri`, the `response_uri` and the root certificate.

### New: the wallet speaks HAIP 1.0 and SIOPv2, and needs no CORS

* **Protocols.** HAIP 1.0 (with its refusals of by-value requests, other
  Client Identifier prefixes and plaintext answers) and SIOPv2
  self-issued ID Tokens, beside OpenID4VP 1.0.
* **A Verifier that sends no CORS headers.** With **Reach the Verifier
  through the debugger's api** ticked, `POST /oid4vp/call` makes the
  exchange on the wallet's behalf. The option appears only where an api
  answers; a static site never offers it.
* **OpenID4VP 1.0 details.** `transaction_data_hashes` in the KB-JWT, and
  `dc_api` / `dc_api.jwt` answers.
* **Independent peers.** The suite presents to the Polaris verifier (an
  OpenID-certified HAIP verifier, 1.2.0) and to rcbj/oid4vc-wallet.

### New: every credential format

The VC workflows issue, hold, present and verify:

* **ISO mdoc** (`mso_mdoc`);
* **Data Integrity** proofs on an `ldp_vc`: `eddsa-rdfc-2022`,
  `eddsa-jcs-2022`, `ecdsa-rdfc-2019`, `ecdsa-jcs-2019`, `ecdsa-sd-2023`
  (selective disclosure), `bbs-2023`, and the legacy
  `Ed25519Signature2018/2020`, `JsonWebSignature2020`,
  `EcdsaSecp256k1Signature2019` and `BbsBlsSignature2020`;
* **W3C VC-JOSE-COSE**: `vc+jwt`, the W3C `vc+sd-jwt` and `vc+cose`;
* **JSON Web Proofs** (JPT) and **SD-CWT**, both drafts;
* **AnonCreds**, a CL holder and verifier with revocation, in its own form
  and the W3C form, held to anoncreds-rs.

Step 1's **Credential to request** lists every format, the issuer's own
configurations first and the built-in ones after, and choosing one fills
the format-dependent fields with values that format accepts.

### New: VC tools pages

* **VC Barcodes** (`vc-barcodes.html`): a credential in a QR code or a
  PDF417 symbol, signed with `ecdsa-xi-2023`, with CBOR-LD 1.0.
* **Gordian Envelope** (`gordian-envelope.html`): dCBOR, the digest tree,
  elision, encryption, compression, SSKR and multi-part URs.
* **ACDC** (`acdc.html`): CESR 1 and 2, KELs, registries and IPEX grants.
* **Predicate queries** (`vc-predicates.html`): DIF Presentation Exchange
  predicates, and range proofs through AnonCreds.

### New in the issuance workflow

* **Client authentication at the token endpoint**: `client_secret_basic`,
  `_post` and `_jwt`, `private_key_jwt`, and the draft Client Attestation,
  on every token call, the code exchange included. No secret is stored.
* **Credential offers** read from a QR code image, and deferred issuance.
* The **attestation** key-proof type beside `jwt` (OpenID4VCI 1.0 §8.2.1).

### New: post-quantum and HPKE JWE

`jose_jwe.js` encrypts and decrypts with ML-KEM-512/768/1024 (with and
without key wrap) and HPKE-0 through HPKE-16, X-Wing included. ECDH-ES
now honours `apu` and `apv` in its key derivation; 0.9.4 ignored them,
so a JWE using either did not decrypt elsewhere.

### New: the api hosts an SSF transmitter

A receiver that expects a full SSF 1.0 transmitter can discover one at
`/.well-known/ssf-configuration/ssf/transmitter/<id>`, create its stream,
and poll it. The SSF page still signs every Security Event Token. The
hand-off scope on the SSF page is editable, and an `invalid_scope` answer
is explained.

### Changed on the pages

* **Landing page.** New cards for **Digital signatures & Hashing** and
  **Encryption tools**. A tool page's return link goes to Home.
* **OAuth 2.0 / OIDC step 2.** The Logout pane stays collapsed until a
  token set and a session exist, and is not opened for Client Credentials.
* **Digital Signature and Encryption pages.** The long introductions fold
  away, closed by default, under a one-line summary.
* **VC Tools pane** is collapsed by default.
* **PKI.** A profile's `keyUsage` defaults follow the key algorithm.
* **XACML.** A disabled policy takes part in no decision, and a legacy
  combining algorithm is kept on update.
* **User guides** for the SAML, WS-Trust, GNAP, XACML and VC workflows,
  with screenshots the test suite takes.

### For developers

* **`local-run-tests.sh` is removed**, with `local-tests.yml` and
  `local-tests-external-sts.yml`. `./docker-run-tests.sh` has every option
  it had.
* `./docker-run-tests.sh --select=<selectors> --repeat=<N>` runs named jobs
  against the full stack, N times.
* The api and embedded images no longer carry the test suites or
  repository files.
* Docker Image CI has a release-candidate mode
  (`gh workflow run dockerimage.yml --ref develop -f candidate=true`):
  images tagged `M.N.P-candidate`, no `latest`, no GitHub release.
* A manual run of either live-site suite may name the iya-sts images
  (`iya_sts_image`, `iya_sts_companion_image`).

## 0.9.4 and earlier

See the [GitHub releases](https://github.com/rcbj/id-proto-debugger/releases).
