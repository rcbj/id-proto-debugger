# The debugger as the OpenID4VP Verifier

`vc-verifier.html`, its bundle `client/src/vc_verifier.js`, and the engine
behind it, `client/src/vp_verifier.js`. Issue #364.

The VC presentation workflow has two roles. The **Wallet** is the debugger
answering somebody else's Verifier: `vc-presentation-0.html` through `-3`,
described in `docs/vc-presentation-guide.md`. The **Verifier** is this page:
the debugger asks a wallet for claims and checks the answer. The role
selector at the top of `vc-presentation-0.html` links the two.

## What the page does

1. **What to ask for.** One credential query from the fields (format, `vct`,
   `doctype` or type values, claim paths, holder binding), generated as a
   DCQL query (OpenID4VP 1.0 section 6). The DCQL textarea stays editable, so
   a second query or `credential_sets` can be written by hand; a hand-edited
   query is kept across page loads.
2. **How to ask.** The settings:
   * **Client Identifier prefix** (section 5.9.3):
     * `x509_hash`, `x509_san_dns`;
     * `redirect_uri` (an unsigned request);
     * `decentralized_identifier` (a `did:jwk` of a key made for the run);
     * `verifier_attestation` (a Verifier Attestation JWT from an attester
       made for the run);
     * a pre-registered `client_id` with no prefix.

     `openid_federation` is refused by name: it needs a trust chain this
     debugger does not build.
   * **Response mode:** `direct_post`, `direct_post.jwt` (encrypted to a P-256
     key made for the run), and the Digital Credentials API's `dc_api` and
     `dc_api.jwt`.
   * **Delivery:** by reference with `request_uri` (GET, or
     `request_uri_method=post`), or by value.
3. **Hand it to a wallet.** The `openid4vp://` Authorization Request, a link
   that opens it on this device, a QR code for a wallet on another device,
   the decoded Request Object, and what a wallet must trust. That depends on
   the prefix: the Verifier's root certificate, the attester's keys, the
   JWKS of a pre-registered client, or the DID.
4. **What the wallet sent.** The api's log of the wallet's calls, then every
   check on the answer as its own row: PASS, FAIL or SKIP. An answer can
   also be pasted and checked; that half needs no api.

## Why the api is involved

`direct_post` has the wallet POST its answer to a `response_uri`, and a
request by reference has the wallet fetch a `request_uri`. A page is not an
HTTP server, so the api hosts both, as it hosts the Shared Signals push
receiver. **The api is a store.** The page makes the key pair and the
certificates and signs the Request Object in the browser; the api is given
the compact JWS and the root certificate and serves them, and keeps what the
wallet posts until the page polls for it. The private keys and the api
session's secret are held for one page load and never stored. The routes,
settings and limits are in `docs/vc-verifier-api.md`.

On the static sites there is no api, so the page cannot host a request. It
says so, and pane 4 still checks a pasted answer.

## The certificate

Each request gets a new self-signed P-256 root and a leaf signed by it. The
leaf's subjectAltName is the api's host name (the host of `response_uri`),
which is what `x509_san_dns` names, and its Authority Information Access
`caIssuers` URL is the api's `/oid4vp/verifier/<id>/ca`, which serves the
root. The Request Object's `x5c` carries the leaf only. A wallet that
completes a chain from AIA, as `rcbj/oid4vc-wallet` does, finds the root
there; any other wallet can be given the root from pane 3 as a trust anchor.

## What is checked

`vp_verifier.verifyResponse()` returns one entry per check and never folds
two into one. The response checks are the `state`, the decryption of a
`direct_post.jwt` answer, and that every required credential query was
answered. Per format:

* **dc+sd-jwt**: the issuer's signature (an `x5c` in the issuer JWT, else
  JWT VC Issuer Metadata, else a DID), the `typ`, the `vct`, validity, every
  disclosure's digest against `_sd`, and every requested claim disclosed. For
  the Key Binding JWT: its `typ` and `alg`, `nonce`, `aud`, `iat`,
  `sd_hash`, and its signature against `cnf.jwk`.
* **jwt_vc_json**: the VP JWT's signature against the holder's key, its
  `nonce` and `aud`, and each embedded credential's issuer signature and
  validity.
* **mso_mdoc**: the issuer-signed checks `mdoc.js` makes, the device
  signature over the OpenID4VP session transcript, and the doctype.
* **ldp_vc**: Data Integrity proofs:
  * `bbs-2023` derived proofs;
  * `eddsa-rdfc-2022`, `ecdsa-rdfc-2019` (P-256 and P-384), `eddsa-jcs-2022`
    and `ecdsa-jcs-2019`, on the presentation and on each credential;
  * the proof's challenge and domain.

  `ecdsa-sd-2023` is reported as SKIP; its derived proofs are not
  implemented.

**Status lists** are checked per credential, and the `status` row summarises
them:

* **dc+sd-jwt and mso_mdoc: the IETF Token Status List**
  (draft-ietf-oauth-status-list).
  * The Status List Token (`typ` `statuslist+jwt`) is fetched and its
    signature checked with the issuer's keys.
  * `lst` is decompressed (zlib, with the browser's `DecompressionStream`).
  * The entry's value is reported: VALID, INVALID, SUSPENDED or
    application-specific. Entry 0 is in the least significant bits of
    byte 0.
  * A CWT status list is recognised and reported as SKIP.
* **jwt_vc_json and ldp_vc: the W3C Bitstring Status List**, one row per
  `statusPurpose`. The list is GZIP and read most significant bit first.

A credential with no status is SKIP, not PASS.

## The Digital Credentials API

Under `dc_api` or `dc_api.jwt` (OpenID4VP 1.0 Appendix A), nothing is hosted.
**Ask through the Digital Credentials API** hands the request to
`navigator.credentials.get({ digital: ... })`, and the wallet's answer comes
back to the page.

* **Unsigned** (`openid4vp-v1-unsigned`): the request names no Client
  Identifier, and the page's origin stands for it.
* **Signed** (`openid4vp-v1-signed`): the request is signed with the chosen
  prefix and lists the page's origin in `expected_origins`.
* `openid4vp-v1-multisigned` is refused, because this debugger is one
  Verifier.
* **Audience:** under the DC API a KB-JWT, a VP and an `ldp_vc` proof are
  held to `origin:<origin>`. An mdoc device signature is checked against the
  DC API handover (B.2.6.2).

A browser without the API, or without a wallet the platform knows, is told
so by name.

## `wallet_nonce`: signing while the wallet waits

Under `request_uri_method=post` a wallet may send a `wallet_nonce`. The Request
Object should then contain it (section 5.10). The api cannot sign, so a
request delivered that way is created with live signing on:

1. The api holds the wallet's POST open for `oid4vpVerifierLiveSignWaitMs`
   (15 seconds by default).
2. The page, polling every 500 ms, signs a fresh Request Object carrying the
   nonce and sends it with `PUT …/request/<signingId>`.
3. The api answers the wallet with that object.

If the page misses the window, the wallet gets the object signed in advance.
The events say which happened. `docs/vc-verifier-api.md` has the routes.

## Tests

| Test | Kind | What it covers |
|---|---|---|
| `tests/vp_verifier_engine.js` | node | the DCQL builder, the certificate, the Request Object read back by the Wallet's own `verifyX509Request()`, and a round trip per format, with a negative case for each check |
| `tests/api_oid4vp_verifier.js` | node | the api's routes, limits and expiry |
| `tests/vc_verifier_page.js` | browser | the page creates a request through the api; node plays the wallet and posts an answer; every check on the page passes, and a tampered answer fails the check it targets. Then a `decentralized_identifier` request under `request_uri_method=post`, where the wallet's `wallet_nonce` must come back in a Request Object signed live; the QR code; and the DC API button naming its absence in headless Chrome |

The independent wallet in the suite, `rcbj/oid4vc-wallet`, is PR 2 of #364.
