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
  * `bbs-2023` derived proofs, as W3C Data Integrity BBS Cryptosuites v1.0
    defines them (#470 B1): the credential is a **reveal document** with an
    embedded `DataIntegrityProof` whose `proofValue` is a derived proof (CBOR
    tag `0xd95d03`). The Verifier canonicalizes the reveal document itself,
    relabels it with the proof's label map, splits it by the mandatory
    indexes and runs BBS ProofVerify (`bbs2023.verifyDerivedProof()`). The
    issuer's key is the `verificationMethod`'s Multikey (`z` + base58btc of
    `0xeb01` and the 96-byte G2 key); a `did:key` is read in place, anything
    else resolved or fetched. It must be the issuer's (the S2 rule below), and
    the credential's `validFrom`/`validUntil` and status are checked like any
    other `ldp_vc`;
  * the derived proof's **presentation header** (`bbs.ph`). A bare reveal
    document is accepted when its presentation header is the request's
    `nonce`, which is then its only binding to the request and an essential
    check. Inside a VP whose proof carries `challenge` = nonce and `domain` =
    Client Identifier (Appendix B.1.3.2.5) the header may be the nonce or
    empty;
  * the **pre-W3C envelope** this debugger's wallet sent before #470
    (`{cryptosuite, proof, disclosedStatements, disclosedIndexes,
    proofOptions}`) is a FAIL that says so. It is not read;
  * `eddsa-rdfc-2022`, `ecdsa-rdfc-2019` (P-256 and P-384), `eddsa-jcs-2022`
    and `ecdsa-jcs-2019`, on the presentation and on each credential;
  * the proof's challenge and domain.

  `ecdsa-sd-2023` is reported as SKIP; its derived proofs are not
  implemented. Of bbs-2023's feature options only `baseline` is; a proof
  using anonymous holder binding or pseudonyms is refused by name.

**Whose key it is (#467).** A signature that verifies says nothing until
something ties the key to the issuer:

* **A `kid` never chooses the issuer.** A DID in the issuer JWT's `kid` is
  resolved only when `iss` IS that DID. An `https` `iss` takes its keys from
  its own JWT VC Issuer Metadata (SD-JWT VC section 2.5), and a DID in `kid`
  beside it is not used. `jwt_vc_json` follows the same rule.
* **An `ldp_vc` proof must be by a method the issuer controls.** For a DID
  issuer, the method is under that DID. For an `https` issuer, it is an
  `https` URL at or under the issuer, or a `did:web` whose document is
  there. Anything else is a FAIL: "verification method not authorised by the
  issuer". Status list credentials follow the same rule.
* **An `x5c` chain is never trusted on sight.** Beside the signature row,
  `issuer.trust` (and `mdoc.issuer-trust` for an mdoc `x5chain`) reports:
  * whether the leaf is self-signed;
  * whether each certificate is signed by the next;
  * whether a trust anchor travels in the chain (HAIP 1.0 section 6.1.1
    forbids that and a self-signed leaf);
  * whether every certificate is within its validity;
  * whether `iss` is bound to the leaf by a dNSName or URI subjectAltName.

  A broken link, an expired certificate or an unbound `iss` is a FAIL. With
  `session.trustAnchors` (PEM or base64 DER) the row is a PASS or a FAIL.
  Without them nothing anchors the chain, and the row is a SKIP. The
  certificate verification is pure JavaScript (node-forge ASN.1,
  @noble/curves, forge RSA). A Status List Token's own `x5c` is not reported
  this way yet.

**The verdict.** Each check carries `essential: true` when it establishes
authenticity: an issuer signature or proof, the issuer trust, a disclosure
digest, the device signature, or a holder signature the query depends on.
The result's `verdict` is one of three values:

* `"fail"`: a check failed.
* `"incomplete"`: nothing failed, but `incomplete` essential checks were
  SKIPs, such as an unsupported cryptosuite or an unanchored `x5c`.
* `"pass"`: neither of the above.

`ok` is true only for `"pass"`. The page shows "Every check passed" only for a
pass, and shows an incomplete verdict in amber, naming how many essential
checks could not be performed.

**Status lists** are checked per credential, and the `status` row summarises
them:

* **dc+sd-jwt and mso_mdoc: the IETF Token Status List**
  (draft-ietf-oauth-status-list-21).
  * The Status List Token is fetched with `Accept:
    application/statuslist+jwt`. The CWT form is not asked for, because it
    is not verified. `typ` is compared as a media type (RFC 7515 section
    4.1.9), so `application/statuslist+jwt` and any letter case pass.
  * Its signature is checked with **the first key that verifies**, in this
    order: the credential issuer's own key when the token references it
    (the same `x5c`, an `x5t` or `x5t#S256` of the credential's leaf, or the
    credential's `kid`); then the token's own key (its `x5c`, a DID, or an
    https `iss`'s `jwt-vc-issuer` metadata); then the credential issuer's key
    as a fallback, for example for an https `iss` with no metadata (section
    11.3). A token with an `x5c` of its own is held to that key alone.
  * A separate `.signer` row says whether that signer **is the credential's
    issuer, or authorised by it** (sections 1, 10 and 11.3). It is PASS for
    the same key, for a key from the credential issuer's own key resolution,
    and for a certificate issued by the same CA as the credential's that
    carries `id-kp-oauthStatusSigning`. That EKU has no OID yet (the draft
    says `1.3.6.1.5.5.7.3.TBD`), so `verifyResponse()` takes the OID a PKI
    uses as `statusSigningEku`; without it, a same-CA certificate is SKIP.
    Anything else is **SKIP, "NOT linked"**, never PASS, and the value row
    names it too.
  * `lst` is decompressed (zlib, with the browser's `DecompressionStream`).
    Entry 0 is in the least significant bits of byte 0. The tests read the
    draft's own vectors (sections 4.1 and 4.2, Appendix C.1 and C.3).
  * VALID is PASS, INVALID and SUSPENDED are FAIL. Any other value is SKIP
    and shown: 0x03 and 0x0C to 0x0F are application-specific (section
    7.1), and the rest are reserved for future registration.
  * A body that is not a compact JWS is reported as what it is. A
    COSE_Sign1 (detected by decoding the CBOR) is SKIP: recognised, not
    verified. An HTML page, other binary data or other text is FAIL. The
    page hands the body over as bytes, so a binary CWT is not mangled into
    text.
  * Status mechanisms other than `status_list`, such as an mdoc's
    `identifier_list`, are reported as SKIP by name, never as "no status".
* **jwt_vc_json and ldp_vc: the W3C Bitstring Status List**, one row per
  `statusPurpose`. The list is GZIP and read most significant bit first.
  * It is asked for as `application/vc`, `application/vc+jwt` and the JSON
    types (section 4).
  * `revocation` and `suspension` FAIL when set. `refresh` is PASS either
    way, and says when an updated credential is available. `message`
    reports the message, matching `statusMessage` by number, so `0x01` is
    `0x1`. With no `statusMessage` on a one-bit entry, the messages are
    "set" and "unset".
  * A `statusSize` above 1 with no `statusMessage`, or a `statusMessage`
    that is not 2^`statusSize` long, is a FAIL `.entry` row (section 2.1).
  * A list credential whose issuer is not the credential's is reported in
    the detail and not failed, because section 2.2 says it MAY differ.
  * A VC-JWT list credential's `validFrom` and `validUntil` are checked as
    well as the JWT's `nbf` and `exp`.

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

Under `request_uri_method=post` a wallet may send a `wallet_nonce`. The
Request Object must then contain it: "the Verifier MUST use it" (section
5.10). The api cannot sign, so a request delivered that way is created with
live signing on:

1. The api holds the wallet's POST open for `oid4vpVerifierLiveSignWaitMs`
   (15 seconds by default).
2. The page, polling every 500 ms, signs a fresh Request Object carrying the
   nonce and sends it with `PUT …/request/<signingId>`.
3. The api answers the wallet with that object.

If the page misses the window, a wallet that sent a `wallet_nonce` is
answered 503 rather than given the object signed in advance, which cannot
carry the nonce (section 5.10.2: any HTTP error makes the wallet stop). A
wallet that sent none gets the object signed in advance. The events say
which happened. `docs/vc-verifier-api.md` has the routes.

## Tests

| Test | Kind | What it covers |
|---|---|---|
| `tests/vp_verifier_engine.js` | node | the DCQL builder, the certificate, the Request Object read back by the Wallet's own `verifyX509Request()`, and a round trip per format, with a negative case for each check |
| `tests/api_oid4vp_verifier.js` | node | the api's routes, limits and expiry |
| `tests/vc_verifier_page.js` | browser | the page creates a request through the api; node plays the wallet and posts an answer; every check on the page passes, and a tampered answer fails the check it targets. Then a `decentralized_identifier` request under `request_uri_method=post`, where the wallet's `wallet_nonce` must come back in a Request Object signed live; the QR code; and the DC API button naming its absence in headless Chrome |

The independent wallet in the suite, `rcbj/oid4vc-wallet`, is PR 2 of #364.
