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
wallet posts until the page polls for it. Each request's leaf key, the
response decryption key and the api session's secret are held for one page
load and never stored. The Verifier's identity is the exception, behind an
opt-out checkbox: see below. The routes,
settings and limits are in `docs/vc-verifier-api.md`.

On the static sites there is no api, so the page cannot host a request. It
says so, and pane 4 still checks a pasted answer.

## Issuer metadata, DID documents and status lists

Checking an answer means reading things the WALLET did not send: an SD-JWT
VC issuer's `/.well-known/jwt-vc-issuer` and its `jwks_uri`, a `did:web`
document, a Token Status List or a Bitstring Status List credential. From the
page each is a cross-origin GET, which the browser lets the page read only
when the server sends CORS headers. iya-sts sends them; SD-JWT VC issuers and
`did:web` hosts generally do not, and Token Status List section 8.1 makes
CORS only a SHOULD.

So pane 2 has **Fetch issuer metadata, DID documents and status lists
through the api** (`vpv_fetch_via_api`, an ordinary remembered setting). It
is **on by default wherever there is an api** and off, and disabled, on the
static sites, which have none. Ticked, each GET goes through `POST
/oid4vp/call` with `responseEncoding: "base64"`, so the api's address
policy, timeouts and size and redirect caps apply, and a status list that is
a binary CWT arrives as its bytes. Unticked, the browser fetches directly,
and a server with no CORS headers is named in the error.

Either way a fetch that fails throws an error naming the URL. For an
issuer's key the engine reports that as a SKIP ("could not fetch …"), which
makes the verdict incomplete, not a signature FAIL.

## The certificate

Each request gets a new P-256 leaf, issued under the Verifier's **root CA**,
which is kept across runs (next section). The leaf's subjectAltName is the
api's host name (the host of `response_uri`), which is what `x509_san_dns`
names, and its Authority Information Access `caIssuers` URL is the api's
`/oid4vp/verifier/<id>/ca`, which serves the root. The Request Object's
`x5c` carries the leaf only. A wallet that completes a chain from AIA, as
`rcbj/oid4vc-wallet` does, finds the root there; any other wallet is given
the root once, as a trust anchor, and it stays valid for every later request.

**The host a wallet is handed** is the api's address as the page reached it,
unless pane 2's **Public base URL of the api** or the api's
`oid4vpVerifierPublicBaseUrl` names another (`docs/vc-verifier-api.md`).
`localhost` or `api` is unreachable from a phone scanning the QR code, and
pane 3 says so when the request uses one.

**An IP address is never a dNSName** (RFC 5280 section 4.2.1.6). When the
host is an address, the leaf carries it as an iPAddress subjectAltName, so
`x509_hash` works. `x509_san_dns` is refused before anything is made: OpenID4VP
1.0 section 5.9.3 makes that Client Identifier "a DNS name" matching a
dNSName SAN, and an address can be neither. The error says to use
`x509_hash` or reach the api by a host name.

## The Verifier's identity across runs

Until #470 every request made a new root, attester and request key, so only
a wallet that fetches its anchor from AIA could trust the Verifier. A wallet
configured with trust anchors, an attester's key or a registered JWKS
refused every signed request. Three things now outlive a request:

| Part | Used by | What a wallet is given |
|---|---|---|
| the root CA (certificate and key) | `x509_hash`, `x509_san_dns` | the root certificate, as a trust anchor |
| the attester | `verifier_attestation` | the attester's JWKS (its `iss` is the `did:jwk` of that key) |
| the request key | `decentralized_identifier`, a pre-registered `client_id`, and the key a Verifier Attestation's `cnf` names | the DID, or the JWKS registered for the `client_id` |

Pane 2 shows all of them, under "The Verifier's identity". Each part is made
the first time a prefix needs it. The response encryption key is not part of
the identity: it is sent in each request's `client_metadata`, so nothing is
anchored on it, and keeping it would only let one leaked key read later
answers.

**These are private keys**, so they follow the key-material rules every
key-pair pane here follows. They are stored in `localStorage` under
`vpv_identity` only while **Keep this identity** (`vpv_save_identity`) is
ticked, which is the default. Unticking it removes the stored identity at
once. `saveState()` removes it whenever the box is off, and so does every
page load. A cached page without the box keeps saving; only an explicit `"0"`
stops it. With saving off the identity lasts one page load. **Download the
identity** writes it as one JSON file (`vp_verifier.js`
`verifierIdentityFile()`: the root's certificate PEM and private JWK, the
attester's `iss` and private JWK, the request key's private JWK), and **Use a
saved identity** reads one back, checking that each JWK's `x` and `y` belong
to its `d` and that the root's key is the one in its certificate. The import
field is never stored. **Make a new identity** discards it, and every wallet
must then be given the new one.

## Request options (#471, E3)

These are on top of the format, type, claims and holder binding fields.
Each is carried as OpenID4VP 1.0 defines it, and `buildDcql()` /
`requestObjectClaims()` refuse a malformed one and say why.

* **Claim ids, `values` and `claim_sets`** (section 6). A claims line may
  be `id: path = v1 | v2`, and the "Claim sets" box takes one set of ids
  per line. `values` are strings, integers or booleans (6.3). Every claim
  needs an id when claim sets are given. The answer is held to them as
  before: a claim matches only with one of its values, and one claim set
  must be met.
* **`intent_to_retain`** on every claim of an `mso_mdoc` query (Appendix
  B.2.4). It is refused for other formats.
* **Ask by `scope`** (section 5.5). It is sent INSTEAD of `dcql_query`;
  section 5.1 allows one or the other, never both. A scope is an alias the
  wallet resolves, so the answer is checked against the query on the page,
  which should be the one the scope stands for.
* **`verifier_info`** (section 5.1): a JSON array of `{ format, data,
  credential_ids? }`, carried as given. `credential_ids` must name the
  query's credential ids.
* **`request_uri_method=get`, said explicitly.** The default GET delivery
  omits the parameter, which means the same to a wallet (RFC 9101).
* **The request key**: P-256 (ES256), P-384 (ES384) or Ed25519 (EdDSA),
  for the leaf an `x509_hash` or `x509_san_dns` request is signed with.
  The root stays P-256. `decentralized_identifier`, `verifier_attestation`
  and pre-registered keep their P-256 request key.

**`transaction_data`** (section 8.4; #471, E3b). The page takes a JSON
array of `{ type, credential_ids, ... }` objects, and
`encodeTransactionData()` sends each as base64url JSON. It refuses a
malformed object, an id that names no query, and a transaction bound to an
SD-JWT VC query that does not require holder binding (Appendix B.3.3: a
Wallet MUST reject that). The answer is checked by Appendix B.3.3.1, the
one profile the spec defines:

* `kb.transaction_data[i]`: the KB-JWT's `transaction_data_hashes`
  contains the hash of the STRING as sent (it is not base64url-decoded
  first), by sha-256 unless the object listed `transaction_data_hashes_alg`.
  In that case the KB-JWT must name the algorithm it used, and it must be
  one of them. sha-256/384/512 and sha3-256/384/512 are computed.
* `response.transaction_data[i]`: one presentation binds the transaction.
  More than one is a FAIL, because section 5.1 lets the Wallet use only one
  of the referenced credentials.

A KB-JWT with no `transaction_data_hashes`, and an mdoc, whose data element
is type-specific (Appendix B.2.1), are reported as not evaluated, never
failed: section 8.4 leaves the representation to each type.

**Multisigned DC API requests** (Appendix A.3.2.2; #471, E3c). With
"multisigned" ticked, the request is `openid4vp-v1-multisigned`. Its
`data.request` is a JWS JSON Serialization: ONE payload, and one signature
per Client Identifier, by the prefix chosen above and a second one. Each
signature's protected header carries its `client_id` (and `verifier_info`
when given) and nothing else does. `iss`, which names the client_id for an
x509 prefix, is left out of the shared payload for the same reason. The
answer's audience is `origin:` plus the page's origin whichever signature
the wallet used, so it is checked as before.

`org-iso-mdoc` (ISO/IEC 18013-7 Annex C) is NOT implemented. Its request
and its HPKE-encrypted response are defined there, not in OpenID4VP, and
the debugger has no copy of that text to implement it from.

## The HAIP 1.0 profile (#471, E1)

"Profile" on pane 2 chooses OpenID4VP 1.0 or HAIP 1.0. HAIP is a profile of
OpenID4VP, not another protocol, and it binds both ends.

**What this Verifier sends.** `vp_verifier.haipRequestProblems()` lists the
rules a request would break, and the page refuses to send it, naming each
rule. These are the Verifier's own MUSTs:

* redirect flow: x509_hash, by reference (`request_uri`), `direct_post.jwt`
  (sections 5 and 5.1);
* DC API: `dc_api.jwt`, and x509_hash when the request is signed (5.2);
* `dc+sd-jwt` or `mso_mdoc` only (5);
* A128GCM and A256GCM both in `encrypted_response_enc_values_supported`
  (5).

No `redirect_uri` back to the wallet is only advised: section 5.1
RECOMMENDS the same-device flow, which needs one.

**What it reports about an answer (rcbj, 2026-11-17).** A presentation that
breaks a HAIP MUST is reported as violating HAIP, and every other check
still runs as far as the information allows. Each rule is a row whose id
contains `haip.` and whose label starts "HAIP 1.0:". It is a PASS, or a FAIL
reading "VIOLATES HAIP 1.0: ..." with the section quoted. These rows carry
`profile: "haip"`. `finish()` leaves them out of the validity verdict and
returns `profile: { name, violations, conformant }`. The page prints that on
its own line under the verdict. The rules:

* the answer is encrypted, and its JWE is ECDH-ES with A128GCM or A256GCM;
* the format is `dc+sd-jwt` or `mso_mdoc`;
* SD-JWT VC (6.1, 6.1.1, 6.1.1.1): the issuer JWT carries `x5c`, its signer
  is not self-signed and its chain does not carry the anchor, a
  credential with `cnf` comes with a KB-JWT, and a `status` claim
  carries `status_list`;
* a Status List Token (6.1): its key is in `x5c`, with the same two chain
  rules;
* mdoc (5.3.1): one document per DeviceResponse, and the same two chain
  rules on its `x5chain`.

Outside HAIP mode none of these rows exist. The self-signed and
included-anchor findings stay the reported rows described below.

## What is checked

`vp_verifier.verifyResponse()` returns one entry per check and never folds
two into one. The response checks are the `state`, the decryption of a
`direct_post.jwt` answer, and that every required credential query was
answered. Per format:

* **dc+sd-jwt**: the issuer's signature (an `x5c` in the issuer JWT, else
  the DID that `iss` is, else the JWT VC Issuer Metadata of an `https`
  `iss`), the `typ`, the `vct`, validity, every
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
  `issuer.trust` (and `mdoc.issuer-trust` for an mdoc `x5chain`) reports
  whether each certificate is signed by the next and is within its
  validity, and whether a supplied trust anchor anchors the chain. A broken
  link or an expired certificate is a FAIL. With `session.trustAnchors`
  (PEM or base64 DER, the page's "Trust anchors for issuers") the row is a
  PASS or a FAIL; without them nothing anchors the chain, the row is an
  essential SKIP, and the verdict is incomplete. The certificate checks are
  pure JavaScript (node-forge ASN.1, @noble/curves, forge RSA).
* **DCQL `trusted_authorities` (#471, E2).** With "Trusted authorities"
  ticked, the generated query carries `{ "type": "aki", "values": [...] }`,
  one value per trust anchor: its SubjectKeyIdentifier in base64url, which
  is the AuthorityKeyIdentifier of every certificate it issues (OpenID4VP
  1.0 section 6.1.1.1; HAIP 1.0 section 5 makes `aki` a MUST to support).
  The query is drawn again when the anchors change. On the answer,
  `issuer.trusted-authorities` (`mdoc.trusted-authorities` for an mdoc)
  passes when a certificate in the credential's chain has an AKI equal to
  a value, as bytes. Otherwise it is a non-essential SKIP naming why: no
  chain, no match, or a type this Verifier does not evaluate (`etsi_tl`,
  `openid_federation`). The wallet "SHOULD" return a matching credential;
  whether the issuer is trusted is still decided by the trust rows.
* **What is REPORTED and never fails (rcbj, 2026-11-17).** Each is a row of
  its own, a SKIP that is not essential, so neither the signature row nor
  the verdict changes because of it:
  * `issuer.self-signed`: the signing certificate is self-signed (HAIP 1.0
    section 6.1.1 says it MUST NOT be);
  * `issuer.anchor-included`: a trust anchor travels in `x5c` (same
    section);
  * `issuer.iss`: whether `iss` is bound to the signing certificate. It is
    bound by a URI subjectAltName equal to `iss`, a dNSName of its host, or
    a configured mapping (SD-JWT VC -27 section 2.5 allows one; the page's
    "Issuer bindings" field: `<iss> = sha256:<hex>` of a certificate of the
    chain or its anchor, or `<iss> = cn:<common name>`). Bound is a PASS.
    Unbound says plainly that `iss` is NOT authenticated by the certificate
    and that the issuer is the certificate's subject, quoting the section's
    "Issuers ... SHOULD NOT include an iss claim without such a binding".

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
    application/statuslist+jwt, application/statuslist+cwt` (section 8.1),
    and both forms are verified. In the JWT form (section 5.1) `typ` is
    compared as a media type (RFC 7515 section 4.1.9), so
    `application/statuslist+jwt` and any letter case pass.
  * The CWT form (section 5.2) is a COSE_Sign1 decoded with `cbor.js` and
    verified in pure JavaScript by `mdoc.verifyCoseSignature()` over RFC
    9052's Sig_structure. It FAILs when it is not tagged
    COSE_Sign1_Tagged (18), when it is tagged with the CWT tag (61, which
    section 5.2 forbids), and when the protected header's type (16) is
    missing or is not `application/statuslist+cwt`. An integer type is a
    CoAP Content-Format, whose number section 14.8 still leaves TBD, so it
    is reported and not judged. The claims are `2` (sub, which must be the
    credential's uri), `6` (iat, required), `4` (exp), `5` (nbf), `65534`
    (ttl, reported) and `65533`, the section 4.3 map whose `lst` is a byte
    string; an `aggregation_uri` there is reported. The key is named by
    the COSE `kid` (4), `x5chain` (33) or `x5t` (34, SHA-256 or SHA-1),
    read into the same header the JWT path uses, so the key order and the
    `.signer` row below are the same for both forms. A COSE_Mac0 (tag 17)
    is SKIP: it needs a key shared with the Status Issuer, and none is held.
    A Content-Type other than the form's media type is reported (section
    8.2).
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
    draft's own vectors (sections 4.1 and 4.2, Appendix C.1 and C.3), the
    CBOR StatusLists of section 4.3 and Appendix C.1 and C.2 inside a CWT,
    and section 5.2's example CWT, which is read and not relied on because
    the draft does not publish its key.
  * VALID is PASS, INVALID and SUSPENDED are FAIL. Any other value is SKIP
    and shown: 0x03 and 0x0C to 0x0F are application-specific (section
    7.1), and the rest are reserved for future registration.
  * A body that is neither a compact JWS nor a COSE structure (detected by
    decoding the CBOR, never by its first byte) is reported as what it is:
    an HTML page, other binary data or other text is FAIL. The page hands
    the body over as bytes, so a binary CWT is not mangled into text.
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
* **The origin has no trailing slash.** It is `window.location.origin`, the
  HTML serialization of an origin (scheme, host, port), and that is what
  OpenID4VP 1.0 calls the Origin: section 2 says "The web origin is
  https://verify.example.com", Appendix A.2's `expected_origins` example is
  `https://origin1.example.com`, and B.2.6.2's worked SessionTranscript
  hashes `https://example.com`. The tests reproduce those bytes. The
  `origin:https://verifier.example.com/` in section 5.9.3 and Appendix A.4 is
  a "for example", and it is the only example that has a slash. An `aud` of
  `origin:<origin>/` therefore FAILs, and the detail explains why. A
  `session.origin` with a path is a URL, not an origin, so
  `response.origin` FAILs too.

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

**The live object honours the wallet's `wallet_metadata` (#471, E4).**
`vp_verifier.planForWalletMetadata()` reads what the wallet POSTed and
`signLive()` acts on it. Each choice is a `wallet_metadata:` line in the
event list, `vc-ok` when honoured and `vc-pending` when it could not be.
Section 5.10 puts no MUST on the Verifier here, so none of them refuses the
wallet:

* `request_object_signing_alg_values_supported`: sign with the first alg
  the request key makes that the wallet lists (Ed25519 makes both
  `Ed25519` and `EdDSA`). With none in common, the key's own alg is used
  and the line says so.
* `jwks`: the Request Object is signed, then encrypted (RFC 9101 section
  4) to the first key that is not `use: "sig"` and that `jose_jwe.js` can
  encrypt to. The alg is the key's own `alg`, else ECDH-ES for EC/OKP and
  RSA-OAEP-256 for RSA; the enc is A256GCM. Both are narrowed by
  `request_object_encryption_alg_values_supported` and
  `..._enc_values_supported` when the wallet lists them. It is a Nested JWT,
  so `cty` is `JWT` (RFC 7519 section 5.2). Only this live answer can be
  encrypted: an object signed in advance has nobody's key.
* `authorization_encryption_enc_values_supported`: for `direct_post.jwt`,
  `encrypted_response_enc_values_supported` is narrowed to the values both
  sides do. A response alg the wallet does not list in
  `authorization_encryption_alg_values_supported` is reported.
* `client_id_prefixes_supported` and `vp_formats_supported`: a prefix or a
  requested format the wallet lacks is reported.

## Predicate requests and AnonCreds (#474)

The page can ask for a **predicate** (`age >= 18`, proven rather than
shown). It has a Predicates box, a query-language choice and an AnonCreds
issuer-material box, and none of the three is stored. `docs/predicates.md`
is the full note. The Verifier-side rules:

- **DCQL**: the predicates go in this debugger's **non-standard**
  extension, `x_debugger_predicates`, marked critical in
  `x_debugger_crit`. `buildDcql()` refuses a predicate whose claim is also
  in `claims`, because a 1.0 wallet ignoring the extension would then
  disclose it. `anoncreds` is a format a query may name (`QUERY_FORMATS`,
  `meta: {}`); `FORMATS` is unchanged.
- **Presentation Exchange 2.1.1** (`buildPresentationDefinition()`) is sent
  as `presentation_definition`, labelled "OpenID4VP drafts —
  presentation_definition, removed in 1.0". It is refused under HAIP and
  over the DC API. The answer's `presentation_submission` gets its own
  row. Only an AnonCreds presentation is verified under it; any other
  format is an essential SKIP, so the verdict is **incomplete**.
- **AnonCreds**: the CL proof is checked against the AnonCreds request this
  debugger maps the query onto, and every predicate gets its own row. The
  issuer's schema and credential definition (and a revocable credential's
  status list) come from `session.anoncreds`. Without them the proof row is
  an essential SKIP, so the verdict is incomplete, never a pass. The
  witness for every row is anoncreds-rs (`tests/vp_query_engine.js`).
- **The extension on another format**: an mdoc's `age_over_NN` must be
  `true`. Any other format FAILs the predicate. A disclosed value is never
  accepted in a predicate's place.

## Tests

| Test | Kind | What it covers |
|---|---|---|
| `tests/vp_verifier_engine.js` | node | the DCQL builder, the certificate, the Request Object read back by the Wallet's own `verifyX509Request()`, and a round trip per format, with a negative case for each check |
| `tests/api_oid4vp_verifier.js` | node | the api's routes, limits and expiry |
| `tests/vc_verifier_page.js` | browser | the page creates a request through the api; node plays the wallet and posts an answer; every check on the page passes, and a tampered answer fails the check it targets. Then a `decentralized_identifier` request under `request_uri_method=post`, where the wallet's `wallet_nonce` must come back in a Request Object signed live; the QR code; and the DC API button naming its absence in headless Chrome |
| `tests/vc_verifier_oid4vc_wallet.js` | browser | the same page against **rcbj/oid4vc-wallet**, a native Rust wallet that shares no code with the debugger. A person makes a pre-authorized offer on iya-sts's `/portal/wallet`; the wallet redeems it by value with the Transaction Code (`accept`), then answers the page twice (`present --approve`): `x509_hash` + GET + `direct_post`, and `x509_san_dns` + `request_uri_method=post` + `direct_post.jwt`. Every check must pass. Then it refuses (`present --refuse`), and the page must report `access_denied` as a failure |

### The independent wallet

`rcbj/oid4vc-wallet` is built inside the tests image, the way iya-sts's own
tests image builds it (its #694). The `oid4vc-wallet` stage of
`tests/Dockerfile` starts from `rust:1.97-bookworm`, which the image mirror
carries. It downloads the wallet's source at a pinned commit, checks the
archive's SHA-256, and runs `cargo build --release --locked`. The binary is
copied to `/opt/oid4vc-wallet/` and named by `OID4VC_WALLET_BIN`. The archive
URL is listed in `KNOWN_FETCHES` in `tests/image_mirror_coverage.js`. To move
to a newer wallet, change the commit and the SHA-256 and nothing else.

The job gives the wallet a home of its own for each run, with
`OID4VC_WALLET_KEY_FILE` in place of a desktop key ring and `SSL_CERT_FILE`
pointed at the stack's CA bundle. A missing binary fails the job by name; it
is never skipped. To run the job on a host, set `OID4VC_WALLET_BIN`.
