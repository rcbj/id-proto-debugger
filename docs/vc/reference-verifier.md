# Configuration reference: the VC Verifier page (the debugger as an OpenID4VP Verifier)

On `vc-verifier.html` the debugger is the **Verifier** of
[OpenID4VP 1.0][oid4vp]. You use it in four steps:

1. Compose a DCQL query.
2. The page signs an Authorization Request. For the x509 prefixes it uses a
   certificate issued under the Verifier's own root.
3. Hand the request to any wallet. It can be another product, or the
   debugger's own [wallet pages](reference-presentation.md).
4. Read what came back. Every check on the answer is its own row.

The page is reached from the **Verifier** card on `vc-presentation-0.html`.

**What the api does, and only that.** A page cannot answer an HTTP request,
so the debugger's api stores three things for the page and serves them to the
wallet:

- the signed Request Object at a `request_uri`;
- a `response_uri` the wallet posts its answer to;
- the root certificate the leaf's Authority Information Access names.

The page signs everything itself, with keys that never leave the tab. It
**polls** the api for what the wallet did. The api routes are listed in
[vc-verifier-api.md](../vc-verifier-api.md), and the design is in
[vc-verifier.md](../vc-verifier.md).

**Without an api** (the static sites), `vpv_api_status` says so. The page
cannot host a request there, but pane 4 still checks an answer you paste.

Unless a row says otherwise, every setting below is stored in `localStorage`
under its own element id (`VERIFIER_KEYS` in `client/src/vc_verifier.js`,
declared in `models/storage/vc_verifier.tsp`). The page writes a setting each
time you change it.

- [1. What to ask for](#1-what-to-ask-for)
- [2. How to ask](#2-how-to-ask)
  - [The Verifier's identity](#the-verifiers-identity)
  - [Buttons](#buttons)
  - [What HAIP 1.0 refuses before a request is sent](#what-haip-10-refuses-before-a-request-is-sent)
- [3. Hand it to a wallet](#3-hand-it-to-a-wallet)
- [4. What the wallet sent, and every check on it](#4-what-the-wallet-sent-and-every-check-on-it)
  - [The event list](#the-event-list)
  - [The verdict](#the-verdict)
  - [The check rows](#the-check-rows)
- [What is stored, and what is not](#what-is-stored-and-what-is-not)

---

## 1. What to ask for

Pane `pane_query`. The fields generate **one** credential query into the DCQL
box at the bottom of the pane. The box stays editable, so you can write a
second query or `credential_sets` by hand. If the box has text, that text is
what is sent.

| Field | id | What it is | Spec | Default |
|---|---|---|---|---|
| Credential query id | `vpv_query_id` | The query's `id`. The wallet's `vp_token` is keyed by it. | OpenID4VP 1.0 §6.1, §8.1 | `credential` |
| Format | `vpv_format` | `dc+sd-jwt` (SD-JWT VC), `jwt_vc_json`, `mso_mdoc` (ISO mdoc) or `ldp_vc` (W3C VC with a Data Integrity proof). These four are the formats this Verifier checks. | Appendix B | `dc+sd-jwt` |
| vct / doctype / type values | `vpv_type` | The label follows the format. For `dc+sd-jwt` it is `meta.vct_values` (separate several with spaces). For an mdoc it is `meta.doctype_value` (one). For the two W3C formats it is `meta.type_values`. Appendix B makes it **required**: when it is empty the query is not generated, and `vpv_dcql_status` says why. | Appendix B | Empty |
| Claims (one path per line) | `vpv_claims` | One claim path per line, with segments separated by dots. A number is an array index and `*` means every element. For an mdoc the first segment is the namespace. A line may start with `id:` and end with `= v1 \| v2` to constrain the values (a whole number becomes an integer, and `true`/`false` become booleans). | §6.3, §7 | Empty |
| Claim sets (optional) | `vpv_claim_sets` | One set per line: claim ids separated by commas, most preferred first. Every claim then needs an id. | §6.1 `claim_sets` | Empty |
| Intent to retain (mdoc) | `vpv_intent_to_retain` | Sets `intent_to_retain` (true or false) on every claim of an `mso_mdoc` query. "not said" leaves it out. | Appendix B.2.4 | not said |
| Holder binding | `vpv_binding` | `require_cryptographic_holder_binding`: whether the answer must carry a Key Binding JWT, a signed VP or a device signature. | §6.1 | On |
| Trusted authorities | `vpv_trusted_authorities` | Asks for credentials whose X.509 chain lies under the issuer anchors in pane 2. This is DCQL `trusted_authorities`, type `aki`: each anchor's SubjectKeyIdentifier, base64url. `vpv_trusted_authorities_note` counts the values found and names anchors without one. A credential that does not match is reported on its own row. | §6.1.1.1; HAIP 1.0 §5 | Off |
| DCQL query | `vpv_dcql` | The query that is sent. Generated from the fields above whenever one of them changes. | §6 | Generated on first load |

---

## 2. How to ask

Pane `pane_request`.

| Field | id | What it is | Spec | Default |
|---|---|---|---|---|
| Profile | `vpv_profile` | **OpenID4VP 1.0**, or **HAIP 1.0**. Under HAIP the page will not send a request that HAIP forbids (see [below](#what-haip-10-refuses-before-a-request-is-sent)). An answer that breaks a HAIP rule is reported on "HAIP 1.0" rows, and every other check still runs. `vpv_profile_note` lists what HAIP only advises. | HAIP 1.0 | OpenID4VP 1.0 |
| Request key | `vpv_request_key` | The key type of the request's leaf certificate under `x509_hash` / `x509_san_dns`: P-256 (ES256), P-384 (ES384) or Ed25519 (EdDSA). The root CA is always P-256. | HAIP 1.0 §7 (ES256) | P-256 |
| Ask by scope (optional) | `vpv_scope` | Sent **instead of** `dcql_query`. A scope is an alias for a query the wallet already knows. The answer is still checked against the DCQL above, so make that the query the scope stands for. | §5.1, §5.5 | Empty |
| transaction_data (optional) | `vpv_transaction_data` | A JSON array of objects, each `{ type, credential_ids, ... }`, sent base64url-encoded. For an SD-JWT VC, the KB-JWT's `transaction_data_hashes` must hold the hash of each string as it was sent: SHA-256, or one of the object's `transaction_data_hashes_alg`. A query a transaction is bound to must require holder binding. | §8.4; Appendix B.3.3 | Empty |
| verifier_info (optional) | `vpv_verifier_info` | A JSON array of attestations about this Verifier, each `{ format, data, credential_ids? }`. Carried as given. | §5.1 | Empty |
| Client Identifier prefix | `vpv_client_prefix` | One of the options below. **`openid_federation` is not offered:** it needs an OpenID Federation 1.0 trust chain, and this Verifier refuses it by name. | §5.9.3 | `x509_hash` |
| Pre-registered client_id | `vpv_client_id_typed` | Shown only for `pre-registered`. The request is signed with the Verifier's request key, and pane 3 shows the JWKS to register for this id. | §5.9 | Empty |
| Response mode | `vpv_response_mode` | One of the modes below. `vpv_dc_api_note` explains the Digital Credentials API case. | §8.2, §8.3, Appendix A | `direct_post` |
| Digital Credentials API request: signed | `vpv_dc_signed` | Ticked, the request is `openid4vp-v1-signed`: `client_id` carries the prefix above, and the certificate names **this page's host**. Unticked, it is `openid4vp-v1-unsigned`: no `client_id` is sent, and the audience is `origin:<this page's origin>`. | Appendix A.2–A.3 | On |
| multisigned | `vpv_dc_multisigned`, `vpv_dc_second_prefix` | `openid4vp-v1-multisigned`. The same payload is signed again as a second Client Identifier (`decentralized_identifier`, `x509_hash`, `x509_san_dns` or `verifier_attestation`), in JWS JSON Serialization. `client_id` and `verifier_info` go only in each signature's protected header. | Appendix A.3.2.2 | Off; `decentralized_identifier` |
| Request delivery | `vpv_delivery` | One of the options below. Forced to "by value" for `redirect_uri`. | §5, §5.10 | by reference, GET |
| Wallet invocation scheme | `vpv_scheme` | The scheme of the link and the QR code. | — | `openid4vp://` |
| Trust anchors for issuers (PEM, optional) | `vpv_trust_anchors` | The roots an issuer's `x5c` must chain to (an IACA for an mdoc). With none, issuer trust for an `x5c`-signed credential is reported as **not performed**, and the verdict is *incomplete*, not a pass. | SD-JWT VC §2.5 (*draft-ietf-oauth-sd-jwt-vc-27*) | Empty |
| Public base URL of the api (optional) | `vpv_public_base_url` | The https address a wallet uses to reach this debugger's api. The `request_uri`, the `response_uri` and the root's caIssuers URL are built from it; the api still serves on its own host. If the host is an IP address, the leaf names it as an iPAddress, and `x509_san_dns` cannot be used. | — | Empty: the api's `oid4vpVerifierPublicBaseUrl`, else the address the page reached the api at |
| Issuer-side fetches | `vpv_fetch_via_api` | Fetch issuer metadata, issuer JWKS, DID documents and status lists through the api's `POST /oid4vp/call` instead of from the browser. Most of those servers send no CORS headers. A failed fetch is reported as a check not performed, naming the URL, never as a signature failure. | Token Status List §8.1 (*draft-ietf-oauth-status-list-21*) | On wherever there is an api; off and disabled without one |
| Issuer bindings (optional) | `vpv_issuer_bindings` | One line per binding: `<iss> = sha256:<hex>` (of the signing certificate, a certificate in its chain or the anchor) or `<iss> = cn:<name>`. Without a binding, an `iss` that no subjectAltName names is reported as not authenticated by the certificate. That never fails the signature. | SD-JWT VC §2.5 | Empty |
| Send the wallet's browser to (optional) | `vpv_redirect_uri` | Returned as `redirect_uri` in the api's answer to the wallet's POST, with a fresh random `response_code` added each time. | §8.2; HAIP 1.0 §5.1 | Empty |

The Client Identifier prefixes (`vpv_client_prefix`):

| Option | What it means |
|---|---|
| `x509_hash` | The hash of the request's certificate. |
| `x509_san_dns` | A DNS name in the certificate. |
| `redirect_uri` | An unsigned request, by value only. |
| `decentralized_identifier` | A `did:jwk` of the request key. |
| `verifier_attestation` | A Verifier Attestation JWT signed by the Verifier's attester. |
| `pre-registered` | No prefix: a `client_id` the wallet already knows. |

The response modes (`vpv_response_mode`):

| Option | What happens |
|---|---|
| `direct_post` | The wallet POSTs a form to `response_uri`. |
| `direct_post.jwt` | The same, encrypted to an ECDH-ES P-256 key made for this run. |
| `dc_api` | The answer comes back through the browser's Digital Credentials API. |
| `dc_api.jwt` | The same, encrypted. |

The request delivery options (`vpv_delivery`):

| Option | What happens |
|---|---|
| `reference-get` | By reference: the wallet fetches `request_uri` with GET. |
| `reference-post` | By reference, with `request_uri_method=post`. The wallet may send a `wallet_nonce` and `wallet_metadata`. The page signs a fresh object echoing the nonce, encrypting it if the wallet asked, while the api holds the wallet's POST open (`oid4vpVerifierLiveSignWaitMs`, 15 s by default). If the page cannot answer in time, the api answers **503**; it never serves an object without the nonce. `client_metadata` goes next to `request_uri`. |
| `reference-get-explicit` | By reference, with `request_uri_method=get` stated in the request. |
| `value` | By value: the signed Request Object is in the link. |

### The Verifier's identity

These three keys are what a wallet is given in order to trust this Verifier,
so they last from one request to the next:

- the **root CA**, which a wallet anchors for the x509 prefixes;
- the **attester**, whose key a wallet trusts for `verifier_attestation`;
- the **request key**, which is the `did:jwk` and the pre-registered JWKS.

Only each request's leaf certificate is new.

| Field / button | id | Does | Stored |
|---|---|---|---|
| Keep this identity in this browser | `vpv_save_identity` | When ticked, the identity, **private keys included**, is kept under `vpv_identity`. Unticked, nothing is stored, any stored identity is removed at once, and the identity lasts this page load only. | On by default; `vpv_save_identity`; identity in `vpv_identity` (key material) |
| (trust text) | `vpv_identity_trust` | What to give a wallet, for each prefix. | |
| Download the identity | `btn_vpv_identity_download` | Saves `oid4vp-verifier-identity.json`. It holds private keys. | |
| Make a new identity | `btn_vpv_identity_new` | Discards the identity. The next request makes a new one, and every wallet that trusted the old one must be given the new one. | |
| Use a saved identity | `vpv_identity_import`, `btn_vpv_identity_import` | Paste a downloaded file to replace the identity. | Pasted text **never stored** |

`vpv_identity_status` reports the result.

### Buttons

| Button | id | Does |
|---|---|---|
| Create the request | `btn_vpv_create` | Checks that the api answers (`GET /oid4vp/verifier/limits`), opens a session (`POST /oid4vp/verifier`), makes the signer, signs the Request Object, publishes it with the root certificate (`PUT …/request`), fills pane 3 and starts polling. Under a `dc_api*` mode it does what the next button does. |
| Ask through the Digital Credentials API | `btn_vpv_dc_api` | Builds the DC API request and calls `navigator.credentials.get({ digital: … })`, then checks the answer. Nothing is hosted. This needs a browser with the API, a secure origin and a wallet the platform knows; otherwise the page says so. |
| Start over | `btn_vpv_reset` | Stops polling, deletes the api session (`DELETE /oid4vp/verifier/:id`) and clears panes 3 and 4. |

`vpv_create_status` reports the result.

The **nonce** and **state** are fresh random values for each request; you do
not set them. For `direct_post.jwt` / `dc_api.jwt` the page makes a fresh
ECDH-ES P-256 key for the run. Its private half lives only in this page load,
and the request offers A128GCM and A256GCM.

### What HAIP 1.0 refuses before a request is sent

With **Profile = HAIP 1.0**, `haipRequestProblems()` in
`client/src/vp_verifier.js` stops the request, naming each of these rules:

- a query format other than `dc+sd-jwt` or `mso_mdoc` (§5);
- **outside the DC API:**
  - a prefix other than `x509_hash` (§5, §5.1);
  - delivery by value (§5.1);
  - a response mode other than `direct_post.jwt` (§5.1);
- **through the DC API:**
  - a response mode other than `dc_api.jwt` (§5.2);
  - a signed request with a prefix other than `x509_hash`;
- an `enc` list missing A128GCM or A256GCM (§5).

HAIP only **advises** one thing: sending no `redirect_uri` (§5.1, the
same-device flow).

---

## 3. Hand it to a wallet

Pane `pane_handoff`. All fields are read-only.

| Label | id | Shows |
|---|---|---|
| Authorization Request | `vpv_invocation`, `vpv_invocation_link` | The invocation URI, with an **Open it on this device** link. Under the DC API it is the request object passed to the browser instead. `vpv_same_device_note` warns when no `redirect_uri` is configured, which a same-device flow needs. |
| For a wallet on another device | `vpv_qr`, `vpv_qr_note` | A QR code. If the request is too long for one, the page says so; use delivery by reference instead. The note also warns when the `request_uri` / `response_uri` host is loopback or a single-label name, which another device usually cannot reach. |
| What a wallet must trust | `vpv_trust_out` | For the current prefix: the root CA, the attester's JWKS, the DID, or the pre-registered JWKS. |
| client_id | `vpv_client_id` | |
| request_uri | `vpv_request_uri` | Empty for a request by value, or one through the DC API. |
| response_uri | `vpv_response_uri` | Empty for the DC API. |
| Request Object (decoded) | `vpv_request_object` | The header and payload. Marked when it was signed live for a `wallet_nonce`. For `redirect_uri` it shows the unsigned parameters. |
| The Verifier's root certificate | `vpv_root_pem` | Give it to a wallet that does not follow Authority Information Access. |

---

## 4. What the wallet sent, and every check on it

Pane `pane_response`.

| Element | id | Does |
|---|---|---|
| Waiting status | `vpv_wait_status` | Shows "Waiting for the wallet …" while the page polls the api, every 2 s, or every 0.5 s under live signing. |
| Events | `vpv_events` | One line per event the api recorded (see below). |
| Paste an answer | `vpv_pasted` | A form body (`vp_token=…&state=…`, or `response=eyJ…`) or its JSON. Works without the api, but needs a request created on this page: the nonce, `state` and `client_id` an answer is held to are this page's. |
| Check this answer | `btn_vpv_check` | Runs every check on the pasted answer. |
| Verdict | `vpv_verdict`, `vpv_profile_verdict` | See below. |
| Checks | `vpv_checks` | One row per check. |
| Disclosed claims | `vpv_claims_out` | The claims each presentation disclosed, as JSON. |

### The event list

The api records five kinds of event:

- `request-fetched`: the wallet fetched the Request Object, by GET or POST,
  with its `wallet_nonce` and `wallet_metadata`.
- `request-signed`: a live signature was made for that wallet, or the wallet
  was answered with an HTTP error (503, for example), with the reason.
  Findings from honouring `wallet_metadata` follow as `wallet_metadata:` lines.
- `ca-fetched`: the wallet fetched the root certificate from the AIA URL.
- `response`: the wallet posted its answer, with its content type and field
  names, and any `redirect_uri` / `response_code` returned to it.
- `response-refused`: the api refused a POST to `response_uri`.

### The verdict

`vpv_verdict` gives one of three results:

- **pass**: every check passed.
- **fail**: N of M checks failed.
- **incomplete**: nothing failed, but an *essential* check could not be
  performed, so the presentation is **not** verified. The essential checks are
  those that establish authenticity: an issuer signature or proof, the trust
  in an `x5c` chain, and a holder or device signature the query depends on.

Under the HAIP profile, `vpv_profile_verdict` says separately whether the
answer conforms to every HAIP rule checked. HAIP rows never change the
validity verdict.

### The check rows

Each row in `vpv_checks` has four columns:

- **status**: PASS, FAIL or SKIP;
- **group**: `response`, `status`, or `<query id>[<n>] <format>` for each
  presentation;
- **label**;
- **detail**.

A SKIP of an essential check is marked as not performed. The labels below are
those in `client/src/vp_verifier.js`; some rows appear only when they apply.

**The answer as a whole** (group `response`)

- The answer was posted as a form. The response mode is held to §8.2.
- For an encrypted answer:
  - The encrypted answer opens with this Verifier's key.
  - The JWE names the key it was encrypted to (`kid`).
  - The JWE `alg` is the key's `alg`.
  - The JWE `enc` is one the request offered.
  - The JWE marks no extension critical that this Verifier does not
    understand.
  - A row on `zip`.
- The Wallet answered with a presentation, or an `error`.
- `state` is this request's.
- The audience is this page's origin (DC API only).
- `vp_token` answers the query, keyed by credential query id (§8.1). Each
  query is answered as DCQL requires.
- Transaction *n* is authorized by exactly one presentation. A transaction no
  presentation binds is reported, not failed.
- The self-issued ID Token verifies, when there is one.

**Each `dc+sd-jwt` presentation**

- The presentation is an SD-JWT.
- The issuer JWT's `typ` is `dc+sd-jwt`.
- The credential's issuer signature verifies, through `x5c`, issuer metadata
  or a DID. The issuer's `x5c` is trusted, its signing certificate is not
  self-signed, and its `x5c` does not carry its own trust anchor.
- `vct` is one the query asks for.
- Every Disclosure's digest is in an `_sd` array.
- The credential is within its validity window.
- Every requested claim is disclosed.
- A Key Binding JWT is present.
- The KB-JWT's `typ` is `kb+jwt` and it is signed.
- The KB-JWT verifies with the credential's `cnf` key.
- The KB-JWT's nonce is this request's.
- The KB-JWT's `aud` is this Verifier's Client Identifier.
- The KB-JWT is fresh.
- `sd_hash` covers exactly what was presented.

**Each `jwt_vc_json` presentation**

- The VP JWT verifies with the holder's key.
- The VP is signed by the key the credential is bound to.
- The VP JWT's nonce is this request's.
- The VP JWT's `aud` is this Verifier's Client Identifier.
- The VP JWT is fresh.
- The VP JWT is within its `exp` and `nbf`.
- The credential's issuer signature verifies, and the credential is within
  its validity window.
- Every requested claim is disclosed.

**Each `mso_mdoc` presentation**

- The presentation is an mdoc DeviceResponse.
- `issuerSigned` verifies.
- The document signer certificate is trusted (against the issuer anchors).
- The MSO docType matches.
- The device signature covers this request (the session transcript).
- `docType` is the one the query asks for.
- One row per further mdoc check.

**Each `ldp_vc` presentation**

- The presentation is an `ldp_vc`.
- The credential's issuer proof verifies. The cryptosuites are `bbs-2023`,
  `ecdsa-rdfc-2019`, `ecdsa-jcs-2019`, `eddsa-rdfc-2022` and `eddsa-jcs-2022`;
  any other is a SKIP. See [data-integrity.md](../data-integrity.md).
- The VP's holder proof verifies.
- The VP proof's challenge is this request's nonce.
- The VP proof's domain is this Verifier's Client Identifier.
- The holder is the credential's subject.

**Credential status** (group `status`, "Credential status (revocation)")

The IETF **Token Status List** (*draft-ietf-oauth-status-list-21, a draft*),
in its JWT and CWT forms:

- The Status List Token verifies.
- Its signer is the credential's issuer, or is authorised by it.
- The status entry is well formed.
- The status value itself.

The W3C **Bitstring Status List**:

- The status list credential verifies (for each purpose).

A status list behind a COSE_Mac0 is a SKIP that says so.

**HAIP 1.0 rows** (HAIP profile only)

- The format is `dc+sd-jwt` or `mso_mdoc`.
- The issuer's signing certificate is in `x5c`.
- A KB-JWT is present for a holder-bound query.
- The status claim carries a status list.
- One mdoc per DeviceResponse.

**Fallbacks**

- The format is one this Verifier reads. This fails for any format outside
  the four above.
- The presentation could be checked. This fails when checking threw.

---

## What is stored, and what is not

| Kept in `localStorage` | Never stored (this page load only) |
|---|---|
| Every setting in panes 1 and 2 (the `VERIFIER_KEYS` ids above, including the trust anchors, which are public certificates). The Verifier's identity (`vpv_identity`) while *Keep this identity* is ticked. | The response decryption key. Each request's leaf key. The api session's `secret` (the bearer the page uses for `PUT`, `GET …/events` and `DELETE`). A pasted identity file. A pasted answer. |

The api keeps a session for at most `oid4vpVerifierTtlMs` (30 minutes), or
`oid4vpVerifierIdleTtlMs` (10 minutes) with nothing happening, with the
defaults in `api/env/local.js`. Its other limits are listed in
[vc-verifier-api.md](../vc-verifier-api.md#settings-apienvjs).

[oid4vp]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
