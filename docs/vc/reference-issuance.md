# VC Issuance — configuration reference

This page lists every pane, field and button on the five pages of the VC
Issuance workflow: `vc-issuance-0.html` through `vc-issuance-4.html`. In this
workflow the debugger is the **wallet**. It discovers an OpenID4VCI Credential
Issuer, gets an access token from that issuer's authorization server, proves
possession of a holder key and receives the credential. Then it shows,
verifies, refreshes and keeps the credential.

For every control the reference gives:

- the element id
- what the control does
- which specification defines it
- its default, and where that default comes from
- whether it is stored and where, or whether it is never stored

Read the [tutorials](index.md#tutorials) for the order to use these controls in. Read
the developer notes in [`../sd-jwt-vc-issuance.md`](../sd-jwt-vc-issuance.md)
for why the workflow behaves as it does.

Unless a row says otherwise, **"Stored"** means `localStorage`, under a key
of the same name as the id. Values come from the Credential Issuer you point
the workflow at. The "Default" column gives only the placeholder that is
shown before any metadata has been retrieved.

- [The step bar (every page)](#the-step-bar-every-page)
- [Step 0 — Choose a use case](#step-0--choose-a-use-case-vc-issuance-0html)
- [Step 1 — Discover the issuer](#step-1--discover-the-issuer-vc-issuance-1html)
- [The OIDC leg](#the-oidc-leg)
- [Step 2 — Approve and request the credential](#step-2--approve-and-request-the-credential-vc-issuance-2html)
- [Step 3 — The issued credential](#step-3--the-issued-credential-vc-issuance-3html)
- [Step 4 — Refresh the credential](#step-4--refresh-the-credential-vc-issuance-4html)
- [What is stored, and what never is](#what-is-stored-and-what-never-is)

## The step bar (every page)

Each page includes the same row of five links at the top
(`partials/vc_steps.html`, `ol#vc_steps`). The links are:

| id | Caption |
|---|---|
| `vc_step_0` | 0. Choose a use case — how the issuance starts |
| `vc_step_1` | 1. Discover the issuer — issuer and authorization server metadata |
| `vc_step_2` | 2. Authorize & approve — authenticate, review tokens, request it |
| `vc_step_3` | 3. The credential — the issued credential and its disclosures |
| `vc_step_4` | 4. Refresh it — Refresh Token, then the issuer again |

The page you are on is highlighted. After the list, a badge names the
use case chosen on step 0. Pages 1 to 4 also have a **Collapse all panes**
checkbox (`dbg_toggle_all`), which opens or closes every pane at once.

## Step 0 — Choose a use case (`vc-issuance-0.html`)

This page chooses which of the use cases in OpenID4VCI 1.0 Appendix H the
workflow runs.

| Field | id | What it is | Default | Stored |
|---|---|---|---|---|
| Issuer website URL | `vc_issuer_site_url` | The page on the issuer's own website where a person asks for a credential. OpenID4VCI does not name such a page, so this field takes a full URL. Only the http and https schemes are followed. | The deployment's `oid4vciIssuerSiteUrlDefault`, which is empty on the static sites. | `sdjwtvc_issuer_site_url`, when **Save** (`vc_issuer_site_save`) is pressed. An empty value removes the key. |
| Use-case cards | inside `vc_usecases` | Four buttons, generated from the use-case list in `sd_jwt_vc.js`. Choosing a card records it and discards any earlier Credential Offer. | Wallet-initiated | `sdjwtvc_use_case` |
| Status line | `vc_usecase_status` | Names the use case that is selected now. | — | — |

| Card | Appendix | Where it sends you |
|---|---|---|
| Start from the wallet | H.6, wallet-initiated | Step 1. You give an issuer metadata URL, and the flow is Authorization Code with PKCE. |
| The issuer offers you a credential | H.1, same-device Credential Offer | The issuer website above. The issuer sends you back to step 1 with `credential_offer` or `credential_offer_uri`. |
| Scan a code, type a transaction code | H.2, cross-device, pre-authorized code with `tx_code` | The issuer website. Bring its offer, or its QR code, to step 1. |
| The credential is not ready yet | H.3, deferred | The issuer website. The Credential Endpoint answers with a `transaction_id`. |

If you choose an offer card while the issuer website field is empty, the page
says so and opens step 1 after a short delay. You can paste the offer there
instead.

The page ends with the shared **VC Tools** row, which links to DID Tools, VC
Barcodes, Gordian Envelope and ACDC. See the
[tools reference](reference-tools.md).

## Step 1 — Discover the issuer (`vc-issuance-1.html`)

The panes are listed in page order. Several of them retrieve a document, and
those panes all have the same four buttons. **Retrieve** fetches the URL from
the browser. **Upload** loads a file you saved yourself, for example with
`curl`, which you need when the server sends no CORS headers. **Clear**
forgets the document and the values it filled in, on screen and in storage.
**Validate Signature** or **Verify** checks the document.

### Credential Offer (`pane_offer`)

This pane is shown only when an offer is present. An offer arrives in one of
two ways: in the URL, as `?credential_offer=<JSON>` (by value) or
`?credential_offer_uri=<URL>` (by reference), or through the Receive pane
below. OpenID4VCI 1.0 section 4 defines the offer.

| Shown | Meaning |
|---|---|
| Offered by | The `credential_issuer` named in the offer. The panes below are filled in from it. |
| Credential offered | `credential_configuration_ids` from the offer |
| Grant | The offer's `grants`: either `authorization_code`, with its `issuer_state`, or `urn:ietf:params:oauth:grant-type:pre-authorized_code`, with its `tx_code` description |
| How it arrived | By value or by reference |
| The offer | The offer object, verbatim |

**Discard this offer** (`offer_discard_button`) forgets the offer and carries
on as a wallet-initiated issuance. The offer is stored as
`sdjwtvc_credential_offer`.

### Credential Issuer Metadata (`pane_vci`)

This pane retrieves the issuer metadata defined in OpenID4VCI 1.0 section 12.2.

| Field | id | What it is | Default | Stored |
|---|---|---|---|---|
| Credential Issuer Metadata URL | `vci_metadata_endpoint` | The issuer's `/.well-known/openid-credential-issuer` URL | `oid4vciIssuerUrlDefault` plus that path. This is `https://localhost:8081/...` on a local build and empty on the static sites. | `vci_metadata_endpoint` |
| Retrieve / Upload / Clear | `vci_retrieve_button`, `vci_upload_button` (file input `vci_metadata_file`), `vci_clear_button` | See above | — | The document is kept as `vci_info`, with its provenance in `vci_info_source`. |
| Validate Signature | `vci_validate_signed_metadata_button` | Verifies the `signed_metadata` JWT in the browser. The keys come from `/.well-known/jwt-vc-issuer` or from a `jwks_uri` in the document. The check compares `iss` with `credential_issuer` and reports any signed member that disagrees with the plain JSON. | — | — |

Below the buttons the pane shows the document as a table
(`vci_metadata_table`), a **Populate Meta Data** control
(`vci_metadata_populate`) that applies the document again, and a schema
report (`vci_schema_report`).

### Issuer DID Document (`pane_did`)

This pane resolves the issuer's DID, as described in W3C DID Core 1.0.
Background is in [`../dids.md`](../dids.md).

| Field | id | What it is | Default | Stored |
|---|---|---|---|---|
| Issuer DID | `did_identifier` | The DID to resolve. It is filled in from a credential's `iss` or `issuer` when that value is a DID. | empty | `did_identifier` |
| Resolve | `did_resolve_button` | `did:jwk` and `did:key` are decoded locally. `did:web` is fetched from the URL the method derives. | — | — |
| Upload / Clear | `did_upload_button` (`did_document_file`), `did_clear_button` | Loads a document from a file, or forgets it | — | — |
| Document URL | `did_resolution_url` | Where a `did:web` document is fetched from. Resolve fills it in as `https://<host>/.well-known/did.json`, or `/<path>/did.json` when the DID has path segments. You can edit it. | empty | `did_resolution_url` |
| Retrieve | `did_retrieve_button` | Fetches from the URL above rather than from the derived one. A document whose `id` is a different DID is reported, not refused. | — | — |
| Verify Issuer Key | `did_verify_button` | Checks that a key in the document verifies the credential you hold | — | — |
| Verify Linkage | `did_linkage_button` | Fetches `/.well-known/did-configuration.json` from the issuer's origin and verifies the Domain Linkage Credential (DIF Well Known DID Configuration). For `did:web`, this is the only check that is not circular. | — | — |

### Authorization Server Metadata (`pane_as`)

This pane retrieves the authorization server's RFC 8414 metadata.

| Field | id | What it is | Default | Stored |
|---|---|---|---|---|
| Metadata Endpoint URL | `oidc_discovery_endpoint` | The RFC 8414 metadata URL of the authorization server that protects the issuer | Taken from `authorization_servers` in the issuer metadata once that is retrieved. Before then, the deployment's default. | `oidc_discovery_endpoint`, a key shared with `oauth2_oidc_1.html` |
| Retrieve / Upload / Clear | `as_retrieve_button`, `as_upload_button` (`as_metadata_file`), `as_clear_button` | Clear also empties the values the debugger pages share | — | — |
| Validate Signature | `as_validate_signed_metadata_button` | Verifies `signed_metadata` against the server's own `jwks_uri` | — | — |

### DID Configuration (`pane_didcfg`)

This pane loads the DIF Well Known DID Configuration resource.

| Field | id | What it is | Default | Stored |
|---|---|---|---|---|
| DID Configuration URL | `didcfg_url` | `/.well-known/did-configuration.json` at the origin root | Filled in from the issuer's origin once the issuer metadata is retrieved | `didcfg_url`. The document is kept as `didcfg_info`. |
| Retrieve / Upload / Clear | `didcfg_retrieve_button`, `didcfg_upload_button` (`didcfg_file`), `didcfg_clear_button` | — | — | — |
| Verify Linkage | `didcfg_verify_button` | Resolves the linked DID, verifies the credential's signature against the keys that DID authorises, and checks that the origin it names is the origin it was fetched from. The linkage result is not kept across a reload. | — | — |

### Receive a Credential Offer (`pane_scan`)

This pane takes an offer that did not arrive in the URL.

| Field | id | What it is |
|---|---|---|
| Scanned offer | `scan_offer_input` | What the QR code encodes: an `openid-credential-offer://` URI or a link that carries an offer. You can also paste an image straight into this box. |
| Or its QR code | `scan_offer_image` | An image of the QR code, such as a screenshot, a photo or an SVG. It is decoded in the page, and the result goes into the box above. |
| Take this offer | `scan_offer_button` | Reads the offer, then discovers the issuer and the authorization server it names |

Nothing typed here is stored. The offer, once taken, is stored as
`sdjwtvc_credential_offer`.

### Configuration Parameters (`pane_config`)

The rows of this pane are generated into `config_rows`, in groups. Every
field has the class `stored`. **Save** (`config_save_button`) writes every
field. **Clear All** (`config_clear_button`) empties every field and writes
`""` rather than removing the key, so the placeholder does not come back.
**Restore Defaults** (`config_defaults_button`) puts the placeholders back and
saves them.

**OAuth 2.0 client.** These fields are shared with `oauth2_oidc_1.html`,
under the same ids and keys.

| Field | id | Default | Notes |
|---|---|---|---|
| client_id | `client_id` | `oidc-authorization-code-public` | The wallet's OAuth client. Save also writes the value to `token_client_id`. |
| redirect_uri | `redirect_uri` | This deployment's `/callback` | The debugger pages accept only a URI on their own origin. |
| scope | `scope` | `openid profile email` | When the AS metadata is retrieved, the scopes the server advertises are kept. The chosen configuration's `scope` is appended if the server advertises it. Save also writes the value to `token_scope`. |

**Authorization server endpoints.** These are taken from RFC 8414 or OpenID
Connect Discovery 1.0: `authorization_endpoint`, `token_endpoint`,
`oidc_userinfo_endpoint` (from `userinfo_endpoint`), `jwks_endpoint` (from
`jwks_uri`), `registration_endpoint`, `introspection_endpoint`,
`revocation_endpoint` and `device_authorization_endpoint`. All of them are
empty until the metadata is retrieved. Only the authorization and token
endpoints are used by issuance.

**Authorization server metadata.** These rows hold every other RFC 8414 /
Discovery member, under the member's own name. The workflow uses
`token_endpoint_auth_methods_supported`, `authorization_details_types_supported`,
`dpop_signing_alg_values_supported` and `issuer` later on. A member the
server does not publish is marked *not defined* rather than left blank.

**Credential issuer metadata.** These rows are defined in OpenID4VCI 1.0
section 12.2.4. They are stored under `vci_<member>`.

| Member | Default placeholder |
|---|---|
| `credential_issuer` (REQUIRED) | `http://localhost:8081` |
| `credential_endpoint` (REQUIRED) | `http://localhost:8081/oid4vci/credential` |
| `authorization_servers` | `http://localhost:8080/realms/debugger-testing` |
| `nonce_endpoint` | `http://localhost:8081/oid4vci/nonce` |
| `notification_endpoint` | `http://localhost:8081/oid4vci/notification` |
| `deferred_credential_endpoint`, `batch_credential_issuance`, `credential_response_encryption`, `credential_request_encryption`, `display`, `signed_metadata` | empty |

These placeholders are local-development values. Retrieving any issuer's
metadata replaces all of them.

**Issuer DID document.**

| Field | id | What it is | Default | Stored |
|---|---|---|---|---|
| Use DIDs for this credential | `did_enabled` | Whether the issuer's verification key is taken from its DID document rather than from the issuer URL | On for `ldp_vc`, which VC Data Model 2.0 makes DID-native. Off for every other format, because SD-JWT VC defines no DID-based issuer key, so using one there is a profile extension. | `did_enabled`, as `"1"` or `"0"` |
| DID document members | `did_<member>` | Members of the resolved document | empty | `did_<member>` |

**DID Configuration.** These rows hold the members of the resolved resource.

**Credential configuration.** These rows describe the chosen entry of
`credential_configurations_supported`, from OpenID4VCI 1.0 Appendix A.

| Field | id | What it is | Default |
|---|---|---|---|
| Credential to request | `vci_credential_configuration_select` | Which entry to request. Choosing an entry rewrites every row below from the metadata. The list is empty until the issuer metadata is retrieved. | — |
| credential_configuration_id | `vci_credential_configuration_id` | What the Credential Request names | `IdentityCredential` |
| format | `vci_format` | The credential format identifier. The field suggests every format the debugger knows: `dc+sd-jwt`, `jwt_vc_json`, `jwt_vc_json-ld`, `ldp_vc`, `vc+jwt`, `vc+sd-jwt`, `vc+cose`, `jpt`, `sd-cwt`, `anoncreds` and `mso_mdoc`. | `dc+sd-jwt` |
| credential_definition | `vci_credential_definition` | Required for the W3C formats | empty |
| vct | `vci_vct` | Required for `dc+sd-jwt` | `urn:idptools:sd-jwt-vc:identity` |
| scope | `vci_scope` | The OAuth scope that asks for this credential | `identity_credential` |
| cryptographic_binding_methods_supported | `vci_cryptographic_binding_methods_supported` | `jwk`, `did:jwk`, `did:key` or `cose_key` | **Depends on the format** (see below) |
| credential_signing_alg_values_supported | `vci_credential_signing_alg_values_supported` | The format's own algorithm identifiers. The field suggests the ones the chosen format defines. | **Depends on the format** |
| proof_signing_alg_values_supported | `vci_proof_signing_alg_values_supported` | From `proof_types_supported.jwt`: the algorithms the issuer accepts on the wallet's key proof | `ES256` |

The two rows marked as format-dependent take their placeholders from
`client/src/vc_formats.js` (`metadataDefaults()`). When you change `format`,
any of these fields that still holds the old format's default, or nothing,
takes the new format's default. A value you typed yourself is left alone.

| format | binding default | signing default |
|---|---|---|
| `dc+sd-jwt`, `jwt_vc_json`, `jwt_vc_json-ld`, `vc+jwt`, `vc+sd-jwt` | `jwk` | `ES256` |
| `ldp_vc` | `did:jwk` | `eddsa-rdfc-2022, ecdsa-rdfc-2019` |
| `vc+cose` | `jwk` | `-7` (COSE ES256) |
| `mso_mdoc` | `cose_key` | `-7` |
| `sd-cwt` (draft-ietf-spice-sd-cwt-09, DRAFT) | `cose_key` | `-9` |
| `jpt` (draft-ietf-jose-json-proof-token-15, DRAFT) | `jwk` | `SU-ES256` |
| `anoncreds` | `link_secret` | `CL` |

### Client Authentication (token endpoint) (`pane_client_auth`)

This pane says how the wallet authenticates to the token endpoint. The same
method is used for every token call the workflow makes: the code exchange,
the pre-authorized grant and the refresh. Details are in
[`../vc-client-auth.md`](../vc-client-auth.md).

| Field | id | What it is | Spec | Default | Stored |
|---|---|---|---|---|---|
| Client authentication | `vc_client_auth_method` | `none`, `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, `private_key_jwt` or `attest_jwt_client_auth`. The server's `token_endpoint_auth_methods_supported` is shown beside the choice, for information only. | RFC 6749 §2.3, RFC 7523, draft-ietf-oauth-rfc7523bis-11, draft-ietf-oauth-attestation-based-client-auth-12 (**drafts**) | `none` (a public client). A credentialed method is never chosen for you. | `sdjwtvc_client_auth_method` |
| Client secret | `vc_client_secret` | For the three secret methods | RFC 6749 | empty | **Never stored.** Type it again on step 2 and step 4. |
| Assertion alg | `vc_client_auth_alg` | Empty means HS256 for `client_secret_jwt`, and the key's own algorithm for `private_key_jwt`. Choices are HS256/384/512, ES256/384/512, ES256K, EdDSA, PS256 and RS256. | RFC 7523 | empty | `sdjwtvc_client_auth_alg` |
| Assertion aud | `vc_client_auth_audience` | Either the issuer identifier (rfc7523bis-11) or the token endpoint URL (RFC 7523) | | `issuer` | `sdjwtvc_client_auth_audience` |
| Explicit typ | `vc_client_auth_typed` | Puts `typ: client-authentication+jwt` on the assertion | rfc7523bis-11 | on | `sdjwtvc_client_auth_typed` |
| kid | `vc_client_auth_kid` | The assertion header's `kid` | | empty | `sdjwtvc_client_auth_kid` |
| Client private key / Generate | `vc_client_private_jwk`, `vc_client_key_generate` | The `private_key_jwt` key. Generate makes one. | | — | `sdjwtvc_client_private_jwk`, **key material** |
| Public JWKS | `vc_client_public_jwks` | Read-only. Register this JWKS with the authorization server. | | — | — |
| Client Attestation / Make one | `vc_client_attestation`, `vc_client_attestation_make` | A Client Attestation JWT, either from the wallet provider or made here by a local attester | attestation-based-client-auth-12 (**DRAFT**) | — | `sdjwtvc_client_attestation`, **key material** |
| Instance private key | `vc_client_instance_jwk` | The key the attestation's `cnf` names. It signs the PoP. | | — | `sdjwtvc_client_instance_private_jwk`, **key material** |
| Attester JWKS | `vc_client_attester_jwks` | Read-only, and present only when the attestation was made here. The server must be told to trust this key. | | — | The attester's private key is `sdjwtvc_client_attester_private_jwk`, **key material**. |
| Keep the client keys in this browser | `vc_save_client_key` | Clearing this box deletes the four key-material entries at once | | on | `sdjwtvc_save_client_key` |

### Claims to Request (`pane_claims`)

This pane chooses which claims to ask for, using the `claims` member of an
`openid_credential` `authorization_details` entry (OpenID4VCI 1.0 section
5.1.1 and Appendix A).

- **Credential** (`vc_claims_credential`) is the configuration chosen above.
- The table (`vc_claims_table`) has one checkbox per claim the issuer
  advertises. Every box is checked by default. A claim the issuer marks
  `mandatory` can still be unchecked, and the row says the issuer will
  include it anyway.
- **Select All** (`vc_claims_all_button`) and **Select None**
  (`vc_claims_none_button`) change every box.
- **Ask with authorization_details** (`vc_claims_use_details_button`)
  switches the hand-off below to `authorization_details`.
- The selection is stored as `sdjwtvc_requested_claims`.
- A claims selection is sent only when it is a **strict subset** of what the
  issuer advertises. It goes on the authorization request when the mechanism
  is `authorization_details`, or on the step 2 Token Request for a
  pre-authorized offer.
- A `scope` request cannot carry a claims selection.

### Authorize Issuance (OIDC Authorization Code Flow) (`pane_handoff`)

| Field | id | What it is | Default | Stored |
|---|---|---|---|---|
| Hand-off URL | — | `/oauth2_oidc_1.html?sdjwtvc=1` | — | — |
| Authorization Endpoint | — | The value from Configuration Parameters | — | — |
| Ask for the credential with | `handoff_request_mechanism` | `scope`, or `authorization_details` (RFC 9396), as described in OpenID4VCI 1.0 section 5.1. With `authorization_details`, the token response grants `credential_identifiers`, and step 2 must name one of them. | `scope`. When nothing is stored and the credential advertises claims, the page may default to `authorization_details`, and the note under the select (`handoff_mechanism_note`) says when it has. | `sdjwtvc_request_mechanism`. The details sent are stored in `sdjwtvc_authorization_details`. |
| Credential requested | — | The configuration step 2 will ask for | — | — |
| Start Issuance | `start_issuance_button` | Saves the configuration and continues. For a **pre-authorized** offer it goes straight to step 2; this needs `token_endpoint` and `credential_endpoint`. Otherwise it opens the Authorization Code flow; this also needs `authorization_endpoint` and `client_id`. The flow sends the offer's `issuer_state` back if there is one (`sdjwtvc_issuer_state`). | — | — |

## The OIDC leg

When the flow is not pre-authorized, **Start Issuance** opens
`oauth2_oidc_1.html?sdjwtvc=1` with the grant set to
`oidc_authorization_code_flow`. The user signs in at the authorization
server, and `oauth2_oidc_2.html` exchanges the code for tokens using the
client authentication chosen on step 1. Then it returns to step 2. Those two
pages are documented in [the OAuth2 / OIDC guide](../oauth2-oidc/index.md).

If DPoP was enabled before this hand-off, the authorization request carries
`dpop_jkt`, as described in RFC 9449 section 10.

## Step 2 — Approve and request the credential (`vc-issuance-2.html`)

### Client Authentication (`pane_client_auth`)

This pane is shown only for a pre-authorized offer, because only then does
this page call the token endpoint. It shows the method chosen on step 1
(`vc_client_auth_method_shown`) and whichever fields that method needs:

- the secret (`vc_client_secret`), which is never stored
- the client private key, which you paste when the key was not kept
- the attestation and its instance key

### Token Request (pre-authorized code) (`pane_pre_authorized`)

This pane redeems a pre-authorized code, as defined in OpenID4VCI 1.0
section 6.1.

| Field | id | What it is | Stored |
|---|---|---|---|
| Pre-authorized code | `vc_pre_authorized_code` | Taken from the offer. It can be used once. | It is part of the stored offer. |
| Transaction Code | `vc_tx_code` | The `tx_code` the issuer showed you somewhere other than the offer. The hint (`vc_tx_code_hint`) gives the length and input mode the offer declares, and the field's maxlength is set to that length. If the offer requires a code and none is typed, nothing is sent. | **Not stored** |
| The call | `vc_token_request` | The request exactly as it will be sent. A secret is shown as `<client_secret>`. | — |
| Send the Token Request | `vc_token_request_button` | Redeems the code. Nothing is issued yet. | The tokens are stored as `token_access_token` and `token_refresh_token`. |

### Tokens from the OIDC Authorization Code Flow (`pane_tokens`)

This pane shows the **Access Token** (`vc_access_token`), **ID Token**
(`vc_id_token`), **Refresh Token** (`vc_refresh_token`) and the decoded ID
Token claims. All of them are read-only. They are the workflow's output and
are stored under the `token_*` keys the OAuth pages use.

### DPoP — Sender-Constrained Access Token (`pane_dpop`)

This pane controls DPoP, defined in RFC 9449. Background is in
[`../dpop.md`](../dpop.md).

| Field | id | What it is | Default | Stored |
|---|---|---|---|---|
| Sender-constrain the token | `vc_dpop_enabled` | Sends DPoP proofs, so that the token comes back as `token_type: DPoP` | **off** (Bearer) | `sdjwtvc_dpop_enabled` (`"1"` means on) |
| Credential key binding | `vc_dpop_holder_of_key` | Holder of Key: the DPoP key is also the credential's holder key. Unchecked, the credential has a holder key of its own. Holder of Key needs DPoP to be on. | off (`pop`) | `sdjwtvc_dpop_binding` |
| Proof algorithm | `vc_dpop_alg` | RS256/384/512, ES256/384/512, PS256/384/512, EdDSA (Ed25519 or Ed448) or ES256K | `ES256` | `sdjwtvc_dpop_alg` |
| New Key Pair | `vc_dpop_regenerate_button` | Makes a new DPoP key | — | The public key is `sdjwtvc_dpop_public_jwk`, the private key is `sdjwtvc_dpop_private_jwk` (**key material**, governed by the holder-key checkbox), and the thumbprint is `sdjwtvc_dpop_jkt`. |
| Server accepts | — | `dpop_signing_alg_values_supported`. If this is absent, the server has not said it supports DPoP. | — | — |
| jkt (RFC 7638) | — | The thumbprint, which the token's `cnf.jkt` should carry | — | — |
| Bind the authorization code | — | Whether `dpop_jkt` was sent on step 1's authorization request | — | — |
| Token binding | `vc_dpop_token_status` | What the server actually answered: `token_type` and `cnf.jkt` | — | `sdjwtvc_dpop_token_type`, `sdjwtvc_dpop_token_jkt` |
| Server-supplied nonce | — | A `DPoP-Nonce` the server sent with `use_dpop_nonce`. The page retries once, then reuses the nonce. | — | `sdjwtvc_dpop_nonce` |
| Proof sent | — | The last DPoP proof sent, decoded | — | — |

### OID4VCI Credential Request (`pane_request`)

This pane builds the Credential Request, defined in OpenID4VCI 1.0 section 8.

| Field | id | What it is | Default | Stored |
|---|---|---|---|---|
| Credential Endpoint / Credential Issuer / Credential requested | — | From step 1 | — | — |
| Holder public key | — | The holder key, as a JWK. Its algorithm is chosen by `vc_formats.holderKeyAlgFor()`: the first of ES256, EdDSA, Ed25519, ES384, ES256K, ES512, PS256 and RS256 that the issuer lists in `proof_signing_alg_values_supported`. An `mso_mdoc` key is always ES256. If the issuer lists nothing, ES256 is used. A stored key that does not fit is replaced. | Generated in the browser | `sdjwtvc_holder_jwk` |
| Regenerate Key | `vc_regenerate_key_button` | Makes a new holder key pair | — | — |
| Download Key Pair | `vc_download_key_button` | Saves the pair as a file. Step 4 and the presentation pages accept this file as pasted input. | — | — |
| Save this holder key pair in browser localStorage | `vc_save_holder_key` | Whether the **private** half may be written to `localStorage` | **on** | `sdjwtvc_save_holder_key`. Only an explicit `"0"` turns saving off. |
| c_nonce | `vc_nonce` | A fresh nonce from `nonce_endpoint` (section 7). The page says so when the issuer has no nonce endpoint. | — | — |
| Key proof (openid4vci-proof+jwt) | `vc_proof_jwt`, decoded in `jwt_header` and `jwt_payload` | The key proof from section 8.2 and Appendix F.1. It is signed by the holder key, has `aud` set to the credential issuer, and carries `iat` and the `c_nonce`. Only the `jwt` proof type is sent. This is not the DPoP proof. | — | — |
| Request body | `vc_request_body` | The JSON that will be POSTed | — | — |

### Credential Request Options (`pane_request_options`)

| Field | id | What it is | Default |
|---|---|---|---|
| Naming the credential | `vc_identifier_mode` | `credential_identifier` if the token response granted `credential_identifiers`, otherwise `credential_configuration_id`. The rule comes from section 8.2; it is not a choice. | — |
| Keys to bind | `vc_batch_size` | The number of proofs, which is also the number of credentials (section 8.3). It is capped at the issuer's `batch_credential_issuance.batch_size`, and the field is disabled when the issuer does not advertise one. | `1` |
| Encrypt the response | `vc_encrypt_response` | Asks for a JWE Credential Response (section 10). It is offered only when the issuer advertises `credential_response_encryption`. The `enc` is `A256GCM` when the issuer offers it, otherwise the issuer's first value. The wallet implements RSA-OAEP-256. | off |
| Encrypt the request | `vc_encrypt_request` | Encrypts the request to a key in the issuer's `credential_request_encryption.jwks` and sends it as `application/jwt`. When the issuer requires request encryption, the box is checked and locked. | off |

None of these options are stored. The issuer's advertised values are kept
under `vci_batch_credential_issuance`, `vci_credential_response_encryption`
and `vci_credential_request_encryption`.

### Approve Issuance (`pane_approval`)

**The call this will make** (`vc_approval_request`) shows the full request.
**Approve and Request Credential** (`vc_approve_button`) sends it. If the
`c_nonce` has gone stale, the page rebuilds the request and retries once.
When the credential arrives, step 3 opens. **Deny** (`vc_deny_button`) sends
nothing.

### Deferred Issuance (`pane_deferred`)

This pane is shown when the Credential Response is a `transaction_id`
(section 9).

| Field | id | What it is |
|---|---|---|
| Transaction | `vc_transaction_id` | The `transaction_id` |
| Endpoint | — | `deferred_credential_endpoint` from the issuer metadata |
| The call | `vc_deferred_request` | The Deferred Credential Request |
| Attempts | — | Every poll and what came back |
| Check again now | `vc_deferred_poll_button` | Polls immediately. The page also polls on its own at the `interval` the issuer asks for (5 seconds if it gives none), and opens step 3 when the credential is ready. |

## Step 3 — The issued credential (`vc-issuance-3.html`)

### The Credential (`pane_credential`)

This pane shows **Issued by**, **Requested** and the credential's serialized
form (`vc_serialized`, and raw in `vc_credential_raw`). For a batch, a select
(`vc_credential_select`) picks one credential per proof. The buttons are:

| Button | id | What it does |
|---|---|---|
| Copy Credential | `vc_copy_button` | Copies the credential |
| Verify Again | `vc_verify_button` | Runs the checks again |
| Refresh this Credential | `vc_goto_refresh_button` | Opens step 4 |
| Start Over | `vc_restart_button` | Begins the workflow again |

The credential is stored as `sdjwtvc_credential`, and every credential of a
batch is in `sdjwtvc_credentials`. How it was obtained is stored in
`sdjwtvc_credential_meta`: the issuer, endpoint, configuration,
`notification_id` and request.

### Issuer-signed JWT, Disclosures, Resulting Claim Set (`pane_jwt`, `pane_disclosures`, `pane_claims`)

These panes show the Header, the Payload and a **Checks** list, followed by
one row per Disclosure and the claim set that results. The checks depend on
the format.

- **SD-JWT VC.** The checks are:
  - the media type (`typ`, `dc+sd-jwt` or the earlier `vc+sd-jwt`)
  - the signing algorithm, which must not be `none`
  - `vct`
  - the key binding: `cnf` must match the holder key
  - `_sd_alg`
  - the validity window
  - that no Key Binding JWT is attached
  - each Disclosure digest found in `_sd`
  - the issuer signature, using keys from `/.well-known/jwt-vc-issuer` or
    from the DID

  These checks come from RFC 9901 and SD-JWT VC.
- **`ldp_vc`.** The checks are the proof, the holder binding
  (`credentialSubject.id`), the validity window and the issuer proof. See
  [`../data-integrity.md`](../data-integrity.md).
- **VC-JOSE-COSE.** The checks are the format, the holder binding and the
  issuer signature. See [`../vc-jose-cose.md`](../vc-jose-cose.md).
- **JPT and SD-CWT** (both drafts). See [`../jwp-sd-cwt.md`](../jwp-sd-cwt.md).
- **AnonCreds.** See [`../anoncreds.md`](../anoncreds.md).

### Notify the Issuer (`pane_notification`)

This pane sends a notification, defined in OpenID4VCI 1.0 section 11.

| Field | id | What it is | Default |
|---|---|---|---|
| notification_id | `vc_notification_id` | From the Credential Response | — |
| Endpoint | — | `notification_endpoint` from the issuer metadata | — |
| Event | `vc_notification_event` | `credential_accepted`, `credential_failure` or `credential_deleted` | `credential_accepted` |
| event_description | `vc_notification_description` | Optional | empty |
| The call / Send the Notification | `vc_notification_request`, `vc_notification_button` | A successful notification is answered with 204. | — |

None of these fields are stored.

### Next: Refresh It, or Present It (`pane_next`)

**Refresh It (step 4)** (`vc_goto_step4_button`) opens step 4. **Present It**
(`vc_present_button`) opens the presentation workflow, which is documented in
the [presentation reference](reference-presentation.md).

## Step 4 — Refresh the credential (`vc-issuance-4.html`)

Refreshing follows OpenID4VCI 1.0 section 14.5: the wallet exchanges the
refresh token for a new access token, then makes the same Credential Request
again.

### The Credential You Hold (`pane_current`)

This pane shows the credential type (`vct`, or `type` for a W3C credential),
its validity against the current time, the key it is bound to (`cnf.jwk`, or
`credentialSubject.id` for a W3C credential), and how it was obtained.

### Credential History (`pane_history`)

The history is a log of **every attempt**, oldest first:

- issuance
- access-token refresh (`token_refresh`)
- Credential Request
- deferred poll (`deferred_poll`)

Each row has an outcome: `success`, `failed`, `deferred`, `pending`, `kept`
or `discarded`.

Rows that hold a credential also carry its public holder key and, while
saving is allowed, its **private** holder key, so that an older generation can
be made current again and still be presented. The navigation buttons are
**Oldest**, **Older**, **Newer** and **Latest**
(`vc_history_oldest_button`, `vc_history_older_button`,
`vc_history_newer_button`, `vc_history_latest_button`). Activating a
generation puts that credential and its key back in hand. **Clear History**
(`vc_history_clear_button`) empties the log.

The history is stored in three keys:

- `sdjwtvc_credential_history` holds the log, up to **100** rows. When the
  log is full, the oldest row that is not a held generation is dropped first.
- `sdjwtvc_credential_history_index` holds the generation in hand.
- `sdjwtvc_credential_history_dropped` counts how many held generations the
  log has had to forget.

**When "Save this holder key pair in browser localStorage" on step 2 is cleared**, the page removes every
stored holder private key:

- `sdjwtvc_holder_private_jwk`
- `sdjwtvc_refreshed_holder_private_jwk`
- `sdjwtvc_previous_holder_private_jwk`
- `sdjwtvc_dpop_private_jwk`

It also sets `holderPrivateJwk` to `null` on **every history row**. Those
generations can still be viewed, but they cannot be presented unless you
paste the key.

### Client Authentication (`pane_client_auth`)

This is the same call-mode pane as on step 2. RFC 6749 section 6 requires a
confidential client to authenticate a refresh.

### Refresh the Access Token (`pane_refresh`)

| Field | id | What it is | Default | Stored |
|---|---|---|---|---|
| Token Endpoint / Access token in hand | — | From step 1 and from the workflow | — | — |
| Refresh Token | `vc_refresh_token_value` | The refresh token. The authorization server does not have to issue one. | `token_refresh_token` | A rotated token replaces `token_refresh_token`. |
| scope | `vc_refresh_scope` | Optional. It can only narrow the scope (RFC 6749 §6). | empty, which keeps the scope originally granted | not stored |
| The call / Send the Refresh Request | `vc_refresh_request`, `vc_refresh_button` | The request is shown with the secret masked. DPoP proofs are used when DPoP is on. This page never generates a DPoP key. | — | — |

### Ask the Credential Endpoint Again (`pane_reissue`)

| Field | id | What it is | Default |
|---|---|---|---|
| Holder key | `vc_refresh_key_mode` | `reuse` keeps the key the current credential is bound to, which is what makes the new credential a replacement. `new` binds a new key. | `reuse` |
| Holder private key | `vc_holder_private_jwk` | Shown only when the bound key is not in storage, either because saving is off or because the credential was issued elsewhere. Accepts the Download Key Pair file or a bare private JWK. **Never stored.** If the pasted key's `x` and `y` match `cnf.jwk`, reuse is allowed. | — |
| c_nonce / Key proof / Request body / The call | `vc_reissue_proof`, `vc_reissue_request` | A fresh nonce, then the same request shape as step 2 | — |
| Request a Refreshed Credential | `vc_reissue_button` | Sends the request. Nothing you already hold is changed by this. | — |
| Deferred / Check for it now | `vc_reissue_deferred_button` | Shown for a 202 response with a `transaction_id`. On this page the deferred endpoint is polled only when you press the button. | — |

The refreshed result is stored separately, as `sdjwtvc_refreshed_credential`,
`sdjwtvc_refreshed_credentials` and `sdjwtvc_refreshed_credential_meta`. A
new key is stored as `sdjwtvc_refreshed_holder_jwk` and
`sdjwtvc_refreshed_holder_private_jwk`.

### What Changed (`pane_compare`)

This pane compares the credential you hold with the refreshed one, because
the issuer may have re-signed it or changed its claims. The buttons are:

| Button | id | What it does |
|---|---|---|
| Replace the credential I hold | `vc_replace_button` | Makes the refreshed credential current. The old one is kept as `sdjwtvc_previous_*`. |
| Discard the refreshed one | `vc_discard_button` | Throws the refreshed credential away |
| Copy Credential | `vc_compare_copy_button` | Copies the refreshed credential |
| Verify in step 3 | `vc_goto_step3_button` | Opens step 3 on the refreshed credential |

The raw refreshed credential is shown in `vc_compare_refreshed_raw`.

### Next: Present It (`pane_next`)

**Present It** (`vc_present_button`) opens the presentation workflow.

## What is stored, and what never is

| Class | Keys |
|---|---|
| **Never stored** | `vc_client_secret`; the transaction code (`vc_tx_code`); the pasted holder key (`vc_holder_private_jwk`). See `common/model/storage_classes.json` and `client/src/secret_storage.js`. |
| **Key material, kept while "Save this holder key pair in browser localStorage" (`sdjwtvc_save_holder_key`) is on** | `sdjwtvc_holder_private_jwk`, `sdjwtvc_refreshed_holder_private_jwk`, `sdjwtvc_previous_holder_private_jwk`, `sdjwtvc_dpop_private_jwk`, and the per-row `holderPrivateJwk` in the history. The gate is in `sd_jwt_vc.js` `set()`, so every writer is covered. |
| **Key material, kept while "Keep the client keys" (`sdjwtvc_save_client_key`) is on** | `sdjwtvc_client_private_jwk`, `sdjwtvc_client_attestation`, `sdjwtvc_client_instance_private_jwk`, `sdjwtvc_client_attester_private_jwk` |
| **Ordinary settings** | the use case, the issuer website, the metadata URLs, Configuration Parameters, the request mechanism, the claims selection, the DPoP and client-auth settings |
| **Output** | the credentials, their metadata and the history; the `token_*` tokens; the retrieved documents (`vci_info`, `didcfg_info`) |

All of it is `localStorage` in this browser. The storage model is
`models/storage/sd_jwt_vc.tsp`, `vc_issuance_1.tsp`, `vc_issuance_2.tsp`,
`vci_metadata.tsp` and `vc_client_auth_pane.tsp`.
