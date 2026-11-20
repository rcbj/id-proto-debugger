# Configuration reference: the VC Presentation workflow (the debugger as a wallet)

This page lists every pane, field, button and chooser on the four pages of the
presentation workflow, `vc-presentation-0.html` to `vc-presentation-3.html`.
On these pages the debugger is the **wallet**. A Verifier somewhere else asks
for claims over [OpenID4VP 1.0][oid4vp]. The wallet reads the request, you
choose what to disclose, and the wallet builds the presentation and sends it.

The credential presented is the one the
[issuance workflow](reference-issuance.md) left in this browser
(`sdjwtvc_credential`). To play the other end, the Verifier, see
[the Verifier page reference](reference-verifier.md).

For background, see the developer notes:
[sd-jwt-vc-presentation.md](../sd-jwt-vc-presentation.md) (formats, HAIP,
SIOPv2, mdoc),
[jwe-pq-kem.md](../jwe-pq-kem.md) (the encryption a `direct_post.jwt` answer
can use). A walk through the pages is
[tutorial-present-to-verifier.md](tutorial-present-to-verifier.md).

**The "Stored" columns.** "local" means `localStorage`. A value marked
**never stored** is held only for the current page load. Each key below is
declared, with its storage class, in `models/storage/sd_jwt_vp.tsp`,
`models/storage/vp_protocols.tsp`, `models/storage/sd_jwt_vc.tsp` and
`models/storage/jsonld_contexts.tsp`.

- [The step bar (all four pages)](#the-step-bar-all-four-pages)
- [Step 0 — `vc-presentation-0.html`](#step-0--vc-presentation-0html)
  - [Which side of the presentation is the debugger?](#which-side-of-the-presentation-is-the-debugger)
  - [Credential status line](#credential-status-line)
  - [Configuration Parameters](#configuration-parameters)
  - [Which protocol is the answer given under?](#which-protocol-is-the-answer-given-under)
  - [How does the request reach the wallet?](#how-does-the-request-reach-the-wallet)
- [Step 1 — `vc-presentation-1.html`](#step-1--vc-presentation-1html)
  - [What the protocol demands of this request](#what-the-protocol-demands-of-this-request)
  - [The Verifier's Authorization Request](#the-verifiers-authorization-request)
  - [What Is Being Asked For](#what-is-being-asked-for)
  - [Receive a Request (cross-device)](#receive-a-request-cross-device)
  - [What blocks Continue, and what only advises](#what-blocks-continue-and-what-only-advises)
- [Step 2 — `vc-presentation-2.html`](#step-2--vc-presentation-2html)
- [Step 3 — `vc-presentation-3.html`](#step-3--vc-presentation-3html)
- [What is stored, and what is not](#what-is-stored-and-what-is-not)

Steps 1 to 3 each have a **Collapse all panes** toggle (`dbg_toggle_all`)
at the top, and clicking a pane's title collapses or expands that pane. Every
page ends with the VC Tools pane, which links to the DID, VC Barcodes, Gordian
Envelope and ACDC pages (see [reference-tools.md](reference-tools.md)).

---

## The step bar (all four pages)

`client/public/partials/sd_jwt_vp_steps.html` draws one row of links,
`vp_steps`, at the top of every page:

| id | Caption |
|---|---|
| `vp_step_0` | 0. Choose a flow — how the verifier asks |
| `vp_step_1` | 1. The request — who is asking, and for what |
| `vp_step_2` | 2. Choose & present — select disclosures, sign the KB-JWT |
| `vp_step_3` | 3. The verdict — what the verifier saw and decided |

The current step is highlighted. Under the row, a badge
(`vp_use_case_badge`) names the flow and the protocol currently chosen.

---

## Step 0 — `vc-presentation-0.html`

### Which side of the presentation is the debugger?

Two cards, `vp_roles`:

| id | Card | Does |
|---|---|---|
| `vp_role_wallet` | **Wallet** — the holder answers a Verifier | This page and steps 1–3. Always selected here. |
| `vp_role_verifier` | **Verifier** — the debugger asks a wallet | Opens [`vc-verifier.html`](reference-verifier.md). |

### Credential status line

`vp_credential_state` describes what the wallet holds. It can say any of the
following:

- No credential is held yet. It links to the issuance workflow.
- The stored credential cannot be parsed.
- A credential is held, with its format and its number of
  selectively-disclosable claims. For `jwt_vc_json` it gives the number of
  claims and adds that none can be withheld.
- Whether the private half of the holder key is in this browser:
  - **held**: the credential can be presented;
  - **deliberately not kept**: you turned saving off on issuance step 2, and
    you will paste the key on step 2 here;
  - **missing**: no Key Binding JWT can be signed.

### Configuration Parameters

Pane `pane_config` (fieldset `config_fieldset`). An OpenID4VP Verifier
publishes no discovery document, so you enter all of these by hand.

| Field | id | What it is | Spec | Default | Stored |
|---|---|---|---|---|---|
| Verifier website URL | `vp_verifier_site_url` | The page on the Verifier's own site where a person starts a verification. All three flows below send you there. OpenID4VP does not name such a page, so this is a whole URL. If your Verifier has no such page, paste its request into step 1. | — | Empty. When empty, the deployment's `oid4vpVerifierSiteUrlDefault` is used (`client/src/env/*.js`; empty on the deployed sites). | local `sdjwtvp_verifier_site_url` |
| Verifier base URL | `vp_verifier_base_url` | The Verifier's origin. The JWKS URL below falls back to `<base>/oauth2/jwks`. | — | Empty. Falls back to `oid4vpVerifierUrlDefault`, and then to the origin of the credential issuer used for issuance. | local `sdjwtvp_verifier_base_url` |
| Verifier JWKS URL | `vp_verifier_jwks_url` | Where the wallet gets the Verifier's keys to check a signed request from a **pre-registered** client, which has no Client Identifier prefix. If it is empty and no base is known, a signed request is reported as unverifiable rather than trusted. | OpenID4VP 1.0 §5.9 (pre-registered); RFC 9101 | Empty. Falls back to `<base>/oauth2/jwks`. | local `sdjwtvp_verifier_jwks_url` |
| x509 trust anchor (PEM) | `vp_x509_trust_anchor` | The root certificate this wallet trusts for a Verifier named by `x509_hash` or `x509_san_dns`. The request's `x5c` chain is completed with this root. If it is empty, the chain is still checked link by link, and its top is reported as untrusted. | OpenID4VP 1.0 §5.9.3; HAIP 1.0 | Empty | local `sdjwtvp_x509_trust_anchor` (a public certificate) |
| Reach the Verifier through the debugger's api | `vp_via_api` | When ticked, every call to the Verifier goes through the api's `POST /oid4vp/call` instead of the browser. That covers fetching the Request Object, the POST under `request_uri_method=post`, the Verifier's JWKS, and the answer posted to `response_uri`. Use it for a Verifier that sends no CORS headers. An answer by `fragment`, `query` or `form_post` always travels through the browser. The box is disabled when no api answers, as on the static sites, and `vp_via_api_note` then says why. | — | Off | local `sdjwtvp_via_api` (`"1"`/`"0"`) |
| check the Verifier's TLS certificate on that route | `vp_api_ssl_validate` | Whether the api validates the Verifier's TLS certificate on that route. | — | On (off only when `"0"` is stored) | local `sdjwtvp_api_ssl_validate` |

Buttons:

| Button | id | Does |
|---|---|---|
| Save | `config_save_button` | Saves the pane. An empty field removes its key. Redraws the flow cards. |
| Clear All | `config_clear_button` | Removes every key in the pane. The page then falls back to the deployment's defaults. |
| Restore Defaults | `config_defaults_button` | Fills the site URL, the base URL and `<base>/oauth2/jwks` from the deployment's `oid4vpVerifierSiteUrlDefault` / `oid4vpVerifierUrlDefault`. Nothing is saved until you press Save. On a deployment that configures no default it says there is nothing to restore. |

`config_status` reports the result.

### Which protocol is the answer given under?

Three cards, `vp_protocols` (`vp_protocol_oid4vp`, `vp_protocol_haip`,
`vp_protocol_siopv2`), from `client/src/vp_protocols.js`.

| Card | response_type | What it changes |
|---|---|---|
| **OpenID4VP 1.0** (default) | `vp_token` | The wallet accepts any Client Identifier it can read, a request by value or by reference, and an answer in the clear (`direct_post`) or encrypted (`direct_post.jwt`). |
| **OpenID4VC HAIP 1.0** | `vp_token` | A profile, not a separate protocol. The request must be a signed Request Object fetched by `request_uri`, with an `x509_hash` Client Identifier and an encrypted answer (`direct_post.jwt`, ECDH-ES on P-256 only). Anything less is refused before a claim is shown. HAIP profiles `dc+sd-jwt` and `mso_mdoc`; any other format is presented over the HAIP transport and reported as a departure. Choosing HAIP while "request by value" is selected switches the flow to the signed request by reference. |
| **SIOPv2** | `id_token`, or `vp_token id_token` | The wallet signs a self-issued ID Token (`iss` equal to `sub`). Next to a presentation, the token is signed by the same key the credential is bound to. |

The choice is stored in `sdjwtvp_protocol` (local). Choosing a protocol
discards any request already read, because that request was checked against
another protocol's rules. `vp_protocol_status` restates the choice.

### How does the request reach the wallet?

Three cards, `vp_usecases` (`vp_usecase_<id>`), from `USE_CASES` in
`client/src/sd_jwt_vp.js`. Each one sends you to the Verifier website URL
above, where you choose the matching option on the Verifier's own page.
Choosing one also discards the previous request, whose nonce is spent.

| id | Card | Mechanics | Notes |
|---|---|---|---|
| `same-device` (default) | Same device — request by value | Request in the query → consent → `vp_token` POSTed to `response_uri` (`direct_post`) | Uses the `redirect_uri` prefix, so the request is unsigned. **Disabled under HAIP 1.0.** |
| `same-device-signed` | Same device — signed request by reference | `request_uri` → signed Request Object (RFC 9101) → verify → consent → `direct_post` | |
| `cross-device` | Cross device — QR code | QR code (`openid4vp://`) → the wallet reads the request → `direct_post` | On this page you paste what the QR code encodes into step 1. |

The choice is stored in `sdjwtvp_use_case` (local). If no Verifier website is
configured, choosing a card sends you to step 1 to paste a request.
`vp_usecase_status` names the current choice and the website it will use.

---

## Step 1 — `vc-presentation-1.html`

Nothing is disclosed on this page. The request arrives in one of three ways:

- in the query string, when a Verifier redirected the browser here;
- by `request_uri`, which the page fetches;
- pasted into the last pane.

A request read on an earlier visit is kept in `sdjwtvp_request` (local), so a
reload does not lose it.

### What the protocol demands of this request

Pane `pane_rules`. The title names the protocol chosen on step 0
(`vp_protocol_label`). The table `vp_protocol_rules` lists every rule with a
result:

- **OK**: the request meets the rule.
- **REFUSED**: a blocking rule failed. This is why Continue is disabled.
- **WARNING**: a rule failed but the request is still answered.

The rules themselves are listed [below](#what-blocks-continue-and-what-only-advises).

### The Verifier's Authorization Request

Pane `pane_request`. All fields are read-only. `vp_request_status` gives the
overall verdict.

| Label | id | What it shows | Spec |
|---|---|---|---|
| Where it came from | `vp_source` | By value in a redirect, fetched from a `request_uri` (signed or unsigned JSON), or pasted by hand, with the time it was received. | OpenID4VP 1.0 §5 |
| client_id | `vp_client_id` | The Client Identifier. It also becomes the `aud` of the Key Binding JWT. | §5.2 |
| Identifier prefix | `vp_client_prefix`, `vp_client_note` | The prefix and its value, with a note on what this wallet can conclude from them. The wallet implements no prefix, `redirect_uri`, `x509_hash` and `x509_san_dns`. Any other prefix is shown as it arrived, without being validated. | §5.9 |
| Signature | `vp_signature_verdict` | **No prefix:** checked against the Verifier JWKS URL. **`x509_*`:** checks `x5c`, `x509_hash` or `x509_san_dns`, the response host, the signature and the trust anchor, one line each. Otherwise: "not signed". | RFC 9101; §5.9.3 |
| nonce | `vp_nonce` | The request's nonce, which is signed into the holder proof. | §5.2 |
| response_type / mode | `vp_response_type`, `vp_response_mode` | If no mode is given, it is shown as `fragment` (the OAuth 2.0 default). | §5.2, §8 |
| response_uri | `vp_response_uri` | Where the answer goes. This is `redirect_uri` for the browser-carried modes. | §8.2 |
| state | `vp_state` | Echoed back with the answer. | |
| dcql_query | `vp_dcql` | The DCQL query. | §6 |
| client_metadata | `vp_client_metadata` | The Verifier's metadata: its formats, its encryption keys (`jwks`) and its `encrypted_response_enc_values_supported`. | §5.1 |
| As received | `vp_request_raw` | Every recognised parameter, exactly as received. | |

The parameters recognised are `client_id`, `response_type`, `response_mode`,
`response_uri`, `redirect_uri`, `nonce`, `state`, `dcql_query`,
`client_metadata`, `request_uri`, `request_uri_method`, `request`, `scope`,
`transaction_data` and `id_token_type`. This wallet **displays**
`transaction_data` but does not compute `transaction_data_hashes` for it.

**`request_uri_method=post`** (§5.10). The wallet POSTs `wallet_metadata`,
describing its own formats, prefixes, algorithms and response modes, together
with a fresh `wallet_nonce`. The signed Request Object must echo that nonce.

### What Is Being Asked For

Pane `pane_requested`, table `vp_requested_table`. There is one row per DCQL
credential query, with these columns:

- **Query id**;
- **Format**;
- **vct wanted**: `meta.vct_values`, or `meta.doctype_value` for an mdoc.
  Shown in red when it is not the type of the credential held;
- **Holder binding**: whether `require_cryptographic_holder_binding` is set
  (it defaults to true);
- **Claims asked for**: each claim path, green when the held credential can
  disclose it and red when it cannot.

A request with no `dcql_query` gets a row saying so.

### Receive a Request (cross-device)

Pane `pane_receive`.

| Field / button | id | Does |
|---|---|---|
| Request URI | `vp_paste_request` | What the Verifier's QR code encodes: an `openid4vp://` URI, an `https://` link with the same parameters, or a bare query string. Never stored as typed. |
| Read this Request | `vp_use_pasted_button` | Parses the text, fetches the Request Object if it is passed by reference, and fills the panes above. Nothing is sent to the Verifier, apart from the `request_uri` fetch. |
| Choose what to disclose → | `vp_continue_button` | Goes to step 2. Disabled while anything blocks. |
| Discard this request | `vp_forget_button` | Forgets the request. Nothing was presented, and its nonce is now useless to anyone. |

### What blocks Continue, and what only advises

These are the rules `requestRules()` in `client/src/vp_protocols.js` checks,
in that order. **Block** means a failure disables Continue. **Warn** means the
failure is shown and the request is still answered.

**Under every protocol except SIOPv2**

| Rule | Level | Passes when |
|---|---|---|
| `response_type` | block | It is exactly `vp_token`. |

**Under all three protocols (OpenID4VP rules)**

| Rule | Level | Passes when |
|---|---|---|
| `nonce` | block | A nonce is present. |
| `dcql_query` | block | A DCQL query is present, when `vp_token` is asked for. |
| `redirect_uri prefix` | block | A `redirect_uri:` request is **not** signed (§5.9.3). |
| `redirect_uri target` | block | The answer goes to the URL the Client Identifier names. |
| `x509_hash signed` / `x509_san_dns signed` | block | An x509 request is signed. |
| `x509_hash` / `x509_san_dns` | block | The Client Identifier names the leaf certificate in `x5c`. |
| `request signature` | block | The Request Object verifies with that certificate's key. |
| `response host` | block | For `x509_san_dns`, the answer goes to the certified DNS name. |
| `trust anchor` | **warn** | The chain reaches the anchor configured on step 0. |
| `typ` | **warn** | A signed Request Object's `typ` is `oauth-authz-req+jwt` (RFC 9101 §10.8). |
| `client_id match` | block | The `client_id` inside the signed object is the one the wallet was handed. |
| `wallet_nonce` | block | The object echoes the `wallet_nonce` this wallet POSTed. |
| `response_mode` | block | One of `direct_post`, `direct_post.jwt`, `fragment`, `query`, `form_post` or `post`. This wallet does not answer `dc_api` or `dc_api.jwt`. |
| `response_uri` / `redirect_uri` | block | The target that mode needs is present. |
| `encryption key` | block | For `direct_post.jwt`, `client_metadata.jwks` has a key the wallet can encrypt to: ECDH-ES P-256, or an ML-KEM or HPKE key. Under HAIP only ECDH-ES P-256 counts. |
| `enc` | block | For `direct_post.jwt`, one offered `enc` is one this wallet does: A128GCM, A256GCM, A128CBC-HS256 or A256CBC-HS512. The default is A128GCM. |

**Added under HAIP 1.0**

| Rule | Level | Passes when |
|---|---|---|
| `HAIP: request_uri` | block | The request was passed by reference. |
| `HAIP: signed` | block | The request is signed. |
| `HAIP: x509_hash` | block | The prefix is `x509_hash`. |
| `HAIP: ES256` | **warn** | The request is signed with ES256. |
| `HAIP: direct_post.jwt` | block | The response mode is `direct_post.jwt`. |
| `HAIP: vp_token` | block | `response_type` is `vp_token`. |
| `HAIP: format` | **warn** | The format is `dc+sd-jwt` or `mso_mdoc`. |

**Added under SIOPv2**

| Rule | Level | Passes when |
|---|---|---|
| `SIOPv2: id_token` | block | `response_type` includes `id_token`. |
| `SIOPv2: scope openid` | block | `scope` includes `openid`. |
| `SIOPv2: subject syntax` | block | The Verifier's `subject_syntax_types_supported` includes one of `urn:ietf:params:oauth:jwk-thumbprint`, `did:jwk` or `did:key`. If it lists none, the JWK Thumbprint syntax is assumed. |

**Added by the wallet itself, whatever the protocol**

These block:

- no credential is held;
- the stored credential cannot be parsed;
- the query's format differs from the format of the held credential (a
  presentation cannot convert between formats);
- the private holder key is missing **while saving is on**;
- a signed Request Object does not verify.

These are advisories only and do not disable Continue:

- the request asks for an ID Token alone;
- the holder key was deliberately not kept, and you will paste it on step 2;
- the credential is a selectively disclosable `ldp_vc` (`bbs-2023`) or a BBS
  JPT, which need no holder key.

---

## Step 2 — `vc-presentation-2.html`

Nothing is sent until you press **Present**. Each pane below reflects the
request from step 1 and the credential held.

### What This Verifier Asked For

Pane `pane_ask`. All fields are read-only.

| Label | id | Shows |
|---|---|---|
| Verifier | `vp_verifier` | The `client_id`, which becomes the holder proof's audience. |
| nonce | `vp_nonce` | The request's nonce. |
| Claims requested | `vp_requested` | The claim paths in the DCQL query. |
| Holder binding | `vp_key_binding` | How this credential's format binds the holder. See below. |
| Always visible | `vp_always_visible` | Claims in the issuer-signed part, which cannot be withheld without breaking the signature. |

What **Holder binding** says depends on the format:

| Format | Holder proof |
|---|---|
| `dc+sd-jwt` | A Key Binding JWT (RFC 9901 §4.3), or "not required" when the query sets `require_cryptographic_holder_binding: false`. |
| `jwt_vc_json` | A VP JWT signed with the bound key. No KB-JWT, nothing to choose between. |
| `vc+jwt` / `vc+cose` (W3C VC-JOSE-COSE) | The credential goes whole as an `EnvelopedVerifiableCredential` inside a `vp+jwt` the holder signs. |
| `mso_mdoc` | The device signature: a COSE_Sign1 over a session transcript that binds `client_id`, the nonce, where the answer goes and, if encrypted, the key it is encrypted to. |
| SD-CWT (*draft-ietf-spice-sd-cwt-09, a draft*) | A Key Binding Token: a COSE_Sign1 carrying `aud`, `cnonce` and `iat`. |
| JPT (*draft-ietf-jose-json-web-proof-15, a draft*) | A Presentation Header with `aud` and the nonce. A BBS JPT needs no holder key and is unlinkable; otherwise the holder signs with the issuer-named `hpk`, and the presentation is linkable. |
| AnonCreds | A zero-knowledge proof under the link secret. Neither OpenID4VCI nor OpenID4VP defines AnonCreds, so the request mapping is this debugger's own. |

See [vc-jose-cose.md](../vc-jose-cose.md), [jwp-sd-cwt.md](../jwp-sd-cwt.md)
and [anoncreds.md](../anoncreds.md) for each format in detail.

### JSON-LD Contexts

Pane `pane_contexts`, used for `ldp_vc`. The wallet never fetches a context:
it uses the standard contexts it ships with, plus any you add here.

| Field / button | id | Does | Stored |
|---|---|---|---|
| (list) | `vp_contexts_list` | The contexts you have added, each with a Remove button. | |
| Context URL | `vp_context_url` | The URL exactly as it appears in the credential's `@context`. | |
| Context document | `vp_context_json` | The JSON-LD document, with its `"@context"` member. | |
| Add Context | `vp_context_add_button` | Adds the context and reloads the page, so the credential is canonicalized with it. | local `vc_jsonld_contexts` |

### Choose What To Disclose

Pane `pane_choose`.

| Element | id | Does |
|---|---|---|
| Disclosure table | `vp_disclosures_table` | One row per Disclosure (for an mdoc, per namespace/element), each with a checkbox. By default exactly what the Verifier asked for is selected. |
| Summary | `vp_selection_summary` | What the selection amounts to. |
| Only what was asked for | `vp_select_requested_button` | Selects only the requested claims. |
| Everything (over-disclose) | `vp_select_all_button` | Selects everything. The Verifier will accept this and keep it; the debugger reports it. |

The selection is stored by the Disclosures' base64url values, not by index, in
`sdjwtvp_selected_disclosures` (local).

### The Presentation

Pane `pane_presentation`. All fields are read-only except the key field.

| Label | id | Shows | Stored |
|---|---|---|---|
| Holder private key | `vp_holder_private_jwk` | Shown only when the private half of the holder key is not in storage. Paste the *Download Key Pair* file from issuance, or a bare private JWK. The key must match the credential's `cnf`. | **never stored** |
| sd_hash | `vp_sd_hash` | base64url of the hash over the issuer JWT and the selected Disclosures, each followed by `~`. | |
| KB-JWT header | `vp_kb_header` | `typ: kb+jwt`, and an `alg` that is not `none`. | |
| KB-JWT payload | `vp_kb_payload` | `iat`, `aud` (the `client_id`), `nonce`, `sd_hash`. | |
| KB-JWT | `vp_kb_jwt` | The signed Key Binding JWT. | |
| Presentation | `vp_presentation` | The SD-JWT+KB in Combined Serialization, or the format's equivalent. | |
| vp_token | `vp_vp_token` | A JSON object keyed by DCQL credential query id, each value an array of presentations (§8.1). | |
| What they will know | `vp_presented_claims` | The claims computed back from the bytes being sent. | |

For an `ldp_vc`, the holder's VP proof suite comes from
`vc_formats.holderSuiteFor()`. That function picks it from the holder key and
from the `cryptosuite_values` / `proof_type_values` the Verifier accepts, so
no pair is chosen by hand.

### The Self-Issued ID Token (SIOPv2)

Pane `vp_siop_pane`. Shown only when the request asks for an `id_token`.

| Field | id | What it is | Spec | Default | Stored |
|---|---|---|---|---|---|
| Subject syntax | `vp_subject_syntax` | JWK Thumbprint (`sub_jwk` carries the key), `did:jwk` or `did:key`. Only the syntaxes the Verifier lists are offered; `vp_subject_offered` shows that list. | SIOPv2 §8 | The first syntax both sides support | local `sdjwtvp_siop_subject_syntax` |
| a pairwise key for this Verifier | `vp_siop_pairwise` | A separate key, and so a separate `sub`, for each Verifier. Offered only for an ID Token on its own. | | Off | |
| keep pairwise keys in browser localStorage | `vp_siop_save_pairwise` | Opt-out for the pairwise **private** keys. Unticking it removes them at once. | | On | `sdjwtvp_siop_save_pairwise`; keys in `sdjwtvp_siop_pairwise_keys` (key material) |
| ID Token header | `vp_id_token_header` | The signing algorithm, and `kid` for a DID subject. | | | |
| ID Token payload | `vp_id_token_payload` | `iss` equal to `sub`, `aud`, `nonce`, `iat`, and `exp` five minutes later. | SIOPv2 §11 | | |
| id_token | `vp_id_token` | The signed token. | | | |

### The Encrypted Response (direct_post.jwt)

Pane `vp_encryption_pane`. Shown only for `direct_post.jwt`.

| Field | id | What it is | Spec | Default |
|---|---|---|---|---|
| Content encryption | `vp_response_enc` | An `enc` from the Verifier's `encrypted_response_enc_values_supported`. | OpenID4VP 1.0 §8.3 | The first value both support; A128GCM when the Verifier says nothing |
| JWE header | `vp_jwe_header`, `vp_jwe_note` | `alg`, `enc`, `epk` and the Verifier key's `kid`. The key is the first usable one in `client_metadata.jwks`, in the Verifier's order. Under HAIP it must be ECDH-ES P-256. For an mdoc, AKP keys are skipped. ML-KEM, HPKE and X-Wing keys are used outside HAIP: see [jwe-pq-kem.md](../jwe-pq-kem.md). | | |
| response | `vp_jwe` | The compact JWE, sent as the single form field `response`. | | |

### Key Binding and DPoP

Pane `pane_dpop_note`, explanation only. OpenID4VP issues no access token, so
there is nothing for DPoP to bind; the Key Binding JWT plays that role. The
pane compares the two side by side. DPoP applies on the issuance side.

### Present It

Pane `pane_present`.

| Element | id | Does |
|---|---|---|
| The call this will make | `vp_assembled_call` | The exact HTTP request: a POST for `direct_post`, `direct_post.jwt` and SIOPv2's `post`; a 302 with the fields in the fragment or the query; or an auto-posting browser form for `form_post`. |
| Present | `vp_present_button` | Sends it, through the api if step 0 says so, then opens step 3. The record is stored in `sdjwtvp_presentation` (local). |
| Refuse | `vp_refuse_button` | Sends an error back the way an answer would travel: `access_denied` for a presentation, `user_cancelled` for an ID Token alone, or `subject_syntax_types_not_supported`. |
| Status | `vp_present_status`, `vp_response_body` | The outcome, and the Verifier's raw answer. |

---

## Step 3 — `vc-presentation-3.html`

### What The Wallet Sent

Pane `pane_sent`. All fields are read-only.

| Label | id | Shows |
|---|---|---|
| Presented to | `vp_sent_to` | The `client_id` and the `response_uri`. |
| When | `vp_sent_at` | When the answer was sent. |
| KB-JWT payload / KB-JWT | `vp_sent_kb_payload`, `vp_sent_kb_jwt` | The holder proof, as signed. |
| What they can read | `vp_sent_claims` | The claims, computed from the bytes sent. |
| Answered the request? | `vp_answered` | What the DCQL query asked for, against what was disclosed. A Verifier need not check this. |
| (serialized) | `vp_sent_serialized`, `vp_sent_presentation` | The presentation, with its parts coloured. |

| Button | id | Does |
|---|---|---|
| Copy Presentation | `vp_copy_button` | Copies the presentation. |
| Present Again | `vp_again_button` | Back to step 2, for the same request. |
| Start Over | `vp_restart_button` | Forgets the request and goes to step 0. |

### The Wallet's Own Checks

Pane `pane_recheck`, table `vp_recheck_table`. The checks a Verifier would
make, run over the bytes that were sent. Which rows appear depends on the
format:

| Format | Rows |
|---|---|
| SD-JWT VC | Key Binding JWT present; KB-JWT nonce; KB-JWT audience; KB-JWT `sd_hash`; Disclosure digests |
| `jwt_vc_json` | Verifiable Presentation JWT; presentation nonce; presentation audience; selective disclosure |
| `bbs-2023` `ldp_vc` | Derived proof verifies; presentation header; statements revealed; holder proof; unlinkability |
| Other `ldp_vc` | Challenge and domain; holder is the subject; holder proof |
| mdoc | Device signature; selective disclosure |
| VC-JOSE-COSE | Holder's `vp+jwt`; nonce and audience; enveloped credential |
| W3C `vc+sd-jwt` | Issuer's `vc+sd-jwt`; Key Binding JWT |
| AnonCreds | AnonCreds presentation (CL) |

### How It Was Answered

Pane `pane_answer`.

| Label | id | Shows |
|---|---|---|
| Protocol | `vp_answer_protocol` | The protocol chosen on step 0. |
| response_type / mode | `vp_answer_mode` | |
| Holder binding | `vp_answer_binding` | |
| ID Token | `vp_answer_id_token` | |
| JWE header | `vp_answer_jwe_header` | |
| What was encrypted | `vp_answer_plaintext` | |
| (checks) | `vp_answer_checks` | The answer's own checks, re-run here: Encrypted; `iss` equals `sub`; ID Token `aud`; ID Token nonce; subject is the key; ID Token signature; same holder. |

### What The Verifier Answered

Pane `pane_verifier`. `vp_verifier_status` and `vp_verifier_raw` show the
body the Response Endpoint returned. Under §8.2 that is all a wallet is told:
`200`, and optionally a `redirect_uri` to send the browser on to. The
Verifier's own verdict stays with the Verifier. For an answer carried by the
browser (`fragment`, `query`, `form_post`), the wallet never sees the
Verifier's response, and the page says so.

---

## What is stored, and what is not

| Kept in `localStorage` | Never stored |
|---|---|
| The Configuration Parameters (`sdjwtvp_verifier_*`, `sdjwtvp_x509_trust_anchor`, `sdjwtvp_via_api`, `sdjwtvp_api_ssl_validate`); the protocol and flow (`sdjwtvp_protocol`, `sdjwtvp_use_case`); the request, the selection, the presentation and the result (`sdjwtvp_request`, `sdjwtvp_selected_disclosures`, `sdjwtvp_presentation`, `sdjwtvp_result`); the SIOPv2 subject syntax; added JSON-LD contexts (`vc_jsonld_contexts`) | A holder private key pasted on step 2 (`vp_holder_private_jwk`); the text pasted into Request URI |

There is one key-material exception: the SIOPv2 pairwise keys
(`sdjwtvp_siop_pairwise_keys`). They are kept only while *keep pairwise keys*
is ticked, and removed the moment it is cleared.

This workflow never writes the holder key. The holder key stays under the
issuance workflow's rule: `vc_save_holder_key` on issuance step 2, enforced
in `client/src/sd_jwt_vc.js`.

The presentation pages hold no client secret and no bearer token.

[oid4vp]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
