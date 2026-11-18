---
title: "VC Tools: DID Tools, VC Barcodes, Gordian Envelope and ACDC"
---

# VC Tools: DID Tools, VC Barcodes, Gordian Envelope and ACDC

This is the configuration reference for the four pages that sit beside the VC
Issuance and VC Presentation workflows. They are not steps of either workflow.
The **VC Tools** pane, at the foot of every workflow page, links to them.

| Page | What it is for | Network | Stored |
|---|---|---|---|
| [`did-tools.html`](#did-tools) | Resolve a DID, check that its key signed the credential this browser holds, and verify a domain linkage | Only for `did:web` and the domain linkage, which the **browser** fetches directly | the DID, the document URL, the origin and the resolved document's members |
| [`vc-barcodes.html`](#vc-barcodes) | Read, verify and issue a W3C VC Barcode | None for the page's own examples, which use `did:key` | nothing |
| [`gordian-envelope.html`](#gordian-envelope) | Read, verify, elide (present) and issue a Gordian Envelope credential | None | nothing |
| [`acdc.html`](#acdc) | Verify an ACDC presentation stream, and issue or revoke one | None | nothing |

None of the four pages uses the api. All four ship to the deployed static
sites, because none of them is on `client/static_site.js`'s excluded list.

* TOC
{:toc}

## The VC Tools pane

`client/public/partials/vc_tools.html` is one pane, **VC Tools**
(`pane_vc_tools`, fieldset `vc_tools_fieldset`). It is included at the bottom
of thirteen pages:

- `vc-issuance-0.html` … `vc-issuance-4.html`
- `vc-presentation-0.html` … `vc-presentation-3.html`
- `did-tools.html`, `vc-barcodes.html`, `gordian-envelope.html` and
  `acdc.html`

`vc-verifier.html` does not include it. The pane title collapses and expands
it. On pages with a **Collapse all panes** toggle, that toggle covers this pane
too.

| Row | Link id | Opens |
|---|---|---|
| **DID Tools** | `vc_tools_did_link` | `/did-tools.html` |
| **Other credential formats** | `vc_tools_barcodes_link`, `vc_tools_gordian_link`, `vc_tools_acdc_link` | `/vc-barcodes.html`, `/gordian-envelope.html`, `/acdc.html` |
| **Certificate Authority & X.509 Tools** | `vc_tools_pki_link` | `/pki.html` (see [`../pki.md`](../pki.md)) |

Every link opens in the same tab. The pane has no fields and stores nothing.

## DID Tools

`/did-tools.html` (`client/src/did_tools.js`, over `client/src/did.js`). The
developer notes are [`../dids.md`](../dids.md).

The page resolves a DID to its document. It then checks two things that the
document cannot establish about itself:

- whether a key the document publishes really signed the credential in this
  browser;
- whether the DID and a web origin belong to the same party (domain linkage).

**DID methods.** `did:jwk` and `did:key` are their key, so they are decoded in
the page with no network call. A `did:key` must be multibase base58btc (it
starts with `z`). Its multicodec must be one of `ed25519-pub`, `x25519-pub`,
`secp256k1-pub`, `p256-pub`, `p384-pub` or `p521-pub`. Only `did:web` has a
document to fetch.

**Where it reads and writes.** The page keeps its own values under the prefix
`didtools_`, so it never overwrites the DID pane on issuance step 1, whose
element ids are the same. The only value it reads from the workflows is the
held credential (`sdjwtvc_credential`), and it never writes that value. When
the origin field has no stored value, the page fills it from the Credential
Issuer that step 1 last discovered (`vci_credential_issuer`).

A **Collapse all panes** toggle (`dbg_toggle_all`) at the top covers the three
panes and VC Tools.

### Pane 1 — DID Document (W3C DID Core 1.0)

Fieldset `did_fieldset`. Spec:
[DID Core 1.0](https://www.w3.org/TR/did-1.0/), plus the
[did:web](https://w3c-ccg.github.io/did-method-web/),
[did:jwk](https://github.com/quartzjer/did-jwk) and
[did:key](https://w3c-ccg.github.io/did-method-key/) method specifications.

| Field or button | id | What it does | Default | Stored |
|---|---|---|---|---|
| **DID** | `did_identifier` | The DID to resolve. Placeholders show `did:web:…`, `did:jwk:…` and `did:key:z…`. | last value | `didtools_did_identifier`, written by **Resolve** and **Save**, and blanked by **Clear** |
| **Resolve** | `did_resolve_button` | `did:jwk` and `did:key` are decoded locally. For `did:web`, the page derives the document URL, writes it to **Document URL** and fetches it from the browser. The URL is the host (with its port percent-decoded) plus `/.well-known/did.json`, or `/<path>/did.json` when the DID has path segments. A resolved document whose `id` is not the DID is refused, as DID Core requires. | | |
| **Upload** | `did_upload_button` (file input `did_document_file`) | Loads a DID Document from a `.json`/`.jsonld` file instead of resolving it. Use it when a `did:web` host sends no CORS headers. Fetch the document with curl, save it, and load the file. | | the members, as for a resolve |
| **Clear** | `did_clear_button` | Forgets the document, its table and the members, on screen and in storage. | | blanks the stored DID and members |
| **Document URL** | `did_resolution_url` | Where a `did:web` document comes from. **Resolve** fills it in. It stays empty for `did:jwk` and `did:key`. | derived | `didtools_did_resolution_url`, written by **Save** only |
| **Retrieve** | `did_retrieve_button` | Fetches the document from **Document URL**, which you may type yourself, for example for a staging host or a tunnel. This is a retrieval, not a resolution. A document whose `id` is a different DID is **reported**, not refused, because you chose the URL. Only `http` and `https` URLs are accepted. | | |
| **Verify Signing Key** | `did_verify_button` | Checks the held credential against the document. A JWS-secured credential (`dc+sd-jwt`, `jwt_vc_json`) is verified against the one key whose id matches the header's `kid`, and that key must be a JWK. For an `ldp_vc`, the page checks that the proof's `verificationMethod` is one this document publishes for assertion. The proof itself is verified on issuance step 3. If the credential's issuer (`iss`, or `issuer` for an `ldp_vc`) is not the document's `id`, the check is refused. | | |
| status | `did_status` | The result of each button above. | | |
| **Credential in this browser** | `did_credential_status` | The format of the credential the workflows last stored, and who it says issued it. If no credential is held, it says so. | | read only |
| document table | `did_document_table` | The resolved document, one row per member, with its source. | | |

**Plain http.** `did:web` must be fetched over https. The page falls back to
plain http only when the page itself is served from `localhost` or over http,
or when the DID's host is `localhost`, `sts` or `127.0.0.1`. Even then it
tries https first.

### Pane 2 — DID Document Members

Fieldset `did_members_fieldset`. This is an editable table with one row per
member. The rows come from `DID_METADATA` in `did.js`, and each row's tooltip
is that member's description.

| Member | id | Kind |
|---|---|---|
| `id` | `did_id` | text |
| `controller` | `did_controller` | text |
| `verificationMethod` | `did_verificationMethod` | JSON |
| `authentication` | `did_authentication` | JSON |
| `assertionMethod` | `did_assertionMethod` | JSON |
| `service` | `did_service` | JSON |

A resolve, retrieve or upload fills the members. It also writes each one to
`didtools_did_<member>`, so the page reopens with them filled in. A member
the document lacks is marked as not defined.

**Editing a member changes only the field.** **Verify Signing Key** and
**Verify Linkage** read the document as it was resolved, retrieved or
uploaded. They do not read these fields. To try a modified document, edit
the JSON file and load it with **Upload**.

| Button | id | What it does |
|---|---|---|
| **Save** | `did_save_button` | Stores the DID, the Document URL and the Origin (`didtools_did_identifier`, `didtools_did_resolution_url`, `didtools_origin`). Despite where the button sits, it does not store the member fields. |

### Pane 3 — Domain Linkage (DIF Well Known DID Configuration)

Fieldset `did_linkage_fieldset`. Spec:
[DIF Well Known DID Configuration](https://identity.foundation/well-known-did-configuration/).
A **Domain Linkage Credential** is a credential that the DID signs with its
own key and that names an origin. It is the check that `did:web` cannot make
on its own: resolving `did:web:example.com` means fetching from
`example.com`.

| Field or button | id | What it does | Default | Stored |
|---|---|---|---|---|
| **Origin** | `did_tools_origin` | The origin in question: scheme, host and port. It can be any origin, not only a credential issuer. | stored value, else the origin of the Credential Issuer last discovered on issuance step 1 | `didtools_origin`, written by **Verify Linkage** and **Save** |
| **Verify Linkage** | `did_linkage_button` | Fetches `<origin>/.well-known/did-configuration.json` from the browser. The resource's `@context` must be exactly the DIF value, and `linked_dids` must be a non-empty array. Every entry is verified and shown, not only the matching one. The DID checked is the **DID** field, or the resolved document's `id` when that field is empty. | | |
| status | `did_linkage_status` | **LINKED** if some entry verifies for this DID. **NOT LINKED** otherwise, and it says when the origin links a different DID. | | |
| results table | `did_linkage_table` | One row per entry, with each check. | | |

Each JWT-form entry gets these checks:

- the JWT header;
- the JWT claims;
- that it is self-issued to one DID;
- the credential `@context`;
- the credential type;
- that it has no credential id;
- that its origin matches the origin fetched;
- its validity window;
- the issuer signature.

**Only the JWT form is verified.** An entry in the Linked Data Proof form is
legal under the specification. The page reports it as **unverified**, not
invalid, because the page does not implement the canonicalization that form
needs.

### What is never stored here

The page writes no key material and no secret. The held credential is only
read. Like every `did:web` fetch, the linkage fetch is made by the browser,
so the origin must allow cross-origin reads.

## VC Barcodes

`/vc-barcodes.html` (`client/src/vc_barcodes_page.js`, over
`client/src/vc_barcodes.js`). The developer notes are
[`../vc-barcodes.md`](../vc-barcodes.md).

Spec: [Verifiable Credential Barcodes v1.0](https://www.w3.org/TR/vc-barcodes/),
a **W3C Working Draft** (the page cites the 22 August 2026 draft).

- The proof is `ecdsa-xi-2023`: `ecdsa-rdfc-2019` with a hash of the
  document's printed optical data appended. That optical data is the MRZ, or
  the AAMVA PDF417 fields.
- The credential is [CBOR-LD 1.0](https://www.w3.org/TR/cbor-ld/), registry
  entry 100.
- The QR text is `VC1-` followed by multibase base45
  ([RFC 9285](https://www.rfc-editor.org/rfc/rfc9285)).

Where the published barcodes and the draft's text disagree, the page follows
the barcodes:

- the CBOR-LD tag is 51997;
- `ecdsa-xi-2023` hashes with SHA-256 on P-384 as well as P-256.

**Nothing on this page is stored**, the issuer's private key included. If you
need the key again, use **Download Key**.

**Offline.** The QR decoder (jsQR) runs in the page, the three JSON-LD
contexts are bundled with it, and `did:key` and `did:jwk` verification
methods are decoded locally. A barcode whose issuer is any other DID needs
that DID resolved, and the browser does the fetch.

### Pane 1 — Read and Verify a Barcode

Fieldset `vcb_read_fieldset`.

| Field or button | id | What it is | Default |
|---|---|---|---|
| **Load the QR + MRZ example** | `vcb_example_ead` | Loads the specification's Utopia QR-code example (an MRZ document): its QR text and its three-line MRZ | |
| **Load the driver's licence example** | `vcb_example_dl` | Loads the specification's Utopia driver's licence: the whole AAMVA PDF417 text, with the credential in subfile `ZZ`, element `ZZA` | |
| **Barcode** | `vcb_barcode` | What a scanner reads. That can be the QR text (`VC1-…`), the whole AAMVA PDF417 text, the PDF417 credential field alone, or the CBOR-LD as hex. Control characters are written `\x1e` and `\r`. | empty |
| **QR image** | `vcb_image` | Reads a QR code from an image file, in the page. PDF417 symbols are **not** decoded from images, so paste what a scanner reads. | |
| **MRZ** | `vcb_mrz` | The Machine Readable Zone, one line per line. For a `MachineReadableZone` credential, the signature covers every line. | empty |
| **AAMVA data** | `vcb_aamva` | The licence's PDF417 text, when **Barcode** holds only the credential field. It is not needed when **Barcode** is the whole PDF417 text. | empty |
| **Status list length** | `vcb_list_length` | How a `TerseBitstringStatusListEntry` expands. The draft requires 2^26, but its own example works only with 2^17 (131072). | `67108864` (2^26) |
| **purpose** | `vcb_status_purpose` | `revocation` or `suspension`, for that expansion | `revocation` |
| **Verify** | `vcb_verify_button` | Decodes and verifies. The result shows how the credential was carried, the CBOR-LD (registry entry and hex), the proof and its verification method, the protected AAMVA fields, the optical data signed, the expanded status entry and the credential. | |

The status entry is only **expanded**. The page does not fetch the status
list or check it.

### Pane 2 — Issue a Barcode

Fieldset `vcb_issue_fieldset`.

| Field or button | id | What it is | Default |
|---|---|---|---|
| **Document** | `vcb_subject_type` | `MachineReadableZone` (an ID card or travel document; the credential goes in a QR code) or `AamvaDriversLicenseScannableInformation` (a driver's licence; the credential goes in its PDF417) | `MachineReadableZone` |
| **MRZ** | `vcb_issue_mrz` | The MRZ the signature covers. It is shown for `MachineReadableZone`. | the Utopia example's MRZ |
| **AAMVA PDF417** | `vcb_issue_aamva` | The licence's PDF417 text without a credential. The credential is added as subfile `ZZ`, element `ZZA`. It is shown for AAMVA. | the Utopia licence's text without its `ZZ` subfile |
| **Protect** | `vcb_protect_<element>` checkboxes in `vcb_protect_boxes` | Which of the 22 mandatory AAMVA elements the signature covers (`protectedComponentIndex`). An element left out can change without the barcode noticing. | `DAC`, `DAQ`, `DCS` |
| **Issuer key** | `vcb_curve` | The curve `ecdsa-xi-2023` signs with: P-256 or P-384 | P-256 |
| **Generate** | `vcb_generate_button` | Makes a key pair, puts its private JWK below, and fills **Issuer** with the key's `did:key` | |
| **Download Key** | `vcb_download_button` | Saves the private JWK as a file. This is the only way to keep it. | |
| **Private JWK** | `vcb_private_jwk` | The issuer's private key. You can also paste one. | empty, **never stored** |
| **Issuer** | `vcb_issuer` | The credential's issuer | the generated key's `did:key` |
| **verificationMethod** | `vcb_issuer_vm` | Optional | `did:key:z…#z…`, or `<issuer>#key-1` for a non-`did:key` issuer |
| **Status** | `vcb_status_base`, `vcb_status_index` | Optional `TerseBitstringStatusListEntry`: the status lists' base URL and this credential's 32-bit index | none |
| **Issue** | `vcb_issue_button` | Signs. An MRZ credential is also drawn as a QR code (`vcb_qr`, alphanumeric mode). An AAMVA credential is written into the PDF417 text, but the page draws no PDF417 symbol. | |
| **Barcode** (output) | `vcb_issue_output` | The QR text, or the PDF417 text with the credential added. Read-only. | |
| **Verify It** | `vcb_read_issued_button` | Copies the output and the printed data into pane 1 and verifies them | |

Not implemented: `IsoDrivingLicenceMachineReadableInformation` (the draft's
informative Appendix B), status list fetching, and drawing or reading PDF417
symbols.

## Gordian Envelope

`/gordian-envelope.html` (`client/src/gordian_envelope_page.js`, over
`client/src/gordian_envelope.js`). The developer notes are
[`../gordian-envelope.md`](../gordian-envelope.md).

Spec: Gordian Envelope,
[**draft**-mcnally-envelope-12](https://datatracker.ietf.org/doc/draft-mcnally-envelope/),
over dCBOR,
[**draft**-mcnally-deterministic-cbor-18](https://datatracker.ietf.org/doc/draft-mcnally-deterministic-cbor/).
Both are individual IETF drafts.

An envelope is a Merkle tree of digests. Any claim can be **elided**, which
replaces it with its digest. The digests above it do not change, and so the
issuer's signature over the root does not change either. A holder presents a
credential by eliding claims, and nothing is re-signed. The page signs a
credential **wrapped**, so every claim is under the signature. The text form
is `ur:envelope/…`.

**Nothing on this page is stored**, the issuer seed included. Nothing is
fetched.

### Pane 1 — Read, Verify and Present

Fieldset `ge_read_fieldset`.

| Field or button | id | What it is |
|---|---|---|
| **Envelope** | `ge_input` | `ur:envelope/…` text, or the hex of its CBOR (`d8c8…`) |
| **Read** | `ge_read_button` | Parses the envelope and shows its root digest (`ge_read_status`), its notation (`ge_notation`) and its digest tree (`ge_tree`). It also lists its claims under **Disclose**. |
| **Issuer key** | `ge_public_key` | `ur:signing-public-key/…`, `ur:crypto-pubkeys/…`, or hex. Hex is 32 bytes for a Schnorr x-only key or 33 for a compressed ECDSA key. |
| **Verify** | `ge_verify_button` | Verifies the signature(s) with that key (`ge_verify_status`). It reads the envelope first if that has not been done. |
| **Disclose** | checkboxes in `ge_claims` | The claims to keep. Every unticked claim is elided. |
| **Present** | `ge_present_button` | Builds the elided envelope. The page confirms that the root digest is unchanged (`ge_present_status`). |
| **Presentation** | `ge_presentation`, notation `ge_presentation_notation` | The presentation as `ur:envelope`. Read-only. |
| **Verify It** | `ge_read_presentation_button` | Moves the presentation into **Envelope** so that it can be read and verified |

### Pane 2 — Issue a Credential

Fieldset `ge_issue_fieldset`.

| Field or button | id | What it is | Default |
|---|---|---|---|
| **Load bc-envelope's Certificate of Completion example** | `ge_example_link` | Fills in the seed, scheme, subject ARID, claims and note of the example from Blockchain Commons' Rust tests. That example is signed with the tests' public "Alice" seed. | |
| **Issuer seed** | `ge_seed` | A `PrivateKeyBase` seed in hex, at least 16 bytes. The signing key is HKDF-SHA-256 of the seed with the salt `"signing"`. | empty, **never stored** |
| scheme | `ge_scheme` | Schnorr (BIP-340), ECDSA secp256k1 or Ed25519 | Schnorr |
| **Generate** | `ge_generate_button` | Makes a random 16-byte seed | |
| **Public key** | `ge_issuer_public_key` | The issuer's public key as a UR, derived from the seed. Read-only. | |
| **Subject ARID** | `ge_subject_arid` | The subject: a 32-byte ARID in hex | empty, which means a random ARID |
| **Claims** | `ge_issue_claims` | One `predicate: value` per line. `'isA'` in single quotes is a known value, `date 2020-01-01` is a Date, a whole number is a number, and anything else is text. | empty |
| **Salt claims** | `ge_salt` | Gives every claim its own salt, so that an elided claim cannot be guessed from its digest | off |
| **Note** | `ge_note` | Added **after** signing, so it is not under the signature | empty |
| **Issue** | `ge_issue_button` | Wraps the credential, then signs it. The result is `ge_issue_output` (read-only). | |
| **Verify It** | `ge_read_issued_button` | Copies the credential and its public key into pane 1, then reads and verifies them | |

Encrypted and compressed elements are read but not opened. SSKR,
recipients, ML-DSA and SSH signatures, and multi-part URs are not
implemented.

## ACDC

`/acdc.html` (`client/src/acdc_page.js`, over `client/src/acdc.js`). The
developer notes are [`../acdc.md`](../acdc.md).

Spec: Trust over IP's
[ACDC](https://trustoverip.github.io/kswg-acdc-specification/),
[KERI](https://trustoverip.github.io/kswg-keri-specification/) and
[CESR](https://trustoverip.github.io/kswg-cesr-specification/)
specifications. These are KERI Suite working-group specifications and still
**drafts**; the page names no revision. The page reads the **CESR version 1**
generation that the released libraries issue credentials in (signify-ts, the
KERIA client that vLEI uses). CESR version 2 messages are refused by name.

An ACDC carries no signature. Its SAID, the digest of its own bytes, is sealed
by an `iss` event in the issuer's registry. That event is anchored in the
issuer's KERI key event log (KEL), and the KEL is signed. Verifying an ACDC
walks that chain.

**Nothing on this page is stored**, and nothing is fetched. Each issuance
makes a fresh issuer whose keys last only for the page load.

**There is no example to load.** To have a stream to verify, press **Issue**
in pane 2, then **Verify It**.

### Pane 1 — Verify a Presentation

Fieldset `acdc_verify_fieldset`.

| Field or button | id | What it is |
|---|---|---|
| **CESR stream** | `acdc_stream` | The issuer's KEL, the registry inception (`vcp`), the credential's `iss` (and `rev`, if any) and the ACDC with its `-I` seal source triple, concatenated as KERIA or keri-ts sends them |
| **Schema** | `acdc_schema` | Optional. The JSON Schema that the credential's `s` names. Its `$id` is checked to be its own SAID. The credential is not validated against the schema. |
| **Verify** | `acdc_verify_button` | The verdict, in `acdc_verify_status`: **VALID** (issued by the issuer, anchored in its KEL, not revoked in this stream), **REVOKED** or **INVALID**, with the reason |
| **Checks** | `acdc_checks` | One row per check, ✔ or ✘. These cover the KEL events (SAID, sequence, prior digest, signatures against the threshold, rotation commitments), the registry, the issuance and revocation anchors, the ACDC and its sections, and the schema. |
| **Credential** | `acdc_credential` | The ACDC as JSON |

### Pane 2 — Issue a Credential

Fieldset `acdc_issue_fieldset`. Each issuance makes a fresh issuer:

- an Ed25519 inception;
- a no-backer registry;
- the credential and its issuance, each anchored by its own interaction event,
  with exactly one seal each.

| Field or button | id | What it is | Default |
|---|---|---|---|
| **Attributes** | `acdc_attributes` | The credential's attributes, as a JSON object | `{"name": "Sunspot College", "level": "gold"}` |
| **Issuee AID** | `acdc_recipient` | Optional `a.i`. It makes the credential targeted. | empty |
| **Issue** | `acdc_issue_button` | Writes the stream (`acdc_issue_output`) and the generated schema (`acdc_issue_schema`). Both are read-only. | |
| **Revoke** | `acdc_revoke_button` | Appends a `rev` to the registry, anchored by another `ixn`, to the stream of the credential last issued on this page. It works only after **Issue**. | |
| **Verify It** | `acdc_verify_issued_button` | Copies the stream and the schema into pane 1 and verifies them. After **Revoke**, the result is **REVOKED**. | |

Not implemented: CESR v2, CBOR and MessagePack bodies, weighted thresholds,
delegated identifiers, witness receipts as a requirement, backer registries,
full schema validation, fetching chained credentials, selective disclosure
(`A` aggregates) and IPEX `exn` grants.

## Sample inputs each page offers

The tutorials start from these.

| Page | Sample | id |
|---|---|---|
| DID Tools | none. A `did:jwk` or `did:key` needs no network, so any one of them resolves offline. A credential held from the issuance workflow gives **Verify Signing Key** something to check. | |
| VC Barcodes | the specification's Utopia QR + MRZ document | `vcb_example_ead` |
| VC Barcodes | the specification's Utopia driver's licence (PDF417) | `vcb_example_dl` |
| VC Barcodes | the issue pane opens with the Utopia MRZ and licence text already filled in; a key comes from **Generate** | `vcb_generate_button` |
| Gordian Envelope | bc-envelope's Certificate of Completion (the "Alice" seed) | `ge_example_link` |
| ACDC | none. **Issue**, then **Verify It**, produces a stream to verify | `acdc_issue_button`, `acdc_verify_issued_button` |
