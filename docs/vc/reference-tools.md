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
| [`vc-barcodes.html`](#vc-barcodes) | Read, verify and issue a W3C VC Barcode (QR + MRZ, AAMVA PDF417, ISO data groups), draw and read PDF417 symbols, and check its status list | None for the page's own examples, which use `did:key`; the status list is fetched by the **browser** on request | nothing |
| [`gordian-envelope.html`](#gordian-envelope) | Read, verify, elide (present) and issue a Gordian Envelope credential; encrypt (to keys, recipients or a password), compress, split with SSKR, and send as a multi-part UR | None | nothing |
| [`acdc.html`](#acdc) | Verify an ACDC presentation stream (CESR v1 or v2, chains, IPEX grants), and issue, revoke, grant or selectively disclose one | None | nothing |

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
`client/src/vc_barcodes.js`, `cborld.js` and `pdf417.js`). The developer notes
are [`../vc-barcodes.md`](../vc-barcodes.md); the user guide is
[format-vc-barcodes.md](format-vc-barcodes.md).

Spec: [Verifiable Credential Barcodes v1.0](https://www.w3.org/TR/vc-barcodes/),
a **W3C Working Draft** (the page cites the 22 August 2026 draft).

- The proof is `ecdsa-xi-2023`: `ecdsa-rdfc-2019` with a hash of the
  document's printed optical data appended. That optical data is the MRZ, the
  AAMVA PDF417 fields, or (Appendix B, **informative**) an ISO/IEC 18013-2
  licence's data groups.
- The credential is [CBOR-LD 1.0](https://www.w3.org/TR/cbor-ld/), registry
  entry 100.
- The QR text is `VC1-` followed by multibase base45
  ([RFC 9285](https://www.rfc-editor.org/rfc/rfc9285)).
- A terse status entry expands to a
  [Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/)
  entry, which pane 2 checks.

Where the published barcodes and the draft's text disagree, the page follows
the barcodes:

- the CBOR-LD tag is 51997;
- `ecdsa-xi-2023` hashes with SHA-256 on P-384 as well as P-256.

**Nothing on this page is stored**, the issuer's private key included. If you
need the key again, use **Download Key**.

**Offline, except the status list.** The QR decoder (jsQR) and the PDF417
reader (@zxing/library) and writer (bwip-js) run in the page, the three
JSON-LD contexts are bundled with it, and `did:key` and `did:jwk` verification
methods are decoded locally. A barcode whose issuer is any other DID needs
that DID resolved, and **Fetch and Check** fetches a status list; the
browser does both fetches.

### Pane 1 — Read and Verify a Barcode

Fieldset `vcb_read_fieldset`.

| Field or button | id | What it is | Default |
|---|---|---|---|
| **Load the QR + MRZ example** | `vcb_example_ead` | Loads the specification's Utopia QR-code example (an MRZ document): its QR text and its three-line MRZ | |
| **Load the driver's licence example** | `vcb_example_dl` | Loads the specification's Utopia driver's licence: the whole AAMVA PDF417 text, with the credential in subfile `ZZ`, element `ZZA` | |
| **Load an ISO licence example (Appendix B)** | `vcb_example_iso` | Loads an ISO licence's data groups with the credential in DG11. No published vector exists; this one was made entirely by Digital Bazaar's libraries, on a throwaway key | |
| **Barcode** | `vcb_barcode` | What a scanner reads: the QR text (`VC1-…`), the whole AAMVA PDF417 text, an ISO licence's data groups as `DGn: …` lines, the credential field alone, or the CBOR-LD as hex. Control characters are written `\x1e` and `\r`. | empty |
| **Draw as PDF417** | `vcb_draw_pdf417_button` | Draws the text in **Barcode** as a PDF417 symbol (`vcb_read_symbol`) | |
| **Barcode image** | `vcb_image` | Reads a QR code (jsQR) or, failing that, a PDF417 symbol (@zxing/library) from an image file, in the page. Crop a photograph to the symbol if it is not found. | |
| **MRZ** | `vcb_mrz` | The Machine Readable Zone, one line per line. For a `MachineReadableZone` credential, the signature covers every line. | empty |
| **AAMVA data** | `vcb_aamva` | The licence's PDF417 text, when **Barcode** holds only the credential field | empty |
| **ISO data groups** | `vcb_iso` | An ISO licence's data groups, one `DGn: contents` line each (text with `\n` `\r` `\t` `\\` and `\xNN` escapes, or `hex:` and hex), when **Barcode** holds only the credential field | empty |
| **Status list length** | `vcb_list_length` | How a `TerseBitstringStatusListEntry` expands. The draft requires 2^26, but its own example works only with 2^17 (131072). | `67108864` (2^26) |
| **purpose** | `vcb_status_purpose` | `revocation` or `suspension`, for that expansion | `revocation` |
| **Verify** | `vcb_verify_button` | Decodes and verifies. The result (`vcb_read_result`) shows how the credential was carried, the CBOR-LD (registry entry and hex), the proof and its verification method, the protected AAMVA fields or ISO data groups, the optical data signed, the expanded status entry and the credential. The expanded entry is also put in pane 2. | |

### Pane 2 — Check the Status List

Fieldset `vcb_status_fieldset`.

| Field or button | id | What it is | Default |
|---|---|---|---|
| **Status entry** | `vcb_status_entry` | The `BitstringStatusListEntry` the terse entry expands to (`statusListCredential`, `statusListIndex`, `statusPurpose`). Filled in by **Verify**; editable. | empty |
| **Status list credential** | `vcb_status_list` | Optional. The `BitstringStatusListCredential` itself, pasted (JSON with a proof, or a VC JWT), for a server a browser cannot fetch from | empty |
| **Fetch and Check** | `vcb_status_fetch_button` | Fetches the list from the browser, verifies its proof, type, `statusPurpose` and validity, inflates the GZIP bitstring and reads the entry's bit | |
| **Check Pasted** | `vcb_status_paste_button` | The same, on the pasted list | |

The verdict (`vcb_status_status`, details in `vcb_status_result`) is **REVOKED**
/ **NOT REVOKED** (**SUSPENDED** for that purpose) only when the list
verified; a bit from a list that did not is **UNVERIFIED**. The reader is the
Verifier page's own.

### Pane 3 — Issue a Barcode

Fieldset `vcb_issue_fieldset`.

| Field or button | id | What it is | Default |
|---|---|---|---|
| **Document** | `vcb_subject_type` | `MachineReadableZone` (an ID card or travel document; the credential goes in a QR code), `AamvaDriversLicenseScannableInformation` (a driver's licence; the credential goes in its PDF417) or `IsoDrivingLicenceMachineReadableInformation` (an ISO licence; the credential goes in DG11; informative) | `MachineReadableZone` |
| **MRZ** | `vcb_issue_mrz` | The MRZ the signature covers. Shown for `MachineReadableZone`. | the Utopia example's MRZ |
| **AAMVA PDF417** | `vcb_issue_aamva` | The licence's PDF417 text without a credential. The credential is added as subfile `ZZ`, element `ZZA`. Shown for AAMVA. | the Utopia licence's text without its `ZZ` subfile |
| **Protect** (AAMVA) | `vcb_protect_<element>` checkboxes in `vcb_protect_boxes` | Which of the 22 mandatory AAMVA elements the signature covers (`protectedComponentIndex`). An element left out can change without the barcode noticing. | `DAC`, `DAQ`, `DCS` |
| **ISO data groups** | `vcb_issue_iso` | The licence's data groups, one `DGn: contents` line each. The credential replaces DG11. Shown for ISO. | the ISO example's data groups, without DG11 |
| **Protect** (ISO) | `vcb_iso_protect_<DGn>` checkboxes in `vcb_iso_protect_boxes` | The data groups the signature covers (a 2-byte `protectedComponentIndex`), in data-group number order. DG11 carries the credential, so its box is disabled. | `DG1`, `DG2`, `DG10` |
| **Issuer key** | `vcb_curve` | The curve `ecdsa-xi-2023` signs with: P-256 or P-384 | P-256 |
| **Generate** | `vcb_generate_button` | Makes a key pair, puts its private JWK below, and fills **Issuer** with the key's `did:key` | |
| **Download Key** | `vcb_download_button` | Saves the private JWK as a file. This is the only way to keep it. | |
| **Private JWK** | `vcb_private_jwk` | The issuer's private key. You can also paste one. | empty, **never stored** |
| **Issuer** | `vcb_issuer` | The credential's issuer | the generated key's `did:key` |
| **verificationMethod** | `vcb_issuer_vm` | Optional | `did:key:z…#z…`, or `<issuer>#key-1` for a non-`did:key` issuer |
| **Status** | `vcb_status_base`, `vcb_status_index` | Optional `TerseBitstringStatusListEntry`: the status lists' base URL and this credential's 32-bit index | none |
| **Issue** | `vcb_issue_button` | Signs. An MRZ credential is drawn as a QR code (`vcb_qr`, alphanumeric mode); an AAMVA credential is written into the PDF417 text and the whole drawn as a PDF417 symbol (`vcb_pdf417`); an ISO credential is put in DG11 (no ISO symbol is drawn). | |
| **Barcode** (output) | `vcb_issue_output` | The QR text, the PDF417 text with the credential added, or the ISO data groups. Read-only. | |
| **Verify It** | `vcb_read_issued_button` | Copies the output and the printed data into pane 1 and verifies them | |

Not implemented: splitting an ISO/IEC 18013-2 compact encoding into data
groups, and drawing an ISO licence's PDF417 (both need ISO/IEC 18013-2, which
is not freely available).

## Gordian Envelope

`/gordian-envelope.html` (`client/src/gordian_envelope_page.js`, over
`client/src/gordian_envelope.js`, `gordian_envelope_crypto.js`, `sskr.js` and
`bc_ur.js`). The developer notes are
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

Elements can also be **encrypted** (to a content key, to recipients, or under
a password), **compressed**, or their key split into **SSKR** shares, and a
large envelope travels as a **multi-part UR** — panes 3 to 6, collapsed when
the page opens.

**Nothing on this page is stored**: the issuer seed, content keys, private
keys and passwords live only in their fields for the page load. Nothing is
fetched.

### Pane 1 — Read, Verify and Present

Fieldset `ge_read_fieldset`.

| Field or button | id | What it is |
|---|---|---|
| **Envelope** | `ge_input` | `ur:envelope/…` text, every part of a multi-part UR (`ur:envelope/3-9/…`, one per line, any order, fountain parts too), or the hex of its CBOR (`d8c8…`) |
| **Read** | `ge_read_button` | Parses the envelope and shows its root digest (`ge_read_status`), its notation (`ge_notation`) and its digest tree (`ge_tree`). It also lists its claims under **Disclose**. |
| **Issuer key** | `ge_public_key` | `ur:signing-public-key/…`, `ur:crypto-pubkeys/…` (Schnorr, ECDSA, Ed25519, ML-DSA-44/65/87 or an SSH key), an OpenSSH public key line (`ssh-ed25519 AAAA…`, `ecdsa-sha2-nistp256 AAAA…`), or hex: 32 bytes for a Schnorr x-only key, 33 for a compressed ECDSA key. |
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
| scheme | `ge_scheme` | Schnorr (BIP-340), ECDSA secp256k1, Ed25519, ML-DSA-44, ML-DSA-65, ML-DSA-87 or SSH Ed25519. An SSH Ed25519 key is HKDF-SHA-256(seed, `"ssh-ed25519-0"`); bc-components derives no ML-DSA key from a seed, so the page uses HKDF-SHA-256(seed, `"signing"`) as FIPS 204's key-generation seed and says so | Schnorr |
| **Generate** | `ge_generate_button` | Makes a random 16-byte seed | |
| **Public key** | `ge_issuer_public_key` | The issuer's public key as a UR, derived from the seed. Read-only. | |
| **Subject ARID** | `ge_subject_arid` | The subject: a 32-byte ARID in hex | empty, which means a random ARID |
| **Claims** | `ge_issue_claims` | One `predicate: value` per line. `'isA'` in single quotes is a known value, `date 2020-01-01` is a Date, a whole number is a number, and anything else is text. | empty |
| **Salt claims** | `ge_salt` | Gives every claim its own salt, so that an elided claim cannot be guessed from its digest | off |
| **Note** | `ge_note` | Added **after** signing, so it is not under the signature | empty |
| **Issue** | `ge_issue_button` | Wraps the credential, then signs it. The result is `ge_issue_output` (read-only). | |
| **Verify It** | `ge_read_issued_button` | Copies the credential and its public key into pane 1, then reads and verifies them | |

### Pane 3 — Encrypt and Decrypt (collapsed)

Fieldset `ge_encrypt_fieldset`. An ENCRYPTED element (tag 40002) is
ChaCha20-Poly1305 over the element's tagged CBOR, authenticated with its
digest, so the tree's digests — and a signature over them — do not change.
**Nothing here is stored**: keys and passwords live only in their fields.

| Field or button | id | What it is | Default |
|---|---|---|---|
| **Envelope** | `ge_enc_input` | The envelope to encrypt or decrypt (`ur:envelope/…`, its parts, or hex) | empty |
| **Wrap first** | `ge_enc_wrap` | Ticked: the envelope is wrapped first, so its assertions are encrypted with its subject (bc-envelope's `encrypt()`). Unticked: only the subject (`encrypt_subject()`, what bc-envelope-cli's `encrypt` does) | on |
| **Content key** | `ge_enc_key`, **Generate** `ge_enc_key_button` | The 32-byte symmetric key: `ur:crypto-key/…` or 64 hex digits. Empty when encrypting: a random one, shown here afterwards | empty |
| **Recipients** | `ge_enc_recipients` | One `ur:crypto-pubkeys/…` per line (X25519 or ML-KEM-512/768/1024); each becomes a `'hasRecipient'` assertion sealing the content key | empty |
| **Password**, KDF | `ge_enc_password`, `ge_enc_kdf` | A password that locks the content key (`'hasSecret'`), with Argon2id, PBKDF2-SHA-256, scrypt or HKDF-SHA-256. Also what Decrypt tries | empty; Argon2id |
| **Private keys** | `ge_enc_private_keys` | For Decrypt as a recipient: `ur:crypto-prvkeys/…`, `ur:crypto-prvkey-base/…`, `ur:seed/…`, or a seed in hex (its X25519 key is HKDF-SHA-256(seed, `"agreement"`)) | empty |
| **Encrypt** / **Decrypt** | `ge_encrypt_button`, `ge_decrypt_button` | Writes the result to `ge_enc_output` (with its notation, `ge_enc_notation`); status in `ge_enc_status`. **Read It** (`ge_enc_read_button`) shows it in pane 1 | |
| **Recipient key pair** | `ge_kp_seed`, `ge_kp_scheme`, **Make Keys** `ge_kp_button` | Makes a recipient's keys: X25519 from a seed (empty: random), or a random ML-KEM-512/768/1024 pair. The private keys go into **Private keys**, the public keys (`ge_kp_public`) into **Recipients** | X25519 |

### Pane 4 — Compress and Decompress (collapsed)

Fieldset `ge_compress_fieldset`. A COMPRESSED element (tag 40003) is
`[CRC-32, size, raw DEFLATE, digest]`: its digest is the uncompressed
element's, so nothing above it changes.

| Field or button | id | What it is | Default |
|---|---|---|---|
| **Envelope** | `ge_comp_input` | The envelope to compress or decompress | empty |
| **Subject only** | `ge_comp_subject` | Compress or decompress only the subject, leaving the assertions (a signature, say) outside | off |
| **Compress** / **Decompress** | `ge_compress_button`, `ge_decompress_button` | Result in `ge_comp_output`, status in `ge_comp_status`; **Read It** (`ge_comp_read_button`) | |

### Pane 5 — SSKR: Split and Join (collapsed)

Fieldset `ge_sskr_fieldset`. Sharded Secret Key Reconstruction
(BCR-2020-011): the envelope is wrapped and encrypted, and its content key
split by Shamir's scheme into groups of shares. Each share envelope carries
one `'sskrShare'`; any shares meeting the thresholds rejoin it.

| Field or button | id | What it is | Default |
|---|---|---|---|
| **Envelope** | `ge_sskr_input` | The envelope to split | empty |
| **Groups** | `ge_sskr_groups` | One `m-of-n` per group, comma-separated (at most 16 groups of at most 16 shares) | `2-of-3` |
| **Group threshold** | `ge_sskr_threshold` | How many groups must meet their own threshold | 1 |
| **Split** | `ge_sskr_split_button` | Writes every share envelope, one per line, to **Shares** | |
| **Shares** | `ge_sskr_shares` | Share envelopes; for Join, paste the ones you have, in any order | empty |
| **Join** | `ge_sskr_join_button` | The rebuilt envelope in `ge_sskr_output`, status in `ge_sskr_status`; **Read It** (`ge_sskr_read_button`) | |

### Pane 6 — Multi-part UR (collapsed)

Fieldset `ge_parts_fieldset`. An envelope too large for one QR code is sent
as `ur:envelope/<seq>-<count>/…` parts (BCR-2020-005, BCR-2024-001): the
first *count* are its fragments, every later one a fountain part (the XOR of
a pseudo-random set of fragments), so any large enough set rebuilds it.

| Field or button | id | What it is | Default |
|---|---|---|---|
| **Envelope** | `ge_parts_input` | The envelope to split into parts | empty |
| **Fragment size** | `ge_parts_max` | The most CBOR bytes in one part's fragment | 100 |
| **Fountain parts** | `ge_parts_extra` | How many mixed parts to write after the fragments | 5 |
| **Make Parts** | `ge_parts_encode_button` | Writes the parts to **Parts**, one per line | |
| **Parts** | `ge_parts_list` | For Join Parts: any parts of one envelope, any order | empty |
| **Join Parts** | `ge_parts_decode_button` | The rebuilt single-part envelope in `ge_parts_output`; **Read It** (`ge_parts_read_button`) | |

Not implemented: SSH-agent locks (a browser has no agent; refused by name),
and SSH DSA and RSA signatures.

## ACDC

`/acdc.html` (`client/src/acdc_page.js`, over `client/src/acdc.js`,
`acdc_threshold.js` and `acdc_schema.js`). The developer notes are
[`../acdc.md`](../acdc.md); the user guide is [format-acdc.md](format-acdc.md).

Spec: Trust over IP's
[ACDC](https://trustoverip.github.io/kswg-acdc-specification/),
[KERI](https://trustoverip.github.io/kswg-keri-specification/) and
[CESR](https://trustoverip.github.io/kswg-cesr-specification/)
specifications. These are KERI Suite working-group specifications and still
**drafts**; the page names no revision. **Both CESR versions are read and
issued**: version 1 (signify-ts and KERIA) and version 2 (keri-ts, the
current specification), mixed in one stream.

An ACDC carries no signature. Its SAID, the digest of its own bytes, is sealed
by an issuance event in the issuer's registry. That event is anchored in the
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
| **CESR stream** | `acdc_stream` | The issuer's KEL (and its delegator's, and the KELs of chained credentials' issuers), the registry events, the credential with its attachments, any credentials its edges point to, and optionally an IPEX grant (an `exn`), concatenated as KERIA or keri-ts sends them |
| **Schemas** | `acdc_schema` | Optional. The JSON Schema the credential's `s` names, or a JSON list of schemas (one per credential in a chain). Each `$id` is checked to be its own SAID, and the credential **as presented** is validated against it (draft-07, or 2020-12 when its `$schema` says so). |
| **Verify Credential** | `acdc_verify_button` | The verdict, in `acdc_verify_status`: **VALID** (issued by the issuer, anchored in its KEL, not revoked in this stream), **REVOKED** or **INVALID**, with the reason |
| **Verify IPEX Grant** | `acdc_verify_grant_button` | Verifies the last IPEX grant (`/ipex/grant`) in the stream: its SAID, the sender's signature against the sender's KEL, its embeds' SAIDs, and the credential it carries |
| **Checks** | `acdc_checks` | One row per check, ✔ or ✘, with what it found: every KEL event (SAID, sequence, prior digest, signatures against a numeric or weighted threshold, rotation commitments, witness receipts against `bt`, delegation seals), the registry (version 1 with or without backers, or version 2), the anchors, the ACDC and its sections and aggregate, the schema, and each edge |
| **Credential** | `acdc_credential` | The ACDC as received |

### Pane 2 — Issue a Credential

Fieldset `acdc_issue_fieldset`. Each issuance makes a fresh issuer, a
registry, the credential and its issuance, each anchored by its own
interaction event (exactly one seal each, which keri-ts requires). The page
also runs the issuer's witnesses, backers and delegator.

| Field or button | id | What it is | Default |
|---|---|---|---|
| **CESR version** | `acdc_version` | 1 (`ACDC10JSON`, `vcp`/`iss`/`rev`, what signify-ts and KERIA issue) or 2 (`KERICAACAAJSON` events, an `acm` ACDC whose SAID is over its most compact form, a `rip`/`upd` registry) | 1 |
| **Attributes** | `acdc_attributes` | The credential's attributes, as a JSON object; `dt` is added | `{"name": "Sunspot College", "level": "gold"}` |
| **Issuee AID** | `acdc_recipient` | Optional `a.i`. It makes the credential targeted, and an IPEX grant goes to it. | empty |
| **Signing keys** | `acdc_signers` | How many keys the issuer's establishment events list (1–9), each signing | 1 |
| **Signing threshold (kt, nt)** | `acdc_kt` | A hex number (`"2"`), a weighted list (`["1/2","1/2","1/2"]`), or clauses that must all reach 1 (`[["1/2","1/2"],["1"]]`); one weight per key; used for the current and the next threshold | empty: a majority |
| **Witnesses** | `acdc_witnesses` | How many witnesses the issuer names in `b`; every event carries their receipts | 0 |
| **Witness threshold (bt)** | `acdc_toad` | How many receipts make an event fully witnessed | empty: all of them |
| **Delegated issuer** | `acdc_delegated` | The issuer is a delegated identifier (`dip`), approved by an interaction event of a delegator whose KEL comes first | off |
| **Registry backers** | `acdc_backers` | Version 1 only. 0 for a no-backer registry (`iss`/`rev`); more for a backer registry (`bis`/`brv`), every registry event receipted by its backers | 0 |
| **Aggregate** | `acdc_aggregate` | Put the attributes in an aggregate `A`: each its own blinded block, the AGID over them, so blocks can be disclosed selectively | off |
| **Chain to a parent** | `acdc_chain` | A second issuer first issues a parent credential to this issuer; this credential's edge `e.parent` points to it (`I2I`). The stream carries both. | off |
| **Issue** | `acdc_issue_button` | Writes the stream (`acdc_issue_output`) and the schema(s) (`acdc_issue_schema`, a list when chained). Both are read-only. | |
| **Revoke** | `acdc_revoke_button` | Appends a revocation of the credential last issued on this page, anchored in the issuer's KEL. It works only after **Issue**. | |
| **IPEX Grant** | `acdc_grant_button` | Appends an IPEX grant (`/ipex/grant`, version 1, as signify-ts builds it) of the credential to its issuee: an `exn` embedding the ACDC, its issuance and the anchoring event, signed by the issuer | |
| **Verify It** | `acdc_verify_issued_button` | Copies the stream and the schema into pane 1 and verifies them. After **Revoke**, the result is **REVOKED**. | |

### Pane 3 — Disclose Selectively

Fieldset `acdc_disclose_fieldset`, for a credential issued above with
**Aggregate**.

| Field or button | id | What it is | Default |
|---|---|---|---|
| **Blocks to disclose** | `acdc_disclose_indices` | Positions in `A`, counting from 1 (`A[0]` is the AGID), comma-separated; the others are shown only as their SAIDs | `1` |
| **Disclose** | `acdc_disclose_button` | Builds the stream with the selectively disclosed credential (`acdc_disclose_output`, read-only). In version 2 its SAID does not change, so the registry still binds it; in version 1 it does, and the result says so. | |
| **Verify It** | `acdc_verify_disclosed_button` | Verifies the disclosed stream in pane 1 | |

Not implemented: CBOR, MessagePack and native CESR bodies; edge-group `AVG` /
`WAVG` (refused by name); fetching KELs, schemas or far nodes (OOBIs,
watchers); version 2 IPEX grants.

## Sample inputs each page offers

The tutorials start from these.

| Page | Sample | id |
|---|---|---|
| DID Tools | none. A `did:jwk` or `did:key` needs no network, so any one of them resolves offline. A credential held from the issuance workflow gives **Verify Signing Key** something to check. | |
| VC Barcodes | the specification's Utopia QR + MRZ document | `vcb_example_ead` |
| VC Barcodes | the specification's Utopia driver's licence (PDF417) | `vcb_example_dl` |
| VC Barcodes | an ISO licence's data groups (Appendix B) | `vcb_example_iso` |
| VC Barcodes | the issue pane opens with the Utopia MRZ, the licence text and the ISO data groups already filled in; a key comes from **Generate** | `vcb_generate_button` |
| Gordian Envelope | bc-envelope's Certificate of Completion (the "Alice" seed) | `ge_example_link` |
| ACDC | none. **Issue** (with any of the options: version 2, weighted thresholds, witnesses, delegation, backers, an aggregate, a chain), then **Verify It**, produces a stream to verify | `acdc_issue_button`, `acdc_verify_issued_button` |
