# VC Barcodes and CBOR-LD

#480, phase 6 of #474. W3C **Verifiable Credential Barcodes v1.0** (Working
Draft, 22 August 2026) and **CBOR-LD 1.0**, on `vc-barcodes.html`.

| File | What it is |
|---|---|
| `client/src/cborld.js` | CBOR-LD 1.0: encode and decode, registry entries 0, 1 and 100, and the 7.x / 6.x framings |
| `client/src/vc_barcodes.js` | base45, the MRZ and AAMVA optical data, `issue()` and `verify()` |
| `client/src/data_integrity.js` | the `ecdsa-xi-2023` row (its `extraInformation` option) |
| `client/src/vc_barcodes_page.js` | the page (bundle global `vcbarcodespage`) |
| `client/src/contexts/{vc_barcodes_v1,utopia_v2,vital_records_v1rc1}.json` | the three contexts the specification's vectors are written in |
| `tests/vc_barcodes_engine.js` | node: the spec's vectors, and Digital Bazaar's library byte for byte |
| `tests/vc_barcodes_browser.js` | Chrome: the page reads, verifies and issues |

## What it is

A credential printed on a physical document, signed over what that document
already prints in machine-readable form, so a barcode copied onto a forged
document does not verify:

- **`MachineReadableZone`** — an ID card or travel document. The credential is
  a QR code beside the MRZ; the signature covers every MRZ line, each followed
  by `\n`, in printed order.
- **`AamvaDriversLicenseScannableInformation`** — a driver's licence. The
  credential rides inside the licence's PDF417 (the specification's example
  puts it in subfile `ZZ`, element `ZZA`); the signature covers the mandatory
  AAMVA fields its 3-byte `protectedComponentIndex` selects, each as
  `ID + value + "\n"`, sorted. A field left out can change without the barcode
  noticing — `tests/vc_barcodes_engine.js` checks that an UNprotected change
  still verifies, because that is what the index means.

The proof is **`ecdsa-xi-2023`**: `ecdsa-rdfc-2019` with a third hash
appended, so the signed message is `SHA-256(c14n(proof options)) ‖
SHA-256(c14n(document)) ‖ SHA-256(opticalDataBytes)`, where
`opticalDataBytes` is itself `SHA-256` of the joined components (the optical
data is hashed twice; the specification says so). It is not offered by
`suitesForKey()`, because it means nothing without a document to print on.

The credential is **CBOR-LD**, registry entry **100**: `D9 CB 1D 82 18 64`
then a map whose keys are term ids. The QR text is `VC1-` + multibase base45
(`R` + base45); the PDF417 field is base64url.

## The published barcodes win

Every published barcode was made by Digital Bazaar's `@digitalbazaar/cborld`
and `ecdsa-xi-2023-cryptosuite`, and where the TR's prose disagrees with them
this follows them, because a debugger that follows the prose verifies none of
the specification's own examples:

| Topic | Followed here (the barcodes) | The draft's prose |
|---|---|---|
| base45 | RFC 9285 (byte pairs, three digits, least significant first) | links CID's generic big-integer "Base Encoding" |
| CBOR-LD tag | 51997, `[registryEntryId, payload]` | "begins with tag 0x0664" (the 7.x form; read too) |
| `ecdsa-xi-2023` on P-384 | SHA-256 for all three hashes | "the same hash as ecdsa-rdfc-2019", i.e. SHA-384 |
| Terse status `listLength` | a parameter (the page defaults to 2^26) | MUST be 2^26 — and its own example works only with 2^17 |

## CBOR-LD, the parts that cost a day if missed

`cborld.js`'s header lists them; the ones that change bytes:

- A term's id is assigned the first time its context is **loaded**, in
  `Object.keys(context).sort()` order from 100 in steps of 2 (odd = the value
  was an array). Which context loads first follows the walk: embedded, then
  type-scoped (types sorted), then property-scoped as sorted keys are visited.
  The decoder sorts each map's entries by term name to load them in the same
  order. So **a different copy of any context renumbers every term after it**
  — which is why the three contexts are shipped, and why the loader refuses a
  context nobody shipped or supplied.
- A URL-typed value equal to **any** term is written as that term's id: the
  Utopia context defines its issuer DIDs and status URL as terms, which is how
  the specification's barcodes are 123 and 148 bytes. A did:key the context
  does not name is `[1025, bytes, bytes]` instead — about 270 bytes for a
  P-256 MRZ credential issued on the page.
- A type-table hit for `url`, `none`, `xsd:date` or `xsd:dateTime` is a
  **byte string**, one byte below 0xFF, so 255 is `00 FF`.
- A URL's scheme, for the codec table, is everything before its **last**
  colon, so `https://host:8443/x` is not compressed.

`tests/vc_barcodes_engine.js` puts a corpus through every codec, under a test
type table, entries 1 and 0, and both legacy framings, and compares bytes and
decoded documents with the library in both directions.

## The page

Read and verify: paste the QR text, the whole AAMVA PDF417 text, the field
alone or hex, or read a QR code from an image (jsQR, in the page). PDF417
symbols are not decoded from images — no PDF417 reader is bundled — so paste
what a scanner reads. PDF417 text carries control characters (RS, CR), shown
and read as `\x1e` and `\r`. Two links load the specification's Utopia
examples.

Issue: generate a P-256 or P-384 key (its did:key is the issuer), choose the
document type and, for AAMVA, the fields to protect, and issue. An MRZ
credential is drawn as a QR code in alphanumeric mode; an AAMVA one is added
to the licence's PDF417 text as subfile `ZZ`, with the header's designators
rewritten — the page draws no PDF417 symbol.

**Nothing on the page is stored**, the private key included:
`tests/vc_barcodes_browser.js` checks both storages are empty afterwards. A
barcode is issued once and printed; a key kept in a browser for that is kept
for no reason. Download it if it is needed again.

## Not done

- `IsoDrivingLicenceMachineReadableInformation` (Appendix B, informative and
  "expected to be refined"): no vector, not implemented.
- Fetching and checking the status list a terse entry expands to: the page
  shows the expansion and stops there.
- Drawing or reading a PDF417 symbol.
