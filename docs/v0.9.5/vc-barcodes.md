# VC Barcodes and CBOR-LD

#480, phase 6 of #474. W3C **Verifiable Credential Barcodes v1.0** (Working
Draft, 22 August 2026) and **CBOR-LD 1.0**, on `vc-barcodes.html`.

| File | What it is |
|---|---|
| `client/src/cborld.js` | CBOR-LD 1.0: encode and decode, registry entries 0, 1 and 100, and the 7.x / 6.x framings |
| `client/src/vc_barcodes.js` | base45, the MRZ, AAMVA and ISO (Appendix B) optical data, `issue()` and `verify()` |
| `client/src/pdf417.js` | drawing a PDF417 symbol (bwip-js 4.11.4, MIT) and reading one from a picture (@zxing/library 0.23.0, Apache-2.0) |
| `client/src/vp_verifier.js` | `checkBitstringStatus()`: the Verifier role's Bitstring Status List reader, for the status a terse entry expands to |
| `client/src/data_integrity.js` | the `ecdsa-xi-2023` row (its `extraInformation` option) |
| `client/src/vc_barcodes_page.js` | the page (bundle global `vcbarcodespage`) |
| `client/src/vc_barcodes_qr.js` | the QR encode (qrcode-generator), QR decode (jsqr) and PDF417 (pdf417.js, over bwip-js and @zxing/library) codecs, in a bundle of their own (global `vcbarcodesqr`) that the page loads ON DEMAND the first time a QR code or PDF417 symbol is drawn or read — ~300 KB that would otherwise sit in the page bundle for every visit. Reached through `codecs.pdf417` so the page uses pdf417.js's functions and constants without requiring it. Served beside the page, so a static deployment still works offline |
| `client/src/contexts/{vc_barcodes_v1,utopia_v2,vital_records_v1rc1}.json` | the three contexts the specification's vectors are written in |
| `tests/vc_barcodes_engine.js` | node: the spec's vectors, Digital Bazaar's library byte for byte, the ISO vector built here, status lists both ways, the PDF417 round trip |
| `tests/vc_barcodes_browser.js` | Chrome: the page reads, verifies and issues; draws and reads PDF417 symbols; fetches and checks a status list |

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
- **`IsoDrivingLicenceMachineReadableInformation`** (Appendix B,
  **informative**, "expected to be refined ... before use") — an ISO/IEC
  18013-2 licence. The signature covers the data groups DG1..DG11 a
  **2-byte** `protectedComponentIndex` selects (first 11 bits, the last five
  padding and 0), each as `"DGn" + base64url(contents) + "\n"`, in data-group
  **number** order — not sorted as strings, which would put DG10 before DG2.
  The credential is base64url in **DG11**, and DG11 cannot be protected (the
  TR: that bit "is set to 0"; a signature cannot cover its own container), so
  issuing refuses it and verifying a DG11-carried credential that protects it
  says so by name.

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

## The ISO type, and what the TR leaves open

No vector exists for Appendix B, so `tests/vc_barcodes_engine.js` builds one:
four fixed data groups (DG2 with bytes above 0x7F, so its base64url has `-`
and `_`), DG1, DG2 and DG10 protected (index `uwEA`), the canonical text
spelled out independently with node's own `Buffer` and pinned, and its
`opticalDataBytes` pinned. Our barcode is verified by Digital Bazaar's
`ecdsa-xi-2023-cryptosuite` given those same bytes, and theirs here; and one
ISO barcode made ENTIRELY by their libraries (signed and CBOR-LD encoded, on a
throwaway key) is pinned as `ISO_EXAMPLE_DG11` and is the page's ISO example.

Four readings, each written down where it is made:

- **The context.** Neither `https://w3id.org/vc-barcodes/v1` nor any
  published context defines `IsoDrivingLicenceMachineReadableInformation`, so
  an issued credential carries a one-term **inline** context mapping it to
  `https://w3id.org/vc-barcodes#IsoDrivingLicenceMachineReadableInformation`,
  the vocabulary every other term there is in. Inventing a context URL for
  somebody else's vocabulary would be worse than the ~120 bytes it costs.
  CBOR-LD carries an embedded context as a plain map, and the library writes
  the same bytes for it. A credential naming the type by its full IRI reads
  the same.
- **base64url is unpadded** (RFC 4648 section 5 without `=`): the TR says
  only "a base64url encoding", and unpadded is what Data Integrity and the
  TR's own multibase values use.
- **The data groups are given already separated.** The TR's optical data is
  the licence's compact encoding "as delimited by the data group delimiter
  character", and that encoding is ISO/IEC 18013-2's, which is not freely
  available. So the page and `vc_barcodes.js` take `DGn: contents` lines —
  text with `\n`, `\r`, `\t`, `\\` and `\xNN` escapes, or `hex:` and hex —
  rather than guess at a delimiter, and draw no ISO symbol for the same
  reason.
- **DG11 is the whole credential field**, with or without a multibase `u`.

## Status

A `TerseBitstringStatusListEntry` expands (with the list length and purpose
the verifier supplies, section 3.2.3) to a `BitstringStatusListEntry`, and
the page's **Check the Status List** pane checks it with
`vp_verifier.js`'s `checkBitstringStatus()` — the reader the Verifier role
uses for a presentation's `credentialStatus`, exported for this, so the two
pages cannot disagree about a list. It fetches the status list credential
**from the browser** (a server without CORS headers cannot be read by a
page, and the message says so), or reads one pasted in; verifies its proof
(Data Integrity, or a VC JWT); checks its type, `statusPurpose` and validity;
inflates the GZIP bitstring (`DecompressionStream`, capped at 16 MiB) and
reads the entry MSB first. The verdict is REVOKED / NOT REVOKED (SUSPENDED
for that purpose) only when the list verified; a bit from a list that did not
is UNVERIFIED and not relied on. A list issuer other than the barcode's is a
note, not a failure (Bitstring Status List section 2.2 allows it).

`tests/vc_barcodes_engine.js` holds it to Digital Bazaar's
`@digitalbazaar/vc-bitstring-status-list` 2.0.1 both ways: their list, signed
with their `ecdsa-rdfc-2019`, at the URL the specification's driver's licence
expands to (entry 8321, list 29385, with `listLength` 2^17) read here; a list
packed and gzipped by the test and signed with `data_integrity.js`, accepted
by their `checkStatus()`, which reads the same bits. The browser test serves
their list from a local server with CORS and checks it fetched and pasted.

## PDF417 symbols

The page draws the AAMVA licence text — with the ZZ subfile it added — as a
PDF417 symbol (bwip-js, error correction level 5, which AAMVA's Annex D
recommends), and the read pane's **Draw as PDF417** draws whatever text is in
the barcode box, the specification's example included. **Barcode image**
reads a QR code (jsQR) or, failing that, a PDF417 symbol (@zxing/library's
`PDF417Reader` and `HybridBinarizer`, required by path so no other ZXing
reader is bundled) from a picture, in the page. The SVG is the encoder's
rectangles: none of the text reaches the markup. The browser test draws,
saves, uploads and re-reads both the issued licence and the specification's
example and verifies each; the engine test rasterises the symbol's modules at
three scales and reads them back in node.

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

Read and verify: paste the QR text, the whole AAMVA PDF417 text, an ISO
licence's data groups, the field alone or hex, or read a QR code or PDF417
symbol from an image, in the page. PDF417 text carries control characters
(RS, CR), shown and read as `\x1e` and `\r`. Three links load the
specification's two Utopia examples and the ISO example above.

Check the status list: Verify fills in the expanded entry; **Fetch and
Check** fetches it, **Check Pasted** reads a pasted list instead.

Issue: generate a P-256 or P-384 key (its did:key is the issuer), choose the
document type and, for AAMVA or ISO, the fields or data groups to protect,
and issue. An MRZ credential is drawn as a QR code in alphanumeric mode; an
AAMVA one is added to the licence's PDF417 text as subfile `ZZ`, with the
header's designators rewritten, and the whole is drawn as a PDF417 symbol; an
ISO one is put in DG11 of the data groups.

**Nothing on the page is stored**, the private key included:
`tests/vc_barcodes_browser.js` checks both storages are empty afterwards. A
barcode is issued once and printed; a key kept in a browser for that is kept
for no reason. Download it if it is needed again.

## Not done

- **Splitting an ISO/IEC 18013-2 compact encoding into data groups, and
  drawing an ISO licence's PDF417.** Both are ISO/IEC 18013-2's, which is not
  freely available; the page takes the data groups already separated and
  draws no ISO symbol rather than guess at the delimiter.
- **The ISO type in a published context.** Until one defines it, an issued
  ISO credential carries the inline context above.
