# VC Barcodes (`vc-barcodes.html`)

W3C **Verifiable Credential Barcodes v1.0** (a **Working Draft**, the 22
August 2026 one) over **CBOR-LD 1.0**: a credential printed on a physical
document, signed over what that document already prints in machine-readable
form, so that a barcode copied onto a forged document does not verify.

This format is outside OpenID4VCI and OpenID4VP. It is reached only through
its own page, linked from the **VC Tools** pane at the bottom of every VC
issuance and presentation page ("Other credential formats"). Nothing on the
page is fetched from an issuer (the status list, on request, is the one
exception, fetched by the browser) and **nothing on it is stored**, the
private key included.

## What the specification says

* Two document types:
  * **`MachineReadableZone`**: an ID card or travel document. The credential
    is a QR code beside the MRZ, and the signature covers every MRZ line,
    each followed by `\n`, in printed order.
  * **`AamvaDriversLicenseScannableInformation`**: a driver's licence. The
    credential rides inside the licence's PDF417 (subfile `ZZ`, element
    `ZZA`, as the specification's example has it). The signature covers the
    mandatory AAMVA fields a 3-byte `protectedComponentIndex` selects. **A
    field left out of the index can change and the barcode still verifies**;
    that is what the index means.
  * **`IsoDrivingLicenceMachineReadableInformation`** (Appendix B,
    **informative** and "expected to be refined"): an ISO/IEC 18013-2
    licence. The signature covers the data groups DG1–DG11 a 2-byte
    `protectedComponentIndex` selects, each as `"DGn" + base64url(contents) +
    "\n"` in data-group number order. The credential is base64url in
    **DG11**, which therefore cannot be protected.
* The proof is **`ecdsa-xi-2023`**: `ecdsa-rdfc-2019` with a third hash, of
  the optical data, appended to the signed message.
* The credential is **CBOR-LD**, registry entry 100. The QR text is `VC1-`
  followed by multibase base45; the PDF417 field is base64url.
* Status, when present, is a `TerseBitstringStatusListEntry`, which expands
  into a Bitstring Status List entry.

Where the draft's prose disagrees with the barcodes the specification itself
publishes (made by Digital Bazaar's libraries), the page follows the
barcodes; the list is in [vc-barcodes.md](../vc-barcodes.md#the-published-barcodes-win).
One of them is user-visible: the draft says a terse entry's list length MUST
be 2^26, and its own example works only with 2^17, so the length is a field.

**The ISO type has no published vector and no published context.** An issued
ISO credential carries a one-term inline context mapping the type into the
`https://w3id.org/vc-barcodes#` vocabulary, and the page takes the data
groups already separated (`DGn: contents` lines) because splitting a licence's
compact encoding is ISO/IEC 18013-2's, which is not freely available. Both
readings are recorded in [vc-barcodes.md](../vc-barcodes.md#the-iso-type-and-what-the-tr-leaves-open).

## The page

### Read and Verify a Barcode

| Field | What it takes |
|---|---|
| Barcode | the QR text (`VC1-…`), the whole AAMVA PDF417 text, an ISO licence's data groups as `DGn: …` lines, the credential field alone, or hex. Three links load the specification's QR + MRZ and driver's licence examples and an ISO licence example. **Draw as PDF417** draws the text as a PDF417 symbol |
| Barcode image | a picture of a QR code or a **PDF417 symbol**, decoded in the page with no network (QR first). Control characters in PDF417 text are shown and read as `\x1e` and `\r` |
| MRZ | the MRZ lines the document prints, for a `MachineReadableZone` credential |
| AAMVA data | the licence's PDF417 text, when the barcode above is only the credential field |
| ISO data groups | the licence's data groups, when the barcode above is only the credential field |
| Status list length | how a terse status entry expands. The tooltip gives 2^26 (67108864) and 2^17 (131072) |
| purpose | `revocation` or `suspension`, for the expansion |

**Verify** decodes the CBOR-LD, assembles the optical data the signature
covers, and checks the `ecdsa-xi-2023` proof (whose type must be
`DataIntegrityProof`). A failure explains that the signature covers the
optical data too, so a barcode on a document that prints different data, or
MRZ / AAMVA / data-group text typed differently, fails exactly that way. A
terse status entry is shown expanded, and fills in the status pane.

### Check the Status List

The expanded `BitstringStatusListEntry` (editable) is checked with the same
reader the Verifier page uses for a presentation's `credentialStatus`, so the
two pages cannot disagree about a list. **Fetch and Check** fetches the status
list credential it names from the browser (a server without CORS headers
cannot be read by a page; the page says so); **Check Pasted** reads one
pasted instead. Either way the list's proof (Data Integrity, or a VC JWT), its
type, `statusPurpose` and validity are verified, the GZIP bitstring inflated
and the entry's bit read. The verdict is REVOKED / NOT REVOKED (SUSPENDED for
that purpose) only when the list verified; a bit from a list that did not is
UNVERIFIED and not relied on. A list issuer other than the barcode's is a
note, not a failure. See [status-lists.md](status-lists.md).

### Issue a Barcode

| Field | What it takes |
|---|---|
| Document | `MachineReadableZone` (MRZ, QR code), `AamvaDriversLicenseScannableInformation` (AAMVA PDF417) or `IsoDrivingLicenceMachineReadableInformation` (ISO data groups, DG11; informative) |
| MRZ / AAMVA PDF417 / ISO data groups | the printed data. For AAMVA, the licence text without a credential; for ISO, the data groups (the credential replaces DG11) |
| Protect | AAMVA: the mandatory fields the signature covers. ISO: the data groups it covers (DG11 cannot be) |
| Issuer key | P-256 or P-384. **Generate** makes a key; **Download Key** saves it, because the page keeps nothing |
| Issuer | filled with the key's `did:key`; the verification method defaults to `did:key:z…#z…` |
| Status | optional: a terse entry's base URL and 32-bit index |

**Issue** signs. An MRZ credential is drawn as a QR code (alphanumeric mode);
an AAMVA one is added to the licence's PDF417 text as subfile `ZZ`, with the
header's designators rewritten, and the whole is **drawn as a PDF417 symbol**
(error correction level 5); an ISO one is put in DG11. **Verify It** hands the
result to the read pane.

## Not implemented

Splitting an ISO/IEC 18013-2 compact encoding into data groups, and drawing an
ISO licence's PDF417 (both ISO/IEC 18013-2's, which is not freely available);
the ISO type in a published context.

## Related

* [VC Barcodes developer notes](../vc-barcodes.md)
* [Tutorial: verify a VC barcode, then issue one](tutorials-tools.md#verify-a-vc-barcode-then-issue-one)
