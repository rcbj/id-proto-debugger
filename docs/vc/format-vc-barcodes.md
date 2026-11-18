# VC Barcodes (`vc-barcodes.html`)

W3C **Verifiable Credential Barcodes v1.0** (a **Working Draft**, the 22
August 2026 one) over **CBOR-LD 1.0**: a credential printed on a physical
document, signed over what that document already prints in machine-readable
form, so that a barcode copied onto a forged document does not verify.

This format is outside OpenID4VCI and OpenID4VP. It is reached only through
its own page, linked from the **VC Tools** pane at the bottom of every VC
issuance and presentation page ("Other credential formats"). Nothing on the
page is fetched from an issuer and **nothing on it is stored**, the private
key included.

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

## The page

### Read and Verify a Barcode

| Field | What it takes |
|---|---|
| Barcode | the QR text (`VC1-…`), the whole AAMVA PDF417 text, the credential field alone, or hex. Two links load the specification's examples |
| QR image | a picture of a QR code, decoded in the page with no network. PDF417 symbols are **not** decoded from images; paste what a scanner reads. Control characters in PDF417 text are shown and read as `\x1e` and `\r` |
| MRZ | the MRZ lines the document prints, for a `MachineReadableZone` credential |
| AAMVA data | the licence's PDF417 text, when the barcode above is only the credential field |
| Status list length | how a terse status entry expands. The tooltip gives 2^26 (67108864) and 2^17 (131072) |
| purpose | `revocation` or `suspension`, for the expansion |

**Verify** decodes the CBOR-LD, assembles the optical data the signature
covers, and checks the `ecdsa-xi-2023` proof (whose type must be
`DataIntegrityProof`). A failure explains that the signature covers the
optical data too, so a barcode on a document that prints different data, or
MRZ / AAMVA text typed differently, fails exactly that way. A terse status
entry is shown expanded; **the status list is not fetched or checked**.

### Issue a Barcode

| Field | What it takes |
|---|---|
| Document | `MachineReadableZone` (MRZ, QR code) or `AamvaDriversLicenseScannableInformation` (AAMVA PDF417) |
| MRZ / AAMVA PDF417 | the printed data. For AAMVA, the licence text without a credential |
| Protect | AAMVA only: the mandatory fields the signature covers |
| Issuer key | P-256 or P-384. **Generate** makes a key; **Download Key** saves it, because the page keeps nothing |
| Issuer | filled with the key's `did:key`; the verification method defaults to `did:key:z…#z…` |
| Status | optional: a terse entry's base URL and 32-bit index |

**Issue** signs. An MRZ credential is drawn as a QR code (alphanumeric mode);
an AAMVA one is added to the licence's PDF417 text as subfile `ZZ`, with the
header's designators rewritten. The page draws no PDF417 symbol. **Verify It**
hands the result to the read pane.

## Not implemented

`IsoDrivingLicenceMachineReadableInformation` (informative, no vector);
fetching the status list a terse entry expands to; drawing or reading PDF417
symbols.

## Related

* [VC Barcodes developer notes](../vc-barcodes.md)
