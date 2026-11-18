# Gordian Envelope (`gordian-envelope.html`)

**Gordian Envelope** (`draft-mcnally-envelope-12`) over **dCBOR**
(`draft-mcnally-deterministic-cbor-18`). Both are **IETF Internet-Drafts**,
and the page says so. The reference implementation the code is held to is
Blockchain Commons' released Rust crates (bc-envelope 0.43.0, dcbor 0.25.2).

This format is outside OpenID4VCI and OpenID4VP. It is reached only through
its own page, linked from the **VC Tools** pane of every VC issuance and
presentation page. **Nothing on the page is stored**, the seed included.

## What the specification says

* An envelope is a **Merkle tree of digests**. A credential is a subject (an
  ARID) carrying assertions (`predicate: object`), **wrapped** and then
  **signed**: the signature covers the wrapped envelope's digest, and so every
  claim inside it.
* A holder presents by **eliding** claims: each is replaced by its digest.
  Every digest above it is unchanged, so the issuer's signature still
  verifies, and nobody re-signs.
* A **salt** assertion on each claim stops an elided claim (`"firstName":
  "John"`) from being guessed from its digest.
* Signatures here are Schnorr (BIP-340), ECDSA on secp256k1, or Ed25519, over
  the subject's digest.

## The page

### Read, Verify and Present

| Field | What it takes |
|---|---|
| Envelope | `ur:envelope/…`, or the hex of its CBOR (`d8c8…`). **Read** shows its notation and digest tree, and the root digest |
| Issuer key | `ur:signing-public-key/…`, `ur:crypto-pubkeys/…`, or hex: 32 bytes for a Schnorr x-only key, 33 for a compressed ECDSA key |
| Disclose | one checkbox per claim. Everything unticked is elided |

* **Verify** reports *VALID* (the scheme, and the subject digest the
  signature covers) or *INVALID* with the reason.
* **Present** produces a `ur:envelope` with the unticked claims elided, and
  checks that the root digest is unchanged, so the signature still holds. It
  says how many claims were disclosed. **Verify It** hands the presentation
  back to the read pane.

A decoded node whose assertions are out of digest order, or repeated, is
refused: the draft says MUST NOT.

### Issue a Credential

| Field | What it takes |
|---|---|
| Issuer seed | a PrivateKeyBase seed (hex); the signing key is HKDF-SHA-256 of it with the salt `"signing"`. **Generate** makes one |
| Signature scheme | Schnorr (BIP-340, the default), ECDSA secp256k1, or Ed25519 |
| Subject ARID | 32 bytes of hex, or empty for a random one |
| Claims | one `predicate: value` per line. `'isA'` in single quotes is a known value, `date 2020-01-01` a Date, a whole number a number, anything else text |
| Salt claims | give every claim its own salt |

**Issue** wraps, then signs. A link loads bc-envelope's *Certificate of
Completion* example.

## Not implemented

Decrypting encrypted elements and decompressing compressed ones (their digests
are carried and verified); SSKR, recipients, ML-DSA and SSH signatures, and
multi-part URs.

## Related

* [Gordian Envelope developer notes](../gordian-envelope.md)
