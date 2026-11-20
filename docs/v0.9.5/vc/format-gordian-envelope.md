# Gordian Envelope (`gordian-envelope.html`)

**Gordian Envelope** (`draft-mcnally-envelope-12`) over **dCBOR**
(`draft-mcnally-deterministic-cbor-18`). Both are **IETF Internet-Drafts**,
and the page says so. The reference implementation the code is held to is
Blockchain Commons' released Rust crates (bc-envelope 0.43.0, dcbor 0.25.2,
bc-components 0.31.1), and their released command-line tool,
bc-envelope-cli 0.35.0, both ways.

This format is outside OpenID4VCI and OpenID4VP. It is reached only through
its own page, linked from the **VC Tools** pane of every VC issuance and
presentation page. **Nothing on the page is stored**: seeds, content keys, private keys
and passwords live only in their fields for the page load.

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
* Signatures here are Schnorr (BIP-340), ECDSA on secp256k1, Ed25519,
  **ML-DSA-44/65/87** (pure, over the digest's 32 bytes) or **SSH** (an
  armored SSHSIG, namespace `envelope`: Ed25519 and ECDSA P-256/P-384), over
  the subject's digest.
* Besides eliding, an element can be **encrypted** (ChaCha20-Poly1305,
  authenticated with its digest, so the digests above it and any signature do
  not change), **compressed** (raw DEFLATE, carrying the uncompressed
  element's digest), or its content key split into **SSKR** shares (Sharded
  Secret Key Reconstruction, BCR-2020-011). An envelope too large for one QR
  code travels as a **multi-part UR** with fountain parts (BCR-2020-005,
  BCR-2024-001).

## The page

### Read, Verify and Present

| Field | What it takes |
|---|---|
| Envelope | `ur:envelope/…`, every part of a multi-part UR (one per line, any order, fountain parts too), or the hex of its CBOR (`d8c8…`). **Read** shows its notation (obscured elements as ELIDED, ENCRYPTED or COMPRESSED), its digest tree, and the root digest |
| Issuer key | `ur:signing-public-key/…`, `ur:crypto-pubkeys/…` (Schnorr, ECDSA, Ed25519, ML-DSA or SSH), an OpenSSH public key line (`ssh-ed25519 AAAA…`, `ecdsa-sha2-nistp256 AAAA…`), or hex: 32 bytes for a Schnorr x-only key, 33 for a compressed ECDSA key |
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
| Issuer seed | a PrivateKeyBase seed (hex); the signing key is HKDF-SHA-256 of it with the salt `"signing"` (an SSH Ed25519 key: the salt `"ssh-ed25519-0"`). **Generate** makes one |
| Signature scheme | Schnorr (BIP-340, the default), ECDSA secp256k1, Ed25519, ML-DSA-44, ML-DSA-65, ML-DSA-87, or SSH Ed25519. bc-components derives no ML-DSA key from a seed; the page uses HKDF-SHA-256(seed, `"signing"`) as FIPS 204's key-generation seed, and says so |
| Subject ARID | 32 bytes of hex, or empty for a random one |
| Claims | one `predicate: value` per line. `'isA'` in single quotes is a known value, `date 2020-01-01` a Date, a whole number a number, anything else text |
| Salt claims | give every claim its own salt |

**Issue** wraps, then signs. A link loads bc-envelope's *Certificate of
Completion* example. A **Note** is added after signing, outside the
signature.

### Encrypt and Decrypt (collapsed)

Encrypt the subject only (the assertions stay readable, as bc-envelope-cli's
`encrypt` does) or, with **Wrap first** (the default), the whole envelope.
The content key is given (`ur:crypto-key` or hex; empty makes a random one),
and may also be:

* **sealed to recipients** — one `ur:crypto-pubkeys` per line, X25519 or
  ML-KEM-512/768/1024; each becomes a `'hasRecipient'` assertion. **Make
  Keys** makes a recipient's key pair (X25519 from a seed, or a random ML-KEM
  pair);
* **locked with a password** — Argon2id, PBKDF2-SHA-256, scrypt or
  HKDF-SHA-256, a `'hasSecret'` assertion.

**Decrypt** uses the content key, a recipient's private keys
(`ur:crypto-prvkeys`, `ur:crypto-prvkey-base`, `ur:seed` or a seed in hex),
or the password. The digests do not change, so a signature over the envelope
still verifies after decryption.

### Compress and Decompress (collapsed)

The envelope, or only its subject (**Subject only**, leaving a signature
outside). The digest is unchanged.

### SSKR: Split and Join (collapsed)

**Split** wraps and encrypts the envelope and splits its content key into
groups of shares — one `m-of-n` per group, and a group threshold — writing
one share envelope per line. **Join** rebuilds the envelope from any shares
that meet the thresholds, in any order.

### Multi-part UR (collapsed)

**Make Parts** writes `ur:envelope/<seq>-<count>/…` parts of a chosen
fragment size, plus a chosen number of fountain parts; **Join Parts**
rebuilds the envelope from any sufficient set of parts, in any order. The
first pane reads parts directly too.

## Not implemented

SSH-agent locks (a browser has no agent; refused by name); SSH DSA and RSA
signatures (Ed25519 and ECDSA P-256/P-384 only; an SSH key is derived from a
seed for Ed25519 only, and ECDSA SSH keys are read from
`ur:crypto-prvkeys`). Multi-part URs are held to the ur crate's vectors, as
bc-envelope-cli has none.

## Related

* [Gordian Envelope developer notes](../gordian-envelope.md)
* [Tutorial: issue an envelope and present it with claims elided](tutorials-tools.md#issue-a-gordian-envelope-credential-and-present-it-with-claims-elided)
