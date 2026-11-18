# Gordian Envelope

#480, phase 6 of #474. **Gordian Envelope** (IETF draft
`draft-mcnally-envelope-12`) over **dCBOR** (`draft-mcnally-deterministic-cbor-18`),
on `gordian-envelope.html`. Both are **drafts**, and the page says so.

| File | What it is |
|---|---|
| `client/src/gordian_envelope.js` | dCBOR (strict decoder), the envelope cases and digests, UR, keys and signatures, elision, notation |
| `client/src/gordian_envelope_page.js` | the page (bundle global `gordianenvelopepage`) |
| `tests/gordian_envelope_engine.js` | node: the drafts' and the Rust crates' own test vectors |
| `tests/gordian_envelope_browser.js` | Chrome: issue, verify, present, salted Ed25519 |

## What it is

An envelope is a **Merkle tree of digests**. A credential is a subject (an
ARID) with assertions (`predicate: object`), **wrapped** and then **signed**:
the signature covers the wrapped envelope's digest, so every claim inside it.
A holder presents by **eliding** claims — replacing each with its digest —
and every digest above them, and so the signature, is unchanged. Nobody
re-signs. A **salt** assertion on each claim stops an elided
`"firstName": "John"` being guessed from its digest.

## The reference, and how it is held to it

The reference is Blockchain Commons' released Rust crates: bc-envelope 0.43.0,
dcbor 0.25.2, bc-components 0.31.1 and known-values 0.15.5. The only
JavaScript port is a **prerelease**, so it is not used.
`tests/gordian_envelope_engine.js` reproduces the crates' own tests' expected
values, byte for byte:

- dcbor's encode table, and its decoder's refusals;
- the draft's section 4 digest vectors;
- the **signed** vectors. These are reproducible because bc-components'
  `PrivateKeyBase` key derivation (HKDF-SHA-256, salt `"signing"`) and bc-rand's
  fake RNG (Xoshiro256**, low byte of each output) are reimplemented in the
  test. This covers the Schnorr "Hello." signature and the ECDSA one;
- the "Certificate of Completion" credential: all 49 digests of its tree, the
  holder's six-claim redaction, and the employer's countersignature.

Blockchain Commons' released command-line tool, **bc-envelope-cli 0.35.0**,
is a live witness too (`tests/gordian_witness.js`, from the private mirror's
`gordian-witness:0.35.0`, built by `tests/gordian-witness/Dockerfile`). It
computes our credentials' digests and verifies our Schnorr, ECDSA and
Ed25519 signatures; we verify what it signs, and what it elides, at the
same root digest. `GORDIAN_ENVELOPE_CLI` points the job at a binary built by
hand (`cargo install --locked bc-envelope-cli@0.35.0`).

## What costs a day if missed

| Rule | |
|---|---|
| A leaf's digest is SHA-256 of its dCBOR **without** tag 201 | the draft's `65 48656C6C6F` example |
| A known value is a **bare uint** on the wire and hashed as `40000(n)` | `'signed'` is the byte `03`; `ur:envelope/axgrbdrnem` |
| Tag 200 is the top level and the **wrapped** case only; a UR body is untagged | an inner `d8c8` always means wrapped |
| A node's assertions are in **digest** order | Carol before Bob in the draft's example |
| A signature covers the 32 raw bytes of the subject's digest | Schnorr and Ed25519 as they are; **ECDSA signs SHA-256(SHA-256(digest))** |
| dcbor 0.25.2 writes 65-bit negatives (`3b` with the top bit set) | the draft forbids them; Rust writes them, so this reads them |

A decoded node whose assertions are out of digest order, or repeated, is
**refused**. The draft says MUST NOT; Rust silently re-sorts. Rust never writes
one, so nothing is lost by refusing.

## The page

- **Read** a `ur:envelope` (or the hex of its CBOR). The page shows its notation
  and digest tree.
- **Verify** against an issuer key: `ur:signing-public-key`, `ur:crypto-pubkeys`,
  or hex.
- **Present:** tick the claims to keep and get a `ur:envelope` with the rest
  elided. It is checked to have the same root digest.
- **Issue:** from a seed and `predicate: value` lines (`'isA'` is a known value,
  `date 2020-01-01` is a Date, a whole number is a number), with Schnorr, ECDSA
  or Ed25519, optionally salting every claim. A link loads the Rust tests'
  example credential.

**Nothing on the page is stored**, the seed included.

## Not done

- **Encrypted and compressed** elements are read (their digests are carried) but
  not decrypted or decompressed.
- **SSKR**, recipients, ML-DSA and SSH signatures, and multi-part URs are not
  implemented.
