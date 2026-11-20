# Gordian Envelope

#480, phase 6 of #474. **Gordian Envelope** (IETF draft
`draft-mcnally-envelope-12`) over **dCBOR** (`draft-mcnally-deterministic-cbor-18`),
on `gordian-envelope.html`. Both are **drafts**, and the page says so.

| File | What it is |
|---|---|
| `client/src/gordian_envelope.js` | dCBOR (strict decoder), the envelope cases and digests, UR, keys and signatures (Schnorr, ECDSA, Ed25519, ML-DSA, SSH), elision, notation |
| `client/src/gordian_envelope_crypto.js` | the obscuring cases: encryption, recipients (X25519, ML-KEM), password locks, compression, SSKR shares |
| `client/src/sskr.js` | Shamir in GF(2^8) and SSKR (BCR-2020-011), bc-shamir 0.13 / sskr 0.12 |
| `client/src/bc_ur.js` | UR, bytewords and CRC-32, and multi-part URs with their fountain code (BCR-2020-005, BCR-2024-001), the ur 0.4.1 crate |
| `client/src/gordian_envelope_page.js` | the page (bundle global `gordianenvelopepage`) |
| `tests/gordian_envelope_engine.js` | node: the drafts' and the Rust crates' own test vectors, and bc-envelope-cli both ways |
| `tests/gordian_envelope_browser.js` | Chrome: issue, verify, present, salted Ed25519, encrypt, compress, SSKR, multi-part, ML-DSA, SSH |

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

The obscuring half is held to it **both ways**: the CLI decrypts what we
encrypt (seven envelope shapes) and we decrypt what it encrypts; the same for
compression, X25519 and ML-KEM-512/768/1024 recipients (its `generate
prvkeys`/`pubkeys` from a seed are byte for byte ours), PBKDF2, scrypt and
Argon2id password locks, SSKR `split`/`join` (two groups), ML-DSA-44/65/87
signatures, and SSH signatures — Ed25519 from a seed byte for byte, ECDSA
P-256 and P-384 by verification. The crates' own vectors are reproduced too:
bc-components' RFC 8439 `EncryptedMessage` (its CBOR and `ur:encrypted`), its
`Compressed` checksums, bc-envelope's compressed-subject tree, the sskr
crate's shares for its three test splits (it prints them; its counting RNG is
reproduced) and bc-shamir's recovery example, and the ur crate's single-part
and twenty-part vectors, fountain parts included.

**The CLI has no multi-part URs**, so they are held to the ur 0.4.1 crate's
vectors (bc-ur 0.19.2's `MultipartEncoder` is a thin wrapper over it). On
2026-11-18 they were also checked once, by hand, against a small program over
the released bc-ur 0.19.2: eighty parts of a 2101-byte envelope identical,
and each side rebuilt the other's from mixed parts with fragments missing.

## What costs a day if missed

| Rule | |
|---|---|
| A leaf's digest is SHA-256 of its dCBOR **without** tag 201 | the draft's `65 48656C6C6F` example |
| A known value is a **bare uint** on the wire and hashed as `40000(n)` | `'signed'` is the byte `03`; `ur:envelope/axgrbdrnem` |
| Tag 200 is the top level and the **wrapped** case only; a UR body is untagged | an inner `d8c8` always means wrapped |
| A node's assertions are in **digest** order | Carol before Bob in the draft's example |
| A signature covers the 32 raw bytes of the subject's digest | Schnorr and Ed25519 as they are; **ECDSA signs SHA-256(SHA-256(digest))** |
| dcbor 0.25.2 writes 65-bit negatives (`3b` with the top bit set) | the draft forbids them; Rust writes them, so this reads them |
| An encrypted element's plaintext is the **tagged** element, `200(...)`; its AAD the dCBOR of `40001(digest)` | for a node only the SUBJECT is encrypted, and the assertions stay outside |
| A compressed element is `[crc32, size, data, 40001(digest)]`, raw DEFLATE, or the bytes themselves when DEFLATE does not shrink them | the compressed bytes are fflate's, not miniz's (286 bytes here where bc-envelope's test has 283); the digest does not cover them, so both read both |
| A recipient's content key is sealed as the dCBOR of `40023(key)`; X25519 shares are HKDF-SHA-256(DH, salt `"agreement"`) | a key pair from a seed is HKDF(seed, `"agreement"`), as `PrivateKeyBase` derives it |
| An EncryptedKey's plaintext is the content key's **raw** 32 bytes; its AAD its parameters | Argon2id is the argon2 crate's defaults (v19, m = 19456 KiB, t = 2, p = 1) |
| The CLI does not count an HKDF lock as a password | `decrypt --password` refuses one; this page reads and writes it |
| An SSH signature is an armored SSHSIG over the digest's 32 bytes, namespace `envelope`, SHA-256 | an SSH Ed25519 key from a seed is HKDF(seed, `"ssh-ed25519-0"`), the first page of `HKDFRng` |
| ML-DSA signs the digest's 32 bytes, pure, empty context; keys and signatures are `[level, bytes]` with level 2, 3 or 5 | bc-components derives no ML-DSA key from a seed |
| A multi-part UR's floating point is the crate's: a double is `u64 / 2^64`, the alias table summed in order | a different rounding picks different fragments and the parts are another stream |

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
  `date 2020-01-01` is a Date, a whole number is a number), with Schnorr, ECDSA,
  Ed25519, ML-DSA-44/65/87 or SSH Ed25519, optionally salting every claim. A
  link loads the Rust tests' example credential. bc-components derives no
  ML-DSA key from a seed; the page uses HKDF(seed, `"signing"`) as FIPS 204's
  key-generation seed, and says so.
- **Encrypt and Decrypt** (collapsed): the subject, or the whole envelope
  wrapped first, under a content key, sealed to `ur:crypto-pubkeys` recipients
  (X25519 or ML-KEM, and a button that makes one), and/or locked with a
  password (Argon2id, PBKDF2, scrypt or HKDF). Decrypt with the key, a
  recipient's private keys or the password.
- **Compress and Decompress** (collapsed): the envelope or only its subject.
- **SSKR: Split and Join** (collapsed): groups as `m-of-n` and a group
  threshold, as `envelope sskr split`; join from any shares, in any order.
- **Multi-part UR** (collapsed): parts of a chosen fragment size, plus fountain
  parts; join from any parts. The first pane reads parts directly too.

**Nothing on the page is stored**: the seed, content keys, private keys and
passwords live in their fields for the page load.

## Not done

- **SSH-agent locks** (`'hasSecret'` with the SSH-agent derivation) need an
  agent; a browser has none, so they are refused by name.
- **SSH DSA and RSA** signatures: Ed25519 and ECDSA P-256/P-384 only. No DSA
  or RSA SSH signing in the pure-JS libraries this page uses, and an SSH key
  from a seed is derived for Ed25519 only (ECDSA SSH keys are read from
  `ur:crypto-prvkeys`).
- **Multi-part URs** are not witnessed by bc-envelope-cli, which has none; the
  ur crate's vectors and the one-off bc-ur check above stand in.
