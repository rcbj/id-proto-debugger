# AnonCreds (`anoncreds`)

Issue #479 (phase 5 of #474). AnonCreds 1.0 (Hyperledger) with CL
signatures, for the **holder** and the **Verifier**, without revocation.
It's pure JS (BigInt) in the browser, as every cryptographic engine here is.

**The witness is anoncreds-rs**, the implementation the AnonCreds ecosystem
runs. The specification publishes no test vectors, and CL is the kind of
code that verifies its own proofs perfectly while interoperating with
nothing. So every test holds this tree to anoncreds-rs itself.

## Modules

| Module | What it is |
|---|---|
| `client/src/anoncreds.js` | The engine, with no DOM: the credential request (key correctness proof checked, link secret blinded), processing the issued credential, presentations (revealed attributes and groups, unrevealed and self-attested referents, all four predicate types, several credentials under one link secret) and verification. Its API mirrors anoncreds-rs's over the same JSON. |
| `client/src/anoncreds_wallet.js` | What the wallet needs around it: the held bundle, the link secret as a holder key, and the OpenID4VP mapping below. |

## What decides interoperability

Each of these was checked against anoncreds-rs v0.2.3 /
anoncreds-clsignatures 0.3.2:

- **Hashing.** Every hash is SHA-256 over the plain concatenation of each
  number's minimal big-endian bytes, with the sign dropped and zero as no
  bytes at all. The digest is read as an unsigned big-endian integer.
- **The presentation challenge** covers every sub-proof's tau items, then
  every `c_list` item, then the request's nonce. It doesn't cover the
  revealed values, `m2` or the public key.
- **The `e` response** is offset by 2^596, and the verifier puts it back.
- **Attribute names inside CL** have their spaces removed and are
  lower-cased. The link secret is the hidden attribute `master_secret`,
  with one random witness shared by every sub-proof.
- **Attribute values** that parse as an `i32` are that integer. Anything
  else is the SHA-256 of its UTF-8 bytes, read big-endian.
- **The key correctness proof** is hashed in the order the issuer sent
  `xr_cap`.

**The verifier checks three things anoncreds-rs 0.2.3 does not:**

1. That each predicate in the proof is the one the request asked for.
   anoncreds-rs never compares `p_value`, and `tests/anoncreds_engine.js`
   shows it accepting a proof of `age <= -7` against a request for
   `age <= -8`.
2. That `c_list` is the A′ and T values the sub-proofs carry.
3. That a revealed raw value encodes to its encoded value. A mismatch is a
   warning, because AnonCreds signs only the encoding.

## In the wallet

Neither OpenID4VCI 1.0 nor OpenID4VP 1.0 defines AnonCreds, so what
follows is **this debugger's mapping**, and the UI says so.

- **The held credential is a bundle,** because presenting needs the
  schema and credential definition, and a wallet with no ledger can't
  fetch them:

  ```json
  { "format": "anoncreds", "credential": {...}, "schema": {...},
    "schema_id": "...", "credential_definition": {...}, "cred_def_id": "..." }
  ```

- **The link secret is the holder's key material,** so it sits where the
  holder key does (`sdjwtvc_holder_private_jwk`), behind the same save-key
  preference and paste field. It's an `oct` JWK, `alg:
  "AnonCreds-link-secret"`, whose `k` is the secret's big-endian bytes.
- **An OpenID4VP request becomes an AnonCreds presentation request:**
  - one requested attribute per DCQL claim, its referent the attribute's
    name;
  - the AnonCreds nonce, which must be decimal digits: the OpenID4VP
    nonce when it already is, otherwise the decimal of the first 80 bits
    of SHA-256 over its UTF-8 bytes.
- **What's sent** is the presentation's JSON. Presentation step 3
  re-verifies it with `anoncreds.js` under the same mapping, and issuance
  step 3 re-checks the held credential's CL signature with the link secret.

No issuer in this stack mints AnonCreds. The tests have anoncreds-rs
issue to our holder and put the bundle in the wallet's storage.

## The witness, and why it is native

`@hyperledger/anoncreds-nodejs` 0.5.0 loads anoncreds-rs v0.2.3's
`libanoncreds.so`, and its install script downloads that library from
GitHub. That breaks the rule that a tests-image build downloads nothing,
so:

- `tests/anoncreds-witness/Dockerfile` installs the binding with
  `--ignore-scripts` from its lock file, adds the library by
  `ADD --checksum`, and writes the `version.json` the script would have
  written. It is built into the private mirror as
  `anoncreds-witness:0.5.0-0.2.3` (`.github/image-mirror-builds.txt`).
- `tests/Dockerfile` copies that tree to `/usr/src/anoncreds-witness`.
- `tests/anoncreds_witness.js` finds the witness there, in
  `ANONCREDS_WITNESS_DIR`, or in a host cache copied once out of the
  mirror image. Without it the jobs FAIL, naming the image.

Native code is used in the tests only. The browser-side engine is pure JS.

## Revocation

`client/src/anoncreds_revocation.js`, over `client/src/amcl_bn254.js`:
the CKS accumulator and the non-revocation proof, for the holder and the
Verifier.

**The curve is not alt_bn128.** anoncreds-clsignatures uses Apache Milagro's
"BN254", which is Nogami's Barreto–Naehrig curve. `amcl_bn254.js` builds
it over `@noble/curves` 1.9's field tower, added under the alias
`@noble/curves-v1.9` so nothing using 1.4.0 changes:

| | |
|---|---|
| BN `x` | −(2⁶² + 2⁵⁵ + 1) |
| G1 | y² = x³ + 2, generator (−1, 1) |
| Fp2 | Fp[i]/(i²+1) |
| ξ | 1 + i |
| G2 | the D-type twist y² = x³ + (1 − i) |

**The pairing must be bit-identical to amcl's,** because pairing values
are hashed into the proof's challenge. So it is the optimal ate pairing
written plainly in Fp12, with the exact final exponentiation
`f^((p¹²−1)/r)`. It is checked against anoncreds-rs's own data by the
holder's equation `e(g_i, V) · e(−g, ω) = accumKey.z`.

**amcl's encodings:**
- **JSON text:** Montgomery residues in homogeneous projective coordinates
  (`"xes HEX"` tokens, R = 2²⁸⁰).
- **Challenge-hash bytes:** fixed-length and affine. G1 is `04‖x‖y`
  followed by 63 zero bytes; G2 is 128 bytes; GT is 512 bytes.

**What it does:**
- **Request:** blinds `vr′` as `ur = vr′·h2`.
- **Processing:** sets `vr = vr′ + vr″` and runs the three pairing checks.
- **Revocation state:** comes from the tails file. That file is `00 02`
  followed by 2L+1 G2 points. Its name, `tailsHash`, is the base58 of its
  SHA-256, which is checked here although anoncreds-rs does not check it.
- **Witness:** the sum of `tail[L+1−j+i]` over the issued `j ≠ i`. Both
  readings of index L are tried and the one that verifies is kept, because
  anoncreds-rs's own holder always counts it as issued. That is right for
  an issuance-by-default registry and wrong for an on-demand one, which the
  engine test covers.
- **The proof:** the seven commitments and eight tau values go ahead of
  the sub-proof's primary items. They share the primary proof's `m̃2`; the
  Verifier uses the primary `m̂2` reduced mod r, which ties the two proofs
  to one credential.
- **The Verifier:** applies anoncreds-rs's interval and timestamp rules,
  and selects the status list by exact `(revRegDefId, timestamp)`. It is
  **stricter than anoncreds-rs 0.2.3** in two ways:
  - It requires a non-revocation proof whenever an interval applies to a
    revocable credential. anoncreds-rs verifies such a sub-proof as if none
    had been asked for.
  - It checks that the `c_list` bytes match the proof's points.

**In the wallet,** a revocable bundle carries the revocation material, and
the debugger's mapping asks for non-revocation at the status list's
timestamp:

```json
"revocation": { "registry_definition": {...}, "status_list": {...},
                "tails": "<base64url>" }
```

## The W3C form

`client/src/anoncreds_w3c.js` reads and writes AnonCreds credentials and
presentations as W3C VC Data Model documents with a Data Integrity proof whose
cryptosuite is `anoncreds-2023`, in the form anoncreds-rs 0.2.3 writes. It is
a **re-encoding**, not another signature scheme: the CL signature and proofs
are the legacy objects `anoncreds.js` already makes and checks.

- **The attribute values** go into `credentialSubject`, raw, with an integer
  as a JSON number. A predicate's attribute appears there as `true`.
- **Everything else** goes into the `proofValue`: `u` plus base64url of
  MessagePack (`client/src/msgpack.js`) of `[kind, object]`. Kind `1` is a
  credential's signature, `2` a credential's sub-proof inside a presentation,
  and `3` the presentation's aggregated proof.
- **Every big number** is converted from a decimal string to its big-endian
  bytes. The ids, and `c_list` (already bytes), are left as they are.

`tests/anoncreds_engine.js` checks both directions against anoncreds-rs:

- its W3C credential is processed here;
- our W3C credential reads back in anoncreds-rs to the same signature;
- our W3C presentation is verified by it, and its W3C presentation by us;
- **with revocation**: its revocable W3C credential (`revocationConfiguration`)
  is processed here, our W3C presentation with a non-revocation proof is
  verified by it and its (with a revocation state and timestamp) by us, it
  presents from OUR revocable W3C credential, and the proof fails after
  revocation.

The revocation members (`r_credential`, `rev_reg`, `witness`, a sub-proof's
`non_revoc_proof`) carry amcl BN254 values: amcl's text in the legacy JSON,
bytes in the W3C form — a G1 or G2 point as 128 bytes, a group-order element
as 32. Both point types are 128 bytes, so the type comes from the member's
name (`REV_SCHEMA` in `anoncreds_w3c.js`), and a member it does not name is
refused rather than guessed.

**In the wallet,** a held bundle whose `credential` is in the W3C form is used
like any other, and its presentation goes out in the W3C form too
(`tests/anoncreds_presentation.js`, the `w3c` case).

## Not yet

- Nothing on predicates is pending here. They can be asked for over
  OpenID4VP now: in DIF Presentation Exchange (the OpenID4VP drafts), or in
  DCQL through this debugger's critical extension. See `docs/v0.9.5/predicates.md`.

## Tests

| Test | What it checks |
|---|---|
| `tests/anoncreds_engine.js` | Revocation in both issuance modes: our request, processing, witness and non-revocation proof verified by anoncreds-rs, anoncreds-rs's proof verified here, a stripped proof named, and a revoked credential refused. Plus: the hash vector and twelve attribute encodings. Then anoncreds-rs issuing against our requests, and both holders reaching the same `v`. Then our presentations verifying in anoncreds-rs and its presentations here: two credentials, groups, unrevealed and self-attested referents, all four predicate types including over a negative value, and restrictions. Plus the negative cases. |
| `tests/anoncreds_presentation.js` | The presentation pages in Chrome, plain and revocable (with a non-revocation proof). anoncreds-rs issues, the wallet reveals two of three attributes under a non-numeric OpenID4VP nonce, and anoncreds-rs verifies. |
