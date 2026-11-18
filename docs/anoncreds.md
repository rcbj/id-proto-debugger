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

## Not yet

- **Revocation:** CKS accumulators, `non_revoc_proof`. A presentation
  carrying a non-revocation proof is refused by name, not passed.
- **The W3C form** (`anoncredsvc-2023` / `anoncredspresvc-2023`).
- **Predicates from DCQL,** which has no way to express them.

## Tests

| Test | What it checks |
|---|---|
| `tests/anoncreds_engine.js` | The hash vector and twelve attribute encodings. Then anoncreds-rs issuing against our requests, and both holders reaching the same `v`. Then our presentations verifying in anoncreds-rs and its presentations here: two credentials, groups, unrevealed and self-attested referents, all four predicate types including over a negative value, and restrictions. Plus the negative cases. |
| `tests/anoncreds_presentation.js` | The presentation pages in Chrome. anoncreds-rs issues, the wallet reveals two of three attributes under a non-numeric OpenID4VP nonce, and anoncreds-rs verifies. |
