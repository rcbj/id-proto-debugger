# AnonCreds (`anoncreds`)

**AnonCreds 1.0** (the Hyperledger AnonCreds Specification v1.0) with
Camenisch–Lysyanskaya (CL) signatures, for the **holder**, the wallet's own
re-check and the **Verifier page**, **with revocation**, in both the legacy
JSON form and the **W3C form** (`anoncreds-2023`). The cryptography runs in
the page, in pure JavaScript.

**Neither OpenID4VCI 1.0 nor OpenID4VP 1.0 defines AnonCreds.** How the
wallet holds one, and how an OpenID4VP request becomes an AnonCreds
presentation request, is *this debugger's mapping*, and the pages say so.

**Predicates** (`>=`, `>`, `<=`, `<` on an integer attribute) are proved in
zero knowledge, natively. They reach the wallet from a Presentation Exchange
2.1.1 request or from this debugger's DCQL predicate extension; see
[presentation-exchange.md](presentation-exchange.md) and
[tutorial-predicates.md](tutorial-predicates.md).

## What the debugger allows (`client/src/vc_formats.js`)

| | |
|---|---|
| Format identifier | `anoncreds` (the debugger's own name) |
| Signature | `CL` |
| Binding | `link_secret`: the holder's link secret, a hidden attribute of every credential |
| Key proof types | none |
| Holder binding | a zero-knowledge proof under the holder's link secret |
| Selective | yes, attribute by attribute |

## How the wallet holds one

Presenting needs the schema and the credential definition, and a wallet with
no ledger cannot fetch them, so the held credential is a **bundle**:

```json
{ "format": "anoncreds", "credential": {...}, "schema": {...},
  "schema_id": "...", "credential_definition": {...}, "cred_def_id": "...",
  "revocation": { "registry_definition": {...}, "status_list": {...},
                  "tails": "<base64url>" } }
```

`revocation` is there only for a revocable credential. `credential` may be in
either form: the legacy JSON anoncreds-rs writes, or the W3C form below. The **link secret is
key material**: it is held where the holder key is, as an `oct` JWK with
`alg: "AnonCreds-link-secret"`, behind the same save-key preference and the
same paste field on the presentation pages.

**Getting one.** No OpenID4VCI issuer issues AnonCreds, and no issuer in the
suite's stack does. The suite's tests have anoncreds-rs (the implementation
the AnonCreds ecosystem runs) issue to the debugger's holder and put the
bundle and link secret in the wallet's storage. There is no
paste-a-credential field on the pages.

## Where it appears

### Issuance step 3

| Check | What passes |
|---|---|
| Format | the attribute count, the schema id and the credential definition id, with the note that neither OpenID4VCI nor OpenID4VP defines AnonCreds |
| Issuer signature | the CL signature verifies under the credential definition's key and this holder's link secret. Without the link secret it cannot be checked, and the row says so |

### Presentation: as a wallet

The OpenID4VP request is mapped to an AnonCreds presentation request:

* one requested attribute per DCQL claim, its referent the attribute's name;
* the AnonCreds nonce must be decimal digits: it is the OpenID4VP nonce when
  that already is, otherwise the decimal of the first 80 bits of SHA-256 over
  the nonce's UTF-8 bytes;
* for a revocable bundle, a **non-revocation proof** is asked for at the
  status list's timestamp.

* each requested predicate becomes an AnonCreds `requested_predicates`
  entry, proved without revealing the value.

What is sent is the presentation's JSON — in the W3C form when the held
credential is. Step 3 re-verifies it under the same
mapping with the bundle's schema and credential definition: one row, *AnonCreds
presentation (CL)*, naming how many attributes were revealed, the nonce used,
and the status list timestamp when there was a non-revocation proof, plus a
*Note* per warning. A revealed raw value that does not encode to its signed
encoding is a warning, because AnonCreds signs only the encoding.

### The Verifier page

`vc-verifier.html` asks for AnonCreds under the format `anoncreds` (this
debugger's identifier; OpenID4VP has none) and verifies the answer, in either
form. A Verifier with no ledger is given the issuer's schema and credential
definition — and, for a revocable credential, its registry definition, status
list and tails — out of band: paste an AnonCreds bundle into **AnonCreds
issuer material** (`vpv_anoncreds_material`, never stored). Without it the
answer is *incomplete*, not passed. The rows:

| Check | What passes |
|---|---|
| The presentation is an AnonCreds presentation | the legacy JSON or the W3C form (`anoncreds-2023`) |
| The AnonCreds proof verifies (CL) | the CL proof verifies under the request the Verifier derived (the nonce mapped as above), including the non-revocation proof when a status list applies; SKIP without the issuer material or the status list |
| Predicate *name* *op* *value* | one row per requested predicate: the proof proves the predicate the request asked for |
| Every requested claim is disclosed | every requested attribute is revealed |

## The W3C form

`client/src/anoncreds_w3c.js` reads and writes AnonCreds credentials and
presentations as W3C VC Data Model documents with a Data Integrity proof
whose cryptosuite is `anoncreds-2023`, in the form anoncreds-rs 0.2.3 writes.
It is a re-encoding, not another signature scheme: the attribute values go
into `credentialSubject` (a predicate's attribute appears there as `true`),
and the CL signature or proof goes into the `proofValue` as `u` plus
base64url of MessagePack. **Revocation is carried too**: a revocable W3C
credential, and a W3C presentation with a non-revocation proof, are read and
written, with the BN254 values as bytes.

A held bundle whose `credential` is in the W3C form is presented in the W3C
form, and a DCQL or Presentation Exchange query naming the `di_vc` format is
accepted for it. The suite holds both directions to anoncreds-rs itself.

## Revocation

AnonCreds revocation is the CKS accumulator with a tails file, over Apache
Milagro's BN254 curve (not alt_bn128). The holder computes its witness from the
tails file (whose name, `tailsHash`, is checked here) and proves its index is
not revoked against the status list. The debugger's verifier is stricter than
anoncreds-rs 0.2.3: it requires a non-revocation proof whenever an interval
applies to a revocable credential, and checks each predicate against the one
the request asked for. The details are in
[anoncreds.md](../anoncreds.md#revocation).

This is AnonCreds' own revocation. The IETF and W3C status lists are a
different mechanism: [status-lists.md](status-lists.md).

## Related

* [AnonCreds developer notes](../anoncreds.md)
