# AnonCreds (`anoncreds`)

**AnonCreds 1.0** (the Hyperledger AnonCreds Specification v1.0) with
Camenisch–Lysyanskaya (CL) signatures, for the **holder** and the wallet's own
re-check, **with revocation**. The cryptography runs in the page, in pure
JavaScript.

**Neither OpenID4VCI 1.0 nor OpenID4VP 1.0 defines AnonCreds.** How the
wallet holds one, and how an OpenID4VP request becomes an AnonCreds
presentation request, is *this debugger's mapping*, and the pages say so.

**The W3C form of AnonCreds** (`anoncredsvc-2023` / `anoncredspresvc-2023`)
**is not implemented**. Neither are predicates from DCQL, which has no way to
express one.

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

`revocation` is there only for a revocable credential. The **link secret is
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

What is sent is the presentation's JSON. Step 3 re-verifies it under the same
mapping with the bundle's schema and credential definition: one row, *AnonCreds
presentation (CL)*, naming how many attributes were revealed, the nonce used,
and the status list timestamp when there was a non-revocation proof, plus a
*Note* per warning. A revealed raw value that does not encode to its signed
encoding is a warning, because AnonCreds signs only the encoding.

### The Verifier page

`vc-verifier.html` does not request or verify AnonCreds.

## Revocation

AnonCreds revocation is the CKS accumulator with a tails file, over Apache
Milagro's BN254 curve (not alt_bn128). The holder computes its witness from the
tails file (whose name, `tailsHash`, is checked here) and proves its index is
not revoked against the status list. The wallet's verifier is stricter than
anoncreds-rs 0.2.3: it requires a non-revocation proof whenever an interval
applies to a revocable credential, and checks each predicate against the one
the request asked for. The details are in
[anoncreds.md](../anoncreds.md#revocation).

This is AnonCreds' own revocation. The IETF and W3C status lists are a
different mechanism: [status-lists.md](status-lists.md).

## Related

* [AnonCreds developer notes](../anoncreds.md)
