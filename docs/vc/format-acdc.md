# ACDC (`acdc.html`)

**Authentic Chained Data Containers**, with the parts of **CESR** and **KERI**
a verifier and an issuer need (the Trust over IP KERI Suite specifications).
The reference implementation the code is held to is **signify-ts 0.4.1**, the
released KERIA client that vLEI credentials are issued through.

This format is outside OpenID4VCI and OpenID4VP. It is reached only through
its own page, linked from the **VC Tools** pane of every VC issuance and
presentation page. **Nothing on the page is stored**: issuing makes a fresh
issuer each time, and its keys are not kept.

## What the specification says

An ACDC **carries no signature**. Its SAID (self-addressing identifier, the
digest of its own bytes) is sealed by an `iss` event in the issuer's
registry; that event is anchored by a seal in an interaction event of the
issuer's **key event log** (KEL); and the KEL is signed. Verifying a
credential means walking that chain, all of which travels in one **CESR
stream**. Revocation is a `rev` event in the same registry.

The page reads **CESR version 1**, the generation the released libraries issue
credentials in (`ACDC10JSON…`, with `vcp` / `iss` / `rev`). A version 2
message is **refused by name** rather than misread.

## The page

### Verify a Presentation

| Field | What it takes |
|---|---|
| CESR stream | the issuer's KEL, the registry inception (`vcp`), the credential's `iss` (and `rev`), and the ACDC with its `-I` seal source triple, concatenated as KERIA or keri-ts send them |
| Schema | optional: the JSON Schema the credential's `s` names |

**Verify** lists each check in the order it is walked. A failure in the chain
(the stream, the KEL, the ACDC's own SAID, the registry or the issuance) ends
the walk there:

| Check | |
|---|---|
| the CESR stream parses | and how many messages it holds |
| the issuer's KEL verifies (signatures, thresholds, chaining) | for each `icp` / `rot` / `ixn`: version string, field order and SAID; sequence and prior digest; signatures by the current keys (Ed25519, secp256k1, P-256) against a numeric threshold; on rotation, the new keys' digests are the prior event's `n` |
| the ACDC's version string and field order | |
| the ACDC's SAID is its bytes' digest | checked over the bytes received, not a re-serialization |
| section `a` / `e` / `r`'s SAID | for each section present |
| the registry inception (vcp): SAID, issuer ii, s 0 | |
| the vcp is anchored in the issuer's KEL | |
| the issuance event (iss): SAID, s 0, ri | |
| the iss is anchored in the issuer's KEL | an anchor is the KEL event the seal source couple names, whose `a` is exactly one seal |
| the ACDC's -I seal source triple names this iss | |
| the schema's $id is its SAID; the ACDC names this schema | only when a schema was given |
| a revocation (rev), anchored | only when the stream carries one: the credential is then revoked |

### Issue a Credential

| Field | What it takes |
|---|---|
| Attributes | the credential's `a` section, as JSON |
| Issuee AID | optional: `a.i`, making the credential targeted |

**Issue** makes a fresh issuer (an Ed25519 inception), a no-backer registry,
the credential and its issuance, each anchored by its own interaction event,
and shows the stream and the schema. **Revoke** adds an anchored `rev` to the
last credential issued. **Verify It** hands the stream to the verify pane.

## Not implemented

CESR version 2 (keri-ts's default KEL), CBOR and MessagePack bodies; weighted
thresholds (refused by name); delegated identifiers; witness receipts as a
requirement; backer registries; full JSON Schema validation (only the
schema's SAID is checked); fetching chained credentials named by edges;
selective disclosure; IPEX grant messages.

## Related

* [ACDC developer notes](../acdc.md)
