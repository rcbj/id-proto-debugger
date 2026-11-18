# ACDC

#480, phase 6 of #474. **Authentic Chained Data Containers**, with the parts
of **CESR** and **KERI** a verifier and an issuer need (Trust over IP KERI
Suite specifications), on `acdc.html`.

| File | What it is |
|---|---|
| `client/src/acdc.js` | CESR v1 primitives and attachments, SAIDs, KEL / registry / ACDC verification, issuance and revocation |
| `client/src/acdc_page.js` | the page (bundle global `acdcpage`) |
| `tests/acdc_engine.js` | node: both ways with signify-ts 0.4.1, and the specifications' vectors |
| `tests/acdc_browser.js` | Chrome: signify-ts's stream verifies, issue, revoke, tamper |

## How an ACDC is verified

An ACDC carries **no signature**. Its SAID, the digest of its own bytes, is
sealed by an `iss` event in the issuer's registry. That event is anchored by a
seal in an `ixn` of the issuer's KERI key event log (KEL), and the KEL is
signed. So `verifyPresentation()` walks:

1. **The KEL** (`icp`, `rot`, `ixn`). For each event it checks:
   - the version string, the field order and the SAID;
   - the sequence and the prior digest;
   - signatures by the current keys (Ed25519, secp256k1, P-256) against a
     numeric threshold;
   - on rotation, that the new keys' digests are the prior event's `n`.
2. **The registry inception** (`vcp`). Its SAID with `i == d`, `ii` = the
   credential's issuer, `s == 0`, anchored.
3. **The issuance** (`iss`) and, if present, the revocation (`rev`). Each is
   anchored. An anchor is the KEL event its `-G` seal source couple names,
   whose `a` is **exactly one** seal `{i, s, d}` of it, as keri-ts and keripy
   require.
4. **The ACDC.** Its field order, its SAID, the SAIDs of its `a` / `e` / `r`
   sections, and that its `-I` triple names the `iss`.
5. **The schema**, when given: its `$id` is its own SAID, and the ACDC's `s`
   names it.

## What is on the wire

The released libraries issue credentials in **version 1**:

- `ACDC10JSON…`, with `vcp` / `iss` / `rev`;
- signify-ts writes its KEL in v1 too.

keri-ts writes its KEL in v2 by default. That generation's CESR tables count
quadlets and use other codes, and they are not implemented here yet. A v2
message is **refused by name** rather than misread.

## SAIDs are checked over the bytes received

A SAID is the digest of a serialization, so re-serializing to check one is
wrong whenever the issuer's JSON differs from JavaScript's:

- Python writes `4.0` where `JSON.stringify` writes `4`;
- `JSON.parse` moves integer-like keys to the front.

`checkSaid()` tokenizes the received text, overwrites the SAID's own span with
`#`, and hashes those bytes. It verifies the ACDC specification's v2 `rip`
example as printed. Issuing uses `JSON.stringify`, as both libraries do.

## The reference

**signify-ts 0.4.1**, the released KERIA client that vLEI credentials are issued
through. Offline, with no KERIA, `tests/acdc_engine.js` checks both directions:

- **signify-ts to us:** it builds an inception, a registry, a credential, its
  `iss` and the anchoring events with its own functions, exactly as its
  `Credentials.issue()` and `Registries.create()` do. `acdc.js` verifies the
  stream.
- **Us to signify-ts:** `acdc.js` issues. signify-ts re-serializes every event to
  the same bytes, verifies every SAID and signature, and writes the same `-I`
  triple and `-V`/`-G` couples.

keri-ts 2.2.9 is the other released implementation. It needs a native LMDB
binding, so it is not used here.

## Not done

- CESR **version 2** (keri-ts's default KEL), CBOR and MessagePack bodies.
- **Weighted** thresholds, which are refused by name.
- Delegated identifiers (`dip`, `drt`).
- Witness receipts as a requirement.
- Backer registries.
- Full JSON-Schema validation of the credential against its schema; only the
  schema's SAID is checked.
- Edges to chained credentials (their SAIDs are checked; the far nodes are not
  fetched).
- Selective disclosure (`A` aggregates).
- IPEX `exn` grant messages.
