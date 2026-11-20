# ACDC (`acdc.html`)

**Authentic Chained Data Containers**, with the parts of **CESR** and **KERI**
a verifier and an issuer need (the Trust over IP KERI Suite specifications,
*working-group drafts*; the page names no revision). The code is held to two
independent implementations: **signify-ts 0.4.1** (the released KERIA client
vLEI credentials are issued through) and **keri-ts 2.2.9 / cesr-ts 2.2.1**,
and to the specifications' own example messages.

This format is outside OpenID4VCI and OpenID4VP. It is reached only through
its own page, linked from the **VC Tools** row of every VC page. **Nothing on
the page is stored** and nothing is fetched: KELs, schemas and chained
credentials come in the stream. Issuing makes a fresh issuer each time, and
its keys are not kept.

## What the specification says

An ACDC **carries no signature**. Its SAID (self-addressing identifier, the
digest of its own bytes) is sealed by an issuance event in the issuer's
registry; that event is anchored by a seal in an event of the issuer's **key
event log** (KEL); and the KEL is signed. Verifying a credential means
walking that chain, all of which travels in one **CESR stream**. Revocation
is an event in the same registry.

**Both CESR versions are read and issued**, mixed in one stream as the
released libraries mix them (signify-ts writes everything in version 1;
keri-ts writes its KEL in version 2 and its credentials in version 1):

| | version 1 | version 2 |
|---|---|---|
| version string | `KERI10JSON…` | `KERICAACAAJSON….` |
| counters | count items | count quadlets |
| registry | `vcp` / `iss` / `rev` (no backers), `vcp` / `vrt` / `bis` / `brv` (backers) | `rip` / `upd` / `bup` |
| ACDC | `ACDC10JSON…`, SAID over the full form | `acm` / `act` / `acg`, SAID over the **most compact form** |

A SAID is checked over **the bytes received**, never a re-serialization
(Python writes `4.0` where JavaScript writes `4`); the version 2 most compact
form is spliced from the received bytes.

## What the debugger checks

`verifyPresentation()` walks, in order, and a failure in the chain ends the
walk there:

1. **Every KEL in the stream** (`icp`, `rot`, `ixn`, `dip`, `drt`),
   delegators before their delegates: version string, field order and SAID;
   sequence and prior digest (a second event at one sequence number is
   duplicity, and fatal); signatures by the current keys (Ed25519, Ed448,
   secp256k1, P-256) against the threshold `kt`, **numeric or weighted**; on
   rotation, the new keys' digests are the prior event's `n` and the prior
   `nt` is satisfied.
   - **Weighted thresholds**: a list of fractions that must sum to at least
     1, a list of such clauses that must all reach 1, or nested groups. The
     arithmetic is exact; a threshold that can never be met is refused.
   - **Witnesses**: receipts from distinct witnesses of the current list, at
     least `bt` of them. An event short of `bt` is refused as not fully
     witnessed.
   - **Delegation**: a `dip` or `drt` is approved only by a seal of it in its
     delegator's KEL. A delegator with `DND` cannot delegate.
2. **The registry**: version 1 without backers (`vcp`, `iss`, `rev`), version
   1 **with backers** (`vcp` listing backers and `bt`, `vrt` rotating them,
   `bis` / `brv` for the credential, every event needing `bt` backer
   receipts), or version 2 (`rip` and its `upd` / `bup` updates, a blinded
   state checked by its BLID). Each registry event is anchored by exactly one
   seal in the issuer's KEL. With no registry, the issuer's KEL seals the
   credential's SAID directly.
3. **The ACDC**: its field order, its SAID and its sections' SAIDs, the
   aggregate's AGID, its `-I` seal source triple (version 1).
4. **The schema**, when given (one, or a list for a chain): its `$id` is its
   own SAID, and the credential **as presented** validates against it (JSON
   Schema draft-07, or 2020-12 when `$schema` names it; `format` never
   rejects; `$dynamicRef` is refused).
5. **The edges**, recursively: each far node is found in the stream and
   verified the same way. Operators `I2I`, `NI2I`, `DI2I` and `NOT`; edge
   groups `AND`, `OR`, `NAND`, `NOR`. A far node that is revoked, invalid or
   absent makes its edge invalid. `AVG` / `WAVG` are refused by name.

**Aggregates and selective disclosure.** `A = [AGID, block, …]`: each block
has its own blinding and SAID, and may be disclosed or replaced by its SAID.
In version 2 the credential's SAID is over the most compact form, so a
disclosure keeps the SAID and the registry still binds it. In version 1 it
does not, and the page says so.

**IPEX.** `verifyExchange()` verifies an IPEX grant (or any `exn`): its SAID,
the sender's signature against the sender's KEL, its embeds' SAIDs, that the
grant goes to the credential's issuee, and the credential it carries,
verified exactly as a presentation is. An admit is checked against the
exchange it answers.

The verdict is **VALID** (issued, anchored, not revoked in this stream),
**REVOKED** or **INVALID**, with the reason, and every check is listed with
what it found.

## The page

### Verify a Presentation

| Field / button | What it does |
|---|---|
| CESR stream | the KELs (issuer, delegator, chained issuers), registry events, the credential with its attachments, any credentials its edges point to, optionally an IPEX grant — concatenated as KERIA or keri-ts send them |
| Schemas | optional: the schema the credential's `s` names, or a JSON list (one per credential in a chain) |
| **Verify Credential** | the walk above |
| **Verify IPEX Grant** | the last `/ipex/grant` `exn` in the stream |

### Issue a Credential

| Field | What it sets |
|---|---|
| CESR version | 1 (signify-ts, KERIA) or 2 (keri-ts, the specification) |
| Attributes | the `a` section, as JSON |
| Issuee AID | optional `a.i`, making the credential targeted |
| Signing keys, Signing threshold (`kt`, `nt`) | how many keys, and a numeric or weighted threshold |
| Witnesses, Witness threshold (`bt`) | witnesses the issuer names, whose receipts the page signs |
| Delegated issuer | a delegator's KEL first, anchoring the issuer's `dip` |
| Registry backers | version 1: a backer registry with `bis` / `brv` |
| Aggregate | attributes as blinded blocks in `A` |
| Chain to a parent | a second issuer issues a parent credential; this one's `e.parent` points to it (`I2I`) |

**Issue** shows the stream and the schema(s). **Revoke** appends a revocation.
**IPEX Grant** appends a grant of the credential to its issuee (version 1, as
signify-ts builds it). **Verify It** hands the stream to the verify pane.

### Disclose Selectively

From a credential issued with **Aggregate**: choose the blocks to disclose
(positions in `A`, from 1); the others are replaced by their SAIDs.
**Verify It** verifies the result.

## Not implemented

CBOR, MessagePack and native CESR bodies (refused by name); edge-group `AVG`
/ `WAVG` (refused by name); bound blinded states; fetching anything (OOBIs,
watchers); version 2 IPEX grants (grants are issued in version 1); checking a
schema against its dialect's meta-schema.

## Related

* [ACDC developer notes](../acdc.md)
* [Tutorial: issue, verify and revoke an ACDC](tutorials-tools.md#issue-verify-and-revoke-an-acdc)
