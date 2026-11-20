# ACDC

#480, phase 6 of #474. **Authentic Chained Data Containers**, with the parts
of **CESR** and **KERI** a verifier and an issuer need (Trust over IP KERI
Suite specifications), on `acdc.html`.

| File | What it is |
|---|---|
| `client/src/acdc.js` | CESR v1 and v2 primitives, counters and streams; SAIDs and the most compact form; KELs, registries, ACDCs, edges, aggregates, IPEX; issuing |
| `client/src/acdc_threshold.js` | KERI signing thresholds, numeric and weighted |
| `client/src/acdc_schema.js` | JSON Schema validation of a credential (`@cfworker/json-schema` 4.1.6) |
| `client/src/acdc_page.js` | the page (bundle global `acdcpage`) |
| `tests/acdc_engine.js` | node: both ways with signify-ts 0.4.1, the specifications' vectors and keys, refusals |
| `tests/acdc_keri_ts.js`, `tests/acdc_keri_ts_lib.mjs` | node: both ways with keri-ts 2.2.9 and cesr-ts 2.2.1 |
| `tests/acdc_browser.js` | Chrome: signify-ts's stream, issue (v1, v2), revoke, disclose, chain, grant, tamper |
| `tests/fixtures/acdc_vectors.json` | the KERI and ACDC specifications' example messages |

## How an ACDC is verified

An ACDC carries **no signature**. Its SAID, the digest of its own bytes, is
sealed by an issuance event in its issuer's registry. That event is anchored
by a seal in an event of the issuer's KERI key event log (KEL), and the KEL is
signed. `verifyPresentation()` walks:

1. **Every KEL in the stream** (`icp`, `rot`, `ixn`, `dip`, `drt`),
   delegators before their delegates. For each event:
   - the version string, the field order and the SAID;
   - the sequence and the prior digest; a second event at one sequence
     number is duplicity, and fatal;
   - signatures by the current keys (Ed25519, Ed448, secp256k1, P-256)
     against the threshold `kt`, numeric or weighted;
   - on rotation, the new keys' digests are the prior event's `n`, and the
     signatures that prove it satisfy the prior `nt`;
   - **witness receipts**: indexed witness signatures (`-B` / `-L`) or
     non-transferable receipt couples (`-C` / `-M`), on the event or on an
     `rct` for it, from distinct witnesses of the current list (`b`, then
     `br`/`ba`), at least `bt` of them. An event short of `bt` is refused:
     it is not fully witnessed. (`opts.unwitnessed` accepts it.)
   - **delegation**: a `dip` or `drt` is approved only by a seal `{i, s, d}`
     of it in its delegator's KEL, at the event its `-G` / `-S` couple
     names. A delegator with `DND` cannot delegate.
2. **The registry.**
   - Version 1, no backers (`NB`): the `vcp` (SAID with `i == d`, `ii` the
     issuer, `s` 0), the credential's `iss` and, if present, `rev`.
   - Version 1 with backers: the `vcp` lists backers and `bt`; `vrt`
     rotates them; the credential's events are `bis` / `brv`, whose `ra`
     names the registry event whose backers apply. Every one of these events
     needs `bt` backer receipts.
   - Each version 1 registry event is anchored by the issuer KEL event its
     `-G` couple names, whose `a` is **exactly one** seal `{i, s, d}` of it
     (keri-ts and keripy require exactly one).
   - Version 2: the `rip` (`i` the issuer, `n` 0) and its updates in order
     (`n`, `p`), each anchored by an issuer KEL event carrying the seal
     `{i: registry, s: n, d}` (keri-ts's `matchesRegistrySeal`). The
     credential's state is the last `upd` whose `td` is its SAID, or the
     last `bup` whose blinded state is disclosed in the stream (a `-a`
     group) with a BLID that verifies. `issued` is valid, `revoked` revoked.
   - No registry: the issuer's KEL seals the credential's SAID directly.
3. **The ACDC.** Its field order; its SAID and its sections' SAIDs; the
   aggregate's AGID; its `-I` triple (version 1).
4. **The schema**, when given (one, or a list for a chain): its `$id` is its
   own SAID, and the credential **as presented** validates against it.
5. **The edges**, recursively: each far node is found in the stream and
   verified the same way. See below.

`verifyExchange()` verifies an IPEX grant (or any `exn`): its SAID, the
sender's signature group against the sender's KEL, `e.d` over its embeds,
each embed, and then the credential, assembled from the embeds (with their
pathed attachments) and the rest of the stream. An admit is checked against
the exchange its `p` names.

## Two CESR versions

The released libraries mix them: signify-ts writes everything in version 1;
keri-ts writes its KEL in version 2 and its credentials and their registry in
version 1. Both are read, mixed in one stream, and issued.

| | version 1 | version 2 |
|---|---|---|
| version string | `KERI10JSON0000fd_` | `KERICAACAAJSONAAFb.` (protocol 2.0, genus 2.0, size in base 64) |
| counters | count **items**, except `-V`/`-L` | count **quadlets**, always |
| signatures | `-A` | `-K` (inside a `-C` attachment group) |
| witness receipts | `-B`, `-C` | `-L`, `-M` |
| seal source couple / triple | `-G`, `-I` | `-S`, `-T` |
| signature group | `-F` | `-X` |
| pathed material | `-L` | `-P` |
| ordinals | 24-character Seqner (`0A…`) | the shortest Number (`MAAB`) |
| ACDC | `ACDC10JSON…`, `ri` | `acm`/`act`/`acg`, `rd`, rip/upd/bup |

A genus-version counter (`-_AAACAA`) switches the table. Attachments follow
their body's version otherwise.

## SAIDs are checked over the bytes received

A SAID is the digest of a serialization, so re-serializing to check one is
wrong whenever the issuer's JSON differs from JavaScript's:

- Python writes `4.0` where `JSON.stringify` writes `4`;
- `JSON.parse` moves integer-like keys to the front.

`checkSaid()` builds a span tree of the received text (`jsonTree()`),
overwrites the SAID's own span with `#`, and hashes those bytes. Nested
blocks are checked over their own spans.

**The version 2 most compact form** is not the form received, so it is
**spliced from the received bytes**: each nested block that has a `d` is
replaced by its SAID (computed over its own compact form, innermost first),
each section by its SAID, the aggregate by its AGID, and `v` re-sized for
that form. The ACDC specification's transcript example carries Python's
`"english":4.0`; its compact form spliced this way is byte for byte the
specification's, and its SAIDs verify. Re-serialized, they do not.

Issuing uses `JSON.stringify`, as both libraries do.

## Thresholds

`kt` and `nt` are a hex number, or weighted: a list of fractions that must
sum to at least 1 over the verified keys, a list of such clauses that must
all reach 1, or a nested group `{"1/2": ["1", "1"]}` whose outer weight
counts when its own members reach 1. A threshold that can never be met, or
whose weights do not match the keys, is refused. The arithmetic is exact.
`acdc_threshold.js` is held to cesr-ts's `Tholder` on every subset of
signers of ten thresholds.

## Edges

An edge `{d, u, n, s, o}` points to a far node `n`, whose schema must be
`s`. Its unary operators: `I2I` (this credential's issuer is the far node's
issuee; the default when the far node is targeted), `NI2I` (no such
requirement; the default otherwise), `DI2I` (the issuer may also be a
delegate of that issuee, checked through the KELs), `NOT` (the far node's
validity inverted). Edge groups combine their members with `AND` (default),
`OR`, `NAND` or `NOR`. `AVG` and `WAVG` average a property the schema or a
governance framework defines; they are not validity operators and are
refused by name. A far node that is revoked, invalid, or not in the stream
makes its edge invalid. A string edge is a simple compact edge (the far
node's SAID) when that credential is presented.

## Aggregates and selective disclosure

`A = [AGID, block, …]`: each block has a blinding `u` and its own `d`; the
AGID is the digest of the JSON list of the blocks' SAIDs with its own slot
dummied (cesr-ts's JSON-kind Aggor). A block may be disclosed or replaced by
its SAID. In version 2 the credential's SAID is over the most compact form,
where `A` is the AGID, so a disclosure keeps the SAID and the registry still
binds it. In version 1 the SAID is over the full form, so a disclosure does
not verify; the page says so.

## Schemas

`acdc_schema.js` uses **@cfworker/json-schema 4.1.6** (MIT), the engine
keri-ts uses, the way keri-ts uses it: the dialect is draft-07, or 2020-12
when `$schema` names it; `format` never rejects (removed first, as in keripy
and keri-ts); `$dynamicRef` is refused rather than ignored. It interprets
schemas and generates no code. keri-ts also checks a schema against its
dialect's meta-schema; that is not done here.

The accreditation schema in the ACDC specification's annex requires `score`
while its credential has `level`: an erratum, which validation reports.

## Issuing

`issue(opts)` makes a fresh issuer and a presentation stream:
`version` (1 or 2), `signers` and `kt`/`nt`, `witnesses` and `toad` (the page
signs their receipts), `delegated` (a delegator anchors the issuer's `dip`),
`backers` (a version 1 backer registry), `aggregate`, `edges`, `rules`,
`private` (a top-level `u`), `direct` (no registry), `issuer` (an existing
controller). `issueChain()` issues a parent to a holder and the holder's
credential chained to it. `revoke()`, `grant()` (an IPEX grant, version 1, as
signify-ts builds it), `discloseAggregate()`.

## The references

- **signify-ts 0.4.1** (`tests/acdc_engine.js`): it issues a KEL, registry,
  credential and anchors, which verify here; it reads ours back byte for
  byte, verifies every SAID and signature, and writes the same attachments.
  Its `exchange()` builds a grant that verifies here, and builds the same
  exn and pathed attachments from our embeds.
- **keri-ts 2.2.9 and cesr-ts 2.2.1** (`tests/acdc_keri_ts.js`, in-memory
  stores): its v2 and v1 KELs (weighted and multi-clause thresholds),
  delegated KELs, witnessed KELs (two witness habitats), credentials,
  revocations, grants and admits, and v2 ACDC messages (rip, acm full and
  compact, upd, bup with its BLID, acg with its AGID) verify here. Its
  Kevery accepts our KELs with the same key state; its Tevery and Verifier
  accept our credentials (no-backer and backer registries, revoked, chained)
  and refuse a chain to a revoked credential as we do (`revokedChain`); its
  Exchanger accepts our grant; cesr-ts's SerderACDC verifies our v2 ACDCs.
- **The specifications** (`tests/fixtures/acdc_vectors.json`): the KERI
  annex's v2 icp/ixn/rot/dip/drt/rct and next-key digests; the ACDC annex's
  rip, acm (full and compact), transcript, upd and bup, schemas, BLIDs; the
  CESR `-X` example. Their **keys** are derived with argon2id (keripy's
  Salter, reproduced with `@noble/hashes`), so Amy's and Cal's inceptions are
  rebuilt, signed and witnessed, and the annex's accreditation ACDC verifies
  end to end through its rip.

## Not done

- CBOR and MessagePack bodies, and native CESR bodies (refused by name).
- Edge-group `AVG` / `WAVG` (refused by name; not validity operators).
- Bound blinded states (`-b` sextuples) and partial rotation semantics
  beyond what the prior next threshold checks.
- Fetching anything: KELs, schemas and far nodes come in the stream (or the
  schema field); there are no OOBIs or watchers.
- Version 2 IPEX with `-P` pathed groups was not exercised against keri-ts
  (its v2 registries need its agent runtime); grants are issued in
  version 1.
- A schema's conformance to its dialect's meta-schema.
