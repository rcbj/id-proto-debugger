# Stateful hash-based signatures — LMS/HSS and XMSS/XMSS^MT

Covers the pane `pane_hbs_signature` on `client/public/digital_signature.html`,
its handlers in `client/src/digital_signature.js`, the engine
`client/src/hbs.js`, and `tests/hbs_signatures.js` with
`tests/hbs_vectors.json`.

Four documents, and the page cites all four because they are not
interchangeable:

| Document | What it adds |
|---|---|
| **RFC 8554** | LM-OTS, LMS and HSS, with four LM-OTS and five LMS parameter sets, all SHA-256 |
| **RFC 9858** | twelve more LM-OTS and fifteen more LMS sets: SHA-256/192, SHAKE256/256, SHAKE256/192 |
| **RFC 8391** | WOTS+, XMSS and XMSS^MT, with twelve XMSS and thirty-two XMSS^MT sets |
| **NIST SP 800-208** | approves both families, adds nine XMSS and twenty-four XMSS^MT sets, and imposes a key-generation rule the RFCs do not have |

All of it is implemented: 16 LM-OTS, 20 LMS, 21 XMSS and 56 XMSS^MT parameter
sets, which is every row of both IANA registries.

## Why this is a different kind of risk from every other signature here

Every other signature scheme on that page is somebody else's implementation
with a thin layer over it — ML-DSA, SLH-DSA and the curves are `@noble`'s, RSA
is node-forge's, and a defect in any of them is a defect in a widely used
library. **There is no LMS or XMSS in this dependency tree**: none in
`@noble/post-quantum`, none in Web Crypto, none in node. So `hbs.js` is an
implementation of two specifications written from the specifications, and
hash-based signatures are the worst possible subject for that: simple enough to
write in an afternoon, and unforgiving enough that every interesting mistake
produces a scheme that signs and verifies **against itself** perfectly and
interoperates with nothing.

Four that are real, and one of them was real here:

* A domain separator dropped. Every hash in LMS is prefixed with `D_PBLC`,
  `D_MESG`, `D_LEAF` or `D_INTR` (RFC 8554 §7.1) and every hash in XMSS with
  `toByte(0..4, padding)`. Remove one and nothing fails locally.
* **The WOTS+ chain address written into the word the LEAF index lives in.** An
  OTS address is eight words and words 4, 5 and 6 are the leaf, the chain and
  the step; RFC 8391 §3.1.4 says a WOTS+ algorithm "MUST NOT manipulate any
  parts of ADRS except for the last three 32-bit words". This module had it
  wrong in its first draft, produced a complete, self-consistent XMSS, and was
  caught by the first reference vector — which is precisely why the vectors
  come first here and the round trips second.
* SP 800-208's **four-byte** function padding for the 192-bit parameter sets,
  where RFC 8391's own sets pad to `n`. Nothing in the name says so.
* The Winternitz checksum left unshifted by `ls`, which makes it zero in every
  digit that is actually signed — a scheme with no checksum, which round-trips.

## The state, which is the whole subject

These are the only signatures in this application whose **private key changes
every time you use it**. Each leaf of the tree is a one-time key, and spending
one twice on two different messages does not merely weaken the scheme: it hands
an attacker the same Winternitz chains revealed at two different heights, which
is the material a forgery on a third message is built from.

So SP 800-208 §1 restricts these schemes to applications where the state can be
guaranteed — firmware and software signing above all — and RFC 8554 §5.4.1
requires the incremented index to reach non-volatile storage **before** the
signature is released. The pane is built around that rather than hiding it:

* the index lives in the private key box, and **Sign rewrites that box** —
  the new key is written first and the signature second, in that order;
* the state line says how many one-time keys are left, and Sign decrements it;
* an exhausted key refuses to sign rather than wrapping around;
* signing again with an un-updated key blob **re-spends the same index**, which
  is the operational hazard, and this build makes it visible rather than
  preventing it.

And the pane has a button that does the forbidden thing on purpose: **Sign both
from one index** signs two different messages from one one-time key and
validates both. Both are valid — that is the point. No verifier anywhere can
tell that the key was used twice, which is exactly why the obligation sits on
the signer, and a page that could only demonstrate the safe path could not show
what the rule is for.

## What a browser can and cannot do, which is not a limitation of this code

Key generation walks every leaf of a tree and each leaf is a full one-time key
pair. For `LMS_SHA256_M32_H20` that is 1,048,576 of them — tens of billions of
hash compressions, hours in C and days in JavaScript. **Verification is
untouched by any of this**: it hashes one authentication path, `h` nodes deep.

So the page verifies, parses and describes **every** parameter set both
registries define, and generates keys only for those whose trees it can
actually build. `keygenCost()` returns the number of hash computations and
`canKeygen()` the verdict; over the limit, the pane refuses **with the number**
rather than freezing the tab.

That gap is also the clearest possible argument for the multi-tree variants,
and the page is the one place you can watch it happen:

| Parameter set | Signatures | Tree(s) built | On this page |
|---|---|---|---|
| `XMSS-SHA2_20_256` | 2^20 | one of 1,048,576 leaves | refused — verify only |
| `XMSSMT-SHA2_20/4_256` | 2^20 | four of 32 leaves | ~0.2s |
| `XMSSMT-SHA2_60/12_256` | 2^60 | twelve of 32 leaves | ~0.2s |
| `XMSS-SHA2_10_256` | 2^10 | one of 1,024 leaves | ~5s |

The same holds on the LMS side: an `L = 2` HSS key reaches 2^10 signatures out
of two 32-leaf trees, because only the top tree exists before the first
signature (RFC 8554 §6).

**The SHAKE parameter sets are three to four times slower than the SHA-2 ones**
for the same shape, because the cost is per hash call and `@noble`'s SHAKE is
slower than its SHA-256. That is why the page's default is `XMSSMT-SHA2_20/4_256`.

## Two hot-path rules this module has to follow

Both are the repo-root `CLAUDE.md`'s rules taken to their limit, because one
key generation is three million hash calls.

**Nothing in the inner loops logs.** `coef()`, `wotsChain()`, `thashF()`,
`thashH()`, `prf()`, `lmotsHash()` and `cat()` carry no `log.debug`, and
`tests/hbs_signatures.js` asserts it — a pair of log lines in `wotsChain()`
would be tens of millions of records for one key, and `client/src/env/local.js`
and `docker-tests.js` both set `logLevel: "debug"`.

**Concatenation is not `crypto_bytes.concatBytes` here.** That function logs on
entry and exit and calls `asBytes()` (which logs twice more) per argument —
right for a page that joins a handful of buffers per click, ruinous five times
per Winternitz step. `hbs.js` has a local `cat()` with no logging and says so
where it is defined. Everything that runs once per operation still uses the
shared helpers.

## The private key format is this tool's own, and it says so

Both specifications define the public key and the signature to the byte and
deliberately leave the private key to the implementation — RFC 8554 §5.2 calls
it "an internal matter to the implementation", RFC 8391 §4.1.3 likewise —
because nothing interoperable depends on it. What this module stores is a seed
and an index, tagged `LMSK` or `XMSK` so a reader can never mistake it for
something another tool reads. The **public** key and the signature are the
standard encodings exactly, and those are what the vectors check.

One consequence worth knowing: because the HSS private key holds a master seed
and a per-level generation counter rather than the level keys themselves, an
exhausted lower tree is replaced deterministically (RFC 8554 §6.2's
regeneration) without needing fresh randomness at signing time.

## Where the vectors come from

`tests/hbs_signatures.js` asserts against nothing this tree produced:

* **RFC 8554 Appendix F**'s two HSS test cases and **RFC 9858 Appendix A**'s
  three, which between them cover W4 and W8, H5 and H10, `L = 1` and `L = 2`,
  and all four LMS hash functions including both truncations.
* **cisco/hash-sigs**'s LM-OTS vectors, which publish `I`, `q` **and** `SEED` —
  so they exercise RFC 8554 Appendix A key generation directly rather than only
  verification.
* **One verification vector for each of the 21 XMSS parameter sets** in the
  IANA registry, produced by Botan.
* The **XMSS reference implementation**'s own key generation vectors. These are
  the only thing that can pin SP 800-208 §6.2's `PRF_keygen` and the 192-bit
  padding rule, because a verifier never touches either.
* Eight signatures that must **not** verify — a swapped byte in the
  authentication path, a swapped byte in the one-time signature, a truncated
  signature, a prefixed one, an unknown OTS type, an empty signature.

**Five key generation vectors are deferred behind `HBS_ALL_KEYGEN=1`** and the
job says so at WARN. They take about 160 seconds between them and pin no rule
the two that always run do not: the padding rule has exactly two cases and
those two are one of each, while all four core hash functions are exercised by
the 21 verification vectors.

## Where the XMSS^MT vectors come from, and how to regenerate them

**Nothing publishes an XMSS^MT test vector.** Botan does not implement the
multi-tree variant, the reference implementation ships no KAT files, and RFC
8391's appendices are XDR formats rather than examples. For a while that left
XMSS^MT here checked only by round trips, which is the state every comment in
this tree warns about.

The vectors in `tests/hbs_vectors.json` under `xmssmtKeygen` and
`xmssmtVerify` are therefore generated with **the reference implementation
itself** — `github.com/XMSS/xmss-reference` at commit `171ccbd`, the code that
accompanies RFC 8391 — and they are deterministic, so anybody can reproduce
them:

1. Clone that repository. It builds with `gcc` and `-lcrypto`; the sources it
   needs are `params.c hash.c fips202.c hash_address.c randombytes.c wots.c
   xmss.c xmss_core.c xmss_commons.c utils.c`.
2. Write a driver that resolves the parameter set with `xmssmt_str_to_oid()`
   and `xmssmt_parse_oid()`, then calls **`xmssmt_core_seed_keypair()`** with a
   `3n`-byte seed of `0x00, 0x01, 0x02, …` — the seeded entry point rather than
   `xmssmt_core_keypair()`, which draws from `/dev/urandom` and would give a
   vector nobody could reproduce.
3. Sign the ASCII message `RFC 8391 interoperability vector` with
   `xmssmt_core_sign()`.
4. Read `sk_seed`, `sk_prf`, `root` and `pub_seed` out of the secret key at
   offsets `index_bytes`, `+n`, `+2n` and `+3n` (RFC 8391 leaves the secret key
   format open; this is the reference implementation's own layout, from
   `xmss_core.c`). The public key is `root || pub_seed`, and the four-byte OID
   is prepended to make the encoding RFC 8391 §4.1.7 defines.

**Nine parameter sets were generated and all nine matched on the first run** —
key generation and verification both — which is worth recording because the
single-tree path had needed a fix before it did.

The shapes are chosen for cost. Key generation vectors use `h/d = 5`, so each
tree is 32 leaves and the whole set reproduces in about two seconds; they cover
**all four hash functions and all three padding lengths**, which is what
retired the flag described below. Verification vectors cover `d = 2, 4, 8` —
including the five-byte index field at `h = 40`, where a parser that assumed
four would be wrong in both directions — and the two 64-byte-output sets are
left out of the verification set on purpose, because their signatures are 34 KB
each and their core hash is already covered by the single-tree vectors.

## The single-tree key generation vectors, and why the flag no longer gates a rule

A single-tree key generation vector is 1,024 leaves: five seconds for SHA-2 and
up to seventy-eight for SHAKE, 168 seconds for all seven, which would have made
this the second-longest job in the suite. Two ran by default and five sat
behind `HBS_ALL_KEYGEN=1`.

That flag **was** load-bearing while those vectors were the only cover for SP
800-208 §6.2's `PRF_keygen` and the padding rule. It is not any more: the
XMSS^MT vectors check both, on every run, from 32-leaf trees — and
`xmssMtMatchesTheReferenceImplementation()` *asserts* that coverage (all four
hash functions, all three padding lengths) rather than assuming it, so trimming
the cheap set fails the job. What is still deferred is the same rules on a
larger tree, which is worth having and is not worth 160 seconds.

## Mutation testing, as a standing check

Every check here is of the form "this vector reproduces", and none of them
proves that a particular line of `hbs.js` is load-bearing — which matters most
in a hash-based signature, where the lines that carry the security are exactly
the ones whose removal still round-trips. `everyRuleIsLoadBearing()` breaks the
module on purpose, seven ways, and requires the named vector to notice:

| Mutation | Must be caught by |
|---|---|
| the 192-bit padding changed from 4 to `n` | an XMSS^MT key generation vector |
| the WOTS+ hash address written to the chain address word | XMSS verification |
| the WOTS+ chain address written to the leaf index word | XMSS verification |
| `D_LEAF` replaced by `D_INTR` | LMS verification |
| the LM-OTS checksum left unshifted by `ls` | LMS verification, **at a shifted parameter set** |
| LM-OTS key generation's `0xff` separator changed to `0xfe` | LM-OTS key generation |
| `PRF_keygen`'s separator changed from 4 to PRF's 3 | XMSS^MT key generation — **and verification must still pass** |

It loads a mutated *copy* from a temp directory with the one relative require
rewritten, so nothing is ever written into `client/src`, where a leftover file
would be swept up by the client-source checks in `jwk_pem_encoding.js`. Each
mutation asserts its target text was present before substituting: a mutation
that silently fails to apply would make the check it anchors pass for the wrong
reason, which is the exact failure the section exists to rule out.

**Two of the seven earned their place immediately.** The `PRF_keygen` case is
the argument for having obtained key generation vectors at all — it breaks key
generation and leaves verification working, because a verifier never touches
that function, so the whole rest of this file would have missed it. And the
checksum case failed on its first run for a reason worth keeping: `ls` is 0 for
every `w = 8` parameter set, and four of the five published LMS vectors are
`w = 8`, so aimed at RFC 8554's Test Case 1 the mutation is a no-op and
survives. `shiftedLmsCase()` now finds a vector whose LM-OTS set actually has a
shift, and throws if the vector set stops containing one.

## What is still not here

**The five deferred single-tree key generation vectors** re-test rules already
covered, on a bigger tree. `HBS_ALL_KEYGEN=1` runs them; the job lists them by
name at info level and says they gate nothing.

**Nothing has run in the containerized stack yet.** The pane was verified
against a locally built bundle in headless Chrome. It uses no Web Crypto, so
the secure-context hazard in `tests/CLAUDE.md` does not apply to it, but that
run has not happened.
