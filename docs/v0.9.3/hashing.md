# Hashing — the Encoding / Hashing Tools page

Covers `client/public/encoding_tools.html`, `client/src/encoding_tools.js`,
`client/src/hash_tools.js`, `client/public/css/encoding_tools.css`,
`tests/encoding_tools.js` (the page) and `tests/hash_engine.js` (the bytes).

The page has six panes. Three are old and dull — Base64, percent-encoding and
a CRC-32 — and three are hashing: **FIPS 180-4** (SHA-1, SHA-2), **FIPS 202**
(SHA-3 and the SHAKE extendable-output functions) and **SP 800-185** (cSHAKE,
KMAC, TupleHash, ParallelHash). The last two were added on 2026-08-28. This
file is what is worth knowing before editing any of it.

## Why the post-quantum half is a HASHING page and not a signature page

The Digital Signature page already signs with ML-DSA and with all twelve
SLH-DSA parameter sets, and the Encryption page already does ML-KEM. What was
missing was the layer underneath all three: **every one of FIPS 203, 204 and
205 is built out of FIPS 202**, and the page that computes hashes could not
compute one of them.

The mapping is in `hash_tools.js`'s registry, as the `role` field on each
entry, and it is there because it is the part that cannot be looked up from
the name:

| Function | Is, in the post-quantum standards |
|---|---|
| SHA3-256 | ML-KEM's **H** (FIPS 203 §4.1) |
| SHA3-512 | ML-KEM's **G** |
| SHAKE128 | ML-KEM's **XOF**, which expands the seed into the matrix A; ML-DSA's ExpandA (FIPS 204) |
| SHAKE256 | ML-KEM's **PRF** and **J**; nearly every hash in ML-DSA; **all six** of SLH-DSA-SHAKE's functions (FIPS 205); and Ed448's internal hash (RFC 8032) |
| SHA-256 / SHA-512 | SLH-DSA-**SHA2**'s parameter sets (FIPS 205) |

"SHA3-256" and "ML-KEM's H" are the same call, and only one of the two is
findable in FIPS 203 — which is exactly the kind of thing this application
exists to make visible.

## It is not Web Crypto, and it could not have been

`crypto.subtle` has **no SHA-3 in any browser** — not one of FIPS 202's six
functions, and none of SP 800-185's four. So the FIPS 202 pane could never
have been built on it, and rather than have one pane on Web Crypto and two on
a library, all of them moved to `hash_tools.js`, which is pure JavaScript
(`@noble/hashes`) and synchronous.

That has a second consequence worth stating because it USED to be a defect:
`crypto.subtle` does not exist outside a **secure context**, and the
containerized suite serves the client at `http://client:3000`, which is not
one. The SHA pane therefore had no cryptography at all on that stack, and
`tests/encoding_tools.js` passed `--unsafely-treat-insecure-origin-as-secure`
to hide it. **That flag is gone, deliberately**, and its absence is now the
assertion: on the containerized stack the job fails if anything on this page
reaches for Web Crypto again. Do not put the flag back to fix such a failure —
see the note in the test.

## The four things that surprise readers, and what the page does about each

**Grover halves preimage resistance and leaves collision resistance where it
was.** Reporting one number for both is what produces the widespread claim
that SHA-256 has "128-bit post-quantum security" — true of its preimage
resistance, false of the property most people are relying on. The birthday
bound already puts a classical attacker at 2^(n/2) for a collision, and the
quantum improvement (BHT, 2^(n/3)) needs quantum-accessible memory of the same
order, which is why NIST's own security **categories** are defined by
collision search on SHA-256/SHA3-256 (category 2) and SHA-384/SHA3-384
(category 4) and treat them as unmoved. Each pane's Notes box states both
resistances separately and says which of them Grover touches;
`tests/hash_engine.js` asserts that it does, and that exactly those four
functions claim a category.

**An XOF's security is capped by its capacity, not by its output length.**
Asking SHAKE128 for 4096 bits does not buy 2048-bit collision resistance; it
buys 128 bits, for ever (FIPS 202 Table 4). The notes compute the bound as
`min(d/2, capacity)` and say so on screen, because the output-length box is
otherwise an invitation to believe the opposite.

**Legacy Keccak is not SHA-3.** FIPS 202 appended the two-bit domain separator
`01` before padding; the original Keccak submission did not, so the two
produce entirely different digests of the same input. Ethereum and a number of
older tools standardized on the pre-FIPS version and call it "SHA3", and that
is the single commonest way a CORRECT SHA-3 implementation gets reported as
broken. The pane therefore **offers both**, under a group labelled *NOT FIPS
202*, with a caution in the notes — hiding the older one would leave the
reader with a mismatch and no way to see why.

**KMAC is not KMAC-XOF, and the difference is not the length.** KMAC binds the
requested output length into the computation with `right_encode(L)`; the XOF
variant encodes `right_encode(0)` instead. So KMAC128 at 512 bits does not
begin with KMAC128 at 256 bits — while SHAKE at 512 bits *does* begin with
SHAKE at 256. Getting those two backwards produces a MAC that verifies against
itself and interoperates with nothing, which is why `hash_engine.js` asserts
both directions.

## The panes' arguments

The SP 800-185 pane is one pane for four functions because they are one
construction with four argument sets, and seeing which argument each one drops
is most of the point. A field the selected function does not read is
**disabled and dimmed** rather than ignored — a value sitting in an ignored box
reads as a value that was applied:

* **KMAC** is the only one that takes a key.
* **cSHAKE** is the only one whose function name `N` is yours to set; SP
  800-185 §3.2 reserves `N` for functions NIST itself defines, and the other
  three fix their own. With `N` and `S` both empty, **cSHAKE IS SHAKE**, bit
  for bit (§3.3) — the page says so and the test proves it.
* **TupleHash** is the only one that takes a LIST. The pane reads **one
  element per line**, and blank lines are dropped rather than hashed as empty
  strings, because an editor's trailing newline would otherwise change the
  digest — precisely the ambiguity TupleHash exists to end.
* **ParallelHash** is the only one whose block size `B` changes the answer. It
  is part of the definition rather than a performance knob: two readers who
  pick different block sizes get different digests of one file.

Every hashing pane takes its input as **text, hex, Base64 or Base64url** and
writes its output as hex, HEX, Base64 or Base64url. That is not decoration: a
pane that can only take UTF-8 text cannot check a published test vector, and
every specification writes its inputs in hex.

**The two new panes load holding the specifications' own samples** — the FIPS
202 pane hashes `abc`, the input that document's examples use, and the SP
800-185 pane holds KMAC Sample #1 (key `40..5F`, data `00010203`, no
customization, L = 256), whose expected output is printed in that document's
appendix. So the page can be checked against NIST by reading it, and both
tests assert exactly that on load.

## Where the testing is split, and why

`tests/encoding_tools.js` drives the page and `tests/hash_engine.js` checks the
bytes — the same division `encryption_tools.js` and `crypto_engines.js` have,
in its sharpest form. A digest is the one value where being wrong looks exactly
like being right, so a round trip through the page proves nothing at all about
correctness. The node job asserts against node's OpenSSL (both SHA families,
both SHAKEs at five lengths), against `openssl mac`'s KMAC128/KMAC256 — the
only second implementation of the SP 800-185 half that exists on these
machines — against fifteen sample values transcribed from SP 800-185, and
against TupleHash and ParallelHash **re-derived from that document's own
`left_encode` / `right_encode` / `encode_string` definitions**, which is what
catches an encoding that is wrong and self-consistent.

Six of those sample values are ALSO driven through the browser, in
`tests/encoding_tools.js`, and that duplication is deliberate: there is no
cSHAKE in node and none in any browser, so a Selenium job has no second
implementation to compare the page against, and comparing it against the very
library it bundles would assert nothing. A published vector is the one
reference that is neither.

Two drift checks live in the node job because nothing else would catch either:
every `<option>` on the page has to name a function the registry actually has
(and every registry entry has to be offered), and every handler the markup
calls has to be exported by the bundle — an option value that is not a
registry id produces an error in a status line nobody is watching, and a
renamed handler is a `ReferenceError` on click.
