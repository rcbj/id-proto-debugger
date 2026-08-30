# Post-quantum XML Signature and XML Encryption

**Status: complete. All sixteen signature methods, all fifteen
key-encapsulation methods, and all five signing pages.**
This document says what exists, what the identifiers are, where they come from,
and what is deliberately absent — because every URI here is from a DRAFT and a
reader has no way to tell a draft identifier from a Recommendation one by
looking at it.

## Where the identifiers come from, and how much they are worth

XMLDSIG is crypto-agile by design: `SignatureMethod/@Algorithm` is a URI and
nothing in the specification enumerates the legal ones, so a new signature
scheme needs an identifier and an implementation and **not** a new version of
XML Signature. That is the whole reason this was possible without touching the
engine.

The identifiers are **`draft-eastlake-rfc9231bis-xmlsec-uris-09`, 21 August
2026**, an individual Internet-Draft intended to obsolete RFC 9231. Weigh it
honestly:

* It carries **no IETF or W3C endorsement** — its own boilerplate says so, and
  section 3.3.16 is still marked *"not yet listed in the indexes in Section
  5"*.
* **W3C has nothing.** Its strategy issue #484 asks for a *workshop* on
  post-quantum cryptography for the XML Signature and XML Encryption suites.
  There is no Recommendation and no Working Group draft.
* **Apache Santuario is mid-adoption and hedges harder than this does.** Its
  in-flight PR (SANTUARIO-633/634) cites this draft's section 3.3.15 by number
  and ships `http://www.w3.org/tbd#ml-dsa-44` — a literal `tbd` host — rather
  than commit to the namespace.
* The academic prior art (*Post-quantum XML and SAML Single Sign-On*,
  eprint 2024/828, which forked OpenSAML, Santuario and BouncyCastle) used
  **custom experimental identifiers** of its own, so it is not a source to
  match.

**This project uses the draft's namespace verbatim** —
`http://www.w3.org/2026/08/xmldsig-more#` — and not Santuario's `#tbd`. The
reasoning is one sentence: matching the draft interoperates with anything that
implements the draft, and matching `#tbd` interoperates with one unreleased
build. If the draft's namespace changes, it changes in one line of
`common/xmldsig.js`.

**Every label in every menu says "draft".** That is not decoration. A URI is a
URI, and a person choosing `ML-DSA-65` from a list has no other way to know
that the identifier may be renamed before anything else in the world implements
it.

## The sixteen signature methods

All sixteen are in `SIG_METHODS` in `common/xmldsig.js`, which is **the one
registry** — five pages carry an algorithm menu and two services read the table,
and a second copy is a copy that disagrees.

| Draft § | Identifiers | Spec | Engine |
|---|---|---|---|
| 3.3.15 | `ml-dsa-44`, `-65`, `-87` | FIPS 204 | `client/src/pqc.js` |
| 3.3.16 | `slh-dsa-{sha2,shake}-{128,192,256}{s,f}` — twelve | FIPS 205 | `client/src/pqc.js` |
| 3.3.14 | `hss-lms` | RFC 8554 | `client/src/hbs.js` |

**The cryptography is not in `xmldsig.js` and that is the pre-existing rule
rather than a new decision.** That file implements RSA and takes everything else
through an `opts.signer` / `opts.verifier` pair — the arrangement it already had
for ECDSA and HMAC, argued in its own header on two grounds: `@noble` in that
file would land in the SAML, WS-Trust and WS-Federation bundles, none of which
had a reason to grow by a megabyte; and an injected signer is what lets a node
test drive the engine with an implementation that is not ours.
`client/src/xmldsig_pqc.js` is the one bridge from a `SignatureMethod` to the
module that performs it.

### Three things that surprise people

**A `SignedInfo` is always ASCII, and that is why a wrong byte conversion would
ship rather than fail.** XMLDSIG hands a signer the canonicalized SignedInfo as
a forge *binary string* — one character per byte, already UTF-8 encoded — and
every post-quantum engine here speaks `Uint8Array`. A `TextEncoder().encode()`
on that re-encodes every byte from 0x80 up as two bytes and signs a different
message, which verifies against itself perfectly and against nothing else. But
a SignedInfo holds URIs, element names and base64: the document's own text never
reaches it, because a Reference carries a *digest* of the content and not the
content. So the two conversions agree on every real SignedInfo, a wrong one
passes every round-trip check, and the first symptom would be another
implementation refusing a signature. The conversion is written once in
`xmldsig_pqc.js` and `tests/xmldsig_pqc.js` demonstrates the divergence on
octets that do carry a high byte.

**HSS/LMS spends a one-time key every time it signs, and nothing in XML
Signature expresses that.** The URI says `hss-lms` and says nothing about which
leaf was spent, so a document signed from a reused index verifies perfectly and
is worthless — spending one one-time key twice hands an attacker the material to
forge a third message. The signer therefore **refuses to sign** unless the
caller passes `onKeyAdvanced`, through which the advanced private key comes
back. It is the only stateful algorithm in this project's XML surface.

**A tampered document is caught by the Reference digest, not by the
signature.** Changing signed content leaves SignedInfo untouched, so
`signatureValid` stays `true` and `referencesValid` goes `false`. A test
asserting `signatureValid === false` there fails against a *correct* engine.

## What is deliberately absent

* **The composite ML-DSA + traditional algorithms** of
  `draft-ietf-jose-pq-composite-sigs` have no XML identifiers anywhere. They are
  absent rather than invented: an identifier this project made up would be a
  signature nothing else on earth can verify, which is the opposite of what a
  debugger is for. (The mock STS and the JOSE pages *do* speak them — over
  JOSE, where they have registered names.)
* **HashML-DSA**, FIPS 204's pre-hashed variant, has no identifiers in the
  draft — section 3.3.15 says the pure variant is what these URIs name.

## The encryption half: ML-KEM (section 3.6.9)

**Implemented.** All three parameter sets — `ml-kem-512`, `-768`, `-1024` —
through `encryptXml()` and `decryptXml()`.

**A KEM IS NOT KEY TRANSPORT, and that is the whole of why this needed a second
path rather than another branch.** RSA key transport takes the content
encryption key the sender has just generated and *wraps* it, so the recipient
decrypts the `CipherValue` and has the key. ML-KEM takes only the recipient's
public key and produces a ciphertext **and a fresh shared secret** — there is
nothing to put a key into. So:

* the `EncryptedKey/CipherData/CipherValue` is an **encapsulation**, not a
  wrapped key (768, 1088 or 1568 bytes, which is how you can tell);
* the content encryption key is **derived** from the shared secret, and the
  sender does not choose it;
* the recipient's key is not in an X.509 certificate — no profile for an ML-KEM
  key is defined by the draft — so it travels as `dsig11:DEREncodedKeyValue`,
  the same element the signature half uses.

### The gap in the draft, and what this project does about it

Section 3.6.9 says the shared secret is *"typically used as input to a key
derivation function, such as HKDF (see Section 3.8.1)"*. **"Typically" is not a
binding**, and it is the one place two correct implementations could disagree
and produce a key that decrypts nothing while naming no reason.

So **every parameter of the derivation is written into the document and read
back out of it** — the PRF, the salt, the info and the key length, in the
draft's own `HKDFParams` element (section 3.8.1's schema, verbatim). A document
produced here says in full how its content encryption key was derived, and a
recipient reading it needs to agree with nothing. An `EncryptedKey` naming a KEM
with *no* `KeyDerivationMethod` is **refused** rather than defaulted.

Where that element sits is also unspecified for a KEM. It goes inside the
`EncryptedKey`'s `EncryptionMethod`, because that is exactly where this engine
already carries RSA-OAEP's `DigestMethod` and `MGF` — an algorithm's own
parameters, beside the algorithm.

**The KDF is implemented here and the lattice is injected**, which is the same
split the signature side makes and for a sharper reason: HKDF is where two
implementations diverge silently, so it is written out once on the HMAC forge
already provides, and held to **RFC 5869 appendix A's own vectors** in
`tests/xmldsig_pqc.js`.

### One thing that surprises people

**A wrong decapsulation key does not fail at the KEM.** ML-KEM is *implicitly
rejecting* (FIPS 203): decapsulating with the wrong key returns a perfectly
well-formed shared secret that is simply a different one. The first thing that
notices is the AEAD tag on the content — so the refusal says that, because
"data decryption failed" over a KEM otherwise reads as a corrupted document
rather than as the wrong key.

## FrodoKEM and eFrodoKEM (section 3.6.10)

**Implemented, all twelve.** `client/src/frodokem.js` — and it is **the only
cryptographic primitive in this project with no library behind it**. `@noble`
has ML-KEM and no FrodoKEM; npm has no FrodoKEM at all; the one credible open
implementation (`microsoft/PQCrypto-LWEKE`) is C plus a Python reference. So it
is written from the specification.

**A lattice KEM written from a specification must not be trusted on a round
trip.** A subtly wrong one encapsulates and decapsulates against itself
perfectly, agrees with itself about every byte, and interoperates with nothing.
So `tests/frodokem_vectors.js` seeds NIST's AES-256-CTR-DRBG with each
published KAT seed and requires the published public key, secret key,
ciphertext and shared secret back, byte for byte, for every one of the twelve.

**That caught a real defect on its first run.** Eight of the twelve matched and
four did not — the SHAKE generator at 976 and 1344 — because specification
algorithm 8 is named *"Frodo.Gen using SHAKE128"* and means it: those parameter
sets hash with SHAKE256 everywhere else in the scheme and with **SHAKE128** for
the matrix A. Both halves round-tripped. Both halves agreed. Four of the twelve
were wrong. Nothing but the vectors could have said so.

### eFrodoKEM is not "FrodoKEM without the salt"

The trap worth stating twice. eFrodoKEM is the **original, pre-2023 scheme**:
the salt was added to the standard variant *along with a widening of the seed*,
so every length derived from `CRYPTO_BYTES` — `s`, `seedSE`, `k`, `pkh` and the
shared secret — is half what the salted variant uses, and `mu` is computed
rather than tabled. Stripping the salt and changing nothing else gives six more
parameter sets that round-trip beautifully and match no published vector.

The salt buys multi-ciphertext security when one key pair answers many
encapsulations; an ephemeral key pair answers one, which is what the `e` means
and why the variant is still worth offering.

### What it costs, measured

FrodoKEM is deliberately **unstructured** — plain Learning With Errors over
generic lattices, which is why [EUCC-ACM] names it beside ML-KEM as the
conservative choice. The price is arithmetic: the public matrix A is n×n with n
up to 1344, so one operation generates 1.8 million 16-bit entries and
multiplies them.

| | keygen | encapsulate | decapsulate |
|---|---|---|---|
| FrodoKEM-640-AES | 45 ms | 33 ms | 33 ms |
| FrodoKEM-1344-AES | 92 ms | 91 ms | 91 ms |
| FrodoKEM-1344-SHAKE | 175 ms | 171 ms | 170 ms |

That is far better than the C reference's shape would suggest, for one reason:
**A is never materialised in full.** The reference builds the whole n×n matrix
and then multiplies — at n=1344 that is 3.6 MB before anything else — while
this generates and consumes one *row* at a time in a 5 KB buffer. Same
arithmetic, and it is the single place this implementation deliberately does
not mirror the reference's structure.

## Tests

`tests/xmldsig_pqc.js` — node only, no browser, no network, 169 assertions. It
does **not** re-test the lattice: `tests/pqc_engines.js` drives FIPS 204 and
205 and `tests/hbs_signatures.js` drives RFC 8554's and RFC 9858's own
vectors, one
verification vector per XMSS parameter set and eight signatures that must not
verify. What this file adds is the XML layer — the registry against the draft's
own numbers written out by hand, the signed octets, the FIPS signature length
per identifier, the round trip, the two negatives, and HSS/LMS reporting the key
it spent — plus the two things on the encryption side that ARE this project's
own: **HKDF against RFC 5869 appendix A's published vectors** (cases 1, 2 and
3, including the zero-length-salt path a wrong implementation gets wrong), and
the
ML-KEM round trip with its encapsulation lengths, its self-describing
derivation, and the two refusals.

## Keeping the two copies in step

`common/xmldsig.js` is vendored into the mock STS as
`sts/common/vendored/xmldsig.js`, **byte-identical**, so both ends of a SAML
exchange canonicalize with the same code. A change here is copied there in the
same commit; `sts/common/vendored/CLAUDE.md` carries the rule.
