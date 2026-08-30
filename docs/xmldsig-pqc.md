# Post-quantum XML Signature and XML Encryption

**Status: the signature half is implemented; the encryption half is not yet.**
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

## The encryption half, and why it is a separate piece of work

The draft also defines key-encapsulation identifiers — section 3.6.9 for
**ML-KEM** at three parameter sets and section 3.6.10 for **FrodoKEM** at
twelve. Neither is implemented yet, and the reason is that a KEM is not key
transport:

* XML Encryption's `EncryptedKey` carries a **wrapped session key**. A KEM
  produces a *ciphertext and a shared secret*, and the draft says the shared
  secret feeds a key derivation function — HKDF,
  `http://www.w3.org/2021/04/xmldsig-more#hkdf` — to produce the content
  encryption key. So the `CipherValue` is the encapsulation and the CEK is
  **derived rather than transported**, which is a different shape through
  `encryptXml()` than the RSA path it is written around.
* The recipient's key is not in an X.509 certificate, which is the only
  recipient form that path accepts today; it would travel as
  `dsig11:DEREncodedKeyValue`, the element the signature half already uses for
  public keys XMLDSIG has no structure for.
* **ML-KEM is available** — `client/src/pk_encryption.js` has all three
  parameter sets. **FrodoKEM is not, in any JavaScript library**: `@noble` has
  none, and the credible open implementation (`itzmeanjan/frodokem`) is C++
  headers. Those twelve identifiers need the scheme written from its
  specification and held to its published KAT files, which is the largest single
  piece of this work and the last of it.

## Tests

`tests/xmldsig_pqc.js` — node only, no browser, no network. It does **not**
re-test the lattice: `tests/pqc_engines.js` drives FIPS 204 and 205 and
`tests/hbs_signatures.js` drives RFC 8554's and RFC 9858's own vectors, one
verification vector per XMSS parameter set and eight signatures that must not
verify. What this file adds is the XML layer — the registry against the draft's
own numbers written out by hand, the signed octets, the FIPS signature length
per identifier, the round trip, the two negatives, and HSS/LMS reporting the key
it spent.

## Keeping the two copies in step

`common/xmldsig.js` is vendored into the mock STS as
`sts/common/vendored/xmldsig.js`, **byte-identical**, so both ends of a SAML
exchange canonicalize with the same code. A change here is copied there in the
same commit; `sts/common/vendored/CLAUDE.md` carries the rule.
