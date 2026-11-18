# JSON Web Proofs and SD-CWT (`jpt`, `sd-cwt`)

Issue #478 (phase 4 of #474). Two DRAFT credential formats, and every label
the UI gives them says *draft*:

- **JSON Web Proof** (draft-ietf-jose-json-web-proof-**15**), its algorithms
  (draft-ietf-jose-json-proof-algorithms-**15**, "JPA") and its claims
  mapping (draft-ietf-jose-json-proof-token-**15**, "JPT");
- **SD-CWT** (draft-ietf-spice-sd-cwt-**09**), selective disclosure for CBOR
  Web Tokens, presented in a Key Binding Token.

**OpenID4VCI 1.0 and OpenID4VP 1.0 name no format identifier for either.**
`vc_formats.js` lists them under their media types' names, `jpt` and
`sd-cwt`, and a Verifier that asks for them under another name won't
match. No issuer in this stack mints either format, so the tests hand the
wallet credentials made outside it.

## Modules

| Module | What it is |
|---|---|
| `client/src/jwp.js` | The JWP engine, with no DOM. It covers the Compact (JPT) and CBOR (CPT) serializations; Single Use (`SU-ES256/384/512`), MAC (`MAC-H256/384/512`, `MAC-H256K`) and BBS (through `bbs.js`); and issue, confirm, present and verify. |
| `client/src/sd_cwt.js` | The SD-CWT engine, with no DOM. It covers issuance (map-key and array-element redaction, nested, decoys), the holder's confirmation, presentation as a Key Binding Token, and the Verifier's section 9 checks, each named. |
| `client/src/sd_jwt_vc.js` | It recognises both formats and gives them the common parsed shape: one row per payload slot (JPT) or per disclosure (SD-CWT). |
| `client/src/sd_jwt_vp.js` | Presentation (`presentJpt()`, `presentSdCwt()`) and `issuerKeyFor()`, which resolves the issuer's key from its `kid` (a DID URL) or `iss` through the resolver VC-JOSE-COSE uses. |

## Where the drafts disagree with themselves

The drafts' Appendix A examples are what other implementations will
produce, so wherever the prose contradicts them, this tree follows the
bytes. `tests/jwp_engine.js` and `tests/sd_cwt_engine.js` hold it to those
bytes.

- **JWP signatures are over raw octets.** The JPA prose talks of "creating a
  JWS with the header `{"alg":"ES256"}`", but the examples sign the octets
  themselves: the issuer header, each payload, and the presentation's
  internal representation. Neither JWS-shaped reading verifies.
- **MAC: what the issuer signs.** §7.4.5 has the issuer sign the Combined
  MAC Representation. §7.4.8 step 3 says to verify that signature "over
  the Issuer Header octets", which is an erratum.
- **MAC: how many proof components a presentation has.** A presented MAC
  JWP has one component per payload slot, plus the issuer's and the
  holder's signatures (§7.4.7). §7.4.8 step 1's "two more than disclosed
  payloads" is an erratum. The A.4 prose also lists the holder's signature
  first, but the bytes put it last.
- **CPT payloads are inline CBOR values,** not the byte strings JWP's CDDL
  asks for. Each payload's octets are its CBOR encoding.
- **CPT header labels are not settled.** JPT's IANA section gives `claims`
  CBOR label 10, which JWP already gives `hpa`. Appendix A.2 instead puts
  `claims` at 6, which is JWP's `aud`. JWP's CBOR tags are still `xxx` and
  `yyy`. This tree reads an Issuer Header's 6 as `claims`, as the example
  does. It reads CPTs but does not issue them.
- **`MAC-K25519` and `MAC-K448` are refused by name.** The draft names KMAC
  over SHAKE but fixes neither its output length nor its customization
  string, so any choice here would be invented.
- **An SD-CWT's Redacted Claim Hash covers the whole byte string,** CBOR
  head included. Figure 8's `af375dc3…` is SHA-256 over `58 21 83 50 …`,
  not over `83 50 …`; hashing the contents alone reproduces nothing.

## Presenting

| Credential | What goes to the Verifier |
|---|---|
| `jpt`, SU or MAC | The chosen payload slots. The Presentation Header carries the Verifier's Client Identifier as `aud` and the request's `nonce`, and the holder signs with the presentation key the Issuer Header names (`hpk`). Presenting one JPT twice is linkable. |
| `jpt`, BBS | The chosen slots and a BBS presentation proof over the same Presentation Header. No holder key exists or is needed, and two presentations are unlinkable. ProofGen needs the issuer's public key, which is resolved from the `kid`. |
| `sd-cwt` | A Key Binding Token: a COSE_Sign1 by the `cnf` key (signed ESP256 for a P-256 key, per RFC 9864), carrying the SD-CWT with only the chosen disclosures, with `aud`, the nonce as `cnonce`, and `iat`. Sent base64url. |

Issuance step 3 runs each format's confirm interaction. Presentation step 3
verifies what went, with the issuer key resolved.

## Tests

| Test | What it checks |
|---|---|
| `tests/jwp_engine.js` | Appendix A of JPA-15 (`tests/fixtures/jwp_jpa15_vectors.json`, from the working group's CI rendering at the -15 tag, since the archived text omits the figures). The SU-ES256 JPT and CPT, BBS and MAC-H256 examples all confirm and verify, and our presentations reproduce every deterministic byte. Every algorithm round-trips, checked by node's crypto over JPA's binary forms rebuilt in the test. BBS is checked both ways against `@digitalbazaar/bbs-signatures`. Plus the negative cases. |
| `tests/sd_cwt_engine.js` | The working group's encoded examples at the -09 tag (`tests/fixtures/sd_cwt_09_vectors.json`, with Appendix C's keys): issued, nested and decoy SD-CWTs, and both KBTs. Our own tokens are checked by `@auth0/cose` and node's SHA-256. Plus the negative cases. |
| `tests/jwp_sd_cwt_presentation.js` | The presentation pages in Chrome: the JPA-15 SU-ES256 example, a BBS JPT signed by Digital Bazaar, and the SD-CWT-09 example. Each result is verified by a party outside the wallet. It needs only the client. |

The released Rust witnesses don't cover these revisions: `json-proof-token`
0.4.1 implements JWP draft -08, and `sd-cwt` 0.3.0 implements SD-CWT -08.
That's why the drafts' own examples are the oracle here.
