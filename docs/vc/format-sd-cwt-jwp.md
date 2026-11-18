# SD-CWT and JSON Web Proofs (`sd-cwt`, `jpt`) — both drafts

Two **draft** credential formats. Every label the debugger gives them says
*draft*, and so does this page.

| Format | Specifications, at the revisions the code implements |
|---|---|
| `jpt`: JSON Proof Token | draft-ietf-jose-json-web-proof-**15** (JWP), draft-ietf-jose-json-proof-algorithms-**15** (JPA), draft-ietf-jose-json-proof-token-**15** (JPT) |
| `sd-cwt`: SD-CWT | draft-ietf-spice-sd-cwt-**09** |

**OpenID4VCI 1.0 and OpenID4VP 1.0 define no format identifier for either.**
The debugger uses `jpt` and `sd-cwt`, its media types' names; a peer that uses
another name will not match.

Where a draft's prose contradicts its own Appendix A examples, the code
follows the example bytes, because that is what other implementations
produce. The list of those places is in
[jwp-sd-cwt.md](../jwp-sd-cwt.md#where-the-drafts-disagree-with-themselves).

## What they are

* **JWP / JPT.** A JSON Web Proof signs an *issuer header* and a list of
  *payloads* (one claim per slot) so that the holder can present any subset.
  The algorithm decides what a presentation is:
  * **Single Use** (`SU-ES256`, `SU-ES384`, `SU-ES512`) and **MAC**
    (`MAC-H256`, `MAC-H384`, `MAC-H512`, `MAC-H256K`): the holder signs a
    presentation with the key the issuer header names (`hpk`). Presenting the
    same JPT twice is linkable.
  * **BBS**: the presentation is a BBS proof, with no holder key, and two
    presentations are unlinkable.
  * `MAC-K25519` and `MAC-K448` are refused by name: the draft does not fix
    their KMAC output length or customization string.
  * Both the compact (JPT) and the CBOR (CPT) serializations are read. CPTs
    are read, not issued.
* **SD-CWT.** Selective disclosure for CBOR Web Tokens: claims (map keys or
  array elements, nested, with decoys) are redacted to hashes, and the holder
  presents in a **Key Binding Token** (KBT): a COSE_Sign1 by the `cnf` key
  that carries the SD-CWT with only the chosen disclosures, `aud`, the nonce as
  `cnonce`, and `iat`.

## What the debugger allows (`client/src/vc_formats.js`)

| | `jpt` | `sd-cwt` |
|---|---|---|
| Algorithms | SU-ES256, SU-ES384, SU-ES512, MAC-H256, MAC-H384, MAC-H512, MAC-H256K, BBS. **Default `SU-ES256`** | fully specified COSE algorithms (RFC 9864): -9, -51, -52, -19, -53, -47. **Default `-9` (ESP256)** |
| Binding method | `jwk` | `cose_key` |
| Key proof type | `jwt` | `cwt` |
| Holder binding | the holder's signature by `hpk` (SU, MAC), or the BBS proof itself | a Key Binding Token by the `cnf` key |
| Selective | yes | yes |

## Where they appear

**Getting one.** The wallet recognises both in a Credential Response, so an
issuer that returns one can issue it through the ordinary issuance flow. **No
issuer in the suite's stack mints either**; the suite's browser test puts the
drafts' own examples, and a BBS JPT made by Digital Bazaar's library, into
the wallet's storage. There is no paste-a-credential field.

### Issuance step 3

| Check | What passes |
|---|---|
| Format | the algorithm and the number of payload slots (JPT) or redacted claims (SD-CWT), with the draft named |
| Holder binding | a holder key is named. A BBS JPT passes with none: the proof is the binding |
| Issuer signature / Issuer proof | the issuer's key is resolved from the `kid` (a DID URL) or `iss`; then the holder's *confirm* step of the draft runs over every payload, or every claim and disclosure. A key that cannot be resolved is reported and nothing is verified |

### Presentation: as a wallet

| Credential | What goes |
|---|---|
| `jpt`, SU or MAC | the chosen payload slots. The Presentation Header carries the Client Identifier as `aud` and the request's `nonce`, signed by the `hpk` key |
| `jpt`, BBS | the chosen slots and a BBS presentation proof over the same header. The issuer's public key, needed to make the proof, is resolved from the `kid` |
| `sd-cwt` | a Key Binding Token, base64url, signed ESP256 for a P-256 key |

Step 3 re-checks with the issuer key resolved: one row, *JSON Web Proof
(draft-ietf-jose-json-web-proof-15, DRAFT)* or *SD-CWT Key Binding Token
(draft-ietf-spice-sd-cwt-09, DRAFT)*, plus a *Note* row per warning.

### The Verifier page

`vc-verifier.html` does not request or verify these formats.

## Related

* [JWP and SD-CWT developer notes](../jwp-sd-cwt.md)
