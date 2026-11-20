---
title: "Digital Signature"
---

# Digital Signature

**Digital Signature** (`/digital_signature.html`) generates keys, signs or
MACs a value, and checks the result, in the browser. Cryptography here is
pure JavaScript, so the page works without Web Crypto and can offer hashes
and curves that `crypto.subtle` does not. Keys are not written to
`localStorage`. A certificate you open in **View certificate details** is
the one exception: that PEM is handed to the certificate page through
`localStorage`.

Open it from the **Tools** pane on the OAuth2 / OIDC pages. The
introduction on the page numbers these twelve panes in this order. When
the page loads, the XML **SignatureMethod** menu gains the draft group
described in [Post-quantum XML Signature](xmldsig-pqc.md).

This page has no screenshot. The pictures in the
[OAuth2 / OIDC guide](oauth2-oidc/index.md) come from the Selenium jobs, and
those jobs were not re-run for this pass.

* TOC
{:toc}

## The twelve panes

Click a title to collapse that pane. **Expand all panes** / **Collapse all
panes** is the switch at the top.

| # | Pane | Default algorithm | Where the detail lives |
|---|---|---|---|
| 1 | SLH-DSA | SLH-DSA-SHA2-128s, pure (no pre-hash) | On this page |
| 2 | Stateful hash-based signatures (LMS/HSS and XMSS) | HSS, `LMOTS_SHA256_N32_W8`, `LMS_SHA256_M32_H5`, one tree | [Stateful hash-based signatures](hbs.md) |
| 3 | RSA | PKCS#1 v1.5, SHA-256, 2048-bit | On this page |
| 4 | ECC | ECDSA P-256, SHA-256 | On this page |
| 5 | ML-DSA | ML-DSA-65, pure (no pre-hash) | On this page |
| 6 | Composite ML-DSA | ML-DSA-44-ES256 | On this page. Draft. |
| 7 | BBS | BLS12-381-SHA-256, UTF-8 messages | On this page |
| 8 | JWS | HS256, compact serialization | On this page |
| 9 | XML Digital Signature | Enveloped, RSA-SHA256, exclusive C14N | On this page, plus [Post-quantum XML Signature](xmldsig-pqc.md) |
| 10 | Keyed-hash MACs | HMAC-SHA256 | On this page |
| 11 | Block-cipher MACs | AES-CMAC | On this page |
| 12 | Universal-hash MACs | Poly1305 | On this page |

Panes 1–9 are signatures (panes 8 and 9 can also carry an HMAC). Panes
10–12 are MACs: a shared secret, and no public key to check them with.

Each signature pane has a **Value**, a **Signature** box, **Generate
Keys**, the private and public key boxes, a keystore format with an
optional password, **Download Keys**, **Sign**, and **Validate
Signature**. Pick the algorithm before **Generate Keys**. The menu is read
at click time.

## Pane 1 — SLH-DSA

FIPS 205. Twelve parameter sets: SHA2 or SHAKE, at 128, 192, and 256 bits,
each in an `s` and an `f` variant. **Pure** is the default. **HashSLH-DSA**
is a different algorithm, not a display option. Signing is pure JavaScript
and can take several seconds. The small-signature (`s`) sets and the
256-bit sets are the slow ones. Download formats: PEM (default), JWK, DER,
PKCS#12.

## Pane 2 — LMS/HSS and XMSS

The private key changes every time it signs. The pane keeps the index in
the private-key box and rewrites it on **Sign**. Spending one one-time key
twice is a separate button, so the failure is something you can watch.
Parameter sets, the HSS layer count, and the XMSS^MT height are all on the
pane. Read [Stateful hash-based signatures](hbs.md) before you change one:
a signature that verifies against itself can still be the wrong scheme.

## Pane 3 — RSA

**Padding** is PKCS#1 v1.5 (default) or PSS. **Hash** defaults to SHA-256
and also offers SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512,
BLAKE2b-512, BLAKE3-256, RIPEMD-160, SHA-1, and MD5. BLAKE2b and BLAKE3 are
PSS only. **Key Size** is 2048 (default), 3072, 4096, or 1024 (insecure).
Keys are PEM.

## Pane 4 — ECC

**Curve** defaults to ECDSA P-256 and also offers P-384, P-521, secp256k1,
Ed25519, Ed448, Schnorr (BIP-340), and BLS12-381. **Hash** applies to
ECDSA. EdDSA, Schnorr, and BLS hash the message themselves. Keys are raw
hex. The keystore default is JWK. Schnorr and BLS have no JWK export; copy
the hex.

## Pane 5 — ML-DSA

FIPS 204. **ML-DSA-65** is the default, with ML-DSA-44 and ML-DSA-87. The
private key the page writes is the 32-byte seed (RFC 9964). **Pure** is the
default. **HashML-DSA** is a different algorithm. A context string is a
separate field from the message. Keys download as PEM or JWK.

## Pane 6 — Composite ML-DSA

Draft `draft-ietf-jose-pq-composite-sigs-03`. One signature is an ML-DSA
signature and a traditional signature, and both halves have to verify.
Default **ML-DSA-44-ES256**. Also ML-DSA-65-ES256, ML-DSA-87-ES384,
ML-DSA-44-Ed25519, ML-DSA-65-Ed25519, and ML-DSA-87-Ed448. The private key
box is the 32-byte ML-DSA seed followed by the traditional private key.
Download is PEM or JWK. The X.509 encoding of a composite is a different
draft and lives on the [PKI](pki.md) page.

## Pane 7 — BBS

Signs a list of messages, one per line, and can derive a proof that
reveals a subset. **Ciphersuite** defaults to `BLS12-381-SHA-256` (also
`BLS12-381-SHAKE-256`). **Input encoding** defaults to UTF-8 text; hex
reproduces the draft's test vectors. **Header** is signed and cannot be
withheld. **Disclosed Indexes** and **Presentation Header** feed **Derive
Proof** and **Verify Proof**. Two proofs from one signature differ. That
is the unlinkability. Download default is JWK.

## Pane 8 — JWS

The payload has to be JSON. **Sign** refuses anything else.

**Algorithm** defaults to **HS256**. The menu also has HS384, HS512, the
RS*, PS*, and ES* sets, Ed25519, Ed448, ES256K (secp256k1), ML-DSA-44/65/87
(RFC 9964), two SLH-DSA draft identifiers
(`draft-ietf-cose-sphincs-plus-10`), six composite draft identifiers, and
`none` (an unsecured JWS).

**Serialization** defaults to compact. Flattened JSON and general JSON are
the other two. Optional header fields: **typ**, **cty**, **kid**, an extra
protected-header JSON object, and an unprotected header (JSON
serializations only).

Checkboxes, all off:

* **Detached payload**
* **Unencoded payload (b64=false)** (RFC 7797)
* **Embed the public key (jwk)**
* **Compact the JSON before signing**
* **Validate with the algorithm from the header** — off so the verifier
  uses the algorithm you picked. Turning it on is how an algorithm-confusion
  case is reproduced.

**Secret encoding** for HMAC defaults to hex (also base64url and UTF-8).
**Key Size** for RS* and PS* defaults to 2048. **Generate Keys**, then
**Sign** or **Validate Signature**. Download default is JWK.

## Pane 9 — XML Digital Signature

**Signature Type** defaults to **Enveloped** (also enveloping and
detached). **Sign** refuses XML that is not well-formed. **Validate XML**
checks that without signing.

**SignatureMethod** in the HTML defaults to **RSA-SHA256** and also lists
RSA-SHA384, RSA-SHA512, RSA-SHA1, three RSASSA-PSS methods (RFC 9231),
ECDSA-SHA256/384/512, ECDSA-SHA1, and four HMAC methods. On load the page
appends an optgroup labelled **Post-quantum —
draft-eastlake-rfc9231bis-xmlsec-uris**, sixteen ML-DSA, SLH-DSA, and
HSS-LMS methods. The note above the menu says those sixteen are a draft.
The identifiers and why they say *draft* are in
[Post-quantum XML Signature](xmldsig-pqc.md).

| Field | Default |
|---|---|
| **DigestMethod** | SHA-256 (also SHA-384, SHA-512, SHA-1) |
| **CanonicalizationMethod** | Exclusive C14N 1.0, with and without comments, and inclusive C14N 1.0 the same way. C14N 1.1 is absent. |
| **SignedInfo InclusiveNamespaces PrefixList** | empty. Exclusive C14N only. |
| **Reference URI** | derived when blank |
| **Placement (enveloped)** | Last child of the root. Also first child, and directly after `<Issuer>` (SAML 2.0 style). |
| **Signature Id** | none |
| **KeyInfo** | X509Data / X509Certificate for RSA |

**Generate Keys** follows the SignatureMethod: an RSA pair and a
self-signed certificate, an ECDSA pair, or a shared secret for HMAC.

## Panes 10–12 — MACs

Each has a value, a MAC box, an algorithm menu, **Generate Key**, **Compute
MAC**, and **Verify MAC**.

* **Keyed-hash:** HMAC-SHA256 (default), HMAC-SHA384, HMAC-SHA512,
  HMAC-SHA3-256, HMAC-SHA3-512, HMAC-SHA1, KMAC128, KMAC256, and keyed
  BLAKE2b, BLAKE2s, and BLAKE3.
* **Block-cipher:** AES-CMAC (default), AES-CBC-MAC, AES-GMAC. The GMAC
  demo uses a fixed all-zero nonce so the tag is repeatable.
* **Universal-hash:** Poly1305 (default, a one-time key) and SipHash-2-4.

UMAC, VMAC, and PMAC are not in the menus.
