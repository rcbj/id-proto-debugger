---
title: "JWT Tools"
---

# JWT Tools

**JWT Tools** (`/jwt_tools.html`) builds, signs, encrypts, verifies, and
decrypts a JSON Web Token in the browser. Open it from the **Tools** pane
on `oauth2_oidc_1.html` or `oauth2_oidc_2.html`. **← Return to debugger**
goes back to the page you came from.

Signing and verification go through `jws.js` with the Web Crypto backend.
That is why this page's algorithm list stops where `crypto.subtle` stops:
no `RSA1_5`, no Ed448, no secp256k1, and no post-quantum `alg`. Those are
on the [Digital Signature](digital-signature.md) JWS pane, which uses the
pure-JavaScript backend. Use the page over `https://` or `http://localhost`.
Web Crypto is absent anywhere else.

Nothing on this page is written to `localStorage`. Keys live for the
session.

This page has no screenshot. The pictures in the
[OAuth2 / OIDC guide](oauth2-oidc/index.md) come from the Selenium jobs, and
those jobs were not re-run for this pass.

* TOC
{:toc}

## 1. Compose

| Field or button | What it does |
|---|---|
| **JWT Header** | JOSE header as JSON. The page starts it with a sample `alg`, `typ`, and `kid`. |
| **JWT Payload** | Claims as JSON. The sample carries the RFC 7519 registered claims with placeholder values. |
| **Encoded JWT** | Compact form. Editing the header or payload rebuilds `BASE64URL(header).BASE64URL(payload).` with a trailing dot and no signature. Pasting a token decodes it back into the two boxes. A pasted signature is also copied into **JWT to Verify** and **Signed JWT**. |
| **Add Custom Claim** | **Name**, **value**, **value type** (String, Number, Boolean, JSON), and **target** (Payload or Header). **Add** inserts it. |
| **Generate RFC 9068 Token** | Replaces the three boxes with an unsigned sample access token, `typ` `at+jwt`. Sign it in pane 2. |
| **JWT RFC Compliance** | Checks the token against RFC 7519 and RFC 7515. The report is **Compliance Output**. |
| **RFC 9068 Compliance** | The same, as an OAuth 2.0 JWT access token. |

A status line under the boxes reports the sync, or a JSON parse error.

## 2. Sign (JWS)

Pick the algorithm, then **Generate Keys**, then **Generate Signed JWT**.
The menu is read when you click. A key generated for one family will not
sign another.

| Algorithm | Key **Generate Keys** produces |
|---|---|
| `RS256` `RS384` `RS512` (default `RS256`) | RSA, RSASSA-PKCS1-v1_5. Size from **RSA Key Size**. |
| `PS256` `PS384` `PS512` | RSA, RSASSA-PSS. Same size list. |
| `ES256` `ES384` `ES512` | P-256, P-384, P-521. |
| `EdDSA` | Ed25519. |
| `HS256` `HS384` `HS512` | A random shared secret. No public key. |

**RSA Key Size** is 2048, 3072, 4096, or 1024 (labelled insecure). It
applies to `RS*` and `PS*` only.

**Private Key (PKCS#8) / HMAC Secret** and **Public Key (SPKI)** show PEM.
**Show keys as JWK** rewrites both boxes as JWK. You can paste your own PEM
or JWK.

**Keystore format** is PEM, JWK, DER, or PKCS#12. **Password** encrypts the
private key (required for PKCS#12). **Download Keys** saves the file. DER
is two files. PKCS#12 export is not offered for EdDSA; use PEM, DER, or
JWK.

**Generate Signed JWT** signs the header and payload, sets `alg` to the
menu, and copies the result into **Signed JWT**, **Encoded JWT**, **JWT to
Verify**, and pane 3's **Payload to Encrypt**.

### Validate a signature

Verification uses the `alg` inside the token, not the menu above.

| Field | Default | What it does |
|---|---|---|
| **JWT to Verify** | the token just signed | Any compact JWS. |
| **Verification Type** | HMAC Secret | Also **X.509 Certificate (PEM)**, **JWKS (JSON)**, and **JWKS (URL)**. |
| **Verification Key / URL** | filled from the key you generated, and from `x5c` when the header has one | Secret, PEM, JWKS JSON, or a URL. A certificate and a bare public key both work. A bundle uses the first certificate as the signer. |
| **Validate the full certificate trust chain** | off | Opens **CA Trust Chain (PEM)**. The signer and this chain are checked together, including key usage (`digitalSignature` on the signer, `keyCertSign` on the issuers). `x5c` fills the signer into the key box and the rest into the chain. |
| **Verify** | | Writes the result to **Verification Output**. |

**JWKS (JSON)** and **JWKS (URL)** select the key by `kid` and verify every
algorithm this page can sign, not only RSA. **View certificate details**
opens the certificate page when the key box holds a certificate.

## 3. Encrypt (JWE)

| Field | Default | What it does |
|---|---|---|
| **Key Management (`alg`)** | RSA-OAEP | Also RSA-OAEP-256, ECDH-ES (P-256), and ECDH-ES+A128KW, +A192KW, +A256KW, all on P-256. |
| **Content Encryption (`enc`)** | A256GCM | Also A192GCM, A128GCM, **A128CBC-HS256**, **A192CBC-HS384**, and **A256CBC-HS512**. |
| **RSA Key Size** | 2048 | Also 3072, 4096, 1024 (insecure). Ignored for ECDH-ES. |
| **Generate Keys** | | Recipient pair: RSA for `RSA-OAEP*`, P-256 for `ECDH-ES*`. |
| **Show keys as JWK** | off | PEM or JWK, same as pane 2. |
| **Keystore format** / **Password** / **Download Keys** | PEM | Same export rules as pane 2. |
| **Payload to Encrypt** | the signed JWT from pane 2 | Any text. A payload that is itself a JWS is marked `cty: JWT`. |
| **Encrypt JWT** | | A five-part compact JWE, using the recipient public key. Copied into **Encrypted JWT (JWE)**, **JWE to Decrypt**, and pane 1's encoded box. |
| **JWE to Decrypt** | the JWE just produced | Decryption uses the recipient private key and the `alg` / `enc` in the protected header. |
| **Decrypt JWT** | | Plaintext, or the inner JWS, in **Decryption Output**. |

AES-192 (`A192GCM`, `A192CBC-HS384`, and `ECDH-ES+A192KW`) fails in
Chromium-based browsers, which do not implement 192-bit AES. Firefox and
Node accept it. The 128-bit and 256-bit choices work in all of them.

`RSA1_5` is not in the menu. Web Crypto does not implement it.
