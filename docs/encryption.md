# Encryption / Decryption — the page, its nine panes, and what it shares

`client/public/encryption_tools.html` is the Digital Signature page's sibling:
the same grid of collapsible panes, the same key-pair sub-sections, the same
stylesheet and the same page chrome, with encryption in it instead of
signatures. It needs no IdP, no api and no network — everything runs in the
browser — and it ships to the static deployments like every other tool page.

| Pane | Mechanism | Engine |
|---|---|---|
| AES | GCM, CBC, CTR, CFB, OFB, ECB at 128/192/256 | `symmetric_crypto.js` (node-forge) |
| ChaCha20-Poly1305 | RFC 8439, plus the raw keystream | `symmetric_crypto.js` (written out) |
| 3DES / DES | CBC and ECB, three-key and two-key | `symmetric_crypto.js` (node-forge) |
| RSA | OAEP (SHA-1/256/384/512) and PKCS#1 v1.5, direct **and hybrid** | `pk_encryption.js` (node-forge) |
| ECC (ECIES) | ephemeral ECDH over P-256/384/521/secp256k1/X25519 → HKDF → AEAD | `pk_encryption.js` (@noble/curves) |
| ML-KEM | FIPS 203 at three parameter sets, alone or hybridised with X25519 | `pk_encryption.js` (@noble/post-quantum) |
| DSA family | ElGamal and DHIES over RFC 3526 MODP groups | `pk_encryption.js` (forge's BigInteger) |
| JWE | RFC 7516 compact serialization | `jose_jwe.js` — **the same module the VC panes use** |
| Password-based | PBKDF2, scrypt, HKDF, and the PBES2 JWE | `@noble/hashes` + `jose_jwe.js` |

## The one thing to know before reading any of it

**Only RSA encrypts a message directly, and even RSA only encrypts a very short
one.** A 2048-bit key carries at most 190 bytes under OAEP-SHA-256 — the page
reports that number the moment a key is generated, because it depends on the
modulus, the padding *and* the hash, and meeting it as a failure afterwards
explains none of the three.

Every other asymmetric mechanism here is a **key encapsulation mechanism**: it
produces a shared secret, and the message is then encrypted symmetrically under
a key derived from it. That is not a simplification the page invented to make
the code shorter — it is what ECIES, HPKE, JWE's `ECDH-ES`, CMS, S/MIME and
every TLS cipher suite actually do. So the four asymmetric panes all emit the
same four fields (an encapsulation, an IV, a ciphertext and a tag) and each
says which part its own algorithm produced. ML-KEM makes the point unavoidable:
a KEM takes **no message at all**, so that pane has no direct mode to offer.

## DSA cannot encrypt, and the pane says so

There is no such thing as DSA encryption and no honest way to add one: DSA is a
signature algorithm and its private-key operation produces a signature, not a
decryption. A tool offering a "DSA encrypt" button is mislabelling something
else.

What a DSA-shaped key's **group** does is what the finite-field family has
always done, and both are on that pane under their own names:

* **ElGamal** — `c1 = g^k`, `c2 = m·y^k mod p`. This is the encryption scheme
  DSA's key structure comes from, and it is worth seeing for that reason. It is
  textbook: no padding, so it is **malleable** — multiply `c2` by `t` and the
  plaintext becomes `m·t`, and the scheme itself does not object. It is also
  length-limited by the group, exactly as RSA's direct mode is limited by the
  modulus.
* **DHIES** — an ephemeral Diffie-Hellman key pair in the same group, the
  agreed secret through HKDF, and an AEAD over the message. Any length,
  authenticated, and the default.

Two details about the ElGamal implementation are load-bearing. The message is
carried as an integer with a **`0x01` marker byte in front**, so a plaintext
with leading zeros survives the trip through a big integer and back — a case
`tests/crypto_engines.js` asserts directly, because ordinary text never
produces it. And that marker means an *arbitrary* mauling is usually caught on
the way back: it is an encoding check, not integrity protection, and both the
pane and the test say so in those words. The first draft of the test asserted
that a mauled ciphertext decrypts to something different, and the marker made
it throw instead; the assertion is now "never the original plaintext", by
either route.

The groups are RFC 3526's named MODP groups (14 and 15). Generating a fresh
safe prime in a browser is minutes of work for no benefit — a DH group is
public and shared by design. `tests/crypto_engines.js` runs Miller-Rabin over
both of them and checks `(p-1)/2` as well, because a mistyped digit in a
617-digit prime gives a group in which everything still works between two
copies of this code and which is not the group anybody else is using.

To **sign** with DSA, use the Digital Signature page.

## The module split, and why the tests are shaped the way they are

Every byte of cryptography on this page is in a module with **no DOM**:

```
crypto_bytes.js       bytes, base64, base64url, hex, PEM framing, compare
symmetric_crypto.js   the block/stream ciphers, and the MAC constructions
pk_encryption.js      RSA, ECIES, ML-KEM, ElGamal/DHIES
jose_jwe.js           JWE, and PBES2
key_material.js       the keystore matrix
tool_panes.js         ← the DOM, and only this
encryption_tools.js   ← the page, and only the page
```

That split is what lets **`tests/crypto_engines.js`** drive all of it in node
against things that are *not* this code: RFC 8439's ChaCha20/Poly1305/AEAD
vectors, RFC 4493's AES-CMAC vectors, the SipHash reference vectors, NIST SP
800-38A's AES-mode vectors, the FIPS 81 DES vector, FIPS 203's ML-KEM key
sizes, and node's own OpenSSL for thirteen ciphers and for RSA-OAEP in both
directions.

**Read that file before adding a "does it encrypt correctly" check to the
browser test.** `tests/encryption_tools.js` drives the page — it presses the
buttons, reads the status lines and proves the wiring — and it *cannot* tell
you the bytes are right, because everything it checks it checks against this
same code. Encrypt-then-decrypt agrees with itself whatever the implementation
does. The AEAD tag is the sharpest example: a construction that forgot RFC
8439's AAD padding or its two length counters passes every round-trip test ever
written and interoperates with nothing, and only the RFC's own tag catches it.
`crypto_engines.js` also asserts that those three modules touch no DOM, since
the whole arrangement rests on it and one `document.getElementById` for
convenience would quietly end it.

## What was already here and is now shared

The user-visible half of this work is a new page; a good deal of it was making
one implementation out of two.

* **`crypto_bytes.js` is new and holds what three files each had a copy of** —
  `jose_jwe.js` (base64url and PEM), `digital_signature.js` (all of it), and
  `key_material.js`, which took jose_jwe's rather than writing a third set.
  Base64 and base64url differ by two characters and a padding rule, `atob`
  throws on the whitespace a textarea supplies for free, and a PEM parser that
  keeps the header line produces bytes that are wrong in a way nothing notices
  until somebody else's tool reads them. One behavioural change came with the
  merge: `hexToBytes()` now **refuses** a non-hex character or an odd digit
  count instead of reading it as zero, which used to mean encrypting under a
  key that was not the one on the screen.
* **`symmetric_crypto.js` holds the Digital Signature page's MAC primitives**
  (AES-CMAC, AES-CBC-MAC, AES-GMAC, Poly1305, SipHash-2-4). Poly1305 forced the
  move: ChaCha20-Poly1305 needs exactly the same RFC 8439 section 2.5
  implementation, and two readings of that section can agree with each other
  and be wrong together. The move was verified by differential test — 1,005
  comparisons across five primitives and every message length from 0 to 200,
  against the functions as they stood in git.
* **`tool_panes.js` holds the page chrome** both pages share, and
  `css/tool_panes.css` is the stylesheet (renamed from `digital_signature.css`;
  the `ds-` class prefix is deliberately unchanged, since renaming the classes
  would touch every selector on a page whose Selenium test already passes).
* **PBES2 moved into `jose_jwe.js`**, where the rest of JWE lives, and
  `key_material.js` re-exports it so every existing caller is unchanged.
* **`x509.selfSignedCertPem()` is new**, extracted from `jwt_tools.js`.
  PKCS#12 cannot carry a bare private key — the format is a key bag beside a
  certificate bag — and `key_material.buildPkcs12()` deliberately takes the
  certificates rather than minting one, so each page mints its own throwaway.
  There were two callers the moment this page's RSA pane offered PKCS#12.

* **The keystore matrix is `key_material.js`'s on both pages now.** The
  Digital Signature page had a second implementation of it in node-forge — PEM,
  DER, JWK and PKCS#12, written again — which is precisely what that module's
  own header says must not exist twice, since these encodings are read by
  OpenSSL, keytool and somebody else's TLS stack and two readings can agree
  with each other and both be wrong. Converting it also removed a defect that
  page had been carrying quietly: it generated its RSA key as **PKCS#1**, which
  the shared matrix refuses with the bare `DataError` described below. Every
  status string the existing 152-assertion Selenium test greps for is produced
  unchanged by `key_material.js`, so that test needed no edit — which is a
  useful sign the two implementations really were saying the same thing.

`digital_signature.js` came out of this 319 lines shorter.

## Seven things that went wrong while building it

Each is now either a comment at the site or an assertion, and every one of them
failed in a way that named something other than itself.

1. **A PEM label may contain a hyphen, and the obvious strip regex cannot cross
   it.** `-----[^-]+-----` reads `-----BEGIN PRIVATE KEY-----` and stops dead
   at `-----BEGIN SLH-DSA PRIVATE KEY-----`. The header then survives into
   `atob`, which throws `Invalid character` — a complaint about base64 from a
   function handed a perfectly good PEM.

   This is the one worth reading twice, because of *how* it arrived.
   `jose_jwe.js`'s `pemToDer()` had only ever seen `PRIVATE KEY` and
   `PUBLIC KEY`, so the assumption was invisible and correct for years. The
   moment it became the shared implementation it met the Digital Signature
   page's post-quantum panes, whose keys are framed as `SLH-DSA PRIVATE KEY`
   and `ML-DSA-65 PRIVATE KEY` — and **every SLH-DSA and ML-DSA operation on
   that page failed at once**, reporting `signature was not produced`, a
   sentence about signing on a page whose signing was fine. `pemLabel()` had
   the same assumption and returned null for exactly the labels a reader most
   needs named. Both are now line-anchored rather than character-class
   anchored, and `tests/crypto_engines.js` runs eight labels through the round
   trip including three hyphenated ones. **Nothing but running the existing
   967-line Selenium suite would have caught it**, which is the argument for
   running a page's own test after a refactor that never touched that page.
2. **forge will not do two-key 3DES.** A 16-byte key is answered with `Invalid
   Triple-DES key size: 128` from inside forge's own DES code. Two-key 3DES is
   not a different algorithm, it is the same one with `K3 = K1`, so
   `expandDesKey()` builds `K1 K2 K1` and hands forge that. The test asserts
   the expansion *and* checks the result against OpenSSL's `des-ede3-cbc`,
   which is the claim being made.
3. **`jose_jwe.js` returns objects, not strings.** `encryptCompact()` gives
   `{jwe, header}` and `decryptCompact()` gives `{plaintext, header}`, because
   both hand back the protected header. Assigning the object to a field put
   `[object Object]` in the box.
4. **Web Crypto rejects with an empty message, and the pane said nothing.**
   Chrome's `crypto.subtle.decrypt` rejects a bad tag with an `OperationError`
   whose `message` is the empty string. The JWE pane, handed a token with one
   bit flipped, wrote that empty string into its status line — so the single
   most important refusal on the page was the one it reported worst.
   `describeError()` in `encryption_tools.js` now translates a bare
   `OperationError` into the sentence it means, and the browser test asserts
   the *message* rather than merely the absence of a plaintext.
5. **forge emits PKCS#1 and everything else here speaks PKCS#8.**
   `privateKeyToPem()` produces `BEGIN RSA PRIVATE KEY`; `key_material.js`,
   `jose_jwe.js` and `crypto.subtle.importKey('pkcs8', …)` all want `BEGIN
   PRIVATE KEY`. The JWK download failed with a bare `DataError` — no message,
   for the reason above. `rsaGenerateKeyPair()` now emits PKCS#8, which forge
   reads back perfectly well.
6. **Every in-progress status must end with an ellipsis, and nothing else may.**
   That is a contract with the test rather than a matter of style: on a page
   whose operations are deferred, the shape of the line is the only way to tell
   "still working" from "finished", and the check is a *trailing* ellipsis
   because finished messages quote ranges and counts containing dots. Two
   messages were written as `"Generating a key pair… (pure JS)"` and the test
   waited out its whole budget on the first of them.
7. **The expand-all switch's checkbox is invisible on purpose.**
   `css/tool_panes.css` gives `#ds_toggle_all` `opacity:0; width:0; height:0`
   and draws the slider span instead, so Selenium answers a click on it with
   "element not interactable" — which reads as a broken control rather than a
   styled one. Click the slider, which is what a person clicks.

There is an eighth that belongs to the test rather than the page, and it is the
one worth copying: **a status line left over from the previous action satisfies
the next wait instantly**, so the assertion after it grades the wrong operation
and the output field is read before the new value is written. It produced two
false passes before it produced a failure. The fix is in `clickButton()` and
`selectOption()` rather than at the thirty call sites — the version a caller
has to remember is the version that gets forgotten, and it fails by passing.

## What is deliberately not here

* **No new dependency.** ChaCha20 is written out (about eighty lines, checked
  against RFC 8439's vectors) rather than adding `@noble/ciphers`, which is the
  same choice `bbs.js` records for the same reason: this tree keeps its
  cryptographic surface small and its `npm audit --omit=dev` clean.
* **No RC2, Blowfish, IDEA or CAST.** forge has RC2 and the others have no
  maintained pure-JS implementation. DES and 3DES are here because reading what
  a legacy system wrote is a real and ordinary need; RC2 is not that.
* **The Web Crypto API is not used for the block ciphers, deliberately.**
  `crypto.subtle` offers AES in GCM, CBC and CTR and nothing else — no CFB, no
  OFB, no ECB, no DES — and Chrome refuses every AES-192 operation outright. A
  page whose point is to show what a mode does cannot offer three of six and
  refuse a key size. The JWE pane *is* Web Crypto, because JWE is, and that is
  where `A192GCM` shows up as offered-by-the-RFC and unusable-in-this-browser:
  `jose_jwe.js` probes for it and the pane reports the reason rather than
  failing with an `OperationError`.
* **No key material is stored.** Nothing on this page touches `localStorage` or
  `sessionStorage`, which is the Digital Signature page's rule and the reason
  neither appears in the key-pair storage opt-out that governs the multi-screen
  workflows.

## Where things are

| File | What |
|---|---|
| `client/public/encryption_tools.html` | the nine panes |
| `client/public/css/tool_panes.css` | the shared pane look (was `digital_signature.css`) |
| `client/src/encryption_tools.js` | the page bundle — DOM only |
| `client/src/crypto_bytes.js` | bytes and encodings, shared by five modules |
| `client/src/symmetric_crypto.js` | ciphers, modes, ChaCha20, and the MACs |
| `client/src/pk_encryption.js` | RSA, ECIES, ML-KEM, ElGamal/DHIES |
| `client/src/tool_panes.js` | the pane grid's behaviour, shared with Digital Signature |
| `tests/crypto_engines.js` | the vectors, in node |
| `tests/encryption_tools.js` | the page, in a browser |

See `docs/pki.md` for `key_material.js` and `x509.js`, and `client/CLAUDE.md`
for how a new page is registered in the two places that matter.
