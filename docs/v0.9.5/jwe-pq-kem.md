# Post-quantum and HPKE key establishment in JWE

`client/src/jose_jwe.js` encrypts and decrypts JWEs with **ML-KEM** and with
**HPKE** over the classical curves, ML-KEM and the PQ/T hybrids, X-Wing among
them (#312). Every algorithm here is from an Internet-Draft. The names, key
formats and key derivation can still change before the drafts are published.

| Module | What it does |
|---|---|
| `client/src/hpke.js` | HPKE: the DHKEMs, ML-KEM-512/768/1024 and the three PQ/T hybrids as HPKE KEMs, HKDF and the one-stage SHAKE/TurboSHAKE KDFs, AES-GCM and ChaCha20-Poly1305, base and PSK modes, Seal/Open and Export. Knows nothing about JOSE. |
| `client/src/jwe_kem.js` | The JOSE half: the algorithm tables, the keys, the pqc-kem-05 KDF and the `Recipient_structure`. |
| `client/src/jose_jwe.js` | The five segments, the AES key wrap and the content encryption, as for every other `alg`. |

None of the three has a DOM, and `hpke.js` and `jwe_kem.js` are synchronous
and use no Web Crypto, so they work on a plain-HTTP origin and in node.
`tests/hpke_jwe_engine.js` covers them; see `docs/v0.9.5/test-suite-map.md`.

## The algorithms

| `alg` | What it is | Specification |
|---|---|---|
| `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024` | ML-KEM direct key agreement: the derived key is the CEK, and the JWE Encrypted Key is empty | draft-ietf-jose-pqc-kem-05 |
| `ML-KEM-512+A128KW`, `ML-KEM-768+A192KW`, `ML-KEM-1024+A256KW` | The derived key wraps a random CEK (AES Key Wrap) | draft-ietf-jose-pqc-kem-05 |
| `HPKE-0` … `HPKE-7`, and `HPKE-0-KE` … `HPKE-7-KE` except `-4-KE` and `-6-KE` | HPKE over DHKEM(P-256, P-384, P-521, X25519, X448) | draft-ietf-jose-hpke-encrypt-22 |
| `HPKE-8`, `HPKE-9` (+`-KE`) | ML-KEM-768 + P-256, SHAKE256 | draft-reddy-cose-jose-pqc-hybrid-hpke-11 |
| `HPKE-10`, `HPKE-11` (+`-KE`) | **X-Wing** (ML-KEM-768 + X25519), SHAKE256 | draft-reddy-cose-jose-pqc-hybrid-hpke-11 |
| `HPKE-12`, `HPKE-13` (+`-KE`) | ML-KEM-1024 + P-384, SHAKE256 | draft-reddy-cose-jose-pqc-hybrid-hpke-11 |
| `HPKE-14`, `HPKE-15`, `HPKE-16` (+`-KE`) | ML-KEM-512 / 768 / 1024, SHAKE256 | draft-reddy-cose-jose-pqc-hybrid-hpke-11 |

The hybrid KEMs are the CG framework of draft-irtf-cfrg-hybrid-kems, as
draft-irtf-cfrg-concrete-hybrid-kems-02 instantiates it, used as HPKE KEMs by
draft-ietf-hpke-pq-05 over draft-ietf-hpke-hpke-02.

**Why pqc-kem-05.** Revision -06 (July 2026) is COSE-only. -05 is the last
revision that defines a JWE `alg`, the `ek` header and a JOSE KDF.

## Wire details that decide interoperability

* **`HPKE-n` (Integrated Encryption) has no `enc`.** HPKE encrypts the
  payload with `info` empty and `aad` = ASCII(BASE64URL(protected header)).
  The JWE Encrypted Key is the encapsulated secret, there is no `ek`, and the
  IV and tag segments are empty. An `enc` a page passes is not written, and a
  JWE that carries one is refused.
* **`HPKE-n-KE` (Key Encryption)** seals a random CEK with `aad` empty and
  `info` = `"JOSE-HPKE rcpt" || 0xFF || enc || 0xFF` (the `Recipient_structure`
  of -22 section 6.1, with no extra info). The encapsulated secret goes in the
  `ek` header. The `enc` works as for any other `alg`.
* **The pqc-kem-05 KDF** is KMAC256(K = SS', X, L, S = ""), with
  X = u32(len(AlgorithmID)) || AlgorithmID || u32(key bits). PartyUInfo and
  PartyVInfo are omitted, not empty. AlgorithmID is the `enc` value for direct
  key agreement and the `alg` value for key wrap. No draft publishes a vector
  for it, so the test computes it independently with `openssl mac KMAC256`.
* **PSK mode.** `HPKE-0` … `7` accept a pre-shared key: the `psk_id` header
  carries the base64url of its identifier, and the PSK is passed as `psk` to
  `encryptCompact()` / `decryptCompact()`. Reddy-11 section 5 allows only the
  base mode for `HPKE-8` … `16`, so a PSK with one of those is refused. The
  pages do not have a PSK field.

## Keys

* ML-KEM and `HPKE-8` … `16` keys are **`kty: "AKP"`** JWKs with `pub`, and
  `priv` for the private half. Each key names **exactly one** `alg`: a key for
  `ML-KEM-768` is refused for `ML-KEM-768+A192KW` or `HPKE-15`.
* An ML-KEM `priv` is the **64-byte seed d || z**. pqc-kem-05 section 10 says a
  32-byte seed, which cannot generate an ML-KEM key; -06 and
  draft-ietf-hpke-pq-05 use 64 bytes, and so does this. A 32-byte ML-KEM `priv`
  is refused with that explanation. A hybrid `priv` is its 32-byte seed.
* `HPKE-0` … `7` take ordinary `EC` or `OKP` JWKs on the suite's curve.
* All of them are JWK only. There is no PEM form of an AKP KEM key.

## Where the debugger uses them

* **JWT Tools** pane 3 and the **Encryption** page's JWE pane: both menus offer
  all 38, and **Generate Keys** makes a JWK pair for the selected `alg`.
* **Dynamic client registration**: `userinfo_encryption_alg_values_supported`
  is `jose_jwe.supportedAlgs()`, so the RP Metadata Choices request offers
  them. The ID Token encryption choice is still omitted, for the reason
  `docs/v0.9.5/oauth2-oidc/dynamic-client-registration.md` gives.
* **The VC presentation wallet**: a `direct_post.jwt` answer is encrypted to
  the first key in the Verifier's `client_metadata.jwks` the wallet can use,
  in the Verifier's order, with that key's `alg`. A Verifier that lists an
  X-Wing key first gets a post-quantum answer. HAIP keeps to ECDH-ES on P-256,
  and an mdoc presentation passes over an AKP key, which has no RFC 7638
  thumbprint for the session transcript. See `docs/v0.9.5/vc/reference-presentation.md`.

## iya-sts

iya-sts #82 implements the same algorithms on the other end. It is the test
peer, not the specification. The iya-sts release image this tree runs (1.0.0)
predates #82, so no job yet exchanges one of these JWEs with it; the
algorithms are held to the drafts' published vectors instead.
