# The debugger as the OpenID4VP Verifier

`vc-verifier.html`, its bundle `client/src/vc_verifier.js`, and the engine
behind it, `client/src/vp_verifier.js`. Issue #364.

The VC presentation workflow has two roles. The **Wallet** is the debugger
answering somebody else's Verifier: `vc-presentation-0.html` through `-3`,
described in `docs/vc-presentation-guide.md`. The **Verifier** is this page:
the debugger asks a wallet for claims and checks the answer. The role
selector at the top of `vc-presentation-0.html` links the two.

## What the page does

1. **What to ask for.** One credential query from the fields (format, `vct`,
   `doctype` or type values, claim paths, holder binding), generated as a
   DCQL query (OpenID4VP 1.0 section 6). The DCQL textarea stays editable, so
   a second query or `credential_sets` can be written by hand; a hand-edited
   query is kept across page loads.
2. **How to ask.** The Client Identifier prefix (`x509_hash`,
   `x509_san_dns`, or `redirect_uri` for an unsigned request), the response
   mode (`direct_post`, or `direct_post.jwt` encrypted to a P-256 key made for
   the run), and the delivery: by reference with `request_uri` (GET, or
   `request_uri_method=post`) or by value.
3. **Hand it to a wallet.** The `openid4vp://` Authorization Request, a link
   that opens it on this device, the decoded Request Object, and the
   Verifier's root certificate.
4. **What the wallet sent.** The api's log of the wallet's calls, then every
   check on the answer as its own row: PASS, FAIL or SKIP. An answer can
   also be pasted and checked; that half needs no api.

## Why the api is involved

`direct_post` has the wallet POST its answer to a `response_uri`, and a
request by reference has the wallet fetch a `request_uri`. A page is not an
HTTP server, so the api hosts both, as it hosts the Shared Signals push
receiver. **The api is a store.** The page makes the key pair and the
certificates and signs the Request Object in the browser; the api is given
the compact JWS and the root certificate and serves them, and keeps what the
wallet posts until the page polls for it. The private keys and the api
session's secret are held for one page load and never stored. The routes,
settings and limits are in `docs/vc-verifier-api.md`.

On the static sites there is no api, so the page cannot host a request. It
says so, and pane 4 still checks a pasted answer.

## The certificate

Each request gets a new self-signed P-256 root and a leaf signed by it. The
leaf's subjectAltName is the api's host name (the host of `response_uri`),
which is what `x509_san_dns` names, and its Authority Information Access
`caIssuers` URL is the api's `/oid4vp/verifier/<id>/ca`, which serves the
root. The Request Object's `x5c` carries the leaf only. A wallet that
completes a chain from AIA, as `rcbj/oid4vc-wallet` does, finds the root
there; any other wallet can be given the root from pane 3 as a trust anchor.

## What is checked

`vp_verifier.verifyResponse()` returns one entry per check and never folds
two into one. The response checks are the `state`, the decryption of a
`direct_post.jwt` answer, and that every required credential query was
answered. Per format:

* **dc+sd-jwt**: the issuer's signature (an `x5c` in the issuer JWT, else
  JWT VC Issuer Metadata, else a DID), the `typ`, the `vct`, validity, every
  disclosure's digest against `_sd`, and every requested claim disclosed. For
  the Key Binding JWT: its `typ` and `alg`, `nonce`, `aud`, `iat`,
  `sd_hash`, and its signature against `cnf.jwk`.
* **jwt_vc_json**: the VP JWT's signature against the holder's key, its
  `nonce` and `aud`, and each embedded credential's issuer signature and
  validity.
* **mso_mdoc**: the issuer-signed checks `mdoc.js` makes, the device
  signature over the OpenID4VP session transcript, and the doctype.
* **ldp_vc**: a `bbs-2023` derived proof, and the proof's challenge and
  domain. Other cryptosuites are reported as SKIP.

Status lists are reported as SKIP. They, the Digital Credentials API, QR
codes and the remaining Client Identifier prefixes are PR 3 of #364.

## A pre-signed Request Object and `wallet_nonce`

Under `request_uri_method=post` a wallet may send a `wallet_nonce` that the
Request Object should then contain (section 5.10). The page signs the Request
Object before any wallet asks for it, and the api cannot sign for it, so the
object cannot echo a `wallet_nonce`. The page shows the nonce the wallet sent
and says that it was not echoed.

## Tests

| Test | Kind | What it covers |
|---|---|---|
| `tests/vp_verifier_engine.js` | node | the DCQL builder, the certificate, the Request Object read back by the Wallet's own `verifyX509Request()`, and a round trip per format, with a negative case for each check |
| `tests/api_oid4vp_verifier.js` | node | the api's routes, limits and expiry |
| `tests/vc_verifier_page.js` | browser | the page creates a request through the api; node plays the wallet and posts an answer; every check on the page passes, and a tampered answer fails the check it targets |

The independent wallet in the suite, `rcbj/oid4vc-wallet`, is PR 2 of #364.
