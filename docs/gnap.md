# GNAP — a client instance

Covers `client/public/gnap.html`, `client/src/gnap.js`,
`client/src/gnap_client.js`, `client/public/css/gnap.css`,
`api/gnap_proxy.js`, `POST /gnap/call` and `tests/gnap_engine.js`.

The page is a Grant Negotiation and Authorization Protocol client
(RFC 9635). It was added for issue #292. iya-sts is an authorization
server. This page is the client that talks to one.

## An independent copy

The signer was written from RFC 9635, RFC 9421, RFC 9530 and
RFC 8941. The shape of the proofs follows the client the iya-sts
tests use. It is not vendored, not a submodule, and not kept in
step by a script. The two copies evolve independently. A later
change to that test client does not arrive here, and a change here
does not go back.

`gnap_client.js` has no DOM and no network. The page decides where
a prepared request is sent. Signing uses Web Crypto, which is the
same API in the browser and in node.

## What the page does

Generate an ES256, ES384, EdDSA or RS256 key, or paste a private
JWK. The public half is what the grant request carries. The private
half stays in this browser. The checkbox `gnap_save_keypair` is
checked by default. Clearing it removes `gnap_private_jwk` at once
and again on the next load. The continuation token, the access
token and the nonces are stored in `gnap_state` so a finish
redirect back to this page can check the interaction hash.

Fill a sample builds a request for this authorization server's
Shared Signals transmitter (`type` `ssf`, action `read`), with a
redirect and a user code, and a finish redirect to this page. That
access is the one resource an authorization server can name without
a registered resource server. Replace it when the grant is for
somewhere else.

Send signs the request and shows the signature base beside the
answer. Continue posts `interact_ref` to the continuation URI when
one was returned. A `too_fast` answer names the wait and does not
sleep. Rotate posts the new public key to the token's management
URI, with a second signature over the first. Revoke is a `DELETE`
of the continuation URI. Check hash computes
`base64url(HASH(client nonce, newline, authorization-server nonce,
newline, interact_ref, newline, grant endpoint))` with the request's
`interact.finish.hash_method` (SHA-256 when it names none; SHA-512 is
the other one supported) and compares it to the `hash` parameter on
the finish redirect.

The logical request is the textarea. The signed body is the
exchange. An attached JWS proof replaces the body with the compact
serialization and sets `Content-Type: application/jose`.

## Proofs

`httpsig` covers `"@method"`, `"@target-uri"`, `"content-digest"`
when there is a body, and `"authorization"` when a token is bound.
The parameters are `created`, a nonce, `keyid` and `tag=gnap`. The
content digest is RFC 9530 (`sha-256=:<standard base64>:`).

`jwsd` is a detached compact JWS over the SHA-256 of the body.
`jws` is an attached compact JWS of the body. Key rotation adds a
second signature. Its label is `new-key`, its tag is `gnap-rotate`,
and it covers the first signature and the first signature-input.

Mutual TLS is not offered. It is a property of the TLS connection,
and a browser cannot present a client certificate this page chose.

The access token is opaque (RFC 9635 section 3.2). Introspection is
a signed call the resource server's key makes. Fill introspection
writes the URL and the body and leaves the key for the user to
paste.

## The API relay

The default path is through the API. `POST /gnap/call` forwards the
URL, the headers and the body string the page signed. It does not
sign, and it does not re-encode the body. A refusal by this service
is a 400. A network failure is a 502. A GNAP error from the
authorization server is a 200 carrying that status and the error
code. `GET /gnap/limits` is how the page learns the relay is there.

Many authorization servers send no
`Access-Control-Allow-Origin`. A browser call to one fails before
the grant is read. The relay is the path that still shows the
answer. The checkbox to skip certificate verification is explicit.
The default verifies.

A static deployment has no API. The page still ships. It calls the
authorization server from the browser, which works when that server
allows the origin. The same trade is the one Shared Signals and
SCIM make.

## What iya-sts answers

`OPTIONS /gnap` is the discovery document: the grant endpoint, the
interaction start modes, the finish methods and the key proofs.
`httpsig`, `jwsd` and `jws` are the three this page can produce.
`mtls` is in that document and is not in the menu here.

In product mode a key the server has not seen is `invalid_client`,
and the description says the application must be provisioned first.
That refusal is the signature succeeding. The proof was checked
before the key was looked up. A signature that does not verify is a
different sentence, and it names the signature.

In development mode the same key creates an application on first
sight, named `gnap-jkt-` and the key's RFC 7638 thumbprint. The
sample request is then still refused: `ssf.read` is iya-sts's own
protected scope, so the answer is `request_denied` until an
administrator declares `ssf.read` in that entry's
`oauthAllowedScope` (`POST /admin-api/applications/add`). That
refusal also means the signature verified, but it is not a grant.
This page does not register a client, and it does not change the
authorization server's settings. Name the display so the entry is
recognisable, and revoke the continuation when the grant is no
longer needed.

`tests/gnap_engine.js` does the administrator's step itself. It
declares the scope, requires a grant for each of `httpsig`, `jwsd`
and `jws`, continues one (iya-sts answers `too_fast` with a fresh
continuation token), revokes all three, and forgets the entry. A
denial is not accepted as a pass. Against a product-mode server the
key is unprovisioned, so only the proofs are checked, and the job
logs that no grant was issued.

## What this page does not do

It does not issue tokens, store grants, or speak the admin console.
It does not verify a macaroon, a biscuit or a ZCAP. Those are token
formats the authorization server chooses. The client treats the
value as opaque. It does not present a client certificate.
