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
checked by default. Clearing it removes `gnap_private_jwk` and the
mtls key `gnap_mtls_key` at once and again on the next load. The
continuation token, the access token, the management URI and token,
the nonces and the mtls certificate are stored in `gnap_state` so a
finish redirect back to this page can check the interaction hash and
carry on.

**Fill a sample** asks for subject information only (`subject`,
`sub_id_formats: ["opaque"]`, RFC 9635 section 2.2), with a redirect
and a user code and a finish redirect to this page. It is the one
request iya-sts grants with no administrator involved. iya-sts issues
an access token only for a right that names a registered resource
server (STS-GNAP-0903, 0904); the one it needs no entry for, its own
Shared Signals transmitter, is a protected scope.

**Fill an SSF access sample** asks for `ssf.read` as well. iya-sts
answers `request_denied` (STS-GNAP-0719) until an administrator
declares `ssf.read` in the `oauthAllowedScope` of the application it
created for the key (`POST /admin-api/applications/add`). Then the
token is one the page can present to the transmitter: **Fill a Shared
Signals call** writes `GET /ssf/stream` with the token into the
Signed call pane.

Send signs the request and shows the signature base beside the
answer. Continue posts `interact_ref` to the continuation URI when
one was returned. A `too_fast` answer names the wait and does not
sleep; it also carries a fresh continuation token, which the page
keeps. Revoke grant is a `DELETE` of the continuation URI (section
5.4). Check hash computes `base64url(HASH(client nonce, newline,
authorization-server nonce, newline, interact_ref, newline, grant
endpoint))` with the request's `interact.finish.hash_method` (SHA-256
when it names none; SHA-512 is the other one supported) and compares
it to the `hash` parameter on the finish redirect. A finish redirect
that lands on this page is checked on load.

Token management uses the token's `manage` URI and its OWN
management token, not the access token (section 3.2.1). **Rotate the
access token** is a `POST` with no body (section 6.1). **Rotate the
client key** posts the new public key with a second signature by it
over the first (section 6.1.1); the page then signs with the new key.
**Revoke the access token** is a `DELETE` (section 6.2).

The logical request is the textarea. The signed body is the
exchange. An attached JWS proof replaces the body with the compact
serialization and sets `Content-Type: application/jose`.

## Proofs

`httpsig` covers `"@method"`, `"@target-uri"`, `"content-digest"`
when there is a body, and `"authorization"` when a token is bound.
The parameters are `created`, a nonce, `keyid` and `tag=gnap`. The
content digest is RFC 9530 (`sha-256=:<standard base64>:`).

`@target-uri` is the URI as sent (RFC 9421 section 2.2.2): the client
normalises the URL once, the way fetch and node serialise it — scheme
and host lower-cased, the default port dropped, an empty path made
`/`, no fragment — and that one string is the request's URL, the
signed component and a JWS `uri`.

`jwsd` is a detached compact JWS over the SHA-256 of the body.
`jws` is an attached compact JWS of the body. Key rotation adds a
second signature. Its label is `new-key`, its tag is `gnap-rotate`,
and it covers the first signature and the first signature-input.

`mtls` (section 7.3.2) is the TLS client certificate. Paste a
certificate and its private key in PEM (the PKI page issues one).
The grant request's key is `{"proof": "mtls", "cert": <DER, base64>}`
and nothing is signed. A browser cannot choose which certificate a
request presents, so an mtls request goes **through the API**, which
presents the pasted pair on a connection opened for that one call;
the browser path refuses it. Section 7.3.2.1 defines no key rotation
for mtls, and the page refuses one. iya-sts in development mode pins
the certificate the key names; in product mode it requires a
certificate from its client PKI bound to the application.

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
code. `GET /gnap/limits` is how the page learns the relay is there,
and it says whether the address policy is on.

For mtls the page adds `clientCertificatePem` and `clientKeyPem`. The
relay refuses half a pair, an `http://` URL, a certificate or key
that is not PEM, a key that is not the certificate's, and more than
64 KiB of either, before anything is sent. The connection is made by
an agent of its own built by the same SSRF guard, with the same
connect deadline, call timeout, response cap and redirect cap as
every other outbound call; it is never cached or kept alive, and it
is destroyed after the call. Neither PEM is logged or stored.

Many authorization servers send no
`Access-Control-Allow-Origin`. A browser call to one fails before
the grant is read. The relay is the path that still shows the
answer. The checkbox to skip certificate verification is explicit.
The default verifies.

A static deployment has no API. The page still ships. It calls the
authorization server from the browser, which works when that server
allows the origin, and it cannot make the mtls proof there. The same
trade is the one Shared Signals and SCIM make.

## What iya-sts answers

`OPTIONS /gnap` is the discovery document: the grant endpoint, the
interaction start modes, the finish methods and the key proofs.
`httpsig`, `jwsd`, `jws` and `mtls` are all four the page can use.

In product mode a key the server has not seen is `invalid_client`,
and the description says the application must be provisioned first.
That refusal is the signature succeeding. The proof was checked
before the key was looked up. A signature that does not verify is a
different sentence, and it names the signature.

In development mode the same key creates an application on first
sight, named `gnap-` and the key's identity: `gnap-jkt-<RFC 7638
thumbprint>` for a JWK, `gnap-x5t-<SHA-256 of the DER>` for a
certificate. The default sample is then granted. The SSF sample is
refused as above until the scope is declared. iya-sts asks for a
`wait` of 5 seconds and enforces it after the interaction too. A
continuation before the person approved must carry the interact_ref
it does not have yet, so it is refused before the proof is looked at.

This page does not register a client, and it does not change the
authorization server's settings. Name the display so the entry is
recognisable, and revoke what you no longer need.

## Tests

| Job | Needs | What it holds |
|---|---|---|
| `tests/gnap_engine.js` | iya-sts | the signers against node's crypto, `@target-uri` vectors, the mtls client and relay offline, the page's ids, and the default sample GRANTED for httpsig, jwsd and jws with no administrator, then revoked |
| `tests/gnap_protocol.js` | iya-sts, Chrome | for each of httpsig, jwsd, jws and mtls: the SSF scope declared, the interaction approved in a browser, the finish hash, continuation past `too_fast`, the token used at `/ssf/stream` and refused without its proof, token rotation, client key rotation (not mtls), token and grant revocation |
| `tests/api_gnap.js` | the api, iya-sts | `GET /gnap/limits`; fifteen refusals as 400s; the address policy; httpsig and jws grants through the relay and an altered body refused; the mtls proof made by the api, refused with no certificate and with a stranger's |
| `tests/gnap_page.js` | the client, the api, iya-sts, Chrome | every button of gnap.html through a grant's life, mtls on both paths, and the save box removing both keys |

The three live jobs that need a grant FAIL in product mode and say
why: a key made by a test cannot be granted anything there. The two
that approve grants hold the `sts-ssf` lock, because an approved
grant's revocation is a CAEP event on streams other jobs read.
`tests/gnap_live.js` is their shared helper.

## What this page does not do

It does not issue tokens, store grants, or speak the admin console.
It does not verify a macaroon, a biscuit or a ZCAP. Those are token
formats the authorization server chooses. The client treats the
value as opaque. It does not rotate an mtls key.
