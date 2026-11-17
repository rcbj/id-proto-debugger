---
title: "Using the GNAP workflow"
---

# Using the GNAP workflow

The GNAP workflow is the **GNAP** card on the landing page. It is one page,
`gnap.html`. The page is a client instance of the Grant Negotiation and
Authorization Protocol (RFC 9635). It signs a grant request with a client
key, follows the interaction, continues the grant, uses the access token,
and rotates or revokes what it was given.

This page has no screenshots. The pictures in the
[OAuth2 / OIDC guide](oauth2-oidc/index.md) come from the Selenium jobs, and
the GNAP job does not take any.

* TOC
{:toc}

## Before you start

From a checkout, follow [Getting started](getting-started.md). Then open
`https://localhost:3000` and pick **GNAP**.

The page is eight panes, top to bottom: **Client key**, **Client
certificate (mtls)**, **Authorization server**, **Grant request**,
**Interaction**, **Continuation**, **Signed call** and **Exchange**. All of
them start expanded. **Collapse all panes** folds them; clicking a pane's
title folds that one.

The line under the heading is the page's status line. Every button reports
there, and a failure is shown in the warning style.

On load the page asks the API for `GET /gnap/limits`. When the API answers,
the status line says:

> The API relay is available. A grant request is signed here and forwarded
> with the body that was signed.

When the API cannot be reached at all, it says:

> The API relay did not answer. A browser call needs the authorization
> server to allow this origin.

## Point it at iya-sts

[iya-sts](https://rcbj.github.io/iya-sts/) is a GNAP authorization server,
and **Grant endpoint** already names it:

`https://localhost:8081/gnap`

That is the address on the stacks in this repository. The test jobs use the
same path under whatever base URL they are given.

iya-sts treats a key it has never seen differently by mode:

| iya-sts mode | A new client key |
|---|---|
| development | iya-sts creates an application for the key on first sight, named `gnap-jkt-<RFC 7638 thumbprint>` for a JWK or `gnap-x5t-<SHA-256 of the DER>` for a certificate. **Fill a sample** is then granted with no administrator involved. |
| product | Refused with `invalid_client`. The description says the application must be provisioned first. The proof was checked before the key was looked up, so this refusal means the signature was good. |

The GNAP test jobs need development mode and fail, naming product mode,
without it.

To test another authorization server, put its grant endpoint in **Grant
endpoint**. If it sends no `Access-Control-Allow-Origin` for this origin,
leave **Send** on **through the API**.

## Client key

The key the client instance proves itself with. Its public half is sent in
the grant request as `client.key`. The private half stays in this browser.

| Field or button | Default | What it does |
|---|---|---|
| **Algorithm** | ES256 | Also ES384, EdDSA and RS256. The kind of key **Generate** makes. RS256 keys are 2048-bit. |
| **Generate** | | A new key pair. The status line says "Generated a ES256 key." (or the chosen algorithm) and reminds you to register the public key, or rely on a development-mode server. |
| **Use pasted key** | | Signs with the JWK in **Private key**. If the JWK has an `alg`, **Algorithm** is set to it. |
| **Save the private key in this browser** | on | Keeps the private key in `localStorage`. Clearing it removes the stored JWK and the stored mtls private key at once, and again on every load while it stays clear. |
| **Public key** | empty | Read-only. The public JWK. |
| **Private key** | empty | The private JWK. Paste one here and press **Use pasted key**. |

A pasted key must be JSON with a `d` member. Otherwise the status line says
"Paste a private JWK. It needs d, or k for a symmetric key." or "That
private key is not JSON." followed by the parser's message.

## Client certificate (mtls)

Used only when **Proof** is **mtls (through the API)** (RFC 9635 section
7.3.2).

| Field | What it holds |
|---|---|
| **Certificate (PEM)** | The client certificate. The grant request carries it as `client.key.cert`, which is the DER in base64. |
| **Private key (PEM)** | The certificate's private key, unencrypted. It follows the save box in **Client key**. |

The [PKI page](pki.md) (the **PKI / X.509** card) issues a certificate. A
self-signed one works with iya-sts in development mode, which pins the
certificate the key names.

The API presents the pair in the TLS handshake of that one call. The HTTP
tab never shows the private key.

## Authorization server

| Field or control | Default | What it does |
|---|---|---|
| **Grant endpoint** | `https://localhost:8081/gnap` | Where the grant request is sent. **Discover**, **Fill introspection**, **Fill a Shared Signals call** and the interaction hash all read this field. |
| **Proof** | httpsig | How the key is proved: `httpsig` (an HTTP message signature), `jwsd` (a detached JWS), `jws` (an attached JWS), or **mtls (through the API)**. |
| **Send** | through the API | Or **from this browser**. |
| **Skip certificate verification on the API path** | off | The API does not verify the authorization server's TLS certificate. It has no effect on a browser call. |
| **API base URL** | this deployment's API (`https://localhost:4000` on the local stack) | The API that forwards the signed request. |
| **Discover** | | An unsigned `OPTIONS` on **Grant endpoint**, which is GNAP discovery. No key is needed. |
| **Display name** | `GNAP debugger` | Sent as `client.display.name`, with this page's URL as `client.display.uri`. Empty sends no display. |
| **class_id** | empty | Sent as `client.class_id` when you fill it in. |

**Discover** reports "Discovery answered HTTP 200." and the document is in
the **Exchange** pane. iya-sts's document carries
`grant_request_endpoint` and `key_proofs_supported`. The page does not copy
anything from it into the form.

### What each proof sends

| Proof | What the request carries |
|---|---|
| `httpsig` | `Signature` and `Signature-Input` headers, tag `gnap`, covering `@method`, `@target-uri`, `content-digest` when there is a body, and `authorization` when a token is presented. A body gets a `Content-Digest` (SHA-256). |
| `jwsd` | A `Detached-JWS` header over the SHA-256 of the body. |
| `jws` | The body replaced by a compact JWS, sent as `Content-Type: application/jose`. A request with no body gets a `Detached-JWS` header instead. |
| `mtls` | Nothing signed. The TLS client certificate is the proof, so the request must go through the API. |

## Grant request

**Request JSON** is the logical request. It is empty on a fresh page.

| Button | What it does |
|---|---|
| **Fill a sample** | Asks for subject information only (`subject.sub_id_formats: ["opaque"]`), with `interact.start` of `redirect` and `user_code`, and a `redirect` finish back to this page with a new nonce. It also writes that nonce into **Client finish nonce**. iya-sts grants it with no administrator involved. |
| **Fill an SSF access sample** | The same, plus `access_token.access: ["ssf.read"]`: a token for iya-sts's Shared Signals transmitter. |
| **Send grant request** | Signs the request with the client key and sends it to **Grant endpoint**. |

**Client finish nonce** is `interact.finish.nonce`, one input to the
interaction hash.

When you send, the page adds `client.key` (and the display and class_id)
unless the JSON already names `client.key` or makes `client` a string. The
body actually signed is in the **Exchange** pane.

The status line shows "Grant response HTTP 200." on success, or "The
authorization server refused the grant: " and the error code. Through the
API, the error's description follows the code.

iya-sts refuses **Fill an SSF access sample** with `request_denied` until
an administrator declares `ssf.read` in the `oauthAllowedScope` of the
application it created for your key. The refusal names that application.
The test jobs declare it through iya-sts's `POST /admin-api/applications/add`.
The page cannot do this for you.

A successful answer fills the rest of the page: the interaction link and
user code, **Authorization server nonce**, **Continue URI** and **Continue
token**, and, when a token was issued, **Access token**, **Token management
URI** and **Management token**.

## Interaction

| Field or link | What it holds |
|---|---|
| the redirect link | `interact.redirect` from the answer. Open it to approve. |
| **User code:** | `interact.user_code`, with the link where it is entered under it. |
| **Authorization server nonce** | `interact.finish` from the answer. |
| **Finish URL** | Paste the redirect back here if it did not land on this page. |
| **interact_ref** | From the redirect back. Sent by **Continue**. |
| **hash** | The hash the server sent with the redirect. |
| **Expected hash** | Read-only. What this page computes. |
| **Check interaction hash** | Compares the two. |

Open the redirect link, sign in at the authorization server and approve the
grant. With either sample the finish URI is this page, so the browser comes
back to `gnap.html` with `hash` and `interact_ref` in the query string. The
page reads them, and when it also has both nonces it checks the hash at once.
The status line says "The interaction hash matches." or "The interaction
hash does not match."

The expected hash is RFC 9635 section 4.2.3: the client nonce, the server
nonce, the interact_ref and the **Grant endpoint** field, one per line,
hashed with the request's `interact.finish.hash_method`. SHA-256 is used
when the request names none. `sha-512` is the only other method the page
supports.

## Continuation

| Field or button | What it does |
|---|---|
| **Continue URI**, **Continue token** | `continue.uri` and `continue.access_token.value` from the last answer. |
| **Continue** | `POST` to **Continue URI**, presenting the continue token. The body is `{"interact_ref": ...}` when **interact_ref** has a value, and empty otherwise. |
| **Revoke grant** | `DELETE` of **Continue URI**, presenting the continue token (RFC 9635 section 5.4). iya-sts answers 204. |
| **Access token** | The token the grant issued. **Inspect** opens the token detail page the OAuth2 workflow uses. |
| **Token management URI**, **Management token** | `access_token.manage.uri` and its own `access_token.manage.access_token`. |
| **Rotate the access token** | `POST` with no body to the management URI, presenting the management token (section 6.1). |
| **Rotate the client key** | Generates a new key of the chosen **Algorithm** and posts it to the management URI, signed by the old key and the new one. On success the page shows and signs with the new key. |
| **Revoke the access token** | `DELETE` of the management URI (section 6.2). On success the access token, management URI and management token fields are cleared. |

A continue right after approval is often answered `too_fast`. The status
line says "The authorization server said too_fast. Wait N seconds and
continue again." The page does not wait for you. It does keep the fresh
continue token that answer carries. iya-sts asks for 5 seconds.

The status line reports each button: "Continuation HTTP 200.", "Revocation
answered HTTP 204.", "Rotated the access token. The old value is no longer
valid.", "Rotated the client key. This page now signs with the new one."
and "Revoked the access token. HTTP 204." A refusal names the error code.
**Rotate the access token** counts as success only when the token's value
actually changed.

**Rotate the client key** is refused for mtls: "RFC 9635 section 7.3.2.1
defines no key rotation for mtls. Rotate the certificate by deployment."

## Signed call

Any other request proved with the same key.

| Field or button | Default | What it does |
|---|---|---|
| **Method** | POST | Also GET, PATCH, DELETE and OPTIONS. |
| **Fill introspection** | | `POST` to `/gnap/introspect` on the grant endpoint's origin, with `{"access_token": ...}` as the body and **GNAP token** cleared. |
| **Fill a Shared Signals call** | | `GET` of `/ssf/stream` on the grant endpoint's origin, with the access token in **GNAP token** and no body. |
| **URL** | empty | Where the call goes. |
| **GNAP token** | empty | Sent as `Authorization: GNAP <token>`, and for a JWS proof bound in `ath`. |
| **Body** | empty | Signed with the client key. |
| **Send** | | Signs and sends. The status line says "Call answered HTTP " and the status. |

Introspection is signed by the resource server's key, not by the client key
that received the token. Paste that key into **Private key** and press
**Use pasted key** before **Send**.

With an SSF grant from iya-sts, **Fill a Shared Signals call** then **Send**
answers 200. A token that was rotated away or revoked answers 401.

## Reading the results

**Exchange** shows the last request of any button:

* **Signed request** is the method and URL, every header, a blank line and
  the body, exactly as sent. For `httpsig` it ends with a `--- signature
  base ---` section: the label (`sig1`, and `new-key` during a key
  rotation) and the signature base that was signed.
* **Response** is `HTTP` and the status, then the raw body.

Four panes also have an **HTTP** tab beside **Form**: **Authorization
server** (Discover), **Grant request**, **Continuation** (Continue, Revoke
grant, Rotate the client key) and **Signed call**. The tab shows that
pane's last request and response, headers and bodies. Its label carries
the status, as in **HTTP (200)**, or **HTTP (no response)**. Through the
API it shows the call the API made to the authorization server.
**Rotate the access token** and **Revoke the access token** are drawn in
no HTTP tab; read them in **Exchange**.

## Through the API or from this browser

**Through the API** posts the signed request to the API's `POST
/gnap/call`, which forwards the URL, headers and body string unchanged. It
does not sign, and the private JWK never leaves the browser. This path
works whatever CORS headers the authorization server sends.

**From this browser** calls the authorization server directly. It needs
the server to allow this origin, and it needs the browser to trust the
server's certificate. It cannot make the mtls proof.

The API answers in three ways:

| API status | Meaning | What the page shows |
|---|---|---|
| 200 | The authorization server answered, whatever its status. A GNAP error such as `invalid_client` arrives here. | The server's status and error code. |
| 400 | The API refused the request before sending it. | The API's reason. |
| 502 | The authorization server could not be reached. | "The authorization server could not be reached: " and the network error. |

## On the deployed sites

The static sites (idptools.com and test.idptools.com) ship `gnap.html`,
and the GNAP card is not greyed out. They have no API, so `POST /gnap/call`
does not exist there.

* Set **Send** to **from this browser**. The page does not switch it for
  you.
* The authorization server must allow the site's origin (CORS).
* The **mtls** proof cannot be made.
* Generating keys, signing, the interaction hash and **Inspect** all run in
  the browser and work.

## Common errors

| Message | What it means |
|---|---|
| Generate or paste a client key first. | **Send grant request** with no key. |
| A script error about `null` | Another signed button pressed with no key. Generate or paste one. |
| The grant request is empty. / The grant request is not JSON. | **Request JSON** is blank or not JSON. |
| The request URL is not an absolute URL: | A URL field is not absolute. |
| The grant URL is not a URL. | A fill button could not read **Grant endpoint**. |
| There is no continuation URI yet. | **Continue** before a grant answer. |
| The token response has no management URI yet. | A rotate button with no **Token management URI**. |
| There is no access token to inspect yet. | **Inspect** with no token. |
| The mtls proof is the TLS client certificate, and a browser cannot choose which one a request presents. Send it through the API. | mtls with **Send** on **from this browser**. |
| The client certificate is not a PEM certificate. / The client certificate needs its private key, in PEM. | The mtls pane is incomplete. |
| clientKeyPem is not the private key of the certificate in clientCertificatePem. | The API found the mtls key and certificate do not match. |
| A client certificate is presented in a TLS handshake, and an http:// URL has none. Use https://. | mtls to an `http://` endpoint. |
| A GET carries no body in RFC 9635, ... | A Signed call with **Method** GET or OPTIONS and a **Body**. Clear the body. |
| `invalid_client`, description naming product mode | iya-sts in product mode, and your key is not provisioned. |
| `request_denied` on the SSF sample | `ssf.read` is not declared on the key's application. |
| `too_fast` | Wait the number of seconds given, then **Continue** again. |
| The interaction hash does not match. | A nonce, the interact_ref or **Grant endpoint** differs from what the server used. Changing **Grant endpoint** after sending is enough. |
| A CORS error, or `Failed to fetch`, on the browser path | The authorization server does not allow this origin. Use **through the API**. |

## What the browser keeps

In `localStorage`:

* `gnap_state`: the form — algorithm, endpoint, proof, send path, the
  certificate-check box, API URL, request, mtls certificate, display name,
  class_id, both nonces, and the continue, access and management tokens and
  URIs. They are kept so a finish redirect back to this page can check the
  hash and carry on.
* `gnap_private_jwk` and `gnap_mtls_key`, only while **Save the private key
  in this browser** is checked.
* `gnap_access_token`, written when you press **Inspect**.

The page does not register a client or change the authorization server's
settings. Revoke grants you no longer need.

## For developers

How the signer, the proofs and the API relay work, and which test jobs hold
them, is in [GNAP](gnap.md).
