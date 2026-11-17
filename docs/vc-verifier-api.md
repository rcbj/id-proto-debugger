# The Verifier role's api half: `/oid4vp/verifier`

When the VC Presentation workflow plays the **Verifier** (issue #364), two
things OpenID4VP 1.0 asks of a Verifier are URLs a **Wallet** connects to:

* the `request_uri` it fetches the signed Request Object from (section 5.7,
  or a POST under `request_uri_method=post`, section 5.10);
* the `response_uri` it posts its answer to under `direct_post` and
  `direct_post.jwt` (section 8.2).

A page is not an HTTP server, so it can be neither. The api hosts both on the
page's behalf, the way it hosts the SSF push receiver (`docs/ssf.md`). **The
page signs the Request Object itself and its key never leaves the browser**;
the api stores and serves a compact JWS it did not make, records what Wallets
send, and verifies nothing. `api/oid4vp_verifier.js` holds every decision and
every bound and has no express and no network; `api/server.js` is wiring.

## The routes

The page calls the first six, from the browser. After `create`, each carries
`Authorization: Bearer <secret>`. A Wallet calls the other four and presents
no credential.

| Route | operationId | Caller | Answer |
|---|---|---|---|
| `GET /oid4vp/verifier/limits` | `oid4vpVerifierLimits` | page | 200: the settings in force, `enabled`, `held` |
| `POST /oid4vp/verifier` | `oid4vpVerifierCreate` | page | 201 `{ id, secret, requestUri, responseUri, caIssuersUrl, liveSigning, expiresAt }` |
| `PUT /oid4vp/verifier/:id/request` | `oid4vpVerifierPublish` | page | 200 `{ ok: true }` |
| `PUT /oid4vp/verifier/:id/request/:signingId` | `oid4vpVerifierPublishFor` | page | 200 `{ ok: true }` (live signing) |
| `GET /oid4vp/verifier/:id/events?after=n` | `oid4vpVerifierEvents` | page | 200 `{ events, next, dropped, expiresAt }` |
| `DELETE /oid4vp/verifier/:id` | `oid4vpVerifierDelete` | page | 200 `{ ok: true, deleted }` |
| `GET /oid4vp/verifier/:id/request` | `oid4vpVerifierRequestGet` | Wallet | 200: the JWS, `application/oauth-authz-req+jwt` |
| `POST /oid4vp/verifier/:id/request` | `oid4vpVerifierRequestPost` | Wallet | 200: the same JWS, or under live signing the one the page signed for it |
| `GET /oid4vp/verifier/:id/ca` | `oid4vpVerifierCa` | Wallet | 200: DER, `application/pkix-cert` |
| `POST /oid4vp/verifier/:id/response` | `oid4vpVerifierResponse` | Wallet | 200 `{}` or `{ "redirect_uri": ... }` |

**Create** takes `{ redirectUri?, ttlMs?, idleTtlMs?, liveSigning? }`. `id` and `secret`
are each 32 hex characters of `crypto.randomBytes`. The three URLs are built
from the api's own address *as the caller reached it* (`publicBaseUrl()`), so
they share one host, which the suite's peer wallet requires of `request_uri`
and `response_uri`. `caIssuersUrl` is for the AIA extension of the Verifier's
leaf certificate. That wallet builds its chain by fetching the root from it.
The two lifetimes may be shorter than the settings and never longer.

**Publish** takes `{ requestObject, caCertificate?, redirectUri? }`.
`requestObject` must be three base64url segments with the first two
non-empty. An `alg: none` object, which has an empty third segment, is
accepted. `caCertificate` is base64 DER or a PEM block, and it must decode to
a DER SEQUENCE. A second PUT replaces the first, so a page that re-signs
serves the new object at the same `request_uri`. Nothing is verified.

**The response route** keeps every field **verbatim**. body-parser's
extended urlencoded parser would reshape a form (`a[0]=x` becomes an array,
and a repeated field collapses), so `server.js` keeps the raw text for these
paths (`keepOid4vpVerifierBody()`) and the module reads it with
`URLSearchParams`. A field sent twice is stored as an array of both values. A
JSON object body is accepted too, and each event records the `Content-Type`
the Wallet sent. Any other media type gets a 400 and is recorded as
`response-refused`. An answer to an unknown or expired session gets a **404**
and never a 200, so a Wallet is never told that an answer was received when
nobody will read it.

## Live signing (`request_uri_method=post`)

Under `request_uri_method=post`, section 5.10 has the Verifier put the
Wallet's `wallet_nonce` in the Request Object it returns, and lets it honour
`wallet_metadata`. The api cannot sign, because the key stays in the page.
Without live signing it serves the object the page signed *before* the Wallet
arrived. That object cannot contain the nonce. The `request-fetched` event
records `walletNonce` and `walletMetadata` (parsed when it is JSON), and the
page reports the mismatch.

A session created with `liveSigning: true` closes that gap with a long poll:

1. A Wallet POSTs to `request_uri`. The api records `request-fetched` with a
   `signingId` (32 hex characters), `waitMs` and `signBy` (an ISO instant),
   and **holds the Wallet's request open** for up to
   `oid4vpVerifierLiveSignWaitMs`. A POST without `wallet_nonce` waits too,
   because `wallet_metadata` alone may matter to the page.
2. The page sees the event on its next poll of `/events`. It signs a fresh
   Request Object carrying that `walletNonce` and sends it as
   `PUT /oid4vp/verifier/:id/request/:signingId` with `{ requestObject }`,
   the Bearer secret, and publish's rules (a compact JWS, at most
   `oid4vpVerifierMaxRequestObjectBytes`).
3. The held Wallet gets **that** object as `application/oauth-authz-req+jwt`,
   and the api records `request-signed` with `liveSigned: true`. The
   session's pre-signed object is not replaced, so a later GET still gets it.
4. If the page does not answer in time, the Wallet gets the pre-signed object
   with a 200, and `request-signed` has `liveSigned: false` and a `reason`.
   **A timeout falls back. It is never an error to the Wallet.** A Wallet
   that closes its connection first ends the wait the same way, with its own
   `reason`.

A PUT for a `signingId` that was never issued, was already answered or has
timed out gets a **404**. A wrong secret gets a 401. At most
`oid4vpVerifierMaxPendingSignings` Wallets wait on one session. One more is
served the pre-signed object at once: its `request-fetched` has no
`signingId`, and a `request-signed` with no `signingId` and `liveSigned:
false` names the setting. A GET to `request_uri` is never held.

Every wait is a timer, and each is cleared when its session ends: on DELETE,
on expiry (found by the sweep), and at shutdown (`shutdown()`, called on the
listener's `close` and in both signal handlers). A Wallet still held then gets
a 404, because a Request Object would only send it to a `response_uri` that
no longer exists.

**For the page.** Poll `/events` about **every 500 ms** while a live session
is waiting for a Wallet, and act on a `request-fetched` with a `signingId` at
once. The page has `waitMs` (15 s by default) to sign and PUT. Signing is
milliseconds, so a 500 ms poll leaves nearly all of it. A 404 from the PUT
means the wait ran out and the Wallet already has the pre-signed object.
Every wait ends with a `request-signed` event carrying the same `signingId`.

## Events

Each event is `{ seq, at, kind, method?, contentType?, fields?,
walletMetadata?, walletNonce?, remoteAddress?, problem?, signingId?, waitMs?,
signBy?, liveSigned?, reason? }`, and `kind` is one of `request-fetched`,
`request-signed`, `ca-fetched`, `response` or `response-refused`. The last
five members are live signing's (see above). `seq`
starts at 0 and is never reused. `after` is the `next` returned by the
previous call. Reading is a cursor and not a destructive read, so a second
tab sees the same events. A cursor that is not a number reads from 0, and a
cursor ahead of `next` is clamped to it.

## Errors

* Page-facing refusals are `{ error: "<sentence>" }`: 400 for a malformed
  value or a cap, 401 for a missing or wrong secret (with `WWW-Authenticate:
  Bearer realm="oid4vp-verifier"`), 403 from create when the role is
  disabled, and 404 for an unknown or expired session. A member of the wrong
  JSON type is the model's `400 { error, code: "EMODELREQUEST" }`.
* Wallet-facing refusals use OAuth's shape: `{ error: "not_found" |
  "invalid_request", error_description }`.
* A full api (`oid4vpVerifierMaxSessions`) and a caller at its own limit
  (`oid4vpVerifierMaxSessionsPerCaller`) both get a **400**, the same
  status the SSF receiver uses. The sentence names the setting.

## Settings (`api/env/*.js`)

| Setting | Default | |
|---|---|---|
| `oid4vpVerifierEnabled` | `true` | Only an explicit `false` turns it off |
| `oid4vpVerifierTtlMs` | 1800000 | Absolute lifetime: the default and the ceiling |
| `oid4vpVerifierIdleTtlMs` | 600000 | Lifetime with nothing touching the session |
| `oid4vpVerifierMaxSessions` | 100 | In all |
| `oid4vpVerifierMaxSessionsPerCaller` | 10 | Per caller address |
| `oid4vpVerifierMaxEvents` | 50 | Per session, oldest dropped first |
| `oid4vpVerifierMaxResponseBytes` | 262144 | One Wallet body |
| `oid4vpVerifierMaxSessionBytes` | 1048576 | All the answers one session holds, oldest dropped first |
| `oid4vpVerifierMaxRequestObjectBytes` | 65536 | A Request Object or the CA certificate (DER) |
| `oid4vpVerifierLiveSignWaitMs` | 15000 | How long a live-signing Wallet POST is held for the page |
| `oid4vpVerifierMaxPendingSignings` | 4 | Wallets held at once per session; one more is served the pre-signed object |

`oid4vpVerifierMaxSessionBytes` exists for the reason
`ssfReceiverMaxInboxBytes` does. Without it the three count caps multiply
out to more than a gigabyte held in memory.

**It is off in `api/env/embedded.js`.** On that deployment every path under
`/api` sits behind the iya-sts sign-in session cookie (`embedded/CLAUDE.md`).
A Wallet that fetches `request_uri` or posts to `response_uri` has no such
session, so the gate would answer it before this service did. Create returns
403 and names the setting, rather than returning URLs that can only fail.

## For the page

* **Detecting the api:** `GET /oid4vp/verifier/limits`. A static site has no
  api and returns nothing there (a network error or a non-JSON 404). An api
  with the role switched off returns 200 with `enabled: false`.
* **CORS** needed no change. The api's `cors()` reflects requested headers
  and allows PUT and DELETE, so `Authorization` passes the preflight.
* Sessions live in memory and are lost when the api restarts. When the api
  returns 404 for a session, create a new one and sign again. The `client_id`
  and certificates do not depend on the session, but `request_uri` and
  `response_uri` do.

`tests/api_oid4vp_verifier.js` drives the module in node and, when it is
given `API_URL`, the routes over HTTP. The model is in
`models/api/oid4vp.tsp`, and the recordings are in
`tests/fixtures/api_model/oid4vp.json`.
