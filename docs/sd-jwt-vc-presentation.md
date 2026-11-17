# The SD-JWT VC presentation workflow (`vc-presentation-{0,1,2,3}.html`)

Read this before changing any `vc-presentation-*` page or `sd_jwt_vp.js`. The credential it presents comes from the issuance workflow, and the two meet at the `localStorage` keys and nowhere else.

The **SD-JWT VC presentation workflow** (`vc-presentation-{0,1,2,3}.html`, bundles `vcpresentation0..3`) is the other half: a Verifier asks for some of a credential over **OID4VP 1.0** and the wallet answers with an **SD-JWT+KB** (RFC 9901 section 4.3). It is reached from its own landing-page card and presents whatever credential the issuance workflow left in `localStorage` — the two workflows meet at those keys and nowhere else. Step 0 chooses the flow (request by value with the `redirect_uri` client identifier prefix, a **signed** Request Object by reference for a pre-registered client, or cross-device by QR code) and all three *start at the verifier*, because a presentation is something a verifier asks for. Step 1 reads the request — fetching and verifying the Request Object when it is passed by reference — and decodes the **DCQL** query into claim paths shown against what the credential actually holds; nothing is disclosed there. Step 2 is the point of the format: a checkbox per Disclosure, defaulting to exactly what was asked for, and it builds the presentation in front of you — the issuer-signed JWT, the selected Disclosures, and a **Key Binding JWT** whose `nonce` is the request's, whose `aud` is the verifier's Client Identifier, and whose `sd_hash` covers exactly the bytes being sent. Step 3 shows what the Verifier ANSWERED — the Response Endpoint's reply to the `direct_post`, which is all OID4VP gives a wallet (section 8.2: 200 and, optionally, a `redirect_uri`) — next to the wallet's own re-check of those bytes, and an *Answered the request?* line comparing what the DCQL asked for against what actually went — **by name, not by count** (counting made withholding one claim and disclosing one unasked-for claim cancel out, and plain withholding read as the reassuring "nothing more than was asked for"). Both directions are named there because neither is something a verifier must report: extra claims are accepted silently, and a presentation that answers only part of the query may be accepted too — walt.id's verifier has no DCQL-fulfilment policy at all, so it says `SUCCESSFUL`. **The pane was "What The Verifier Decided" until 2026-10-23**, filled check by check from `/oid4vp/result/<state>` — a demonstration endpoint of iya-sts's that no other Verifier had (walt.id's answered 404) and that iya-sts #594 deleted. A Verifier's verdict is its own back-office record and a wallet has no route to it, so the pane is "What The Verifier Answered" now, for every Verifier alike; the presentation jobs read iya-sts's verdict where an operator does, at `GET /admin-api/verifications?state=` (`verdictOfWhatWasSent()` in `tests/jwt_vc_json_common.js`).

**Which private key the presentation is signed with is `sd_jwt_vc.js`'s `boundPrivateJwk()`, and it reads the paste field for a reason.** The credential names the key it is bound to in `cnf.jwk`; a Key Binding JWT signed with any other key produces a presentation the Verifier refuses with a complaint about a signature, which says nothing about the key. So that function tests everything in storage against the cnf — the holder key **and** the DPoP key, since under Holder of Key the DPoP key *is* the holder key and both are present at once — and only then looks at what the reader pasted. Until 2026-09-01 that last step called `readHolderPrivateJwk()`, which prefers **storage**, so it handed back the same stored key the loop had just rejected: **a reader who pasted the correct key had it ignored and was told the key they pasted was wrong**, about a key they had not pasted. The storage-first read is right for `readHolderPrivateJwk()`'s other callers on the refresh page (they want the holder key from wherever it is), so the field read was split out as `pastedHolderPrivateJwk()` rather than the shared function being changed. The four outcomes — a pasted key that matches, one that does not, an unreadable paste, and nothing pasted at all — are now four different sentences and are pinned one per check in `tests/sd_jwt_vc_engine.js`; the last of them was **unreachable** while any holder key was stored.

Three things that are easy to get wrong here, and are therefore tested: `sd_hash` is computed over `<Issuer-signed JWT>~<Disclosure>*~` **including the trailing tilde**, so it commits to the exact byte string; the KB-JWT must verify against the credential's own `cnf.jwk` and not a key the presenter nominates; and the `vp_token` is a JSON object **keyed by the DCQL credential query id**, each value an array of presentations (OID4VP section 8.1), not a bare string.

## The VC Presentation workflow, step by step

Issuance puts a credential in a wallet; **presentation** is what it is for. This workflow plays the wallet's part
when a **verifier** asks for part of a credential over
[OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
(OID4VP 1.0), answering with the presentation format
[RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html) defines: an **SD-JWT+KB**. It has its own card on the
landing page, and it presents whatever credential the issuance workflow left in this browser — the two workflows
meet at those `localStorage` keys and nowhere else.

### Step 0 — Choose a flow (`vc-presentation-0.html`)
The three shapes an OID4VP request can take. All of them **start at the verifier**, because a presentation is
something a verifier asks for:

| Flow | How the request travels | What the wallet can prove about the asker |
|---|---|---|
| Same device, by value | The whole request in the query string | Nothing cryptographic: `client_id` uses the `redirect_uri` prefix, so the request *cannot* be signed. What binds it to the verifier is that the presentation goes to that same URL |
| Same device, signed by reference | `client_id` + `request_uri`; the wallet fetches a signed Request Object ([RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html)) | That the request really came from a pre-registered client with a known key, and that the claims asked for are the ones it signed |
| Cross device | A QR code (`openid4vp://…`) on the verifier's screen | The same as by value — and nothing can be redirected, which is why `direct_post` exists |

The page also says whether this wallet is holding a credential *and* the private half of the key it is bound to,
because without both there is nothing to present.

### Step 1 — The verifier's request (`vc-presentation-1.html`)
Nothing is disclosed here. The page answers three questions: **who** is asking (the Client Identifier and what its
prefix lets the wallet conclude — with the signature verified when there is one), **what** they are asking for (the
**DCQL** query decoded into claim paths, shown in green when the credential can disclose them and red when it
cannot, with the `vct` checked against the credential in hand), and **how** the answer travels
(`response_type=vp_token`, `response_mode`, `response_uri`). A request that cannot be answered — no `nonce`, no
`dcql_query`, no credential, no holder key — says so instead of letting step 2 discover it. A pane takes a request
pasted from a QR code for the cross-device flow.

### Step 2 — Choose what to disclose (`vc-presentation-2.html`)
The page selective disclosure exists for. One checkbox per Disclosure, marked with whether *this* verifier asked
for it; the default selection is exactly what was asked for and nothing more. Two buttons make the trade-off
concrete: **Only what was asked for**, and **Everything (over-disclose)** — which is what a credential format
without selective disclosure would force on you. From that choice the wallet assembles, in front of you:

* the **presentation** — `<Issuer-signed JWT>~<selected Disclosures>~<KB-JWT>`;
* the **Key Binding JWT**, decoded: `typ: kb+jwt`, the request's `nonce`, the verifier's Client Identifier as
  `aud`, `iat`, and `sd_hash` — the digest of the issuer-signed JWT and the presented Disclosures, each followed by
  a tilde, so it commits to the exact bytes and nothing can be added or removed afterwards;
* the **`vp_token`**: a JSON object keyed by the DCQL credential query id, each value an array of presentations;
* the claim set **the verifier will end up with**, computed from those bytes rather than from what the page meant
  to send;
* the fully assembled `direct_post` call.

**Refuse** is a first-class answer: OID4VP defines `access_denied` for it, and the verifier is told the request was
seen and declined — which is not the same as never having arrived.

### Step 3 — The verdict (`vc-presentation-3.html`)
Two accounts of the same event. **What the wallet sent**, with the presentation's parts coloured (issuer-signed
JWT · Disclosure · KB-JWT) and re-checked here over the bytes themselves — `sd_hash` recomputed, every
Disclosure's digest looked up in `_sd`, the KB-JWT's `nonce` and `aud` compared with the request. And **what the
verifier did**: its verdict check by check, what it asked for, what it received, and any **over-disclosure** —
because a verifier accepts extra claims without complaint, so the wallet is the only party that can care.

### Mock Verifier for testing
The `sts/` service also hosts a **mock OID4VP Verifier**: a web page at `/oid4vp/verifier`, `/oid4vp/start` which
builds the Authorization Request (by value, signed by reference, or as a QR code), `/oid4vp/request/:id` serving
the signed Request Object, and `POST /oid4vp/response` as the Response URI. It verifies properly — the issuer's
signature, every presented Disclosure's digest against `_sd`, the KB-JWT's `typ`, `alg`, `nonce`, `aud`, `iat` and
`sd_hash`, its signature against the credential's own `cnf.jwk`, the validity window, the `vct`, and whether the
claims it asked for actually arrived — and records a **per-check verdict** so a failure says *which* rule was
broken. `GET /oid4vp/result/:state` (not part of OID4VP; a real verifier shows the End-User its own page) makes
that verdict readable, which is what step 3 and the test suite use.

The suite is `tests/sd_jwt_vc_presentation.js`, and it is deliberately both halves:

* **positive** — the whole workflow through the pages, twice (by value and signed by reference), with the
  presentation verified independently in the test: `sd_hash` recomputed, the KB-JWT signature checked against the
  `cnf` key, and the verifier's claim set compared with what it asked for (it must know `given_name` and
  `family_name`, and must **not** know `email`, `birthdate`, `nationality` or `address`);
* **negative** — five presentations that must be refused, each failing exactly one check: one replayed against a
  different request (`KB-JWT nonce`), one signed by a key the credential is not bound to (`KB-JWT signature`), one
  with a Disclosure the issuer never signed (`Disclosure digests`), one edited after signing (`KB-JWT sd_hash`),
  and one withholding a claim the verifier asked for (`Requested claims`, driven through the pages). A control
  case is presented correctly in the same run, so the refusals cannot be an artefact of a verifier that says no to
  everything.

### Interoperability: presentation against walt.id

The mock Verifier above and our wallet were written together, so a run where they agree proves only that they
agree. The same argument that put **walt.id's `issuer-api2`** in the issuance suite puts
**[walt.id's `verifier-api2`](https://github.com/walt-id/waltid-identity)** here — an independently written
OpenID4VP 1.0 verifier with DCQL and its own policy engine — and `tests/sd_jwt_vc_presentation_waltid.js` drives
*the same four pages and the same buttons* against it.

The credential it presents is **issued by walt.id in the same run**, through our own issuance workflow. Neither end
of the exchange is ours, and the credential is walt.id's in every way that matters to a presentation: signed
**ES256** (our mock uses RS256), `iss` is a **`did:jwk`** rather than a URL, and the salts, disclosure layout and
`vct` are all its choices. The test asserts those properties before presenting anything, because a run that quietly
presented *our* credential would look identical and prove nothing.

| Step | What happens |
|---|---|
| 1 | walt.id issues a credential through `vc-issuance-*` (End-User authenticated at Keycloak, since walt.id authenticates nobody itself) |
| 2 | walt.id's management API creates a verification session: `POST /verification-session/create` with `flow_type`, a `dcql_query` (`meta.vct_values` read off the credential it just issued, not guessed) and its own `vc_policies` |
| 3 | Its Authorization Request — both shapes: the full one by value and the short `request_uri` one — is handed to our step 1, and the workflow runs: choose disclosures, sign the KB-JWT, `direct_post` the `vp_token` |
| 4 | walt.id's session record (`GET /verification-session/{id}/info`) is read back: its status, its `policy_results`, and the claims it ended up with — `given_name` and `birthdate` present, `email` and `phone_number` absent |

There are **two negatives**, and what they found is worth stating plainly.

The first withholds a claim walt.id asked for. The presentation is otherwise perfect — issuer signature, digests
and Key Binding JWT all valid, and our wallet's own checks pass — so the only thing wrong is that it does not
answer the question. **walt.id accepts it, and reports `SUCCESSFUL`.** That is not a defect in this suite or in our
wallet: `verifier-api2` runs a fixed set of policies over a `dc+sd-jwt` presentation — audience, nonce, `sd_hash`,
the KB-JWT signature, `exp`/`nbf` — and at 0.23.0 none of them asks whether the DCQL query was satisfied. So this
is the mirror of over-disclosure: a verifier that does not check cannot complain, and the wallet is the only party
in a position to say anything. The test asserts what is actually guaranteed — the withheld claim never reached
walt.id — and that **our step 3 reports the shortfall** in its *Answered the request?* line.

The second is a **replay**: the exact bytes walt.id just accepted, posted to a second session. Without it a
`SUCCESSFUL` verdict would prove nothing, since a verifier that accepted everything would satisfy every other
assertion here. walt.id refuses it — HTTP 400, `nonce-check` failed, session `FAILED` with `NONCE_MISMATCH` —
because the Key Binding JWT is bound to the first session's nonce. It is posted directly rather than through the
pages, since our wallet will not build a presentation carrying someone else's nonce, which is the point of it.

Wiring: the verifier container listens on 7004 with its own CORS proxy on **7003** (walt.id sends no CORS headers,
and its `urlPrefix` must name an address the browser can use), configured from `waltid/verifier-config/*.conf`
rendered per run by `renderWaltidConfig()` with a freshly generated request-signing key. It is in both compose
files — `docker-compose-run-tests.yml` and `keycloak-tests.yml` — and the job is skipped, not failed, when
`WALTID_VERIFIER_URL` is unset.
