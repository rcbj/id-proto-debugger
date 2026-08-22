# SCIM — the sixteenth protocol, and the first one whose purpose is to WRITE

Read this before touching `client/public/scim.html`, `client/src/scim*.js`,
`api/scim_proxy.js`, `POST /scim`, or any of the three `tests/scim_*.js`.

RFC 7642 (the requirements), RFC 7643 (the schema) and RFC 7644 (the protocol).
The server this workflow is built against is the mock STS's `/scim/v2`, whose
own notes are in `docs/mock-sts.md` and in `scim.js`, `scim_auth.js` and
`scim_map.js` inside that submodule.

## Why this workflow is shaped differently from the other fifteen

Every other protocol family in this debugger asks a question about somebody who
is already there: issue this person a token, tell me who signed in, seal this
ticket, verify this credential. SCIM is the one that **puts somebody there** —
and takes them out again. That single fact drives three decisions that make this
page look unlike its neighbours.

**A single call is rarely the interesting thing.** What somebody debugging a
provisioning integration needs to know is what happens when a hundred calls run
in order against a real directory: whether the group created in step 4 contains
the users created in steps 1–3, whether the delete in step 90 really removed
anything, whether the twelfth `PATCH` landed on the value it named. So the page
has a **scenario harness** beside the ordinary one-endpoint-at-a-time debugger,
and the harness is the larger half.

**A scenario is a plan with an expectation on every step.** Not a script that
runs and produces a log. `scim_scenarios.js` builds a list of steps each
carrying `expect.status` and, where it matters, `expect.scimType`; the runner
JUDGES what came back against that. This is what makes the negative scenarios
work at all: a 409 `uniqueness` on a duplicate `userName` is a **pass**, and a
201 is a **failure**. A runner that recorded what came back rather than judging
it would have those exactly backwards, and a client's error handling is the half
that is never exercised — because a permissive server is hard to make say no.

**The page carries a warning banner, and it means it.** These endpoints create
and delete accounts and there is no undo.

## Four modules, and the split between them is the load-bearing part

| File | Has a DOM? | What it holds |
|---|---|---|
| `client/src/scim_client.js` | no | the endpoint catalogue, request composition, the seven authentication schemes, the RFC 7643 generator, the message bodies, and reading an answer |
| `client/src/scim_scenarios.js` | no | the twelve named scenarios, the random one, references, and `judge()` |
| `client/src/scim.js` | yes | the DOM, the two call paths, the runner, the history |
| `api/scim_proxy.js` | n/a | what `POST /scim` will and will not forward — **no axios and no network** |

The first two have no DOM and the fourth has no socket, which is what lets
`tests/scim_engine.js` drive the whole of the interesting logic in node against
the RFCs' own text with **no server, no browser and no page**. That is not
tidiness. Two failures on this workflow are invisible to any test that only
reads statuses off a live server, and both have a specification citation
attached:

* **A double-encoded id.** The SCIM `id` here is an LDAP DN, so
  `/Users/uid%3Dalice%2C...` is correct and `%25` anywhere in it is not. A
  server decodes once, gets `uid%3Dalice...`, and answers **404** — which reads
  exactly like a deleted user.
* **A wrong Digest hash.** It produces a **401**, which reads exactly like a
  wrong password.

Build a request in a click handler and neither is findable.

## The browser calls the server directly, and that is the difference from LDAP

**SCIM is on the static deployments.** It carries no `data-not-on-static` marker,
`client/static_site.js` does not drop it, and its landing card is a live link —
unlike Kerberos, SPNEGO and LDAP. The reason is simply that RFC 7644 is ordinary
HTTPS with a JSON body, so `fetch` can speak it and the api is not structurally
required the way it is for BER over a socket or DER over port 88.

The api path exists for three things a browser cannot do, and the page names
which is which rather than presenting one as a fallback for the other:

* **CORS.** Essentially no real SCIM endpoint sends
  `Access-Control-Allow-Origin` — it is the most dangerous URL an identity
  provider exposes. The browser refuses before the request is made, and the only
  error JavaScript can see is `TypeError: Failed to fetch`, which is the **same
  message** a browser gives for a dead host, a DNS failure and a rejected
  certificate. `explainBrowserFailure()` spells out all four rather than guessing
  at one.
* **A self-signed certificate**, which a staging server always has.
* **The exchange itself.** A browser withholds the headers it adds and CORS hides
  most of those that come back — `Location`, which every SCIM create sends, is
  usually unreadable from the page even though it was sent. The Exchange pane
  **says so**. A partial list presented as a whole one is a debugger lying with a
  straight face, and that is the same rule the OAuth2 token pane already follows.

## `POST /scim`: the three outcomes, which are `POST /ldap/*`'s three

This is the rule to read before anything else in `api/scim_proxy.js`:

* a refusal by **this service** — a relative URL, a method that is not one of
  RFC 7644's five, a framing header — is a **400**;
* a **network failure** is a **502**;
* **a SCIM error from the far end is a 200**, carrying that status and its
  `scimType`.

The third is the point of the endpoint. A 409 `uniqueness`, a 404 on an id that
names nothing, a 403 from an access control policy and the 501 on `/Me` are the
server **answering**, and they are the most interesting thing a SCIM server ever
says. Collapsing them into a failure would make a provisioning debugger unable
to show the errors it exists to show. `tests/scim_protocol.js` asserts the
transport status on every negative for exactly that reason.

**The address policy is not re-implemented there and must not be.** `POST /scim`
is an axios call like `/token` and `/wstrust`, so `api/ssrf_guard.js` — installed
once on the shared instance — already covers it, redirects included. The two
places that *do* carry their own copy (`ldap_client.js`, `tls_probe.js`) are raw
sockets that axios never sees. A third copy here would be a fourth implementation
of one policy, which is how a policy comes to have a hole in one of its copies.

**Headers are refused by SHAPE, not by an allowlist.** A debugger has to be able
to send the header a server it has never met asks for — a vendor's
`X-Tenant-Id`, an `If-Match`, a `DPoP` proof. What is refused instead is the set
that changes the *shape* of the request: `Host` (which would make this an open
proxy), `Content-Length` and `Transfer-Encoding` (request smuggling), the
hop-by-hop set, and anything whose name is not a token or whose value carries
CR/LF. An allowlist would have been shorter to write and would have made the
endpoint useless against the third server somebody pointed it at.

## All six authentication schemes, and why there are seven rows

RFC 7644 section 2 defines **no SCIM credential of its own**. It names six ways
of doing it and makes exactly two normative statements: a server *SHALL* say
which it accepts in `WWW-Authenticate`, and it *MUST* be able to map an
authenticated client to an access control policy. The mock implements all six;
this page offers all six plus anonymous.

| Scheme | Spec | Scoped? | Where the credential is made | api? |
|---|---|---|---|---|
| OAuth 2.0 Bearer | RFC 6750 | **yes** | pasted, or from the OAuth2/OIDC workflow | yes |
| OAuth 2.0 DPoP | RFC 9449 | **yes** | a proof JWT signed **in the browser** per request | yes |
| HTTP Basic | RFC 7617 | no | the page | yes |
| HTTP Digest | RFC 7616 | no | the page, over the server's nonce | yes |
| HOBA | RFC 7486 | no | an RSA key generated **in the browser** | **no** |
| Session cookie | RFC 7644 §2 | no | the browser attaches it | **no** |
| TLS client certificate | RFC 8446 | no | the TLS handshake | **no** |

**Seven rows for six schemes** because the mock's own table does the same: DPoP
is the same access token held a second way, and its row exists so a client
reading the ServiceProviderConfig can see the bound form is understood. Its
`attempt` in `scim_auth.js` is `null` — `attemptBearer` handles both.

**Only the two OAuth schemes carry scopes**, and the page says so on every other
one. That matters more than it looks: the access control policy reads "an OAuth
credential may do what `scim:read` and `scim:write` say, and every other accepted
credential may do both", so a caller who cannot get the scope can simply use
Basic instead. Somebody testing a scope restriction against a Basic credential
would conclude it works when nothing was restricted.

**Three schemes are browser-only and selecting one LOCKS the call path.** A
cookie is attached by the browser and the api has no cookie jar; a client
certificate is chosen in the handshake and the api would present *its own*,
which is a different identity and a misleading one. A page that let somebody
pick "through the api" with a cookie scheme would send a request with no cookie
and report the 401 as the server's fault. `refreshCallPathControls()` disables
the radio and puts the reason on screen.

### Digest is the one with real arithmetic in it, and four details are load-bearing

**All three registered algorithms are implemented, and none of them is Web
Crypto.** RFC 7616 section 6.1 registers MD5, SHA-256 and SHA-512-256, each with
a `-sess` variant, and the mock offers all three — its challenge is **three
`Digest` challenges in one header**, sharing a nonce. `crypto.subtle` has
neither MD5 (removed from browsers on purpose) nor SHA-512/256 (a different
function from SHA-512 truncated), and it is asynchronous, which would make a
credential a promise. So node-forge supplies MD5 and `@noble/hashes` the other
two, synchronously, in `scim_client.js` — which is also what lets the whole thing
be checked in node.

**The strongest offered algorithm is chosen, and taking the last one parsed is
the trap.** The conventional ordering in a header puts the weakest last, so "the
last `Digest` challenge" reliably means MD5. `chooseDigestChallenge()` walks the
preference order instead.

**`nc` must increase, and getting it wrong costs exactly one request.** The nonce
count is what makes a Digest credential single-use; the mock refuses a repeat as
a replay and refuses it **without** `stale=true`, because stale means "your
credential was fine, try again" and a replay is the opposite claim. A client that
hardcodes `00000001` authenticates once per nonce and then fails in a way that
reads as expired credentials. `digestCounts` in `scim.js` keys the counter **by
nonce**, because the server issues a fresh one when the old goes stale.

**`uri` is the request-target and not the absolute URL** — path and query, as it
appears on the request line. It is hashed into A2 and compared by the server
against what arrived, so an absolute URL produces a perfectly well-formed
credential that matches nothing.

The page also **verifies the server's `rspauth`** (RFC 7616 section 3.5), which
is the half most implementations leave out: it is the same construction with an
*empty* method in A2, so only somebody who knows the password could have produced
it. A client that never checks it has mutual authentication available and unused.
Its absence is reported as ordinary rather than as a failure.

### HOBA's blob is length-prefixed, and that is the whole of it

RFC 7486 section 5: each field becomes **its length in octets, a colon, then the
field**, and the six are concatenated with nothing between — in the order nonce,
algorithm, origin, realm, kid, challenge.

```
3:abc  1:0  13:https://h:443  4:SCIM  2:k1  2:ch
```

A dot-joined or newline-joined version looks perfectly reasonable, is the right
size and shape, and **verifies against nothing** — and the only error a server
can give back is "this does not verify", which sends everybody to look at their
key. The length is in *octets*, so a realm carrying an accent makes it disagree
with `String.length`, silently.

**The origin always carries an explicit port**, including the default one. RFC
7486 gives the origin no serialization of its own, so `https://host` and
`https://host:443` are two different strings over which two different signatures
are computed — and a browser's `location.origin` omits the default port while a
server reconstructing it from `Host` usually does not.

**The algorithm registry has one entry that matters: `"0"`, RSA-SHA256.** So the
key generated by the page is **RSA**; an ECDSA key produces a signature the
scheme has no identifier for. The key lives in the page only and is never
written to `localStorage` — a signing key in storage is a signing key in every
extension's reach — and `tests/scim_page.js` asserts that.

Registration is a form-encoded POST to `/.well-known/hoba/register` on the
**server's origin** (not under the SCIM base path) carrying `pub`, `username` and
`kid`.

## The generator emits every optional attribute, on purpose

`randomUser()` produces the complete RFC 7643 section 4.1 User: all six
sub-attributes of `name`, the five multi-valued types with their
`type`/`primary`/`display`, both addresses with `formatted`, `ims`, `photos`,
`entitlements`, `roles`, `x509Certificates`, and the whole section 4.3 enterprise
extension.

That is the point rather than thoroughness for its own sake. A provisioning
client tested only against `userName` and `emails` has tested nothing about the
fields it will meet in the field — and **what a server stores is usually
narrower than what it accepts**. The difference between "accepted and stored" and
"accepted and dropped" is invisible at the moment of the create and is the single
most common real defect in a provisioning integration. Reading the resource back
is what shows it; reading the *directory* back shows it exactly (below).

Two deliberate omissions:

* **`manager` is not invented.** It is a reference to another user's id, and a
  generator that made one up would produce a dangling reference on *every* user
  — worth running on purpose, and a poor default. The `enterprise` scenario sets
  it once both parties exist.
* **No `password`** unless one is asked for. RFC 7643 makes it `writeOnly`, and
  generating one would make this the only workflow here that wrote a secret
  nobody asked for.

**Random is seeded and therefore reproducible.** `newRng()` is a mulberry32 over
a hash of a caller-supplied seed string, so the same seed always produces the
same fifty users and the same random scenario. The page shows the seed. An
unseeded harness makes every interesting failure a story rather than a test —
"it failed on the seventh user" cannot be run again. It is **not** cryptography
and must never be used for any, which is why it lives beside the generators it
feeds rather than in `crypto_bytes.js` where somebody would eventually reach for
it.

## The twelve scenarios

| id | What it is for |
|---|---|
| `discovery` | the three documents a client should read first; needs no scope anywhere |
| `user-lifecycle` | one user with every attribute, read back, PUT, three PATCHes, delete, then a read that expects 404 |
| `provision-team` | N users, a group, one membership PATCH, a read-back, one member removed, teardown |
| `deprovision` | create N then delete N, each delete followed by a read expecting 404 |
| `modify-sweep` | three PATCH shapes against every one of N users |
| `bulk` | one BulkRequest creating N users **and** a group whose members are those users, by `bulkId` |
| `paging` | 1-indexed `startIndex`, both sort orders, and `count=0` |
| `filter-tour` | all fourteen section 3.4.2.2 forms against one known user |
| `search-post` | `/.search` per type, across both, and a body with no `schemas` |
| `enterprise` | the section 4.3 extension, addressed by full URN path |
| `negatives` | every refusal the server can be made to produce on purpose |
| `scope-refusal` | a read-only credential may read and may not write — including a bulk |
| `random` | two to four of the above, composed from the seed, each phase with its own prefix |

**References, not ids.** The id of a user created by step 3 is not known when the
plan is built, so steps hold `{ ref: 'user-3', field: 'id' }` and `resolve()`
substitutes it just before sending. A plan with a function in it could not be
shown to a person, stored, or compared by a test — and an unresolvable reference
is a *diagnosable* state ("step 7 wanted the id from step 3, which did not run")
rather than a request to `/Users/undefined`, which a server answers 404 and a
reader reads as a deleted user.

A reference cannot be a *fragment* of a string, and several steps need exactly
that — an id inside a filter, an id inside a value-filter path. Those carry a
`substitute` map of SHOUTED placeholder to reference; a placeholder left
unsubstituted is visible in the request the page shows.

**A random scenario namespaces every phase**, giving each its own prefix and its
own derived seed, because two phases that both had a step called `create` would
resolve each other's references — a scenario deleting a user another phase is
still using, which looks like the server losing one.

## The three tests, and why they are three

| File | Needs | What only it can see |
|---|---|---|
| `tests/scim_engine.js` | **nothing** | what this workflow *composes*, against the RFCs' own text and fixed vectors |
| `tests/scim_protocol.js` | api + mock STS | what the server *stored*, read back out of the directory; all six auth schemes |
| `tests/scim_page.js` | a browser | the browser call path, Web Crypto credentials, the runner, `localStorage` |

**`scim_engine.js` runs everywhere and is never gated**, including on the static
targets, because it needs no service at all. It is first of the three
deliberately: a broken request builder makes the other two fail in ways that look
like a broken server. It writes out RFC 7644's endpoint list and RFC 7643's
attribute list **independently** of the catalogues under test — a list derived
from the implementation agrees with it by construction and can notice nothing.

**`scim_protocol.js` reads everything back a second way, and that is why it is
long.** The mock has no store of its own: a SCIM create writes an entry in its
embedded LDAP directory, so

```
POST /scim/v2/Users              ->  uid=alice,ou=users,dc=example,dc=com
POST /ldap/search  (ou=users)    ->  the same entry
GET  /admin-api/scim             ->  the counters that saw it
```

Every attribute the test sends is checked against the LDAP attribute the mock's
`scim_map.js` says it lands in — and that mapping table is **transcribed rather
than imported**, for the same reason. `title` sent, 201 returned, nothing in the
directory: that is a field accepted and silently dropped, and a status-only test
cannot see it.

Its authentication section exercises **all six schemes once each**, plus the
negative that proves each check is really running — a scheme that accepted
everything would pass a positive-only test perfectly. It is deliberately *not* a
cross-product with the endpoints: forty-two runs of the same header parser test
nothing the first one did not. Two of the six **skip with a reason**: the cookie
needs a browser that has signed in, and a client certificate would be the api's
own.

**`scim_page.js` covers only what needs a browser** — the browser call path
(which no other job exercises and which is the *only* one the hosted site has),
the DPoP proof and HOBA key signed with Web Crypto (`scim_protocol.js` signs with
node's crypto, a different implementation), the two schemes that lock the call
path, the runner actually running, and what does and does not reach
`localStorage`.

All three **skip with a stated reason** when the mock STS has no `/scim/v2`
routes — the ordinary state of a checkout whose `sts/` gitlink predates them. A
silent pass there would be this project's recurring defect.

## What the page remembers

Every field goes to `localStorage` except the credentials, and the two
credentials are treated differently from each other on purpose:

* **A password is NEVER stored.** No checkbox, no opt-in, same as the LDAP page.
* **An access token is stored only if `scim_save_token` is ticked, and it ships
  CLEAR.** This is an opt-**in**, the opposite of the key-pair panes' opt-out,
  because the trade is different: a SAML SP key is needed on a later page to
  decrypt an assertion and re-pasting it is real friction, while a bearer token
  is pasted once and expires anyway. **Clearing the box purges what was already
  written**, on the spot — and the purge lives in `saveState()` rather than only
  in the change handler, so no code path can leave one behind. It also runs on
  load, so arriving with the box already clear cleans up.
* **The HOBA private key is never stored under any setting.**

## Adding an endpoint

`OPERATIONS` in `scim_client.js` is the single source for six things — the method
and path, the body shape, the query parameters, the scope, the labels, and what a
scenario step compiles to. Add a row there and the page's selector, its query
editor, its body generator and the history log all follow. A seventh endpoint
added as a button on the page and *not* as a row here is the defect the
arrangement exists to prevent: it would be uncovered by
`scim_engine.js`'s completeness check, which walks the table rather than the
page.

## Adding a protocol costs more than a page

The same list `docs/ldap.md` ends with, as it applied here: a bundle entry in
`client/build.js` **and** a `RUN browserify` line in `client/Dockerfile` (two
places, and the coverage build's `for entry in` list is a third); a landing card
plus its `:nth-child(N) .landing-icon` accent rule, remeasured with
`landingFitsOnOneScreen()`; a stylesheet whose every class is defined, or
`checkStylesheetsLoaded()` fails the page; `COPY` lines in `tests/Dockerfile` for
every module a test loads flat; job entries in `tests/run-report.js`; a row in
each of the five `client/src/env/*.js`; and this file.

The fourteenth card was free — seven across turns 7+6 into a filled 7+7, the same
two rows and the same height. **The fifteenth is the expensive one**: 7+7+1 puts
a third row below the fold, so it will need eight columns at `min <= 108.75`
(`8*108 + 7*10 = 934 <= 940`), and eight columns take another ~17px off every
card so every description wraps again. Measure at each step; anything larger
fails **silently** by staying at seven, with the height as the only symptom.
