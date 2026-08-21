# api/ — the Express backend (port 4000)

Scope: everything under `api/`. Cross-cutting matters — versioning, `CONFIG_FILE`, the key-material rules, how the suite is run — stay in the repo-root `CLAUDE.md`.

It proxies token endpoint calls server-side and provides a `/claimdescription` endpoint with cached IANA JWT claim metadata. It also speaks two protocols the browser cannot: it relays Kerberos to a KDC (`POST /krb5/*`) and it IS the LDAP client (`POST /ldap/*`). Both are raw TCP, so both enforce the address policy themselves — see the two sections below.

## Outbound calls: the address policy and the ten settings

It fetches URLs its **caller** chooses (token, introspection, revocation, device-authorization and userinfo endpoints, the SAML ArtifactResolve back-channel, the WS-Trust STS, the generic proxy), so `api/ssrf_guard.js` refuses outbound calls to loopback and private networks — otherwise anyone who can reach the api can use it to probe `127.0.0.1`, the deployment's private neighbours, or `169.254.169.254` (cloud metadata, which hands out credentials). It is installed **once** on the shared axios instance in `server.js`, so every call site present and future is covered, and it works in two layers: a request interceptor for a readable error, plus the http/https **agents** — which is what catches **redirects** (axios follows them, so a public host answering `302 → http://127.0.0.1` walks past a URL-only check) and closes most of the DNS-rebinding window. The agent needs **two** hooks, not one: a custom DNS `lookup` for hosts given as names, and a wrapped `createConnection` for hosts given as literal addresses — Node never calls `lookup` for a literal, and a redirect `Location` usually is one. That gap was real and is what `tests/api_ssrf_guard.js` caught on its first run. Hostnames are judged by what they RESOLVE to, so `localtest.me` and `127.0.0.1.nip.io` are caught by the same rule, and IPv4-mapped IPv6 (`::ffff:127.0.0.1`) is reduced to its IPv4 form because that is the address the socket reaches.

Before any of that, **one layer the configuration cannot switch off: the scheme must be `http` or `https`.** It is not an address policy, so it does not belong behind the address policy's off switch — and it is needed because axios's Node adapter supports more than HTTP: `platform.protocols` is `['http','https','file','data']`. A caller-supplied `data:` URL was the sharper half of that — axios decodes it *itself* and hands the bytes straight back, so it never touches the network and no address rule can see it; measured before the fix, `/userinfo` with a `data:` URL returned **200 and the decoded bytes**. A `file:` URL passed axios's own supported-protocol check and then died inside Node's http transport, which — see the handler bug below — left the request **hanging indefinitely**, not even bounded by `callTimeout`. `assertProtocolAllowed()` refuses both in one interceptor installed unconditionally by `install()`, before the enabled test. Only two endpoints (`/samlmetadata`, `/wstrust`) ever checked a scheme themselves; they still do, and answer 400. A redirect to a non-http scheme is refused by follow-redirects rather than by this layer, which `tests/api_connect_timeout.js` asserts *because* it is someone else's guarantee.

Two settings, in every `api/env/*.js`: **`blockPrivateNetworkCalls`** (only an explicit `false` disables it, so a missing or misspelled key stays safe) and **`blockedAddressRanges`**, a list of **ranges** — CIDR blocks (`10.0.0.0/8`) or first-last pairs (`10.0.0.0-10.255.255.255`). A bare single address is refused with the reason logged, because a network policy written one host at a time nearly always means the block that host sits in. `local.js` and `docker-tests.js` set the flag **false** and must: on those stacks the identity provider (`localhost:8080` / `keycloak:8080`) and the mock STS *are* private addresses, so the guard would refuse every call the service exists to make. Deployed configurations leave it on.

Two more settings in the same files bound how long those outbound calls may take, because **axios has no default timeout of its own**: a caller-named host that goes quiet would otherwise hold the Express request, its socket and the browser's spinner open until the OS gave up, which is minutes. **`callTimeout`** (default 10000) is the whole call, passed as axios's own `timeout`. **`connectionTimeout`** (default 5000) is the budget for reaching a *usable* connection — DNS, TCP connect, and on https the TLS handshake. Both are milliseconds, and a value that is not a positive number — including `0`, which axios reads as *no timeout*, the very thing these remove — is logged by name and replaced with the default.

The two are **additive, not one shadowing the other**, and that is the whole reason `connectionTimeout` is enforced by `api/connect_timeout.js` rather than by anything axios offers. Neither axios's `timeout` nor an `AbortSignal.timeout` can express it: both bound everything that follows, so a slow-but-alive identity provider dies exactly as readily as a dead address, and whichever setting was smaller became the only one that ever fired. A true connect timeout has to stop counting when the connection comes up, so it is armed in the only place that sees the socket being opened — the agent's `createConnection` — and disarmed on **`secureConnect` for TLS, `connect` for plain HTTP**; disarming on the wrong one leaves a handshake that stalls after the TCP connect unbounded. A reused keep-alive socket never goes through `createConnection` and so is never armed, which is correct: it is already connected.

That means the agents matter, and there is a trap in them. Setting `httpsAgent` on an individual axios call **replaces `axios.defaults.httpsAgent`**, hooks and all — so a bare `new https.Agent({rejectUnauthorized})` at a call site silently drops the SSRF guard's DNS `lookup` and `createConnection` wrappers, i.e. the layer that catches a redirect to a private literal address. Every call in `server.js` sets its own agent (each chooses its own `rejectUnauthorized`, since several endpoints deliberately allow a self-signed IdP certificate), so every one of them was in exactly that state. They now build agents through `outboundHttpAgent()` / `outboundHttpsAgent()`, which compose `guard.createAgent()` (the guard's own factory, one implementation shared with the defaults it installs) with the connect timeout. `httpAgent` is set alongside `httpsAgent` at every site, or a plain-`http` IdP — which is what the local and containerized stacks use — would have no connect timeout at all.

A third, **`maxContentLength`** (default `1048576`, one MiB, written as a plain decimal), bounds how *large* a response may be, because a deadline does not: a host that answers promptly and then streams for as long as it likes is entirely inside its timeout while the api buffers the whole body in memory to hand back to the browser. axios's own default is `-1`, unlimited, so without it the only ceiling is the heap. axios enforces it **incrementally**, destroying the response stream the moment the running total passes the cap, so an oversized body is abandoned mid-download rather than measured after the fact — and it needs no `Content-Length` to do it. Note `0` is not "no limit" here but the opposite: axios enforces any value above `-1`, so zero refuses every response that has a body, which is why the resolver insists on a positive number. It caps **responses** only; request bodies are axios's separate `maxBodyLength`, deliberately not set, since what this service sends is assembled from a request Express has already accepted and size-limited. Raise it to proxy an unusually large document through `/samlmetadata` — a federation metadata *aggregate* (eduGAIN, InCommon) is tens of megabytes, though a single IdP's descriptor is far below the default.

A fourth, **`maxRedirects`** (default `5`, against axios's own 21), bounds the redirect chain. A chain is unbounded work behind one caller-supplied URL — each hop is a fresh lookup and connection, and a loop spends the whole `callTimeout` achieving nothing — and a redirect is precisely how a *public* host sends this service somewhere private (`302 Location: http://127.0.0.1:8080/`). That hop is refused by the SSRF guard's agent layer, which reaches it because axios hands the agents to follow-redirects; `tests/api_connect_timeout.js` asserts that directly, since the URL pre-flight sees only the first URL and so cannot.

It is the one setting where **`0` is legal**: axios switches to the native transport and returns the 3xx unfollowed. It therefore cannot share the others' resolver — `resolvePositiveNumber()` rejects zero, because for a timeout or a size cap zero means *no limit* or *refuse everything*. `maxRedirects` uses `resolveNonNegativeInteger()` instead, and both refuse a value axios would misread: axios gates on `if (maxRedirects)`, so a non-numeric setting is falsy and silently leaves follow-redirects' 21 in force. Be aware that with `0` these endpoints report the upstream's status to the caller, so a redirected IdP surfaces as a bare `302` with no `Location` — fine for a deployment that expects no redirects, not a general hardening knob.

**A handler bug that made all of the above much less effective than it looks, now fixed.** `/token`, `/introspection` and `/userinfo` each answered only when the error carried a `response`: the `500` fallback sat *inside* `if (error.response)`, where it could never run. So every **network-level** failure — a timeout, a refused connection, the size cap, the redirect cap, a refused scheme — sent no reply at all and left the browser waiting forever. Those are precisely the failures the settings above produce, so adding limits without this made them hangs instead of errors. (`/claimdescription` had the same shape and was fixed when its `fetch` became an axios call.) Two of those handlers also had an outer `catch(e)` that logged an undefined `error`, raising a ReferenceError instead. When touching these handlers, the rule is: **the no-response branch must answer**, and it is the common branch, not the rare one.

All four go through one of those two resolvers, which is also what keeps the startup log honest about units (`milliseconds`, `bytes`, a count).

A sixth setting, **`keepAlive`** (a boolean, default **true**, and only an explicit `false` turns it off), pools outbound connections, so a session that calls the token endpoint then introspection then userinfo on one host stops paying for a TCP connection and a TLS handshake each time. It is **why the outbound agents are cached** (`agentFor()` + `outboundAgentCache`) rather than built per call, and the two changes are not separable: an agent owns its idle-socket pool, so a per-call keep-alive agent reuses nothing *and* parks that call's socket in a pool nobody will ever read — a leaked descriptor per outbound call, strictly worse than not pooling. `tests/api_connect_timeout.js` reproduces that leak on a throwaway agent, which is what documents the reasoning. Sharing is safe because everything on these agents is stateless policy; the only per-call choice is `rejectUnauthorized`, now normalised so that **only an explicit `false`** disables verification — which bounds the cache to three agents (no growth from a caller-supplied value) and means a missing or oddly-typed `sslValidate` in a request body can no longer quietly stop certificates being checked. Two consequences of pooling: a reused socket never goes through `createConnection`, so it carries no connect timeout (correct — it is already connected, but it means `connectionTimeout` is not a per-request guarantee once pooling is on); and a reused socket goes back to the address that was already validated, so pooling narrows the DNS-rebinding window rather than widening it.

A fifth setting is not a limit but an identity: **`userAgent`**, default `Identity Protocol Debugger/{{VERSION}}`, sent as the `User-Agent` on all eleven calls (`withUserAgent()`, applied per call for the same reason the agents are — a per-call `headers` object replaces the defaults). Without it axios announces `axios/1.18.1`, which tells the operator of somebody else's identity provider nothing about who is calling, and this service turns up in other people's access logs by design. `{{VERSION}}` is the same placeholder the client's footer and error pages use, and it is replaced with the **build** version: `api/Dockerfile` now copies the repo-root `VERSION` and **the client's `version.js`** (one implementation of the M.N.O scheme for both services) and runs `--stamp .`, so the header names the build and does not change when a container restarts — `resolveAppVersion()` falls back to the client's copy and then to `api/package.json` so a bare checkout still starts. Both `BUILD_NUMBER` and `GIT_COMMIT` are now build args on the api service in all three compose files, as they already were on the client. A blank or non-string `userAgent` is refused with the default, because axios would otherwise send a `User-Agent:` with nothing after the colon — worse than what it replaced. Note that adding this made the api the **second** image that must `COPY VERSION`, and the existing warning applies unchanged: omit it and the version silently reads `0.0.x`, which `tests/api_connect_timeout.js` asserts against directly.

`tests/api_connect_timeout.js` covers this (node only, never skipped), and the case that earns its keep is the second one: a host that **connects and then says nothing** must still be waiting well past the connect budget, failing only at `callTimeout`. That assertion fails against an `AbortSignal` implementation and passes against this one. It also checks a stalled TLS handshake, that wrapping a guarded agent keeps the guard's refusal (and keeps it immediate), that an oversized response is refused while the same body is accepted with no cap set (the control that makes the first half mean something, given axios's unlimited default), and — by reading `server.js` — that every axios call site carries all four limits, the User-Agent, and no bare `https.Agent`, which is the only thing that would catch a *new* call site added without them.

## The HTTP trace on `POST /token`: what only this service can see

The OAuth2/OIDC workflow's token exchange pane has an **HTTP tab** showing the Token Request and its response as they actually went — method, URL, headers and body each way, and how long the far end took. On the browser-direct setting the page records that itself. On the **proxied** setting, which is that pane's default because a great many identity providers refuse a browser-origin Token Request outright, the request is made *here*, and the browser is not party to it: all it ever receives is the parsed token payload. So `POST /token` hands back what it saw, and it is the only thing that can.

It is **opt-in per call**: the request body carries `http_trace: true` and the response then carries an `http_exchange` member beside the token payload. Opt-in rather than always-on because the trace repeats the request verbatim, `Authorization` header and client secret included — a debugging artifact for the caller that asked for it, not something added to every answer this service gives. `convertToOAuth2Format()` builds the outbound form body from named parameters, so the flag reaches no identity provider.

Three things about it are deliberate, and each is the answer to a way it could have been written and been wrong:

- **The shape is `POST /krb5/spnego`'s** — `{request, response, timing}`, with `bodyTruncated`/`bodyLength` on the response — because that is the other endpoint here that hands an HTTP exchange back for display. Two shapes for one idea would mean two renderers in the client for no reason.
- **The response body is captured RAW**, by `captureRawBody()` standing in for axios's default `transformResponse` (it does the same JSON parse and keeps the text as well). By the time a handler sees `response.data` the bytes are gone, and re-serializing the parsed object gives a body the far end never sent: different whitespace, different key order, and no sign of a duplicated member. It is capped for DISPLAY at `TRACE_BODY_CHARS`, which is not `maxContentLength` — that one bounds the transfer, this one bounds what is put in front of a reader, exactly as `SPNEGO_BODY_CHARS` does.
- **`withHttpTrace()` attaches nothing it cannot attach cleanly.** A token endpoint's response is a JSON object in every case this service is built for and nothing obliges one to be — an error page is a string — so a payload that cannot carry a member is sent unchanged, and one that already HAS an `http_exchange` member keeps its own. The client falls back to what the browser itself saw and says so in the pane, which is also what happens against an api that predates this.

**All three branches of the handler produce one**, including the one where there was no response at all: a timeout, a refused connection, a blocked address. That branch is the common one (see the handler bug above), and its elapsed time is what tells a timeout apart from a connection refused.

`tests/token_http_exchange.js` covers it from the browser end, and mutation-testing it means switching `wantsTrace` off here: the test then fails at the pane's note, with **this service's own URL** in the message, which is exactly what the fallback looks like when the trace goes missing.

## The Kerberos relay: a raw socket, and the two bounds that are new because of it

`POST /krb5/kdc` (`api/krb5_relay.js`, `api/krb5_frame.js`) carries a Kerberos v5 message to a KDC and brings the reply back. It exists because **Kerberos is not an HTTP protocol**: it speaks DER over TCP and UDP port 88, a browser cannot open a socket, and so the entire Kerberos workflow depends on this service for ~500 bytes of transport. Everything protocol-shaped happens in the browser (`common/krb5`, staged into the client bundle); this endpoint frames, guards, times and relays, and knows nothing about what it carries beyond the pre-flight described below. `GET /krb5/limits` publishes what it will and will not do, so the page can say so before a call fails rather than reporting its own limits as somebody else's fault.

**`api/ssrf_guard.js` does not cover it, and that is the whole reason this code exists.** The guard is installed on the shared **axios** instance — a request interceptor plus `lookup` and `createConnection` hooks on the outbound agents. A `net.connect(port, host)` walks past all of it: there is no axios in the path and no agent to hook. So this is a second enforcement of the same policy for a transport the guard has never seen, and it reuses the guard's **decision** (`blockedRangeFor`) rather than its own copy of the ranges — two implementations of an address policy is one implementation and one hole. `blockPrivateNetworkCalls` and `blockedAddressRanges` therefore govern both paths, with the same rule that only an explicit `false` disables the first, and the same consequence that `local.js` and `docker-tests.js` must keep it off because their KDC *is* a private address.

Two bounds are new, and neither was needed by the HTTP endpoints:

* **A seventh setting, `krb5AllowedPorts`** (default `[88, 464, 749]` — Kerberos, kpasswd, kadmin). This endpoint is a **broader primitive** than anything else here: it carries *caller-supplied bytes* to a *caller-supplied host and port*. An HTTP fetcher aimed at port 22 gets nothing useful; a byte relay aimed at port 22 is a port scanner whose payload the caller chooses. A malformed entry is dropped with its reason logged, and an allowlist that ends up empty refuses every call — the safe direction, but almost certainly a mistake, so it is logged as one. Note the coupling this creates: the mock KDC's `KRB5_KDC_PORT` exists because port 88 is privileged and a host run is not root, and changing it means adding that port here or the relay will refuse to reach it.
* **A message-shape pre-flight**, before any socket opens. The payload must be an AS-REQ, TGS-REQ or AP-REQ — checked by reading the outermost tag and confirming the declared length matches the bytes supplied. Without it this is a general-purpose tunnel; with it, it sends Kerberos to Kerberos ports. `api/krb5_frame.js` deliberately **does not use `common/krb5`**: that codec is 3,500 lines and is the right tool for decoding a message, and the wrong one for deciding whether to open a socket — a guard whose correctness depends on a large parser inherits every bug in it. It also puts the pre-flight FIRST, before the port check, so a caller sending the wrong bytes is told about the bytes; being told "port 22 is not allowed" first means changing the port and hitting the real problem second.

The four limits are the existing ones, reused, and the reasoning transfers unchanged. `connectionTimeout` and `callTimeout` are **additive**: a host that connects and then says nothing is alive and thinking — which is what a loaded domain controller looks like — so it gets the whole call budget, while a dead address fails at the connect budget. Expressing both with one timer makes whichever is smaller the only one that ever fires, and `tests/api_krb5_relay.js` asserts against exactly that. `maxContentLength` caps the reply, applied to what the far end **declared** rather than measured after the fact: a KDC can announce four gigabytes, and refusing before allocating is the difference between a refusal and an out-of-memory. The TCP length prefix is attacker-controlled in both directions — computed here on the way out, and refused on the way in if it sets the top bit that RFC 4120 reserves.

**A third deadline was missing, and the suite caught it as an intermittent: the NAME LOOKUP.** Both budgets above are armed inside `sendOverTcp`/`sendOverUdp`, so while a hostname is being resolved *nothing* is timing the call — `dns.lookup` was awaited with no bound at all, and a stub resolver waiting out its own retries against a forwarder that has gone quiet holds the promise open for as long as it likes. On 2026-08-17 that failed `tests/api_krb5_relay.js`'s "every path settles" case with the relay still resolving `no-such-host.invalid` five seconds in; on the real endpoint it is a browser waiting on an api that never replies, which is precisely the hang the paragraph below says cannot happen. The lookup now gets `connectionTimeout` of its own — resolving a name and reaching an address are two ways of not having arrived, and each gets the connect budget, so a call is bounded by `connectionTimeout` + `connectionTimeout` + `callTimeout` — and fails with **`EKRB5DNSTIMEOUT`** (a 502: it is a fact about this machine's resolver, not a caller mistake, and the message says so rather than letting it read as the KDC refusing). A late callback is dropped rather than raced, because `dns.lookup` is getaddrinfo in the libuv threadpool and cannot be cancelled. That also explains the one seam in this file: `createRelay()` takes an optional fourth argument `{ lookup }`, because `dns.lookup` ignores `dns.setServers` and a deadline cannot be tested against a resolver that works — the test injects one that never calls back, and asserts by *racing* rather than awaiting, so a relay without the deadline fails in three seconds instead of hanging the run. Nothing in `server.js` passes it.

**The no-response branch must answer, and here it is the COMMON branch.** The bug recorded above — three handlers whose `500` fallback sat inside `if (error.response)`, so every network-level failure sent no reply at all — would be far worse on this endpoint, because aiming it at a host that may not be there is the *point*. Every path in the relay resolves or rejects, `tests/api_krb5_relay.js` asserts that none of them hangs, and the handler distinguishes a refusal by policy (**400** — the caller asked for something this service will not do) from a network failure (**502** — the caller asked for something reasonable and the far end did not deliver). The page shows those differently: one is a mistake to correct, the other is a fact about the KDC.

One trap worth knowing, because it produced a misleading error: **node's base64 decoder is lenient.** `Buffer.from('!!!not base64!!!', 'base64')` does not throw — it skips the characters it does not recognise and returns whatever is left. So an unreadable `message` reached the Kerberos pre-flight and was refused as "not a Kerberos request", which is true and names the wrong mistake. The handler validates the alphabet first.

**`POST /krb5/service` is a second, broader endpoint, and it is OFF by default.** Presenting a ticket is the AP exchange, and it goes to a *service* rather than to a KDC — which breaks the port allowlist as a bounding mechanism, because a Kerberos service can be on any port at all (443 for HTTP, 1433 for SQL Server, 389 for LDAP). So the two endpoints have separate policies and separate pre-flights, and `/krb5/kdc` was tightened to AS-REQ and TGS-REQ only when this was added; an AP-REQ sent there is now refused with a message pointing at the right endpoint, because a caller told "that is not Kerberos" about a perfectly good AP-REQ will not believe it.

What bounds the service endpoint is therefore the **payload check**, and it is strict: a bare AP-REQ whose declared length accounts for every byte, or an InitialContextToken whose mechanism OID is Kerberos v5 *exactly*, whose token id is `01 00`, and whose inner AP-REQ is itself well formed and accounts for the remaining bytes. An HTTP request, a Redis command, a TLS ClientHello, `0x60` followed by arbitrary bytes, a token naming SPNEGO and a token wrapping an AP-REP all fail it. The **eighth setting, `krb5ServicePorts`**, is nonetheless empty by default so the endpoint refuses everything until an operator sets it — a capability this broad should be switched on deliberately rather than inherited. It accepts a list of ports or the string `"any"`, spelled as a word so that enabling it cannot be a plausible typo.

**`POST /krb5/spnego` is the third relay endpoint and the only one that is not a socket.** SPNEGO (RFC 4559) is Kerberos over HTTP, so this one performs one ordinary `GET` and reports **both sides of it verbatim** — the request line, every header sent, the status, and every header that came back. That last part is the whole reason it exists rather than the page fetching the resource itself: a cross-origin `fetch` can read a response header only if the server chose to expose it with `Access-Control-Expose-Headers`, and `WWW-Authenticate` is exactly the header the workflow is about; the browser also owns its own request headers, so a page cannot report what it sent.

What bounds it is narrower than the other two and needs no setting of its own. The method is `GET` and nothing else, and the **only** header a caller can influence is `Authorization`, whose value this service builds itself as `Negotiate <base64>` from a token whose alphabet it has validated (node's base64 decoder is lenient — see the trap above — so an unreadable token would otherwise reach the far end shorter and different, and be refused by somebody else's machine). A caller cannot inject a header, a method or a body. Everything else is the shared axios instance, so the SSRF guard, the four limits and the `User-Agent` apply unchanged and automatically; there is no `krb5SpnegoPorts` because there is nothing here that the existing HTTP endpoints do not already do. `GET /krb5/limits` publishes `spnegoEnabled` so the page can tell an older api from a broken one, and `spnegoBodyChars` — a **display** cap on the body, separate from `maxContentLength`, because what is being debugged is the handshake in the headers and the body is a page meant for a browser.

One thing it must not treat as a failure: **a 401 is the protocol.** The first request is supposed to be refused and the refusal carries the challenge, so `validateStatus` returns true for everything. A handler that threw on 4xx would make the normal case an error path. See `docs/spnego.md`.

One thing the Kerberos service endpoint must not report as a failure: a service that **closes the connection without answering**. A client that did not request mutual authentication is not owed a reply, so the handler answers 200 with a null reply and a note saying that nothing has proved the service is who it claims to be — which is the fact that matters, and is not an error.

A note on how the layered pre-flight is tested, because it produced a false negative. The OID check, the token-id check and the inner-message check each catch most of what the others catch, so removing any one of them leaves a test that only asserts *that* a payload was refused entirely green. `tests/api_krb5_relay.js` therefore asserts **which** check fired for each hostile payload; without that, two of the four mutations against this pre-flight passed silently.

**If an api is ever deployed to the public internet, read this paragraph.** An endpoint that will send an AS-REQ to any KDC its caller names is, when hosted, a pre-authentication guessing relay running from somebody else's IP address. Today that is hypothetical — the static deployments have no api at all — and the mitigation is cheap: a per-source and per-target-realm rate limit, off where `blockPrivateNetworkCalls` is off and on wherever it is on. It is **not implemented yet**, and this is the note that says so rather than leaving it to be discovered.

## LDAP: a client rather than a relay, and the third enforcement of the address policy

The eight `POST /ldap/*` endpoints (`api/ldap_client.js`) speak **LDAP v3** to a directory the caller names. They exist for the reason the Kerberos relay does — RFC 4511 is BER over a TCP socket, a browser cannot produce an `LDAPMessage`, and so the entire protocol has to live here — and `GET /ldap/limits` publishes what this service will and will not do, so the page can say so before a call fails.

**It is NOT a byte relay, and that difference is the whole security argument.** The caller sends an operation described in JSON — a DN, a filter, a list of changes — and this service encodes the bytes with `ldapjs`. A caller cannot choose what goes on the wire. That is a far narrower primitive than `POST /krb5/kdc`, which is why `ldapAllowedPorts` is a convenience here rather than the only thing standing between the endpoint and a port scanner.

The library is the **`api/node-ldapjs` submodule**, pinned by commit and used unmodified (`"ldapjs": "file:node-ldapjs"`). It has to sit INSIDE `api/` and not at the repository root: npm installs a `file:` dependency as a symlink and node resolves that package's own requires by walking up from where the REAL directory lives, so a copy one level up walks past `api/node_modules` entirely and fails with `Cannot find module 'abstract-logging'` from inside ldapjs. `api/.npmrc` carries `omit=dev` because npm installs a local-path dependency's devDependencies too, and ldapjs's are tap and eslint.

**`api/ssrf_guard.js` does not cover it, for exactly the reason it does not cover the Kerberos relay**: the guard is installed on the shared **axios** instance, and a `net.connect` has no axios in the path and no agent to hook. So this is a third enforcement of the same policy for a transport the guard has never seen, and it reuses the guard's **decision** (`blockedRangeFor`) rather than its own copy of the ranges — two implementations of an address policy is one implementation and one hole. Four things bound it: the scheme must be `ldap:` or `ldaps:` (checked before anything reaches the library, since a parser that defaults an unknown scheme has already made the decision); the shared address policy; resolve-then-connect-to-the-literal, with the ORIGINAL NAME still handed to TLS as `servername` for `ldaps:` — connecting to the literal without that would make certificate verification compare the certificate against an IP address and fail every time, a security hole created by a security control; and **`ldapAllowedPorts`**, a ninth setting defaulting to `[389, 636, 1389, 1636, 3268, 3269]` (the assigned ports, the Active Directory global catalogue, and the unprivileged pair a directory run outside a container lands on). `"any"` is accepted, spelled as a word so that widening it cannot be a plausible typo.

The four existing limits are reused unchanged, and **a tenth setting is new**: `connectionTimeout` bounds the name lookup and, separately, the connection — the same additive arrangement the Kerberos relay uses and for the same reason, since until a name is resolved neither of the other budgets has started; `callTimeout` bounds the operation once a connection is up, because a directory that has answered is alive and thinking and a large subtree search legitimately takes longer than a connect; and the result is capped by BOTH `maxContentLength` and **`ldapMaxEntries`** (default 1000). Both are needed and neither substitutes for the other: a million one-attribute entries fits inside a megabyte of values and is still a million objects to build, while a single entry carrying a `jpegPhoto` is one object and is still megabytes.

**THE THREE OUTCOMES, and collapsing them is the mistake these endpoints exist to avoid.** A refusal by this service (bad scheme, blocked address, port not allowed, a missing DN) is a **400**; a network failure is a **502**; and **an LDAP result code from the directory is a 200**, with `ok: false` and the code. `noSuchObject` on a DN that is not there, `invalidCredentials` on a bad bind, `entryAlreadyExists` on a duplicate — the operation completed and the answer was "no". Reporting those as failures would make a debugger unable to show the single most interesting thing a directory ever says. `tests/api_ldap.js` asserts the STATUS on every negative for that reason. Note `compare` in particular: it answers `compareTrue` (6) or `compareFalse` (5), **neither of which is success (0)**, which an implementation reusing a generic success path gets wrong.

Two refusals are published rather than left to be discovered: **a referral is recorded and NOT followed** — chasing one means opening a connection to a URL the *directory* chose, which is a server-side request forgery with a specification citation attached, the same reason WS-Federation's `wreqptr` is never dereferenced — and there is no StartTLS and no SASL, simple bind only.

One implementation detail that is not optional: **the bind waits for the socket.** ldapjs's client is created not-yet-connected, and an operation issued before its `connect` event is refused with result code 80 and the message "connection unavailable" when `queueDisable` is set — which looks exactly like a directory answering `other`. The first working version of this file reported a healthy local server as a failed bind with a code that has nothing to do with credentials. `reconnect` is off for a related reason: a silent retry turns an intermittent failure into a report saying everything worked. See `docs/ldap.md`.

## The TLS probe: a second raw socket, and the ninth setting

`POST /tls/connect` (`api/tls_probe.js`) opens a TLS — or **mutual** TLS —
connection to a caller-named host and reports both sides of the handshake. It
exists for the PKI page (`client/public/pki.html`, `docs/pki.md`), and it exists
**because a browser cannot do this and is not close**:

* the **client certificate** is chosen by the browser's own UI from the browser's
  own store, so a page cannot present the certificate it issued thirty seconds
  ago, and cannot choose to present none;
* the **truststore** is the platform's, so "does this chain verify against THIS
  root and no other" — the entire question a private CA raises — is unaskable;
* the negotiated **version, cipher, ALPN protocol and the server's chain** are
  not exposed to script at all;
* and a failed handshake reaches script as a generic network error with the
  **alert discarded**, which is the one informative thing in it.

So the page has no in-browser option for this and never will; `tests/pki_page.js`
asserts the pane contains no radio button, so it cannot be "fixed" by mistake.

**`api/ssrf_guard.js` does not cover it, for the same reason it does not cover
the Kerberos relay**: the guard is installed on the shared axios instance, and
`tls.connect` is a raw socket with no axios in the path and no agent to hook. So
this is a third enforcement of the same policy, and it reuses the guard's
**decision** (`blockedRangeFor`) rather than its own copy of the ranges. A name
is judged by what it RESOLVES to; a literal is checked directly, because node
never calls a resolver for one.

**A ninth setting, `tlsAllowedPorts`.** This endpoint is broader than the
Kerberos relay in one specific way, and it is the way that matters: **there is
no payload shape to bound it with**. `/krb5/kdc` can insist the bytes are an
AS-REQ; a ClientHello sent to port 22 is a perfectly well-formed ClientHello, so
"it must look like the protocol" rules nothing out here and the port allowlist
does all of that work. The default is the ports TLS is commonly spoken on (443,
636, 989, 990, 993, 995, 1433, 4443, 5061, 5432, 5671, 6697, 8443, 8843, 9443,
10443, 8883); `"any"` is accepted and is spelled as a word so that enabling it
cannot be a plausible typo. `local.js` and `docker-tests.js` set it, and say why.

The three deadlines are the existing ones and the reasoning transfers unchanged,
**including the one the Kerberos relay learned from a flaky run**: the name
lookup gets `connectionTimeout` of its own, because until a name is an address
neither of the other budgets has started and an unbounded lookup is an unbounded
request. A call is bounded by `connectionTimeout` (resolve) + `connectionTimeout`
(connect) + `callTimeout` (handshake), and `tests/api_tls_probe.js` asserts that
a server which **connects and then says nothing** survives well past the connect
budget and fails only at the call budget — the assertion that fails against an
implementation expressing both with one timer. `maxContentLength` caps the
certificate chain that comes back.

**The handshake is always made with `rejectUnauthorized: false`, and the verdict
is reported rather than enforced.** That looks like the wrong default and is the
only useful one here: the question is what the server presents and whether it
verifies against the truststore the caller chose, and aborting on a verification
failure throws away the chain that would explain it. Node computes
`socket.authorized` and `socket.authorizationError` either way, so nothing is
lost by not aborting — the caller gets the certificate, the alert AND the
verdict, and the response says `authorized: false` in as many words. Note also
that supplying trust anchors does **not** quietly add the platform roots: a
chain that verifies for a reason the caller did not ask about is not an answer.

**A COMPLETED HANDSHAKE IS NOT AN ACCEPTED CLIENT CERTIFICATE, and this is the
sharpest thing in the file.** Under TLS 1.2 a server refuses a client
certificate during the handshake. Under TLS 1.3 the client sends its Certificate
and Finished LAST — the handshake is complete from its point of view the instant
it has written them — and the server's verdict arrives afterwards, either as a
post-handshake alert or as a bare **hang-up** (which is what node's own TLS
server does when `rejectUnauthorized` refuses one: the socket closes with no
alert at all). An implementation that resolves on `secureConnect` therefore
reports a happy mutual-authentication connection to a server that rejected the
certificate a millisecond later, and answers "client authentication not
required" for every TLS 1.3 server on earth. The socket is read for
`POST_HANDSHAKE_GRACE_MS` (750 ms) after the handshake; an alert, a close or the
server's first bytes all end the wait. `handshakeUsable()` is what every verdict
is computed from, and it is not `connected`.

**A client certificate is sent with its CHAIN, and the failure when it is not
looks like something else entirely.** A server verifying a client certificate
builds a path from what the client SENT to an anchor it holds, so a leaf issued
by an intermediate and presented alone is unverifiable to a server holding only
the root — and node's TLS server answers that by **resetting the connection with
no alert**, which reads as "the server refused my certificate" when what it
could not do was find the issuer. `connectOptions.cert` takes concatenated PEM;
the page sends the leaf and its intermediates (not the root, which a server that
does not already hold it will not trust because we sent it). Found by driving
the page end to end against a real server, and asserted from both sides in
`tests/api_tls_probe.js`.

Related, and the reason it went unnoticed for an afternoon: **`usable` is
computed here, once, and every caller reads it.** "Did this connection work" is
not `connected` — see the paragraph above — and a caller left to re-derive it
gets the TLS 1.3 case wrong, which is exactly what the page did.

**Whether a server REQUIRES a client certificate cannot be read off a node TLS
socket** — there is no event, no property, and the CertificateRequest is consumed
inside OpenSSL — so `mutualAuthProbe` measures it: one handshake with the
certificate, one without, reported side by side, with five verdicts (`required`,
`not-required`, `certificate-rejected`, `required-and-rejected`, `unknown`). The
fourth is the case an operator hits most and the one a single connection cannot
tell from the first.

**An optional `httpRequest: {path}` asks the far end what IT saw**, and it is
the only part of this endpoint that is not about the handshake. Everything above
is *this end's* account, and this end already knows what it sent; which chain the
server built, which anchor it verified against and whether it accepted the
certificate at all exist only over there — and under TLS 1.3 the client has not
been told by the time its handshake completes. So after the handshake one **GET**
is written on the **same socket** (a second connection is a different connection
and proves nothing about this one) and the response is reported verbatim as
`result.httpResponse`. What bounds it needs no setting of its own, for the reason
`POST /krb5/spnego` needs none: the method is GET, every header is built here,
and the path is the only thing a caller contributes — one carrying CR, LF or
whitespace is refused as `ETLSBADHTTPPATH` rather than escaped, because escaping
means deciding which of two things the caller meant. `Connection: close` makes
the end of the response an event rather than a guess; `maxContentLength` caps it;
`HTTP_RESPONSE_GRACE_MS` (2000 ms, restarted per chunk) bounds a server that
answers and then holds the socket open.

Two things in that reader are byte-level and both were found rather than
anticipated. **A chunked body is de-framed in BYTES** — node's own server answers
chunked whenever it does not know the length, so this is the common path, and a
decoder working on a JavaScript *string* walks off the end of a chunk at the
first multi-byte character, producing valid JSON followed by a fragment of
hexadecimal. And **a FIN with no bytes behind it is the hang-up**: `'end'` fires
before `'close'`, so recording the peer's close only in the `'close'` handler
leaves `usable` true for a server that answered nothing — exactly the TLS 1.3
rejection two paragraphs up. Both are asserted, and mutation-tested, in
`tests/api_tls_probe.js`.

`GET /tls/limits` publishes the ports, the budgets, the caps and the platform
root count — plus `httpRequestAvailable`, so a page can tell an older api from a
server that said nothing — so the page can say what this service will do before a
call fails rather than reporting its own limits as somebody else's fault. And **the
no-response branch must answer**, as everywhere else here: a refusal by policy is
a 400, a network failure is a 502, and a failed HANDSHAKE is neither — it
resolves with a report, because the alert is the answer. See `docs/pki.md`.

## Dependency overrides

`api/package.json` carries three, and each pins something this service does not depend on directly. Two are for `express-swagger-generator@1.1.17` — an unmaintained package the api uses once, at startup, to build the Swagger document out of the JSDoc in `server.js`:

* **`validator: ^13.15.22`**, and
* **`js-yaml: ^3.15.1`** (GHSA/CVE-2026-59870's weakness in the 3.x line: `resolveYamlOmap()` enforced key uniqueness with `objectKeys.indexOf()` inside the per-element loop, so an `!!omap` of *n* entries cost O(n²) and blocked the event loop — 80,000 entries took **4,690 ms** on 3.15.0 and **187 ms** on 3.15.1, which replaces the linear scan with a `hasOwnProperty` map). It arrives four levels down: `express-swagger-generator → swagger-parser → json-schema-ref-parser → js-yaml@^3.12.0`. **Nothing attacker-supplied reaches it** — the api parses no YAML of its own (`grep yaml api/server.js` is empty) and the only document `json-schema-ref-parser` sees is the one generated from this repository's own source — so the alert is hygiene rather than an open door. The override exists anyway, because the transitive range `^3.12.0` would happily resolve back to 3.15.0.

Two traps when changing them. **npm will not re-resolve an override you edit**: `packages[""]` in this lock records no `overrides` key, so `npm install --package-lock-only` (even with `--force`) reports "up to date" and leaves the old version pinned. Delete the offending `node_modules/<pkg>` entry from `package-lock.json` and install again — npm then re-resolves that one package and honours the override, which is a three-line lock diff rather than a full regeneration. And **the third override is version-selective on purpose**: `brace-expansion@1` / `brace-expansion@2` exist in two majors here, so a single unversioned entry makes npm prune one of them.
