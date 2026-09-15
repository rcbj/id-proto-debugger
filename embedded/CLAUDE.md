# embedded/ — the debugger as the mock STS embeds it

**The consumer is the mock STS** (`rcbj/mock-sts`, the `sts/` submodule here).
It serves this debugger's UI as STATIC FILES from a listener of its own — its
own origin, e.g. `https://host:8444/` — behind an OIDC sign-in, and proxies
everything under `https://host:8444/api/*`, after checking an access token and
with **`/api` stripped**, to this debugger's api, which it runs as a **forked
child process listening on a unix socket, plain HTTP**. All authentication
lives in the mock STS; the api has none and needs none, because its only peer
is that proxy.

**Nothing here changes the standalone debugger.** client:3000 / api:4000, the
compose stacks and the idptools.com static build behave exactly as before:
every change is additive and off unless `DEPLOYMENT=embedded` or one of the
`DEBUGGER_*` variables below is set. `tests/embedded_deployment.js` and the
allow-list section of `tests/api_ssrf_guard.js` hold this side; a static build
with and without these changes was compared file by file when they landed and
was identical.

This file is the CONTRACT between the two repositories. Changing any name,
path or variable in it is a change to the mock STS too.

| File | What it is |
|---|---|
| `build.sh` | `embedded/build.sh --out <dir>` — writes the tree below, WITHOUT docker |
| `Dockerfile` | the same tree in a `FROM scratch` image, by running `build.sh` |

## A. The tree

```
<OUT>/ui/            client/build.js, DEPLOYMENT=embedded, CONFIG_FILE=./env/embedded.js
<OUT>/api/           a runnable api: `cd <OUT>/api && node server.js`
<OUT>/common/        tls_listener.js and spiffe/ — what the api requires as ../common/...
<OUT>/version.json   the build's M.N.O (the same record as api/version.json)
```

`<OUT>/api` is what `api/Dockerfile` stages at `/usr/src/app`: every file under
`api/` (its `env/embedded.js` included), production `node_modules` with the
`ldapjs` link to `node-ldapjs` inside the package root, `data.js` and
`xmldsig.js` from `common/`, the repo-root `VERSION`, the client's `version.js`
and the stamped `version.json`. `<OUT>/common` is that Dockerfile's two COPYs
into `/usr/src/common` and nothing more. **When `api/Dockerfile` stages
something new beside the api, `build.sh` needs the same line**, or the image
works and the embedded api dies at startup with `Cannot find module`.

**`build.sh` touches nothing in the checkout.** It copies `VERSION`, `client/`,
`api/` and `common/` to a temporary directory (minus `node_modules`, build
output and the per-build files the images write), runs `npm ci`, `build.js`,
`npm install --omit=dev` and the version stamp THERE, copies the result to
`<OUT>` and deletes the temporary directory however it exits. The reason is
that all four of those steps write into the tree they run in, and several
stacks run from one checkout concurrently. It copies what is ON DISK, so
uncommitted work is in the build, as it would be in a `docker build`. It sets
`BUILD_NUMBER` once so the UI's and the api's `version.json` agree.

**`Dockerfile`** — build context is the repo root, classic builder only (no
BuildKit on the machines this runs on, so no `# syntax`, `--mount` or
`--build-context`), Node 24.16.0 installed as the other images do, and a final
`FROM scratch` stage holding exactly `/debugger/ui`, `/debugger/api`,
`/debugger/common` and `/debugger/version.json`. Tag it
`rcbj/id-proto-debugger-embedded:<tag>`; the mock STS's Dockerfile does
`COPY --from=rcbj/id-proto-debugger-embedded:<tag> /debugger/ …`. Pass
`--build-arg GIT_COMMIT=…` — there is no `.git` in the context to ask.

## B. The api child's environment

The mock STS forks `<OUT>/api/server.js` with cwd `<OUT>/api` and sets:

| Variable | Read by | Effect |
|---|---|---|
| `CONFIG_FILE` | `api/server.js` | absolute path of `<OUT>/api/env/embedded.js` |
| `DEBUGGER_LISTEN_SOCKET` | `common/tls_listener.js` | bind plain HTTP on this unix socket (see below) |
| `DEBUGGER_UI_URL` | `api/env/embedded.js` | the debugger origin, no trailing slash; `uiUrl` = it, `apiUrl` = it + `/api`, `spEntityId` = it + `/saml/sp`, `acsUrl`/`sloUrl`/`wsfedAcsUrl` = apiUrl + `/samlacs`, `/samlslo`, `/wsfed` |
| `DEBUGGER_ALLOWED_ADDRESS_RANGES` | `api/env/embedded.js` → `api/ssrf_guard.js` | a JSON array of ranges; non-empty = allow-list mode |
| `DEBUGGER_BLOCK_PRIVATE_NETWORK_CALLS` | `api/env/embedded.js` | `"true"`/`"false"`, only without an allow-list; default true |
| `DEBUGGER_LOG_LEVEL` | `api/env/embedded.js` | default `info` |
| `NODE_EXTRA_CA_CERTS` | node | the anchor for the mock STS's own certificate |

**The socket.** `tls_listener.listen()` takes `options.socketPath` or
`DEBUGGER_LISTEN_SOCKET`, and a socket OUTRANKS `https` and `TLS_ENABLED` —
it is always plain HTTP, and `materialFor()` is never asked, so a config left
at `https: true` with no certificate cannot stop it starting. It removes a
stale SOCKET at the path first (and refuses anything else there — a regular
file is somebody's), binds with the umask narrowed, chmods 0600, and when
`process.send` exists sends `{ type: 'debugger-api-listening', socket }` once.
`serverCertificate()` is null. The filesystem mode IS the access control, there
being no address to firewall.

**Trust proxy.** On the socket, and only there, `api/server.js` sets
`trust proxy`, because its one peer sends `X-Forwarded-Proto` and
`X-Forwarded-Host`. The one place the api builds a URL for somebody else from
the request — the SSF push receiver's `deliveryEndpoint` — goes through
`publicBaseUrl()`, which on the socket reads the forwarded host and appends
`X-Forwarded-Prefix` (`/api`); on a TCP listener the header is ignored, since
anybody could send it. Everything else the api hands a browser is built from
`uiUrl`/`apiUrl` (the SAML and WS-Federation landings redirect to `uiUrl`), and
the API document's host and base path are set from `uiUrl` + `/api`.

**Lifetime.** SIGTERM/SIGINT close the listener (which unlinks the socket)
and exit; IPC `disconnect` — which arrives even when the parent is SIGKILLed —
does the same, so an orphan never outlives the mock STS. Both are gated on the
socket, and the COVERAGE handler is unchanged.

**The address policy — allow-list mode.** A non-empty
`appconfig.allowedAddressRanges` (same grammar as `blockedAddressRanges`)
REPLACES the block-list, is on whatever `blockPrivateNetworkCalls` says, and
refuses every address outside it. It flows through the two members every
raw-socket relay already asks — `guard.enabled` and `guard.blockedRangeFor()` —
so `krb5_relay.js`, `ldap_client.js`, `tls_probe.js` and `spiffe_client.js`
are covered without an edit; `blockedRangeFor()` returns
`everything outside allowedAddressRanges [...]`, which finishes their own
sentence. **An allow-list with no usable entry FAILS CLOSED** — the opposite of
the block-list's empty case — and `embedded.js` turns a value that is not a
JSON array into exactly that, so a typo in the parent cannot open the relay.

Two things the parent has to get right, both of which fail as a refusal naming
an address rather than anything here:

* **A name is refused if ANY address it resolves to is outside the list.**
  `localhost` resolves to `::1` as well as `127.0.0.1` on most hosts, so an
  allow-list of `["127.0.0.0/8"]` refuses `https://localhost:8081`. Pass
  `["127.0.0.0/8", "::1/128"]` (plus whatever address the service is reached by
  in its container).
* The relays' refusal text still ends with their standalone advice to set
  `blockPrivateNetworkCalls` — true of block mode, and harmless noise here;
  the axios path's own message says "outside the allowed address ranges".

## C. The UI

`client/src/env/embedded.js` is evaluated IN THE BROWSER (browserify +
envify): `uiUrl` = `window.location.origin`, `apiUrl` = that + `/api`, and the
four landings as in B. The defaults that name the mock STS use the literal
**`__STS_EMBED_STS_URL__`**, which the mock STS substitutes with its main base
URL in every `.js` and `.html` it serves; `build.js` (step 3a) fails an
embedded build when a bundle carrying those defaults lost the literal to the
minifier. Socket targets the api dials inside the container are `localhost`:
`krb5KdcHostDefault`, `ldapUrlDefault: ldap://localhost:389`,
`spiffeWorkloadAddressDefault: localhost:8092`.

`CONFIG_FILE` is `./env/embedded.js` — relative to `client/src`, because it is
the bundles' own `require()` that envify rewrites.

`client/build.js` with `DEPLOYMENT=embedded` (an unknown value is refused):
drops no page, greys no card and reveals no static-only note (2a); writes no
`claimdescription` (2b — the api serves it at `/api/claimdescription`); skips
the dead-link check (nothing was dropped); never injects Google Analytics;
writes no `callback/` shim (the mock STS serves `/callback`); and writes to
`OUT_DIR` when given, which it refuses when that is `/`, `$HOME`, the checkout
or above it, because it is emptied first. `client/server.js`'s `/callback` and
`/tls/server-certificate` are not in the embedded tree and were not changed.
