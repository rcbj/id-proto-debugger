# LDAP — the twelfth protocol, and the second one that is not HTTP

Read this before touching `ldap.html`, `client/src/ldap.js`, `api/ldap_client.js`, the eight `POST /ldap/*` endpoints, or the mock STS's `ldap_server.js`.

## Why it is shaped like Kerberos and not like everything else

LDAP v3 (RFC 4511) is BER over a TCP socket. A browser cannot speak it — there is no `fetch`, no XHR and no WebSocket that will produce an `LDAPMessage`, and no amount of code in a bundle changes that. So the workflow has the same shape Kerberos has and the opposite shape to SAML, WS-Trust and WebAuthn:

| | SAML / WS-Trust / WebAuthn | Kerberos | **LDAP** |
|---|---|---|---|
| where the protocol runs | the browser | the browser (`common/krb5`) | **the api** |
| what the api does | proxies, optionally | relays bytes | **speaks the protocol** |
| on a static deployment | works | not shipped | **not shipped** |

That last row is the visible consequence and it is why `client/static_site.js` drops `ldap.html`, `js/ldap.js` and `css/ldap.css` from `dist/` and greys the landing card. A page whose every button reported "no back end" would be worse than no page: the failure names a fetch rather than the absent backend.

There is a second consequence, less obvious and more expensive: **the URL in the connection pane is resolved by the api, not by the browser.** `localhost` in that field means the machine the api runs on. That is exactly the trap `krb5KdcHostDefault` documents, and it is why `ldapUrlDefault` is `ldap://sts:389` on the local and containerized stacks and `""` on the deployed ones.

Unlike the Kerberos relay, though, this is **not a byte relay**. The caller sends an operation described in JSON — a DN, a filter, a list of changes — and `api/ldap_client.js` encodes the bytes with `ldapjs`. The caller never chooses what goes on the wire. That is a much narrower primitive than `POST /krb5/kdc`, which is why `ldapAllowedPorts` is a convenience rather than the only thing standing between the endpoint and a port scanner.

## The library is a submodule, in two places, and it is not modified

`ldapjs` 3.0.7, pinned as [`rcbj/node-ldapjs`](https://github.com/rcbj/node-ldapjs) and used **unmodified**:

* `api/node-ldapjs` — the CLIENT half, `"ldapjs": "file:node-ldapjs"` in `api/package.json`.
* `sts/node-ldapjs` — the SERVER half, inside the mock STS submodule, `"ldapjs": "file:node-ldapjs"` in its own `package.json`.

**Two copies rather than one shared, and the reason is npm rather than taste.** npm installs a `file:` dependency as a symlink, and node then resolves that package's own requires by walking up from where the *real* directory lives — not from the symlink. A copy one level above `api/` walks `…/node_modules`, `/node_modules`, and never reaches the `node_modules` the install just wrote. The failure is `Cannot find module 'abstract-logging'` from inside ldapjs, naming a package nobody here has heard of. The submodule has to sit **inside the package root**; that is the whole rule.

Three more things about the dependency:

* **`git submodule update --init` is not enough.** `sts/node-ldapjs` is a submodule of a submodule, and `--init` stops one level short of it. Use `--recursive`; the launchers call `requireMockStsCheckout()` and `requireApiLdapjsCheckout()` in `common/common.sh`, and the CI workflows check out with `submodules: recursive`. An uninitialised submodule is an **empty directory**, so the COPY succeeds, npm installs a package with no `main`, and the failure arrives at runtime as `Cannot find module 'ldapjs'` — which names a package rather than a submodule.
* **`npm install` on a `file:` dependency installs that package's devDependencies too.** ldapjs's are `tap` and `eslint` and their trees: about 200 extra packages and a dozen advisories that have nothing to do with either service. Both repositories carry an `.npmrc` with `omit=dev`, and both Dockerfiles pass `--omit=dev` as well. The duplication is deliberate — a build that loses the `.npmrc` should not quietly start shipping them.
* **Neither side patches the library.** That is a promise worth keeping: the point of pinning a fork is to have a *usable* copy of ldapjs, not a fork nobody else can consume, and it means both halves of this workflow run the same code anybody else's ldapjs would.

### Two ldapjs defects this code routes around, and where they bite

Both are in `SearchResponse.prototype.send()`, both were found by this workflow, and both are worked around in the mock's handler rather than patched in the submodule.

**1. A second, case-sensitive attribute filter.** After the handler has chosen what to send, `send()` filters again — comparing the entry's attribute name *lower-cased* against the requested list held *exactly as the client sent it*:

```js
} else if (self.attributes.length && self.attributes.indexOf(_a) === -1) { delete ... }
```

So a client asking for `telephoneNumber` gets back everything it asked for **except** `telephoneNumber`. Every attribute whose conventional spelling carries a capital — `telephoneNumber`, `givenName`, `displayName`, `objectClass`, `userPassword` — is silently dropped from a *selective* search and from nothing else, which is why a search asking for everything looks perfect. LDAP attribute descriptions are case-insensitive (RFC 4512 section 2.5), so this is a defect.

The trap inside the trap: `send()`'s `nofiltering` argument does **not** turn it off. That flag guards the `_`-prefix and `notAttributes` branches above this one; the requested-attributes branch has no guard at all, while the documentation ("skip filtering notAttributes and '_' attributes") reads as though it covers everything.

What does turn it off is passing a `SearchResultEntry` **instance** rather than a plain `{dn, attributes}` object — `send()` takes an early branch for one and writes it untouched. `toSearchEntry()` in `ldap_server.js` therefore builds the message itself.

**2. `messageId` defaults to 1, so that early branch throws.** `LdapMessage` initialises the field to 1, so `send()`'s `if (!entry.messageId)` never fires — 1 is truthy — and the very next line throws `SearchEntry messageId mismatch` for every search after the first on a connection. The symptom is an uncaught exception in the server's log and a search that returns **zero entries and then ends successfully**, which reads as an empty directory. `toSearchEntry()` takes `res.messageId` and sets it.

## The mock directory

`sts/ldap_server.js`, an LDAPv3 server on TCP **389** (`LDAP_PORT`) and, over TLS, on TCP **636** (`LDAPS_PORT`), base DN `dc=example,dc=com` (`LDAP_BASE_DN`). `GET /ldap` describes it, `GET /ldap/directory` lists every entry, and both take `?format=json`.

The second port is the **same directory**, not a second one: one store, one set of handlers, two ldapjs server objects (that library decides between a `net.Server` and a `tls.Server` at construction, so TLS cannot be an option on one server). `tests/api_ldap.js` runs bind, add a user, add a group, join it and modify the user over 636 and then reads the result back over 389, because everything short of that cross-socket read would pass just as well against two separate directories sharing a base DN. Two things TLS there does **not** change: every bind still succeeds — encryption keeps the password off the wire, nothing checks it — and no client certificate is ever requested, so a certificate offered to 636 is not a login. The certificate is the mock's own, self-signed and regenerated on every start, which is why the api's LDAPS calls in that test pass `rejectUnauthorized: false` and why the refusal *without* it is asserted: an api that had quietly stopped verifying would otherwise look identical.

It is started from `listen()` in the mock's `server.js` rather than at require time, for the same reason the KDC is: binding a privileged port can fail, and a require that throws takes the whole service down where a route cannot. A failure to bind is **recorded and published** (`listening` / `listenError` on `GET /ldap`) rather than fatal — the HTTP view answers 200 either way, so without that field there is no way to tell a running directory from one whose listener lost a race with the host's own `slapd`, and both tests check it before doing anything.

**Every bind succeeds** — any DN, any password, anonymous included — with one exception: the literal password `invalid`, which is refused with `LDAP_INVALID_CREDENTIALS` (49). That is this service's standing convention, the same string the password grant, WS-Trust and the WS-Federation sign-in screen already reject, and it exists so a negative test has something to fail on. A directory that could not produce a 49 would make "the bind failed" untestable, and 49 is the code an LDAP client's error handling is built around.

**It is schemaless on purpose.** No objectClass is enforced, no attribute is checked against a syntax, no `must`/`may` is consulted. A real directory would refuse most of what this one accepts, and where that matters it is a difference a reader should be *told* about rather than one the mock should hide by inventing a schema of its own. `GET /ldap` says so.

Four rules **are** enforced, because each is real and its absence would teach a client something false:

* an add whose parent does not exist is `noSuchObject` (32) — a directory is a tree, and a client that has never seen this refusal will write its first entry into a real directory and not understand the error;
* a delete of an entry with children is `notAllowedOnNonLeaf` (66);
* a modify `delete` naming an absent attribute is `noSuchAttribute` (16);
* deleting the last value of an attribute deletes the attribute, since an LDAP attribute always has at least one value (RFC 4511 section 4.1.7) — which is why a second delete of the same attribute is a 16 rather than a no-op.

And one is **deliberately not** enforced: deleting a user does not remove its DN from the groups that list it as a `member`. Referential integrity is a directory feature and not a protocol rule — OpenLDAP needs an overlay for it, Active Directory does it in the DSA — so the dangling member is the honest result and is what the page shows. Both tests assert it, so tidying it away would have to be a deliberate change.

A modify is **atomic**: the changes are applied to a copy and the copy replaces the stored attributes only once every change has been accepted. Applying them in place and rolling back is the same thing written so that a bug leaves half a change behind.

### An LDAP object for every user who authenticates

`LDAP_AUTOCREATE_USERS`, **on by default** (only an explicit `0`/`false`/`no`/`off` turns it off, so a misspelling stays safe). The first time anybody authenticates to the mock through **any** of its twelve protocol families — the OAuth2 login screen, WS-Trust, WS-Federation, a Kerberos AS-REQ, a WebAuthn assertion — an entry appears at `uid=<name>,ou=users,<base>`.

That is **one hook, not twelve**, because `admin_stats.recordAuthentication()` is already the single funnel every one of those call sites goes through at the moment a credential is ACCEPTED. The hook is **inverted**, exactly as `helpers.js`'s `setJwtRecorder` is: `ldap_server.js` requires `admin_stats.js` (it needs `identityOf`'s normalisation, so `alice`, `urn:sts-mock:user:alice` and `alice@REALM` seed one entry and not three), so `admin_stats.js` cannot require it back without a cycle — it offers a slot and `ldap_server.js` fills it at require time. The observer's return value is ignored and a throw from it is caught: a directory must never be able to fail an authentication.

Two identities are skipped:

* **an LDAP bind**, because the identity a bind presents is a DN — it already names an object in this directory — so `uid=cn=admin\,dc=example…` would be nonsense, and the mock's own binds would grow the directory without bound;
* **an OAuth client**, because a client is not a person and `ou=users` is for people. The admin console already makes that distinction with `isClient`, which is what this reads.

## The api

Eight endpoints, all thin: everything protocol, policy or timing is in `api/ldap_client.js`.

| | |
|---|---|
| `POST /ldap/bind` | the bind on its own |
| `POST /ldap/search` | base, scope, filter, attributes, sizeLimit |
| `POST /ldap/add` | a DN and an attribute object |
| `POST /ldap/delete` | a DN |
| `POST /ldap/modify` | a DN and a list of `{operation, type, values}` |
| `POST /ldap/modifydn` | rename or move |
| `POST /ldap/compare` | an attribute value, without reading the entry |
| `GET /ldap/limits` | what this service will and will not do |

### The three outcomes, and why collapsing them is the mistake to avoid

* a **refusal by this service** — a scheme that is not `ldap(s)`, a blocked address, a port outside the allowlist, an operation missing a DN — is **400**. The caller asked for something this service will not do.
* a **network failure** — nothing listening, refused, timed out — is **502**. The caller asked for something reasonable and the far end did not deliver.
* an **LDAP result code from the directory is 200**, with `ok: false` and the code. `noSuchObject` on a DN that is not there, `invalidCredentials` on a bad bind, `entryAlreadyExists` on a duplicate: the operation completed and the answer was "no". Reporting those as failures would make a debugger unable to show the single most interesting thing a directory ever says, and would put the most useful half of this workflow behind an error page.

`tests/api_ldap.js` asserts the **status** on every negative for exactly that reason.

Note `compare` in particular: it answers `compareTrue` (6) or `compareFalse` (5), **neither of which is success (0)**. An implementation reusing a generic success path gets that wrong.

### What bounds it

The same four ideas the Kerberos relay uses, with the reasoning unchanged:

1. **The scheme must be `ldap:` or `ldaps:`**, checked before anything is handed to the library — a parser that helpfully defaults an unknown scheme has already made the decision.
2. **The address policy**, shared with the HTTP and Kerberos sides. `api/ssrf_guard.js` is installed on the shared **axios** instance — a request interceptor plus `lookup`/`createConnection` hooks on the agents — and a `net.connect` walks past all of it. So this is a third enforcement of the same policy for a transport the guard has never seen, and it reuses the guard's **decision** (`blockedRangeFor`) rather than its own copy of the ranges. Two implementations of an address policy is one implementation and one hole.
3. **Resolve, then connect to the literal** that was checked — re-resolving at connect time is the DNS-rebinding window. For `ldaps:` the **original name** is still handed to TLS as `servername`, or certificate verification would compare the certificate against an IP address and fail every time: a security hole created by a security control.
4. **A port allowlist**, `ldapAllowedPorts`, defaulting to `[389, 636, 1389, 1636, 3268, 3269]` — the assigned ports, the AD global catalogue, and the unprivileged pair a directory run outside a container usually lands on. `"any"` is accepted, spelled as a word so widening it cannot be a plausible typo.

And the limits, which are the existing settings reused: `connectionTimeout` bounds the **name lookup** and, separately, the connection (until a name is resolved neither of the other budgets has started, and an unbounded lookup is an unbounded request — the same defect `krb5_relay.js` records having hit); `callTimeout` bounds the operation once a connection is up, because a directory that has answered is alive and thinking and a large subtree search legitimately takes longer than a connect; `maxContentLength` and the new **`ldapMaxEntries`** cap the result.

Both caps are needed and neither substitutes for the other: a million one-attribute entries fits inside a megabyte of values and is still a million objects to build, while a single entry carrying a `jpegPhoto` is one object and is still megabytes.

Two more things it does not do, stated rather than left to be discovered and published on `GET /ldap/limits`: **it does not follow referrals** — chasing one means opening a connection to a URL the *directory* chose, which is a server-side request forgery with a specification citation attached, the same reason WS-Federation's `wreqptr` is never dereferenced — and there is **no StartTLS and no SASL**, simple bind only.

One implementation detail that is not optional: **the bind waits for the socket.** ldapjs's client is created not-yet-connected, and an operation issued before its `connect` event is either queued or, with `queueDisable`, refused immediately with result code 80 and the message "connection unavailable" — which looks exactly like a directory answering `other`. The first working version of `ldap_client.js` reported a healthy local server as a failed bind with a code that has nothing to do with credentials. Binding from inside the `connect` handler is what makes `queueDisable` safe rather than wrong. `reconnect` is off for a related reason: a silent retry turns an intermittent failure into a report that says everything worked.

## The page

`client/public/ldap.html` + `client/src/ldap.js`, one page, five panes. The arrangement is the teaching rather than a menu:

* **Connection** — the bind on its own. It is a distinct operation and the only one whose failure is about credentials, so it gets a button rather than being a side effect of the first search somebody runs. "My credentials are wrong" and "my filter is wrong" must never look alike.
* **Search** — the read half, with four presets that **fill the fields and then run**. Filling rather than running a hidden query is the point: the filter is the thing worth seeing.
* **Users / Groups** — the write half in the vocabulary of the objects. Each button composes into an Entry-pane operation and says which.
* **Entry** — the same operations in the protocol's own vocabulary, against any DN. This is what the two panes above are shorthand for, and *Show as a raw operation* is the bridge between the two levels.
* **Exchange** — what was sent to the api and what came back, verbatim.

Plus the shared Operations History (`ldap_history.js` over `op_history.js`, the fifth sibling), whose three results matter: `Failure` means the round trip worked and the directory said no; a row that stays **`Sent`** means the api never answered at all. Those two are what people most often confuse, and on this workflow they are the whole diagnosis.

### The one thing this page exists to teach

**There is no "add user to group" operation in LDAP.** A `groupOfNames` keeps its membership in a multi-valued `member` attribute whose values are DNs, so adding a member is a `modify` with one `add` change *on the group*, and removing one is a `modify` with one `delete` change carrying the value. An implementation that put the change on the *user* looks right until somebody reads the group.

Its mirror image is the fourth search preset, and almost nobody guesses it: **the groups a user is in are found from the other end.** There is no attribute on the user to read — `memberOf` is a Microsoft extension that OpenLDAP has only behind an overlay — so the question is answered by searching the *groups* for a `member` value that is the user's DN.

### Smaller things the page is deliberate about

* **`replace`, not `add`, when setting an attribute.** These attributes are multi-valued in the schema even where a person thinks of them as single-valued, so `add` leaves the old value beside the new one.
* **Empty optional fields are omitted rather than sent empty**, because an LDAP attribute always has at least one value and an empty one is malformed rather than a weaker claim.
* **A `groupOfNames` is seeded with a member**, because RFC 4519 makes `member` a MUST attribute and an empty one is not expressible. This directory has no schema and would accept one; sending it anyway would teach a habit every real directory refuses.
* **The results table is built with `createElement` and `textContent`.** Every value in it — DNs, attribute names, attribute values — came out of a directory this page does not control.
* **The password is never written to `localStorage`**, while every other field is. It is redacted from the Exchange pane too, with its **length** kept: "did the field reach the api at all" is a real question when a bind fails, and answering it with silence sends people hunting.
* **The scope is read from the number on the wire**, not from ldapjs's `scopeName` — which spells the middle two `single` and `subtree`. A handler comparing against `one` and `sub` matched neither, fell through to its default, and answered every one-level search as a subtree one. That is a **superset**, so every assertion about the contents still passed and the only symptom was one extra entry. A wrong scope is invisible in exactly the direction that makes it hardest to notice, and it has already happened once here.

## The tests

| | |
|---|---|
| `tests/api_ldap.js` | the protocol, node only: the ten operations, the three outcomes, the scopes compared against each other, membership from both ends, the negatives, the api's own refusals, and the auto-created user |
| `tests/ldap_page.js` | the page, Selenium: the DNs it builds, the presets that fill the fields, the modify that is membership, what it remembers, the History's three states, and the `ldap-` stylesheet check |

Both create names **unique per run**. The mock's directory lives for the life of its process, so a fixed `uid=dave` is `entryAlreadyExists` on the second run — a test that only passes against a freshly started service is one nobody can re-run.

`ldap_page.js` is gated on `LDAP_AVAILABLE`, a **separate** variable from `KERBEROS_AVAILABLE`: the two protocols are absent from a static deployment for the same underlying reason but independently, and a target could perfectly well be api-backed with a directory reachable and no KDC. `api_ldap.js` is deliberately **not** gated — it speaks HTTP to the api and the mock rather than loading anything out of the `sts/` submodule, so it does not acquire the spurious `CONFIG_FILE` failure the Kerberos jobs did on a remote target, and it skips with its own more specific reason when either service is absent.

## Adding a protocol costs more than a page

If LDAP is the model for a thirteenth, the checklist it had to satisfy:

* `client/build.js`'s `BUNDLES`, a `RUN browserify` line in `client/Dockerfile`, **and** that Dockerfile's coverage loop — three places, none near the others;
* `client/static_site.js` if the page needs the api, with its own stylesheet in `EXCLUDED_ASSETS` and `data-not-on-static` on the card;
* a landing card, a `:nth-child(N) .landing-icon` accent rule, and the arithmetic: twelve cards is 6+6 and cost no column change, but **thirteen is 6+6+1** and a third row is below the fold, so it will need seven columns (`min <= 124.3` at the current 10px gap);
* `tests/Dockerfile` — every script `run-report.js` schedules must be COPYed, or it fails in the image with `MODULE_NOT_FOUND` in a tenth of a second while passing on every host run;
* `tests/navigation.js`'s `STYLED_PREFIXES`;
* `sts_metadata.js` in the mock, one entry per endpoint plus the specifications — and a note by hand for anything that registers no route, since that page is built by walking the Express router and a raw socket is invisible to it.
