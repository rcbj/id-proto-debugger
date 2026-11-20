# Abstract data model — design and implementation plan

**Status: implemented on 2026-11-16, except where noted below.** The plan as written follows, for the reasoning behind each decision; where the build departed from it, the departure is noted here. The current description is `models/CLAUDE.md` (for somebody changing a model) and `docs/v0.9.6/data-model.md` (for a reader).

**What differs from the plan:**

- **The compiler is in `models/package.json`**, as planned, and NOT also in `tests/package.json`. The TypeSpec compiler resolves its libraries upward from the `.tsp` files, so a copy under `tests/` cannot serve `models/`. The tests image runs `npm ci` in `/usr/src/source-tree/models` instead.
- **The validator owns less than "remove the hand-written check" suggests.** Most checks live in modules that are libraries with callers of their own (`ldap_client.js`, `krb5_relay.js`, the `*_proxy.js` decision halves). They stay where they are and are named with `@checkedInCode`. Only checks a ROUTE made were moved into the schema, and each keeps its sentence through `@refusal`.
- **The secret lists are read from `storage_classes.json`**, a four-list file generated beside `storage.json`, so the bundles do not carry the whole inventory. `sd_jwt_vc.js`'s holder-key list stays a literal held to the model, because the tests image copies that module flat.
- **The storage check lives in `tests/data_model.js`**, not in `secret_storage_engine.js`, and reads the keys out of the source with acorn (`tests/storage_inventory.js`).
- **The run-time storage recorder** wraps `WebDriver.quit()` from a preload (`tests/tools/record-storage-on-quit.js`), the way the coverage flush already did, rather than adding a hook to each browser test.
- **The API explorer** is Swagger UI from `swagger-ui-dist`, with its `@scarf/scarf` install analytics switched off in `api/package.json` and `api/Dockerfile`; the script-free list is at `/api-docs/operations`.
- **Phase 5 was done after all**, for the OAuth discovery and RP-metadata tables, SCIM's operations, error types, scenarios and vocabularies, and the Shared Signals event vocabulary, as typed `const`s written to `client/src/catalog/`. The IANA claim registry stays IANA's.
- **The api's families were switched in parallel**, each on its own branch from the pilot's commit, and merged.

## What this adds

This project's data shapes get **one written source, in TypeSpec, under `models/`**. Today four kinds of shape are written down only in the code that uses them:

1. **The api's HTTP surface.** `api/server.js` registers 60 routes. 47 carry a JSDoc `@route` block that `express-swagger-generator` turns into a Swagger 2.0 document; 13 carry none. That document is prose about the code, and nothing holds the code to it. Each handler checks its own input, or doesn't: `ssf_proxy.describeRequest()` checks what it is given, while `POST /token` reads `req.body.token_endpoint`, `client_id` and `sslValidate` directly and checks none of them.
2. **Configuration.** `api/env/*.js` has 38 keys and `client/src/env/*.js` has 41. Neither has a schema. A misspelled key in an env file is silently a missing setting, and CLAUDE.md's "sixteen settings none of which may be dropped" is enforced by reading the prose.
3. **Persisted browser state.** About 74 literal storage keys, 409 `.stored` form fields across `client/public/*.html`, and keys built from element ids at run time (`jwt_tools.js:515`, `token_detail.js:257`, `spiffe.js:250`). Which of these are secrets, bearer tokens or key pairs is three hand-kept arrays in `client/src/secret_storage.js`, plus the opt-out lists in each key-pair pane and in `sd_jwt_vc.js`.
4. **The embedded contract.** `embedded/CLAUDE.md` says "the mock STS is the consumer and the file is the contract". The contract is a Markdown table of `DEBUGGER_*` variables and output paths that another repository depends on.

Each of these becomes a TypeSpec declaration. Its generated form (OpenAPI 3.1, JSON Schema, or a JSON table) is what the code reads, and a test fails when the two disagree.

**The approach comes from iya-sts v1.0.0's `models/`. Its models, decorators and generated files are not used here.** Three things carry over: one source per shape, generated artefacts read by the running code, and the rule that nothing switches to the model until the generated form is shown to equal what it replaces. iya-sts's decorator libraries are BUSL-1.1 and model things this project does not have (an LDAP directory, SQL tables), so nothing of theirs is copied, and nothing here ever reads iya-sts's `models/generated/`.

## Non-goals, and why

- **No protocol conformance checks in the api's validators.** This is the decision everything else depends on. A debugger has to be able to send a malformed authorization request, an expired assertion or an extra subject-identifier member. Watching the far end refuse it is the point. So an api request model describes what the **api** needs in order to do its job: a URL it can fetch, a port number, a boolean, a body under the size cap. Wherever the payload is the user's protocol message, which the api forwards as typed, the model says exactly that: an opaque string, or `Record<unknown>`. A validator that refused a bad `grant_type` would break the tool.
- **No shared grammars with iya-sts.** CLAUDE.md already keeps the SSF subject grammar unshared ("a grammar is a READING"), and protocol features follow the specifications, not the test peer. Phase 5's catalogues, if built, are this project's own reading.
- **No directory, persistence or domain-invariant namespaces.** The debugger has no LDAP schema, no database and no server-side records. iya-sts's `Domain` namespace ties concepts to records its own code keeps, and the only records the debugger keeps are in the browser (phase 3) and in the SSF receiver's in-memory inboxes (modelled as that endpoint's answers in phase 1).
- **No runtime TypeSpec.** The compiler is a dev/test dependency. Only the generated files ship, and the api gains exactly one runtime dependency, a JSON Schema validator.

## Layout

```
models/
  CLAUDE.md                 how a model is written, what each test holds
  package.json              @typespec/compiler, /http, /openapi3, /json-schema
                            (exact versions; dev only, never in an image)
  main.tsp                  imports every namespace below
  lib/
    debugger_lib.tsp        this project's decorators (few; see below)
    debugger_lib.js         their implementations, and the closed key sets
  api/
    main.tsp                @service, servers, the shared Refusal model
    common.tsp              Limits, Timing, HttpTrace, OutboundRefusal
    oauth.tsp  saml.tsp  wsfed.tsp  wstrust.tsp  krb5.tsp  ldap.tsp
    tls.tsp  scim.tsp  ssf.tsp  gnap.tsp  spiffe.tsp  smartcard.tsp
  config/
    api_config.tsp          api/env/*.js
    client_config.tsp       client/src/env/*.js
  storage/
    storage.tsp             the key classes and the Key model
    oauth2_oidc.tsp  saml.tsp  wsfed.tsp  wstrust.tsp  sd_jwt_vc.tsp  ...
                            one file per workflow's pages
  contract/
    embedded.tsp            the DEBUGGER_* variables and the output tree
  catalog/                  (phase 5 only, if at all)
  tools/
    generate.js             compile, emit, write common/model/, --check
    inventory_storage.js    scans client/public/*.html for .stored ids
common/model/               GENERATED, COMMITTED
  openapi.json              the api document, OpenAPI 3.1
  api_config.schema.json  client_config.schema.json
  storage.json              every declared key with its class
  embedded_contract.json
```

**The generated files are committed**, which is the opposite of what iya-sts does, for three reasons specific to this tree. `api/native.js` runs the api straight from a checkout, before anything is known to be installed. `client/build.js` builds the static sites and the embedded tree without docker. `embedded/build.sh` is run by another repository. In none of those is a TypeSpec compile available, or one that should be required. iya-sts made the same choice for `schema.sql`, for the same kind of reason. `node models/tools/generate.js --check` regenerates into a temporary directory and fails on any difference, and a suite job runs it.

**They go in `common/model/`** because both services read them, which is the same reason `common/data.js` and `common/xmldsig.js` live in `common/`. The client bundles that need `storage.json` or the config schema get it staged into `client/src/` by `client/build.js` the way `common/xmldsig.js` is. **`client/Dockerfile` has its own copy of that staging and must change in the same commit**, because `build.js` says it "matches client/Dockerfile", and the coverage build is the Dockerfile's.

**The output is JSON, not generated JavaScript.** Browserify bundles a required `.json` natively. Generated JS would also have to follow the house style (entry/exit logging, 80 columns, no one-line `try`), which a generator would reproduce badly and a reviewer would have to ignore.

**Stock emitters do most of the work.** iya-sts needed a dozen decorator libraries because it modelled LDAP attributes and SQL DDL. An HTTP JSON API is what `@typespec/http` and `@typespec/openapi3` already express, and a config file or a storage table is what `@typespec/json-schema` already expresses. This project's own decorators are the facts those emitters cannot state:

| Decorator | On | Says |
|---|---|---|
| `@outboundPolicy` | an api config property | it is one of the settings every outbound call site must honour (today's "sixteen") |
| `@passthrough` | a request property | the api forwards this as the user typed it. It is never checked beyond type and size, and the validator must not tighten it |
| `@storageClass(...)` | a storage key | `secret` (never stored), `session` (sessionStorage only), `keypair` (stored behind a named opt-out checkbox), `output` (a token the workflow obtained), `ordinary` |
| `@optOut("saml_save_keypair")` | a `keypair` key | the preference key that gates it |
| `@contract` | an embedded variable | it is read by iya-sts, so renaming it is a cross-repo change |

A decorator's argument set is closed, so an undeclared key is a compile error. That keeps the decorators from becoming free-form notes.

## Phase 0 — toolchain and skeleton

- `models/package.json`, with exact pinned versions current at implementation time. The compiler also goes in `tests/package.json`, so the tests image can run `--check`.
- `models/tools/generate.js` with `--check`. It logs entry and exit like any other module (it is a build script, so it carries the console-backed `log` shim CLAUDE.md lists for those).
- One trivial model to prove the pipeline end to end: `GET /healthcheck` plus the shared `Limits` answer.
- Suite job `Abstract data model is current` in `tests/run-report.js`'s `buildJobs()`: node only, no browser, no `JOB_LOCKS` entry. It runs `generate.js --check`.
- `models/CLAUDE.md`, `docs/v0.9.6/data-model.md` (the reader's page, like iya-sts's), and a row in the root CLAUDE.md's table.

**Done when** the job is green, and a deliberate one-character edit to a `.tsp` turns it red, naming the file that would change.

## Phase 1 — the api's HTTP surface

### The pilot: LDAP

The eight `POST /ldap/*` operations plus `GET /ldap/limits` go first. They are already documented field by field, they share one handler (`runLdapOperation()`), they have one caller (`client/src/ldap.js`), and their refusals are already a closed set (`LDAP_REFUSED_BY_POLICY`). Everything the pilot proves is then repeated per family.

Each family switches in five steps:

1. **Record.** A node test drives every current handler with valid requests, a refusal for each check the handler makes, an unreachable target and an oversized body, and writes each `(request, status, body)` to `tests/fixtures/api_model/<family>.json`. Those recordings are the equivalence baseline, and the step is done before any model is written, so the model can't shape what is recorded.
2. **Write the model.** Request, every answer by status, and the refusal model. The refusal **text** is part of the model (`@doc` and a refusal table), because the client shows it and existing tests assert it.
3. **Generate and validate.** `api/model_validate.js` builds one validator per operation from `common/model/openapi.json` (ajv, the one new runtime dependency), keyed by `operationId`. It is Express middleware that answers the same `400 { error, code }` the handler did, with the same text, in the same order of checks. **It refuses a JSON Schema keyword it does not support**, because a validator that ignored one would accept what the document forbids.
4. **Prove equivalence.** `tests/api_model_wire.js` replays every recorded request against the new path and requires the recorded answer byte for byte. It also checks every recorded answer against the document's response schema.
5. **Remove the hand-written check** from the handler, and the family's `@route` JSDoc with it, keeping any reasoning those comments carry.

### Order after the pilot

Ordered by risk, lowest first:

1. The nine `GET /*/limits` endpoints: one shared model, trivial.
2. Kerberos (`/krb5/kdc`, `/service`, `/spnego`) and TLS (`/tls/connect`, `/tls/server-certificate`): small bodies, already hand-validated.
3. SCIM, SSF (`/ssf/call` and the four `/ssf/receiver` routes), GNAP and SPIFFE. Their proxies already have a `describeRequest()`, which becomes the validator's input and loses its own checks.
4. Smartcard and OTP (eight routes).
5. **OAuth** (`/token`, `/introspection`, `/revoke`, `/tokenexchange`, `/deviceauthorization`, `/register`, `/userinfo`). This is the family where `@passthrough` matters most and where today's handlers check least. Each grant's parameters are `@passthrough`; `token_endpoint`, `sslValidate`, `auth_style` and `http_trace` are the api's own and get real types. `common/data.js`'s `convertToOAuth2Format()` stays as it is: it normalizes, and the model only describes what reaches it.
6. **The browser-facing SAML and WS-* routes** last (`/samlacs`, `/samlslo`, `/wsfed`, the `*response` GETs, `/samlsign`, `/samlartifactctx`, `/samlmetadata`, `/wstrust`). An identity provider posts some of these as `application/x-www-form-urlencoded`, and the answer is a redirect or HTML. They are modelled with their real media types and validated for envelope only. An IdP that posts an unexpected field must still reach the page that shows it.

### The served document

`express-swagger-generator` and the JSDoc blocks go once the last family switches. The api serves `common/model/openapi.json` at the URL the old document used, keeping the existing embedded-mode rewrite. That rewrite becomes `servers[0].url = uiUrl + "/api"` in place of Swagger 2.0's `host`/`basePath`/`schemes`. That changes the document's format from Swagger 2.0 to OpenAPI 3.1. Nothing in this tree or in iya-sts reads the document programmatically (checked on 2026-11-16), so the only visible effect is the explorer page. The release notes say so.

### Responses in test runs

The api config gains `validateResponses` (default false, true in `env/docker-tests.js`). When it is on, every answer is checked against its operation's response schema, and a mismatch is logged as `MODEL GAP <operationId> <status>: <path>`. The answer is never changed. A suite job scans the api log for `MODEL GAP` after the run and fails on any. This is how the model of the answers stays true after phase 1, when nobody is recording any more.

**Done when** every route has an `operationId` in the document, `express-swagger-generator` is out of `api/package.json`, `api_model_wire.js` replays every family's recordings, and a full run logs no `MODEL GAP`.

## Phase 2 — configuration

- `ApiConfig` and `ClientConfig` models, emitted as JSON Schema with `additionalProperties: false`, so a misspelled key is an error and not a silently missing setting.
- **The api checks its config at startup** and refuses to bind, naming the key and the file, the same way it already refuses to start without a TLS pair. `api/env/embedded.js` computes its values from `DEBUGGER_*`, so the check runs on the computed object, not on the file text.
- **The client is checked at build time, in `client/build.js`**, before envify inlines the config into the bundles. A bad env file then breaks the static-site build, not a page in somebody's browser.
- The 16 `@outboundPolicy` properties become a generated list. `tests/api_connect_timeout.js` and its siblings read that list instead of a list in prose, and a new outbound call site that omits one fails the same test.
- Every key's `@doc` becomes the reference table in `docs/v0.9.6/running.md`, generated, so the documentation and the schema can't drift.

## Phase 3 — persisted browser state

- **Inventory first.** `models/tools/inventory_storage.js` scans `client/public/*.html` for `.stored` ids and `client/src` for literal `setItem`/`getItem` keys. It prints them grouped by page, which is the first draft of `models/storage/*.tsp`.
- **Each key is declared once**, with its page, its storage, its `@storageClass` and, for a `keypair`, its `@optOut`. Dynamic keys (history rows, per-pane ids) are declared as patterns.
- **`secret_storage.js`'s `SECRET_KEYS`, `SESSION_KEYS` and `SECRET_MEMBERS` are read from `storage.json`**, as are the three key-pair panes' lists and the three `*_HOLDER_PRIVATE_JWK` keys `sd_jwt_vc.js`'s `set()` refuses. Equivalence step: the generated arrays deep-equal the current literals before the literals go.
- **`tests/secret_storage_engine.js` gains two rules:** a `setItem` of a key no model declares fails, and so does a declared key that nothing writes any more. The static scan covers literal keys and `.stored` ids.
- **A run-time recorder covers the dynamic keys** the static scan cannot see. A test helper reads `Object.keys(localStorage)` and `Object.keys(sessionStorage)` before each browser job's `driver.quit()`, and the report fails on an undeclared key. It runs in node and reads only what `executeScript` returns, so CLAUDE.md's no-logging-inside-the-browser rule is respected. Of everything in this phase, this is the piece that catches a new secret field before it ships.

## Phase 4 — the embedded contract

`models/contract/embedded.tsp` declares each `DEBUGGER_*` variable (type, default, which file reads it), the socket variable, and the paths `embedded/build.sh` writes. Generated from it:

- the variables table in `embedded/CLAUDE.md`, between marker comments,
- `common/model/embedded_contract.json`, which `embedded/build.sh` copies into the tree it writes, so a consumer can read what the tree it was handed promises,
- a check in `tests/embedded_deployment.js` that every declared variable is read where the model says, and that every `process.env.DEBUGGER_*` read in the tree is declared.

**This phase does not change iya-sts.** Whether iya-sts reads the JSON is that repository's decision, made there and offered to its integrator session; nothing here writes into iya-sts.

## Phase 5 — protocol catalogues (decision gate, not scheduled)

These are candidates: `ssf_events.js`'s 24 event types, the RFC 7643 schemas in `scim_client.js`, the OAuth parameter sets the pages offer, and the IANA claim registry behind `/claimdescription`. They are already data, DOM-free, and tested against the RFCs, so moving them into TypeSpec mostly changes how they are written. **Proceed with one only if it gains something concrete**: a published JSON Schema somebody will use, or a second consumer in this tree that would otherwise copy the table. When one goes, it follows the same switch: the generated table deep-equals the literal, then the literal goes. Its model is this project's reading of the specification, written from the specification.

## Testing summary

| Job | Phase | Holds |
|---|---|---|
| Abstract data model is current | 0 | `common/model/` is exactly what the `.tsp` files generate |
| `api_model_wire.js` | 1 | each switched family answers exactly what the recordings captured |
| `MODEL GAP` log scan | 1 | no answer in a full run deviates from its documented schema |
| config schema at startup and at build | 2 | no unknown, missing or mistyped key, in any env file |
| `secret_storage_engine.js`, extended | 3 | no undeclared key is written, and no declared key is dead |
| storage recorder | 3 | the same, for keys only a running page creates |
| `embedded_deployment.js`, extended | 4 | the contract and the tree agree |

All of them are node jobs except the recorder, which rides on the existing browser jobs. None needs a new service or a `JOB_LOCKS` entry.

## Phases and sizing

| Phase | Size | Depends on |
|---|---|---|
| 0 Toolchain | small | — |
| 1 API: LDAP pilot | medium | 0 |
| 1 API: remaining families | large; one PR per family | pilot |
| 2 Config | small–medium | 0 |
| 3 Storage | medium; the inventory is most of it | 0 |
| 4 Embedded contract | small | 2 (shares the variable models) |
| 5 Catalogues | per catalogue, if at all | 0 |

Phases 2 and 3 do not depend on phase 1 and can run beside it. Each phase, and each API family, is its own ticket and branch, landing on `develop` through the integrator.

## Open decisions

1. **Validator: ajv or zod?** This plan says ajv. The api is plain JavaScript, ajv reads OpenAPI 3.1's JSON Schema 2020-12 directly, and there is no TypeScript here for zod to pay for.
2. **Should the served API document keep its URL?** This plan says yes. Changing the URL would break bookmarks for no gain.
3. **Should `validateResponses` ever be on outside tests?** This plan says no. It costs a schema check per answer and protects nobody using the tool.
4. **Is the storage recorder worth a hook in every browser job,** or only in the jobs that cover pages with dynamic keys? Start with every job: it is one `executeScript` per job, and partial coverage is how a new key gets missed.
