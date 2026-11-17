# The abstract data model

**The shapes this project's code exchanges are written once, in TypeSpec, under `models/`**, and the code reads what is generated from them. There are four, kept in separate namespaces because they are different kinds of thing:

| What | Written in | Generated into `common/model/` | What reads it |
|---|---|---|---|
| **The api's HTTP surface**: all 63 operations, what each accepts and what each answers, by status | `models/api/<family>.tsp` | `openapi.json` (OpenAPI 3.1) | `api/model_validate.js`, which builds every route's request validator from it; the api serves it at `GET /api-docs.json` |
| **The two services' configuration files** | `models/config/` | `config.schema.json` (JSON Schema 2020-12, both objects closed) | the api at startup; `client/build.js` and `client/Dockerfile` before bundling |
| **Every browser storage key** the client names (532), with what it is: a secret never stored, a bearer token kept in sessionStorage only, key material behind a save checkbox, an output, or configuration | `models/storage/` | `storage.json`, and `storage_classes.json` (the four lists that are enforced) | `client/src/secret_storage.js` and the three key-pair panes; `tests/data_model.js` |
| **The embedded deployment's contract** with iya-sts: the variables the api child reads, and the tree `embedded/build.sh` writes | `models/contract/` | `embedded_contract.json`, and the variables table in `embedded/CLAUDE.md` | `embedded/build.sh` ships it in the tree; `tests/data_model.js` |

The approach is iya-sts v1.0.0's: one source, generated artefacts that the running code reads, and nothing switched until what was generated was shown to equal what it replaced. **None of iya-sts's models, decorators or generated files are used.** Its libraries are BUSL-1.1 and describe things this project does not have, such as an LDAP directory and SQL tables. Everything under `models/` was written for this tree, under MIT.

## What it changed for somebody using the debugger

Very little, on purpose. The rule every request model follows is that **the api refuses only what no handler could use**: a member of the wrong JSON type, or a required member that is missing. It never constrains the *content* of a protocol message it forwards. A `grant_type` of `not-a-grant`, an RFC 4515 filter that will not parse, a SAML assertion that is wrong — all still reach the far end, because a debugger exists to show what the far end says about them. Such a member is marked `@passthrough` in the model, so nobody tightens it later.

Where a request used to be accepted with a member of the wrong JSON type, it is now refused with `400 { error, code: "EMODELREQUEST" }`, naming the member. Each of those cases is recorded with the answer it used to get and one sentence saying why the new one is better. Most of the old answers were accidents, for example:

- `sslValidate: 0` read as *true*;
- an object `auth_style` moving the client credentials into the body;
- a numeric APDU turned into its decimal digits and sent to a smart card as hex;
- a number given as an LDAP bind DN, bound as the string `"7"`.

There are 68 such cases across the fourteen fixture families.

**`GET /api-docs.json` is now OpenAPI 3.1**, generated from the model, where it was a Swagger 2.0 document built from comments in `api/server.js` that nothing held to the code. `GET /api-docs` is now a self-contained page listing every operation. It is not the interactive explorer that came with `express-swagger-generator`: the alternatives were `swagger-ui-dist`, which has an install-time telemetry dependency, or a CDN.

A misspelt key in an `api/env/*.js` file now stops the api at startup, naming the key and the file. The same mistake in a `client/src/env/*.js` file stops the build. Before, either one silently left the setting at its default.

## How the api's families were switched

Each family — LDAP first, as the pilot, then service, Kerberos, TLS, SPIFFE, SCIM, Shared Signals, GNAP, smart cards and OTP, OAuth 2.0 / OpenID Connect, and SAML / WS-Federation / WS-Trust — went through the same five steps:

1. **Record.** Every refusal the handler and its module make, an empty body, a wrong type, and a well-formed request aimed at a `.invalid` host, which RFC 6761 guarantees never resolves. Each was sent to the api *as it was*, and its answer written into `tests/fixtures/api_model/<family>.json`.
2. **Write the model.**
3. **Opt the routes in** with `model.route('<operationId>')`.
4. **Replay.** Any difference was either a mistake in the model, which was fixed, or a deliberate change, which was marked `changed` and kept its old answer as `before`.
5. **Delete** the hand-written check the schema now owned, and replay again.

`tests/api_model_wire.js` replays all 385 recordings on every suite run. It holds each answer both to its recording and to the document, and it fails on any operation that no recording covers. Beyond the recordings:

- **Success paths** were driven against throwaway local peers: a KDC, an LDAP server, an authorization server, a SPIRE server, a TLS server asking for a client certificate. Each time the api's record of answers its document did not describe (`GET /model/gaps`) came back empty.
- **The test configuration** keeps that record on for the whole suite (`validateResponses`), and `tests/api_model_gaps.js` runs after every other job and fails on any gap.

## Changing a model

Edit the `.tsp` file, run `node models/tools/generate.mjs` (once `npm install` has been run in `models/`), and commit both. `tests/data_model.js` fails until the generated files match the models. It also edits a copy of a model to prove that check would notice. `models/CLAUDE.md` has the rules a model follows and the procedure for a new api family.

## The protocol catalogues

Some client modules hold specification data as tables: discovery metadata members, SCIM error types and operations, and the Shared Signals event vocabulary. Each of those tables is now a typed `const` in `models/catalog/*.tsp`. The generator writes it to `client/src/catalog/<name>.json`, and the module requires it as `./catalog/<name>.json`. That is a sibling path because the tests image copies several of these modules flat.

A catalogue row model is closed, so a row with a member its model does not declare is a compile error. Each table moved only after the generated JSON deep-equalled the literal it replaced. `tests/data_model.js` then holds every module's exported table to its JSON on disk.

Each catalogue is this project's reading of its specification. None is shared with iya-sts.

**The IANA JWT claim registry is not one of them.** The api fetches it from IANA at run time (`GET /claimdescription`) and ships a copy as `api/jwt.xml`. A TypeSpec copy would be a second source for a document whose owner already publishes it machine-readable.

## Storage keys at run time

The static inventory reads 509 keys and 9 prefixes out of `client/src`. 133 call sites build their key in ways it cannot follow, so the suite also records what the browsers actually held:

- `tests/tools/record-storage-on-quit.js` is preloaded into every job. Just before each browser closes, it reads the key names (never the values) on the debugger's origin.
- `tests/storage_keys_recorded.js` runs last. It fails on any of these:
  - a key no model declares;
  - a secret found in any storage;
  - a bearer token found in localStorage.

## Bodies that are not JSON

A Security Event Token pushed to the SSF receiver arrives as `application/secevent+jwt` text. It is validated as the string schema the document gives it, and the wire harness can send one (`text` with a `contentType`).

## The explorer

`GET /api-docs` is Swagger UI again, rendering the model's document, and it can try an operation. It is served from the api's own `node_modules` (`swagger-ui-dist`), never a CDN.

`swagger-ui-dist` depends on `@scarf/scarf`, an install-time analytics hook. That hook is switched off twice:

- by `scarfSettings.enabled: false` in `api/package.json`, which scarf honours;
- by `SCARF_ANALYTICS=false` in `api/Dockerfile`.

The script-free list of operations is at `GET /api-docs/operations`.
