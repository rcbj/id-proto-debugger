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

## Not done, and why

- **Keys built at run time.** The static storage inventory reads 509 keys and 9 prefixes out of `client/src`, but 133 call sites build their key in ways it cannot follow: a helper's parameter, or a key passed in from another module. The plan's run-time recorder would cover those. It needs a hook in every browser test, because each one builds its own WebDriver and there is no shared place to read storage before `quit()`. So it is a separate piece of work.
- **The protocol catalogues** (`ssf_events.js`, the SCIM schemas, the OAuth parameter sets, the IANA claim registry). These were deliberately not scheduled. They are already DOM-free data tables tested against the specifications, so moving one into TypeSpec would mostly change how it is written. One moves only when that buys something concrete.
- **Request bodies that are not JSON or a form** — a Security Event Token pushed as `application/secevent+jwt` — are documented but not validated.
