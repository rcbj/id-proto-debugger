# models/ — the abstract data model

**One written source for the shapes this project's code exchanges**, in
TypeSpec, compiled into `common/model/` by `tools/generate.mjs`. The approach
is iya-sts v1.0.0's (one source, generated artefacts the running code reads,
nothing switched until the generated form equalled what it replaced); **none
of its models, decorators or generated files are used here**, and nothing
here ever reads iya-sts's `models/generated/`. Its libraries are BUSL-1.1;
everything in this directory is MIT and was written for this tree.

`docs/v0.9.6/data-model.md` is the reader's page. This file is for somebody changing
a model.

## The four namespaces

They stay apart: a request body is not a setting, and neither is a storage
key.

| Namespace | Sources | Generates | Read by |
|---|---|---|---|
| `IdProtoDebugger.Api` | `api/*.tsp`, one file per endpoint family | `common/model/openapi.json` (OpenAPI 3.1) | `api/model_validate.js` (every opted-in route's request validator; with `validateResponses`, every answer); the api serves it at `GET /api-docs` |
| `IdProtoDebugger.Config` | `config/api_config.tsp`, `config/client_config.tsp` | `common/model/config.schema.json` (JSON Schema 2020-12, both objects closed) | `common/model_config.js`, called by `api/server.js` at startup and by `client/check_config.js` before bundling |
| `IdProtoDebugger.Storage` | `storage/*.tsp`, one file per workflow | `common/model/storage.json` | `client/src/secret_storage.js` and the three key-pair panes (`storage_classes.json`); `tests/data_model.js` (both) |
| `IdProtoDebugger.Catalog` | `catalog/*.tsp`, one file per protocol | `client/src/catalog/<const name>.json`, one per typed `const` | the client module the table came from, as `require("./catalog/<name>.json")`; `tests/data_model.js` |
| `IdProtoDebugger.Contract` | `contract/main.tsp` | `common/model/embedded_contract.json` | `embedded/build.sh` copies it into the tree; `tests/embedded_deployment.js` |

`lib/debugger_lib.tsp` declares this project's decorators and the closed
value types they take; `lib/debugger_lib.mjs` implements them. An object
value given a key its model does not declare is a compile error — a new fact
is added there first.

## Running it

```bash
cd models && npm install          # once: the compiler and the emitters
node models/tools/generate.mjs    # write common/model/
node models/tools/generate.mjs --check   # write nothing; exit 1 naming each
                                         # file that would change
```

**The generated files are committed** — the opposite of iya-sts — because
`api/native.js`, `client/build.js` and `embedded/build.sh` all run from a
checkout where no TypeSpec compiler may be installed. A change to a `.tsp`
file and its regenerated output go in the same commit; `tests/data_model.js`
fails until they agree, and it also edits a copy of the model to prove the
check would notice.

The compiler is in `models/package.json` only. Nothing that ships has it:
not the api image, not the client image, not the static sites. The tests
image installs it under `/usr/src/source-tree/models` for `data_model.js`.

## What a request model says

**This is the rule every API family follows, and the reason it is the rule.**

A debugger has to be able to send a malformed protocol message and show the
far end refusing it. So the schema refuses only **what no handler could
use**: a member of the wrong JSON type, a required member that is missing, a
body that is not an object. It says **nothing about the content of a protocol
message the api forwards** — a `grant_type`, an RFC 4515 filter, a SAML
assertion, a client id — and such a member is marked `@passthrough` so nobody
tightens it later.

Everything about a *value* — a URL's scheme, a port in an allow-list, an
address under the address policy, a DN that must not be empty, a scope's
spelling — stays in the code that already checks it, and the member says so
with `@checkedInCode("file: what it checks (ERRCODE)")`. Several of those
checks live in modules that are libraries with other callers
(`ldap_client.js`, `krb5_relay.js`, the `*_proxy.js` decision halves); moving
them into the schema would write them twice.

When a route's OWN handler check (not a library's) becomes the schema's —
`runLdapOperation()`'s `if (!body.url)` was the first — the member carries
`@refusal(#{ message, code? })` with the handler's exact sentence, the
handler check is deleted, and the answer is unchanged. `code` is left out of
`@refusal` when the handler answered `{ error }` alone.

Optional members a module coerces with `String(x == null ? '' : x)` are typed
`string | null`, so a `null` keeps working. A member that the module
stringifies whatever it is, and which a user types as JSON (an LDAP attribute
value), is `unknown`.

A refusal the model itself writes is `400 { error, code: "EMODELREQUEST" }`,
naming the member. When several members fail, the first in the model's
property order wins, so **order a request model's properties in the order the
handler checked them**.

Query and path parameters are validated too (`@query`, `@path`), with type
coercion, since they are text on the wire. Form-encoded bodies
(`application/x-www-form-urlencoded`, an IdP's POST) are validated like JSON
ones.

## What an answer model says

Every status an operation can answer is listed, with its body. Models are
**open** (the emitter does not close them), so an extra member is not a gap;
a missing required member, a wrong type, or an undocumented status is. With
`validateResponses` on — `api/env/docker-tests.js` sets it — every answer is
checked, a mismatch is logged `MODEL GAP <operationId> <status>: <path>` and
kept at `GET /model/gaps`, and `tests/api_model_gaps.js` runs LAST in the
suite and fails on any. The answer itself is never changed.

Non-JSON answers (an HTML page, a redirect, XML) are documented with their
media type and are not checked.

## How a family switches

Each step is done before the next starts.

1. **Record.** Write `tests/fixtures/api_model/<family>.json`: `family`,
   `about`, and `cases` (`name`, `method`, `path`, `body`, optional
   `volatile` — dotted body paths that differ per run). Cover every refusal
   the handler and its module make, an empty body, a wrong type, and at least
   one well-formed request per operation. A well-formed request must end the
   same way on any machine: aim it at a `.invalid` host (RFC 6761: never
   resolves), so it reaches the network and stops there. Then, **against the
   api as it is**, run `node tests/api_model_wire.js --record --family <f>`
   with `API_URL` pointing at an api started on
   `api/env/docker-tests.js` (the containerized stack's configuration, which
   the suite replays under), over https — see "Running the api by hand"
   below.
2. **Write the model**, `api/<family>.tsp`, imported from `api/main.tsp`.
   Every operation has an `@operationId` and an `@tag`.
3. **Opt the routes in**: `app.post('/x', model.route('opId'), handler)`.
4. **Replay** (`node tests/api_model_wire.js --family <f>`). A difference is
   either a mistake in the model, fixed there, or a deliberate change: then
   the case gets `changed` (one sentence: why) and `before` (the old answer,
   moved from `expect`), and `--record --missing` records the new `expect`.
5. **Delete the hand-written check** the schema replaced, keeping the
   reasoning its comments carried, and replay again.

`tests/api_model_wire.js` with no `--family` also fails on an operation in the
document with no case, so a new operation cannot arrive unrecorded.

### Running the api by hand

Record and replay over **https**, which is what the suite's stack runs:
an endpoint whose answer depends on the listener differs on plain HTTP
(`GET /tls/server-certificate` is a 404 there and a 200 with the PEM on
TLS). Any self-signed pair will do:

```bash
cd api && npm install
openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/k.pem -out /tmp/c.pem \
  -days 7 -subj /CN=localhost -addext subjectAltName=DNS:localhost
cat > /tmp/api-wire.js <<'EOF2'
module.exports = Object.assign({}, require('/abs/path/api/env/docker-tests.js'),
  { port: '4998', tlsCertFile: '/tmp/c.pem', tlsKeyFile: '/tmp/k.pem' });
EOF2
NODE_PATH=$PWD/node_modules CONFIG_FILE=/tmp/api-wire.js node server.js
# elsewhere:
cd tests && NODE_EXTRA_CA_CERTS=/tmp/c.pem CONFIG_FILE=./env/docker-tests.js \
  API_URL=https://localhost:4998 node api_model_wire.js --family ldap
```

`NODE_PATH` is needed because `common/data.js` requires bunyan from outside
`api/`. Stop it by PID, never with `pkill -f` on a pattern in the same
command line. **`api/env/docker-tests.js` turns the smart-card relay ON**,
so an api run by hand on it with `node-hid` and `pcsclite` installed can
reach a real reader or YubiKey on the machine; move the two packages out of
`api/node_modules` first unless that is what you mean to do.

### The fixture format

A case is `name`, `method`, `path` (with any query string), and one of
`body` (sent as JSON) or `form` (sent as `application/x-www-form-urlencoded`,
what an identity provider's browser POSTs). Redirects are not followed: a
3xx is recorded with its `location`. `volatile` lists what may differ per
run — dotted paths into the body, or `location` for the header — and those
are removed from both sides before comparing. A case cannot carry a value
from one case into the next (a generated id); cover those paths by hand and
say so in the family's `about`.

`--record` re-records every case of the families it reads (all of them,
unless `--family` names one) and `--record --missing` only cases with no
`expect`. **Neither belongs anywhere near a family that has already
switched**: its `expect` is now the new behaviour, and re-recording a
`changed` case would silently drop the evidence of what changed.

### What the validator does with the document

It validates JSON and form-encoded bodies, and query and path parameters,
coercing a parameter's text to the type the document gives. A parameter
spread from a named model is emitted as a `$ref` to
`components.parameters` and is resolved. A parameter's `@refusal` is read
from the parameter object. An answer's status is matched exactly, then by
range (`4XX`), then `default` — so a proxy that relays the far end's
status can document a range. A non-JSON answer (a redirect, a page, XML)
has its status checked and nothing else. A body that is neither JSON nor a
form (`application/secevent+jwt`) is documented and not validated.

## Catalogues

A catalogue is data, not a type: the rows a client module reads. It is written as a **typed `const`** under `catalog/` (`const SCIM_OPERATIONS: ScimOperation[] = #[ #{ ... } ];`), and `generate.mjs` writes each one to `client/src/catalog/<const name, lower case>.json`. The row model is closed, so an unknown member is a compile error, the same as a decorator argument. TypeSpec has no string concatenation, so a long string in a row stays on one line.

The JSON goes beside the modules rather than in `common/model/`, because the tests image copies several of them flat. `require("./catalog/<name>.json")` resolves in a checkout, in a bundle and in a flat copy alike, and `tests/Dockerfile` copies the directory once.

A table moves only after the generated JSON is shown to deep-equal the literal it replaces. The module then keeps its code and loses its rows. `tests/data_model.js` gets a section that holds the module's exported table to the file on disk.

## Style

The repo-root CLAUDE.md's three rules apply to `lib/*.mjs` and
`tools/*.mjs`: every function logs `Entering NAME().` and `Leaving NAME().`
(before each return), no single-line `try`/`catch`, 80 columns. Both are run
outside any install that has bunyan, so each carries a console-backed `log`
shim, quiet unless `MODEL_DEBUG=1`. A `.tsp` file is 80 columns except for a
string literal that cannot be broken (a refusal sentence, a
`@checkedInCode` note) — TypeSpec has no string concatenation in decorator
arguments.

Every `.tsp` and `.mjs` here carries the MIT SPDX header.
