# Infrastructure (Terraform, containerized)

All Terraform runs **inside a Docker container** — the only thing on your host
(or the CI runner) is Docker. Same pattern as the static-content deploy pipeline
in `../deploy`.

## Layout

| Path | What |
|---|---|
| `terraform/` | **prod** — idptools.com (apex + www) |
| `terraform-test/` | **test** — test.idptools.com (subdomain of the prod zone) |
| `edge/` | source for the edge compute both stacks deploy (see below) |
| `Dockerfile` | Terraform + AWS CLI runner image |
| `entrypoint.sh` | runs `init`/`plan`/`apply`/… for one env inside the container |
| `terraform-local.sh` | host wrapper: builds the image, bridges your SSO creds, runs it |
| `bootstrap-state.sh` | one-time creation of the S3 state bucket |

## Edge compute — why a static site can still speak these protocols

Both distributions carry three pieces of code at the edge. They exist for the
same reason: an identity protocol's *response* has to land somewhere, and static
hosting has no server. None of them is an optimisation.

| What | Kind | Where | Why |
|---|---|---|---|
| `callback_rewrite` | CloudFront **Function**, viewer-request | inline in `cloudfront.tf` | Rewrites `/callback` → `/callback/index.html` so the S3 website endpoint does not issue a trailing-slash redirect and drop the OAuth2 query string before the callback shim runs. |
| `wsfed_landing` | **Lambda@Edge**, viewer-request, `include_body` | `edge/wsfed_landing.js` | Receives the WS-Federation IdP's auto-POST of `wresult` to `/wsfed` and hands it to `wsfed_response.html`. |
| `saml_landing` | **Lambda@Edge**, viewer-request, `include_body` | `edge/saml_landing.js` | Receives the SAML IdP's POST of `SAMLResponse` to `/samlacs` or `/samlslo` and hands it to `saml_response.html`. |

Both Lambdas are wired in `lambda_edge.tf` and share `edge/edge_common.js`, which is why the zip is built from the whole `edge/` directory (`source_dir`) rather than one file; each function picks its entry point with `handler`.

The two Lambdas differ in how badly they are needed.

The **WS-Federation Passive Requestor Profile has no alternative at all**. It
defines exactly one way to return the token — the IdP renders a form that
auto-POSTs `wa`/`wresult`/`wctx` to `wreply` — and S3 answers a POST with
403/405. Without `wsfed_landing` the round trip simply cannot complete.

**SAML has one, and it was used**: with no landing the client asks the IdP to
return the *Response* over HTTP-Redirect to a static page
(`responseProtocolBinding()` in `client/src/saml_request.js`), which is why the
"HTTP-POST binding" test passed on a backendless target — it POSTs the request
and receives a GET. That still works and is still the fallback, because real
deployments use the Redirect binding and it is the only thing available with
nothing able to receive a POST. But it is out of profile —
[saml-profiles-2.0-os](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf)
§4.1.2 step 5: *"The HTTP Redirect binding MUST NOT be used, as the response will
typically exceed the URL length permitted by most user agents"* — and that stated
reason is measurable. Ciphertext does not compress, so a Keycloak response
DEFLATEs to ~42% of its size plain but only ~71% encrypted, taking the redirect
URL from ~3.0 KB to ~7.0 KB against CloudFront's 8,192-byte URL cap, with each
extra attribute or role mapper adding 350–450 bytes more. With `saml_landing`
deployed the static sites use POST like everyone else, and the
EncryptedAssertion workflow works there at all.

Note what was *not* the problem: decryption. `decryptAssertion()` in
`client/src/saml_response.js` is node-forge in the page — no `fetch`, no api, not
even Web Crypto. The obstacle was only ever delivery.

`HTTP-Artifact` remains impossible statically under any arrangement: resolving a
`SAMLart` means a signed server-to-server SOAP `ArtifactResolve` call, which a
viewer-request function cannot make. `saml_landing.js` refuses one saying exactly
that, rather than failing generically.

Three things to know before changing them:

* They **must** be Lambda@Edge, not CloudFront Functions. CloudFront Functions
  are never given the request body, so the token would be gone before any code
  saw it. That is also why each association sets `include_body = true`, and why
  `/wsfed`, `/samlacs` and `/samlslo` each get their own `ordered_cache_behavior`
  (POST allowed, caching off): a behavior can carry a CloudFront Function *or* a
  Lambda@Edge on a given event type, never both.
* Neither Lambda can stash anything, so each hands its value to the browser in
  `sessionStorage` and redirects to the response page with `?posted=1`. Those key
  names are a **contract duplicated** in `client/src/edge_landing.js` — the
  Lambdas ship via Terraform, the page via the site build, and they cannot import
  each other. `tests/edge_landing_contract.js` loads both and fails if they
  drift; it runs from both `wsfed_sso.js` and `saml_encrypted_sso.js`.
* The SAML landing does **not decode** the `SAMLResponse`. It passes the base64
  through exactly as it arrived — still DEFLATE-compressed if that is how it came
  — because `decodeSamlParam()` on the response page already handles both and is
  the decoder the direct `?SAMLResponse=` path has always used. One decoder,
  already tested.

The site build and the infrastructure ship **independently**, so a target can be
current and still have no landing. `client/src/env/{prod,test-idptools-com}.js`
declare `wsfedEdgeLanding: true` and `samlEdgeLanding: true` to say they are
deployed; with either false the page falls back (paste the `wresult` in by hand;
ask the IdP for the Redirect binding). `remote-run-tests.sh`'s
`probeEdgeLandings()` probes both with a real POST **before `configureKeycloak`
runs**, since what it finds is what gets registered as the SAML client's ACS, and
skips the affected job — with a message naming this — rather than failing when a
Lambda is not there yet.

Note on `destroy`: CloudFront replicates a Lambda@Edge to the edge locations and
AWS removes those replicas on its own schedule, so a `terraform destroy` soon
after an `apply` fails with *"Lambda was unable to delete … replicated
function"*. Wait and re-run; it is an AWS constraint, not a misconfiguration.

## Remote state

State lives in S3: **`s3://idptools-terraform-state-721850476504`**
(versioned, encrypted, private), keys `idptools.com/prod.tfstate` and
`idptools.com/test.tfstate`. Locking is **S3-native** (`use_lockfile`,
Terraform ≥ 1.11) — no DynamoDB. This is what lets CI runs be meaningful; the
bucket was created once via `bootstrap-state.sh` and is intentionally not
managed by Terraform.

## Run locally

Host needs **Docker** and the **AWS CLI**; sign in first:

```bash
aws sso login          # or: aws login

./infra/terraform-local.sh test plan     # env action
./infra/terraform-local.sh prod plan
./infra/terraform-local.sh prod apply
```

`env` = `prod|test` (default `test`), `action` =
`init|validate|plan|apply|destroy|output` (default `plan`). If your Docker needs
root, the wrapper auto-falls back to `sudo docker` (or set `DOCKER="sudo docker"`).

## CI

`.github/workflows/terraform.yml` builds the same image and runs it on
**manual dispatch only** (Actions tab → *Terraform* → *Run workflow* → pick
environment + `plan`/`apply`).

It deliberately does **not** run on `pull_request`: on a public repo that would
either fail noisily on fork PRs (secrets are withheld from forks) or, worse,
risk executing untrusted PR content with credentials. Keeping it dispatch-only
means CI never runs on untrusted PR content.

CI authenticates with the `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` repo
secrets (local runs use your SSO session instead).
