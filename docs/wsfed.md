# WS-Federation — the request page, the response page, and the POST between them

Two pages, because the Passive Requestor Profile has two halves and they happen in different places:

| Page | What it does |
|---|---|
| `wsfed_request.html` | Loads the IdP's federation metadata, builds the sign-in request (`wa=wsignin1.0` with `wtrealm`/`wreply`/`wctx`/`wct`/`wfresh`/`whr`/`wauth`/`wreq`) or the sign-out (`wa=wsignout1.0`), and hands the browser to the IdP. |
| `wsfed_response.html` | Renders what came back: the `wresult` RSTR, the WS-Trust fields, the security token, and the decoded assertion — with Validate Signature and Decrypt. |

**The request page was called `wsfed_tools.html` until 2026-08-09.** It was renamed to match `saml_request.html`, which is the same thing for the same reason: the page *builds and sends the request*, and "tools" said nothing about that. The rename is total — the bundle, the standalone global the `onclick` handlers call, the landing card, the header's context-aware Home link, `saml_cert.js`'s return map, and the tests all use the new name, and nothing answers on the old URL. If you are looking at a branch where `wsfed_tools` still appears, it predates that merge. (For the SAML family the equivalent map is in `docs/`'s SAML notes: `saml_tools.html` there is the **assertion builder**, a different page from `saml_request.html`.)

## The POST that has nowhere to land

The profile ends with the IdP **auto-POSTing** a form to the RP's `wreply`. That is the whole difficulty of hosting this workflow, because there is no redirect binding to fall back to the way SAML has one. Three deployments, and the request page's `wreply` default reflects which one it is on:

* **api backend** — Express's `/wsfed` route receives the POST, stashes the `wresult`, and redirects to `wsfed_response.html?id=…`.
* **static + Lambda@Edge** — `infra/edge/wsfed_landing.js` receives it at the edge and, having nowhere to stash it, hands it to the browser in `sessionStorage`, then redirects to `wsfed_response.html?posted=1`. It **cannot** be a CloudFront Function: functions are never given the request body, so the `wresult` would be gone. See `infra/CLAUDE.md`.
* **static with no landing** — nothing can receive it, so the response page takes the `wresult` XML pasted into a box.

`wsfed_response.js` handles all three, and `client/src/edge_landing.js` is the client half of the second one's hand-off contract.

## Signing the request

The Passive Requestor Profile does **not** require a signed sign-in request and many IdPs ignore one, so this is a debugging affordance: it puts a signature on the wire so you can see what an IdP does with it. The toggle (`wsfed_sign_request`) is **on by default**, and there are two bindings, which are not interchangeable:

| Binding | Signs | Leaves unprotected |
|---|---|---|
| **Redirect** | the whole query string — SigAlg is appended *before* signing and is covered, so an IdP cannot be talked into a weaker algorithm by rewriting the parameter | nothing in the request |
| **Enveloped** | an XML-DSIG inside the inline `wreq` | everything outside it, including `wtrealm` and `wreply` — they live in the query and nowhere else |

Because the enveloped binding has nothing to sign without an inline `wreq`, selecting it **turns that on for you** rather than silently producing an unsigned request. Four RSA algorithms are offered (SHA-1/256/384/512); the RP key is RSA, so those are the applicable XML-DSIG URIs.

**With signing on and no key, the request is built unsigned and the status says `NOT signed`** — the one outcome that must never be silent, because a request that merely looks signed is exactly what somebody debugging a signature would be misled by. Pressing *Generate Keys* rebuilds the request immediately, so what is on screen is always what the buttons would send.

Both paths go through `client/src/xmldsig.js` — `signQueryString()` and `signEnveloped()` — the same engine the SAML and WS-Trust pages use. Nothing here reimplements a signature.

`tests/wsfed_sso.js` drives all eight combinations (two bindings × four algorithms × two initiation routes), against each IdP, and asserts the signature **client-side, before the round trip**: that is the deterministic part. Whether the IdP then honours it is a separate, best-effort concern — neither of them verifies a passive sign-in request, which the profile does not require them to.

## Operations History

`client/src/wsfed_history.js` is the third sibling of `saml_history.js` and `wstrust_history.js` over the shared `op_history.js`. It exists because the two pages each know half of what happened:

* the **request** page records the attempt as `Sent` immediately before `window.location.assign()` — before, because the page is about to be replaced by the IdP's and anything after that call may never run;
* the **response** page resolves that entry to `Success` or `Failure` when the `wresult` arrives, because in this profile the IdP's verdict lands there and nowhere else.

**The two operation labels are exported from `wsfed_history.js` rather than written out in each page.** The pages match a pending entry by its operation string (`resolvePending(result, detail, match)`), so a label spelled in two places is a row that never closes — it stays `Sent` for ever, which reads as "the IdP never answered" when in fact the two pages merely disagreed about a word. `tests/wsfed_sso.js` asserts the sign-out label against this module's value for the same reason.

An entry that legitimately stays `Sent` is still informative: it means the IdP never returned a `wresult` to this debugger, so the next place to look is the IdP's own error page.

## Two IdPs, and why each is needed

Keycloak 26.x has no WS-Federation support at all, so the workflow's original IdP is a dedicated **Keycloak 8.0.1 side-car** carrying the cloudtrust extension. Everything about that image, its two very different compose configurations, and the provisioning is in `keycloak-wsfed/CLAUDE.md` — including the boot traps that are fatal and silent. `tests/wsfed_sso.js` is skipped rather than failed when `WSFED_METADATA_URL` is unset, so a missing side-car costs a skip; `./local-run-tests.sh --wsfed-only` brings up just api + client + the mock STS + the side-car and runs the test against **both** IdPs, for a fast loop on it. It takes an optional identity provider — `--wsfed-only=sts` or `--wsfed-only=keycloak` — and `=sts` is the fastest loop there is here, because it is the one that does not wait twenty seconds for WildFly. Drive both before believing a change: the whole point of the pair is that they fail differently, and a loop that runs one of them green-lights what the real run then fails.

Since 2026-08 the **mock STS answers this profile too** (`sts/wsfed.js`, and `docs/mock-sts.md`), and **every combination below runs against both** — 42 jobs where there were 21. That is not redundancy; the two IdPs are complementary, and the reason is what each of them *cannot* tell you:

* **Keycloak is somebody else's implementation.** A real server, a real session cookie, a real login form, provisioned through its admin API. It is the only thing here that can say the debugger interoperates with software this project did not write, which is the whole reason an EOL server is kept alive.
* **The mock reads what the debugger sends.** Keycloak's extension ignores `wreq` entirely, accepts any `wauth`, and never states a token type — so against it, nine of these jobs prove only that a request was *built* and a round trip completed. The mock refuses a `wauth` naming a method it cannot perform, a token type its `fed:TokenTypesOffered` does not list, and `wreqptr` outright, each with a reason. A request that is well-formed but wrong therefore fails there and passes at Keycloak.
* It is also the only WS-Federation IdP available **where the side-car is not** — it runs in every stack the suite starts, including the host and live-site runs, so a target that skips Keycloak still gets the profile exercised.

The differences between them are four, all marked `IDP:` in the test, and none is a difference in the protocol: the submit button's id on the sign-in screen (`#kc-login` vs `#wsfed-login` — the fields are `#username`/`#password` on both), where the passive endpoint sits relative to the metadata document, which token types an inline `wreq` may ask for, and **how sign-out returns the browser** (see below). Anything else that diverges is a finding rather than a case to special-case, which is the point of running both.

The mock needs no provisioning at all — it registers no relying parties, so `wtrealm` is any string and becomes the audience, and it authenticates nobody: the username typed is the subject of the assertion and the only password refused is the literal `invalid`. Its jobs are gated on `WSFED_STS_METADATA_URL`, which the launchers set wherever the STS is reachable **by the browser** (compose DNS name in the containerized stack, loopback on the host and live-site runs). It is deliberately a separate variable from `WSTRUST_STS_URL`, which may legitimately be pointed at a real Apache CXF STS that has no passive endpoint at all — deriving one from the other would turn "not this protocol" into a run of failing jobs.

## What the test covers

`tests/wsfed_sso.js` drives the round trip **and the sign-out**, in one browser and in that order, because a sign-out needs a session to end. Sign-out returns no token, so what is checked is that the browser came back to `wreply` as a sign-out and that **the session is really gone** — signing in again must show the IdP's login form rather than silently minting a second token off a surviving SSO cookie. It also asserts the Operations History closed the sign-out out as `Success`, which is the user-visible confirmation that a dispatched call actually completed.

**How the browser gets back to `wreply` after `wa=wsignout1.0` is the one leg where the two IdPs genuinely differ, and 13.2.4 permits both** — it says the IdP MAY return the browser and does not say how. Keycloak redirects. The mock renders a *Signed out* page carrying a **link**, deliberately: that page also fires the front-channel cleanup pings (one 1×1 image per relying party the session signed into), and a 302 would abandon them before they were sent. So the test waits for either and follows the link when it is offered — which is also the only reason the landing must answer a **GET** as well as the POST that carries a token.

The `signout=` flag on the last hop is deliberately **not** asserted to be `wsignout1.0`, and neither IdP sends it: the extension's `finishLogout` sends no `wa` at all, the mock's return link is `wreply` verbatim (its `wsignoutcleanup1.0` goes on the cleanup pings, where 13.2.4 puts it), so the landings' fallback makes it `signout=1`. `wsignoutcleanup1.0` is the value when Keycloak's `frontchannelLogout` is involved instead. The test drives **either landing** without knowing which, because the assertions are on what the user sees and both landings put the same thing on the same page.
