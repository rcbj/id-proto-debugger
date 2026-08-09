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

## Operations History

`client/src/wsfed_history.js` is the third sibling of `saml_history.js` and `wstrust_history.js` over the shared `op_history.js`. It exists because the two pages each know half of what happened:

* the **request** page records the attempt as `Sent` immediately before `window.location.assign()` — before, because the page is about to be replaced by the IdP's and anything after that call may never run;
* the **response** page resolves that entry to `Success` or `Failure` when the `wresult` arrives, because in this profile the IdP's verdict lands there and nowhere else.

**The two operation labels are exported from `wsfed_history.js` rather than written out in each page.** The pages match a pending entry by its operation string (`resolvePending(result, detail, match)`), so a label spelled in two places is a row that never closes — it stays `Sent` for ever, which reads as "the IdP never answered" when in fact the two pages merely disagreed about a word. `tests/wsfed_sso.js` asserts the sign-out label against this module's value for the same reason.

An entry that legitimately stays `Sent` is still informative: it means the IdP never returned a `wresult` to this debugger, so the next place to look is the IdP's own error page.

## The IdP, and why it is a side-car

Keycloak 26.x has no WS-Federation support at all, so the workflow's IdP is a dedicated **Keycloak 8.0.1 side-car** carrying the cloudtrust extension. Everything about that image, its two very different compose configurations, and the provisioning is in `keycloak-wsfed/CLAUDE.md` — including the boot traps that are fatal and silent. `tests/wsfed_sso.js` is skipped rather than failed when `WSFED_METADATA_URL` is unset, so a missing side-car costs a skip; `./local-run-tests.sh --wsfed-only` brings up just api + client + the side-car for a fast loop on it.

## What the test covers

`tests/wsfed_sso.js` drives the round trip **and the sign-out**, in one browser and in that order, because a sign-out needs a session to end. Sign-out returns no token, so what is checked is that the browser came back to `wreply` as a sign-out and that **the session is really gone** — signing in again must show Keycloak's login form rather than silently minting a second token off a surviving SSO cookie. It also asserts the Operations History closed the sign-out out as `Success`, which is the user-visible confirmation that a dispatched call actually completed.

The `signout=` flag on the last hop is deliberately **not** asserted to be `wsignout1.0`: the extension's `finishLogout` sends no `wa` at all, so the api's fallback makes it `signout=1`, and `wsignoutcleanup1.0` is the value when `frontchannelLogout` is involved instead. The test drives **either landing** without knowing which, because the assertions are on what the user sees and both landings put the same thing on the same page.
