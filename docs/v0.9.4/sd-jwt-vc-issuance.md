# The SD-JWT VC issuance workflow (`vc-issuance-{0,1,2,3,4}.html`)

Read this before changing any `vc-issuance-*` page, its bundle, or `css/sd_jwt_vc.css`. Two things here are counter-intuitive: the layout constraints are *measured* and mutation-tested, so a plausible CSS simplification is caught; and Credential History is a log of every attempt, of which the held credentials are only a navigable subset.

## The workflow

The **SD-JWT VC issuance workflow** (`vc-issuance-{0,1,2,3,4}.html`) reuses the OIDC Authorization Code flow on `oauth2_oidc_1.html` / `oauth2_oidc_2.html`: the `?sdjwtvc=1` query parameter marks the flow active, and `oauth2_oidc_2.html` returns to step 2 once it has the tokens. Both debugger pages behave exactly as before without that parameter. Step 1's authorization-server pane deliberately writes the **same localStorage keys** the debugger pages read.

**That sharing runs both ways, and one of the two directions is a trap.** `oauth2_oidc_1.html`'s metadata pane defaults to an *OpenID Connect Discovery* URL (`https://localhost/oidc/.well-known`, a placeholder it writes on a browser that has merely loaded the page) and stores it under `oidc_discovery_endpoint` — the same name step 1's **RFC 8414** pane uses. Read back unfiltered, that turns "Metadata Endpoint URL" on `vc-issuance-1.html` into an `openid-configuration` URL, or into a placeholder that resolves to nothing, for every browser that has visited the OAuth2 / OIDC workflow once — and it looks like a wrong default rather than like a value from another page. `asMetadataUrlAtLoad()` in `client/src/vc_issuance_1.js` is the filter: at load, a stored value is this pane's own only if it carries `/.well-known/oauth-authorization-server` (the RFC 8414 section 3.1 issuer-path form included) or is the empty string a *Clear* leaves behind; anything else loses to `rfc8414MetadataUrlDefault` from the client env — `https://localhost:8081/.well-known/oauth-authorization-server`, the mock STS, on `local.js`. Nothing is written back, so the debugger page keeps its own URL. It is the same rule `defaultAuthorizationServerUrl()` already applied to what it found in the field after a credential-issuer retrieval.

Step 0 chooses which OID4VCI **Appendix H use case** to run. The list lives in one place — `USE_CASES` in `client/src/sd_jwt_vc.js` — and both the chooser's cards and the badge every other page shows are generated from it, so they cannot disagree; `setUseCase()` redraws the badge itself, because an arriving Credential Offer changes the use case after the page has already been laid out. **H.6** (wallet-initiated) is what the workflow has always done. **H.1** (issuer-initiated) starts at the issuer's own page, comes back to step 1 with a Credential Offer in `credential_offer` or `credential_offer_uri`, and carries the offer's `issuer_state` into the authorization request (`oauth2_oidc_1.js` appends it as a custom authorization parameter). **H.2** (cross-device) and **H.3** (deferred) start at the issuer's QR screen, arrive through step 1's *Receive a Credential Offer* pane (the wallet is on another device, so nothing navigates it), and use the `pre-authorized_code` grant — no authorization request, so step 1 hands off straight to step 2, which owns the Token Request and the `tx_code`. H.3 adds the deferred pane: a `202` Credential Response with a `transaction_id`, polled at `deferred_credential_endpoint` until the credential arrives.

Step 4 (`vc-issuance-4.html`) **refreshes** a credential the wallet already holds — OID4VCI **section 14.5**, *Refreshing Issued Credentials* — in the two calls that mechanism is made of: `grant_type=refresh_token` at the token endpoint (RFC 6749 section 6, so nothing about it is OID4VCI-specific), then the same Credential Request step 2 makes, which is why both pages build it with `vci_wallet.js`. Section **14.3** is the reason the refresh half is optional rather than required: the Credential Endpoint may be asked again with an access token that is still valid, which is the only route left after the pre-authorized code grant (H.2/H.3), since that grant issues no refresh token.

Every page of the workflow opens with the **same row of links to every step** — `partials/vc_steps.html`, included at the top of the container, above the page title, with each page marking its own `vc_step_N` as current from its bundle. It is deliberately **one row**: `ol.vc-steps` is `flex-wrap: nowrap` with items that may shrink (`flex: 1 1 0; min-width: 0`), because with the wrapping it had before, adding step 4 pushed the fifth link onto a second line. Captions in the partial are kept short for the same reason, and `stepLinksOnEveryPage()` in `tests/sd_jwt_vc_issuance.js` asserts geometrically — all five items on one top edge, the row one item tall, above the title, no horizontal page scroll — on all five pages.

**Layout trap on these panes.** Everything they display is base64url with no break opportunity in it, and `bootstrap.css` sets `code { white-space: nowrap }` — so a long `c_nonce` or access token used to run off to the right of the pane, and in the Approve pane's list it pushed the whole page sideways. `sd_jwt_vc.css` fixes it at the root: `.dbg-pane code` overrides the `nowrap`, `.vc-token-table` is `table-layout: fixed` (the cell decides the width, as the disclosure tables already did), and `pre.vc-json` / `textarea.vc-token` are both `width: 100%; box-sizing: border-box` so a `<pre>` and a `<textarea>` in one pane come out the same size. `panesContainTheirContent()` in `tests/sd_jwt_vc_issuance.js` plants an over-long value into every `<code>` on all four pages and fails if anything is wider than its pane or the page scrolls horizontally.

**Step 1 is laid out for one screen, and the row of metadata panes is what pays for it.** That page carries four discovery panes — Credential Issuer Metadata, Issuer DID Document, Authorization Server Metadata, DID Configuration — and each is a URL, a few buttons and a status, so stacked full-width they spent 1,234px on content that fits in a quarter of the width. They now sit in `<div class="vc-pane-row">`, a `repeat(auto-fit, minmax(270px, 1fr))` grid with `align-items: start`, four across at 287px each on a desktop container and folding to 3+1 / 2+2 / one-per-line as the window narrows. The rest of the page was compressed the same way: each pane's prose is folded into `<details class="vc-hint">` (a `<details>` needs no script, which matters because these pages set `script-src` tightly), the page intro and the Configuration Parameters note likewise, the legends are short, the *Return to home* link is merged onto the title, and *Receive a Credential Offer* moved below the row. Empty page 6,569px → 2,920px; the four panes, the use-case badge, the collapse toggle and most of the offer pane are above an 839px fold.

Four things about that row are load-bearing, and three of them were regressions in the first cut:

* **A quarter-width pane needs its content stacked, not tabled.** Each pane's own layout table is two columns of label|control, which at 287px left a ~120px control column and put each pane's button group on a different line from the next (these tables split them across two cells, `Retrieve`/`Upload` | `Clear`). So inside `.vc-pane-row` the pane's `fieldset > table` becomes blocks with each `<tr>` a flex line: a cell holding a label, a field, a hint or a filled status claims the whole line (`flex: 1 0 100%`) and everything else shares one. Scoped to `fieldset > table` deliberately — it must not reach the retrieved-document tables nested in `<div>`s below.
* **The retrieved tables need a CEILING, and this is the failure the whole thing turns on.** A quarter of the width wraps every value over several lines, and a grid row is as tall as its tallest pane: the STS's credential issuer metadata document measured **23,299px** in a 287px pane against roughly 4,000 at full width, taking the page to **25,846px** — ten times the stacked layout the row replaced. `.vc-pane-row .discovery_info_table` is therefore `max-height: 300px; overflow: auto`, the same way `#vc_history_table` is bounded, so the row's height no longer depends on what was retrieved (773px with all four loaded). The readable full-width rendering of the same values is the Configuration Parameters pane below; the pane's own table is the raw document beside its controls. **This is invisible on an empty page** — every geometry check passed before the ceiling existed, because nothing had been retrieved — so `stepOneFitsInOneRow()` fills the panes before it measures.
* **The Configuration Parameters pane is three CSS columns, and its groups break across them.** `#config_rows` is a `<div class="vc-config-groups">` (`column-count: 3`, 2 at 1100px, 1 at 700px) holding one self-contained `.vc-config-group` per document, each with an `h4.vc-group-heading`. Multi-column rather than a grid because it balances uneven blocks, and `break-inside: auto` on the group rather than `avoid` because one group holds the RFC 8414 document's remaining 36 members and is ~1,200px on its own — atomic, it set the column height and left the other two columns half empty, so the columns cost height without buying density. `h4.vc-group-heading` carries `break-after: avoid`, since a heading stranded at the foot of a column is the only part of a break that reads as a bug. 1,771px → 1,398px.
* **A member name has to wrap, and the failure is not a height or an overflow.** `id_token_encryption_enc_values_supported` is 40 characters with no break opportunity; in a third of the width it was painted straight over the input beside it and both were unreadable. `.vc-config-table td:first-child` gets `overflow-wrap: anywhere`. Note the tables are `table-layout: fixed`, so the **cell box never moves** — only the glyphs overflow — which is why `stepOneFitsInOneRow()` measures a `Range` over the cell's contents rather than comparing the two cells' bounding boxes. A box-versus-box check sees nothing and passes, which is exactly what removing the wrapping rule proved.

`stepOneFitsInOneRow()` in `tests/sd_jwt_vc_issuance.js` covers all four, and it is mutation-tested: dropping the ceiling (row 23,339px), turning the grid back into a block (four lines), and removing the name-wrapping rule are each caught. Two rules the first cut added were caught *by the same exercise* as doing nothing and were removed — a `table-layout: fixed` and a `word-break` restated for the row's document tables, which `debugger.css`'s `.discovery_info_table` block (`max-width: 100%` plus `overflow-wrap: anywhere`) already enforces, and a `display: table` restoring a display the stacking rule never took away. A rule that claims to hold a layout together while holding nothing is worse than no rule. Separately, note that `vc-config-table` is applied by `vc_issuance_1.js` and `did_tools.js` in generated markup and was for a while styled only via `.vc-config-group table` — defined in no stylesheet, which is precisely what `checkStylesheetsLoaded()` in `tests/navigation.js` fails a run over. Style the class the markup carries.

Step 4 also carries a **Credential History** pane, the counterpart of `oauth2_oidc_2.html`'s Token History — recording rather more than oauth2_oidc_2 does: **every attempt**, one row each, newest first. `sd_jwt_vc.js` holds the store; a row has a `kind` (`issuance` / `token_refresh` / `credential_request` / `deferred_poll`), an `outcome` (`success` / `failed` / `deferred` / `pending` / `kept` / `discarded`) and a `detail` saying what the issuer actually said. `recordHistoryEntry()` appends one row per attempt and returns its id; `updateHistoryEntry()` resolves it later (`pending` → `kept` or `discarded`), so a retry, a refusal and a discarded credential are all on record without any of them becoming a second row for the same call. Every row is numbered in `#` by the order the attempts were made — there is no unnumbered row — while `Gen` carries the generation number, which only the `kept` rows with a credential have: those are the **generations** (`heldGenerations()` numbers them, `activeGeneration()` says which is in hand) and `◀ Older` / `Newer ▶` / Oldest / Latest move over *that subset* (a log row is not a place to be, and says `log only`). The list is the newest `HISTORY_LIMIT` (100) attempts in a **fixed-height scrolling box** with a sticky header (`#vc_history_table` in `sd_jwt_vc.css`): a 100-row log would otherwise push the panes below it off the screen and the pane's height would jump on every attempt. Trimming at `HISTORY_LIMIT` drops the oldest **log** rows first and only touches a generation when nothing else is left, so an audit trail never costs the ability to go back to a credential. `HISTORY_INDEX` holds the active row's **id**, not an index, so a log row appearing between two generations cannot shift it. A credential the issuer has just returned shows up there immediately as a `vc-history-pending` row (outcome `pending`) marked *not kept yet*, with Keep/Discard on it — the pane has to react to the **retrieval**, not only to keeping, or it reads as broken; and keeping deliberately **does not navigate** (`replaceCredential()` calls `reloadHeldCredential()` in place and offers a *Verify in step 3* button), because the pane the holder acted in is the pane that has to show what the action did. Activating a generation is a real state change, not a highlight: it writes `CREDENTIAL`/`CREDENTIALS`/`CREDENTIAL_META` **and that generation's holder key pair**, because a credential whose `cnf` key the wallet no longer has cannot be presented at all — which is also why each entry stores its own key pair, and why *Clear History* writes an empty list rather than removing the key (`hasCredentialHistory()` distinguishes "cleared on purpose" from "never recorded", and only the latter backfills the credential in hand as generation 1). A discarded refresh stays in the log as a `discarded` row — the attempt happened — but its credential and private key are stripped, because discarded has to mean discarded, and it is not a generation: the wallet never held it. Three things the page must get right, all of them wallet behaviour the spec leaves open: the refreshed credential is kept **apart** from the one in hand until the holder chooses (section 14.5 warns about a wallet holding two credentials of the same type and not knowing which is current); what the issuer changed is **read off the two credentials** rather than assumed, because the issuer decides whether to update the signature only or the claim values too — and the salts, Disclosures and digests are new either way, so the comparison is of claim *values*; and choosing to bind a **new holder key** must not overwrite `HOLDER_PRIVATE_JWK` until that credential is kept, or the credential still in hand loses the key it needs to be presented (the pending pair parks in `REFRESHED_HOLDER_*`, and the replaced credential's pair in `PREVIOUS_HOLDER_*`).

Steps 3 and 4 each end with a pane offering the **next thing to do with the credential** — step 3 offers both *Refresh It* (step 4) and *Present It*, step 4 offers *Present It*. Two things about that hand-off are load-bearing. First, **it copies nothing**: the two workflows meet at the storage keys described under *Key Implementation Notes* in the repo-root `CLAUDE.md` and the presentation bundles read `CREDENTIAL` / `HOLDER_PRIVATE_JWK` directly, so the credential is already where the other workflow looks — a hand-off that duplicated it would be a second copy that goes stale, and `presentationHandoff()` in `tests/sd_jwt_vc_issuance.js` asserts the click adds no new key holding those bytes. What the offer owes the user is therefore not a transfer but an honest answer to *will anything happen if I click this*, which is `presentationReadiness()` in `sd_jwt_vc.js` — **one implementation**, because it has to reach the same verdict `renderRequest()` in `vc_presentation_1.js` will reach a page later. It keeps that function's three-way distinction: no credential or an unparseable one blocks; a holder key that is **missing while saving is on** blocks, because it was never generated here, there is nothing to paste and step 1 refuses; a holder key **absent by choice** does *not* block, because presentation step 2 has a field for it. Collapsing those last two to "no key → blocked" is the plausible simplification and it strands the user two pages before the only field that fixes it, so the test asserts they come out differently.

Second, **step 4 is the one page where "the credential" is ambiguous**, and the offer has to say which one would go. It names the generation in hand (and whether it is the newest — going back to an older one is a supported thing to do there), and it explicitly **disowns a refreshed credential that has been retrieved but not kept**: that one is the newest thing on the screen and is not in storage at all, so it is not what a Verifier would see. The offer is rendered from `renderHistory()`, which is the pass every state change goes through — keeping, discarding, activating, stepping, clearing — but the call sits at the **top** of that function rather than the tail, because the empty-history early return is itself a state the offer must describe. Putting it at the tail leaves a fresh wallet with a blank, still-enabled offer, and it is invisible unless the test clears the history as well as the credential — which is exactly what the mutation testing caught.

## Asking for a subset of the claims, and where that request actually goes

Step 1 carries a **Claims to Request** pane: one row per claim the chosen credential configuration says it can carry, every row checked, and clearing a row asks the issuer to leave that claim out. The rows are built from the issuer's own metadata — `credential_configurations_supported[<id>].claims`, an array of claims description objects (OID4VCI Appendix A.2) — so the wallet asks in the vocabulary the issuer published rather than in one invented here, and an issuer that publishes no `claims` member gets a pane that says so rather than an empty table.

**The member does not go where almost everybody looks for it first.** OID4VCI 1.0 puts the optional `claims` member in the **`authorization_details`** entry of type `openid_credential` (section 5.1.1). The **Credential Request has no such member**: section 8.2 defines `credential_identifier` / `credential_configuration_id`, `proofs` and `credential_response_encryption`, and nothing else — the 1.1 editor's draft still does. So the selection is made where the issuance is *authorized*, and by the time step 2 builds the Credential Request it has already been granted; what step 2 shows in its approval pane is what was asked for, not what the metadata offers. Adding a `claims` member to the Credential Request body instead would be ignored by a conforming issuer ("the Credential Issuer MUST ignore any unrecognized parameters"), which is the worst possible failure here: the credential comes back carrying everything and nothing says why.

That places two constraints on the pane, and both are visible in it:

* **A scope cannot carry it, and that is the trap this pane exists inside.** Step 1's *Ask for the credential with* select defaults to `scope`, and a scope request has nowhere to put a claims member — so a selection made on the default route travels nowhere, the issuer returns everything it is configured to issue, and the whole thing reads as *the issuer ignoring the request*. That is exactly how it was first reported, one day after it shipped, and the fault was entirely on this side: the pane said "9 of 10 advertised claims will be asked for" while the authorization request carried none, and the only warning was a sentence appended to the **hand-off pane's** note, which is not where anybody looks. So the verdict now lives in the claims pane itself — a `vc-bad` status reading *This selection will NOT be sent*, naming both halves of the reason, with an **Ask with authorization_details** button beside it that flips the select in one click. `claimsCannotTravelOnAScope()` in `tests/sd_jwt_vc_issuance.js` holds it, checks that the authorization request really carries nothing in that state, and is mutation-tested against forcing the verdict back to "deliverable". The lesson generalises past this pane: a control whose effect depends on a setting **somewhere else on the page** has to report on that setting where the control is. **That notice failed a second time on 2026-08-19, and the default moved instead.** The verdict renders into `vc_claims_status`, a span at the end of the *Select All* / *Select None* button row, in the pane you have just finished using, about a select further up the page — so it reads as a caption rather than a stop sign, and the second reader missed it exactly as the first had. A notice that has failed twice at its only job is not made to work by writing it a third time. So `defaultRequestMechanism()` in `vc_issuance_1.js` now offers **authorization_details** whenever the chosen configuration advertises claims, and the note under the select says the page chose it rather than the user. Four things bound that: a STORED choice still wins (this fills in a blank, it does not overrule an answer), a configuration advertising **no** claims still defaults to scope so the plain flow is byte-for-byte what it was, the default is never written to storage — storing it would freeze today's answer onto a page whose credential configuration changes under it — and, added the same day after it broke the suite, **the authorization server has to be able to redeem the request**. RFC 9396 section 10 has the server publish `authorization_details_types_supported`; the mock issuer's own AS advertises `openid_credential` and Keycloak's RFC 8414 document omits the member altogether. Keycloak accepts the authorization request and issues a code, then refuses it at the **Token Request** with `invalid_authorization_details` (*"Unsupported type 'openid_credential' … Supported values: []"*), which stopped the workflow on `oauth2_oidc_2.html` and failed the Keycloak leg of `tests/sd_jwt_vc_issuance.js` — a timeout waiting for step 2, naming neither the mechanism nor the parameter. So `asAcceptsAuthorizationDetails()` gates the flip: a document not yet retrieved is **unknown** and the credential decides (which is what the pane reports), a document in hand that does not name `openid_credential` keeps **scope**, and the note under the select says authorization_details would have been the default and why it is not. It is re-decided from `updateHandoffSummary()` rather than only when the claims pane is built, because the two documents are retrieved in that order and the AS one arrives last. `authorizationDetailsIsTheDefault()` in `tests/sd_jwt_vc_issuance.js` holds all three, and is mutation-tested against forcing the default back to scope. The `vc-bad` verdict and its button stay, for the reader who chooses scope deliberately.
* **The pre-authorized code flow has no authorization request at all**, so H.2 / H.3 would have nowhere to put it. Section 6.1.1 allows `authorization_details` in the **Token Request** in both flows, and that is where step 2 puts it — but only when the pane asks for a strict subset. That condition is not squeamishness: introducing the parameter changes nothing about the claims when everything is selected, and it changes a great deal about the *request*, because a token response that grants `credential_identifiers` forbids `credential_configuration_id` in the Credential Request (section 8.2). So the default flow is byte-for-byte what it was, and asking for fewer claims switches those two things together.

Three decisions inside the pane that are easy to get wrong the other way:

* **What is stored is which claims are EXCLUDED** (`sdjwtvc_requested_claims`, one entry per credential configuration in `client/src/vci_claims.js`). Storing the included set would make "all checked" depend on a list written at some point in the past: a claim the issuer starts advertising tomorrow would arrive **unchecked** for anybody who had ever touched the pane, and nothing on screen would say why the wallet stopped asking for it.
* **Everything checked sends no `claims` member.** Asking for all of them is exactly what omitting it means, and the pane says so — a note reading "10 of 10 requested" would describe a member that is not there. Nothing checked sends none either, because Appendix A.1 requires a **non-empty** array: a wallet cannot ask for a credential with no claims, and the pane says that rather than sending `[]` for the issuer to refuse.
* **A row the issuer marks `mandatory` stays checkable.** In the *metadata* `mandatory` means the issuer includes the claim whether or not it was asked for (Appendix A.2), so unchecking it changes nothing — but this is a debugger, and being able to send that request is how you find out whether an issuer means it. The row says what will happen instead of preventing it. Note the two `mandatory`s are different statements: the one a *wallet* sends (A.1) means it will refuse a credential lacking the claim, which is a refusal this workflow does not make, so nothing here ever sends it.

**Step 2 describes what was ASKED, not what was ticked**, for the same reason: its approval pane reads the claims out of the token response's granted `authorization_details` (RFC 9396 section 7), or — before a pre-authorized Token Request has been sent — out of the request it is about to make. Reading step 1's stored selection instead is what made that pane agree with the lie above; the wire cannot.

The mock issuer honours the selection end to end — the authorization endpoint validates the paths against what it advertises, the granted details ride inside the access token, and the credential endpoint builds only the claims that were asked for — and refuses an unadvertised path, a repeated claim (Appendix A.3) and a malformed pointer with `invalid_authorization_details`. `claimsSelection()` and `preAuthorizedClaimsRequest()` in `tests/sd_jwt_vc_issuance.js` follow one selection from the pane through the authorization request, the token response and into the credential's Disclosures, and read what the issuer advertises **off the wire** rather than assuming it: which claims that mock carries is `/admin/vc` configuration and it survives between tests. Both are mutation-tested — dropping the `claims` member from the client and dropping the filter from the issuer are each caught, the second by a message naming the claim that should not have been there.

## Step 0 has to fit on one screen

`vc-issuance-0.html` is a chooser, and a chooser that scrolls cannot do its job — you cannot compare four options by scrolling between them. It did not start that way: four full-width cards stacked in a 1100px column came to **757px of a 1450px page against a 839px viewport** (what a 1512x982 display leaves after the browser's chrome), while all the horizontal space beyond the cards sat empty. Everything the page offers now ends **795px** in, 44px above the fold — it was 808px until the shared VC Tools pane grew a second tool, which is the story at the end of this section.

Two changes got it there, and the split matters. `.vc-usecases` is a **grid** — `repeat(auto-fit, minmax(400px, 1fr))`, so two readable columns in the container and one on a narrow screen with no breakpoint — which is what uses the horizontal room. And the rest is a denser vertical rhythm **scoped to `.vc-fit`** on this page's container: the return link rides on the title's line, the intro drops the 1100px reading cap (a wider paragraph is fewer lines, and here height is the scarce thing), and the card padding, inner gaps and pane legend are each trimmed a few pixels. Scoped, because the other eight workflow pages are meant to be read top to bottom and may legitimately scroll — tightening `.vc-title` globally would be a decision about all of them.

Measurement notes, both of which flatter the result if got wrong: `align-items: start` on the grid, or every card in a row stretches to the tallest and the grid quietly gives the height back; and `setRect()` sets the **outer** window height, so the window is opened at 982 to get 839 inside it — measuring the window rather than the viewport overstates the space by ~143px, and headless has no toolbar to correct for.

`chooserFitsOnOneScreen()` in `tests/sd_jwt_vc_issuance.js` defends all of it: a grid rather than one card per row, columns still at least 380px wide (squeezing in more columns buys height only by making every card taller — measured: four across saved just 46px), everything above the fold, and no sideways scroll gained in exchange. Run against the pre-change build it reports "still one card per row; below the fold by 397px".

**The pane that breaks this page is the one that belongs to no step.** The shared **VC Tools** pane (`partials/vc_tools.html`) sits at the foot of all nine workflow pages, and it grows: it gained a second tool on 2026-08-17 (the Certificate Authority & X.509 page), which put the page at **871px against the 839px viewport** and failed that check by 32px — a page nobody edited, broken by a partial two directories away. Note what it does *not* look like: the assertion names step 0's last pane, so the first thing it suggests is the chooser, which was fine.

The 32px came back from height that was never content, and the page now ends at **795px, 44px above the fold** — deliberately more than one tools row, so the next tool does not repeat this:

| Reclaimed | How | Worth |
|---|---|---|
| The pane legend's line box | `.vc-fit .dbg-legend` had its padding trimmed already, leaving one 14px word in a 40px line box | 23px |
| The second tool's description | Shortened to roughly the DID tool's length — this table's row is as tall as its longest cell | 19px |
| The title's line box | 24.5px of text in a 40px line box | 9px |
| The tools rows' leading | `.vc-fit #pane_vc_tools td` at `line-height: 1.3`; 12.6px note text does not need 20px lines | 3px now, ~11px per future row |
| Doubled whitespace | The step row's bottom margin and the card grid's top margin were both spent on the same gap | 12px |

So a third tool costs about **33px** of the 44 remaining, and a fourth needs another decision — the obvious next one being that this pane starts collapsed on `.vc-fit`, since its legend already toggles it. The trims are all scoped to `.vc-fit` (step 0 and step 1); only the shortened description is shared, and it is shorter on every page for the same reason. Checked against `stepOneFitsInOneRow()` as well, because that page carries the same class: its four metadata panes each lose the same 21px of legend, stay on one row, and the populated row measures 772px against its 1100px ceiling.

One thing it does **not** require is the footer above the fold: that is 200px of shared site furniture on every page in the project, so demanding it would be a constraint on the footer rather than on this page. Related and pre-existing: every VC workflow page overflows sideways by exactly 182px below about 1200px of width — the five-item steps row's floor, present on untouched pages too and absent from `oauth2_oidc_1.html` and the landing page.

## The VC Issuance workflow, step by step

Issue a **Selective Disclosure JWT Verifiable Credential** — [SD-JWT, RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html) — from a Credential Issuer using [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) (OID4VCI). The workflow plays the wallet's part across five pages — choose a use case, discover the issuer, authorize and approve, inspect the credential, and refresh it — and deliberately **reuses the OIDC Authorization Code flow already implemented on `oauth2_oidc_1.html` / `oauth2_oidc_2.html`** to authorize the issuance, exactly as OID4VCI intends. It is reached from its own card on the landing page.

### Step 0 — Choose a use case (`vc-issuance-0.html`)
A credential reaches a wallet in more than one way, and OID4VCI's [Appendix H](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-use-cases) names them. They are not different protocols — they differ in **who starts**, **how the wallet learns what is on offer**, and **which grant authorizes it** — so the choice is made once, here, and the rest of the workflow follows it. Each is a card describing what it is and what it does on the wire; the two that are not implemented yet are listed anyway, plainly marked, because knowing what is coming is more useful than a shorter list.

| | Use case | Who starts | On the wire |
|---|---|---|---|
| **H.6** | Wallet-initiated | the wallet | issuer metadata by URL → Authorization Code + PKCE → Credential Request |
| **H.1** | Credential Offer, same device | the issuer | Credential Offer (by value or by reference) → `issuer_state` on the authorization request → Credential Request |
| **H.2** | Credential Offer, cross device | the issuer | offer by QR code → pre-authorized code + `tx_code` → Token Request → Credential Request (no authorization request at all) |
| **H.3** | Credential Offer, cross device & deferred | the issuer | the same, and then a `202` Credential Response carrying a `transaction_id`, collected from the Deferred Credential Endpoint |

Every page of the workflow opens with the same **row of links to all five steps** (with the current one marked and
the finished ones ticked off), so you can move between them directly rather than retracing the flow, and carries a
badge saying which use case is running, with a link back here. Changing it discards any Credential Offer in hand but keeps the issuer and client settings already configured.

**H.2 and H.3 in this workflow**: the issuer displays a **QR code** on its own screen (the mock's is at
`<credential issuer>/issuer/offer?mode=cross-device`, or `?mode=deferred`) together with a **Transaction Code**
that is deliberately *not* in the offer — it reaches the End-User by another channel, which is what makes a QR
code anyone can photograph safe to display. Because the wallet is on the other device, nothing navigates it
here: step 1's **Receive a Credential Offer** pane takes whatever the QR code encodes (an
`openid-credential-offer://` URI, an `https://` link carrying the same parameters, or the bare JSON).

The offer carries a `pre-authorized_code` instead of an `issuer_state`, so **there is no authorization request
and nobody is sent to a login page** — the End-User was identified by the issuer beforehand. Step 2 grows a
**Token Request** pane: the assembled call, a field for the Transaction Code, and the token endpoint's answer.
The wallet refuses to send without the code; the issuer refuses a wrong one; the code is single use.

For **H.3** the Credential Response is `202` with a `transaction_id` and an `interval` rather than a credential.
A **Deferred Issuance** pane then shows the assembled Deferred Credential Request, every attempt and what came
back, and the wallet keeps asking at the interval the issuer named until the credential arrives — after which
the `transaction_id` stops working, as OID4VCI section 9 requires.

**H.1 in this workflow**: choosing it sends the End-User to the *issuer's* web page (the mock issuer's is at `<credential issuer>/issuer`) rather than into the wallet. Following the offer link there brings them back to step 1 with a **Credential Offer** — passed either by value in `credential_offer` or by reference in `credential_offer_uri`, both of which the page accepts — which names the issuer, the credential configuration on offer, and the `authorization_code` grant with its **`issuer_state`**. The offer is shown in its own pane, the wallet discovers the issuer *and* the authorization server it names without being asked, and the `issuer_state` is carried into the authorization request so the issuer can tie the two halves together. The offer can be discarded, which returns the workflow to wallet-initiated.

### Step 1 — Discover the issuer (`vc-issuance-1.html`)
Four panes, plus a fifth — **Credential Offer** — shown only when an offer brought the End-User here:

1. **Credential Issuer Metadata (OID4VCI)** — retrieve `/.well-known/openid-credential-issuer`, tabulate it (with a note saying which document it is and where it came from), pick one entry of `credential_configurations_supported`, and **Validate Signature** on the document's `signed_metadata` JWT. The issuer's keys are resolved the SD-JWT VC way, from `/.well-known/jwt-vc-issuer` under the credential issuer identifier (or a `jwks_uri` in the document itself); the rest of the check is the same code the Metadata Retrieval pane on `oauth2_oidc_1.html` runs — signature, `iss`, and any signed claim that disagrees with the plain JSON.
2. **Authorization Server Metadata (RFC 8414)** — the same pane as `oauth2_oidc_1.html`'s. Its URL starts on the deployment's configured RFC 8414 endpoint (`rfc8414MetadataUrlDefault`, the mock authorization server the STS service publishes; empty where there is no such service) and is replaced by the server named in the issuer's `authorization_servers` once the issuer metadata is retrieved. It writes to the **same `localStorage` names** `oauth2_oidc_1.html` uses (`discovery_info`, `authorization_endpoint`, `token_endpoint`, the OpenID Provider metadata members, …), so retrieving it here also configures the OAuth2 / OIDC workflow.
3. **Configuration Parameters** — every parameter both documents can define, generated from the shared member lists (`client/src/op_metadata.js` for the OpenID Provider / RFC 8414 members, `client/src/vci_metadata.js` for the credential issuer ones) so the pane cannot drift from them. Each value is overridable; a member the retrieved document omits shows the same grayed-out `-->not defined<--` note as the debugger pane. The OAuth2 / OpenID Provider half shares its storage with the debugger pages; the OID4VCI half is prefixed `vci_`.
4. **Authorize Issuance** — hands off to `oauth2_oidc_1.html?sdjwtvc=1`.

### The OIDC leg (`oauth2_oidc_1.html` → IdP → `oauth2_oidc_2.html`)
The `sdjwtvc=1` query parameter puts the debugger into this workflow: it shows a banner saying so, starts the Authorization Code request with the configuration from step 1, and — once the user has authenticated and `oauth2_oidc_2.html` has exchanged the code for tokens — sends the browser on to step 2. Without the parameter neither page behaves any differently.

### Step 2 — Approve and request (`vc-issuance-2.html`)
Shows the access / ID / refresh tokens the OIDC leg obtained (and the decoded ID token claims), generates an **ES256 holder key pair** in the browser (the private half never leaves it), and asks the user to approve the issuance.

The whole request is assembled **before** the user approves — the page fetches a `c_nonce` from the issuer's Nonce Endpoint and signs a proof of possession (`typ: openid4vci-proof+jwt`, the holder public key in the header, the credential issuer as `aud`) on load — so the nonce, the proof (raw and decoded), the JSON body, and a box showing the **fully assembled call** (method, full URL, headers including the Bearer access token, and body) are all there to read first. Approving sends exactly that; because a `c_nonce` is single use and expires, a proof that has gone stale by then is rebuilt and the request retried once. **Deny** sends nothing and returns to step 1.

### Naming the credential: `scope` or `authorization_details`
OID4VCI has two ways for a wallet to say which credential it wants
([§3.3.4](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) contrasts them), and step 1's
hand-off pane offers both. A **scope** is the simple one. **`authorization_details`** ([RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html))
of type `openid_credential` is the expressive one, and choosing it changes what happens afterwards: the token
response grants `credential_identifiers`, and the Credential Request then **MUST** name one of those and **MUST
NOT** send a `credential_configuration_id`. Step 2 says which of the two it is using and why — that is not a
preference, it follows from what was granted — and the mock issuer refuses all three ways of getting it wrong
(both parameters together, the configuration id after identifiers were granted, and an identifier that was never
granted).

### Batch issuance and an encrypted Credential Response
Step 2's **Credential Request Options** pane offers the two things an issuer's metadata can advertise and a
wallet has to opt into:

- **Keys to bind** — one proof per key, one credential per proof ([§8.3](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)),
  capped at the issuer's `batch_credential_issuance.batch_size`. Step 3 then shows every credential that came
  back, with a picker, and verifies whichever is selected — each is bound to *its own* key.
- **Encrypt the response** — the wallet generates an RSA key, sends the public half as
  `credential_response_encryption`, and the issuer returns a **JWE** (`application/jwt`) instead of JSON, which the
  page decrypts in the browser. The private half is generated non-extractable, so it cannot leave the page.

Both controls are disabled, with the reason stated, against an issuer whose metadata does not advertise the
feature — which is the case for walt.id, and is what the interoperability suite checks.

### Telling the issuer what happened
The Credential Response carries a `notification_id`, and step 3's **Notify the Issuer** pane sends the
[§11](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) Notification Request for it:
the assembled call, one of the three events the spec defines (`credential_accepted`, `credential_failure`,
`credential_deleted`), and the issuer's answer. It is optional for a wallet — an issuer cannot assume it will be
told — so it is a button, not something that happens automatically. The mock issuer validates the id and the
event rather than answering `204` to anything, and records what it was told, so a test can check that the
notification actually landed.

### Step 3 — The credential (`vc-issuance-3.html`)
Takes the returned SD-JWT VC apart the way a verifier would: the Combined Serialization with its `~` separators, the issuer-signed JWT header and payload, and one row per **Disclosure** — salt, claim name, value, and the digest recomputed in the browser (`base64url(SHA-256(the ASCII of the base64url Disclosure))`) and looked up in the JWT's `_sd`. A checks table reports the media type (`dc+sd-jwt`), the algorithm, `vct`, the `cnf` binding to the holder key from step 2, `_sd_alg`, the validity window, whether a Key Binding JWT is present (it is not, at issuance), digest coverage, and the **issuer signature**, verified against the issuer's published JWKS. The last pane shows the claim set a verifier ends up with if every Disclosure is presented.

### Step 4 — Refresh the credential (`vc-issuance-4.html`)
A credential goes stale: its claim values age and its validity window runs out.
[Section 14.5](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html), *Refreshing Issued
Credentials*, gives two mechanisms — get an updated credential from the Credential Endpoint with a valid access
token, **with no End-User interaction at all**, or start the issuance over from step 1, which needs the End-User
and is the only route left once the refresh token has gone too. This step is the first, in the two calls it is
made of:

1. **Refresh the access token** — `grant_type=refresh_token` at the authorization server's Token Endpoint
   ([RFC 6749 §6](https://www.rfc-editor.org/rfc/rfc6749.html#section-6)). Nothing about this call is
   OID4VCI-specific, which is section 14.5's point; the pane shows it assembled, sends it, and says whether the
   refresh token **rotated** — because if it did, the old one is spent. This half is skippable:
   [§14.3](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) allows asking the Credential
   Endpoint again with the token already in hand, and the pre-authorized code grant (H.2/H.3) issues no refresh
   token at all, so the page says so and offers the routes that remain rather than a button that cannot work.
2. **Ask the Credential Endpoint again** — the same Credential Request step 2 makes, built by the same module
   (`client/src/vci_wallet.js`), with a fresh `c_nonce` and a new proof of possession. The wallet chooses whether
   to stay bound to the **holder key the credential already uses** (which is what makes the result a replacement)
   or to bind a new one. An issuer that cannot answer at once may defer this too, so a `202` with a
   `transaction_id` is collected from the Deferred Credential Endpoint — on a button, since nobody is waiting on a
   refresh.

Then the part that is actually interesting: **what changed**. Section 14.5 leaves it to the issuer *"whether to
update both the signature and the claim values, or only the signature"*, and §14.3 permits the same credential
over again, so none of it can be assumed — it is read off the two credentials side by side (`vct`, `iss`, `sub`,
`iat`/`nbf`/`exp`, the bound key, the signature, the Disclosure and digest counts) with a separate comparison of
disclosed claim **values**. Values, because the salts and therefore every Disclosure and digest are new each time
an issuer mints a credential; reporting those as changes would bury the ones that matter. The verdict names which
case it was.

**Credential History.** A credential is not one object over its life, so step 4 carries the counterpart of the
**Token History** pane on `oauth2_oidc_2.html` — and records more than it does: **every attempt**, not only the ones
that worked. One row each, newest first, for every access-token refresh, every Credential Request, every poll of
the Deferred Credential Endpoint and every decision you made about what came back, with the outcome
(`success`, `FAILED` with the refusal, `deferred`, `returned — not kept yet`, `kept`, `discarded`) and what the
issuer actually said. Because "I tried to refresh and it did not work" is the case a debugger is most needed for,
and a pane that shows only successes cannot tell you whether the request was refused, deferred, or never made.
Retrying a stale proof leaves both rows; discarding a credential leaves the attempt on record and takes the
credential away. Every row is numbered in `#` by attempt order; the separate `Gen`
column carries the generation number, which only the **`kept`** rows have, because only those are credentials the
wallet holds and can go back to. The one in hand is marked; every other row says `log only`. The newest **100**
attempts are kept, in a fixed-height scrolling list with a sticky header, so a long log does not push the rest of
the page around. `◀ Older` / `Newer ▶` (and Oldest / Latest, or **Activate** on any generation row) move **backwards and
forwards** through those generations, skipping the log rows, and moving is a real change rather than a highlight: the generation you land on becomes
the credential the wallet holds, **together with the holder key pair it is bound to** — without that private key
the credential could not be presented at all, so each entry keeps its own. That is what makes going *back*
useful: a refresh that turned out worse than what it replaced is a real outcome, and this is how you return to
the credential that was working. A refreshed credential you discarded is not in the list, because it was never
held; the `Source` column distinguishes `issued`, `refreshed` (a fresh access token was obtained first) and
`refreshed (§14.3)` (the token in hand was reused). *Clear History* forgets the generations and leaves the
credential in hand alone.

A credential the issuer has just returned appears in the pane **immediately**, marked *not kept yet* and carrying
its own Keep / Discard buttons: the list reacts to the retrieval, not only to the keeping. Keeping it does not
navigate anywhere — the new generation simply becomes the one in hand, in the pane you were looking at, and
*Verify in step 3* is there when you want the full check.

Nothing is replaced until you say so. Section 14.5 again: *"the Wallet might need to check if it already has a
Credential of the same type and, if necessary, delete the old Credential. Otherwise, the Wallet might end up with
more than one Credential of the same type, without knowing which one is the latest."* So **Replace** promotes the
refreshed credential (keeping the old one, and its holder key, for comparison) and opens step 3 to verify it,
while **Discard** leaves the wallet exactly as it was — including its holder key, which a declined refresh must
never rotate: the credential still in hand needs the private half to be presented at all.

### Interoperability: the same workflow against walt.id

A mock issuer that agrees with us proves only that we agree with ourselves. The
test suite therefore also runs **[walt.id's `issuer-api2`](https://github.com/walt-id/waltid-identity)**
— an independently written OpenID4VCI 1.0 Credential Issuer — as a container
(`waltid/issuer-api2`, configured by `waltid/config/*.conf`), and drives *the
same pages, the same bundles and the same buttons* against it:
`tests/sd_jwt_vc_waltid.js`, covering both implemented use cases (H.6 and H.1,
the offer created through walt.id's own management API exactly as its portal
would create it).

Nothing in the workflow is walt.id-specific. Everything below is a difference in
the **issuer**, and the wallet either copes with it or the test fails:

| What walt.id does | What it means for a wallet |
|---|---|
| Its Credential Issuer Identifier has a **path** (`…/openid4vci`) | The metadata is at `/.well-known/openid-credential-issuer/openid4vci` — [RFC 8414 §3.1](https://www.rfc-editor.org/rfc/rfc8414.html#section-3.1) **inserts** the well-known segment before the path; it is not appended. Both forms are tried, insertion first (`wellKnownCandidates()` in `client/src/metadata_client.js`), and the provenance note says which one answered. |
| It publishes no `authorization_servers` | Per OID4VCI §11.2.3 the Credential Issuer is then its own authorization server, and the wallet must fall back to it. |
| It signs with a **`did:jwk`** | The credential's `iss` is not a URL, so there is no `/.well-known/jwt-vc-issuer` to fetch — but a `did:jwk` *is* the key, base64url-encoded in the identifier, so step 3 resolves it without a network call. Its `kid` is a DID URL whose **fragment** is the JWKS key id, which is why key selection falls back from an exact `kid` match to the fragment and then to trying every published key (a `kid` is a hint for finding the key, not part of the signature). |
| It authenticates the End-User at an **external** OpenID Provider | Its authorization endpoint always redirects there. In this suite that provider is the same Keycloak realm everything else uses, so the run is a genuine three-party issuance — our wallet, walt.id as issuer and authorization server, Keycloak as IdP — and the credential ends up carrying the claims of whoever signed in. |

Those four points are exactly the changes the interoperability work produced;
the mock issuer never exercised any of them, because it agreed with us by
construction.

One thing walt.id does **not** do is CORS: its services install no CORS plugin at all (walt.id's own compose
stack fronts every one of them for that reason), and a browser-based wallet cannot read a response without
`Access-Control-Allow-Origin`. So the container runs behind a small proxy — `waltid/cors-proxy.js`, no
dependencies, run by a stock `node` image — that adds those headers and answers preflights itself, and the
issuer's `baseUrl` names the **proxy**: every URL walt.id publishes has to be one the browser can actually use,
and the proof of possession's `aud` has to be that same identifier, so the proxy cannot merely forward — it has
to *be* the issuer's address. The public demo at `issuer2.demo.walt.id` shows the same
thing from the other side: its edge sends `Access-Control-Allow-Methods: OPTIONS` only, so a browser wallet can
read its metadata and never POST to it.

walt.id also publishes no `authorization_details_types_supported`, `notification_endpoint`,
`batch_credential_issuance` or `credential_response_encryption`. All four are OPTIONAL, so that is not a defect —
but it is the situation a wallet most easily gets wrong, by assuming a feature is there or offering the End-User
something the issuer cannot do. The interoperability suite therefore checks **capability detection**: every
omitted member is marked `-->not defined<--`, the batch and encryption controls are disabled with the reason
given, step 3 offers no notification, choosing `authorization_details` warns that this server does not advertise
it — and the issuance still completes by the route the issuer does support. The mock covers the mechanics of each
feature; only a second implementation can cover behaving correctly when the feature is absent.

Deferred issuance (H.3) is the one use case walt.id cannot exercise: `issuer-api2` publishes no
`deferred_credential_endpoint` and issues everything immediately, which OID4VCI permits — section 9 makes the
endpoint OPTIONAL. The walt.id suite therefore checks that the wallet *reads that capability off the metadata*
rather than assuming it, and the mock issuer covers the deferred mechanics themselves. That division is what
having both stacks is for: the mock exercises what real deployments leave out.

The issuer's signing key is generated fresh per run (`generateWaltidIssuerKey`
in `common/common.sh`) and passed in through the environment, so no private key
is committed here — the same rule the SAML SP key pair follows. The container is
part of `docker-compose-run-tests.yml` and `local-tests.yml`; the job is skipped
when `WALTID_ISSUER_URL` is unset, so a run without that container still passes.

### Mock Credential Issuer for testing
The `sts/` service also hosts a **bare-minimum OID4VCI Credential Issuer**: `/.well-known/openid-credential-issuer` (with `signed_metadata` and one `dc+sd-jwt` credential configuration), `/.well-known/jwt-vc-issuer` for key resolution, `POST /oid4vci/nonce`, and `POST /oid4vci/credential`. It requires a Bearer token, and properly verifies the wallet's proof of possession (typ, algorithm, audience, single-use nonce, and the signature against the key in the proof's own header) before minting an SD-JWT VC per RFC 9901 — disclosures with 128-bit salts, `_sd` digests plus a decoy, `_sd_alg`, `cnf.jwk`, and the required trailing `~`. It cannot validate an access token issued by a separate authorization server, and does not pretend to. It also implements **`authorization_details`** of type `openid_credential` (advertised as `authorization_details_types_supported`, granting `credential_identifiers` in the token response and enforcing the mutual exclusion at the credential endpoint), **batch issuance** (several proofs, one credential per proof, `batch_size` enforced — and one `c_nonce` per *request*, not per proof), **response encryption** (RSA-OAEP-256 to the wallet's key, refusing any algorithm it does not perform), a **Notification Endpoint** that validates the `notification_id` and the event and remembers what it was told, the **pre-authorized code grant** (`tx_code` required, checked, and single use), and a **Deferred Credential Endpoint** — `202` with a `transaction_id` for a few seconds, then the credential, then `invalid_transaction_id` for anyone who asks again. For H.1 it also hosts the **issuer's side of a Credential Offer**: a web page at `/issuer` with the offer links, `GET /issuer/offer` which builds the offer and sends the End-User to the wallet (`OID4VCI_WALLET_URL`) with it — by value or, with `?by=reference`, as a `credential_offer_uri` pointing at `GET /oid4vci/credential-offer/:id` — and it remembers each `issuer_state` so the authorization endpoint can recognise a request as belonging to an offer it made. For the cross-device use cases it shows a real **QR code** and the Transaction Code on its own page (`/issuer/offer?mode=cross-device|deferred`). By default the metadata advertises the mock **itself** as its authorization server, which is what lets an issuer-initiated offer be walked end to end with no identity provider at all; `OID4VCI_AUTHORIZATION_SERVER` points it at a real one instead. The end-to-end test is `tests/sd_jwt_vc_issuance.js`.
