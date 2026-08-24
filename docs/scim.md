# SCIM — the sixteenth protocol, and the first one whose purpose is to WRITE

Read this before touching `client/public/scim.html`, `client/src/scim*.js`,
`api/scim_proxy.js`, `POST /scim`, or any of the three `tests/scim_*.js`.

RFC 7642 (the requirements), RFC 7643 (the schema) and RFC 7644 (the protocol).
The server this workflow is built against is the mock STS's `/scim/v2`, whose
own notes are in `docs/mock-sts.md` and in `scim.js`, `scim_auth.js` and
`scim_map.js` inside that submodule.

## Why this workflow is shaped differently from the other fifteen

Every other protocol family in this debugger asks a question about somebody who
is already there: issue this person a token, tell me who signed in, seal this
ticket, verify this credential. SCIM is the one that **puts somebody there** —
and takes them out again. That single fact drives three decisions that make this
page look unlike its neighbours.

**A single call is rarely the interesting thing.** What somebody debugging a
provisioning integration needs to know is what happens when a hundred calls run
in order against a real directory: whether the group created in step 4 contains
the users created in steps 1–3, whether the delete in step 90 really removed
anything, whether the twelfth `PATCH` landed on the value it named. So the page
has a **scenario harness** beside the ordinary one-endpoint-at-a-time debugger,
and the harness is the larger half.

**A scenario is a plan with an expectation on every step.** Not a script that
runs and produces a log. `scim_scenarios.js` builds a list of steps each
carrying `expect.status` and, where it matters, `expect.scimType`; the runner
JUDGES what came back against that. This is what makes the negative scenarios
work at all: a 409 `uniqueness` on a duplicate `userName` is a **pass**, and a
201 is a **failure**. A runner that recorded what came back rather than judging
it would have those exactly backwards, and a client's error handling is the half
that is never exercised — because a permissive server is hard to make say no.

**The page carries a warning banner, and it means it.** These endpoints create
and delete accounts and there is no undo.

## The page's layout, and the six decisions behind it

Read this before moving a pane, because four of the six are load-bearing
rather than cosmetic and one of them is a bug fix that looks like a style
change.

**The top row is Discovery and Configuration Parameters, side by side.**
Neither is a *step* — between them they hold every setting the panes below read
and the documents those settings are read out of — and stacked they put the
buttons somebody came here to press (Send, Run) two screens down.
`.scim-topgrid` is a two-column grid using `minmax(0, 1fr)` and NOT `1fr`: a
grid item's automatic minimum size is its min-content size, so a column holding
a percent-encoded DN grows the track instead of scrolling inside it.
`tests/scim_page.js` asserts the row by GEOMETRY, because a grid that has
silently fallen back to one column still has every class it had.

> **There is no Connection pane and no Authentication pane, and their absence
> is the design.** Both were built beside the configuration table and both were
> spellings of rows already in it — a service root in two places is a service
> root that can disagree with itself, and the table's own job is to be the one
> place a setting lives. So the table now **owns** those controls:
> `configInput()` gives an owned row the field's own id, which is why
> `val('scim_auth_scheme')` reads a cell of that table and why `REMEMBERED`
> keeps working unchanged. What could not be a table row went with them but not
> into it — a password, a generated signing key, a minted proof are not values
> that can be compared against a document — and those sit in the **Credential**
> block directly under the table, where only the blocks the selected scheme
> uses are ever on screen. `tests/scim_page.js` asserts both halves: that each
> named control is INSIDE `#scim_config`, and that none of `pane_connection`,
> `pane_auth`, `scim_call_browser`, `scim_call_backend` or `btn_scim_probe_auth`
> is anywhere on the page.

> **The service root is the one exception, and it is not the Connection pane
> coming back.** `baseUrl`'s box is on the **Discovery** line, with the three
> buttons that compose paths onto it: a URL a screen away from the buttons that
> fetch from it was the arrangement this page was awkward about. What makes
> that different from the pane that was deleted is that there is still exactly
> one box. The `baseUrl` row is a **mirror** — the same kind of row the
> generator's and the scenario planner's fields already had — so an edit in
> either place is a write to the one element and a read back into the other,
> where the old pane held a second, independent field. The table's control is
> `scim_cfg_baseUrl`; `val('scim_base_url')` reads the Discovery box, and
> `REMEMBERED` keeps working unchanged because it is keyed by element id
> wherever the element sits. `wireBaseUrl()` moved with it: it is called once
> from `onload()` now rather than by `configInput()` on every rebuild, because
> nothing rebuilds that box any more.
> `theServiceRootSitsWithItsButtons()` in `tests/scim_page.js` pins all three
> halves — one element, inside `#pane_discovery`, and sharing one line with all
> three buttons, the last asserted by GEOMETRY because `.scim-buttons` wraps by
> default and a wrapped row keeps every class it had.

**Every block of prose longer than a line is inside a `details`.** The
explanations are why this workflow is worth using — what a 409 on a duplicate
`userName` means, why a wrong Digest hash reads exactly like a wrong password —
so they are folded rather than cut, and the live readouts (what this operation
needs, how the run went, how the call was made) are folded **open**. The one
block that must never fold is the sentence saying these endpoints create and
delete accounts; `tests/scim_page.js` strips every `details` out of the warning
box and asserts that sentence is still there. A `show()` on a folded note has
to hide the **fold** and not the paragraph inside it, or the reader is left a
summary that opens onto nothing: the convention is that the fold's id is the
paragraph's with `_fold` on the end, and `show()` looks for it first.

**Every field carries a hover tooltip, and that is what the prose used to be.**
The house pattern, `<div class="tooltip scim-tip"><label…><span
class="tooltiptext">…</span></div>`, restyled in `scim.css` for a form: the
shared `.tooltip` is 120px wide, centred over its own middle and dotted-
underlined, because it was written for a hoverable word in a sentence. Buttons
keep a native `title` instead — a hover tooltip over the thing you are about to
click is the interception hazard below.

> **`pointer-events: none` on `.tooltiptext` is not decoration.** bootstrap
> hides it with `visibility: hidden` and not `display: none`, so the span still
> occupies layout and the browser reports it as the topmost element at a nearby
> control's position — which Selenium raises as `element click intercepted: …
> <span class="tooltiptext">`, at coordinates that look perfectly correct in a
> screenshot. The rule is in `css/common.css` and again in `css/scim.css`, and
> `tests/scim_page.js` asserts it in the browser rather than trusting either
> copy: it makes EVERY tooltip visible at once and then asks the browser what
> is on top of each control. A test that merely clicked the buttons would pass
> whether or not the rule were there — a tooltip is only over a control while
> something is hovering it — which is the difference between testing the fix
> and testing the weather. Mutating the rule away fails both halves, one of
> them with a real `element click intercepted`.

**The Discovery pane has two tabs and the second one is not a fallback.** A
discovery document is read for two different reasons and one rendering cannot
serve both: nine times in ten what is wanted is "where do Users live and does
this server do PATCH", and the tenth time it is "show me exactly what it said",
because somebody is arguing about it. So *Described* is a table and *Document*
is the bytes. Both are kept: the table is a READING of the document, and a
disagreement between the two is a defect in this page that hiding the original
would make undiscoverable. ResourceTypes and Schemas have described views too
as of this change — before it, only the ServiceProviderConfig did, and finding
an endpoint in a nested ListResponse was a scroll and a squint.

**Every readout is a `textarea` and this fixed a real overflow.** They used to
be `pre` elements with `overflow: auto` and a `max-height`, which is the obvious
shape and does not work inside a `fieldset`. A pre's min-content width is its
longest line; a SCIM response is full of percent-encoded DNs, `Location` URLs
and base64 certificates with no space in them; and a fieldset carries
`min-inline-size: min-content` in the UA stylesheet. So the PANE was made wide
enough to avoid the overflow and the `overflow: auto` never scrolled anything.
Measured on the page before the change: one long id took the Exchange pane to
**7511px** and the document to **7627px** in a 1400px viewport. A textarea has
an intrinsic size content cannot change, scrolls both ways by construction, is
`resize: vertical`, and carries an **Expand** button that opens it to a working
height and closes it again.

Both halves are needed — `.scim-pane` also carries `min-width: 0` /
`min-inline-size: 0`, without which every `max-width`, `overflow` and
`word-break` inside it is powerless.

Section 8's existing "the page does not scroll sideways" check could not see any
of this, and that is worth keeping in mind: by the time it runs, the browser
test has deleted everything it created and every readout holds a short body or
nothing. A geometry check that only ever measures an empty box measures
nothing, so the new one **plants** the pathological value first.

**The panes collapse, and one switch does all of them.** The chrome is the
shared `.dbg-*` set every other workflow here uses (`css/debugger.css`, which
this page now links ahead of its own sheet): each pane is a
`div.scim-pane.dbg-pane` holding a `.dbg-legend` title and the `fieldset` that
title collapses, with a `.dbg-controls` toggle at the top of the page. Three
things about it are load-bearing.

The legend and the fieldset are paired **by convention** — `x_expand_button`
drives `x_fieldset` — and wired in `wirePanes()`, not by an inline
`onclick="…togglePane('x_fieldset')"`. Several workflows here spell it inline,
which repeats the id in two places and fails *silently* when the two drift: a
title that does nothing at all, indistinguishable from a title nobody thought
to make clickable. Here a drifted pair is a `log.warn`, and section 9 asserts
the browser console is clean, so it is a failed test rather than a shrug.

`setAllPanes()` **discovers** the fieldsets (`.dbg-pane fieldset`) rather than
holding a list of ids. The workflows that keep a list each have one a new pane
has to be remembered into, and the only symptom of forgetting is one pane the
switch skips.

And the `style="display: block"` in the markup is not decoration: the
collapse/expand triangle is drawn by
`.dbg-pane:has(fieldset[style*="display: none"]) .dbg-legend::before`, which
reads the **inline** style. A pane shipped with no inline `display` would show
an expanded triangle over a pane the toggle had never touched.

**The prose is folded rather than cut, the way the Kerberos pages fold theirs.**
Ten `details.scim-more` blocks, styled on `.krb-more`. The explanations are the
reason this workflow is worth using — what a 409 on a duplicate `userName`
means, why a wrong Digest hash reads exactly like a wrong password — so none of
them was deleted to buy vertical space. Two of the folds are the whole content
of an authentication row (cookie, client certificate), so their **summary
carries the headline sentence** and only the elaboration folds away; a row that
collapsed to nothing reads as a scheme this page had not implemented.

> **The sentence saying these endpoints delete accounts is NOT inside a fold.**
> It stays in the warning box with only the elaboration folded beneath it,
> because a safety notice that can be collapsed out of sight is a safety notice
> somebody will not have read. `tests/scim_page.js` section 8d asserts it by
> reading the warning's text with its `details` **subtracted** — a check
> written against the whole box would pass with the sentence moved inside.

Note also that the `fieldset` that WAS the pane is now *inside* it, so the
`min-width: 0` / `min-inline-size: 0` rule that stops one unbreakable token
sizing the pane to its longest line had to follow it inwards
(`.scim-pane > fieldset`). Without that the Exchange pane goes straight back to
7511px, which is the defect section 7b plants a value to catch.

**The Discovery pane's described tables scroll sideways.** They are rendered
into the third column of the top row — about 381px at a 1400px viewport — and
their last column is *prose*. With a name column of 11em and a value column of
12em ahead of it, that column got a strip a few words wide and one row grew to
**247px**, running down past the pane and past the two beside it. Wrapping
harder cannot fix that; there is no width at which prose fits in 150px. So
`.scim-described-scroll` is `overflow-x: auto`, the tables keep a `min-width`
of 46em, and the two fixed columns give some of themselves back (9.5em and
10.5em) so a readable strip of the note is on screen before anybody scrolls.
The same row now measures **87px**. `min-width` and not `width`: on a wide
viewport, or in the single-column fallback under 1100px, the tables take the
room they are given and nothing scrolls at all.

## The Exchange pane shows the headers, in wire form

`Name: value`, one per line, and not a JSON dump. What a reader compares these
against is a header they read in an RFC, a `curl -v` transcript or another
server's log, and none of those is quoted, braced or comma-separated. A repeated
header becomes one line each — `Set-Cookie` is the one that matters, and RFC
7230 section 3.2.2 says in as many words that it may not be joined with a comma,
because a cookie's own `expires` attribute contains one. (fetch's `Headers` has
already joined those before this page can see them; the api hands them over as
an array and they are unrolled.)

Request and response sit **side by side**, because they are read against each
other: a header sent and a header that came back, a body posted and the resource
it produced. Stacked, the pair is a screen apart and the comparison is done from
memory.

One asymmetry is deliberate and the pane says so. On a browser-direct call the
request headers shown are **the ones this page set** — the browser adds `Host`,
`Origin`, `User-Agent`, `Referer` and `Content-Length` of its own and will not
say what they were. Through the api they are corrected after the answer arrives
from `http_exchange.request.headers`, which is what axios actually sent.

## The Configuration Parameters pane

Every setting this workflow has, in one table, **with the source of each**. That
last column is the reason the pane exists: the value of a parameter is already
visible in the field it belongs to, and what is not visible anywhere else is
whether it is there because somebody typed it or because a server said so in a
discovery document — and those two behave identically right up until the server
changes its mind, after which exactly one of them is stale and nothing on screen
says which.

Three kinds of row, and the difference between the first two is the whole
design:

* an **owned** field (`field`). The row *is* the control: `configInput()` gives
  it the field's own id, so `scim_auth_scheme` and `scim_auth_username` are
  elements of this table and of nothing else. That is a change from the first cut, where
  the row mirrored a field in a Connection or an Authentication pane — one
  setting spelled twice, in two panes that could disagree about it. There is now
  nothing to mirror. Two consequences worth knowing before editing
  `renderConfig()`: it **carries the owned values across a rebuild** (it reads
  them out of the DOM, and every discovery tears the table down) and it **puts
  the focus back**, because the automatic probe below rebuilds the table from an
  event the reader did not cause;
* a **discovered** parameter, which lives here and nowhere else.
  `discoveredValues` keeps what the document said and `configValues` keeps what
  is in force, so an override is a **visible difference** between the two —
  tinted, with "the server said: …" beside it — rather than a lost original.
  **Restore discovered values** has something to restore to;
* a **mirror** of a field that is still in a pane of its own (`field` *without*
  `owns`): the generator's four, the scenario planner's three, and the **service
  root**, whose box is on the Discovery line. The field is the value and the row
  reads and writes it in both directions, so there is still one element per
  setting — which is what separates a mirror from the Connection pane that was
  deleted, where the second control was a second *value*;
* a **dynamic** row, which exists only because a server said so. Every
  resource type, every authentication scheme, every schema and every attribute
  inside every schema is one. See *The three documents configure the workflow*
  below;
* a **heading**, which is a row of the table and not a parameter;
* a **block**, which is not a parameter at all: a row spanning the whole table
  into which an element authored in `scim.html` is **moved**. There is one, and
  it is the access token — see below.

**A row's control is a text box, a `select` or a RADIO PAIR (`kind`).** The pair
is `callPath`, and it is labelled **FrontEnd / BackEnd** to match the way every
other workflow in this debugger asks the same question — `introspection.html`,
`userinfo.html` and `oauth2_oidc_2.html` all offer "Initiate … From front or
backend" as two radios. The values underneath are still `browser` and `api`,
because those are what `callVia()` returns and what `configValues.callPath`
remembers; the labels changed and the mechanism did not.

Two radios are two elements, and everything that touches a configuration control
expects one — `refreshConfigValues()` assigns `.value`,
`refreshCallPathControls()` assigns `.disabled`, `saveConfig()` reads `.value`,
and `tests/scim_page.js` drives the row by setting `.value` on the id and
dispatching a change. So `radioPair()` wraps the pair in a `span` that carries
the row's id and **defines `value` and `disabled` over the radios inside it**. A
span has neither property of its own, nothing is shadowed, the one-element-per-id
invariant the table rests on is untouched, and not one caller or test needed to
learn which rows are radios. There is also only one change listener: `change`
bubbles, so the one on the wrapper hears a click on a radio (`event.target` is
the radio) and a scripted `.value =` plus dispatch (`event.target` is the
wrapper) alike, and both answer with the same value.

Adopting a newly-read value tests against the PREVIOUS discovered value and not
against emptiness: a row nobody has touched follows the server forever, and a
row somebody has edited keeps their edit even when a later read says something
else. Adopting over an edit would silently undo it, on a button press that says
"read the documents".

**No credential is a ROW of that table, and it is not an oversight to be tidied
up later — the panes went away and this rule did not.** The password is never
written anywhere and the HOBA private key is generated per session and never
stored; both are in the **Credential block below the table**, which is part of
the same pane and is not part of the table. What decides whether a thing is a
row here is whether it is a value that can be compared against a document, and
a minted proof never can be. `tests/scim_page.js` checks this by VALUE — it
types a distinctive credential into the Credential block and searches the whole
table for it — because a name-based check would pass a table with a row called
`secret`, and would also trip over `changePassword.supported`, which is a
ServiceProviderConfig capability that contains the word "password".

**The access token is the exception, and it is a placement rather than a hole
in any of that.** It is not a row: it is a `block` — the same textarea, the
same opt-in checkbox and the button that goes and gets one, MOVED into the
Authentication section directly under the `authScheme` select. It is there
because it is the only credential on this page a reader has to leave the page
to obtain, and a button that launches the OAuth2 / OIDC workflow is no use a
screen away from the select that decides whether a token is sent at all.
Nothing about the storage changed: `saveState()` is still the only thing that
writes it and the opt-in still ships clear.

> **A block is MOVED and never copied.** `renderConfig()` takes the node out of
> the page and appends it to the row it builds, which is the same rule `owns`
> exists to keep, arrived at from the other end: copying the markup would put
> two `scim_auth_token` textareas on the page, and `getElementById` answers
> with whichever comes first in document order — so the field the reader types
> in would silently stop being the field the request is composed from. The
> table is rebuilt whole on every discovery, so the node is held by reference
> across `innerHTML = ''` and re-appended with its value and its listeners
> intact. `tests/scim_page.js` counts the elements per id for exactly this
> reason, and asserts the row's position between the Authentication heading
> and the one after it.

### The scheme list is read off the server, and nothing asks for it

RFC 7644 section 2 defines no SCIM credential of its own. It names six ways of
doing it and makes exactly ONE normative requirement of a server: that a 401 say
in `WWW-Authenticate` which of them it accepts. There is nothing in that for a
reader to decide, so **there is no probe button**: a change to the service root
schedules one unauthenticated request, and the `authScheme` row is ordered by
what came back, with the offered schemes marked `— offered` and moved to the
top. `challengeSchemes`, `challengeRealm` and `digestAlgorithms` are filled from
the same answer, which is why they are `discovered` rows beside the three
documents.

Five things about that probe are load-bearing:

* **It prefers the api, whatever `callPath` says.** The whole content of the
  request is a *response header*, and CORS hands a browser-direct call only the
  seven simple ones — `WWW-Authenticate` is not among them. From the browser a
  probe of a cross-origin SCIM server therefore reads an empty challenge from a
  server that sent a perfectly good one. `probeVia()` takes the api when there
  is one that answered `GET /scim/limits`; the reader's `callPath` still decides
  every request they actually asked for.
* **It is quiet.** `sendOnce(request, auth, {quiet: true})` keeps it out of the
  Exchange pane. The request somebody is looking at is the one *they* sent, and
  having it replaced by a probe they did not ask for makes the page look like it
  is sending things at random.
* **It is debounced and keyed by URL.** `change` on a field fires on every blur,
  so a Tab through the table would otherwise send one request per field, and
  re-entering the field without editing it would send another.
* **Every scheme stays selectable.** Filtering the list to the challenge would
  be wrong twice over: a server that accepts Bearer without advertising it is
  common enough to be why somebody opened this page, and a session cookie and a
  TLS client certificate can never appear in a challenge at all. Anonymous stays
  at the top of the list — it is not something a server offers, it is sending
  nothing, and it is what the probe itself uses.
* **A 401 with no readable challenge is reported as this call path, not as that
  server.** Saying "this server named no scheme" out of a limit of the browser's
  header access would be a claim about somebody else's software; the status line
  names the CORS restriction and points at the `callPath` row instead.

`tests/scim_page.js` section 3b asserts all of it, including the case the
ordering can only get wrong once: pointing the service root at a port that
answers nothing must **empty** the challenge rows, because a scheme list ordered
by what a *different* server said is wrong in a way nothing on screen would
contradict. Because the probe starts by itself, the test waits on
`scim.autoProbeState()` rather than on a sleep — a read taken during the
rebuild looks like a wrong value rather than an early one.

### The one parameter that is applied rather than shown, and why it matters

`userEndpoint` and `groupEndpoint` are handed to `scimClient.buildRequest` as
`spec.endpoints`, so **the page composes its requests onto whatever the
ResourceTypes document said**. `/Users` and `/Groups` are conventions and
nothing more: RFC 7643 section 6 defines a ResourceType's `endpoint` as "the
resource's HTTP-addressable endpoint relative to the Base URL", RFC 7644 section
4 has the server publish one per type, and a server answering on `/people` is
conformant. A client that hard codes the convention meets it with a 404 on every
operation — a failure that names an id nobody has rather than a path nobody
serves.

The substitution is a prefix swap on the rows that name a resource type. The
discovery paths, `/.search`, `/Bulk` and `/Me` name none and are left exactly as
they are — a substitution that reached them would relocate the three operations
most implementations already get wrong, and moving the document that PUBLISHES
the endpoints would make a wrong override unfixable. An absent or empty override
means "the catalogue's own path", so an unread ResourceTypes document changes
nothing at all. All of that is pinned in `tests/scim_engine.js`, in node.

Every other row is read out and shown, and each row's tooltip says which of the
two it is. A settings pane implying that a value it cannot act on is being
applied is worse than no pane, because it makes a server's refusal look like a
bug in this page.

## Four modules, and the split between them is the load-bearing part

| File | Has a DOM? | What it holds |
|---|---|---|
| `client/src/scim_client.js` | no | the endpoint catalogue, request composition, the seven authentication schemes, the RFC 7643 generator, the message bodies, and reading an answer |
| `client/src/scim_scenarios.js` | no | the twelve named scenarios, the random one, references, and `judge()` |
| `client/src/scim.js` | yes | the DOM, the two call paths, the runner, the history, the tabs and the configuration store |
| `api/scim_proxy.js` | n/a | what `POST /scim` will and will not forward — **no axios and no network** |

The first two have no DOM and the fourth has no socket, which is what lets
`tests/scim_engine.js` drive the whole of the interesting logic in node against
the RFCs' own text with **no server, no browser and no page**. That is not
tidiness. Two failures on this workflow are invisible to any test that only
reads statuses off a live server, and both have a specification citation
attached:

* **A double-encoded id.** The SCIM `id` here is an LDAP DN, so
  `/Users/uid%3Dalice%2C...` is correct and `%25` anywhere in it is not. A
  server decodes once, gets `uid%3Dalice...`, and answers **404** — which reads
  exactly like a deleted user.
* **A wrong Digest hash.** It produces a **401**, which reads exactly like a
  wrong password.

Build a request in a click handler and neither is findable.

## The browser calls the server directly, and that is the difference from LDAP

**SCIM is on the static deployments.** It carries no `data-not-on-static` marker,
`client/static_site.js` does not drop it, and its landing card is a live link —
unlike Kerberos, SPNEGO and LDAP. The reason is simply that RFC 7644 is ordinary
HTTPS with a JSON body, so `fetch` can speak it and the api is not structurally
required the way it is for BER over a socket or DER over port 88.

The api path exists for three things a browser cannot do, and the page names
which is which rather than presenting one as a fallback for the other:

* **CORS.** Essentially no real SCIM endpoint sends
  `Access-Control-Allow-Origin` — it is the most dangerous URL an identity
  provider exposes. The browser refuses before the request is made, and the only
  error JavaScript can see is `TypeError: Failed to fetch`, which is the **same
  message** a browser gives for a dead host, a DNS failure and a rejected
  certificate. `explainBrowserFailure()` spells out all four rather than guessing
  at one.
* **A self-signed certificate**, which a staging server always has.
* **The exchange itself.** A browser withholds the headers it adds and CORS hides
  most of those that come back — `Location`, which every SCIM create sends, is
  usually unreadable from the page even though it was sent. The Exchange pane
  **says so**. A partial list presented as a whole one is a debugger lying with a
  straight face, and that is the same rule the OAuth2 token pane already follows.

## `POST /scim`: the three outcomes, which are `POST /ldap/*`'s three

This is the rule to read before anything else in `api/scim_proxy.js`:

* a refusal by **this service** — a relative URL, a method that is not one of
  RFC 7644's five, a framing header — is a **400**;
* a **network failure** is a **502**;
* **a SCIM error from the far end is a 200**, carrying that status and its
  `scimType`.

The third is the point of the endpoint. A 409 `uniqueness`, a 404 on an id that
names nothing, a 403 from an access control policy and the refusal on `/Me` are the
server **answering**, and they are the most interesting thing a SCIM server ever
says. Collapsing them into a failure would make a provisioning debugger unable
to show the errors it exists to show. `tests/scim_protocol.js` asserts the
transport status on every negative for exactly that reason.

**The address policy is not re-implemented there and must not be.** `POST /scim`
is an axios call like `/token` and `/wstrust`, so `api/ssrf_guard.js` — installed
once on the shared instance — already covers it, redirects included. The two
places that *do* carry their own copy (`ldap_client.js`, `tls_probe.js`) are raw
sockets that axios never sees. A third copy here would be a fourth implementation
of one policy, which is how a policy comes to have a hole in one of its copies.

**Headers are refused by SHAPE, not by an allowlist.** A debugger has to be able
to send the header a server it has never met asks for — a vendor's
`X-Tenant-Id`, an `If-Match`, a `DPoP` proof. What is refused instead is the set
that changes the *shape* of the request: `Host` (which would make this an open
proxy), `Content-Length` and `Transfer-Encoding` (request smuggling), the
hop-by-hop set, and anything whose name is not a token or whose value carries
CR/LF. An allowlist would have been shorter to write and would have made the
endpoint useless against the third server somebody pointed it at.

## All six authentication schemes, and why there are seven rows

RFC 7644 section 2 defines **no SCIM credential of its own**. It names six ways
of doing it and makes exactly two normative statements: a server *SHALL* say
which it accepts in `WWW-Authenticate`, and it *MUST* be able to map an
authenticated client to an access control policy. The mock implements all six;
this page offers all six plus anonymous.

| Scheme | Spec | Scoped? | Where the credential is made | api? |
|---|---|---|---|---|
| OAuth 2.0 Bearer | RFC 6750 | **yes** | pasted, or from the OAuth2/OIDC workflow | yes |
| OAuth 2.0 DPoP | RFC 9449 | **yes** | a proof JWT signed **in the browser** per request | yes |
| HTTP Basic | RFC 7617 | no | the page | yes |
| HTTP Digest | RFC 7616 | no | the page, over the server's nonce | yes |
| HOBA | RFC 7486 | no | an RSA key generated **in the browser** | **no** |
| Session cookie | RFC 7644 §2 | no | the browser attaches it | **no** |
| TLS client certificate | RFC 8446 | no | the TLS handshake | **no** |

**Seven rows for six schemes** because the mock's own table does the same: DPoP
is the same access token held a second way, and its row exists so a client
reading the ServiceProviderConfig can see the bound form is understood. Its
`attempt` in `scim_auth.js` is `null` — `attemptBearer` handles both.

**Only the two OAuth schemes carry scopes**, and the page says so on every other
one. That matters more than it looks: the access control policy reads "an OAuth
credential may do what `scim:read` and `scim:write` say, and every other accepted
credential may do both", so a caller who cannot get the scope can simply use
Basic instead. Somebody testing a scope restriction against a Basic credential
would conclude it works when nothing was restricted.

**`/Me` is an alias here and used to be a refusal, so both legs are asked
for.** RFC 7644 section 3.11 makes `/Me` an alias for the subject a request
authenticated *as*. The mock answered 501 for one reason — nothing there
authenticated, so there was never a subject — and that stopped being true when
these endpoints started requiring a credential. So `tests/scim_protocol.js`
asks twice: with the run's credential it must come back as **this run's own
principal**, and with none it must refuse (401, or 501 where the server has no
such notion). A `/Me` that resolves to *somebody else* is the failure worth
catching, because a client that only ever provisions itself cannot tell it from
a working one and the write that follows lands on the wrong account.

### The three documents configure the workflow

The pane used to be a **readout**. It displayed what ServiceProviderConfig,
ResourceTypes and Schemas said, and all but the two endpoint rows were inert —
each row's tooltip admitted it in as many words. That was honest, and it made
the pane a picture of the server rather than a configuration of the page.

Now **every value the three documents publish is a row, every row is editable,
and the rows drive what the page sends.**

**The rows that only exist because a server said so.** ServiceProviderConfig has
a fixed shape and its rows are written out in `CONFIG_PARAMS`. The other two do
not: a server publishes as many resource types and schemas as it likes, each
schema with as many attributes as it likes. So those rows are built from what
was read, and **the name is the whole row** — `dynamicRowFor()` turns a name
back into a row object and `allConfigParams()` finds the names by scanning the
two value stores. There is no registry to keep in step, nothing to rebuild when
a discovery lands, and nothing extra to persist: `configValues` and
`discoveredValues` are keyed by name and were already written to localStorage,
so the rows come back on a reload for free. The grammar:

| Name | What it holds |
|---|---|
| `type\|<name>\|endpoint` | where that resource type answers — **applied** |
| `type\|<name>\|schema`, `\|extensions`, `\|description` | the rest of its entry |
| `authscheme\|<type>\|name`, `\|description`, `\|specUri`, `\|documentationUri`, `\|primary` | one advertised scheme |
| `schema\|<id>\|name`, `\|description` | the schema itself |
| `schema\|<id>\|attributes` | its attribute names, **in order** — membership AND ordering |
| `attr\|<id>\|<attribute>` | one attribute's characteristics, as `key=value` pairs |

`schema|…|attributes` is load-bearing rather than decorative: it is both the
membership and the order of the attribute rows, so **removing a name from it
removes that attribute from the generated body** and stops the row being drawn.
Editing that one row is how a reader says *this server does not really have that
attribute, whatever its Schemas document claims*.

**User and Group keep their fixed rows.** `userEndpoint`, `groupEndpoint`,
`userSchema` and `groupSchema` are what everything on this page reads, so those
two types do not also gain a `type|…|` spelling. Every OTHER resource type does
— until this change a server whose types were named something else contributed
nothing at all and said so in a warning nobody reads, which made the page
undriveable against exactly the servers worth testing it on.

**How the Schemas document bites.** The generator in `scim_client.js` produces a
rich, complete User — every section 4.1 attribute, filled with plausible data —
and that is worth keeping. What it cannot know is what *this* server's schema
declares. So the body is generated as before and then **filtered through the
configured attributes**, rather than built from them: building from the schema
would throw away every piece of realistic data the generator knows how to make,
and a schema-shaped body full of `string-1` values exercises nothing.
`applySchemaToBody()` does four things and reports every one of them under the
preview:

* an attribute the configured schema does not declare is **dropped**;
* `mutability: readOnly` and `immutable` are dropped, because a client that
  sends them is testing its own ability to be ignored;
* `multiValued` decides whether a value is wrapped or unwrapped, and
  `canonicalValues` is what a generated `type` is snapped to — a generator that
  invents `type: "office"` against a schema offering work/home/other produces a
  400 that reads like a server bug;
* a `required` attribute the generator did not produce is **added**.

> **RFC 7643 section 3.1's common attributes are exempt, and this is not a
> nicety.** `id`, `externalId` and `meta` are defined by the specification
> rather than by a server's Schemas document, so no attributes row will ever
> mention them. Without the exemption the filter drops `externalId` from every
> generated body — it looks exactly like an attribute the schema does not
> declare. That was the first thing this filter got wrong, and it was invisible
> until one generated body was compared against the one before it: `externalId`
> is the attribute a provisioning client most relies on and the one whose
> absence a server will not complain about. `tests/scim_page.js` asserts it.

**A row never blocks a send.** This is the rule the whole design rests on. A
capability row changes what is generated and **warns** when the request
contradicts it; it does not refuse. This is a debugger — the most interesting
thing a SCIM server does is refuse something, and a page that refuses first on
the server's behalf has removed the test case and replaced the server's own 400
with its own opinion. So `filter.supported = no` gets you a warning under the
preview and the request still goes. The Source column says which of the three a
row is: **applied** (it changes the request), **warns** (it does not, but it
says so first), or neither, which still says so in the tooltip.

Which is why **every row is editable**, and the two facts are one design: the
pane is not only a picture of what the server said, it is where you say what you
want this page to believe. A server whose Schemas document is wrong about an
attribute is corrected by editing the row; a capability the server
under-reports is forced by editing the row to `yes`. The *the server said: …*
note beside an edited row keeps that from being a lie you forget you told, and
**Restore discovered values** puts all of it back.

**`etag.supported` is the one row whose meaning is a round trip**, so it is the
one that adds a header rather than changing a value. The ETag is remembered per
resource id from whatever response carried it and sent back as `If-Match` on the
next PUT, PATCH or DELETE to that id — but only when the row says yes, because a
client that sends `If-Match` at a server with no ETags gets a 412 for a reason
that has nothing to do with what it was testing. A browser-direct call usually
cannot see the ETag at all: it is not CORS-safelisted, so unless the server names
it in `Access-Control-Expose-Headers` the browser withholds it, and the warning
says which call path you are on rather than blaming the server.

**The pane says that it scrolls, and this is a fix rather than a decoration.**
The table lives in a 520px box with `overflow-y: auto`, and a box like that with
a flat bottom edge looks exactly like a table that *ends* there — the rows below
the fold are not merely out of reach, they read as settings the pane does not
have. That was reported as parameters being missing when they had been on screen
the whole time, one scroll down. Two cues answer two different questions: the
**count above the box** (`109 parameters — 36 shown, 73 inside folded groups.
The table scrolls.`) is the only one a reader can see without touching anything
and the only one that says how much is missing; the **fades** at the top and
bottom edges say which way there is more, and each appears only when there is
something in that direction, so a table short enough to fit shows neither. The
fades are overlays in a positioned wrapper rather than a background on the
scroll box itself, for two reasons — a background would be painted over by the
group headings' own opaque backgrounds, and anything inside the scrolling
element scrolls away with the content it is meant to be pointing at.
`refreshConfigScrollCues()` is called from three places and needs all three: the
scroll event, `renderConfig()` (the table changed height under a box that did
not move — which is what folding a group does), and resize.

**A fade is a 120ms `transition`, which is a trap for the test rather than for
the reader, and it cost a run on 2026-08-24.** The computed opacity a moment
after a scroll is still the value the cue is coming *from*, so a test that
scrolls and reads in the same `executeScript` asserts the state before the
scroll — it reported the top fade as absent at the end of the table, 120ms
before it arrived, and named the cue rather than the timing. `scrollCuesAt()`
in `tests/scim_page.js` scrolls, waits for `getAnimations()` on the two cue
elements to come back empty (a CSS transition is held there while it is
*pending* as well as while it runs, and an unchanged cue starts none, so this
costs nothing when nothing moved), and only then reads. A `sleep` here is the
bet this suite has lost before. The row class is the matching trap from the
other side: a foldable group heading carries `scim-config-group` and nothing
else, because a second class would be a hook no stylesheet answers and
`everyStyleClassIsDefined()` fails a run over exactly that — the fold's own
styling belongs to the button, `.scim-config-fold`.

**The generated groups fold, and start folded.** Reading all three documents in
full turns the table from about forty rows into a hundred and twenty-six, inside
a box 520px tall. Every one of those rows is wanted — that is the point — but a
reader who came to change the service root should not scroll past twenty-one
attribute rows to reach `authScheme`. So groups built from a document fold; the
fixed groups at the top do not fold at all. A row under a folded group is **not
built**, rather than built and hidden — and its value still drives the
generator, because that is read from `configValues` and never from the DOM. The
fold state outlives the rebuild that every discovery causes, which is why it is
kept in localStorage rather than in the table.

**Three schemes are browser-only and selecting one LOCKS the call path.** A
cookie is attached by the browser and the api has no cookie jar; a client
certificate is chosen in the handshake and the api would present *its own*,
which is a different identity and a misleading one. A page that let somebody
pick BackEnd with a cookie scheme would send a request with no cookie and
report the 401 as the server's fault. `refreshCallPathControls()` disables the
`callPath` row of the configuration table and puts the reason on screen — and
it disables the control without touching the **preference** underneath, so
selecting a cookie scheme for one call does not silently throw away a call path
chosen for the next one. The row is a **radio pair** and `disabled` on it
reaches both radios, which is one of the two properties `radioPair()` defines
over the wrapper; see below.

### Digest is the one with real arithmetic in it, and four details are load-bearing

**All three registered algorithms are implemented, and none of them is Web
Crypto.** RFC 7616 section 6.1 registers MD5, SHA-256 and SHA-512-256, each with
a `-sess` variant, and the mock offers all three — its challenge is **three
`Digest` challenges in one header**, sharing a nonce. `crypto.subtle` has
neither MD5 (removed from browsers on purpose) nor SHA-512/256 (a different
function from SHA-512 truncated), and it is asynchronous, which would make a
credential a promise. So node-forge supplies MD5 and `@noble/hashes` the other
two, synchronously, in `scim_client.js` — which is also what lets the whole thing
be checked in node.

**The strongest offered algorithm is chosen, and taking the last one parsed is
the trap.** The conventional ordering in a header puts the weakest last, so "the
last `Digest` challenge" reliably means MD5. `chooseDigestChallenge()` walks the
preference order instead.

**`nc` must increase, and getting it wrong costs exactly one request.** The nonce
count is what makes a Digest credential single-use; the mock refuses a repeat as
a replay and refuses it **without** `stale=true`, because stale means "your
credential was fine, try again" and a replay is the opposite claim. A client that
hardcodes `00000001` authenticates once per nonce and then fails in a way that
reads as expired credentials. `digestCounts` in `scim.js` keys the counter **by
nonce**, because the server issues a fresh one when the old goes stale.

**`uri` is the request-target and not the absolute URL** — path and query, as it
appears on the request line. It is hashed into A2 and compared by the server
against what arrived, so an absolute URL produces a perfectly well-formed
credential that matches nothing.

The page also **verifies the server's `rspauth`** (RFC 7616 section 3.5), which
is the half most implementations leave out: it is the same construction with an
*empty* method in A2, so only somebody who knows the password could have produced
it. A client that never checks it has mutual authentication available and unused.
Its absence is reported as ordinary rather than as a failure.

### HOBA's blob is length-prefixed, and that is the whole of it

RFC 7486 section 5: each field becomes **its length in octets, a colon, then the
field**, and the six are concatenated with nothing between — in the order nonce,
algorithm, origin, realm, kid, challenge.

```
3:abc  1:0  13:https://h:443  4:SCIM  2:k1  2:ch
```

A dot-joined or newline-joined version looks perfectly reasonable, is the right
size and shape, and **verifies against nothing** — and the only error a server
can give back is "this does not verify", which sends everybody to look at their
key. The length is in *octets*, so a realm carrying an accent makes it disagree
with `String.length`, silently.

**The origin always carries an explicit port**, including the default one. RFC
7486 gives the origin no serialization of its own, so `https://host` and
`https://host:443` are two different strings over which two different signatures
are computed — and a browser's `location.origin` omits the default port while a
server reconstructing it from `Host` usually does not.

**The algorithm registry has one entry that matters: `"0"`, RSA-SHA256.** So the
key generated by the page is **RSA**; an ECDSA key produces a signature the
scheme has no identifier for. The key lives in the page only and is never
written to `localStorage` — a signing key in storage is a signing key in every
extension's reach — and `tests/scim_page.js` asserts that.

Registration is a form-encoded POST to `/.well-known/hoba/register` on the
**server's origin** (not under the SCIM base path) carrying `pub`, `username` and
`kid`.

## The generator emits every optional attribute, on purpose

`randomUser()` produces the complete RFC 7643 section 4.1 User: all six
sub-attributes of `name`, the five multi-valued types with their
`type`/`primary`/`display`, both addresses with `formatted`, `ims`, `photos`,
`entitlements`, `roles`, `x509Certificates`, and the whole section 4.3 enterprise
extension.

That is the point rather than thoroughness for its own sake. A provisioning
client tested only against `userName` and `emails` has tested nothing about the
fields it will meet in the field — and **what a server stores is usually
narrower than what it accepts**. The difference between "accepted and stored" and
"accepted and dropped" is invisible at the moment of the create and is the single
most common real defect in a provisioning integration. Reading the resource back
is what shows it; reading the *directory* back shows it exactly (below).

Two deliberate omissions:

* **`manager` is not invented.** It is a reference to another user's id, and a
  generator that made one up would produce a dangling reference on *every* user
  — worth running on purpose, and a poor default. The `enterprise` scenario sets
  it once both parties exist.
* **No `password`** unless one is asked for. RFC 7643 makes it `writeOnly`, and
  generating one would make this the only workflow here that wrote a secret
  nobody asked for.

And one deliberate substitution, which looks like an omission and is not:

* **`roles` and `x509Certificates` carry `display` where every other
  multi-valued attribute carries `type`.** RFC 7643 section 8.7.1 declares
  `"canonicalValues": []` on the `type` sub-attribute of exactly those two and
  of no other — section 4.1.2 says of roles that "no vocabulary or syntax is
  specified" — and a strict server reads an empty list as an *exhaustive* one.
  scimmy, which this project's mock is built on and which is a fair share of
  the real SCIM servers a user of this page will meet, then refuses **any**
  value there: `400 invalidValue: Attribute 'type' contains non-canonical value
  from complex attribute 'roles'`, which fails the create before a single
  attribute is stored. A generated User that cannot be created is worth less
  than a sub-attribute, and the refusal names the field rather than the schema
  rule behind it, so it reads as a bug in the page. `display` is defined on
  both and constrained on neither. `tests/scim_engine.js` pins it, so a `type`
  put back here fails in node with the rule written out rather than as a 400
  from whichever server was being debugged.

**Random is seeded and therefore reproducible.** `newRng()` is a mulberry32 over
a hash of a caller-supplied seed string, so the same seed always produces the
same fifty users and the same random scenario. The page shows the seed. An
unseeded harness makes every interesting failure a story rather than a test —
"it failed on the seventh user" cannot be run again. It is **not** cryptography
and must never be used for any, which is why it lives beside the generators it
feeds rather than in `crypto_bytes.js` where somebody would eventually reach for
it.

## The twelve scenarios

| id | What it is for |
|---|---|
| `discovery` | the three documents a client should read first; needs no scope anywhere |
| `user-lifecycle` | one user with every attribute, read back, PUT, three PATCHes, delete, then a read that expects 404 |
| `provision-team` | N users, a group, one membership PATCH, a read-back, one member removed, teardown |
| `deprovision` | create N then delete N, each delete followed by a read expecting 404 |
| `modify-sweep` | three PATCH shapes against every one of N users |
| `bulk` | one BulkRequest creating N users **and** a group whose members are those users, by `bulkId` |
| `paging` | 1-indexed `startIndex`, both sort orders, and `count=0` |
| `filter-tour` | all fourteen section 3.4.2.2 forms against one known user |
| `search-post` | `/.search` per type, across both, and a body with no `schemas` |
| `enterprise` | the section 4.3 extension, addressed by full URN path |
| `negatives` | every refusal the server can be made to produce on purpose |
| `scope-refusal` | a read-only credential may read and may not write — including a bulk |
| `random` | two to four of the above, composed from the seed, each phase with its own prefix |

**References, not ids.** The id of a user created by step 3 is not known when the
plan is built, so steps hold `{ ref: 'user-3', field: 'id' }` and `resolve()`
substitutes it just before sending. A plan with a function in it could not be
shown to a person, stored, or compared by a test — and an unresolvable reference
is a *diagnosable* state ("step 7 wanted the id from step 3, which did not run")
rather than a request to `/Users/undefined`, which a server answers 404 and a
reader reads as a deleted user.

A reference cannot be a *fragment* of a string, and several steps need exactly
that — an id inside a filter, an id inside a value-filter path. Those carry a
`substitute` map of SHOUTED placeholder to reference; a placeholder left
unsubstituted is visible in the request the page shows.

**A random scenario namespaces every phase**, giving each its own prefix and its
own derived seed, because two phases that both had a step called `create` would
resolve each other's references — a scenario deleting a user another phase is
still using, which looks like the server losing one.

**A plan belongs to the inputs it was built from, and changing any of them
throws it away.** Run plans for itself when nothing is planned, and only then —
so choosing a different scenario, seed, prefix or user count after pressing Plan
and then pressing Run used to run THE OLD ONE, while the description beside the
selector and the table on screen both described the new one. Nothing about that
looks like a failure: the run goes green, every step passes, and it was the
wrong scenario. `forgetPlan()` drops the plan and empties the table on any
change to those four inputs; a run in flight keeps its own plan, because the
steps left to run are its.

**One `bulkId` reference per operation against this mock, and it is the
server's limit rather than the page's.** RFC 7644 section 3.7.2 lets an
operation reference a resource another operation in the same request is about
to create. The mock delegates that to scimmy (1.3.5, the current release),
whose substitution loop re-parses the *original* request body once per
reference and replaces one name at a time — so each pass discards the one
before it and only the LAST reference resolves. A group sent with three
`bulkId` members comes back holding two literal `bulkId:uN` values stored as
member DNs. `tests/scim_protocol.js` asks for one reference and states the rest
as a skip; the `bulk` scenario is unaffected, because its two checks are
`bulkAllSucceeded` and `listNotEmpty` and neither reads the group's
membership.

## The three tests, and why they are three

| File | Needs | What only it can see |
|---|---|---|
| `tests/scim_engine.js` | **nothing** | what this workflow *composes*, against the RFCs' own text and fixed vectors |
| `tests/scim_protocol.js` | api + mock STS | what the server *stored*, read back out of the directory; all six auth schemes |
| `tests/scim_page.js` | a browser | the browser call path, Web Crypto credentials, the runner, `localStorage` |

**`scim_engine.js` runs everywhere and is never gated**, including on the static
targets, because it needs no service at all. It is first of the three
deliberately: a broken request builder makes the other two fail in ways that look
like a broken server. It writes out RFC 7644's endpoint list and RFC 7643's
attribute list **independently** of the catalogues under test — a list derived
from the implementation agrees with it by construction and can notice nothing.

**`scim_protocol.js` reads everything back a second way, and that is why it is
long.** The mock has no store of its own: a SCIM create writes an entry in its
embedded LDAP directory, so

```
POST /scim/v2/Users              ->  uid=alice,ou=users,dc=example,dc=com
POST /ldap/search  (ou=users)    ->  the same entry
GET  /admin-api/scim             ->  the counters that saw it
```

Every attribute the test sends is checked against the LDAP attribute the mock's
`scim_map.js` says it lands in — and that mapping table is **transcribed rather
than imported**, for the same reason. `title` sent, 201 returned, nothing in the
directory: that is a field accepted and silently dropped, and a status-only test
cannot see it.

**Its section 4b is about an entry SCIM did not create**, and it is there
because of a flake that named nothing. `userName` is the one attribute RFC 7643
makes required, and the mock enforces that on the way OUT as well as in — while
its own mutual-TLS listener records a client certificate by seeding a directory
entry named `cn=<CN>,ou=users` with **no `uid` on it at all**. One such entry
made every `GET /Users` answer `400 invalidValue — Required attribute 'userName'
is missing`: a message about the request, on a request that was fine, caused by
an entry it does not name. The suite runs its jobs in a pool, so whether
`tests/api_tls.js` gets there before the SCIM jobs is a coin toss. The section
adds such an entry over LDAP — around SCIM entirely, which is also the honest
statement of the rule, since the directory enforces no schema and an `ldapadd`
may write one at any time — and asserts that the list still answers, that the
users from section 4 are still in it, and that the entry itself comes back as a
User whose `userName` is its RDN value. The fix is in the mock
(`scim_map.js`'s `toScimUser()` falls back to the RDN value and then to the DN,
as the Group mapping already did for `displayName`), so this test fails against
a mock STS older than 2026-08-23.

Its authentication section exercises **all six schemes once each**, plus the
negative that proves each check is really running — a scheme that accepted
everything would pass a positive-only test perfectly. It is deliberately *not* a
cross-product with the endpoints: forty-two runs of the same header parser test
nothing the first one did not. Two of the six **skip with a reason**: the cookie
needs a browser that has signed in, and a client certificate would be the api's
own.

**`scim_page.js` covers only what needs a browser** — the browser call path
(which no other job exercises and which is the *only* one the hosted site has),
the DPoP proof and HOBA key signed with Web Crypto (`scim_protocol.js` signs with
node's crypto, a different implementation), the two schemes that lock the call
path, the runner actually running, and what does and does not reach
`localStorage`.

All three **skip with a stated reason** when the mock STS has no `/scim/v2`
routes — the ordinary state of a checkout whose `sts/` gitlink predates them. A
silent pass there would be this project's recurring defect.

**Both server-facing tests run under a credential, and it is HTTP Basic in each.**
The mock refuses an unauthenticated SCIM request (`scim.authRequired`, on by
default there), so a test that provisioned anonymously stopped working the moment
`scim_auth.js` landed in the mock — with a 401 on every write, naming an endpoint
rather than the cause. `scim_protocol.js` establishes one in section 1b and
`scim_page.js` in `useRunCredential()`; both build it with the workflow's own
`applyAuth()`, so a header this suite gets wrong is a header the page gets wrong.
Basic is chosen over Bearer on purpose: it is the one scheme that is a header and
nothing else — no token endpoint, no scope, no nonce, no key — so a refusal in a
provisioning section is about SCIM rather than about an authorization server
having a bad day. What that leaves out is exercised properly in the
authentication section, which is where a scheme *should* be tested rather than
incidentally a hundred times over.

Three things follow from it and each has already been got wrong once:

* **The credential-less legs have to say so.** The Digest and HOBA handshakes
  both open with a deliberate anonymous request, to collect the challenge they
  compute over, and so does the probe that reads `WWW-Authenticate` — those pass
  `scimCall(..., { anonymous: true })`, and without it they get a 200 and nothing
  to sign.
* **It is PROBED, not assumed.** `scim.authRequired` is a runtime setting and the
  mock's `/admin` state outlives a test file, so section 1b asks for the 401
  first; against a mock with authentication turned off nothing is attached and
  the run passes unchanged.
* **The Basic username is not the run's prefix.** An accepted Basic name is
  recorded as an authentication at the mock and gains a directory entry, and the
  deprovisioning section asserts that nothing matching the prefix is left behind.
  A run's provisioning identity is not one of the users that run provisioned.

## What the page remembers

Every field goes to `localStorage` except the credentials, and the two
credentials are treated differently from each other on purpose:

* **A password is NEVER stored.** No checkbox, no opt-in, same as the LDAP page.
* **An access token is stored only if `scim_save_token` is ticked, and it ships
  CLEAR.** This is an opt-**in**, the opposite of the key-pair panes' opt-out,
  because the trade is different: a SAML SP key is needed on a later page to
  decrypt an assertion and re-pasting it is real friction, while a bearer token
  is pasted once and expires anyway. **Clearing the box purges what was already
  written**, on the spot — and the purge lives in `saveState()` rather than only
  in the change handler, so no code path can leave one behind. It also runs on
  load, so arriving with the box already clear cleans up.
* **The HOBA private key is never stored under any setting.**

## Getting a token, which this page cannot do and the one next door can

RFC 7644 section 2 names an OAuth 2.0 bearer token as a SCIM authentication
scheme and then says **nothing whatever** about where one comes from — no
grant, no endpoint, not even a hint that a client should have an authorization
server. So this page offered a field for a token and no route to one, which
left the reader with a second tab, somebody else's workflow and a clipboard.

The route is the **OAuth2 / OIDC workflow in this same application**, driven
exactly as it always is. `client/src/token_handoff.js` is the whole of the
mechanism and it is four moving parts:

1. **`getAccessToken()`** (the *Get one from the OAuth2 / OIDC workflow* button
   beside the token field) marks this page as waiting — `start({returnUrl,
   label})` — and navigates to `/oauth2_oidc_1.html?tokenhandoff=1`.
2. **`oauth2_oidc_1.js`** puts up a banner naming the waiting workflow, so a
   page that is about to send a token somewhere else says so *before* a grant
   is run on it. **Nothing there is pre-filled**, which is the difference from
   the SD-JWT VC hand-off beside it in that file: that workflow arrives with an
   authorization endpoint and a client id its own step 1 has just written,
   while this one arrives from a page that knows a SCIM service root and
   nothing at all about an authorization server. Guessing any of it would
   produce a request that fails for a reason the reader did not choose.
3. **`oauth2_oidc_2.js`** calls `offerTokenToHandoff()` from **all three** of
   its token-bearing responses — the token endpoint, a Refresh Token grant, and
   the authorization response itself, which is where an Implicit or Hybrid
   flow's access token arrives and *only* there. It fills the slot and offers a
   link back. **The browser is not sent back by itself**, which again differs
   from the SD-JWT VC hand-off: that page is a waypoint in a numbered sequence,
   whereas a reader who came here for a token is on the one page that shows
   them what came back — the claims, the DPoP verdict, the whole exchange — and
   yanking them off it the instant the response lands takes away the thing they
   can only see there.
4. **`applyHandedToken()`** runs from this page's `onload()`, after
   `loadState()` (so a handed-back token is not overwritten by what storage
   remembered) and after `refreshAuthControls()`. It fills the field and says
   where the token came from.

**The slot is `sessionStorage` and not `localStorage`, and that is the whole
reason the opt-in above is still true.** A hand-off that wrote the token to
`localStorage` would have stored a credential on the reader's behalf without
asking: `scim_save_token` would still be clear and would now be a lie. Session
storage is scoped to the tab and dies with it, the hand-off is a single
same-tab navigation (the identity provider round trip leaves this tab and comes
back to it), and `take()` **removes what it returns** — so the slot holds a
token for the length of one page load. A delivered token also **expires** after
half an hour, because a slot that was filled and never collected would
otherwise be picked up by an unrelated visit an hour later, and a bearer token
appearing in a field nobody filled is worse than no hand-off at all.

`applyHandedToken()` collects a delivered token and **leaves an undelivered
hand-off alone**. The difference matters: the workflow's round trip goes out to
an identity provider and back to `oauth2_oidc_2.html` and never through this
page, so this page loading with a hand-off still open means the reader came
back by themselves — a Back button, a bookmark — and cancelling it there would
break the flow they are still in the middle of.

`tests/scim_page.js` section 8f drives the whole route with **no identity
provider**: the button, the banner on page 1, `offerTokenToHandoff()` called
directly (which is what the token endpoint's success handler does with
`data.access_token`), the link back, the field, and then a reload — because
with the save box clear the token must be in the field and nowhere else.

## Adding an endpoint

`OPERATIONS` in `scim_client.js` is the single source for six things — the method
and path, the body shape, the query parameters, the scope, the labels, and what a
scenario step compiles to. Add a row there and the page's selector, its query
editor, its body generator and the history log all follow. A seventh endpoint
added as a button on the page and *not* as a row here is the defect the
arrangement exists to prevent: it would be uncovered by
`scim_engine.js`'s completeness check, which walks the table rather than the
page.

## Adding a protocol costs more than a page

The same list `docs/ldap.md` ends with, as it applied here: a bundle entry in
`client/build.js` **and** a `RUN browserify` line in `client/Dockerfile` (two
places, and the coverage build's `for entry in` list is a third); a landing card
plus its `:nth-child(N) .landing-icon` accent rule, remeasured with
`landingFitsOnOneScreen()`; a stylesheet whose every class is defined, or
`checkStylesheetsLoaded()` fails the page; `COPY` lines in `tests/Dockerfile` for
every module a test loads flat; job entries in `tests/run-report.js`; a row in
each of the five `client/src/env/*.js`; and this file.

The fourteenth card was free — seven across turns 7+6 into a filled 7+7, the same
two rows and the same height. **The fifteenth is the expensive one**: 7+7+1 puts
a third row below the fold, so it will need eight columns at `min <= 108.75`
(`8*108 + 7*10 = 934 <= 940`), and eight columns take another ~17px off every
card so every description wraps again. Measure at each step; anything larger
fails **silently** by staying at seven, with the height as the only symptom.
