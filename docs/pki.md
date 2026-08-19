# PKI — a certificate authority, X.509v3, and a real TLS handshake

Scope: `client/public/pki.html` and its bundle, `client/src/x509.js`,
`client/src/key_material.js`, `client/src/pki_store.js`,
`client/src/pki_history.js`, `api/tls_probe.js` and the two endpoints it sits
behind. Cross-cutting matters — the logging convention, the 80-column rule, the
key-material opt-out rule, how the suite is run — stay in the repo-root
`CLAUDE.md`.

Read this before touching any of those files. Almost everything in it is a
defect that produced bytes which parse perfectly and are then refused by
something else, with an error message naming the wrong thing.

## What it is

One page that builds a certificate authority — **Root**, **Intermediate**,
**Issuing** — and issues the leaf certificates any of them can sign, with every
X.509v3 extension editable including its critical flag. Then it makes a real
TLS or mutual-TLS connection with what it issued, which is the only way to find
out whether any of it works.

The split across files is not arbitrary, and it is what makes the claim "every
combination" testable:

| File | Holds | Has a DOM? |
|---|---|---|
| `client/src/key_material.js` | key pairs, PEM↔JWK, PEM/DER/JWK/PKCS#12 export | no |
| `client/src/x509.js` | profiles, extensions, issuing, describing, chain checks | no |
| `client/src/pki_store.js` | the keys and certificates kept for reuse | no (localStorage only) |
| `client/src/pki_history.js` | the Operations History, over `op_history.js` | no |
| `client/src/pki.js` | the page: the form, the tables, the buttons | all of it |
| `api/tls_probe.js` | the TLS / mutual-TLS connection | n/a |

So `tests/pki_x509.js` drives ~240 certificates through the real encoder in node
and hands every one of them to **OpenSSL**, and `tests/pki_page.js` is left with
only the page.

Two ways in, and both stay. The page has had a **landing card** of its own
since 2026-08-18 (`PKI / X.509`, the twelfth) — it is a workflow rather than a
tool of another protocol's, and being reachable only from somebody else's tools
pane said the opposite. The **Tools** pane entries on `oauth2_oidc_1.html`,
`oauth2_oidc_2.html`, `saml_request.html`, `saml_response.html` and
`wsfed_response.html` are deliberately kept, because they are the other journey:
you are mid-flow and you need a certificate, rather than here because the
certificate authority IS the task. Note that those links carry `?from=<page>`
and this page does **not** read it — `pki.html`'s *Return* is a static link to
the landing page, unlike `jwt_tools.js`'s `setReturnLink()`. Note too that the
card carries **no** `data-not-on-static` marker: the CA is Web Crypto and pkijs
in the browser and only the TLS test needs the api, which `#pki_backend_notice`
says on the page itself. See `client/CLAUDE.md`.

**Both browser tests reach the page by clicking that card** rather than by
getting its URL — `openThePageFromTheLandingCard()` in `tests/pki_page.js` and
`tests/pki_mutual_tls.js`, used for every load including the reloads that check
the store survives (localStorage is per origin, so the trip through the landing
page preserves what a direct re-get would; verified). `tests/navigation.js`
checks the card too, but once and only against the containerized stack's base
URL, whereas these run wherever the suite is pointed — the deployed static
sites included. A card that stops pointing anywhere, or that something is drawn
over, then fails here instead of being nobody's test.

## The page is five panes, and it was seven

This page carries more fields than any other in the tree: a key pair, sixteen
certificate fields, a distinguished name, **twenty** X.509v3 extension cards and
a TLS pane. On 2026-08-18 its first three panes — *Key Pair*, *Issue a
Certificate*, *X.509v3 Extensions* — became one, `pane_config`, its fields laid
out in three columns, with the extension list flowing in three of its own and
the TLS pane in two. Nothing was removed; what changed is where it sits and how
much margin it pays.

**What it bought, measured at 1366x768 in headless Chrome.** The page went from
**4941px** to **3323px** — a third of it — and the *Keys & Certificates* pane,
which is where you go to look at what you just issued, moved from 3802px down
the document to **2146px**. A second pass the same day took it to **~2600px**:
the configuration pane went to three columns, the extension list to three, and
the TLS pane to two. A third took it to **2196px** by moving every standing
note and warning into the tooltip of the control it describes — see *Every
field has a tooltip* below. `tests/pki_page.js` holds a **2700px** budget with
~20% of slack in it for font metrics (fonts-liberation in the container, the host's
Arial on a host run), because what it is there to catch is the change that gives
a whole saving back at once rather than the tens of pixels a font accounts
for.

**Why one pane.** Those three described one act. Every field in all three is an
input to the single **Generate Key Pair & Issue Certificate** button, at the top
of the *Key Pair* block of the pane they became — you cannot issue anything from
*Key Pair* alone, and the extensions are not a separate operation, they are
arguments. Each extra pane
costs a title bar, two borders and the gap between them before a field is drawn,
and it made the reader collapse three things to reach the store rather than one.
This is the same trade `kerberos_ap.html` made, for the same reasons and with the
same consequence, and `docs/kerberos.md` measures it there at 213px.

**What the lost legends became.** A pane legend can only say one thing, so *Key
Pair* and *X.509v3 Extensions* are `.pki-group` headings over the blocks they
named. Without them the key algorithm dropdown and the profile dropdown are two
unlabelled selects side by side. A `div` rather than a `<label>`, because it
labels a **group**: a `<label>` with no control to point at is one the browser
cannot associate with anything, and pointing it at the first field would claim
the heading belongs to that field alone.

**The configuration pane is THREE columns, and the third one is why.** Key pair,
certificate fields, subject DN. It was two, with the DN under the certificate
fields, and the arithmetic of a grid is what was wrong with that: a grid **row
is as tall as its tallest item**, so a 392px column sat beside a 675px one and
the key pair ended in 283px of nothing. Three blocks of roughly equal height
spend that space instead of paying for it. `tests/pki_page.js` measures both the
heights (a column under 60% of the tallest is dead space with a border) and the
**tops** — see the next paragraph for what makes them move.

**Four traps live in that layout, and all four are invisible until something
is narrow.** `.pki-cols` is `auto-fit` with a **390px** minimum, and that
minimum — not the design — is what decides whether the pane has three columns,
two or one: three need `3*390 + 2*22 = 1214px` and there are 1275 at a 1366px
window, so raising it to the 420 it used to be silently wraps the third column
onto a row of its own and makes the pane **taller** than the two-column version
it replaced. A layout that looks deliberate at 1500px and stacks at 1024 is
usually this number biting rather than a broken rule — with the exception of
the configuration pane above 1330px, where `.pki-cols-3`'s media queries take
the track sizes over and the minimum stops deciding anything. `.pki-col` carries
`min-width: 0`, which is not decoration: a grid item's default minimum is its
content's, and this page's content includes an unbreakable 64-character line of
base64 in a PEM textarea. Without it the column refuses to be narrower than that
line, the grid overflows its pane, and the page scrolls sideways — which reads
as a broken layout rather than as two missing words of CSS. And `.pki-flag`'s
`white-space: nowrap` belongs to the flag **grids** and the card headings, where
the labels are single identifiers: the half-dozen flags elsewhere are whole
sentences ("also connect without it, and say whether the server requires one"),
and a sentence that may not wrap hangs 66px out of a half-width column at 900px
— reported by the page as a horizontal scrollbar rather than as a label.

**The fourth is a control that does not shrink, and it is the only one of the
four with no symptom at all.** `.pki-col` carries `min-width: 0` and the fields
inside it are `flex: 1 1 0`, so a control with a **fixed** width does not
narrow with its column — it keeps that width and draws over the column beside
it. Nothing reports that: the grid itself still fits, so there is no horizontal
scrollbar, nothing is clipped, and the page height does not move. What you see
is two controls sharing a few pixels, which reads as a font difference.

The one that had it was `input[type="number"]`. `saml_common.css` sizes
`.saml-pane textarea`, `input[type="text"]`, `input[type="password"]` and
`select` at `width: 100%` with `box-sizing: border-box`, and does not name
`number` — so `bootstrap.css`'s `input { width: 206px }` plus its own padding
and border survived on the two this page has, at 220px each. *Validity (years)*
sat 49px inside the Key Pair column at 1366px, over the Export block's
*Keystore Format* label and select, and the TLS pane's *Port* was the same
220px between a *Host* and an *SNI* that were not. Both are now sized by
`.saml-pane input[type="number"]` in `css/pki.css`, with the shared sheet's own
declarations rather than a second opinion about how wide a field should be. It
is fixed **here** rather than in `saml_common.css` because the only other
number inputs in the tree — `jwt_clock_skew` on `token_detail.html`,
`vc_batch_size` on `vc-issuance-2.html` — sit in table cells carrying a `size`
attribute, where `100%` means the width of the cell: deliberately narrow fields
that a fix in the shared sheet would stretch for a defect neither of them has.

This was invisible while these were three full-width panes: the overflow had
nothing to land on. So `tests/pki_page.js` now measures every control in every
`.pki-col` against its column's right edge rather than just the one that had
it — any control type the shared sheet does not name arrives the same way.

**The TLS pane is two columns, on the same reasoning and with the same
`.pki-cols`.** Left is the connection this end makes — host, port, SNI, the
version range, the cipher list, ALPN, and the client certificate; right is what
the answer is checked against — the truststore, the extra PEM anchors, and the
`GET` that asks the server what *it* saw. That is also the order the two are
decided in. The button, the status line and the report stay full width below,
because the report is a table of what both ends saw and half a page is not where
it goes. *Truststore* lost its `.saml-sub` wrapper on the way: it heads a column
now, and a column that opens on a dashed separator reads as the tail of the one
beside it.

**The extension list is CSS columns, deliberately not a grid.** A grid lays its
items out in **row** order, so twenty cards of wildly different heights
(`subjectKeyIdentifier` is one checkbox; `subjectAltName` is a checkbox, a
four-row textarea and a paragraph of syntax) leave a gap under every short one to
the height of the tallest in its row. A column flow packs them and keeps document
order reading **down** each column, which is the order the list is in and the
order the page's own prose refers to. `columns: 380px 3` is a **maximum** of three:
below about 1180px of pane there is room for two and below ~780px for one, and
each collapse happens on its own, so no media query is needed — and, less
happily, one card that stops fitting 380px costs a whole column with no symptom
except that you scroll further. That is ~400px of page, which is why
`tests/pki_page.js` **measures** the column count from where the cards actually
landed rather than assuming it. What decides whether a card fits is the
`.pki-flags` minimum inside it: at **172px** the keyUsage and extendedKeyUsage
grids are still two flags wide in a 380px column, and raising it back to the 240
it was is what would take the list from three columns to two. `break-inside:
avoid` is what stops a card being split across the boundary; a `subjectAltName`
whose checkbox is at the foot of one column and whose textarea is at the head of
the next is two half-controls, and it happens silently.

**The prose is folded, not cut.** Seven long notes — the intro's enumeration of
what is on offer, the three block explanations, the TLS pane's two, the history
pane's — are now `<details class="pki-more">`, the same mechanism and the same
reasoning as `.krb-more`: a debugger that omits why a thing fails is the thing
nobody needed. Where a note has one sentence that must be read **before**
anything is typed, that sentence stays outside the fold and only the reasoning
goes in — which is why the TLS pane still says on its face that the API layer
makes this connection, the sentence `tests/pki_page.js` asserts on. The rule in
the other direction is stricter and is asserted too: **nothing anybody has to
operate may be inside a fold.** A checkbox behind a summary is a setting nobody
finds, and unlike missing prose that costs a certificate rather than an
explanation.

**One button, and it is at the top.** *Generate Key Pair* and *Issue
Certificate* were two buttons for one act. A pair that is never certified is
kept nowhere — `generateKeys()` says exactly that in its own status line — and
`issue()` refused outright without one, so the second button was a step that
could only ever be forgotten and the page had an error message
("Generate a key pair first") whose whole job was to say so. They are now
`pki.generateAndIssue()`, on one button at the **top** of the *Key Pair* block:
a reader should not have to scroll past twenty-two extension cards to find out
what any of them are for. What the two-button flow gave for free was re-issuing
for a key that already exists — a CA renewing its own certificate — so a
**reuse the key pair below** checkbox (`pki_reuse_key`) sits beside it, cleared
by default, and the store's *Use this key pair* button ticks it itself rather
than loading a pair the next click would throw away. The box is checked
**together with the fields**: ticked over two empty fields it is a request to
certify nothing, and the generation happens anyway.

**Each extension is one line.** `issuerAltName`, `cRLDistributionPoints`,
`freshestCRL` and the eleven others with a value were a checkbox row, then a
textarea under it, then a note under that; the checkbox row and the textarea are
now the same row — name, value, `critical` — inside `.pki-ext-head`, with only
the syntax note below. The boxes are `rows="1"` in the markup **and**
`min-height` in `.pki-inline`, and neither is enough alone. Note what did *not*
change: they are still `<textarea>`s, so the multi-line values these extensions
take (subjectAltName is one name per line, and always was) are still typed,
stored and parsed exactly as before — what was cut is the space an empty one
occupies, which was four lines of nothing twenty-two times over. `resize:
vertical` rather than `both`, because horizontal resizing inside a CSS column
pushes the column's own width around. The 90px floor under the flex basis is
what makes a long name — `cRLDistributionPoints` is 21 characters — wrap the
row instead of collapsing the box to a slot.

**The key pair and the certificate fields swapped columns**, so the pane now
reads *Issue a Certificate* | *Key Pair* | *Subject Distinguished Name*: the
profile decides what the certificate is, and the key algorithm and the button
sit in the middle beside the DN they are about to be bound into.

**That middle column is two rows, and both of them are one line.** The key
algorithm select, the *Show as JWK* toggle, *Generate Key Pair & Issue
Certificate* and its *reuse the key pair below* checkbox are one row; the
keystore format, the password, *include the chain*, *save private keys here*
and *Download* are the other. They were four lines between them — the select
had a row of its own above the button, and the format and password a row of
their own above the checkboxes and the button — and those two extra lines are
the whole of why the key-pair column used to hang ~70px below the two beside
it. Everything on both rows is now as wide as what it holds (`.pki-narrow`,
130px for seven algorithm names, 140px for four format names, 100px for a
password) rather than half a column each.

**The width for that comes from the other two columns, and it takes two media
queries.** Nothing above will fit in an equal third of the pane: the key-pair
row alone wants ~650px and a third is 410px at a 1366px window, 478px at the
container's 1478px maximum. So `.pki-cols-3` — the configuration pane's grid,
and not the TLS pane's, which is the same class with two columns — gives the
middle column `1.3fr` against `0.85fr` either side from 1330px, and `1.4fr`
against `0.8fr` from 1530px, where the middle reaches ~669px and nothing on
either row wraps at all. The side columns lose nothing measurable to it: they
are label-and-input rows and eight short DN fields, and at 1366px they measure
354px and 374px against the 352px and 363px they were.

**Between 1330px and 1530px the rows shrink instead of wrapping**, which is
what `flex-wrap: nowrap` on `.pki-actions` and `.pki-export-row` inside that
media query is for. Flexbox assigns items to lines by their *max-content*
width before it shrinks anything, so a row that is 100px short does not narrow
its widest item — it moves the last control to a line of its own, which is
exactly the white space this removes. With `nowrap` the fixed-width controls
keep their width and the checkbox labels take the shortfall as wrapped text:
at 1366px *reuse the key pair below* is two lines of text inside a row that is
still one row. The `nowrap` is confined to the media query on purpose, because
the row's unshrinkable minimum — a 130px select plus a 235px button — is wider
than the 390px column the base `auto-fit` rule hands it below that, and an
overflowing flex line is a horizontal scrollbar across the whole page.
`tests/pki_page.js` asserts the property that survives both bands: every
control in each row shares one bottom edge, which one flex line always has and
two never do.

**Measured at 1366x768 in headless Chrome, with an empty store**: 2523px of
document, a 1159px configuration pane, a 605px extension list still in three
columns, and *Keys & Certificates* 1365px down. The budget in
`tests/pki_page.js` is 2700px and is there to catch a change that gives a whole
saving back at once.

**The density overrides live in `css/pki.css` and override `css/saml_common.css`
on purpose.** That sheet is linked by `pki.html` and by nothing else, so a bare
`.saml-row` in it reaches this page only — which is the whole reason they are
there rather than in the shared sheet, where they would reach five pages that do
not want them. Nothing in that block changes a font size, a border or a colour:
what is cut is margin and padding. A row that is hard to read is not denser.

## The key-pair pane is jwt_tools' pane

`client/src/key_material.js` is not new code. It is the bottom third of
`client/src/jwt_tools.js`, extracted: the algorithm table, generation, the
PEM/JWK conversion behind the format toggle, PBES2-encrypted PKCS#8, PKCS#12,
and the PBES2 JWE that password-protects a JWK set. `jwt_tools.js` is now a
**caller** of it — the page lost 340 lines and gained nothing — and the two
panes are identical rather than similar.

Two things came out of that extraction that are worth knowing:

* **`exportKeyPair()` returns the files rather than downloading them.** A
  keystore is a wire format that somebody else's tool has to read, so "the
  button said Downloaded" is a check on nothing. Returning `{name, data, mime}`
  is what lets `tests/pki_key_formats.js` produce all 49 cells of the matrix and
  read them back with `openssl pkcs12 -in`, `openssl pkey -in` and friends.
* **PKCS#12 for Ed25519 works, and the refusal that used to be there was
  misattributed.** PKCS#12 carries an Ed25519 key perfectly well — OpenSSL reads
  both bags. What failed was building the self-signed certificate the keystore
  has to wrap it in, because **pkijs cannot import an Ed25519 public key**. The
  certificate is `x509.js`'s job now, so the format works and the refusal is
  gone.

## The profile fills in the subject CN

Every profile carries a `cn` beside its extension defaults in `x509.js`'s
`PROFILES` — `RootCA`, `IntermediateCA`, `IssuingCA` for the three authorities,
`server` and `client` for the TLS pair, and `Signer`, `Recipient`,
`CodeSigner`, `EmailUser`, `OCSPResponder`, `TimeStampingAuthority`,
`SmartcardUser`, `kdc` for the rest. It is in the module rather than in the
page for the same reason the extension defaults are: the node tests then start
from what the browser starts from.

**They were *Example Root CA* and `localhost` until 2026-08-18**, and two
things went with the rename. The TLS profiles no longer default to a name a
local server answers to — issuing for `localhost` is now one field to type,
which is the trade for a store whose rows read as a hierarchy. And `server` and
`client` are short enough to be words somebody might type for themselves:
`isDefaultSubjectCN()` cannot tell those apart from one of ours and will
replace them on the next profile change, which was already true of `localhost`
and is more likely now.

Nothing fails without it. An empty subject is a legal DN and `x509.js` will
issue one — what it costs is a store holding four rows that read the same and a
chain view nobody can follow, after typing four names by hand to get to the
first handshake.

**The rule is three cases, and two of them are the reason it is a function
rather than a line.** `applyDefaultSubjectCN()` in `pki.js` fills an empty
field, **replaces** a field still holding any profile's default, and leaves
anything else exactly as it is:

* it has to MOVE with the profile, or picking *Intermediate CA* after *Root CA*
  issues an intermediate called "Example Root CA" — which chains correctly,
  validates, and reads as a bug in the chain view rather than in the form;
* and it must never touch a name somebody typed. The path that would lose one is
  not the profile dropdown but a **reload**: `onProfileChange()` runs on load,
  *after* `restoreState()` has just put their CN back in the field.

That is why the test is `x509.isDefaultSubjectCN()` — "is this any profile's
default" — rather than a comparison with the current profile's. By the time the
question is asked the dropdown has already moved on, and the value in the field
belongs to the profile that was selected a moment ago.

## The serial number is filled in, not left blank

`pki_serial` used to be an optional field: empty meant `issueCertificate()`
called `x509.randomSerialHex(16)` for you, and the value first appeared in the
store's *Serial Number* row, after the certificate had been signed. Since
2026-08-18 the field carries a random 128-bit serial from the moment the page
loads, `newSerial()` in `pki.js` puts a fresh one there after **every**
successful issue, and it is an ordinary editable input the whole time — type a
serial and that is what gets signed.

**Why it is refilled rather than left holding the last one.** Two certificates
from one issuer sharing a serial is precisely what a serial exists to prevent:
`(issuer, serial)` is the pair a CRL entry, an OCSP request and most caches and
pins are keyed on, so the second certificate is not merely a duplicate, it is
indistinguishable from the first to everything that revokes or looks one up.
A field that kept its value would produce that on the second press of the
button, silently, and with the store showing two rows that differ everywhere
else.

Three details in eight lines of code:

* `newSerial()` calls `saveState()` itself. `setVal()` is not a user edit, so
  the delegated `change` listener at the bottom of `onload()` never sees it and
  the value would not survive a reload — the field is `.stored` like every
  other one on this page.
* the refill is on the **success** path of `issue()`, where the old
  `setVal('pki_serial', '')` used to be. A failed issue leaves the serial
  alone, because the next thing that happens is another press of the same
  button.
* `issue()` still falls back to `x509.randomSerialHex(16)` when the field is
  empty. The field can be cleared, and a cleared field must not mean a
  certificate with no serial.

`theSerialIsFilledInEditableAndRotates()` in `tests/pki_page.js` asserts all
four through the form: the value on load, that it survives a reload, that the
certificate carries the serial the field was showing, that the field holds a
different one afterwards, and that a serial typed by hand is the one signed.

## The rest of the DN, and the SAN that has to match the CN

Since 2026-08-18 the CN is not the only field with something in it. **O, OU, L,
ST and C** come from `x509.DEFAULT_DN` — *Example Corp*, *Information
Technology*, *Austin*, *Texas*, *US* — and they behave **differently from the
CN on purpose**: they do not vary by profile, so `applyDefaultSubjectDN()` runs
once on load and fills only what is EMPTY. There is no "is this still a
default" question to answer and no replacement rule to get wrong. What it
cannot tell apart is a field somebody deliberately emptied — clear O, reload,
and O is back — which is the same trade the CN has always made, and the
alternative is remembering a negative in storage for every field on the page.

A DN with nothing in it but a CN is a legal name and a poor example of one.
These five put the encoding an operator actually meets — the PrintableString of
a country code, the ordered RDNSequence — in the first certificate somebody
issues here rather than the fifth.

**The subjectAltName is the one that matters most and shows least.** The two
serverAuth profiles now tick `subjectAltName` and fill it with `dns:` + their
own CN, because for a TLS server the CN is *not* what is checked — every
current browser ignores it. A server certificate issued here with the CN filled
in and the SAN empty is a certificate no client will accept, and neither the
page nor the store says so anywhere: it is a valid certificate, it chains, and
the only symptom is a browser refusing it for a reason it attributes to the
name.

`defaultSubjectAltName()` derives it from the profile's `extKeyUsage` rather
than storing it per profile, so a new server-ish profile cannot be added
without one. `applyDefaultSubjectAltName()` in `pki.js` then applies the same
three cases the CN uses — fill an empty field, **replace** one this page put
there, never touch what somebody typed — and the middle case is the one worth
having: picking *Root CA* after *TLS Server* has to take `dns:server` away
again, because a root asserting that name has no business carrying it and the
field is two columns from where the profile was chosen.

**It follows the CN, not the profile's own default**, which is the whole point
of it. Picking *TLS Server* and then typing the name you actually want is the
ordinary way to use this page, and a SAN left saying `dns:server` while the CN
says `www.example.test` is the same unusable certificate as no SAN at all — the
one this is here to stop. So `pki_dn_cn` carries an `onchange` of its own.

That makes "is this still ours?" a question `isDefaultSubjectAltName()` cannot
answer alone: once the CN has been typed over, the SAN derived from it is not
any profile's default and looks exactly like a name a person chose. So
`subjectAltNameIsOurs()` also accepts the last value this page wrote
(`lastAutoSan`, a module variable) and one that already says exactly what the
CN says — rewriting *that* to match a new CN takes nothing away. `lastAutoSan`
is deliberately not persisted: after a reload the page cannot tell its own
derived SAN from a typed one, and the safe reading of an unknown is that it
belongs to the reader. `tests/pki_page.js` asserts every one of those
directions.

## Every field has a tooltip, and that is where the notes went

On 2026-08-18 the standing notes and warnings came off the page and became the
`title` of the control they describe: the syntax lines under twelve extension
textareas, the paragraph under the store, the truststore's, the history's, the
two that printed under the *Profile* and *Signature Algorithm* dropdowns, and
the warning at the head of the TLS pane. The page went from **~2600px to
2196px** at 1366x768, and `tests/pki_page.js`'s budget came down from 3200 to
**2700**.

Three rules decided what moved:

* **Static prose moved.** A sentence that is the same on every visit is a
  tooltip; it was costing a line of page to say something the reader needs once.
* **Runtime output stayed.** `pki_status`, `pki_tls_status`, `pki_store_count`,
  `pki_tls_limits`, `pki_keys_storage_note` and the rest are what the page has
  just *done*. Most are empty until they have something to say, so they cost no
  height at rest, and a warning nobody hovers over is not a warning. The two
  that were always filled — the profile note and the signature-algorithm note —
  are prose selected by a dropdown rather than output, and they became the
  **dropdown's own** `title`, dynamically: `setTitle('pki_profile', …)` where
  it used to be `setText('pki_profile_note', …)`. The profile note has a
  fallback sentence because only seven of the fourteen profiles have one, and a
  control whose title is empty has no tooltip at all.
* **The folds stayed.** The seven `<details class="pki-more">` blocks are one
  summary line each and hold the prose that explains *why* something fails,
  which is the prose worth keeping readable and copyable rather than in a
  hover.

The consequence is that a field with no tooltip is now a field with no
explanation anywhere, so `everyFieldHasATooltip()` asserts every one of the
**131** controls on the page has one — on itself, on its `label[for=…]`, or on
a `<label>` around it, the three shapes this page uses. Three controls failed
it when it was first written, and all three for the same reason: a
`<label title="…">` with no `for` attribute is a label the browser associates
with nothing, so its tooltip was not the field's tooltip either.

## Not Before and Not After are pickers

The four validity fields — the certificate's pair and `privateKeyUsagePeriod`'s
— were text inputs holding ISO 8601 until 2026-08-18 and are `datetime-local`
inputs now. The picker's value is **local** time and what is encoded is the
instant, which `new Date("2035-06-07T08:09")` gets right without any conversion
in `validityDates()`.

Two things in eight lines of code, both of which fail silently:

* **A `datetime-local` rejects anything but `YYYY-MM-DDTHH:MM` by setting
  itself to EMPTY.** Every one of these fields is `.stored`, so the reload that
  upgraded somebody's page would have handed the input a `2026-01-01T00:00:00Z`
  it refuses, and their validity dates would have vanished with nothing
  anywhere to say why. `restoreState()` converts by `type`, not by a list of
  ids, so the two `privateKeyUsagePeriod` fields are covered by the same line.
* **It has a minimum width of its own** — a row of spin fields plus a calendar
  button, which Chrome will not draw narrower than their text. `width: 100%`
  alone does not make one fit a 174px half-column: it stops shrinking and hangs
  out over the column beside it, which is exactly the trap the `number` input
  was in. `css/pki.css` gives it `min-width: 0` and 0.78em, and the
  no-control-outside-its-column assertion is what proves it landed.

## Four things about certificates that are wrong and self-consistent

Each of these produces a certificate that parses, that `openssl x509 -text`
displays plausibly, and that something else then refuses. Each was real. All
four are why `tests/pki_x509.js` asserts by asking **OpenSSL** what it reads
rather than by reading back what this codebase just wrote.

**1. pkijs builds a Name as one multi-valued RDN.** A `Name` is an
`RDNSequence` — a SEQUENCE of SETs, one per attribute. `pkijs`'s
`RelativeDistinguishedNames.toSchema()` emits a single SET holding all of them,
which OpenSSL renders as `CN = host + O = Example + C = US`; the `+` is the tell.
It parses. It is simply a different name, so nothing chains to it. `buildDn()`
therefore builds the DER itself and hands it to pkijs as a parsed schema, which
`toSchema()` then returns verbatim.

**2. pkijs wraps an otherName in a second `[0]`.** GeneralName's otherName is
`[0] IMPLICIT OtherName`, so the tag *replaces* the SEQUENCE tag and the OID and
the `[0] EXPLICIT` value sit directly inside it. `pkijs.GeneralName`'s `toSchema()`
for type 0 wraps whatever it is given in a further `[0]`. `openssl x509 -text`
prints the name quite happily; `openssl verify` refuses the whole certificate
with:

```
error:0580009E:x509 certificate routines:ossl_x509v3_cache_extensions:reason(158)
```

which names no extension, no name and no field. `otherNameGeneralName()` builds
that DER by hand and returns a duck-typed object with the `toSchema()` its
callers use, and `buildAltName()` emits the `GeneralNames` SEQUENCE itself so
the hand-built name is accepted alongside the pkijs ones.

**3. The hash a signing key is IMPORTED with is the hash that lands in the
certificate.** pkijs reads `privateKey.algorithm` to build the
`signatureAlgorithm` field, so importing an RSA key as SHA-256 and then asking
`sign()` for SHA-512 produces a certificate whose declared algorithm and actual
signature disagree. `signerDescriptor()` derives the import parameters from the
**signature algorithm chosen**, never from the key. `openssl verify` is what
catches getting this wrong, and it reports it as a bad signature — naming no
hash.

**4. A date at or after 2050 must be a GeneralizedTime.** RFC 5280 §4.1.2.5.
pkijs picks UTCTime by default, and a 2050+ UTCTime is read as **1950** — a
certificate that expired seventy years ago, reported by every validator as
expired and by none as misencoded. `issueCertificate()` switches the type at the
boundary. A twenty-year root issued in 2031 crosses it.

And a fifth, which is not pkijs's fault: **an IP name constraint is the address
followed by its mask** — eight bytes for IPv4, not four. It is the one place a
general name's `iPAddress` is not just an address, and encoding it as one
produces a constraint that constrains nothing while looking correct in every
dump. `ipConstraintBytes()` does it; `nameConstraintsAreEnforcedByOpenssl()`
proves it by having OpenSSL **refuse** a name outside the permitted subtree.

## Ed25519 is signed by hand

`pkijs` cannot import an Ed25519 public key (`subjectPublicKeyInfo.importKey()`
throws *"Error during exporting public key: Incorrect key data"*) and cannot
sign with one. Both are avoidable:

* an SPKI **is** the exact DER that field holds, so it is parsed in with
  `fromSchema()` for **every** algorithm rather than only for the one that needs
  it. One path, so the odd one out is not the untested one.
* signing sets both AlgorithmIdentifiers to `1.3.101.112`, encodes the TBS,
  signs it with Web Crypto and drops the result in as the BIT STRING.
  `verifySignature()` has the mirror image, because `cert.verify()` has the same
  gap.

OpenSSL verifies the result, and `tests/pki_x509.js` issues a whole chain
through it.

### The browser has to have Ed25519 at all

Everything above is about `pkijs`; the *browser's* own Web Crypto is the other
half, and it is younger than this page. Chrome enabled Ed25519 in the Web
Cryptography API by default in **Chrome 137** — before that the implementation
is present but gated, and `generateKey`, `importKey` and `sign` naming
`{ name: 'Ed25519' }` all reject with *Algorithm: Unrecognized name*. So on an
older browser this page's `ed25519` key algorithm cannot produce a key, and
node — which has had Ed25519 for years — cannot see that: `pki_x509.js` and
`pki_key_formats.js` both pass. The tests image pins Chrome 121, so
`tests/pki_page.js` asks for the feature by name through
`browserFlags.addWebCryptoEd25519Flags()`, which is a no-op on a browser that
already has it.

Reading a certificate is the part that degrades gracefully rather than failing:
`describeCertificate()` falls back to the algorithm named in the
SubjectPublicKeyInfo when the key cannot be imported (see the bullet under
*"View certificate details"* below), so such a browser still describes an
Ed25519 certificate it cannot verify.

What did **not** degrade gracefully was issuing, and it is worth knowing why
the message was about the wrong call. *Generate Key Pair & Issue Certificate*
is one button — `generateAndIssue()` — and `generateKeys()` catches its own
error, leaving the two key fields exactly as they were. They therefore still
held the PREVIOUS certificate's pair, of a different algorithm, since changing
the dropdown is the only reason to generate again; the emptiness check let that
through, and issuing imported that pair under the newly selected algorithm and
reported

```
Could not issue the certificate: Failed to execute 'importKey' on
'SubtleCrypto': Algorithm: Unrecognized name
```

— `importKey` rather than `generateKey`, about a key the user had not asked to
certify. It now compares the private key field before and after (two successful
generations never produce the same key), so a failed generation stops there and
its own message stands.

## "View certificate details" and the page it opens

The store's *View certificate details* button hands the selected PEM to
`saml_cert.html` through `localStorage['saml_cert_view']` and opens it in a
second tab. That page is shared: ten pages send certificates to it, and until
2026-08-18 it parsed them with **node-forge**, whose `certificateFromPem()`
reads the SubjectPublicKeyInfo eagerly and supports exactly one algorithm in
it. So every EC and every Ed25519 certificate — which is **every certificate
this page issues except the RSA ones** — arrived at

```
Parse error: Cannot read public key. OID is not RSA.
```

a message about a public key, on a page that had not got as far as showing the
subject, and produced by the page you were sent to rather than the one that
issued the certificate.

It parses with `x509.js` now, which is the module the certificate was issued
with, so there is one description of a certificate in this tree rather than
two: every extension the page can build it can also read back. Three things
came with the change:

* **`extensionValueText()` moved into `x509.js`** from `pki.js`, which had it
  as `describeExtensionValue()`. `describeExtension()` returns a string for
  some extensions, a number for others, an array for the list-shaped ones and
  an object for `basicConstraints`, `nameConstraints` and the authority key
  identifier — a caller that renders only the shapes it has met prints
  `[object Object]` for the rest.
* **`describeCertificate()` no longer needs Web Crypto to answer.** The two
  fingerprints are the only part of it that does, and they are digests of a
  public document; `fingerprintsOf()` returns nulls with a warning rather than
  throwing, and the page prints a note in those two rows. The public key falls
  back to the algorithm named in the SubjectPublicKeyInfo when
  `describePublicPem()` cannot import the key — which is what a browser with
  no Ed25519 in Web Crypto does with an Ed25519 certificate. The certificate
  says what it is; a page that cannot import the key can still say so.
* **`saml_cert.js` takes the FIRST certificate out of a pasted bundle.** A
  chain is what an IdP's metadata carries, and `pemToDer()` strips every armour
  line before decoding, which turns two certificates into one unparseable blob
  and an error about ASN.1 rather than about a chain.

The return link needed `pki.html` in its map as well, or the reader lands on a
page whose only way back is the browser's own button.

`theDetailsPageReadsEveryKeyAlgorithm()` in `tests/pki_page.js` asserts this
through the button, in the tab it opens, once per key algorithm — **EC first**,
since RSA is the one algorithm the old parser got right. Neither module's own
tests could have caught it: `pki_x509.js` never opens a browser, and
`pki_page.js` had never left the PKI page.

## The store, and the private-key opt-out

`pki_store.js` keeps every object under one localStorage key as a JSON array —
one key rather than one per object, because the order is the hierarchy's order
and a store spread over *n* keys has no order at all.

The repository's standing rule is that key material stays out of localStorage,
with an opt-out on every protocol that generates a key pair. Here it is applied
**the way the SD-JWT VC workflow applies it rather than the way the SAML page
does**, because there is not one key pair but a collection, and the certificates
in it are public documents:

* the preference (`pki_save_keys`, on by default) governs the **private half
  only**. Clearing it strips `privateKeyPem` from every entry already stored and
  from every entry written afterwards; subjects, certificates and public keys
  stay.
* the enforcement is **central** — one write path, `writeRaw()` — because a
  guard per call site is a guard somebody forgets, and this failure is silent in
  the reassuring direction: the box unticks, the note appears, and the key goes
  on being written.
* an entry without its private key is **not useless**, and the page says which
  it is: the certificate can still be inspected, exported and used as a trust
  anchor. What it cannot do is sign or be presented as a client certificate, so
  `canSign()` is what every caller asks and such a CA is not offered in the
  "Signed by" dropdown at all — offering one produces a Web Crypto error two
  clicks later that names neither the CA nor the missing key.

`tests/pki_page.js` reads localStorage directly for all of this, for the same
reason `tests/keypair_storage_optout.js` does on the other four protocols.

## The list fields are text, and that is deliberate

`subjectAltName`, the CRL distribution points, the AIA entries, the policies,
the name constraints and the custom extensions are textareas with a small
documented syntax rather than rows of widgets. Three reasons: an editor built
out of widgets can only express what its widgets anticipated, and the point of
this page is issuing the certificate that is wrong in **exactly one way**; a
line of text is something an operator can paste from a ticket; and it is input a
test can drive exhaustively. The syntax is documented on the page beside each
field, parsed by the `parse*()` functions in `pki.js`, and checked directly by
`tests/pki_page.js`.

```
dns:example.com            ip:10.0.0.1        ip:2001:db8::1
email:user@example.com     uri:https://x/y    rid:1.2.3.4
upn:user@EXAMPLE.COM       krb5:host/h@REALM  dirname:CN=alt,O=Example
othername:<oid>:<base64 DER>

permit dns:example.com     exclude ip:10.0.0.0/8      (name constraints)
ocsp:http://ocsp/          caissuers:http://ca/       (AIA / SIA)
1.3.6.1.4.1.99999.1|cps=https://c/|notice=text        (policies)
<oid>|critical|<base64 DER>                           (any extension at all)
```

A malformed line is **refused by name** rather than dropped. A certificate
quietly missing a name somebody typed is the failure this whole page exists to
avoid.

## The TLS test, and why the page has no option to make it itself

Every other page here offers the choice: call from the browser, or proxy through
the api. **This one does not, and the omission is the design.** A browser cannot
answer any of the questions the pane exists to ask:

* the **client certificate** is chosen by the browser's own UI from the
  browser's own store, so the certificate issued thirty seconds ago on this page
  is not offered — and "present none" is not offerable either;
* the **truststore** is the platform's, so *"does this chain verify against my
  root, and only mine"* is unaskable;
* the negotiated **version, cipher, ALPN protocol and the server's chain** are
  not exposed to script at all;
* and a failed handshake reaches script as a generic network error with **the
  alert discarded** — the one genuinely informative thing.

So `POST /tls/connect` opens the socket and reports both sides. A browser-side
option would be a button that answers a different question badly, and every
answer it gave would be about the browser. `tests/pki_page.js` asserts that the
pane contains no radio button, so this cannot be "fixed" by mistake.

### A completed handshake is not an accepted client certificate

This is the sharpest thing in `api/tls_probe.js` and the assertion that earns
its keep.

Under **TLS 1.2** a server that refuses a client certificate refuses it during
the handshake, and `secureConnect` never fires. Under **TLS 1.3** the client
sends its Certificate and Finished **last** — the handshake is complete from the
client's point of view the instant it has written them — and the server's
verdict arrives afterwards. It arrives in one of two ways, and neither is
visible in the handshake:

* a **post-handshake alert** (`certificate required`, `bad certificate`,
  `unknown ca`), or
* the server simply **hangs up**. Node's own TLS server does exactly this when
  `rejectUnauthorized` refuses a client certificate: the socket closes with no
  alert at all.

An implementation that resolves on `secureConnect` therefore reports a happy
mutual-authentication connection to a server that rejected the certificate a
millisecond later, and its mutual-auth probe answers *"not required"* for every
TLS 1.3 server on earth. So the socket is **read for a moment** after the
handshake (`POST_HANDSHAKE_GRACE_MS`, 750 ms): an alert, a close or the server's
first bytes all end the wait, and only silence spends the whole grace period.
`handshakeUsable()` is what every verdict is computed from, and it is not
`connected`.

### A client certificate is sent with its chain

The page sends `chainPems()` — the leaf and its intermediates, leaf first — and
not the leaf alone. A server verifying a client certificate has to build a path
from what the client **sent** to an anchor it holds, so a leaf issued by an
Issuing CA and presented by itself is unverifiable to a server holding only the
root.

This one is worth knowing because of how it fails. Node's TLS server answers an
unverifiable client certificate by **resetting the connection with no alert at
all**, so the far end reads as *"the server refused my certificate"* when what
it could not do was find the issuer — and the mutual-auth probe duly reports
`required-and-rejected` against a server that would have been perfectly happy.
It was found by driving the page end to end against a real server, and it is
now asserted from both sides in `tests/api_tls_probe.js`: the leaf alone must
fail, the chain must work. Asserting only the second would pass against a
server that verifies nothing.

The **root** is deliberately not sent: a server that does not already hold it
will not trust it because we offered it.

### Asking the server what *it* saw

Everything the pane reports so far is **this end's** account of the handshake,
and this end is the party that already knows what it sent. Three things exist
only on the far end:

* **which chain the server built** out of what arrived. The leaf-without-its-
  intermediates mistake above is invisible from the client — it looks like a
  refusal;
* **which anchor it verified against**, which is the whole question a private CA
  raises;
* **whether it accepted the certificate at all** — which, under TLS 1.3, the
  client has not been told by the time its own handshake finishes.

So `POST /tls/connect` takes an optional `httpRequest: { path }` and, after the
handshake, writes **one GET on the same socket** and reports the response
verbatim: status line, headers, body. The same socket is the point — a second
connection is a different connection and says nothing about this certificate on
this handshake. The pane has a checkbox and a path field for it (`/tls/whoami`
by default) and renders the answer as *"What the server saw"*, tabulated when the
body is the JSON the mock STS publishes and shown as text otherwise, because a
pane that discarded an unrecognised body would be useless against every server
that is not the mock.

What bounds it is narrower than the rest of the endpoint and needs no setting of
its own, for the reason `POST /krb5/spnego` needs none: **the method is GET and
the path is the only thing a caller contributes.** Every header is built in
`tls_probe.js`; a path with CR, LF or whitespace in it is refused by name
(`ETLSBADHTTPPATH`) rather than escaped, since escaping means deciding which of
two things the caller meant and a newline in a request line is somebody else's
header. `Connection: close` is sent so the end of the response is an event
rather than a guess, the body is capped by `maxContentLength`, and a server that
answers and then holds the socket open is bounded by `HTTP_RESPONSE_GRACE_MS`
(2000 ms, restarted on every chunk, and inside `callTimeout` either way).

Two things in the reader are byte-level on purpose, and both were found rather
than anticipated:

* **A chunked body is de-framed in BYTES.** Node's own HTTP server answers
  chunked whenever it does not know the length in advance, which is most of the
  time, so this is the common path and not an edge case. A chunk size counts
  bytes; a JavaScript string is indexed in UTF-16 code units — so a decoder
  working on text walks off the end of a chunk the moment the body contains a
  multi-byte character, and the result is *valid JSON followed by a fragment of
  hexadecimal*, from a server whose only crime was writing prose with em dashes
  in it.
* **A FIN with no bytes behind it is the hang-up.** `'end'` fires before
  `'close'`, so recording the peer's close only in the `'close'` handler leaves
  `usable` true for a server that answered nothing — which is precisely the TLS
  1.3 client-certificate rejection this file's longest comment is about. Both
  cases are asserted in `tests/api_tls_probe.js` and both are mutation-tested.

The far end of all this in the suite is the **mock STS**, which grew two HTTPS
listeners for it: 8443 asks for a client certificate and never refuses one (so
it can report *why* something did not verify), 9443 requires one (so reaching it
is itself the proof). Its client truststore starts empty and is filled at
runtime over its plain HTTP port, because the CA in question is generated in a
browser minutes before the connection. See `docs/mock-sts.md`.

### `usable`, not `connected`

Because of the TLS 1.3 ordering above, *"did this connection actually work"* has
one answer and it is not `connected`. The api computes it once, as `usable` on
every report, and every caller reads that field — the page included. The page
briefly re-derived it, and duly announced *"Handshake completed"* for a server
that had already hung up.

### Mutual authentication is measured, not read

Node exposes no `CertificateRequest`: there is no event and no property, and it
is consumed inside OpenSSL. The only way to find out whether a server *requires*
a client certificate is to try both ways, which is what `mutualAuthProbe` does —
one handshake with the certificate and one without, reported side by side, with
five possible verdicts:

| verdict | means |
|---|---|
| `required` | worked with the certificate, failed without it |
| `not-required` | worked both ways (it may still have asked optionally) |
| `certificate-rejected` | worked **without** the certificate, failed with it |
| `required-and-rejected` | neither worked, both reached TLS — the server wants one and refused this one, usually an untrusted issuing CA |
| `unknown` | neither reached a handshake; the errors are about reaching the server |

That fourth row is the case an operator hits most, and it is exactly the one a
single connection cannot tell from `required`.

### What bounds the endpoint

Same accounting as the Kerberos relay, plus one setting of its own:

* **the address policy**, reused from `api/ssrf_guard.js` rather than
  reimplemented — `tls.connect` is a raw socket, so the guard's axios
  interceptor and agent hooks never see it. It asks `guard.blockedRangeFor()`
  for the decision, because two implementations of an address policy is one
  implementation and one hole.
* **`tlsAllowedPorts`**, the ninth setting in `api/env/*.js`. This endpoint is
  broader than the Kerberos relay in one specific way: **there is no payload
  shape to bound it with**, because a ClientHello sent to port 22 is a perfectly
  well-formed ClientHello. So the ports do all of that work. `"any"` is spelled
  as a word so enabling it cannot be a plausible typo; `local.js` and
  `docker-tests.js` set it, and say why.
* **three deadlines**, and the name lookup gets one of its own for the reason
  `api/krb5_relay.js` records: until a name is an address, neither of the other
  budgets has started. A call is bounded by `connectionTimeout` (resolve) +
  `connectionTimeout` (connect) + `callTimeout` (handshake), and
  `everyDeadlineIsSeparateAndArmed()` fails against an implementation that
  expresses the last two with one timer.
* **`maxContentLength`**, applied to the certificate chain that comes back.

**The handshake is always made with `rejectUnauthorized: false`, and the verdict
is reported rather than enforced.** That looks like the wrong default and is the
only useful one: the question is *"what does this server present, and does it
verify against the truststore I chose"*, and aborting on a verification failure
throws away the chain that would explain it. Node computes `socket.authorized`
and `socket.authorizationError` either way, so nothing is lost — the caller gets
the certificate, the alert **and** the verdict, and the response says
`authorized: false` in as many words.

Note also that supplying trust anchors **does not** quietly add the platform
roots. A chain that verifies for a reason the caller did not ask about is not an
answer.

## Tests

| Test | Covers | Skips? |
|---|---|---|
| `tests/pki_x509.js` | ~240 certificates over every (issuer key, signature algorithm) pair × every subject key algorithm; every extension read back by OpenSSL; the whole set at once; all 14 profiles; a four-deep chain; name constraints, pathLen and an unknown critical extension actually **refusing** something; serials; the 2050 boundary; key identifiers | never |
| `tests/pki_key_formats.js` | 7 algorithms × 4 formats × password on/off, read back by OpenSSL; a PKCS#12 carrying a whole chain; the refusals by name; PEM↔JWK round trips | never |
| `tests/api_tls_probe.js` | the address policy on a raw socket, the port allowlist, truststore selection, the mutual-auth measurement (all five verdicts), the three deadlines, that **every path settles**, and the ask-the-server request — the path refusals, the chunked de-framing in bytes, and a hang-up not reading as success | never |
| `tests/pki_page.js` | the hierarchy built through the form, the *View certificate details* hand-off read back on `saml_cert.html` for every key algorithm, the store surviving a reload, the private-key opt-out in both states, the serial number (shown, persisted, signed, rotated, and typed over), the subject-DN defaults and the profile subjectAltName, a tooltip on every one of the 131 controls, the validity pickers and the ISO-8601 values an older build stored, the list-field syntax, the TLS test end to end, no browser-side TLS option — and the **layout**: five panes and not six, the three headings the merge left behind, the extension list's column count measured from where the cards landed, no horizontal scroll, no control drawn outside its column, and every folded note still holding its prose and no control | needs the client; the TLS section skips without an api |
| `tests/pki_mutual_tls.js` | the same page against a server that **answers back**: a client certificate issued through the form, presented with its chain to the mock STS's two listeners, and the **server's own account** of the connection — the chain it built, the anchor it verified against, and `required` told apart from `required-and-rejected` by trusting the CA between two otherwise identical runs | needs the client, the api and `STS_TLS_URL` |

The first three are node-only and need **`openssl` on the PATH** (the tests image
installs it); they say so rather than skipping if it is absent, because a test
that quietly stops asserting is worse than one that fails.

## Adding to this page

* A new **key algorithm** is one entry in `KEY_ALGS`. The dropdown is filled
  from it, so nothing in the markup changes — but add an expectation to
  `everyAlgorithmGeneratesAKeyOpensslRecognises()`, which asserts the two lists
  match so a new algorithm cannot arrive untested.
* A new **signature algorithm** is one entry in `SIG_ALGS` plus its `kind`, which
  is what filters it to the keys that can produce it.
* A new **profile** is one entry in `PROFILES` and `PROFILE_ORDER`.
  `everyProfileIssuesWhatItPromises()` will issue it and check what it claims.
* A new **extension** needs a builder, a branch in `buildExtensions()`, a branch
  in `describeExtension()`, a control in `pki.html`, a case in
  `everyExtensionIsWrittenAndReadBack()` with **OpenSSL's own words** as the
  expectation, and an entry in the id list `thePageOffersWhatTheModulesDefine()`
  checks. Miss the last and the extension is one nobody can set, with nothing to
  say so.
* **A new block of fields is not a new pane.** Everything that is an input to
  *Generate Key Pair & Issue Certificate* goes inside `pane_config`, under a
  `.pki-group` heading if
  it needs a name — `theConfigurationIsOnePane()` asserts the pane list by name,
  so a fourth pane fails there rather than being noticed by somebody a month
  later. The same section asserts that a `<details class="pki-more">` holds no
  `input`, `select`, `textarea` or `button`: fold prose, never a control.
