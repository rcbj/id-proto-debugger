# SAML 1.1 in the SAML protocol workflow

Scope: the **Protocol Version** selector on `saml_request.html` and everything
that follows from choosing **SAML 1.1** — what is sent, what comes back, which
settings stop applying, and what the four tests hold it to. SAML 2.0 is the
workflow's default and is not described here except where the two differ.

Read this before touching `client/src/saml_request.js`,
`client/src/saml_response.js`, `POST /samlartifactctx` or `handleSamlAcs()` in
`api/server.js`. The identity provider at the other end is `sts/saml/saml11_sso.js`,
whose own notes are in that submodule's `saml/CLAUDE.md`.

---

## THE ONE SENTENCE THIS FILE EXISTS TO PREVENT SOMEBODY WRITING

> "SAML 1.1 is SAML 2.0 with older element names."

It is not, and almost everything below is a consequence of the difference:
**SAML 1.1 has no request message.** There is no `<samlp:AuthnRequest>` in the
specification. The browser profiles (`saml-profile-1.1` sections 4.1 and 4.2) are
**identity-provider-initiated**, and a flow begins when a browser arrives at the
*inter-site transfer service* carrying a `TARGET`.

Six things follow, and each of them is a place where a reader who knows 2.0 will
expect the opposite:

| | SAML 2.0 | SAML 1.1 |
|---|---|---|
| the request | a signed, optionally encrypted `<samlp:AuthnRequest>` | four query parameters, unsigned, and **not a standard** |
| the service provider names itself | `<saml:Issuer>` on the request | it cannot — `providerId`, a path segment, or the identity provider GUESSES from the `TARGET`'s origin |
| where the response goes | `AssertionConsumerServiceURL` on the request | Shibboleth's `shire` parameter, or nothing |
| choosing a response binding | `ProtocolBinding` on the request | **nothing in the protocol** — the identity provider decides |
| Single Logout | both directions | **does not exist** |
| the relay state | `RelayState` | `TARGET`, which is also supposed to be a URL |

## WHAT THIS PAGE ACTUALLY SENDS, AND WHY IT IS NOT A STANDARD

Shibboleth 1.x bolted a request onto the profile and it is the one every real
SAML 1.1 service provider sends: a redirect to the identity provider carrying
`shire`, `target`, `providerId` and `time`, identified by the profile URI
`urn:mace:shibboleth:1.0:profiles:AuthnRequest` and advertised in metadata as a
`SingleSignOnService`. **It is supported, it is not a standard, and the page says
so** — a SAML 1.1 service provider that could not tell an identity provider where
to send the assertion would be a debugger nobody could point at anything.

`saml11RequestParams()` builds it. Six parameters, and **two of them are
non-spec and are named as such everywhere they appear**:

| Parameter | What it is |
|---|---|
| `TARGET` | the relay state. See below — this is the one worth reading twice. |
| `shire` | the assertion consumer URL. Shibboleth's name for the ACS. |
| `providerId` | this service provider's identifier. Becomes the assertion's audience. |
| `time` | seconds since the epoch. Read, logged and enforced nowhere by the mock. |
| `profile` | **non-spec.** `post` or `artifact` — which browser profile to answer with. |
| `format` | **non-spec.** A NameIdentifier format, when one is selected. |

An identity provider that does not know the last two ignores them, which is why
sending them costs nothing. Without `profile` the identity provider's own default
decides, and the binding a test *thinks* it is exercising is not the one that ran.

### `TARGET` carries the relay state, and that deserves a paragraph

The profile intends `TARGET` as the URL of the resource the person was trying to
reach. What the binding actually **guarantees** is that it comes back byte for
byte, and that guarantee is the whole of what this page needs from it — exactly
as `RelayState` is used on the 2.0 side. The Browser/Artifact flow carries the
API's `art:<id>` context handle in it, and **there is nowhere else in SAML 1.1 to
put one**: `RelayState` did not exist until 2.0.

That is why `handleSamlAcs()` in `api/server.js` reads `TARGET` as well as
`RelayState`. Reading only `RelayState` made every 1.1 artifact resolution fail
with *no artifact context*, which reads as an expired stash rather than as a
parameter the handler never looked at.

---

## THE THREE BINDINGS, AND WHAT EACH ONE MEANS HERE

The selector keeps its three options and they keep their *shape*; only the
spellings change, because "HTTP-Redirect" names a SAML 2.0 binding URI that does
not exist in 1.1.

| Selection | The request travels | The response comes back |
|---|---|---|
| **Redirect** | a top-level `GET` to the inter-site transfer service | Browser/POST (section 4.2): a form POST of `SAMLResponse` to `shire` |
| **POST** | a form POST of the same parameters | Browser/POST |
| **Artifact** | a top-level `GET` | Browser/Artifact (section 4.1): a redirect to `shire` with `SAMLart`, resolved by the API over SOAP |

Two notes on that table.

**Redirect and POST differ only in how the REQUEST travels**, which is the same
thing the SAML 2.0 selector means and is worth saying because the response is
identical. **SAML 1.1 defines no POST-bound request at all** — that option sends
the same non-standard parameters as a form, which the mock STS reads and a
Shibboleth identity provider would not.

**There is no redirect-bound RESPONSE in SAML 1.1**, so the fallback the 2.0
workflow uses on a backend-less deployment has no equivalent. A static site needs
the Lambda@Edge ACS landing (`infra/edge/saml_landing.js`) for SAML 1.1 to work at
all — the version notice on the page says so when there is none — and the Artifact
profile needs the API whatever the deployment (that landing refuses a `SAMLart` by
name and explains why, which is the right answer for both versions). The landing
reads `TARGET` as well as `RelayState`, for the reason below.

### The artifact is a different artifact

A SAML 2.0 artifact is 44 bytes, type `0x0004`, and stands for a **message** — the
whole `<samlp:Response>` that would otherwise have been POSTed, handed back inside
an `<ArtifactResponse>`. A SAML 1.1 artifact is **42 bytes, type `0x0001`, and
stands for an ASSERTION**; the `<samlp:Response>` around it is built at resolution
time, which is what lets it carry `InResponseTo` naming the SOAP request and a
`Recipient` naming whoever asked. 2.0 added a two-byte `EndpointIndex` after the
type code, which is the two bytes of difference — a relying party that assumes the
2.0 layout reads a 1.1 artifact's `SourceID` two bytes late and matches no
identity provider it knows.

`buildArtifactResolveMessage()` in `api/server.js` is the fork. It builds a
`<samlp:Request>` carrying an `<AssertionArtifact>` for 1.1 and an
`<ArtifactResolve>` for 2.0, and three details in it are load-bearing:

* **`RequestID`, not `ID`.** `xmldsig.signEnveloped()` searches `ID`, `AssertionID`
  and `Id` for the reference URI and finds none on a SAML 1.1 request — told
  nothing, a signer of that shape invents an id and points the reference at what
  it invented. So the reference is passed explicitly.
* **The signature is the FIRST child.** SAML 1.1's `RequestAbstractType` sequence
  is `RespondWith*`, `ds:Signature?`, then the query or the artifact. A 2.0
  `<ArtifactResolve>` has an `<Issuer>` and the signature follows it.
* **A key is optional.** Neither version requires this message be signed, and
  SAML 1.1 has no request to sign in the first place, so `POST /samlartifactctx`
  no longer refuses without one — it says out loud that it is sending an unsigned
  request. (That refusal used to make "the service provider generated no key
  pair" fail in a call whose error text names `privateKeyPem` and nothing else.)

An artifact is **one-shot** in both versions (`saml-bindings-1.1` section 3.2.3):
resolving it destroys it. That is the identity provider's rule rather than this
page's, and it is why the response page is reached exactly once per artifact.

---

## WHAT IS SWITCHED OFF, AND WHY IT IS SWITCHED OFF RATHER THAN HIDDEN

`applyVersionAvailability()` is the one place this is decided. Five settings have
no meaning in SAML 1.1:

| Setting | Why |
|---|---|
| Username hint | goes in `<saml:Subject>` on an AuthnRequest |
| Digitally sign the AuthnRequest | there is nothing to sign |
| Encrypt the AuthnRequest | there is nothing to encrypt |
| Logout | SAML 1.1 has **no Single Logout** — absent from the protocol |
| The three SLO endpoint fields | nothing publishes them |

**Each is disabled AND greyed, and both halves are needed.** The class is what a
reader sees; `disabled` is what a Return keypress in a text field obeys. A block
that only *looks* dead still submits, and `callIdp()`'s own refusal is then the
first thing that says anything — by which point the browser has been handed to an
identity provider. `pki.js`'s `disableTlsPane()` makes the same argument at pane
scale and `tests/pki_page.js` asserts the same two properties separately.

The greying is done with **colours rather than `opacity`**, for `pki.css`'s
reason: `opacity` makes a stacking context, and the one line in a disabled block
that has to stay readable — the notice saying why — could then not be brought back
to full contrast by any rule of its own.

**`signEnabled()` and `encEnabled()` read the VERSION before the checkbox**, and
that is the enforcement rather than a convenience. Both checkboxes are persisted,
so a page restored from a 2.0 session arrives with *sign* ticked; a caller that
read the checkbox alone would try to sign a document that does not exist.

### The SP key pair is NOT switched off, and that is deliberate

It looks inconsistent beside "there is nothing to sign", and greying it would take
away two things that work:

* it signs the SOAP `<samlp:Request>` that resolves an artifact, and
* it is the `KeyDescriptor` in the SP metadata this page downloads.

So the section stays **visible** (`onSignChange()` forces it open on 1.1, even
though the checkbox above it is clear) and enabled, and carries a note saying what
the key is for. `tests/saml11_options.js` asserts all of that, precisely so a
later sweep that greys "everything to do with signing" fails instead of shipping.

SAML **1.0** stays reference-only. It is 1.1 with a `MinorVersion` of 0, nothing
here builds one, and `callIdp()` refuses by name.

---

## THE METADATA DECIDES THE VERSION

A SAML 1.1 descriptor declares
`protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol"`, and loading
one **moves the Protocol Version selector and says so on the status line**.

It is applied only when the document is unambiguous — one version, and not the one
already selected — because an unannounced change to a selector the user set is
worse than the wrong default. Left on 2.0 in front of a 1.1 descriptor the page
would build an `<AuthnRequest>` and post it at an inter-site transfer service, and
the refusal would read as an identity provider problem.

Three things about reading that document:

* **A SAML 1.1 identity provider has ONE SSO endpoint**, which its metadata names
  once per profile it answers — Browser/POST, Browser/Artifact, and Shibboleth's
  request profile. `parseMetadata()` therefore puts that one address in **all
  three** SSO fields. Reading the document as though the fields were exclusive
  populates none of them, and the page then reports *no IdP endpoint for the
  selected binding* about a document that named it three times.
* **In a 1.1 descriptor the `Binding` attribute carries a PROFILE identifier**
  rather than a binding one — the 1.1 profiles bundle their binding into the
  profile. That reads wrong and is what Shibboleth's own metadata does. The SP
  metadata this page *builds* follows the same rule.
* **The artifact resolution address is published twice** — once as an
  `ArtifactResolutionService` inside the `IDPSSODescriptor` and once as an
  `AttributeService` on an `AttributeAuthorityDescriptor`, because a Shibboleth
  service provider reads the second one and will not look for it inside the first.
  Either will do here, so the second is a fallback.

The SP metadata `buildSpMetadata()` produces for 1.1 differs from the 2.0 one in
four ways, and every one of them is a claim an identity provider acts on:
`protocolSupportEnumeration` names the 1.1 protocol, the assertion consumer
endpoints carry the two profile URIs, there is **no** `SingleLogoutService`, and
there is **no** `AuthnRequestsSigned`.

---

## READING THE RESPONSE

`client/src/saml_response.js` reads both versions. Every field it shows is spelled
differently in 1.1, and each of these produced a **blank cell rather than an
error** when the page knew only 2.0:

| What | SAML 2.0 | SAML 1.1 |
|---|---|---|
| message id | `ID` | `ResponseID` |
| version | `Version="2.0"` | `MajorVersion="1" MinorVersion="1"` |
| issuer | a `<saml:Issuer>` child | an **attribute** — and often absent from the Response, the assertion carrying it instead |
| where it was sent | `Destination` | `Recipient` |
| assertion id | `ID` | `AssertionID` |
| the subject | `<saml:NameID>` | `<saml:NameIdentifier>` |
| the audience | `<saml:AudienceRestriction>` | `<saml:AudienceRestrictionCondition>` |
| an attribute's name | one `Name` URI | `AttributeName` + `AttributeNamespace` |

### The status code is a QName, and this is the one that matters most

SAML 2.0's `StatusCode/@Value` is a URI ending `:status:Success`. **SAML 1.1's is a
QName** — `samlp:Success`, resolved against the namespace declarations in scope, so
a strict reader sees `{urn:oasis:names:tc:SAML:1.0:protocol}Success`.

The old check was `indexOf(':status:Success') >= 0`, which is false for every SAML
1.1 success. A sign-in that worked would render a red status **and close its
Operations History row as a FAILURE**, which is the worst possible way to be wrong
about a working flow. `isSuccessStatus()` matches the local part after the last
colon, which covers both spellings and still refuses a lookalike.

### The confirmation method IS the profile

`saml-profile-1.1` section 4.1.1.4 requires
`urn:oasis:names:tc:SAML:1.0:cm:artifact` for Browser/Artifact and section 4.2.1.4
requires `...:cm:bearer` for Browser/POST. They are not interchangeable and they
are not decoration: the confirmation method is the assertion's own statement of
**how it reached the relying party**, so an artifact-profile assertion confirmed as
`bearer` claims to have travelled through the browser when it did not.

**A relying party that does not check works perfectly with either**, which is
exactly why the tests assert it per binding rather than once. `DoNotCacheCondition`
is the same shape of check: the Browser/POST profile's single-use policy, present
on a POSTed assertion and absent from an artifact one.

### Signature verification resolves through `AssertionID`

`common/xmldsig.js`'s `findById()` was taught `AssertionID`, `ResponseID` and
`RequestID` alongside `ID`/`Id`/`id`. A verifier that knows only the first three
resolves `#<id>` to **nothing** on a signed SAML 1.1 document and reports
*referenced element not found* — which reads like a stripped element rather than
like a name the list did not have.

Nothing here saves a subject for Single Logout on a 1.1 response, and that is
deliberate rather than an omission: there is no LogoutRequest in the protocol to
spend it on, and writing one would leave the request page's Logout button looking
armed on a version where it is disabled.

---

## THE FOUR TESTS, AND WHY THERE ARE FOUR

| Test | What it drives | Needs |
|---|---|---|
| `tests/saml11_sso.js` | the DEBUGGER's pages, once per binding — the full round trip | the mock STS, a browser; artifact also needs the api |
| `tests/saml11_options.js` | which settings apply and which are off, the request shape per binding, the 1.1 SP metadata | a browser and nothing else |
| `tests/sts_saml11.js` | the mock STS's identity provider, over HTTP, with a relying party it writes itself | the mock STS, no browser |
| `tests/saml_operation_history.js` | the shared log — its reference-only refusal case is SAML **1.0** now | a browser |

**There is no Keycloak half of any of them and there will not be one.** Every
other browser-SSO job in this suite runs once per identity provider, because a
mock that is quietly more permissive than the real thing passes every test written
against it alone. That argument still holds and there is nothing to act on it
with: Keycloak dropped SAML 1.1 years ago.

`sts_saml11.js` is what compensates. It writes the relying party **itself** rather
than importing the debugger's — the same reasoning `sts_dpop.js` gives for writing
its own DPoP client — so a shared misunderstanding between the two ends of the
exchange cannot pass unnoticed. It is also almost entirely negatives, several of
which a browser cannot easily reach: an artifact resolved twice, an `InResponseTo`
on a profile with no request, a signature reference through the real
`AssertionID`.

**It was called `saml11_sso.js` until 2026-08-25**, and the rename is the whole of
the difference: that name now belongs to the Selenium job, because it is
`saml_sso.js`'s sibling and runs the same round trip through the same pages.

### They share a JOB_LOCK, and that is not optional

`sts_saml11.js` turns `saml11.signAssertion` and `saml11.signResponse` **off** one
at a time, flips `saml11.defaultProfile` to artifact, and turns
`saml11.autocreateApplications` off. Each is restored, and none of them instantly
— so a browser round trip running inside that window gets an unsigned assertion, a
profile it did not ask for, or a 400 for a relying party it just named.
`saml11_sso.js` asserts a valid signature and the confirmation method for its
binding, so it would fail naming the signature or the profile and **nothing would
say which other job did it**. `JOB_LOCKS` in `tests/run-report.js` puts all four
binding jobs and `sts_saml11.js` on `sts-saml11`.

`saml11_options.js` is deliberately outside that lock: it needs no identity
provider at all.

### Running one by hand

```bash
# The whole SAML suite, both versions, against the mock STS only — the fastest
# loop, and the one that includes SAML 1.1 (the Keycloak half cannot).
./local-run-tests.sh --saml-only=sts

# One binding, with a stack already up. SAML11_METADATA_URL names the mock's
# per-relying-party 1.1 descriptor; nothing has to be provisioned, because that
# service mints one for any identifier asked for.
SLUG="app-$(printf '%s' "$SAML_SP_ENTITY_ID" | sha256sum | cut -c1-12)"
SAML11_METADATA_URL="https://localhost:8081/saml11/metadata/${SLUG}" \
SAML_BINDING=artifact CONFIG_FILE=./env/local.js \
  node tests/saml11_sso.js --url http://localhost:3000
```

`SAML_SP_PRIVATE_KEY` and `SAML_SP_CERT` have to be in the environment, exactly as
for the SAML 2.0 tests — see `common/sp_keypair.js`.

---

## WHAT IS DELIBERATELY NOT HERE

* **No encrypted assertion.** SAML 1.1 has no `<saml:EncryptedAssertion>` element,
  and the mock's browser profiles encrypt nothing for a stronger reason than
  2.0's: there is no request to carry a recipient certificate in even in
  principle. The response page's Decrypt pane still works on any
  `<xenc:EncryptedData>` — the SAML Assertion Tool can produce one — it is just
  not something this profile will ever hand it.
* **No Single Logout**, and it is not a gap. See the table at the top.
* **No `AuthorizationDecisionQuery`**, the fifth SAML 1.1 request type. The mock
  refuses it by name; this page has no pane for any of the query types.
* **No SAML 1.0.** Reference-only, and `callIdp()` says so.
