---
title: "Using the Verifiable Credential workflows"
---

# Using the Verifiable Credential workflows

The debugger plays every role in a Verifiable Credential exchange, one step
at a time, showing each request before it is sent and each answer after it
arrives:

* **the wallet receiving a credential** — the **VC Issuance** workflow,
  `vc-issuance-0.html` to `vc-issuance-4.html`, over
  [OpenID4VCI 1.0](openid4vci.md);
* **the wallet presenting it** — the **VC Presentation** workflow,
  `vc-presentation-0.html` to `vc-presentation-3.html`, over
  [OpenID4VP 1.0](openid4vp.md), [HAIP 1.0](haip.md) or
  [SIOPv2](siopv2.md);
* **the Verifier asking for it** — `vc-verifier.html`, reached from the role
  chooser on `vc-presentation-0.html`;
* and four **VC Tools** linked from the foot of every VC page: DID Tools,
  VC Barcodes, Gordian Envelope and ACDC.

These pages are for somebody **using** the debugger. Why it behaves as it
does is in the developer notes listed [at the end](#developer-notes).

* TOC
{:toc}

## Before you start

Start the debugger as [Getting started](../getting-started.md)
describes, open `https://localhost:3000`, and choose **VC Issuance** or
**VC Presentation**. The deployed copy at [idptools.com](https://idptools.com)
has every VC page, but it runs no backend, so some things work there and some
need the local containers — see
[What the static sites can and cannot do](#what-the-static-sites-can-and-cannot-do).

**The other end is yours to choose.** Nothing in these workflows is specific
to one product: the wallet works with any OpenID4VCI Credential Issuer and
any OpenID4VP Verifier, and the Verifier page with any OpenID4VP wallet.
Every value you type comes from the other party's metadata, from the offer
it made you, or from its request. The test suite runs them against iya-sts,
walt.id's issuer and verifier, and Polaris (an independent HAIP Verifier),
and the screenshots here use an OpenID4VCI Credential Issuer at
`https://localhost:8081`.

**CORS.** The pages fetch the other party's documents from the browser, so
that party must send CORS headers naming the debugger's origin. Where it
does not, upload the document from a file (issuance step 1), or send the
call through the api (presentation step 0, and the Verifier page's
issuer-side fetches).

## What the static sites can and cannot do

The deployed copies ([idptools.com](https://idptools.com) and
test.idptools.com) are **S3 + CloudFront with no backend** — they run no
server and **store nothing**. Everything a page does happens in your browser.
One principle follows, and it decides every row below: anything that needs a
server to **hold a message between two parties**, to **keep state**, or to
speak a **non-browser wire protocol** needs the local containers; everything
else works on the static sites too.

**Works on the static sites:**

- **OAuth 2.0 / OIDC** — the Authorization Code flow and the other grants.
  The token-endpoint calls run in the browser and the redirect returns to
  `/callback`. (The "through the api" option is simply off here.)
- **SAML 2.0 and WS-Federation** sign-in — the identity provider's POST is
  received at the CDN edge by a Lambda@Edge (`/samlacs`, `/samlslo`,
  `/wsfed`). SAML HTTP-Artifact is the one leg that still needs the api.
- **VC issuance** as the wallet — against an issuer that sends CORS headers
  (or upload its metadata from a file). The credential lives only in your
  browser; nothing is stored server-side.
- **The VC Verifier** in **Digital Credentials API** mode, and **pane 4**
  paste-checking of an answer.
- **Every offline tool** — JWT, PKI, encryption, hashing, XACML, DID Tools,
  the predicates page, VC Barcodes / Gordian Envelope / ACDC, and the
  decoders. They need no network at all.

**Not available on the static sites:**

- **The Verifier's hosted `request_uri` / `response_uri` modes** (by
  reference, and `direct_post`). Hosting a wallet's answer would mean holding
  a **presented credential on the server**, and these sites store nothing, so
  those modes are not offered. Use DC API mode, paste the answer into pane 4,
  or run the local containers.
- **Kerberos, SPNEGO, LDAP and SPIFFE** — those pages are not built into the
  static sites at all. A browser cannot speak their wire protocols; the api
  does, so the whole page lives behind it.
- **Anything routed through the api** — the presentation workflow's "through
  the api" proxy (used when the other party sends no CORS), the server-side
  token-proxy option, and SAML HTTP-Artifact.

## Optional: iya-sts setup

[setup-iya-sts.md](setup-iya-sts.md) — **for iya-sts only**: creating a
holder account, wallet clients and offers there. Every other issuer has its
own way, and the tutorials never depend on this page.

## Configuration reference

Every pane, field and button, with its element id, the specification that
defines it, its default and where the default comes from, and whether — and
where — it is stored.

| Page(s) | Reference |
|---|---|
| `vc-issuance-0.html` … `vc-issuance-4.html` | [reference-issuance.md](reference-issuance.md) |
| `vc-presentation-0.html` … `vc-presentation-3.html` | [reference-presentation.md](reference-presentation.md) |
| `vc-verifier.html` | [reference-verifier.md](reference-verifier.md) |
| `did-tools.html`, `vc-barcodes.html`, `gordian-envelope.html`, `acdc.html`, the VC Tools row | [reference-tools.md](reference-tools.md) |
| `vc-predicates.html`, and what the wallet and Verifier pages do with a predicate query | [reference-predicates.md](reference-predicates.md) |

## Protocol and format guides

What each specification says, what the debugger does at each step, and what
it checks. Drafts are labelled as drafts, with the revision the code
implements.

| Protocols | |
|---|---|
| [openid4vci.md](openid4vci.md) | OpenID4VCI 1.0: offers, pre-authorized and authorization code, `tx_code`, client authentication (including attestation), DPoP, key proofs, nonce, deferred and notification endpoints, refresh |
| [openid4vp.md](openid4vp.md) | OpenID4VP 1.0: DCQL, request by value and by reference, `request_uri_method=post`, Client Identifier prefixes, `direct_post` / `direct_post.jwt`, the Digital Credentials API |
| [haip.md](haip.md) | HAIP 1.0, the high-assurance profile, on both ends |
| [siopv2.md](siopv2.md) | SIOPv2 self-issued ID Tokens |
| [presentation-exchange.md](presentation-exchange.md) | Predicates: DIF Presentation Exchange 2.1.1 (OpenID4VP drafts — removed in 1.0), the debugger's non-standard DCQL predicate extension, and OpenID4VP 1.0 §6.4.1 `values` matching |

| Credential formats and status | |
|---|---|
| [format-sd-jwt-vc.md](format-sd-jwt-vc.md) | `dc+sd-jwt` — SD-JWT VC, RFC 9901, the Key Binding JWT |
| [format-mdoc.md](format-mdoc.md) | `mso_mdoc` — ISO mdoc |
| [format-jwt-vc-json.md](format-jwt-vc-json.md) | `jwt_vc_json` |
| [format-ldp-vc.md](format-ldp-vc.md) | `ldp_vc` — every Data Integrity and Linked Data proof suite |
| [format-vc-jose-cose.md](format-vc-jose-cose.md) | W3C VC-JOSE-COSE: `vc+jwt`, `vc+sd-jwt`, `vc+cose` |
| [format-sd-cwt-jwp.md](format-sd-cwt-jwp.md) | SD-CWT and JWP / JPT (drafts) |
| [format-anoncreds.md](format-anoncreds.md) | AnonCreds, with revocation |
| [format-vc-barcodes.md](format-vc-barcodes.md) | W3C VC Barcodes |
| [format-gordian-envelope.md](format-gordian-envelope.md) | Gordian Envelope |
| [format-acdc.md](format-acdc.md) | ACDC / KERI |
| [status-lists.md](status-lists.md) | IETF Token Status List and W3C Bitstring Status List |

## Tutorials

| Tutorial | What it shows | The other end | Screenshots |
|---|---|---|---|
| [Read a Credential Issuer's metadata](tutorial-issuer-discovery.md) | step 0, step 1's four documents, the configuration they produce | any OpenID4VCI issuer | yes |
| [Receiving a credential](tutorials-issuance.md) | pre-authorized code with a Transaction Code, an offer from its QR code, authorization code, a claims subset, DPoP, deferred issuance, refresh and the Credential History, no keys in the browser, `private_key_jwt` and Client Attestation, other formats | an OpenID4VCI issuer **where you have an account** (pre-authorized) **or a registered client** (authorization code) | no — see below |
| [Present selected claims to the debugger's own Verifier](tutorial-present-to-verifier.md) | both ends of OpenID4VP 1.0 in one browser, then HAIP 1.0 with an encrypted answer | the debugger's own Verifier page (hosted modes need the local containers); any OpenID4VP Verifier for the wallet half | yes |
| [The Verifier page, and reading its checks](tutorial-verifier-checks.md) | DCQL, the Verifier's identity, the hand-off, every check row, `direct_post.jwt`, a wrong nonce, a request signed live for a `wallet_nonce` | any OpenID4VP wallet (hosted modes need the local containers; DC API and paste work statically) | yes |
| [Resolve an issuer's DID and check its domain linkage](tutorial-did-linkage.md) | `did:web` resolution and the DIF Domain Linkage Credential | any site that publishes them | yes |
| [Prove age >= 18 without revealing it](tutorial-predicates.md) | a predicate query by Presentation Exchange and by the DCQL extension, answered with an AnonCreds proof; a `values` mismatch refused | none — the page and the wallet carry everything | yes |
| [VC Barcodes, Gordian Envelope and ACDC](tutorials-tools.md) | verify and issue a barcode; elide claims of an envelope; issue, verify and revoke an ACDC | none — the pages carry their own samples | yes |

**What needs another issuer or verifier.** Everything above runs against
the debugger itself or against any spec-compliant peer; nothing needs the
product the screenshots were taken with. Some steps do need a peer that
offers them:

* **Receiving a credential** needs an issuer account (a pre-authorized offer
  is made for a person the issuer knows) or a client registered at its
  authorization server (the Authorization Code flow). If your issuer is
  iya-sts, [setup-iya-sts.md](setup-iya-sts.md) shows one way to create
  them; it is optional help for that one product. The pictures in this
  edition were taken against an issuer in product mode where the
  documentation run had neither, which is why that tutorial has none; the
  job that takes them is ready to (see below).
* **SIOPv2** needs a Verifier that asks for an ID Token; the debugger's own
  Verifier page asks only for presentations.
* **ISO mdoc**, the **W3C VC-JOSE-COSE** formats, **JPT**, **SD-CWT** and
  **AnonCreds** need an issuer that issues them; the suite's issuers do not,
  and the suite's tests mint them with test issuers. Their guides say what
  the debugger checks once you hold one.
* The **Digital Credentials API** needs a browser and platform wallet that
  implement it.
* **Status lists** need a credential whose issuer publishes one.

## What the debugger remembers

Everything is in this browser's storage; nothing is sent anywhere to be
kept. Three rules apply on every VC page, and each reference lists its keys:

* **Secrets are never stored**: a client secret, a Transaction Code, a pasted
  holder key, a pasted Verifier identity.
* **Private keys are key material behind a checkbox, ticked by default**:
  the holder key pair (**Save this holder key pair in browser localStorage**, issuance step 2 — clearing it
  also strips the private key from every Credential History row), the client
  keys and attestation (**Keep the client keys in this browser**), the
  Verifier's identity (**Keep this identity in this browser**), and SIOPv2
  pairwise keys. Clearing the box removes what was stored at once. The
  Barcodes and Gordian Envelope pages store no key at all.
* **Everything else** — settings, retrieved documents, the credentials and
  the tokens the workflow obtained — is ordinary `localStorage`.

## Regenerating the screenshots

The pictures are taken by the Selenium jobs that drive these screens, through
`tests/doc_screenshots.js`, which does nothing unless `DOC_SCREENSHOT_DIR` is
set; an ordinary run of the suite takes none. A file is named
`<prefix>-<step>.png`, the prefix naming the walk and the step its place in
it, and the Markdown links to those names — so renaming a `snap()` breaks a
picture here.

| Job | Pictures |
|---|---|
| `vc_user_guide.js` | `vc-issuance-*`, `vc-metadata-*`, `did-tools-*`, `vp-openid4vp-*`, `vp-haip-*`; and, when it can sign in and take offers, `vc-authorization-code-*`, `vc-refresh-*`, `vc-pre-authorized-*`, `vc-dpop-*`, `vc-deferred-*`, `vc-jwt-vc-json-*`, `vc-ldp-vc-*` |
| `vc_verifier_page.js` | `vc-verifier-*` |
| `vc_barcodes_browser.js` | `vc-barcodes-*` |
| `gordian_envelope_browser.js` | `gordian-envelope-*` |
| `acdc_browser.js` | `acdc-*` |

`vc_user_guide.js` walks these tutorials against the issuer named by
`OID4VCI_ISSUER_URL`, and the Verifier-page halves against the api named by
`API_URL`. Against an issuer you do not run, three variables keep it to
ordinary protocol use:

| Variable | Effect |
|---|---|
| `VC_GUIDE_NO_PROVISION=1` | register nothing at the issuer. Without it, the job declares a public wallet client (`vc-user-guide-wallet`, with this client's `/callback` as its redirect URI) and the holder account in iya-sts's registry through `/admin-api`, which needs an admin token |
| `VC_GUIDE_HOLDER_USERNAME`, `VC_GUIDE_HOLDER_PASSWORD` | the account to sign in with, on the issuer's offer page and at its authorization server; without them, a run with `VC_GUIDE_NO_PROVISION=1` skips the sections that sign in or take offers. Pass the password only in the environment |
| `VC_GUIDE_CLIENT_ID` | the wallet's registered `client_id`; the Authorization Code and refresh sections run only with one |
| `VC_GUIDE_IGNORE_CORS=1` | start Chrome with `--disable-web-security`, for a build served from an origin the issuer's CORS policy does not list |

The pictures here were taken like this, from a client build served on a
scratch port, with a separate api whose `uiUrl` named that port:

```bash
cd tests
export CONFIG_FILE=$PWD/env/local.js DOC_SCREENSHOT_DIR=$PWD/../docs/v0.9.5/vc/images
VC_GUIDE_NO_PROVISION=1 VC_GUIDE_IGNORE_CORS=1 \
  OID4VCI_ISSUER_URL=https://localhost:8081 API_URL=<api> \
  node vc_user_guide.js -u <client>
API_URL=<api> node vc_verifier_page.js -u <client>
node vc_barcodes_browser.js -u <client>
node gordian_envelope_browser.js -u <client>
node acdc_browser.js -u <client>
```

Chrome must trust the issuer's and the api's TLS certificates: set
`STS_SPKI_PIN` and `STACK_TLS_SPKI_PIN` to their SPKI pins (see
`tests/browser_flags.js`), as the launchers do.

The presentation pictures present a test SD-JWT VC from a test issuer named
by `did:jwk`, held in the wallet by the job, so they do not depend on what
the issuer will issue.

## Developer notes

[../sd-jwt-vc-issuance.md](../sd-jwt-vc-issuance.md),
[../sd-jwt-vc-presentation.md](../sd-jwt-vc-presentation.md),
[../vc-verifier.md](../vc-verifier.md),
[../vc-verifier-api.md](../vc-verifier-api.md),
[../vc-client-auth.md](../vc-client-auth.md),
[../dpop.md](../dpop.md), [../dids.md](../dids.md),
[../data-integrity.md](../data-integrity.md),
[../vc-jose-cose.md](../vc-jose-cose.md),
[../jwp-sd-cwt.md](../jwp-sd-cwt.md), [../anoncreds.md](../anoncreds.md),
[../vc-barcodes.md](../vc-barcodes.md),
[../gordian-envelope.md](../gordian-envelope.md), [../acdc.md](../acdc.md),
[../jwe-pq-kem.md](../jwe-pq-kem.md).
