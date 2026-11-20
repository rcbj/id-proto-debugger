# What a protocol debugger is

A **protocol debugger** is a tool that stands at one end of a network
protocol, speaks that protocol for real, and shows you every message in both
directions with each field decoded, each signature checked and each encrypted
part opened.

Three claims are in that sentence and the middle one carries the rest. This
page is about why.

---

## THE ONE SENTENCE THIS FILE EXISTS TO PREVENT SOMEBODY WRITING

> "A protocol debugger is Wireshark with a nicer interface."

It is not, and the difference is not the interface. A sniffer, a proxy and the
browser's network tab **observe** a conversation between two other parties. A
protocol debugger **is one of the parties**. It holds that party's keys, makes
that party's decisions, and receives errors that were addressed to it.

Four things follow, and an observer has none of them:

| | an observer | a debugger |
|---|---|---|
| **encrypted content** | sees the ciphertext. A proxy with its own CA can open the *TLS* layer, which is not the layer the secrets are in: a SAML `<EncryptedAssertion>`, a JWE, a Kerberos `EncPart` and a WS-Trust encrypted token are each encrypted a second time, to a key the proxy does not have | holds that key, because it is the recipient. The assertion opens |
| **signatures** | can tell you a signature is *present* | verifies it, and says which check failed — the digest, the canonicalization, the certificate, or the key |
| **composing** | can replay what it captured, and vary it | composes a message that has never existed: one field changed, one field absent, one field deliberately wrong |
| **the error** | infers the far end's opinion from response bytes | *is* the counterparty the far end is answering, so the refusal is addressed to it and the state it depends on is local and inspectable |

An observer answers *what went over the wire*. A debugger answers *what the
other end thinks of me, and why* — which is the question you actually have at
2am.

---

## The three jobs

Every workflow in this project is these three things in a row, and the panes
on a page are usually in this order for that reason.

### 1. Compose

Build the request field by field, including the fields a library would not let
you reach and the values a library would not let you send. A debugger's job
includes sending the wrong thing on purpose: an `AuthnRequest` with no
`Destination`, a token exchange with a mismatched `audience`, an
`acr_values` your identity provider has never heard of. The interesting
question is nearly always *what does the far end do with this*, and a
well-behaved client is precisely the thing that cannot ask it.

### 2. Exchange

Actually send it, over the actual binding, to the actual far end — a real
identity provider, key distribution center, directory, issuer or verifier. Not
a simulation. A debugger that only pretends to transmit can confirm your
understanding of the specification and can never confirm the *other
implementation's* understanding of it, which is where the disagreements live.

### 3. Decode and verify

Take the response apart: every field named and explained, every signature
checked as a separate result rather than one boolean, every encrypted part
opened when you supply the key, and every identifier that is really a
structure (a Kerberos PAC, a COSE key, a `SubjectPublicKeyInfo`, an
`_sd` array) expanded rather than shown as base64.

Verification as *separate results* is the part that tends to be missed. "The
signature is invalid" is one bit and it is the same bit for a truncated
digest, a canonicalization disagreement, an untrusted issuer and a clock skew.
Four independent checks reported independently turn a dead end into a
direction.

---

## Why identity protocols need this more than most protocols do

Because their failure messages name a **category** and almost never a
**cause** — sometimes by accident, and in at least one case on purpose.

| you see | what it can actually mean |
|---|---|
| OAuth 2.0 `invalid_grant` | the code is expired, or already used, or was issued to a different client, or the `redirect_uri` does not match byte for byte, or the PKCE verifier does not hash to the challenge |
| a SAML identity provider's `invalid signature` | the digest, the canonicalization, the transforms, the certificate, the key, or the fact that you signed the assertion and it wanted the response signed |
| WebAuthn `NotAllowedError` | no matching credential, *or* the user declined, *or* it timed out — collapsed into one error **deliberately**, for privacy. The specification is not going to tell you which, ever |
| Kerberos `KDC_ERR_BADOPTION` | in the delegation area, essentially every refusal: a missing attribute on the front end, a missing one on the back end, an evidence ticket that is not forwardable, or padata that was not sent |
| SCIM `404` | the user was deleted — or its id was double-encoded on the way into the URL, which looks identical from outside |
| SCIM `401` | the password is wrong — or the Digest hash used the wrong one of the three registered algorithms |
| a browser `CORS error` on a call that worked yesterday | frequently not CORS at all: a TLS handshake the browser refused, reported as a preflight that got no response. See the api-port note in the repo-root `CLAUDE.md` |
| a SPIFFE bundle that `verifies nothing` | every JWK in it lacked a `use` member, which a consumer **must** ignore — and ignoring is silent, so nothing anywhere reports an error |

Each row is a place where the honest answer is *I cannot tell from here*, and
each is a place where being the participant rather than the observer is what
narrows it. That is the whole argument for this class of tool.

---

## The half that needs no network at all

A large part of protocol debugging is not an exchange. It is: *somebody sent me
these bytes and I need to know what they say.*

So a protocol debugger is also a **decoder**, driven by paste rather than by a
connection — and it is the half that works when the far end is somebody else's
production system you will never get credentials for, a capture from last
Tuesday, or a bug report attachment. In this project that is the Kerberos
Decoder, the WebAuthn Analyzer, the SAML Response Decoder, the JWT/JWK tools,
the encoding, hashing and signature tools, the certificate describer and the
SPIFFE SVID inspector — each of which parses, explains and verifies with no
identity provider, no credentials and, in most cases, no network.

The two halves answer different questions and neither replaces the other. The
exchange half tells you what the far end does; the decode half tells you what
the bytes mean.

---

## Where a debugger has to live, and why this one is two services

A browser is an excellent place to debug a protocol a browser can speak: the
redirects are real redirects, the origin is a real origin, and the page is the
relying party rather than an impersonation of one. That covers OAuth 2.0,
OpenID Connect, SAML, WS-Federation, WS-Trust, SD-JWT VC, SCIM and WebAuthn.

It is a hopeless place to debug anything else, and the reason is not policy. A
browser cannot open a raw TCP socket, so it cannot speak Kerberos (DER on port
88) or LDAP (BER on port 389); it cannot open an HTTP/2 stream of its own or
read trailers, so it cannot speak gRPC, which is two thirds of SPIFFE; it
cannot choose a client certificate or be handed a truststore, so it cannot make
a mutual-TLS connection you control; and it is **not an HTTP server**, so it
cannot be the far end of a push delivery.

That is why this project is a browser front end *and* a backend service, and
why four cards are greyed out on the hosted, backend-less site. A page whose
every button fails at the network is worse than a card that says why.

---

## What it is not

| not a | because |
|---|---|
| **packet sniffer** | see the top of this page. It participates; it does not watch |
| **conformance suite** | a conformance suite **asserts** — it has a fixed list of cases and answers pass or fail. A debugger **shows**, and the case is whatever you just typed. This project has a conformance-shaped piece (the RFC 9700 checkbox, the SCIM scenario harness) and that is a feature inside the tool rather than what the tool is |
| **client library** | a library's job is to make the correct thing easy and the incorrect thing impossible. A debugger's job is the opposite one |
| **identity provider** | it is the *other* end. This repository does ship a mock identity provider, and only so that the test suite has a far end that does what the test told it to |
| **attack tool** | composing an invalid message against a system you run is debugging. The read-only WebAuthn observer in this project refuses to name an RP ID it does not own for exactly this reason: a tool that could would be a working defeat of the protocol's phishing resistance |

---

## What using one costs you, and what to do about it

A debugger only works because you give it the credentials of the party it is
standing in for. That is not a side effect; it is the mechanism. Two
consequences are worth stating plainly.

* **Key material.** To decrypt an assertion you must supply the private key it
  was encrypted to. In this project configuration lives in the browser's
  `localStorage`, passwords are never stored, and every workflow that
  generates a key pair carries a checkbox that turns storage off — clearing
  which also **removes what was already written**, since an opt-out that
  leaves yesterday's private key behind is not one.
* **Where the exchange happens.** The hosted site is static, so an
  authorization code redirected back to it arrives through the hosting
  provider as part of an ordinary page request. Nothing is logged, and every
  token operation happens in your browser — but if that is unacceptable for
  your identity provider, run it locally, which is the point of the project
  being a container you can start in one command.

And the obvious one: the messages are real. A SCIM scenario that deprovisions
ten users deprovisions ten actual users. Point it at something you are willing
to change.

---

## Where to go from here

The repo-root `README.md` is the feature list and `CLAUDE.md` is the map of
the tree. Each protocol has its own page here:

| | |
|---|---|
| SAML 1.1, as a different protocol rather than an older spelling | [saml11.md](saml11.md) |
| WS-Federation | [wsfed.md](wsfed.md) |
| the OAuth 2.0 Security BCP | [rfc9700.md](rfc9700.md) |
| what is worth building next in OAuth 2.0 / OIDC | [spec-roadmap.md](spec-roadmap.md) |
| OIDC flows, DPoP, DIDs | [oidc-flows.md](oidc-flows.md), [dpop.md](dpop.md), [dids.md](dids.md) |
| SD-JWT VC issuance and presentation | [sd-jwt-vc-issuance.md](sd-jwt-vc-issuance.md), [sd-jwt-vc-presentation.md](sd-jwt-vc-presentation.md) |
| WebAuthn, and the read-only observer | [webauthn.md](webauthn.md) |
| Kerberos v5, and SPNEGO over HTTP | [kerberos.md](kerberos.md), [spnego.md](spnego.md) |
| LDAP | [ldap.md](ldap.md) |
| SCIM 2.0 provisioning | [scim.md](scim.md) |
| Shared Signals, and the two vocabularies over it | [ssf.md](ssf.md), [caep.md](caep.md), [risc.md](risc.md) |
| SPIFFE / SPIRE | [spiffe.md](spiffe.md) |
| X.509, the certificate authority, and post-quantum PKI | [pki.md](pki.md) |
| encryption, hashing, XML Signature, stateful hash-based signatures | [encryption.md](encryption.md), [hashing.md](hashing.md), [xmldsig-pqc.md](xmldsig-pqc.md), [hbs.md](hbs.md) |
| the mock identity provider the tests run against | [mock-sts.md](mock-sts.md) |
