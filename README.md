![OAuth2 / OIDC / SAML2 Debugger](docs/images/oauth2oidcdebugger+iyasec-logo-black.png)

# id-proto-debugger

A **protocol debugger for identity**: it plays the client, the relying
party, the service provider, the wallet or the workload against a real
identity provider, issuer, verifier, key distribution centre or security
key, and shows every message on the way past — decoded, checked against
the specification, and explained. [This](https://github.com/rcbj/id-proto-debugger)
is the official home of the community project. It runs in your browser at
[idptools.com](https://idptools.com), or locally from a checkout or the
published images.

*Formerly `oauth2-oidc-debugger`*, renamed on 2026-08-28 because it debugs a
good deal more than OAuth 2.0 and OpenID Connect now. It began with a Red Hat
SSO blog post in November 2017. New to this kind of tool?
[**What a protocol debugger is**](docs/what-is-a-protocol-debugger.md)
explains what one does and why identity protocols in particular need one.

**The documentation is at [rcbj.github.io/id-proto-debugger](https://rcbj.github.io/id-proto-debugger/)**
(the [`docs/`](docs/) directory, published as a GitHub Pages site): a user
guide, a page per workflow, and how to run, test and release it.

## What it debugs

| Workflow | Major specifications | Page |
|---|---|---|
| OAuth 2.0 and OpenID Connect | RFC 6749, OIDC Core 1.0, PKCE, RFC 8628, RFC 8693, RFC 7009, RFC 7662, Dynamic Client Registration, RP-Initiated Logout | [User guide](docs/oauth2-oidc/index.md) |
| OAuth security | RFC 9700, RFC 9449 (DPoP) | [RFC 9700 mode](docs/rfc9700.md), [DPoP](docs/dpop.md) |
| SAML | SAML 2.0 (Redirect, POST, Artifact, Single Logout), SAML 1.1 | [SAML 2.0](docs/saml.md), [SAML 1.1](docs/saml11.md), [Assertion Tool](docs/saml-assertion.md), [decoders](docs/saml-decoders.md) |
| WS-* | WS-Trust 1.0–1.4, WS-Federation 1.2 | [WS-Trust](docs/wstrust.md), [WS-Federation](docs/wsfed.md) |
| Verifiable credentials | OID4VCI 1.0, OID4VP 1.0, SD-JWT (RFC 9901), SD-JWT VC, DIDs | [Issuance](docs/sd-jwt-vc-issuance.md), [presentation](docs/sd-jwt-vc-presentation.md), [DIDs](docs/dids.md) |
| Authentication | WebAuthn Level 3, ISO 7816 smart cards (PIV, OpenPGP, OATH, Yubico OTP, YubiHSM Auth) | [WebAuthn](docs/webauthn.md), [smart cards](docs/smartcard.md) |
| Kerberos | RFC 4120, RFC 4121, MS-PAC, MS-SFU, SPNEGO (RFC 4178) | [Kerberos v5](docs/kerberos.md), [SPNEGO](docs/spnego.md) |
| Directories and provisioning | LDAP (RFC 4511), SCIM 2.0 (RFC 7643, RFC 7644) | [LDAP](docs/ldap.md), [SCIM](docs/scim.md) |
| Workload identity | SPIFFE, the SPIRE Server API | [SPIFFE](docs/spiffe.md) |
| Authorization | XACML 3.0 with ALFA and the JSON Profile, GNAP (RFC 9635) | [XACML](docs/xacml.md), [GNAP](docs/gnap.md) |
| Shared Signals | OpenID SSF 1.0, CAEP, RISC, RFC 8417, RFC 8935/8936 | [SSF](docs/ssf.md), [CAEP](docs/caep.md), [RISC](docs/risc.md) |
| PKI and cryptography | X.509 / RFC 5280, TLS and mutual TLS, JOSE, XML Signature and Encryption, ML-DSA, SLH-DSA, ML-KEM, LMS/XMSS | [PKI](docs/pki.md), [encryption](docs/encryption.md), [hashing](docs/hashing.md), [JWT Tools](docs/jwt-tools.md), [Digital Signature](docs/digital-signature.md), [hash-based signatures](docs/hbs.md) |

The full list, with every specification linked, is
[Supported specifications and features](docs/supported-specs.md). The
identity providers it has been tested with, and what was learned about each,
are in [Identity provider notes](docs/identity-providers.md).

Kerberos, SPNEGO, LDAP and SPIFFE need the api service (a browser cannot
open their sockets), so they are not on the hosted static sites and their
landing cards there are greyed out. Run the debugger locally for them.

## Running it

From a checkout, with Docker:

```bash
git submodule update --init --recursive   # api/node-ldapjs, a nested submodule
./generate-tls-cert.sh                    # once per checkout: the TLS pair
CONFIG_FILE=./env/local.js docker-compose up
```

Then open `https://localhost:3000` and register
`https://localhost:3000/callback` as the redirect URI with your identity
provider. Trust `./generated-tls-ca/stack-tls-root.pem` once, or accept the
certificate warning on both `https://localhost:3000` and
`https://localhost:4000`.

Or run the published images, which every `master` build pushes to
`ghcr.io/rcbj/id-proto-debugger-{api,client}` and
`docker.io/iyasec/id-proto-debugger-{api,client}` as `latest` and as one
`M.N.P.B` per build:

```bash
docker pull ghcr.io/rcbj/id-proto-debugger-client:latest
docker pull ghcr.io/rcbj/id-proto-debugger-api:latest
```

[Getting started](docs/getting-started.md) walks through a first grant, and
[Running the debugger](docs/running.md) covers the published images, the TLS
certificate, docker compose and docker run, building the images, and the
debugger embedded in IYA STS.

## Running the tests

The Selenium suite runs in containers against the whole stack, including
Keycloak, walt.id and IYA STS:

```bash
docker login ghcr.io                      # the stack's images are private copies
./docker-run-tests.sh                     # every job
./run-coverage.sh                         # the same, with the coverage floors
./remote-run-tests.sh https://test.idptools.com   # against a deployed site
```

[Running the tests](docs/running-tests.md), [What each test covers](docs/test-suite-map.md),
[Testing against the deployed sites](docs/live-site-testing.md) and
[Code coverage](COVERAGE.md) have the details; `tests/CLAUDE.md` has the rules
for writing a test.

## Versioning and releases

A build is **M.N.P.B**: the release in the [`VERSION`](VERSION) file (now
`0.9.3`) and the UTC build instant. It is in every page's footer and at
`/version.json`. The first `master` build of each release creates the GitHub
release `release-M.N.P`. [Releases, versions and images](docs/releases.md)
explains the tags, what a build publishes and how to cut a release;
[Version history](docs/version-history.md) lists the releases.

## Privacy and security

The hosted sites are static: there is no application backend, and all token
handling happens in your browser, with your configuration only in its
`localStorage` (passwords excluded). An identity provider's redirect does
reach the hosting provider, so if that is not acceptable for what you are
testing, run the debugger locally. [Privacy and security](docs/privacy-and-security.md)
has the details, and [SECURITY.md](SECURITY.md) the security policy, including
how to report a vulnerability.

As of Q1 2026, Anthropic Claude has been used to implement some new features of
this project. All code is reviewed by a human before it is merged into the main
branch.

## Authors

Robert C. Broeckelmann Jr. - Initial work

## License

This project is licensed under the MIT License - see the LICENSE.md file for details

## Acknowledgments
Thanks to the following:
* [APICast (3Scale API Management Gateway OAuth2 Example)](https://github.com/3scale/apicast/tree/master/examples/oauth2) for being the starting point for this experiment.
* [Docker](https://docs.docker.com/reference/cli/docker/)
* [docker-compose](https://docs.docker.com/reference/cli/docker/compose/)
* [Node.js](https://nodejs.org/api/all.html)
* [Javascript](https://devdocs.io/javascript/)
* [Typescript](https://www.typescriptlang.org/docs/)
* [Browserify](https://github.com/browserify/browserify#usage)
* [OpenAPI](https://swagger.io/specification/)
* [Selenium](https://www.selenium.dev/selenium/docs/api/javascript/index.html)
* [Walt.ID](https://github.com/walt-id/waltid-identity)
* [KeyCloak](https://github.com/keycloak/keycloak)
* [KeyCloak WS-Federation Support](https://github.com/cloudtrust/keycloak-wsfed)
