<!--
SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
SPDX-License-Identifier: MIT
-->

# shibboleth-idp/ — the SAML 1.1 peer side-car

Scope: this image and its one compose service. The test it exists for is
`tests/saml11_peers.js` (see its entry in `docs/test-suite-map.md`); what
SAML 1.1 is and how the debugger speaks it is `docs/saml11.md`.

**What it is.** Shibboleth Identity Provider **4.3.3** on **Jetty 10.0.22**,
on `eclipse-temurin:11-jdk`. It answers Shibboleth's AuthnRequest profile at
`/idp/profile/Shibboleth/SSO` — the four query parameters `providerId`,
`shire`, `target` and `time`, which is exactly what the debugger sends — with
a SAML 1.1 **Browser/POST** response. iya-sts answers the same profile; this
is the other implementation, and the one most SAML 1.1 deployments ran.
Keycloak dropped SAML 1.1 long ago, so there is no Keycloak half.

**Where it runs.** Only `docker-compose-run-tests.yml`, as the service
`shibboleth-idp` (container `id-proto-debugger-shibboleth-idp`) on the
stack's bridge network, plain HTTP on 8080, **no host port**. The `tests`
service waits for it with `condition: service_healthy`; the probe is
`/idp/status`, which the stock `access-control.xml` answers only to the
loopback address, where the probe runs. It is ready in about 15 seconds.
`run-tests-in-container.sh` sets `SHIBBOLETH_IDP_URL=http://shibboleth-idp:8080/idp`
when the debugger is the compose `client`, and blanks it on a partial stack
that did not start this service, so a focused mode skips that half rather
than failing on it. No host-run launcher starts it.

**What the image does at build.** Downloads both archives from their
official locations (shibboleth.net, Maven Central) and checks each against a
pinned SHA-256 in the Dockerfile; runs `bin/install.sh` non-interactively,
which **generates the signing, encryption and back-channel keys and the
data sealer at build time** (every container of one image shares them, and
nothing outside the stack trusts them); overlays the configuration below;
builds a Jetty base with the modules a V4 IdP needs and a context descriptor
(`jetty/idp.xml`) that deploys `war/idp.war` in place; and drops to
`appuser`, uid/gid 10001, like every image here. The base image comes from
the ghcr.io mirror through `additional_contexts`, like the others.

**Bumping a version** means a new SHA-256 for that archive. Shibboleth
publishes one beside the tarball (`.sha256`); Maven Central publishes only a
SHA-1 for `jetty-home`, so compute the SHA-256 of a download whose SHA-1
matches. Jetty must stay at 10: a V4 IdP is `javax.servlet`, Jetty 11 and
later are `jakarta.servlet`.

## The configuration, and what it changes

The XML under `conf/` is Shibboleth's own file as the 4.3.3 installer writes
it, edited, so it carries no licence header of ours. Each differs from stock
in one place:

| File | Change |
|---|---|
| `conf/relying-party.xml` | `Shibboleth.SSO` enabled (stock comments it out), with `includeAttributeStatement="true"`. That bean signs the **Response** and not the assertion, which is what the test asserts. |
| `conf/attribute-filter.xml` | a policy releasing `mail` and `uid` to `https://debugger.example.test/saml11`. The stock attribute registry encodes both for SAML 1 under `urn:mace:shibboleth:1.0:attributeNamespace:uri`. |
| `conf/attribute-resolver.xml` | the `mail` template (`${uid}@example.org`) on one line rather than inside a multi-line CDATA block. |
| `conf/metadata-providers.xml` | a filesystem provider for `metadata/debugger-saml11-sp.xml`. |
| `conf/authn/password-authn-config.xml` | the Password flow validates against `credentials/demo.htpasswd` and nothing else. |

`idp-merge.properties` (ours) is merged into `idp.properties` by the
installer: the entityID `http://shibboleth-idp:8080/idp/shibboleth`, scope
`example.test`, the Password flow only, and `idp.cookie.secure=false`
because the stack reaches it over plain HTTP.

**The user** is `jdoe` with password `saml11-shibboleth` (an `{SHA}` line in
`credentials/demo.htpasswd`) — the test's defaults, so no variable is set.
After the login the IdP shows its attribute-release consent page once; the
test's `walk()` submits it.

**The service provider** is `metadata/debugger-saml11-sp.xml`: entityID
`https://debugger.example.test/saml11`, one AssertionConsumerService at
`https://debugger.example.test/acs` bound to
`urn:oasis:names:tc:SAML:1.0:profiles:browser-post`. Those are the defaults
of `SHIBBOLETH_SP_ENTITY_ID` and `SHIBBOLETH_ACS_URL` in the test. Change
either there and this file has to change too, or the IdP answers *Web Login
Service - Unsupported Request*. Nothing is posted to that ACS: the test reads
the Browser/POST form out of the page.

## Running it on its own

```bash
docker build -f shibboleth-idp/Dockerfile -t shibidp-dev:local \
  --build-context "eclipse-temurin:11-jdk=docker-image://ghcr.io/rcbj/id-proto-debugger/mirror/eclipse-temurin:11-jdk" .
docker network create shibidp-dev-net
docker run -d --name shibidp-dev-idp --network shibidp-dev-net shibidp-dev:local
# then, from tests/, with no iya-sts base set:
SHIBBOLETH_IDP_URL=http://<container address>:8080/idp \
  CONFIG_FILE=./env/docker-tests.js node saml11_peers.js
```

The IdP's own log is `/opt/shibboleth-idp/logs/idp-process.log` inside the
container; Jetty's goes to the container's stdout.
