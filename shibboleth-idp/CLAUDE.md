<!--
SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
SPDX-License-Identifier: MIT
-->

# shibboleth-idp/ — the SAML 1.1 peer side-car

Scope: this image and its one compose service. Two tests use it:
`tests/saml11_peers.js`, with no browser, and the two Shibboleth jobs of
`tests/saml11_sso.js` (`SAML11_PEER=shibboleth`), which drive the debugger's
own pages and api against it (see both entries in `docs/v0.9.5/test-suite-map.md`);
what SAML 1.1 is and how the debugger speaks it is `docs/v0.9.5/saml11.md`.

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
than failing on it. No host-run launcher starts it. The browser in the tests
container and the api both reach it by that compose name, which is the one
its metadata publishes.

**The shared SP metadata volume** (#425). `shibboleth-sp-metadata`, a tmpfs
owned by uid 10001, is mounted here at `metadata/sp` and in the tests
container at `/shibboleth-sp-metadata` (`SHIBBOLETH_SP_METADATA_DIR`). A job
registers a service provider by writing its metadata there as
`<lower-case hex SHA-1 of the entityID>.xml`, which is where the
`LocalDynamicMetadataProvider` in `conf/metadata-providers.xml` looks on the
first request naming that entityID. Every job uses an entityID of its own
(`https://debugger.example.test/saml11/<job>-<stamp>`) and deletes its file
afterwards, so nothing a previous job left or a lookup cached as a miss is in
the way.

**What the image does at build.** Copies both archives out of
`shibboleth-idp-dist:4.3.3` — a FROM scratch image holding exactly the two
files, built from `dist/Dockerfile` (`ADD --checksum` from shibboleth.net and
Maven Central) into the private mirror by `.github/scripts/mirror-builds.sh`
and reached through the compose file's named context of that name — so the
build downloads nothing; checks each against its pinned SHA-256 again; runs `bin/install.sh` non-interactively,
which **generates the signing, encryption and back-channel keys and the
data sealer at build time** (every container of one image shares them, and
nothing outside the stack trusts them); overlays the configuration below;
builds a Jetty base with the modules a V4 IdP needs and a context descriptor
(`jetty/idp.xml`) that deploys `war/idp.war` in place; and drops to
`appuser`, uid/gid 10001, like every image here. The base image comes from
the ghcr.io mirror through `additional_contexts`, like the others.

**Bumping a version** means a new URL and SHA-256 in `dist/Dockerfile`, the
same digest in `Dockerfile`, a new tag for `shibboleth-idp-dist` in
`Dockerfile`'s FROM, `.github/image-mirror-builds.txt` and the
`x-mirror-contexts` of `docker-compose-run-tests.yml`, and a run of
`.github/scripts/mirror-builds.sh missing` to put it in the mirror. Shibboleth
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
| `conf/attribute-filter.xml` | a policy releasing `mail` and `uid` to `https://debugger.example.test/saml11` and every entityID under it (`RequesterRegex`), which is what the per-run entityIDs are. The stock attribute registry encodes both for SAML 1 under `urn:mace:shibboleth:1.0:attributeNamespace:uri`. |
| `conf/attribute-resolver.xml` | the `mail` template (`${uid}@example.org`) on one line rather than inside a multi-line CDATA block. |
| `conf/metadata-providers.xml` | a filesystem provider for `metadata/debugger-saml11-sp.xml`, and a `LocalDynamicMetadataProvider` over `metadata/sp` (the shared volume above). |
| `conf/authn/password-authn-config.xml` | the Password flow validates against `credentials/demo.htpasswd` and nothing else. |

Three more files of ours, each because a stock V4 IdP is not what a SAML 1.1
deployment publishes or what a browser can reach over plain HTTP (#425):

| File | What it does |
|---|---|
| `publish-saml11-metadata.sh` | run at build over the installer's `metadata/idp-metadata.xml`, which `/idp/shibboleth` serves. The installer writes a SAML 2.0-only *example*: the SAML 1.1 endpoints are commented out, the locations name `https://shibboleth-idp/` and `:8443`, which this side-car does not serve, and `validUntil` is the build instant, so it has expired before anybody reads it. The script adds the 1.1 protocol and `urn:mace:shibboleth:1.0` to `protocolSupportEnumeration`, uncomments the Shibboleth AuthnRequest SSO and the SAML 1.1 ArtifactResolutionService, rewrites every location to `http://shibboleth-idp:8080/idp/`, removes `validUntil`, and checks each edit so a different installer layout fails the build. |
| `jetty/idp-override-web.xml` | applied by Jetty after the war's own `web.xml`, which marks `JSESSIONID` `Secure`. A browser drops a `Secure` cookie set over http, so the login's next step finds no session and the IdP answers *Web Login Service - Stale Request*. `idp.cookie.secure=false` covers the IdP's own cookies and not this one. It lives in `etc/`, not `webapps/`, where Jetty would deploy it as a context. |
| `jetty/idp.xml` | names that override (`overrideDescriptor`). |

The metadata it then publishes carries **two signing certificates**: the
back-channel key first and the front-channel key second. Browser/POST
responses and resolved artifact responses are both signed with the second, so
a relying party that trusts only the first rejects every response; that is
what the debugger's response page did before #425.

**Artifact resolution** is the SAML 1.1 SOAP binding at
`/idp/profile/SAML1/SOAP/ArtifactResolution`, over plain HTTP here. A SAML 1.1
`<samlp:Request>` has no `<Issuer>`, so the IdP takes the requester from the
artifact and authenticates it by the request's signature, against the
signing key in that SP's metadata. An unsigned request gets *Success with no
assertion* (`Message context was not authenticated` in the log), which is what
`sstc-saml-bindings-1.1` section 4.1.1.6 requires.

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
M=ghcr.io/rcbj/id-proto-debugger/mirror
docker build -f shibboleth-idp/Dockerfile -t shibidp-dev:local \
  --build-context "eclipse-temurin:11-jdk=docker-image://$M/eclipse-temurin:11-jdk" \
  --build-context "shibboleth-idp-dist:4.3.3=docker-image://$M/shibboleth-idp-dist:4.3.3" .
# Without the mirror's dist image, build it locally (it downloads the two
# archives, checksum-pinned) and point the context at the local tag:
#   docker build -t shibidp-dist:local shibboleth-idp/dist
#   ... --build-context "shibboleth-idp-dist:4.3.3=docker-image://shibidp-dist:local"
docker network create shibidp-dev-net
# A host directory stands in for the shared SP metadata volume; the IdP
# runs as uid 10001, so it must be writable by that uid.
SPDIR=$(mktemp -d) && chmod 0777 "$SPDIR"
docker run -d --name shibidp-dev-idp --network shibidp-dev-net \
  -p 127.0.0.1:8080:8080 -v "$SPDIR":/opt/shibboleth-idp/metadata/sp \
  shibidp-dev:local
# then, from tests/, with no iya-sts base set. The metadata names
# http://shibboleth-idp:8080, and saml11_peers.js reaches it through
# SHIBBOLETH_IDP_URL whatever the published address says:
SHIBBOLETH_IDP_URL=http://127.0.0.1:8080/idp SHIBBOLETH_SP_METADATA_DIR="$SPDIR" \
  CONFIG_FILE=./env/docker-tests.js node saml11_peers.js
```

The browser job (`SAML11_PEER=shibboleth node saml11_sso.js`) needs a
running api and client too, and a browser and an api that resolve
`shibboleth-idp`, which the containerized stack gives it for free; from a
host, Chrome's `--host-resolver-rules="MAP shibboleth-idp 127.0.0.1"` and
the artifact resolution field pointed at `127.0.0.1` are enough to drive it
by hand.

The IdP's own log is `/opt/shibboleth-idp/logs/idp-process.log` inside the
container; Jetty's goes to the container's stdout.
