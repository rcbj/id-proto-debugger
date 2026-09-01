var config = {
  apiUrl: "https://api:4000",
  uiUrl: "https://client:3000",
  // ---------------------------------------------------------------------------
  // THIS SERVICE SERVES TLS, AND EVERY ADDRESS ABOVE FOLLOWS IT.
  //
  // The api and the client both bind https now (common/tls_listener.js), on ONE
  // certificate generated per run by common/common.sh's
  // generateStackTlsCertificate() — which calls common/generate_tls_cert.js,
  // which is a caller of this project's own client/src/x509.js rather than
  // another encoder.
  //
  // The certificate itself is NOT named here. The launchers pass
  // TLS_CERT_FILE and TLS_KEY_FILE, which outrank this file, because a
  // checked-in configuration cannot name a path that is created per run — the
  // same reason the mock STS's certificate is fetched rather than declared. A
  // process started with `https: true` and no certificate refuses to bind and
  // says which generator makes one, rather than inventing a key nothing in the
  // run trusts.
  //
  // WHAT THIS BOUGHT, beyond the obvious: an https origin is a SECURE CONTEXT,
  // so `window.crypto.subtle` exists on the containerized stack without
  // --unsafely-treat-insecure-origin-as-secure; and an https page may submit a
  // form to an https action, which is what Chrome's "Form is not secure"
  // interstitial had been refusing for every SAML and WS-Federation response
  // once the mock went TLS (53 of 77 jobs on 2026-08-27). Both hazards are
  // recorded in tests/browser_flags.js and both are now structurally absent
  // rather than flagged around.
  // ---------------------------------------------------------------------------
  https: true,
  hostname: "0.0.0.0",
  port: "3000",
  // ---------------------------------------------------------------------
  // `info`, AND IT WAS `debug` UNTIL 2026-09-01 — the CLIENT half of the
  // change api/env/docker-tests.js records beside it, which went to `info`
  // a day earlier (issue #269).
  //
  // THIS ONE REACHES THE BROWSER. `client/build.js` bakes the file this key
  // lives in into every bundle (browserify -t envify --CONFIG_FILE), so the
  // level is not only the client SERVER's: it is the level every page logs
  // at, in Chrome, inside the tests container. A record there is a JSON
  // serialization plus a console write — ~15us measured in headless Chrome —
  // and the root CLAUDE.md's style notes already record what that costs when
  // it is on a path something walks a thousand times.
  //
  // IT IS WORST ON THE RUN THAT COULD AFFORD IT LEAST. `./run-coverage.sh`
  // serves Istanbul-INSTRUMENTED bundles, which are slower to parse and
  // slower to execute, to a pool of jobs sharing a four-core GitHub runner —
  // and every browser wait in this suite is `waitTime`, two seconds. On
  // 2026-09-01 that combination took [08] OAuth2 Authorization Code (public,
  // PKCE=false) red on a two-second wait for `#token_client_id` after the
  // Keycloak redirect, i.e. it reported the page's LOAD TIME as an assertion
  // about the page. See TEST_WAIT_TIME_MS in tests/env/test.js for the other
  // half of that fix.
  //
  // For a debug run of this stack, set it back for the length of that run —
  // or use `env/local.js`, which is still `debug` for exactly that reason.
  // Nothing else changes: the SEVERE console assertions several tests make
  // are error-level and are unaffected by this key.
  // ---------------------------------------------------------------------
  logLevel: "info",
  // api backend is available, so both frontend and backend initiation are
  // offered.
  backendAvailable: true,
  // SAML Service Provider identity + ACS/SLO endpoints (hosted by the api
  // layer).
  spEntityId: "https://client:3000/saml/sp",
  acsUrl: "https://api:4000/samlacs",
  sloUrl: "https://api:4000/samlslo",
  // WS-Federation: RP realm default + the API landing endpoint (wreply target),
  // reachable by its compose DNS name inside the test network.
  wsfedRealm: "urn:wsfed:test:rp",
  wsfedAcsUrl: "https://api:4000/wsfed",
  wsfedMetadataUrlDefault: "http://keycloak-wsfed:8080/auth/realms/wsfed-testing/protocol/wsfed/descriptor",
  samlMetadataUrlDefault: "http://keycloak:8080/realms/debugger-testing/protocol/saml/descriptor",
  // Default WS-Trust STS endpoint (the mock STS service, reachable by its
  // compose DNS name inside the test network).
  // ---------------------------------------------------------------------------
  // EVERY MOCK-STS DEFAULT BELOW IS **https**, AND THE PORT IS STILL 8081.
  //
  // That service binds its main port as TLS on this stack (STS_HTTPS=true on
  // the `sts` service in docker-compose-run-tests.yml). The reason is the RFC
  // 9700 pass: it is a TRUST REALM on that one instance now —
  // /realm/rfc9700/... — rather than a second container, a realm binds no
  // socket of its own, and the pass is only honest over TLS, since requirement
  // 8.1 is that every configured endpoint is https and the client under test
  // enforces it. So the scheme belongs to the process and every default here
  // follows.
  //
  // The certificate is self-signed and REGENERATED ON EVERY START of that
  // service, which is why nothing is baked anywhere: the api fetches it in its
  // own entrypoint (STS_CERT_URL) and the tests container fetches it in
  // trustStsCertificate() (common/common.sh), which installs it for node
  // (NODE_EXTRA_CA_CERTS) and for Chrome (an exact SPKI pin).
  // ---------------------------------------------------------------------------
  wstrustStsUrlDefault: "https://sts:8081/sts",
  // Default OID4VCI Credential Issuer base URL (the mock issuer the STS
  // service also hosts) for the SD-JWT VC issuance workflow.
  oid4vciIssuerUrlDefault: "https://sts:8081",
  // Where the OID4VP verifier lives, for the PRESENTATION workflow. Separate
  // from the issuer above: they share an origin only on this suite's mock STS,
  // and deriving one from the other breaks the moment issuance is run against
  // walt.id (its issuer is :7005/openid4vci, its verifier a different service
  // on :7003).
  oid4vpVerifierUrlDefault: "https://sts:8081",
  // Default RFC 8414 (OAuth 2.0 Authorization Server Metadata) endpoint for
  // the Metadata Retrieval panes. The mock authorization server metadata the
  // STS service publishes.
  rfc8414MetadataUrlDefault: "https://sts:8081/.well-known/oauth-authorization-server",

  // ---------------------------------------------------------------------------
  // Kerberos. These fill kerberos.html so the workflow runs against this project's
  // mock KDC without anything being typed.
  //
  // **The host is `sts`, not localhost, and that is not a typo.** The relay runs in
  // the API container, so the KDC address is resolved from THERE — and the mock
  // KDC's port 88 is not published to the host by any compose file, only reachable
  // on the compose network. `127.0.0.1` in this field means the api container
  // itself, which listens on nothing, and the failure is a connection refused that
  // names an address the user can reach perfectly well from their own shell.
  //
  // The password is a published test credential from the mock's principal table,
  // not a secret. It is set here and EMPTY in prod.js / test-idptools-com.js, which
  // is also where `backendAvailable` is false and the workflow cannot run at all.
  // ---------------------------------------------------------------------------
  krb5RealmDefault: "EXAMPLE.COM",
  krb5KdcHostDefault: "sts",
  krb5KdcPortDefault: "88",
  krb5PrincipalDefault: "alice",
  krb5PasswordDefault: "password!",
  // ---------------------------------------------------------------------------
  // SPNEGO's two fields, and why one of them is deliberately EMPTY.
  //
  // The URL is fetched by the **api**, not by the browser, so it follows the same
  // rule as krb5KdcHostDefault above: the compose service name where the api runs
  // in a container, loopback for a host run, and nothing at all on a build with no
  // api behind it. It was hard-coded as `http://localhost:8081/...` in
  // spnego.html, which is right for exactly one of those three.
  //
  // The SPN is empty ON PURPOSE, and must stay that way unless a deployment
  // genuinely knows better. A client derives it from the URL's host — `HTTP/<host>`,
  // which is what RFC 4559 clients and every browser do — and that derivation is
  // the thing the page exists to make visible: nothing in SPNEGO carries the SPN,
  // so when it is wrong the failure is a KDC error naming nothing about HTTP.
  // Pre-filling a value here would hide the guess behind a default and teach
  // nobody. Set it only for a service whose SPN does not match its URL host, which
  // is the case that needs saying out loud anyway.
  // ---------------------------------------------------------------------------
  krb5SpnegoUrlDefault: "https://sts:8081/spnego/protected",
  krb5SpnegoSpnDefault: "",

  // ---------------------------------------------------------------------------
  // LDAP. These fill ldap.html so the workflow runs against this project's mock
  // directory without anything being typed.
  //
  // **The host follows the same rule as krb5KdcHostDefault above, and for the
  // same reason.** LDAP is BER over a TCP socket, so the connection is opened by
  // the **api**, and the address is therefore resolved from THERE: the compose
  // service name where the api runs in a container, loopback for a host run, and
  // nothing at all on a build with no api behind it. `localhost` in this field
  // means the api container itself, which listens on no LDAP port, and the
  // failure is a connection refused naming an address the user can reach
  // perfectly well from their own shell.
  //
  // The bind DN and password are a published test credential — this directory
  // accepts EVERY bind, whatever is typed — not a secret. They are set here and
  // EMPTY in prod.js / test-idptools-com.js, which is also where
  // `backendAvailable` is false and the workflow cannot run at all.
  // ---------------------------------------------------------------------------
  ldapUrlDefault: "ldap://sts:389",
  ldapBaseDnDefault: "dc=example,dc=com",
  ldapBindDnDefault: "cn=admin,dc=example,dc=com",
  ldapPasswordDefault: "password!",

  // ---------------------------------------------------------------------------
  // SPIFFE (client/public/spiffe.html, docs/spiffe.md).
  //
  // **BOTH gRPC ADDRESSES FOLLOW THE SAME RULE AS ldapUrlDefault ABOVE, AND FOR
  // THE SAME REASON.** A browser cannot produce gRPC at all, so both surfaces
  // are dialled by the **api** and the addresses are resolved from THERE: the
  // compose service name where the api runs in a container, loopback for a host
  // run, and nothing at all on a build with no api behind it. `localhost` in
  // those two fields means the api container itself, which listens on no SPIFFE
  // port, and the failure is a connection refused naming an address the user can
  // reach perfectly well from their own shell.
  //
  // The bundle endpoint URL follows the same rule and is the case that looks
  // like it should not: it is plain HTTPS, which a browser could fetch — but a
  // bundle endpoint sends no CORS headers, so the page goes through the api for
  // it like everything else and the URL is resolved on the api's side too.
  //
  // The two ports are not SPIRE's own. A real spire-server's default is 8081,
  // which the mock STS's HTTP port already has, so its Workload API is on 8092
  // and its SPIRE Server API on 8181. All three are in the api's
  // spiffeAllowedPorts default.
  //
  // These are EMPTY in prod.js / test-idptools-com.js, where `backendAvailable`
  // is false and neither gRPC surface can be reached at all — the page's bundle
  // reader, SVID inspector and SPIFFE ID checker still work there, and none of
  // the three needs an address.
  // ---------------------------------------------------------------------------
  spiffeTrustDomainDefault: "example.org",
  spiffeWorkloadAddressDefault: "sts:8092",
  spiffeServerAddressDefault: "sts:8181",
  spiffeBundleUrlDefault: "https://sts:8081/spiffe/bundle",

  // ---------------------------------------------------------------------------
  // SCIM 2.0 (client/public/scim.html, docs/scim.md).
  //
  // The service root the page opens on — the host plus the SCIM base path,
  // which is `/scim/v2` on essentially every implementation. NOT a resource
  // path: the page builds /Users, /Groups and the rest onto it.
  //
  // **THIS ONE IS RESOLVED BY THE BROWSER**, unlike `ldapUrlDefault` beside it,
  // which the api resolves. That is the whole difference between the two
  // workflows: SCIM is ordinary HTTPS with a JSON body, so this page calls a
  // SCIM server directly and works with no api behind it — which is why it is
  // NOT in client/static_site.js's exclusions and its landing card is not
  // greyed. So `localhost` here means the machine the BROWSER runs on, and on
  // the containerized stack that is not the same host the api sees.
  //
  // It is EMPTY in prod.js / test-idptools-com.js, because a public site has
  // no business defaulting to somebody's localhost — and a test that asserts
  // this default therefore has to read it off the page rather than assume it.
  // See tests/CLAUDE.md.
  // ---------------------------------------------------------------------------
  // `sts:8081` and NOT `localhost:8081`, like every other endpoint default in
  // this file: on the containerized stack the browser runs inside the compose
  // network, so localhost there is the tests container. This is the ONE
  // browser-resolved SCIM URL — `ldapUrlDefault` above is resolved by the api
  // instead, which is a different question with a different answer on this
  // stack, and confusing the two has cost this suite a run before.
  scimBaseUrlDefault: "https://sts:8081/scim/v2",
  // Where the cookie scheme's "sign in at the server" button goes. Empty means
  // the page uses the service root's own ORIGIN, which is the honest default:
  // a service's login screen is usually reached through a protocol flow (an
  // authorization request, a WS-Federation wsignin1.0) rather than at a URL a
  // client can name, and a button that opened a 404 would be worse than one
  // that opened the front door. Set it where a deployment does have one.
  scimSignInUrlDefault: "",

  // ---------------------------------------------------------------------------
  // SHARED SIGNALS (client/public/ssf.html, docs/ssf.md).
  //
  // The TRANSMITTER's base URL. The page looks for
  // /.well-known/ssf-configuration under it in BOTH shapes — RFC 8414 inserts
  // the well-known segment before the issuer's path and OpenID Connect
  // Discovery appends it — and every endpoint it then calls comes out of that
  // document. This page composes no paths of its own, so this one value is the
  // whole of what has to be typed.
  //
  // **IT IS RESOLVED BY THE BROWSER BY DEFAULT**, like `scimBaseUrlDefault`
  // beside it and unlike `ldapUrlDefault`: SSF's management API is ordinary
  // HTTPS with a JSON body, so the page calls a transmitter directly and works
  // with no api at all — which is why it is NOT in client/static_site.js and
  // its landing card is not greyed. Switching callPath to BackEnd moves the
  // resolution to the api, and on the containerized stack that is a different
  // host: confusing the two has cost this suite a run before.
  //
  // It is EMPTY in prod.js / test-idptools-com.js, because a public site has
  // no business defaulting to somebody's localhost — and a test that asserts
  // this default therefore has to read it off the page rather than assume it.
  ssfTransmitterUrlDefault: "https://sts:8081",


};

module.exports = config;
