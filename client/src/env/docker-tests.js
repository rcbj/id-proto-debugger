var config = {
  apiUrl: "http://api:4000",
  uiUrl: "http://client:3000",
  hostname: "0.0.0.0",
  port: "3000",
  logLevel: "debug",
  // api backend is available, so both frontend and backend initiation are
  // offered.
  backendAvailable: true,
  // SAML Service Provider identity + ACS/SLO endpoints (hosted by the api
  // layer).
  spEntityId: "http://client:3000/saml/sp",
  acsUrl: "http://api:4000/samlacs",
  sloUrl: "http://api:4000/samlslo",
  // WS-Federation: RP realm default + the API landing endpoint (wreply target),
  // reachable by its compose DNS name inside the test network.
  wsfedRealm: "urn:wsfed:test:rp",
  wsfedAcsUrl: "http://api:4000/wsfed",
  wsfedMetadataUrlDefault: "http://keycloak-wsfed:8080/auth/realms/wsfed-testing/protocol/wsfed/descriptor",
  samlMetadataUrlDefault: "http://keycloak:8080/realms/debugger-testing/protocol/saml/descriptor",
  // Default WS-Trust STS endpoint (the mock STS service, reachable by its
  // compose DNS name inside the test network).
  wstrustStsUrlDefault: "http://sts:8081/sts",
  // Default OID4VCI Credential Issuer base URL (the mock issuer the STS
  // service also hosts) for the SD-JWT VC issuance workflow.
  oid4vciIssuerUrlDefault: "http://sts:8081",
  // Where the OID4VP verifier lives, for the PRESENTATION workflow. Separate
  // from the issuer above: they share an origin only on this suite's mock STS,
  // and deriving one from the other breaks the moment issuance is run against
  // walt.id (its issuer is :7005/openid4vci, its verifier a different service
  // on :7003).
  oid4vpVerifierUrlDefault: "http://sts:8081",
  // Default RFC 8414 (OAuth 2.0 Authorization Server Metadata) endpoint for
  // the Metadata Retrieval panes. The mock authorization server metadata the
  // STS service publishes.
  rfc8414MetadataUrlDefault: "http://sts:8081/.well-known/oauth-authorization-server",

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
  krb5SpnegoUrlDefault: "http://sts:8081/spnego/protected",
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


};

module.exports = config;
