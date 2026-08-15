var config = {
  apiUrl: "https://api.tools.test.idptools.io",
  uiUrl: "https://tools.test.idptools.io",
  hostname: "0.0.0.0",
  port: "3000",
  logLevel: "info",
  // api backend is available, so both frontend and backend initiation are
  // offered.
  backendAvailable: true,
  // SAML Service Provider identity + ACS/SLO endpoints (hosted by the api
  // layer).
  spEntityId: "https://tools.test.idptools.io/saml/sp",
  acsUrl: "https://api.tools.test.idptools.io/samlacs",
  sloUrl: "https://api.tools.test.idptools.io/samlslo",
  wsfedRealm: "",
  wsfedAcsUrl: "https://api.tools.test.idptools.io/wsfed",
  wsfedMetadataUrlDefault: "",
  samlMetadataUrlDefault: "",
  wstrustStsUrlDefault: "",
  // No mock credential issuer on a hosted deployment either: the user supplies
  // the OID4VCI Credential Issuer URL.
  oid4vciIssuerUrlDefault: "",
  // Where the OID4VP verifier lives, for the PRESENTATION workflow. Separate
  // from the issuer above: they share an origin only on this suite's mock STS,
  // and deriving one from the other breaks the moment issuance is run against
  // walt.id (its issuer is :7005/openid4vci, its verifier a different service
  // on :7003).
  oid4vpVerifierUrlDefault: "",
  // Default RFC 8414 (OAuth 2.0 Authorization Server Metadata) endpoint for
  // the Metadata Retrieval panes. No mock STS on a hosted deployment: the
  // user supplies the URL.
  rfc8414MetadataUrlDefault: "",

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
  krb5PasswordDefault: "hunter2"
}

module.exports = config;
