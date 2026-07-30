var config = {
  apiUrl: "http://localhost:4000",
  uiUrl: "http://localhost:3000",
  hostname: "0.0.0.0",
  port: "3000",
  logLevel: "debug",
  // api backend is available, so both frontend and backend initiation are offered.
  backendAvailable: true,
  // SAML Service Provider identity + ACS/SLO endpoints (hosted by the api layer).
  spEntityId: "http://localhost:3000/saml/sp",
  acsUrl: "http://localhost:4000/samlacs",
  sloUrl: "http://localhost:4000/samlslo",
  // WS-Federation: RP realm default + the API landing endpoint (wreply target)
  // that captures the IdP's POSTed wresult and redirects to the response page.
  wsfedRealm: "urn:wsfed:test:rp",
  wsfedAcsUrl: "http://localhost:4000/wsfed",
  wsfedMetadataUrlDefault: "http://localhost:8082/auth/realms/wsfed-testing/protocol/wsfed/descriptor",
  samlMetadataUrlDefault: "http://localhost:8080/realms/debugger-testing/protocol/saml/descriptor",
  // Default WS-Trust STS endpoint (the mock STS service on :8081).
  wstrustStsUrlDefault: "http://localhost:8081/sts",
  // Default OID4VCI Credential Issuer base URL (the mock issuer the STS
  // service also hosts) for the SD-JWT VC issuance workflow.
  oid4vciIssuerUrlDefault: "http://localhost:8081",
  // Default RFC 8414 (OAuth 2.0 Authorization Server Metadata) endpoint for
  // the Metadata Retrieval panes. The mock authorization server metadata the
  // STS service publishes.
  rfc8414MetadataUrlDefault: "http://localhost:8081/.well-known/oauth-authorization-server"
};

module.exports = config;
