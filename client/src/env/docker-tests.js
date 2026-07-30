var config = {
  apiUrl: "http://api:4000",
  uiUrl: "http://client:3000",
  hostname: "0.0.0.0",
  port: "3000",
  logLevel: "debug",
  // api backend is available, so both frontend and backend initiation are offered.
  backendAvailable: true,
  // SAML Service Provider identity + ACS/SLO endpoints (hosted by the api layer).
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
  // Default RFC 8414 (OAuth 2.0 Authorization Server Metadata) endpoint for
  // the Metadata Retrieval panes. The mock authorization server metadata the
  // STS service publishes.
  rfc8414MetadataUrlDefault: "http://sts:8081/.well-known/oauth-authorization-server"
};

module.exports = config;
