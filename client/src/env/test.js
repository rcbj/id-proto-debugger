var config = {
  apiUrl: "https://api.tools.test.idptools.io",
  uiUrl: "https://tools.test.idptools.io",
  hostname: "0.0.0.0",
  port: "3000",
  logLevel: "info",
  // api backend is available, so both frontend and backend initiation are offered.
  backendAvailable: true,
  // SAML Service Provider identity + ACS/SLO endpoints (hosted by the api layer).
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
  // Default RFC 8414 (OAuth 2.0 Authorization Server Metadata) endpoint for
  // the Metadata Retrieval panes. No mock STS on a hosted deployment: the
  // user supplies the URL.
  rfc8414MetadataUrlDefault: ""
}

module.exports = config;
