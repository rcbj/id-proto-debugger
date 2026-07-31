// Production config for the static idptools.com deployment.
//
// This is the CONFIG_FILE baked into the browser bundles for the static build
// (browserify + envify). There is no api backend in the static deployment, so
// token endpoint calls must be made client-side (the server-side proxy option
// will not work). uiUrl is used to construct redirect URIs and the callback
// target, so it must be the public site origin.
var config = {
  apiUrl: "https://idptools.com",
  uiUrl: "https://idptools.com",
  hostname: "0.0.0.0",
  port: "3000",
  logLevel: "info",
  // Static site: no api backend, so token/refresh/revocation/token-exchange
  // calls must originate from the frontend (browser). The UI disables the
  // "backend" initiation option when this is false.
  backendAvailable: false,
  // SAML. Everything except the Artifact back-channel runs in the browser here:
  // metadata parsing, AuthnRequest signing, signature validation and
  // EncryptedAssertion decryption are all client-side already. What a static
  // site lacks is somewhere for the IdP to POST its Response — so acsUrl/sloUrl
  // are answered at the CDN edge by infra/edge/saml_landing.js, and
  // samlEdgeLanding says that function is deployed.
  //
  // It matters that this is POST rather than the Redirect binding the page falls
  // back to without a landing: saml-profiles-2.0-os section 4.1.2 says Redirect
  // MUST NOT carry the Response, and an encrypted assertion is the case where
  // that bites — ciphertext does not compress, so the redirect URL roughly
  // doubles and approaches CloudFront's 8,192-byte cap.
  //
  // HTTP-Artifact still needs the api (a server-side SOAP ArtifactResolve) and
  // remains unavailable here.
  spEntityId: "https://idptools.com/saml/sp",
  acsUrl: "https://idptools.com/samlacs",
  sloUrl: "https://idptools.com/samlslo",
  samlEdgeLanding: true,
  // WS-Federation: the passive profile returns its token by auto-POSTing to
  // wreply and defines no redirect alternative, so unlike SAML it cannot be made
  // to work by asking for a different response binding. This deployment answers
  // that POST at the CDN edge instead — a Lambda@Edge on /wsfed
  // (infra/edge/wsfed_landing.js, deployed by infra/terraform) that hands the
  // wresult to wsfed_response.html. wsfedEdgeLanding says it is deployed; it is
  // a separate flag because Terraform and the site build ship independently, and
  // with it false the page falls back to manual paste.
  wsfedRealm: "",
  wsfedAcsUrl: "https://idptools.com/wsfed",
  wsfedEdgeLanding: true,
  wsfedMetadataUrlDefault: "",
  samlMetadataUrlDefault: "",
  // WS-Trust STS: no STS is bundled with the static deployment, so this is blank
  // (the user supplies an STS URL). The backend routing option is disabled here.
  wstrustStsUrlDefault: "",
  // No mock credential issuer on a hosted deployment either: the user supplies
  // the OID4VCI Credential Issuer URL.
  oid4vciIssuerUrlDefault: "",
  // Default RFC 8414 (OAuth 2.0 Authorization Server Metadata) endpoint for
  // the Metadata Retrieval panes. No mock STS on a hosted deployment: the
  // user supplies the URL.
  rfc8414MetadataUrlDefault: ""
};

module.exports = config;
