// Test-environment config for the static test.idptools.com deployment.
//
// Static site (no api backend), so token calls must be made client-side.
// uiUrl is the public test origin, used to build redirect URIs / the callback.
// NOTE: distinct from the legacy env/test.js, which targets the old
// api-backed idptools.io test site.
var config = {
  apiUrl: "https://test.idptools.com",
  uiUrl: "https://test.idptools.com",
  hostname: "0.0.0.0",
  port: "3000",
  logLevel: "info",
  // Static site: no api backend, so token/refresh/revocation/token-exchange
  // calls must originate from the frontend (browser). The UI disables the
  // "backend" initiation option when this is false.
  backendAvailable: false,
  // SAML requires the api backend (ACS + signing + metadata proxy). On the
  // static deployment these are non-functional; the SAML page gates on
  // backendAvailable and explains this.
  spEntityId: "https://test.idptools.com/saml/sp",
  acsUrl: "https://test.idptools.com/samlacs",
  sloUrl: "https://test.idptools.com/samlslo",
  samlMetadataUrlDefault: "",
  // WS-Trust STS: no STS is bundled with the static deployment, so this is blank
  // (the user supplies an STS URL). The backend routing option is disabled here.
  wstrustStsUrlDefault: ""
};

module.exports = config;
