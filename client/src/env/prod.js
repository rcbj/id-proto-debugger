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
  // SAML requires the api backend (ACS + signing + metadata proxy). On the
  // static deployment these are non-functional; the SAML page gates on
  // backendAvailable and explains this.
  spEntityId: "https://idptools.com/saml/sp",
  acsUrl: "https://idptools.com/samlacs",
  sloUrl: "https://idptools.com/samlslo",
  samlMetadataUrlDefault: "",
  // WS-Trust STS: no STS is bundled with the static deployment, so this is blank
  // (the user supplies an STS URL). The backend routing option is disabled here.
  wstrustStsUrlDefault: ""
};

module.exports = config;
