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
  logLevel: "info"
};

module.exports = config;
