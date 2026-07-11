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
  logLevel: "info"
};

module.exports = config;
