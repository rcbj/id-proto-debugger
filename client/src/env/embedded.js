// File: embedded.js
//
// ---------------------------------------------------------------------------
// THE CLIENT'S CONFIGURATION WHEN THE DEBUGGER IS EMBEDDED IN THE MOCK STS.
//
// Built by `DEPLOYMENT=embedded CONFIG_FILE=./env/embedded.js node build.js`
// (embedded/build.sh does that). Like every file here it is bundled by
// browserify through envify, so it is EVALUATED IN THE BROWSER, once per page
// — which is what lets the two addresses below be the page's own origin
// rather than something written down at build time. The mock STS serves this
// UI on an origin of its own and proxies `<origin>/api/*` to the api, so:
//
//   uiUrl   = window.location.origin
//   apiUrl  = window.location.origin + "/api"
//
// and every landing derives from those exactly as api/env/embedded.js derives
// its own from DEBUGGER_UI_URL — the two files must agree, since the api
// redirects a browser to uiUrl and the page tells an identity provider to
// post to acsUrl. tests/embedded_deployment.js evaluates both.
//
// `typeof window` is guarded because node reads this file too (that test, and
// anything that requires every env file), and there `''` is the honest
// answer: there is no origin.
//
// ---------------------------------------------------------------------------
// THE MOCK STS'S OWN ADDRESS IS A PLACEHOLDER, AND THE SERVICE FILLS IT IN.
//
// The defaults that point the workflows at the mock STS need its MAIN base
// URL (https://host:8081), which is not this page's origin and is not known
// when the image is built. So they are written against the literal
// `__STS_EMBED_STS_URL__`, and the mock STS substitutes it in every `.js` and
// `.html` it serves. The literal has to SURVIVE MINIFICATION for that to
// work — terser folds `STS + "/sts"` into one string, which keeps the
// substring, but a rename of the variable must never be allowed to split it —
// so client/build.js checks, for DEPLOYMENT=embedded, that the literal is in
// every bundle that reads one of these defaults and fails the build if not.
//
// The SOCKET targets are different: Kerberos, LDAP and the SPIFFE Workload API
// are dialed by the api, which runs inside the same container as the mock STS,
// so for them `localhost` is exactly right and no substitution is needed.
// ---------------------------------------------------------------------------
var ORIGIN = (typeof window !== "undefined" && window.location &&
              window.location.origin) ? window.location.origin : "";
var STS = "__STS_EMBED_STS_URL__";

var config = {
  apiUrl: ORIGIN + "/api",
  uiUrl: ORIGIN,
  // No client server runs in this deployment — the mock STS serves the files
  // — so these three are read by nothing that matters here. They are kept
  // because bundles read the keys, and an undefined port has broken a page
  // before where an unused one has not.
  https: true,
  hostname: "0.0.0.0",
  port: "8444",
  logLevel: "info",
  // The api IS here, behind the mock STS's proxy, so both frontend and
  // backend initiation are offered and nothing is greyed.
  backendAvailable: true,
  // SAML Service Provider identity + ACS/SLO endpoints (hosted by the api
  // layer, which on this deployment is under /api).
  spEntityId: ORIGIN + "/saml/sp",
  acsUrl: ORIGIN + "/api/samlacs",
  sloUrl: ORIGIN + "/api/samlslo",
  // WS-Federation: RP realm default + the api landing endpoint (wreply).
  wsfedRealm: "urn:wsfed:test:rp",
  wsfedAcsUrl: ORIGIN + "/api/wsfed",
  // --- the mock STS, through the placeholder (see the header) --------------
  wsfedMetadataUrlDefault: STS +
      "/FederationMetadata/2007-06/FederationMetadata.xml",
  samlMetadataUrlDefault: STS + "/saml2/metadata",
  wstrustStsUrlDefault: STS + "/sts",
  oid4vciIssuerUrlDefault: STS,
  oid4vpVerifierUrlDefault: STS,
  rfc8414MetadataUrlDefault: STS + "/.well-known/oauth-authorization-server",

  // Kerberos: the KDC is dialed by the api, in the same container as the mock
  // STS, so localhost. The password is the mock's published test credential,
  // as in client/src/env/local.js.
  krb5RealmDefault: "EXAMPLE.COM",
  krb5KdcHostDefault: "localhost",
  krb5KdcPortDefault: "88",
  krb5PrincipalDefault: "alice",
  krb5PasswordDefault: "password!",
  // SPNEGO's URL is fetched by the api too, but it is an HTTP URL on the mock
  // STS's main listener, so it takes the placeholder like the rest. The SPN
  // stays empty for the reason client/src/env/local.js gives.
  krb5SpnegoUrlDefault: STS + "/spnego/protected",
  krb5SpnegoSpnDefault: "",

  // LDAP: dialed by the api, so localhost.
  ldapUrlDefault: "ldap://localhost:389",
  ldapBaseDnDefault: "dc=example,dc=com",
  ldapBindDnDefault: "cn=admin,dc=example,dc=com",
  ldapPasswordDefault: "password!",

  // SPIFFE: the Workload API is a gRPC socket the api dials (localhost); the
  // server address and the bundle endpoint are the mock STS's.
  spiffeTrustDomainDefault: "example.org",
  spiffeWorkloadAddressDefault: "localhost:8092",
  spiffeServerAddressDefault: STS,
  spiffeBundleUrlDefault: STS + "/spiffe/bundle",

  // SCIM and Shared Signals are called from the browser by default, and the
  // mock STS's main origin is what the browser has to reach.
  scimBaseUrlDefault: STS + "/scim/v2",
  scimSignInUrlDefault: "",
  ssfTransmitterUrlDefault: STS
};

module.exports = config;
