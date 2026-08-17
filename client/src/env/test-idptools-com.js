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
  // SAML. Everything except the Artifact back-channel runs in the browser here:
  // metadata parsing, AuthnRequest signing, signature validation and
  // EncryptedAssertion decryption are all client-side already. What a static
  // site lacks is somewhere for the IdP to POST its Response — so acsUrl/sloUrl
  // are answered at the CDN edge by infra/edge/saml_landing.js, and
  // samlEdgeLanding says that function is deployed.
  //
  // It matters that this is POST rather than the Redirect binding the page
  // falls back to without a landing: saml-profiles-2.0-os section 4.1.2 says
  // Redirect MUST NOT carry the Response, and an encrypted assertion is the
  // case where that bites — ciphertext does not compress, so the redirect URL
  // roughly doubles and approaches CloudFront's 8,192-byte cap.
  //
  // HTTP-Artifact still needs the api (a server-side SOAP ArtifactResolve) and
  // remains unavailable here.
  spEntityId: "https://test.idptools.com/saml/sp",
  acsUrl: "https://test.idptools.com/samlacs",
  sloUrl: "https://test.idptools.com/samlslo",
  samlEdgeLanding: true,
  // WS-Federation: the passive profile returns its token by auto-POSTing to
  // wreply and defines no redirect alternative, so unlike SAML it cannot be
  // made to work by asking for a different response binding. This deployment
  // answers that POST at the CDN edge instead — a Lambda@Edge on /wsfed
  // (infra/edge/wsfed_landing.js, deployed by infra/terraform-test) that hands
  // the wresult to wsfed_response.html. wsfedEdgeLanding says it is deployed;
  // it is a separate flag because Terraform and the site build ship
  // independently, and with it false the page falls back to manual paste.
  wsfedRealm: "",
  wsfedAcsUrl: "https://test.idptools.com/wsfed",
  wsfedEdgeLanding: true,
  wsfedMetadataUrlDefault: "",
  samlMetadataUrlDefault: "",
  // WS-Trust STS: no STS is bundled with the static deployment, so this is
  // blank (the user supplies an STS URL). The backend routing option is
  // disabled here.
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

  // Kerberos. Empty on a build with no api behind it: the relay is what reaches a
  // KDC, and `backendAvailable` is false here, so the workflow cannot run at all and
  // a default would only be a value that fails. See local.js for why the working
  // value is a compose service name rather than localhost.
  krb5RealmDefault: "",
  krb5KdcHostDefault: "",
  krb5KdcPortDefault: "88",
  krb5PrincipalDefault: "",
  krb5PasswordDefault: "",
  // ---------------------------------------------------------------------------
  // SPNEGO's two fields, and why one of them is deliberately EMPTY.
  //
  // The URL is fetched by the **api**, not by the browser, so it follows the same
  // rule as krb5KdcHostDefault above: the compose service name where the api runs
  // in a container, loopback for a host run, and nothing at all on a build with no
  // api behind it. It was hard-coded as `http://localhost:8081/...` in
  // spnego.html, which is right for exactly one of those three.
  //
  // The SPN is empty ON PURPOSE, and must stay that way unless a deployment
  // genuinely knows better. A client derives it from the URL's host — `HTTP/<host>`,
  // which is what RFC 4559 clients and every browser do — and that derivation is
  // the thing the page exists to make visible: nothing in SPNEGO carries the SPN,
  // so when it is wrong the failure is a KDC error naming nothing about HTTP.
  // Pre-filling a value here would hide the guess behind a default and teach
  // nobody. Set it only for a service whose SPN does not match its URL host, which
  // is the case that needs saying out loud anyway.
  // ---------------------------------------------------------------------------
  krb5SpnegoUrlDefault: "",
  krb5SpnegoSpnDefault: ""

};

module.exports = config;
