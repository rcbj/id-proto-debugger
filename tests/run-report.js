#!/usr/bin/env node
//
// run-report.js — lightweight test runner + report generator for the
// Selenium tests in this directory.
//
// Selenium WebDriver itself produces no reports; these test files are bare
// Node scripts that exit non-zero on failure. This runner executes each one
// (continuing past failures, unlike runTests() in common/common.sh which
// aborts on the first), captures exit code / output / timing, and writes a
// timestamped run directory tests/report/<timestamp>/ containing:
//
//   report.html        — human-readable report
//   report.xml         — JUnit XML (for CI dashboards)
//   logs/NN-<test>.log — full stdout+stderr per test
//
// Each test's stdout and stderr are streamed live to the console AND written
// to its log file as they are produced (a tee), so the complete output is
// captured even for long-running tests that print hundreds of lines.
//
// It reproduces the env-var wiring from runTests() so the existing test
// files run unchanged. Provide the same config vars in the environment
// (DEBUGGER_BASE_URL, CLIENT_CREDENTIALS_*, AUTHORIZATION_CODE_PUBLIC_*, etc.)
// that runTests() expects.
//
// Usage:
//   node tests/run-report.js          # run the suite, write reports
//   node tests/run-report.js --demo   # write a SAMPLE report (no tests run)
//
const { spawn, execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const bunyan = require("bunyan");

// The runner's own progress lines. They used to be console.log, which made this
// the last thing in this directory writing outside bunyan — every test it
// spawns already logs bunyan JSON, so the runner's plain lines were the odd
// ones out.
//
// Note what this changes and what it does not. These lines now come out as JSON
// like everything else, so pipe the run through `npx bunyan` for the old look.
// The REPORT is unaffected: report.html, report.xml and logs/NN-<test>.log are
// written with fs.writeFileSync and are what CI reads. And the live echo of
// each child's output further down stays process.stdout.write — it forwards
// another process's bytes as they arrive, in arbitrary chunks, so wrapping it
// would interleave JSON records with fragments of the child's own lines and
// make both unreadable.
//
// The level is guarded because this runner is started without CONFIG_FILE set
// (it sets one per job for the tests it spawns), so a bare require would throw.
const log = bunyan.createLogger({
  name: "run-report",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      // No CONFIG_FILE, or it does not resolve from here. Falling back to info
      // loses only the configured verbosity.
      return "info";
    }
  })()
});

const TESTS_DIR = __dirname;
const REPORT_DIR = path.join(TESTS_DIR, "report");
// Each run gets its own timestamped subdirectory so history is preserved.
// Filesystem-safe ISO stamp, e.g. 2026-05-30T17-45-00
const RUN_ID = new Date().toISOString().replace(/:/g, "-").replace(/\..+$/, "");
const RUN_DIR = path.join(REPORT_DIR, RUN_ID);
const LOGS_DIR = path.join(RUN_DIR, "logs");
const BASE_URL = process.env.DEBUGGER_BASE_URL || "http://localhost:3000";
const env = process.env;

// Mirror of the *active* (non-commented) test invocations in
// common/common.sh runTests(). Each job maps the suite's config vars onto the
// generic names (AUDIENCE, CLIENT_ID, ...) each test script reads.
function buildJobs() {
  log.debug("Entering buildJobs().");
  const jobs = [];

  // Basic navigation: landing page -> OAuth2/OIDC debugger -> Home -> SAML ->
  // Home.
  jobs.push({
    name: "Navigation (landing page → OAuth2/OIDC → Home → SAML → Home)",
    script: "navigation.js",
    env: {},
  });

  // What the STATIC deployments leave out (client/static_site.js). Kerberos is
  // DER over port 88, so every page of it goes through the api's relay and
  // idptools.com has no api: the static build drops those pages and greys their
  // landing card. Every part of that fails silently when it drifts — an
  // exclusion naming a renamed file removes nothing, a card that stops matching
  // its marker stays a live link to a page the build just deleted, and a
  // surviving page linking to a dropped one is a 404 no test clicks. This is
  // also the only check that the exclusion has NOT escaped into
  // client/Dockerfile, which must still build all five for the container.
  // Node only — no browser, no services — so it never skips.
  jobs.push({
    name: "Static deployment exclusions (the dropped pages, the greyed " +
        "landing card, no dead links)",
    script: "static_site_exclusions.js",
    env: {},
  });

  jobs.push({
    name: "OAuth2 Client Credentials",
    script: "oauth2_client_credentials.js",
    env: {
      AUDIENCE: env.CLIENT_CREDENTIALS_AUDIENCE,
      DISCOVERY_ENDPOINT: env.CLIENT_CREDENTIALS_DISCOVERY_ENDPOINT,
      CLIENT_ID: env.CLIENT_CREDENTIALS_CLIENT_ID,
      CLIENT_SECRET: env.CLIENT_CREDENTIALS_CLIENT_SECRET,
      SCOPE: env.CLIENT_CREDENTIALS_SCOPE,
    },
  });

  for (const PKCE_ENABLED of ["true", "false"]) {
    jobs.push({
      name: `OAuth2 Authorization Code (public, PKCE=${PKCE_ENABLED})`,
      script: "oauth2_authorization_code.js",
      env: {
        AUDIENCE: env.AUTHORIZATION_CODE_PUBLIC_AUDIENCE,
        DISCOVERY_ENDPOINT: env.AUTHORIZATION_CODE_PUBLIC_DISCOVERY_ENDPOINT,
        CLIENT_ID: env.AUTHORIZATION_CODE_PUBLIC_CLIENT_ID,
        CLIENT_SECRET: env.AUTHORIZATION_CODE_PUBLIC_CLIENT_SECRET,
        SCOPE: env.AUTHORIZATION_CODE_PUBLIC_SCOPE,
        USER: env.AUTHORIZATION_CODE_PUBLIC_USER,
        PKCE_ENABLED,
      },
    });
  }

  jobs.push({
    name: "OAuth2 Implicit",
    script: "oauth2_implicit.js",
    env: {
      AUDIENCE: env.IMPLICIT_AUDIENCE,
      DISCOVERY_ENDPOINT: env.IMPLICIT_DISCOVERY_ENDPOINT,
      CLIENT_ID: env.IMPLICIT_CLIENT_ID,
      SCOPE: env.IMPLICIT_SCOPE,
      USER: env.IMPLICIT_USER,
    },
  });

  jobs.push({
    name: "OAuth2 Resource Owner Password Credentials",
    script: "oauth2_resource_owner_password_credentials_grant.js",
    env: {
      AUDIENCE: env.RESOURCE_OWNER_CREDENTIAL_AUDIENCE,
      DISCOVERY_ENDPOINT: env.RESOURCE_OWNER_CREDENTIAL_DISCOVERY_ENDPOINT,
      CLIENT_ID: env.RESOURCE_OWNER_CREDENTIAL_CLIENT_ID,
      CLIENT_SECRET: env.RESOURCE_OWNER_CREDENTIAL_CLIENT_SECRET,
      SCOPE: env.RESOURCE_OWNER_CREDENTIAL_SCOPE,
      USER: env.RESOURCE_OWNER_CREDENTIAL_USER,
    },
  });

  for (const PKCE_ENABLED of ["true", "false"]) {
    jobs.push({
      name: `OIDC Authorization Code (public, PKCE=${PKCE_ENABLED})`,
      script: "oidc_authorization_code.js",
      env: {
        AUDIENCE: env.OIDC_AUTHORIZATION_CODE_PUBLIC_AUDIENCE,
        DISCOVERY_ENDPOINT: env.OIDC_AUTHORIZATION_CODE_PUBLIC_DISCOVERY_ENDPOINT,
        CLIENT_ID: env.OIDC_AUTHORIZATION_CODE_PUBLIC_CLIENT_ID,
        CLIENT_SECRET: env.OIDC_AUTHORIZATION_CODE_PUBLIC_CLIENT_SECRET,
        // matches runTests(): the OIDC scope is prefixed with the std scopes
        SCOPE: `openid profile email offline_access ${env.OIDC_AUTHORIZATION_CODE_PUBLIC_SCOPE || ""}`.trim(),
        USER: env.OIDC_AUTHORIZATION_CODE_PUBLIC_USER,
        PKCE_ENABLED,
      },
    });
  }

  // Every OIDC authentication flow against the mock STS, with DPoP and without:
  // six flows times two, twelve jobs from one script.
  //
  // The STS is the OP for two reasons: it advertises and implements all seven
  // response types, and it is in this project's control, so a failure is a
  // failure in the debugger. That also means these need no identity provider —
  // the gate is the STS, like the WS-Trust jobs.
  //
  // Both halves of the DPoP axis earn their place. `on` is not simply "and it
  // still works": for the four code-bearing flows it requires dpop_jkt on the
  // authorization request and cnf.jkt on the exchanged token, and for the two
  // Implicit ones it requires the opposite — nothing bound, and the pane saying
  // why, since those flows never reach a token endpoint. `off` is what keeps
  // the Bearer path, which is what the specifications describe first, from
  // quietly becoming un-runnable.
  if (env.WSTRUST_STS_URL) {
    const OIDC_FLOWS = [
      ["oidc_authorization_code_flow", "OIDC Authorization Code Flow (code)"],
      ["oidc_implicit_flow", "OIDC Implicit Flow (id_token token)"],
      ["oidc_implicit_flow_id_token", "OIDC Implicit Flow (id_token)"],
      ["oidc_hybrid_code_id_token", "OIDC Hybrid (code id_token)"],
      ["oidc_hybrid_code_token", "OIDC Hybrid (code token)"],
      ["oidc_hybrid_code_id_token_token", "OIDC Hybrid (code id_token token)"],
    ];
    for (const [OIDC_FLOW, label] of OIDC_FLOWS) {
      for (const OIDC_DPOP of ["off", "on"]) {
        jobs.push({
          name: `${label} — mock STS, DPoP ${OIDC_DPOP}`,
          script: "oidc_flows.js",
          // The client id, scope and username are the script's own: the mock
          // registers no clients and checks no passwords, so there is nothing
          // for the suite to provision and nothing to keep in step here.
          env: { WSTRUST_STS_URL: env.WSTRUST_STS_URL, OIDC_FLOW, OIDC_DPOP },
        });
      }
    }
  }

  // The same twelve against KEYCLOAK, which asks the other half of the
  // question: whether any of it interoperates with a real OP. Gated on the
  // client configureKeycloak() provisions for it (OIDC_ALL_FLOWS_PUBLIC) — one
  // client with standardFlowEnabled AND implicitFlowEnabled, since Keycloak
  // gates the response types on that pair, and without "always use DPoP" so
  // that both halves of the DPoP axis run against it.
  //
  // Note what differs from the mock and is passed in rather than assumed:
  // Keycloak's `sub` is a UUID (OIDC_EXPECT_SUB), which is a different string
  // from the name typed at the login screen (OIDC_LOGIN_USER). The DPoP jobs
  // also need the server started with --features=dpop; the test checks the
  // metadata advertises DPoP and says so by name rather than failing at the
  // last assertion.
  if (env.OIDC_ALL_FLOWS_PUBLIC_DISCOVERY_ENDPOINT) {
    const OIDC_FLOWS_KC = [
      ["oidc_authorization_code_flow", "OIDC Authorization Code Flow (code)"],
      ["oidc_implicit_flow", "OIDC Implicit Flow (id_token token)"],
      ["oidc_implicit_flow_id_token", "OIDC Implicit Flow (id_token)"],
      ["oidc_hybrid_code_id_token", "OIDC Hybrid (code id_token)"],
      ["oidc_hybrid_code_token", "OIDC Hybrid (code token)"],
      ["oidc_hybrid_code_id_token_token", "OIDC Hybrid (code id_token token)"],
    ];
    for (const [OIDC_FLOW, label] of OIDC_FLOWS_KC) {
      for (const OIDC_DPOP of ["off", "on"]) {
        jobs.push({
          name: `${label} — Keycloak, DPoP ${OIDC_DPOP}`,
          script: "oidc_flows.js",
          env: {
            DISCOVERY_ENDPOINT: env.OIDC_ALL_FLOWS_PUBLIC_DISCOVERY_ENDPOINT,
            CLIENT_ID: env.OIDC_ALL_FLOWS_PUBLIC_CLIENT_ID,
            // No offline_access: it is refused on the Implicit flows, and a
            // refresh token is not what any of these twelve are about.
            SCOPE: `openid profile email ${env.OIDC_ALL_FLOWS_PUBLIC_SCOPE ||
                ""}`.trim(),
            OIDC_LOGIN_USER: env.OIDC_ALL_FLOWS_PUBLIC_USERNAME,
            OIDC_EXPECT_SUB: env.OIDC_ALL_FLOWS_PUBLIC_USER,
            OIDC_FLOW,
            OIDC_DPOP,
          },
        });
      }
    }
  }

  // The UserInfo endpoint through all three of debugger2.html's "UserInfo Data"
  // links — the token set the flow produced, the one the refresh call produced,
  // and the one selected from Token History. The three differ only in which
  // access token they carry, which is exactly the failure a single call cannot
  // see: every token in the run belongs to the same user, so a link carrying
  // the wrong one still returns a correct-looking answer.
  //
  // Runs against both OPs, like the flow matrix. Unlike it, this one exercises
  // the UserInfo page's DEFAULT configuration, which on a build that HAS the
  // api initiates the call from it — so these two jobs need the api service as
  // well as the OP. On a backend-less target (the deployed static sites) the
  // page disables that option and calls the OP from the browser instead; the
  // test reads which build it is off the page rather than being told here,
  // because it is the page's own state that decides what pressing the button
  // does.
  if (env.WSTRUST_STS_URL) {
    jobs.push({
      name: "OIDC UserInfo through all three token sets — mock STS",
      script: "oidc_userinfo.js",
      env: { WSTRUST_STS_URL: env.WSTRUST_STS_URL },
    });
  }
  if (env.OIDC_ALL_FLOWS_PUBLIC_DISCOVERY_ENDPOINT) {
    jobs.push({
      name: "OIDC UserInfo through all three token sets — Keycloak",
      script: "oidc_userinfo.js",
      env: {
        DISCOVERY_ENDPOINT: env.OIDC_ALL_FLOWS_PUBLIC_DISCOVERY_ENDPOINT,
        CLIENT_ID: env.OIDC_ALL_FLOWS_PUBLIC_CLIENT_ID,
        SCOPE: `openid profile email ${env.OIDC_ALL_FLOWS_PUBLIC_SCOPE ||
            ""}`.trim(),
        OIDC_LOGIN_USER: env.OIDC_ALL_FLOWS_PUBLIC_USERNAME,
      },
    });
  }

  // DPoP is OPTIONAL on the OAuth2 / OIDC workflow: off by default, on when the
  // pane asks for it, and — the case this exists for — not decided by the
  // SD-JWT VC workflow's own switch, which is what used to make it mandatory
  // here.
  if (env.WSTRUST_STS_URL) {
    jobs.push({
      name: "OIDC DPoP is optional (RFC 9449: off by default, on when asked, " +
          "never inherited)",
      script: "oidc_dpop_optional.js",
      env: { WSTRUST_STS_URL: env.WSTRUST_STS_URL },
    });
  }

  // Token Revocation (RFC 7009). Uses the OIDC public client with the
  // offline_access scope so a refresh token is issued and can be revoked
  // alongside the access token.
  jobs.push({
    name: "OAuth2 Token Revocation (RFC 7009)",
    script: "oauth2_token_revocation.js",
    env: {
      AUDIENCE: env.OIDC_AUTHORIZATION_CODE_PUBLIC_AUDIENCE,
      DISCOVERY_ENDPOINT: env.OIDC_AUTHORIZATION_CODE_PUBLIC_DISCOVERY_ENDPOINT,
      CLIENT_ID: env.OIDC_AUTHORIZATION_CODE_PUBLIC_CLIENT_ID,
      CLIENT_SECRET: env.OIDC_AUTHORIZATION_CODE_PUBLIC_CLIENT_SECRET,
      SCOPE: `openid profile email offline_access ${env.OIDC_AUTHORIZATION_CODE_PUBLIC_SCOPE || ""}`.trim(),
      USER: env.OIDC_AUTHORIZATION_CODE_PUBLIC_USER,
      PKCE_ENABLED: "true",
      // The Token Introspection Endpoint is called as the confidential client,
      // which is permitted to introspect (the public/PKCE client is not).
      INTROSPECTION_CLIENT_ID: env.AUTHORIZATION_CODE_CONFIDENTIAL_CLIENT_ID,
      INTROSPECTION_CLIENT_SECRET: env.AUTHORIZATION_CODE_CONFIDENTIAL_CLIENT_SECRET,
    },
  });

  // Token Introspection (RFC 7662). Signs in via the OIDC Authorization Code
  // flow, then exercises all six "Introspect Token" links on the debugger
  // (initial access/refresh, refresh-call access/refresh, and Token History
  // access/refresh), confirming each reports the token as active.
  //
  // A single confidential client (TOKEN_INTROSPECTION, created in
  // common/common.sh) is used for BOTH the sign-in and the introspection
  // calls. Keycloak only returns active=true when the introspecting client is
  // in an access token's audience AND is the client a refresh token was issued
  // to, so the same client must own the tokens and introspect them. It carries
  // a self-audience mapper so its own access tokens introspect as active.
  jobs.push({
    name: "OAuth2 Token Introspection (RFC 7662)",
    script: "token_introspection.js",
    env: {
      AUDIENCE: env.TOKEN_INTROSPECTION_AUDIENCE,
      DISCOVERY_ENDPOINT: env.TOKEN_INTROSPECTION_DISCOVERY_ENDPOINT,
      CLIENT_ID: env.TOKEN_INTROSPECTION_CLIENT_ID,
      CLIENT_SECRET: env.TOKEN_INTROSPECTION_CLIENT_SECRET,
      SCOPE: `openid profile email offline_access ${env.TOKEN_INTROSPECTION_SCOPE || ""}`.trim(),
      USER: env.TOKEN_INTROSPECTION_USER,
      // Confidential client, so no PKCE — it authenticates with its secret.
      PKCE_ENABLED: "false",
      // Introspect as the same confidential client that obtained the tokens: it
      // is in its own access tokens' audience and owns its refresh tokens, so
      // Keycloak reports active=true for both.
      INTROSPECTION_CLIENT_ID: env.TOKEN_INTROSPECTION_CLIENT_ID,
      INTROSPECTION_CLIENT_SECRET: env.TOKEN_INTROSPECTION_CLIENT_SECRET,
    },
  });

  // Token Exchange (RFC 8693). The requesting confidential client obtains a
  // subject token via the auth code flow, exchanges it for a token aimed at the
  // target audience client, and the issued token is confirmed via
  // introspection.
  jobs.push({
    name: "OAuth2 Token Exchange (RFC 8693)",
    script: "oauth2_token_exchange.js",
    env: {
      DISCOVERY_ENDPOINT: env.TOKEN_EXCHANGE_DISCOVERY_ENDPOINT,
      CLIENT_ID: env.TOKEN_EXCHANGE_CLIENT_ID,
      CLIENT_SECRET: env.TOKEN_EXCHANGE_CLIENT_SECRET,
      SCOPE: "openid profile email",
      USER: env.TOKEN_EXCHANGE_USER,
      PKCE_ENABLED: "false",
      // The target client whose audience the exchanged token is aimed at.
      AUDIENCE_CLIENT_ID: env.TOKEN_EXCHANGE_TARGET_CLIENT_ID,
      // Introspect as the target (audience) client. As of Keycloak 26.2 the
      // introspection endpoint returns {"active": false} unless the
      // authenticated client is present in the token's "aud" claim, and the
      // exchanged token is aimed solely at the target client's audience.
      INTROSPECTION_CLIENT_ID: env.TOKEN_EXCHANGE_TARGET_CLIENT_ID,
      INTROSPECTION_CLIENT_SECRET: env.TOKEN_EXCHANGE_TARGET_CLIENT_SECRET,
    },
  });

  // Device Authorization Grant (RFC 8628). Requests a device/user code,
  // approves the device at the Keycloak verification URI, then polls for the
  // access token.
  jobs.push({
    name: "OAuth2 Device Authorization Grant (RFC 8628)",
    script: "oauth2_device_authorization.js",
    env: {
      DISCOVERY_ENDPOINT: env.DEVICE_AUTHORIZATION_GRANT_DISCOVERY_ENDPOINT,
      CLIENT_ID: env.DEVICE_AUTHORIZATION_GRANT_CLIENT_ID,
      CLIENT_SECRET: env.DEVICE_AUTHORIZATION_GRANT_CLIENT_SECRET,
      SCOPE: "openid profile email",
      USER: env.DEVICE_AUTHORIZATION_GRANT_USER,
    },
  });

  // OIDC Dynamic Client Registration (OpenID Connect Registration 1.0 /
  // RFC 7591 / RFC 7592). Creates a client using an initial access token, then
  // reads, updates, and deletes it via the client configuration endpoint.
  jobs.push({
    name: "OIDC Dynamic Client Registration",
    script: "oidc_dynamic_client_registration.js",
    env: {
      DISCOVERY_ENDPOINT: env.DYNAMIC_CLIENT_REGISTRATION_DISCOVERY_ENDPOINT,
      INITIAL_ACCESS_TOKEN: env.DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN,
    },
  });

  // JWT Tools page. First obtains a real OIDC ID Token via the Authorization
  // Code grant (public client), pastes it into the Encoded JWT field and
  // confirms the decoded Payload matches the token. Then, from the debugger,
  // opens the Tools pane, follows the JWT Tools link, adds
  // string/number/boolean claims and checks RFC compliance, and exercises
  // signing + X.509 verification and JWE encryption + decryption, including the
  // PEM/JWK format toggle and the key-download buttons.
  jobs.push({
    name: "JWT Tools (ID Token decode, compose, sign/verify, encrypt/decrypt)",
    script: "jwt_tools.js",
    env: {
      AUDIENCE: env.OIDC_AUTHORIZATION_CODE_PUBLIC_AUDIENCE,
      DISCOVERY_ENDPOINT: env.OIDC_AUTHORIZATION_CODE_PUBLIC_DISCOVERY_ENDPOINT,
      CLIENT_ID: env.OIDC_AUTHORIZATION_CODE_PUBLIC_CLIENT_ID,
      CLIENT_SECRET: env.OIDC_AUTHORIZATION_CODE_PUBLIC_CLIENT_SECRET,
      SCOPE: `openid profile email offline_access ${env.OIDC_AUTHORIZATION_CODE_PUBLIC_SCOPE || ""}`.trim(),
      USER: env.OIDC_AUTHORIZATION_CODE_PUBLIC_USER,
      PKCE_ENABLED: "true",
    },
  });

  // Encoding / Hashing Tools page. A fully client-side page needing no IdP:
  // opens it from the debugger Tools pane, confirms the on-load defaults, then
  // exercises every button — Base64 Encode/Decode (verifying the decoded value
  // round-trips to the original), URI Encode/Decode, the one-way CRC-32
  // Checksum, and SHA hashing across all four digest sizes — validating each
  // output against an independently computed reference value.
  jobs.push({
    name: "Encoding / Hashing Tools (Base64, URI, CRC-32, SHA)",
    script: "encoding_tools.js",
    env: {},
  });

  // Digital Signature page. A fully client-side page needing no IdP. For every
  // pane it sets a value, generates a key, produces a signature/MAC, confirms
  // it validates, and exercises the keystore downloads. Asymmetric: SLH-DSA (12
  // sets); RSA (v1.5 & PSS × every hash × 2048/3072); ECC (ECDSA over
  // P-256/384/521/secp256k1 × every hash, EdDSA, Schnorr, BLS); ML-DSA
  // (44/65/87). Symmetric MACs: keyed-hash (HMAC/KMAC/BLAKE), block-cipher
  // (CMAC/CBC-MAC/ GMAC), universal-hash (Poly1305/SipHash) — compute + verify
  // + tamper check.
  jobs.push({
    name: "Digital Signature (asymmetric sigs + symmetric MACs — generate, " +
        "sign/MAC, validate, download)",
    script: "digital_signature.js",
    env: {},
  });

  // SAML Assertion Tool. Another fully client-side page needing no IdP: compose
  // an assertion for each SAML version (2.0 / 1.1 / 1.0) with its
  // version-specific structure, toggle the optional elements, add typed +
  // URI-prefixed custom attributes, run the spec-compliance check, then sign it
  // with an enveloped XML Signature (whose placement and Reference URI differ
  // per version), verify it, reject a tampered copy, and round-trip it through
  // XML Encryption. Also checks the Tools pane on the SAML Test Tools page
  // links here. Operations History pane on the SAML request page: records every
  // attempted IdP call (AuthnRequest / Single Logout / metadata load) with its
  // binding, SAML version, entity IDs, and result. Needs no IdP — the failure
  // paths come from the page's own pre-flight checks and the dispatch is aimed
  // at a URL on the site itself. RFC 8414 (OAuth 2.0 Authorization Server
  // Metadata): the document the STS mock serves at
  // /.well-known/oauth-authorization-server (all 23 members, host-derived
  // issuer, verifiable signed_metadata, resolvable jwks_uri) and the Metadata
  // Source selector on debugger.html that retrieves it. Needs the STS mock,
  // like the WS-Trust jobs.
  if (env.WSTRUST_STS_URL) {
    jobs.push({
      name: "OAuth2 Authorization Server Metadata (RFC 8414 endpoint + " +
          "debugger Metadata Source)",
      script: "oauth2_metadata_rfc8414.js",
      env: { WSTRUST_STS_URL: env.WSTRUST_STS_URL },
    });
  }

  // The mock authorization server the STS service hosts: every endpoint its
  // RFC 8414 document advertises answers, with real RS256 tokens that verify
  // against the advertised JWKS. No browser — it drives the endpoints directly.
  if (env.WSTRUST_STS_URL) {
    jobs.push({
      name: "OAuth2 Authorization Server endpoints (the STS mock's authorize " +
          "/ token / introspect / revoke / register)",
      script: "oauth2_sts_endpoints.js",
      env: { WSTRUST_STS_URL: env.WSTRUST_STS_URL },
    });
  }

  // The shared in-browser JWE implementation, tested directly: every alg/enc
  // pair round-trips, and the Concat KDF is checked against an implementation
  // written from RFC 7518 section 4.6 that shares no code with it. Needs no
  // services — node's Web Crypto is enough — so it is never skipped.
  jobs.push({
    name: "JOSE JWE module (RFC 7516/7518: RSA-OAEP, ECDH-ES, Concat KDF)",
    script: "jose_jwe_encryption.js",
    env: {},
  });

  // The "save this key pair in browser localStorage" opt-out on the SAML and
  // WS-Trust request pages, exercised in BOTH states. Worth a browser test
  // because the failure mode is silent and reassuring: if the guard in
  // saveState() broke, the box would still untick and the note would still
  // appear while the private key went on being written. Only reading storage
  // shows it. Needs the client alone — no IdP, no STS — so it is never skipped.
  jobs.push({
    name: "Key pair localStorage opt-out (SAML, WS-Trust, WS-Fed, SD-JWT VC " +
        "— checked and unchecked)",
    script: "keypair_storage_optout.js",
    env: {},
  });

  // The inertness of this app's XML parsing — the invariant behind CodeQL's
  // js/xss-through-dom reports on every DOMParser call in client/src (alert
  // #147 and eleven siblings). Those are a modelling artefact: parseFromString
  // with 'application/xml' yields an inert, detached document, and nothing
  // renders it as markup. Sanitizing the input would be the wrong fix —
  // XML-DSIG signs the exact octets that get canonicalized, so rewriting them
  // breaks the signature. What CAN be done is keep the premise true, which is
  // what this asserts. Node only, never skipped.
  jobs.push({
    name: "XML parsing is inert (no DOMParser HTML mode, no markup sink on " +
        "the XML path)",
    script: "xml_parse_inert.js",
    env: {},
  });

  // The scheme allowlist applied before the app navigates anywhere
  // (client/src/url_safety.js). Every URL it guards is caller-supplied — a
  // typed IdP endpoint, or one out of fetched metadata — and reaches
  // window.location.assign() or a form action, where `javascript:` is script
  // execution in this origin. The cases that earn the test are the ones the URL
  // parser normalises: `java\tscript:` and a leading control character are both
  // the javascript: protocol by the time the browser acts. Node only, never
  // skipped.
  jobs.push({
    name: "URL safety (only http/https reaches a navigation sink)",
    script: "url_safety_schemes.js",
    env: {},
  });

  // The JWK -> SPKI PEM encoder the JWKS page displays (client/src/jwk_pem.js).
  // It exists so the page does not have to require `jwk-to-pem`, which reaches
  // `elliptic` — GHSA-848j-6mx2-7j84, an ECDSA flaw that can expose a private
  // key, and one with NO patched version in existence. That trade is only sound
  // if the replacement encodes correctly, so this checks the DER against node's
  // own SPKI parser, and additionally fails if any file in client/src takes a
  // require that would put elliptic back into a bundle. Node only, never
  // skipped.
  //
  // It carries two more source checks of the same kind, both about things that
  // reach a bundle and break it: no BigInt literal in client/src (envify's
  // esprima cannot parse one, and the build then fails against a file nobody
  // touched), and no `require`/`process` in coverage_beacon.js — the one file
  // there that is APPENDED to finished bundles rather than browserified, so a
  // require in it is an uncaught ReferenceError on every instrumented page.
  // That last one is invisible to this suite's own launchers, which never
  // append the beacon; only ./run-coverage.sh does, and it failed 12 tests and
  // shipped an empty frontend report on 2026-08-14 for exactly that.
  jobs.push({
    name: "JWK to PEM encoder (SPKI DER correctness; elliptic, BigInt " +
        "literals and require() stay out of the bundles)",
    script: "jwk_pem_encoding.js",
    env: {},
  });

  // Every test in this suite that builds a Selenium driver must start Chrome
  // headless, and must do so BY DEFAULT rather than when asked. A test written
  // by copying a neighbour easily picks up browser_flags.js — which handles the
  // secure-context and private-network hazards and says nothing about headless
  // mode — while missing the flag itself; kerberos_delegation_page.js did
  // exactly that and opened a window on every run. On a desktop that steals
  // focus for the length of the run; on a CI runner or in a container there is
  // no display at all, so the session fails to start and names the page the
  // test was about to visit. Reads this directory's sources: node only, no
  // browser, never skipped.
  jobs.push({
    name: "Browser tests are headless (every driver-building test, by " +
        "default)",
    script: "browser_tests_headless.js",
    env: {},
  });

  // The WebAuthn decoder (client/src/cbor.js, cose.js, webauthn.js) against
  // REAL ceremonies — ES256 and RS256, registration and assertion — produced by
  // the WebDriver virtual authenticator and committed as
  // tests/webauthn_vectors.json. Two oracles neither of which is ours: the
  // browser's own getPublicKey(), which our COSE -> JWK -> SPKI chain must
  // reproduce byte for byte, and node's crypto, which verifies the same
  // signatures independently. Then the negatives, each failing exactly one
  // named check — including a UV-clear assertion that must be rejected on the
  // FLAG while its signature stays valid, because reporting that as a bad
  // signature would send the user after the wrong thing. Node only, no browser,
  // no network, never skipped.
  jobs.push({
    name: "WebAuthn decoder (CBOR, COSE_Key, authenticator data, assertion " +
        "verification)",
    script: "webauthn_decode.js",
    env: {},
  });

  // The wallet's WebAuthn decoder and the STS's, over the same real ceremonies,
  // required to reach the same verdict on each. The two share no code —
  // different CBOR readers, different COSE mappings, and different signature
  // paths, since node takes an ECDSA signature as DER while Web Crypto demands
  // raw r‖s — so a mistake in one is not mirrored in the other. One
  // implementation agreeing with itself is not a result; two independent
  // readings of section 7.2 agreeing is. Same arrangement as
  // bbs2023_cryptosuite.js. Node only, never skipped.
  jobs.push({
    name: "WebAuthn: the wallet's decoder and the STS's agree " +
        "(cross-implementation)",
    script: "webauthn_cross_impl.js",
    env: {},
  });

  // The WebAuthn Analyzer PAGE, driven against the same real ceremonies. It
  // covers what the node test above cannot: that the decoded values reach the
  // screen. Those are different failures — a pane left empty by a renamed
  // element id decodes perfectly and shows nothing — and only this one catches
  // the second. Needs the client and nothing else: the page performs no
  // ceremony, so there is no authenticator, no IdP and no network involved.
  jobs.push({
    name: "WebAuthn Analyzer page (decode and verify pasted artifacts)",
    script: "webauthn_analyzer_page.js",
    env: {},
  });

  // The WebAuthn Lab page, running REAL ceremonies against the WebDriver
  // virtual authenticator — a CTAP2 authenticator inside the browser, so no
  // hardware, no touch and no flake. Registration, assertion, the counter
  // advancing across two assertions, and the no-credential path reported rather
  // than hung. Note what is NOT here: a UV-required ceremony against an
  // authenticator that cannot verify is refused by the BROWSER, so the relying
  // party never sees a UV-clear assertion and that check cannot be exercised
  // from this page; it lives in webauthn_decode.js, where the material can be
  // manufactured. Needs the client and nothing else.
  jobs.push({
    name: "WebAuthn Lab page (real ceremonies against a virtual authenticator)",
    script: "webauthn_lab_page.js",
    env: {},
  });

  // WebAuthn as the SECOND FACTOR of an OIDC Authorization Code sign-in against
  // the mock STS — the join between the two protocols, and the reason the
  // workflow was built against this service. A relying party asks for step-up
  // with acr_values, a real ceremony happens against the virtual authenticator,
  // and the ID token records it as amr ["pwd","hwk"] with acr "mfa". The last
  // section is the one that matters: a sign-in WITHOUT the second factor must
  // report ["pwd"] and acr "1", because a service that stamped hwk on every
  // token would pass every other check here. Needs the STS (no Keycloak, no
  // hardware), so it is gated on WSTRUST_STS_URL like the rest.
  if (env.WSTRUST_STS_URL) {
    jobs.push({
      name: "WebAuthn as OIDC second factor (amr/acr earned, not decorative)",
      script: "webauthn_oidc_mfa.js",
      env: { WSTRUST_STS_URL: env.WSTRUST_STS_URL },
    });
  }

  // The browser extension, side-loaded for real, watching a ceremony on an
  // origin that is not the debugger's — which is the only way to debug somebody
  // else's relying party, and the reason the extension exists. Two claims are
  // checked: that both halves arrive (the REQUEST half especially, which no
  // relying party shows anybody and pasting a response can never produce), and
  // that the extension changes NOTHING about the ceremony it watches. Nobody
  // reviews an unpacked extension on our behalf, so that second one is the
  // whole of the read-only guarantee.
  //
  // Needs the STS, and needs the extension built (buildBrowserExtension() in
  // common/common.sh, called by the launchers before compose). It will NOT run
  // against branded Google Chrome, which refuses to side-load an unpacked
  // extension; the image pins Chrome for Testing, which allows it.
  if (env.WSTRUST_STS_URL) {
    const browser = extensionCapableBrowser();
    const extensionJob = {
      name: "WebAuthn browser extension (observes a third party, " +
          "changes nothing)",
      script: "webauthn_extension.js",
      env: { WSTRUST_STS_URL: env.WSTRUST_STS_URL },
    };
    if (browser.capable && browser.bin) {
      // Use the binary we probed, not whatever Selenium would pick.
      extensionJob.env.CHROME_BIN = browser.bin;
    }
    if (!browser.capable) {
      extensionJob.skip =
        "this browser cannot side-load an unpacked extension: " +
        (browser.version || "no chrome/chromium found on PATH") +
         ". Branded Google Chrome refuses " +
        "the flags and reports it only on stderr, so the job would fail with " +
            "every assertion timing " +
        "out and nothing naming the cause. The containerized suite pins " +
            "Chrome for Testing and does " +
        "run it; to run it here, point CHROME_BIN at a Chrome-for-Testing or Chromium build.";
    }
    jobs.push(extensionJob);
  }

  // The wallet's DID module (client/src/did.js): did:jwk, did:key and did:web,
  // reading a DID document, and the DIF Well Known DID Configuration check that
  // proves a DID and an origin are the same entity. Everything here fails
  // silently when it is wrong — a multicodec written as a fixed-width number
  // instead of a varint produces DIDs that decode here and nowhere else, a
  // compressed EC point decompressed with the wrong square root gives the other
  // valid point on the curve, and a Domain Linkage Credential with a typ header
  // or an iat claim is exactly what a JWT library produces by default. It found
  // a real bug on its first run: P-384's and P-521's field primes were
  // truncated. Node only, never skipped.
  jobs.push({
    name: "DID module (did:jwk/key/web, document reading, DIF domain linkage)",
    script: "did_document.js",
    env: {},
  });

  // DPoP's own arithmetic (client/src/dpop.js): the RFC 7638 JWK Thumbprint
  // that becomes cnf.jkt, the htu normalization, the ath hash, and the shape of
  // the proof itself. Every one of those fails SILENTLY when it is wrong — a
  // proof with a wrong thumbprint or a wrong htu is perfectly well formed and
  // simply matches nothing, so the server's refusal reads as "your key is
  // wrong" rather than "your encoding is wrong". The oracle is not a second
  // implementation but the RFCs' own published values: RFC 9449 prints an EC
  // key and the jkt of the token bound to it, RFC 7638 section 3.1 does the
  // same for RSA. Node only, never skipped.
  jobs.push({
    name: "DPoP arithmetic (RFC 7638 thumbprints against the RFCs' own " +
        "vectors, htu/ath/jti)",
    script: "dpop_vectors.js",
    env: {},
  });

  // The wallet's DID module (client/src/did.js): did:jwk, did:key and did:web,
  // reading a DID document, and the DIF Well Known DID Configuration check that
  // proves a DID and an origin are the same entity. Everything here fails
  // silently when it is wrong — a multicodec written as a fixed-width number
  // instead of a varint produces DIDs that decode here and nowhere else, a
  // compressed EC point decompressed with the wrong square root gives the other
  // valid point on the curve, and a Domain Linkage Credential with a typ header
  // or an iat claim is exactly what a JWT library produces by default. It found
  // a real bug on its first run: P-384's and P-521's field primes were
  // truncated. Node only, never skipped.
  jobs.push({
    name: "DID module (did:jwk/key/web, document reading, DIF domain linkage)",
    script: "did_document.js",
    env: {},
  });

  // DPoP's own arithmetic (client/src/dpop.js): the RFC 7638 JWK Thumbprint
  // that becomes cnf.jkt, the htu normalization, the ath hash, and the shape of
  // the proof itself. Every one of those fails SILENTLY when it is wrong — a
  // proof with a wrong thumbprint or a wrong htu is perfectly well formed and
  // simply matches nothing, so the server's refusal reads as "your key is
  // wrong" rather than "your encoding is wrong". The oracle is not a second
  // implementation but the RFCs' own published values: RFC 9449 prints an EC
  // key and the jkt of the token bound to it, RFC 7638 section 3.1 does the
  // same for RSA. Node only, never skipped.
  jobs.push({
    name: "DPoP arithmetic (RFC 7638 thumbprints against the RFCs' own " +
        "vectors, htu/ath/jti)",
    script: "dpop_vectors.js",
    env: {},
  });

  // The wallet's DID module (client/src/did.js): did:jwk, did:key and did:web,
  // reading a DID document, and the DIF Well Known DID Configuration check that
  // proves a DID and an origin are the same entity. Everything here fails
  // silently when it is wrong — a multicodec written as a fixed-width number
  // instead of a varint produces DIDs that decode here and nowhere else, a
  // compressed EC point decompressed with the wrong square root gives the other
  // valid point on the curve, and a Domain Linkage Credential with a typ header
  // or an iat claim is exactly what a JWT library produces by default. It found
  // a real bug on its first run: P-384's and P-521's field primes were
  // truncated. Node only, never skipped.
  jobs.push({
    name: "DID module (did:jwk/key/web, document reading, DIF domain linkage)",
    script: "did_document.js",
    env: {},
  });

  // DPoP's own arithmetic (client/src/dpop.js): the RFC 7638 JWK Thumbprint
  // that becomes cnf.jkt, the htu normalization, the ath hash, and the shape of
  // the proof itself. Every one of those fails SILENTLY when it is wrong — a
  // proof with a wrong thumbprint or a wrong htu is perfectly well formed and
  // simply matches nothing, so the server's refusal reads as "your key is
  // wrong" rather than "your encoding is wrong". The oracle is not a second
  // implementation but the RFCs' own published values: RFC 9449 prints an EC
  // key and the jkt of the token bound to it, RFC 7638 section 3.1 does the
  // same for RSA. Node only, never skipped.
  jobs.push({
    name: "DPoP arithmetic (RFC 7638 thumbprints against the RFCs' own " +
        "vectors, htu/ath/jti)",
    script: "dpop_vectors.js",
    env: {},
  });

  // The Kerberos v5 encryption framework (common/krb5/krb5_primitives.js and
  // krb5_crypto.js) against the RFCs' own published values: RFC 3961's n-fold,
  // RFC 3962's AES string-to-key and CBC ciphertext stealing, RFC 8009's SHA-2
  // KDF and sample encryptions, plus RFC 1320/1321/2202 for the MD4, MD5 and
  // HMAC-MD5 that etype 23 needs and Web Crypto does not have.
  //
  // This is the one test in the Kerberos workflow that cannot be replaced by a
  // test against the mock KDC, and the reason is worth keeping: every error in
  // this layer produces the SAME symptom — one opaque integrity failure at the
  // far end, indistinguishable from a wrong password — and two implementations
  // written from the same misreading agree with each other perfectly. A wrong
  // n-fold, a wrong key usage number, an omitted CTS block swap or a MAC over
  // the ciphertext where the specification says plaintext all round-trip
  // happily and interoperate with nothing. It is mutation-tested: six
  // deliberate defects were each confirmed to fail it.
  // Node only, never skipped.
  jobs.push({
    name: "Kerberos v5 crypto (RFC 3961/3962/8009 vectors, CTS, etypes 17/18/19/20/23)",
    script: "krb5_crypto_vectors.js",
    env: {},
  });

  // The Kerberos v5 DER codec and message structures (common/krb5/krb5_asn1.js
  // and krb5_messages.js) against RFC 4120's grammar.
  //
  // A codec that round-trips its own output proves nothing — every field could
  // be under the wrong context tag and it would still pass — so a third of these
  // assertions are byte-exact expectations that pin each tag NUMBER, and another
  // third are the compatibility behaviours only a real deployment produces: an
  // AS-REP enc-part tagged EncTGSRepPart (RFC 4120 section 5.4.2 requires a
  // client to accept it), a NEGATIVE checksum type (-138, which S4U2Self uses),
  // a KRB-ERROR carrying the salt in its e-data, and a relayed Ticket whose
  // original bytes must survive re-encoding. The rest is the negative half: this
  // codec parses bytes pasted into a web page and bytes returned by a host the
  // user named, so refusing malformed and oversized input is part of the job.
  //
  // Mutation-testing it found a real defect: three writers had `addresses`
  // hard-coded to null, so a captured message carrying them could be decoded and
  // never re-encoded. Node only, never skipped.
  jobs.push({
    name: "Kerberos v5 DER codec (RFC 4120 messages, byte-exact tags, compatibility cases)",
    script: "krb5_codec.js",
    env: {},
  });

  // What the Kerberos decoder page SHOWS (common/krb5/krb5_describe.js), plus the
  // keytab reader that lets it show the inside of a ticket (krb5_keytab.js).
  //
  // The page is a renderer with no protocol knowledge in it — the split follows
  // webauthn.js / webauthn_panes.js — so everything it displays is checkable here
  // with no browser. Three behaviours are the ones worth having a test for, and
  // all three are judgement rather than arithmetic: a capture arrives as hex, as
  // base64 or with the TCP length prefix still attached (and the prefix must be
  // stripped AND reported, since leaving it makes the ASN.1 parse fail on byte
  // zero); a failure to decrypt is CONTENT rather than an error, because most of a
  // Kerberos message is encrypted under keys the reader does not have; and
  // `problems` must hold things that are WRONG (a lower-case realm, an RC4-only
  // etype list, a clock five minutes out) and NOT things that are merely absent —
  // KDC_ERR_PREAUTH_REQUIRED specifically is not a problem, it is where the salt
  // comes from.
  //
  // It found a real defect on its first run: an AS-REP was reported as "does not
  // parse" because the describer read `doc.kind` from inside the literal defining
  // `doc`. A parse failure blamed on the message when the fault is in the tool is
  // the worst outcome this page can have. Node only, never skipped.
  jobs.push({
    name: "Kerberos v5 decoder output (input forms, decryption reporting, findings, keytabs)",
    script: "krb5_describe_output.js",
    env: {},
  });

  // The Kerberos Decoder PAGE (client/public/kerberos_decoder.html). The content
  // it shows is already covered without a browser by krb5_describe_output.js, so
  // this job covers only what needs one:
  //
  //  * that the bundle loaded at all — a page registered in client/build.js but
  //    not in client/Dockerfile builds fine for the static deployments while the
  //    containerized page's <script> 404s, so the failure appears only here and
  //    only as a page that does nothing;
  //  * that a hostile value in a KDC's realm or e-text renders as TEXT. This page
  //    displays bytes a stranger pasted in, is built entirely with createElement
  //    and textContent, and the check is mutation-tested: swapping one
  //    textContent for innerHTML fails it;
  //  * that decryption works on Web Crypto, which is a different implementation
  //    from the node path the other tests exercise;
  //  * and that the page persists NOTHING, because everything it is given — a
  //    password, a keytab, a session key out of a decrypted ticket — is a
  //    credential.
  //
  // Needs only the site: this page talks to no KDC and has no back end. That is
  // not enough to put it on the deployed static sites, though — see below.
  //
  // NONE of the Kerberos PAGES exist on a static deployment. Kerberos is DER
  // over port 88, so the workflow needs the api's relay and idptools.com has no
  // api; client/static_site.js drops all five pages from that build and greys
  // out their landing card, the decoder included (it needs no network, but it
  // has no card of its own and the only route to it is a link on kerberos.html,
  // which is not there either). Without this gate those jobs run against a 404
  // and fail naming an element on a page that was never deployed. The three
  // KDC-backed ones already skip when the KDC is unreachable — this reason is
  // the accurate one for a static target, and it reaches the decoder job, which
  // has nothing else to skip on. remote-run-tests.sh sets the variable per
  // target; unset (every containerized and local run) means they are there.
  // KERBEROS_AVAILABLE is the current name; KERBEROS_PAGES_AVAILABLE is the
  // one it replaced and is still honoured, because it may be set in a CI
  // environment or a shell that predates the rename. See the sweep at the end
  // of this function for why the name had to change.
  const kerberosOff =
    (env.KERBEROS_AVAILABLE || env.KERBEROS_PAGES_AVAILABLE) === "false";
  const kerberosPagesSkip = kerberosOff
    ? "the Kerberos pages are not on this deployment: the workflow needs the " +
      "api's port-88 relay, which a static site has not got, so " +
      "client/static_site.js leaves all five pages out of the build and " +
      "greys out the landing card. Run them against the containerized stack " +
      "(./docker-run-tests.sh) or a local dev server."
    : null;

  {
    const decoderJob = {
      name: "Kerberos Decoder page (wiring, hostile input as text, in-browser decryption)",
      script: "kerberos_decoder_page.js",
      env: {},
    };
    if (kerberosPagesSkip) decoderJob.skip = kerberosPagesSkip;
    jobs.push(decoderJob);
  }

  // The Kerberos relay (api/krb5_relay.js, api/krb5_frame.js) behind POST
  // /krb5/kdc. This is the most important test in phase 2, for a specific reason:
  // api/ssrf_guard.js is installed on the shared AXIOS instance, and a raw
  // `net.connect` walks past all of it — so the relay is a SECOND enforcement of
  // the same address policy for a transport the guard has never seen.
  //
  // It is also a broader primitive than anything this service had before: it
  // carries caller-supplied bytes to a caller-supplied host and port. An HTTP
  // fetcher aimed at port 22 gets nothing; a byte relay aimed at port 22 is a port
  // scanner with a payload of the caller's choosing. Four things bound it and all
  // four are tested: the shared address policy, resolve-then-connect-to-the-literal,
  // a port allowlist (new with this endpoint), and a message-shape pre-flight that
  // runs before any socket opens.
  //
  // The assertion that earns its keep most is the same one api_connect_timeout.js
  // makes for the HTTP side: a host that CONNECTS AND THEN SAYS NOTHING must be
  // given until callTimeout, not killed at connectTimeout. That fails against an
  // implementation expressing both deadlines with one timer, which is the natural
  // way to write it. Mutation-tested: eight deliberate defects, all caught.
  // Node only, never skipped.
  jobs.push({
    name: "Kerberos relay (address policy on raw sockets, port allowlist, pre-flight, limits)",
    script: "api_krb5_relay.js",
    env: {},
  });

  // The AS exchange end to end: the wallet-side codec (common/krb5) against the
  // mock KDC (the sts/ submodule), over a real socket, through the api's relay. It
  // starts the KDC in-process on an ephemeral port, so it needs no docker and no
  // running service.
  //
  // This is the first test that puts a CLIENT and a KDC on opposite ends of a wire
  // and makes them agree — a different claim from the vector tests, because the two
  // disagree in ways neither can detect alone: a key usage number one folds in and
  // the other does not, a salt one derives from the principal name and the other
  // from configuration, a nonce one echoes and the other regenerates. It is still
  // NOT proof of interoperability: both ends are this repository's code, and the
  // interoperability evidence is the MIT krb5 / Samba AD exchange in phase 4.
  //
  // Most of it is the negative half, which is the product: KDC_ERR_ETYPE_NOSUPP to
  // an RC4-only client against a hardened account (the 2026 case), a locked
  // account, an expired password, a wrong salt reported as PREAUTH_FAILED with
  // ETYPE-INFO2 re-sent so the client can find out, and a clock outside the
  // tolerance. Mutation-tested: nine deliberate defects in the KDC, all caught —
  // including a regenerated nonce, a pre-authent flag set when no pre-authentication
  // happened, and a computer account salted like a user.
  // Node only, never skipped.
  jobs.push({
    name: "Kerberos AS exchange (the codec against the mock KDC: the two-message dance, refusals)",
    script: "krb5_as_exchange.js",
    env: {},
  });

  // The rest of the protocol: TGS then AP, with mutual authentication and
  // per-message tokens. The client is common/krb5; the KDC and the protected service
  // are the sts/ submodule's, started in-process on ephemeral ports so this needs no
  // docker and no running service.
  //
  // The AS test gets a TGT, which is the easy half. This one is a ticket being
  // PRESENTED to something that decrypts it, checks it, and proves itself back —
  // until something does that, "the ticket looks right" is the strongest claim
  // available about any of it.
  //
  // Four things here fail in ways nothing else catches: a TGS-REQ carries the TGT
  // inside a PA-TGS-REQ whose value is an entire AP-REQ, whose Authenticator
  // checksums the ENCODED request body (re-encode it and the checksum covers
  // something else); the TGS-REP is at key usage 8 or 9 depending on whether a subkey
  // was sent, and both paths are exercised; the 0x8003 checksum is not a checksum and
  // its integers are LITTLE-endian; and mutual authentication is an ECHO that has to
  // be CHECKED, not merely requested.
  //
  // It found a real bug on its first run: KerberosTime carries no fractional seconds,
  // so the wire ctime is truncated to the second and the client was comparing the
  // AP-REP's echo against a millisecond-precision Date — accusing a correct service
  // of not being itself.
  //
  // The negatives are the point: a replayed Authenticator, a ticket for the wrong
  // service, a stale key version, a request body swapped after signing, a clock
  // outside the tolerance, a checksum that is not 0x8003, and a forged echo.
  // Mutation-tested: the KDC's checksum check, the service's replay cache, its
  // ticket-is-for-me check, and the 0x8003 byte order — all caught.
  //
  // Phases 4 and 5 grew it well beyond its name, because each addition needs the live
  // exchange rather than a fixture:
  //
  //  * **the PAC the KDC actually minted**, in BOTH kinds of ticket. In a TGT the service
  //    key and the krbtgt key are the same key, so a KDC using the wrong one for the
  //    server signature passes every TGT test ever written and issues service tickets no
  //    Windows service accepts. Only the service ticket separates them.
  //  * **cross-realm referrals**, chased end to end: a referral is an ordinary successful
  //    TGS-REP whose `sname` is not what was asked for, and a client that does not compare
  //    those two presents a ticket-granting ticket to a web server. The PAC is re-signed by
  //    the target realm, and the test proves the OLD signatures no longer verify — if they
  //    did, nothing had been re-signed.
  //  * **S4U2Self and S4U2Proxy, authorized both ways**: classic constrained delegation
  //    (`msDS-AllowedToDelegateTo` on the front end) and RBCD (`msDS-AllowedToActOn-
  //    BehalfOfOtherIdentity` on the back end), with the asymmetries that make RBCD the
  //    easier path — and five refusals, without which the successes prove nothing.
  //  * **renewals**, which preserve authtime and cap at renew-till. That test contains the
  //    only deliberate sleep in the file: KerberosTime has one-second resolution and the
  //    test runs inside one second, so without a clock boundary a KDC that reset authtime
  //    on renewal produced an identical value and the mutation went undetected.
  //
  // Thirty-three further mutations were used to develop those sections and all thirty-three
  // fail them. Four were caught only after the test was strengthened, each a real gap: a
  // realm-aware principal lookup that needed a client NATIVE to the second realm, a PAC
  // domain SID nothing asserted, the delegation flag that is invisible where it is set, and
  // a vacuous authtime comparison that compared a value with itself.
  // Node only, never skipped.
  jobs.push({
    name: "Kerberos TGS + AP, the PAC, cross-realm referrals, S4U delegation and renewals",
    script: "krb5_tgs_ap.js",
    env: {},
  });

  // The Kerberos codec exists TWICE — common/krb5 for the browser and the api, and
  // a vendored copy in the sts/ submodule for the KDC, because compose builds that
  // service with `context: ./sts` and a Docker build cannot COPY from outside its
  // context. This is the test that makes that safe.
  //
  // A file comparison alone would not be enough. The failure mode of a vendored
  // wire codec is not "one copy is broken" — it is that BOTH copies are
  // self-consistent and disagree only with each other, each one's own tests
  // passing, and the symptom is an integrity failure indistinguishable from a wrong
  // password. So the copies are cross-checked behaviourally: messages built by one
  // and read by the other, and — the assertion nothing else can make — one copy
  // ENCRYPTS and the other DECRYPTS. Then the files are compared too, which catches
  // drift before it has consequences and names the one command that fixes it
  // (common/krb5/sync-to-mock-sts.sh).
  //
  // Proved against five real drift scenarios, each caught by a different assertion:
  // a key usage number, a MAC over the ciphertext instead of the plaintext, a
  // context tag, a comment-only edit, and a reader silently dropping a field.
  // With the submodule uninitialised it says so and passes — an uninitialised
  // submodule is an EMPTY DIRECTORY, and reporting that as a codec failure sends
  // somebody looking in the wrong place. Node only, never skipped.
  jobs.push({
    name: "Kerberos codec sync (common/krb5 against the mock STS's vendored copy, cross-wise)",
    script: "krb5_codec_sync.js",
    env: {},
  });

  // SPNEGO's codec (common/krb5/krb5_spnego.js), byte by byte. Node only, no
  // browser and no services, and it never skips.
  //
  // Every value it asserts is derived by hand from RFC 4178 section 4 and from
  // the OIDs' own registrations rather than from what the encoder produces,
  // because a reader and a writer sharing one misunderstanding agree perfectly
  // with each other and with nothing else. Four things earn it its keep: the
  // OID coder (SPNEGO is the first thing here that has to write one — Kerberos's
  // own ASN.1 contains no OBJECT IDENTIFIER at all, and Microsoft's mis-typed
  // Kerberos OID differs from the real one in a single arc); that the
  // mechListMIC covers `MechTypeList` and NOT `[0] MechTypeList`, which is two
  // bytes and the commonest mistake in this protocol; that a `[3]` is a MIC in
  // RFC 4178 and negHints in [MS-SPNG]'s NegTokenInit2, told apart by what is
  // inside rather than by the direction of travel; and that negState is
  // ENUMERATED rather than INTEGER, which encode identically apart from the tag
  // so a coder using the wrong one round-trips against itself perfectly and is
  // refused by a strict peer.
  jobs.push({
    name: "SPNEGO codec (RFC 4178's NegTokenInit and NegTokenResp, byte by byte)",
    script: "krb5_spnego_codec.js",
    env: {},
  });

  // SPNEGO over HTTP end to end: RFC 4559 carrying RFC 4178 carrying RFC 4121
  // carrying an AP-REQ. Node only — the mock KDC and the mock's Express app are
  // started in-process on ephemeral ports — so it never skips.
  //
  // The NEGATIVES are the substantial half, deliberately: an acceptor that
  // authenticates a good client looks finished and is worth very little. Ten of
  // them, and the two that nothing else could catch are a mechListMIC computed
  // over the `[0]`-tagged list (the ticket is perfect and the request is
  // refused) and an edited mechanism list (everything else about the request is
  // valid, which is exactly why the MIC is the only thing that can notice —
  // that is the downgrade RFC 4178 section 5 exists to stop). The rest: no
  // mechanism in common in both directions, a list with no token answered
  // accept-incomplete rather than reject, a tampered MIC, a replayed AP-REQ, a
  // ticket for another service, a TGT presented as one, a Basic Authorization
  // header, bytes that are not a token, and a continuation with nothing to
  // continue. Each asserts WHICH check fired, not merely that something was
  // refused — and the ones carrying a KRB-ERROR assert the error code inside
  // the responseToken, because SPNEGO's negState has no reason field at all and
  // an acceptor that swallows the mechanism's error leaves a rejection
  // indistinguishable from a wrong password.
  jobs.push({
    name: "SPNEGO over HTTP (the handshake, and the ten negatives that make an acceptor worth anything)",
    script: "krb5_spnego_http.js",
    env: {},
  });

  // The Ticket Cache & History pane, on all five Kerberos pages. Node only:
  // the pane is markup and needs a browser, but what it STORES is a hundred
  // session keys and that is checkable without one. The assertion that matters
  // is that unticking krb_save_ccache purges the whole list —
  // enforceStoragePreference() names each key it removes, so a key added later
  // is forgotten there by
  // default, and the symptom would be an opt-out that quietly keeps a hundred
  // credentials. The rest is where an activated ticket LANDS (a service ticket
  // in the TGT slot is accepted silently and fails a page later) and the
  // static wiring: every page includes the partial, mounts it once, mounts
  // only the slots it holds, and the decoder mounts it read-only.
  jobs.push({
    name: "Kerberos ticket cache & history (credential store, slots, the " +
        "opt-out purge, and the wiring on all five pages)",
    script: "krb5_ticket_history.js",
    env: {},
  });

  // The Operations History pane, on all five Kerberos pages. Node only, and
  // deliberately: the half of this that a browser test could not catch is the
  // static one. A row is opened when an operation starts and closed by the
  // status line that operation named, so a page that opens a row against a line
  // it never writes a terminal status to leaves every one of those operations
  // reading "Sent" — a legitimate-looking value meaning "the far end never
  // answered". The pane renders, the row is there, and nothing looks wrong. So
  // this checks, per bundle, that every line an operation is opened against has
  // both a success and a failure path; that all five pages include the partial
  // AND mount it against the partial's own ids (a page that includes it and
  // never mounts shows an empty div, which looks exactly like a workflow that
  // has done nothing); and that the classes op_history.js renders with this
  // workflow's prefix are defined in css/kerberos.css, since its defaults are
  // the saml-* ones and these pages do not load that stylesheet.
  jobs.push({
    name: "Kerberos operations history (the log, and the wiring on all five " +
        "pages)",
    script: "krb5_operation_history.js",
    env: {},
  });

  // The byte ranges the hex tab on the AS exchange page colours with. Node
  // only, no browser: the arithmetic is in common/krb5/krb5_ranges.js precisely
  // so it can be checked without one, and an offset that is relative rather
  // than absolute does not crash — it highlights the wrong bytes, plausibly.
  jobs.push({
    name: "Kerberos byte ranges (absolute offsets for the hex view)",
    script: "krb5_ranges_offsets.js",
    env: {},
  });

  // The NAMES on those bytes, and the wiring that puts the view on a page.
  // Node only, and the same reasoning: a tag mapped to the wrong field does not
  // crash, it says `till` while highlighting `rtime`. Half the file is static —
  // a hex pane nothing fills, or a tab strip nothing wires, renders empty,
  // which is what a page looks like before an exchange has been run.
  jobs.push({
    name: "Kerberos field names (RFC 4120 names on the hex view's bytes)",
    script: "krb5_field_naming.js",
    env: {},
  });

  // Delegation, run TWICE — once per KDC — because that is the only way a
  // divergence between the mock and Active Directory becomes visible.
  //
  // tests/krb5_tgs_ap.js already drives S4U against the mock, and harder: it
  // forges tickets and swaps keys, which no real domain controller can be asked
  // to do. But it only ever asks the mock, and the mock was written from the
  // same reading of [MS-SFU] as the client it checks — so a shared misreading
  // shows up in neither. These two jobs run ONE set of assertions against both,
  // so the same assertion failing on one and passing on the other is the
  // finding.
  //
  // The mock half needs nothing (in-process KDC on an ephemeral port). The
  // Windows half needs a domain controller and is skipped without one, on the
  // same terms as krb5_real_dc.js: it costs money and no launcher starts it.
  {
    const delegationIdps = [
      { key: "mock", label: "mock KDC", skip: null, env: {} },
      {
        key: "windows",
        label: "real Windows KDC",
        skip: env.KRB5_DC_JSON ? null :
          "no real Windows KDC to delegate against (KRB5_DC_JSON unset). " +
          "The four delegation accounts are provisioned by " +
          "infra/terraform-krb5 and described in the bootstrap's dc.json; " +
          "./infra/krb5-test.sh fetches it and sets this. Not free tier, so " +
          "nothing starts it automatically.",
        env: {
          KRB5_DELEG_TARGET: "windows",
          KRB5_DC_JSON: env.KRB5_DC_JSON,
          KRB5_DC_HOST: env.KRB5_DC_HOST,
          KRB5_DC_PORT: env.KRB5_DC_PORT,
        },
      },
    ];
    for (const idp of delegationIdps) {
      const job = {
        name: "Kerberos delegation — S4U2Self, classic S4U2Proxy, RBCD [" +
          idp.label + "]",
        script: "krb5_delegation_interop.js",
        env: Object.assign({ KRB5_DELEG_TARGET: idp.key }, idp.env),
      };
      if (idp.skip) { job.skip = idp.skip; }
      jobs.push(job);
    }
  }

  // What a real Windows KDC sent, asserted offline. This is the job that keeps
  // the expensive one's evidence alive: tests/krb5_real_dc.js needs a domain
  // controller on EC2 and therefore runs almost never, so its exchange was
  // recorded once (tests/captures/windows-server-2025.json) and is re-checked
  // here on every run with no AWS, no network and no services.
  //
  // It has already earned its place. The capture showed that Windows Server
  // 2025 sends NO s2kparams in ETYPE-INFO2 — it relies on the RFC 3962 default
  // — while the mock KDC always sends one and krb5_as_exchange.js asserts it is
  // there. A client that required the field would pass this whole suite and
  // fail against every real domain, reporting a wrong password. Never skipped:
  // the capture is committed.
  jobs.push({
    name: "Kerberos vectors from a REAL Windows KDC (recorded; salt, refusals, keytab, PAC)",
    script: "krb5_windows_vectors.js",
    env: {},
  });

  // The one Kerberos job that talks to software this project did not write.
  //
  // Every other job in this section — the codec, the crypto vectors, the PAC
  // layout, the AS and TGS exchanges — runs against the mock KDC in the
  // rcbj/mock-sts submodule. The mock was written from the same reading of RFC
  // 4120 and [MS-PAC] as the client it checks, so the two agree by construction
  // and a shared misreading is invisible to all of them. This job is the answer
  // to that, and it is the open risk docs/kerberos.md names.
  //
  // It needs a real Windows Server domain controller, which is what
  // infra/terraform-krb5 stands up and infra/krb5-test.sh drives:
  // apply -> wait for the forest -> run this -> destroy, with the teardown on an
  // EXIT trap so a failed test still removes the instance. The stack is NOT free
  // tier and is not left running, so nothing here starts it — the job is skipped
  // unless KRB5_DC_HOST names one that already exists.
  //
  // The skip names the script rather than the variable, because the variable on
  // its own reads as something a launcher forgot to export, and it is not: no
  // launcher sets it, on purpose.
  {
    const realDcSkip = env.KRB5_DC_HOST ? null :
      "no real Windows KDC to test against (KRB5_DC_HOST unset). This one " +
      "job drives a domain controller on EC2, which costs money and is not " +
      "free tier, so no launcher starts it. Run ./infra/krb5-test.sh, which " +
      "applies infra/terraform-krb5, runs this test and tears the stack down " +
      "again whatever the result.";
    const job = {
      name: "Kerberos against a REAL Windows KDC (AS-REQ, TGS-REQ, ktpass keytab, PAC, AP-REQ)",
      script: "krb5_real_dc.js",
      env: {
        KRB5_DC_HOST: env.KRB5_DC_HOST,
        KRB5_DC_PORT: env.KRB5_DC_PORT,
        KRB5_REALM: env.KRB5_REALM,
        KRB5_USER: env.KRB5_USER,
        KRB5_PASSWORD: env.KRB5_PASSWORD,
        KRB5_SPN: env.KRB5_SPN,
        KRB5_KEYTAB_B64: env.KRB5_KEYTAB_B64,
      },
    };
    if (realDcSkip) { job.skip = realDcSkip; }
    jobs.push(job);
  }

  // The Windows PAC (common/krb5/krb5_pac.js and krb5_ndr.js), which is the structure
  // a Windows service actually authorizes on: a Kerberos ticket proves who you are and
  // says nothing about your group memberships, so "authentication worked and access was
  // denied" is nearly always a question about this.
  //
  // It is also the worst case for self-consistency testing, and the reason this job
  // exists separately from the codec one. The logon information is NDR — [MS-RPCE]'s RPC
  // marshalling, with referent-id pointers and alignment padding — so a reader and a
  // writer that share ONE misunderstanding agree perfectly with each other and with
  // nothing else in the world. Read FILETIME as an 8-aligned 64-bit integer in both
  // halves and every field still round-trips; the two just insert and skip four bytes of
  // padding no real KDC ever wrote. So the assertions are byte offsets counted out of
  // [MS-PAC] section 2.5's field list BY HAND, structures with more than one element
  // (an ExtraSids array defers all its SID pointers past the END of the array, so a
  // reader that follows each as it goes is right for one element and wrong for two), and
  // the four signatures checked SEPARATELY — including the case that matters: altering
  // the PAC's contents breaks the server and extended KDC signatures and leaves the KDC
  // signature verifying, because that one covers only the server signature's bytes. That
  // is the shape of CVE-2022-37967.
  //
  // Eighteen mutations were used to develop it and all eighteen fail it, two of which
  // were real bugs it found: a signed/unsigned comparison that made SE_GROUP_LOGON_ID
  // unmatchable, and a consistency check reading a field one line before it was
  // assigned. Node only, never skipped.
  jobs.push({
    name: "Kerberos PAC (MS-PAC: the NDR layout at hand-derived offsets, and all four signatures)",
    script: "krb5_pac_layout.js",
    env: {},
  });

  // The Kerberos AS exchange PAGE. krb5_as_exchange.js already drives the same
  // exchange with no browser, so this job covers only what needs one: that the
  // bundle is registered in BOTH client/build.js and client/Dockerfile, that the
  // api's CORS allowlist actually lets the page call POST /krb5/kdc (a failure no
  // node test can see, and one that appears as a fetch which never resolves rather
  // than as anything naming CORS), that step 2 is DISABLED until step 1 has learned
  // the salt, that the salt the KDC sent is shown AND used, and that the session key
  // is treated as the credential it is — sessionStorage by default, localStorage
  // only when asked, purged when the box is unticked.
  //
  // Needs the client, the api and the mock STS (which carries the KDC). It SKIPS
  // with a named reason when the KDC is unreachable, because an absent service is an
  // environment fact rather than a defect.
  //
  // Mutation-tested against the built bundle: step 2 enabled from the start, the
  // cache always going to localStorage, the salt field left unfilled, and the purge
  // removed — the last needing BOTH purge paths removed to fail, which is the
  // belt-and-braces arrangement CLAUDE.md prescribes for key material.
  const asPageJob = {
    name: "Kerberos AS exchange page (wiring, CORS, the two-step flow, credential handling)",
    script: "kerberos_as_page.js",
    env: {
      STS_URL: env.STS_URL || "http://localhost:8081",
      // "sts", not "localhost": this value is TYPED INTO THE PAGE and the address is
      // resolved by the API's relay, which runs in the api container — where localhost is
      // the api itself, listening on nothing. The mock KDC's port 88 is not published to
      // the host by any compose file, so the compose service name is the only address
      // that reaches it.
      KRB5_KDC_HOST: env.KRB5_KDC_HOST || "sts",
      KRB5_KDC_PORT: env.KRB5_KDC_PORT || "88",
    },
  };
  if (kerberosPagesSkip) asPageJob.skip = kerberosPagesSkip;
  jobs.push(asPageJob);

  // The TGS and AP exchange pages, and — the part nothing else covers — the CREDENTIAL
  // HANDOFF between all three. The AS page produces a TGT, the TGS page spends it, the
  // AP page presents the result, and they pass those through a shared cache in
  // kerberos_panes.js. Testing the TGS page in isolation would mean fabricating a TGT
  // in storage, which tests the fabrication rather than the workflow — and the handoff
  // is exactly where a rename breaks things silently. One did: a refactor left three
  // sites calling removeItem(KEYS.CCACHE) after the shared module renamed the key to
  // KEYS.TGT, so removeItem(undefined) deleted a key called "undefined" and the
  // storage opt-out quietly stopped purging a session key.
  //
  // Browser-only assertions: the TGS button is ENABLED once a TGT is held (the markup
  // ships it disabled, so that direction is the one proving the page read the cache);
  // the page reports key usage 8 without a subkey and 9 with one; the issued ticket is
  // NOT flagged `initial`; the AP page decodes the 0x8003 checksum field by field
  // including that its integers are little-endian and that Bnd is sixteen ZERO bytes
  // rather than absent; mutual authentication reads CONFIRMED only when the echo was
  // checked; per-message tokens are keyed from the ACCEPTOR's subkey; and unticking
  // MUTUAL says plainly that nothing has proved the service's identity.
  //
  // Needs the client, the api, the mock STS (KDC and protected service) AND the api's
  // krb5ServicePorts set — POST /krb5/service is off by default. It skips with a named
  // reason for each of those, because a disabled capability is a configuration fact
  // rather than a defect.
  const tgsApPageJob = {
    name: "Kerberos TGS + AP pages (the credential handoff, 0x8003, mutual auth, per-message tokens)",
    script: "kerberos_tgs_ap_page.js",
    env: {
      API_URL: env.API_URL || "http://localhost:4000",
      STS_URL: env.STS_URL || "http://localhost:8081",
      KRB5_KDC_HOST: env.KRB5_KDC_HOST || "sts",
      KRB5_KDC_PORT: env.KRB5_KDC_PORT || "88",
      KRB5_SERVICE_HOST: env.KRB5_SERVICE_HOST || "sts",
      KRB5_SERVICE_PORT: env.KRB5_SERVICE_PORT || "8888",
    },
  };
  if (kerberosPagesSkip) tgsApPageJob.skip = kerberosPagesSkip;
  jobs.push(tgsApPageJob);

  // The SPNEGO page, and the two pages a user is ROUTED THROUGH to feed it.
  // krb5_spnego_http.js already drives the protocol harder than this does with
  // no browser, so this job covers only what needs one:
  //
  //  * **the routing loop**, which is the whole reason this is a workflow. The
  //    SPNEGO page cannot obtain a ticket — that is the AS page and then the
  //    TGS page — so it sends the user out with `?return=spnego` and each of
  //    them offers a link back. This walks the loop: out, on to the TGS page
  //    with the SPN carried in the query, and back through the banner's own
  //    link. Nothing about the protocol notices when that breaks.
  //  * **the banner BEFORE a ticket exists**, which is the case it is for and
  //    the one an implementation puts after an early return and never renders.
  //    That happened here once already.
  //  * **the credential handoff** under a third reader of kerberos_panes.js's
  //    shared cache. A rename there is silent: the pane renders, the button
  //    stays disabled, and the page says "no service ticket held" for a ticket
  //    that is sitting in storage.
  //  * **the SPN the page guesses** from the URL's host, which nothing in the
  //    SPNEGO exchange carries — when it is wrong the failure is a KDC error
  //    three steps earlier naming nothing about HTTP, so the field has to
  //    exist, be pre-filled and be overridable.
  //  * **the panes**: the decoded NegTokenInit and what its mechanism ORDER
  //    decides, the AP-REQ inside it, the 0x8003 checksum, the hex view naming
  //    a field and its absolute offset under the pointer, and the ticket —
  //    which is opaque until a service key is supplied and must SAY so rather
  //    than rendering an empty pane. Supplying the key opens the EncTicketPart
  //    and the PAC, which is the structure a client can never see in its own
  //    ticket.
  //
  // And three negatives through the UI, each a deliberate misconfiguration the
  // mock offers as a query parameter: an acceptor with no mechanism in common,
  // a client offering only a mechanism this build cannot perform, and a server
  // that accepts the ticket and proves nothing back.
  //
  // Needs the client, the api and the mock STS (its KDC and its
  // SPNEGO-protected page). Unlike the AP page it needs no extra api setting —
  // POST /krb5/spnego is an ordinary outbound HTTP call rather than a byte
  // relay to an arbitrary port. It skips with a named reason for each missing
  // piece, including an api or a mock that predates the workflow.
  const spnegoPageJob = {
    name: "SPNEGO page (the routing loop, the handshake, the ticket, and three refusals)",
    script: "kerberos_spnego_page.js",
    env: {
      API_URL: env.API_URL || "http://localhost:4000",
      STS_URL: env.STS_URL || "http://localhost:8081",
      KRB5_KDC_HOST: env.KRB5_KDC_HOST || "sts",
      KRB5_KDC_PORT: env.KRB5_KDC_PORT || "88",
      // The URL the API — not the browser — fetches, so it is the api's view of
      // the mock that matters. On the containerized stack that is the compose
      // name; STS_URL is browser-facing and follows a different rule (see
      // tests/CLAUDE.md on WSFED_STS_METADATA_URL), which is why this is its
      // own variable rather than derived.
      KRB5_SPNEGO_URL: env.KRB5_SPNEGO_URL ||
        (env.KRB5_SPNEGO_HOST ? "http://" + env.KRB5_SPNEGO_HOST +
          "/spnego/protected" : "http://sts:8081/spnego/protected"),
    },
  };
  if (kerberosPagesSkip) spnegoPageJob.skip = kerberosPagesSkip;
  jobs.push(spnegoPageJob);

  // The DELEGATION page: S4U2Self, S4U2Proxy with both authorization routes, forwarding
  // and renewal. tests/krb5_tgs_ap.js already drives every one of those exchanges with no
  // browser, so this job covers only what needs one:
  //
  //  * **the credential handoff** — the service's own TGT comes from the AS page and the
  //    evidence ticket from S4U2Self is stored for S4U2Proxy to find, under keys the
  //    shared module owns. A rename there breaks this and nothing else, which has happened
  //    once already. The evidence ticket carries a session key, so the storage opt-out has
  //    to purge it too, and this checks it leaves — including that nothing lands under a
  //    key literally called "undefined", which is what a purge using a renamed constant
  //    writes while leaving the real key in place.
  //  * **what the page SAYS when a delegation fails.** Every refusal here is
  //    KDC_ERR_BADOPTION whatever the cause — missing PA-PAC-OPTIONS, an unauthorized
  //    pair, non-forwardable evidence — and the error names none of them. So the page's
  //    job is to narrow it, and that text IS the product: a test asserting only "it
  //    failed" would pass against a page that said nothing useful. Three refusals are
  //    checked for naming their actual cause, including both attributes on both accounts.
  //  * **forwardability reported when the evidence ARRIVES**, not two steps later when
  //    classic S4U2Proxy refuses it — a missing TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
  //    surfaces as a complaint about the evidence ticket, which is not where it is.
  //
  // It authenticates as HTTP/frontend.example.com rather than as a user, because S4U2Self
  // is a request a SERVICE makes and that is the commonest misunderstanding about it.
  // Needs the client, the api's relay and the mock KDC; without them it SKIPS naming what
  // was absent, since an environment capability is not a defect.
  const delegationPageJob = {
    name: "Kerberos delegation page (S4U2Self, S4U2Proxy, RBCD, forwarding, renewal)",
    script: "kerberos_delegation_page.js",
    env: {},
  };
  if (kerberosPagesSkip) delegationPageJob.skip = kerberosPagesSkip;
  jobs.push(delegationPageJob);

  // The layout of all six pages at 1366x768: does each one put the control it
  // exists for on the first screen, and do the two CSS rules that height rests
  // on still match anything?
  //
  // It is a job of its own rather than an assertion inside the five page tests
  // above because those SKIP without a KDC, and a layout regression has nothing
  // to do with a KDC. It needs the site and nothing else — the buttons it
  // measures are in the served markup, not rendered by a bundle — so on a run
  // where the stack is half up this is still a real check. It does skip on a
  // static target for the same reason the others do: the pages are not there.
  //
  // Both of the CSS facts it asserts were found broken on 2026-08-17 and
  // neither made a page look wrong: bootstrap's `legend { line-height: 40px }`
  // was back on every pane (the override still said `.krb-pane > legend`, and
  // the panes had moved to `.dbg-pane`), and `.krb-field`'s 4px bottom margin
  // was losing to `input[type="text"]`'s 10px on specificity. Between them they
  // were most of ~1,300px across the workflow.
  const kerberosDensityJob = {
    name: "Kerberos pages fit one screen (six pages, 1366x768, pane chrome)",
    script: "kerberos_page_density.js",
    env: {},
  };
  if (kerberosPagesSkip) kerberosDensityJob.skip = kerberosPagesSkip;
  jobs.push(kerberosDensityJob);

  // The api's outbound address policy (api/ssrf_guard.js): the service fetches
  // URLs its caller supplies, so it must refuse loopback and private
  // destinations or it is an SSRF probe into whatever network it runs in. Node
  // only — no browser, no services — so it is never skipped.
  jobs.push({
    name: "API SSRF guard (outbound calls to loopback / private ranges " +
        "are refused)",
    script: "api_ssrf_guard.js",
    env: {},
  });

  // The api's outbound limits: api/connect_timeout.js plus callTimeout,
  // connectionTimeout, maxContentLength and maxRedirects in api/env/*.js. axios
  // defaults to no timeout, no size cap and 21 redirects, so without these a
  // caller-named host that goes quiet holds a request open for minutes, one
  // that streams fills the heap, and one that redirects can walk the service
  // elsewhere. The interesting half is that a connection which SUCCEEDED must
  // not be cut off by the connect budget — an AbortSignal-based implementation
  // gets that wrong. Node only, so never skipped.
  jobs.push({
    name: "API outbound call policy (timeouts, caps, User-Agent, keep-alive)",
    script: "api_connect_timeout.js",
    env: {},
  });

  // The SD-JWT VC issuance workflow (OID4VCI + RFC 9901): the mock Credential
  // Issuer the STS service hosts, the three vc-issuance pages, and the
  // ?sdjwtvc=1 hand-off through debugger.html / debugger2.html. Needs both the
  // STS mock (which is the credential issuer) and Keycloak (which authorizes
  // the issuance), so it is gated on the STS like the other STS-backed jobs.
  if (env.WSTRUST_STS_URL) {
    jobs.push({
      name: "VC Issuance — SD-JWT VC (OID4VCI credential issuance end to end)",
      script: "sd_jwt_vc_issuance.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL,
        KEYCLOAK_BASE_URL: env.KEYCLOAK_BASE_URL || "",
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
  }

  // The BBS signatures the debugger produces, checked by a DIFFERENT BBS
  // implementation (@digitalbazaar/bbs-signatures). No browser and no services,
  // so it never skips. It is the foundation the bbs-2023 cryptosuite stands on:
  // BBS has several places where a signer and verifier can share a mistake and
  // agree perfectly with each other and with nobody else.
  {
    jobs.push({
      name: "BBS signatures (cross-checked against an independent " +
          "implementation)",
      script: "bbs_crypto.js",
      env: {},
    });
  }

  // The third credential format through both workflows: ldp_vc secured by a
  // bbs-2023 Data Integrity proof. Registered unconditionally like the
  // jwt_vc_json pair — a gated job that does not register is the quietest way
  // for a format to go untested.
  {
    jobs.push({
      name: "VC Issuance — ldp_vc / bbs-2023 (embedded Data Integrity proof)",
      script: "ldp_vc_issuance.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL || "",
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
    // Refreshing one (OID4VCI 14.5's two calls, and the 14.3 route that is all
    // that remains after the pre-authorized grant). Registered separately from
    // issuance because it drives a different call site — issuance step 4's —
    // over the same wallet module, and because holder binding for this format
    // is credentialSubject.id rather than cnf.jwk, which is what distinguishes
    // a replacement from a second credential.
    // Section 10 in the direction the response-encryption support did not
    // cover: the ISSUER publishes the key and the wallet encrypts to it. Needs
    // only the STS mock, so it is registered unconditionally.
    jobs.push({
      name: "OID4VCI Credential Request encryption (section 10, " +
          "issuer-published keys)",
      script: "oid4vci_request_encryption.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL || "",
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
        WALTID_ISSUER_URL: env.WALTID_ISSUER_URL || "",
      },
    });
    jobs.push({
      name: "VC Refresh — ldp_vc / bbs-2023 (OID4VCI 14.5 refresh_token + " +
          "re-request)",
      script: "ldp_vc_refresh.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL || "",
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
    jobs.push({
      name: "VC Presentation — ldp_vc / bbs-2023 (statement disclosure, " +
          "unlinkable)",
      script: "ldp_vc_presentation.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL || "",
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
        OID4VP_VERIFIER_URL: env.OID4VP_VERIFIER_URL || "",
      },
    });
    // The issuer named by a DID, for both formats that can carry one. It runs
    // against the IdentityCredentialDid / IdentityCredentialLdpVcDid
    // configurations, which exist so that ONE run covers both routes: those two
    // name the issuer by did:web while their plain siblings keep the https
    // identifier, so the specification's own key resolution
    // (/.well-known/jwt-vc-issuer, which is all draft-ietf-oauth-sd-jwt-vc
    // defines) goes on being exercised beside the DID extension. A server-wide
    // switch could only ever test one of the two.
    //
    // The chain it checks is advertisement -> resolution -> domain linkage ->
    // credential -> signature, and the last link is the one that matters: a DID
    // that resolves to the wrong key looks like success until something tries
    // to verify with it. Needs only the STS mock. The mock STS's own index of
    // itself: GET /sts-metadata lists every endpoint it registers, with its
    // methods, and every specification it implements. The list is read from the
    // running Express router rather than kept by hand, and this job is what
    // makes that worth something — it fails if a route is registered and
    // undescribed (the page understates what is callable) or described and not
    // registered (the page advertises a 404, which is what a rename produces).
    // Needs only the STS mock. did-tools.html, the general-purpose DID verifier
    // reached from the VC Tools pane on every page of both workflows. The DIDs
    // it works on are GENERATED by the mock STS (GET /did/generate), which
    // hands back a DID together with a credential signed by the key that DID
    // publishes — so the page's verdict can be checked against a known-good
    // answer instead of against "the document parsed". Its two negatives are
    // the point: a document that resolves perfectly but did not sign the held
    // credential must not read as verified, and an origin that vouches for a
    // different DID must not read as linked. Needs the STS and the client; no
    // Keycloak, no walt.id.
    jobs.push({
      name: "DID Tools page (resolve, verify a signing key, verify a " +
          "domain linkage)",
      script: "did_tools.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL || "",
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
    jobs.push({
      name: "STS metadata page (/sts-metadata lists exactly what the router " +
          "registers)",
      script: "sts_metadata.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL || "",
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
    jobs.push({
      name: "VC Issuance — issuer named by DID (did:web, domain linkage, " +
          "both formats)",
      script: "vc_did.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL || "",
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
  }

  // The cryptosuite ABOVE the primitive: JSON-LD canonicalization, the base
  // proof, and selective disclosure. The STS issues with one BBS implementation
  // and the wallet derives with the other, so neither marks its own homework.
  {
    jobs.push({
      name: "bbs-2023 cryptosuite (ldp_vc issue, derive, verify across two " +
          "implementations)",
      script: "bbs2023_cryptosuite.js",
      env: {},
    });
  }

  // The metadata schema check on vc-issuance-1.html, both panes. Its rule
  // half needs no browser and no services and never skips; its wiring half
  // drives the page, so it needs only the client — which every run has.
  // Registered unconditionally for the same reason as the four below.
  {
    jobs.push({
      name: "Metadata schema validation (OID4VCI and RFC 8414 panes, " +
          "positive and negative)",
      script: "metadata_schema_validation.js",
      env: {},
    });
  }

  // These four are registered UNCONDITIONALLY, unlike their SD-JWT siblings. A
  // gated job that does not register simply is not in the report, which is the
  // quietest possible way for a credential format to go untested — the run says
  // "all green" and nothing says the format was never exercised. Each of these
  // instead runs and FAILS with what is missing and how to supply it. The SAME
  // issuance workflow in the other credential format this issuer offers:
  // jwt_vc_json, a W3C VC secured as a JWT. Its own job rather than a flag on
  // the one above, because that suite is built around Disclosures and this
  // format has none — a flag would leave most of it skipped and the run would
  // read as though selective disclosure had been declined rather than being
  // unavailable. Skips itself when the issuer offers no such configuration.
  {
    jobs.push({
      name: "VC Issuance — jwt_vc_json (W3C VC secured as a JWT)",
      script: "jwt_vc_json_issuance.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL,
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
  }

  // The SD-JWT VC PRESENTATION workflow (OID4VP 1.0 + RFC 9901 section 4.3):
  // the mock Verifier the STS service hosts, the four vc-presentation pages,
  // and the presentation itself — an SD-JWT+KB whose Key Binding JWT is signed
  // over the request's nonce. Needs only the STS (issuer AND verifier), so no
  // identity provider is involved. Carries its own negatives: a replayed
  // presentation, a KB-JWT signed by the wrong key, an invented Disclosure, one
  // removed after signing, and a claim the verifier asked for withheld.
  if (env.WSTRUST_STS_URL) {
    // The SERVER half of DPoP, over HTTP with no browser: all twelve RFC 9449
    // section 4.3 proof checks, the cnf.jkt binding on access and refresh
    // tokens, the dpop_jkt code binding, jti replay detection, and the nonce
    // handshake in both of its shapes. It is almost entirely negatives, because
    // a DPoP server that issues bound tokens and accepts good proofs looks
    // finished and can be worth nothing — the value is all in what it refuses.
    // Needs only the STS.
    jobs.push({
      name: "DPoP server checks (RFC 9449: the twelve proof checks, binding, " +
          "replay, nonces)",
      script: "sts_dpop.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL,
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
    // And DPoP through the PAGES, which is the part neither of the two above
    // can reach: that the wallet really sends the proofs, that the token which
    // comes back is really bound (checked against the token's own cnf.jkt, not
    // against what the pane says), and that Holder of Key really binds the
    // credential to the DPoP key. Driven with the pre-authorized code grant, so
    // no IdP is needed.
    jobs.push({
      name: "DPoP through the VC Issuance pages (the pane, the real binding, " +
          "Holder of Key)",
      script: "dpop_workflow.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL,
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
    jobs.push({
      name: "VC Presentation — SD-JWT VC (OID4VP: selective disclosure, " +
          "positive and negative)",
      script: "sd_jwt_vc_presentation.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL,
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
  }

  // The PRESENTATION half of the same format: a Verifiable Presentation JWT
  // instead of an SD-JWT+KB, with holder binding done by that JWT's own
  // signature rather than by a Key Binding JWT. Carries its own negatives — a
  // VP JWT signed by the wrong key, a replay, a tampered credential, and an
  // SD-JWT answering a jwt_vc_json query (which matters because a Combined
  // Serialization also splits into three dot-separated parts).
  {
    jobs.push({
      name: "VC Presentation — jwt_vc_json (Verifiable Presentation JWT, " +
          "positive and negative)",
      script: "jwt_vc_json_presentation.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL,
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
        OID4VP_VERIFIER_URL: env.OID4VP_VERIFIER_URL || "",
      },
    });
  }

  // The same SD-JWT VC issuance workflow, driven against walt.id's issuer-api2
  // instead of our mock: a real, independently written OpenID4VCI 1.0
  // Credential Issuer. This is the interoperability check — same pages, same
  // buttons, someone else's implementation on the other end — so it is gated on
  // that container being up rather than on the STS.
  if (env.WALTID_ISSUER_URL) {
    jobs.push({
      name: "VC Issuance — SD-JWT VC against walt.id (OID4VCI " +
          "interoperability)",
      script: "sd_jwt_vc_waltid.js",
      env: {
        WALTID_ISSUER_URL: env.WALTID_ISSUER_URL,
        KEYCLOAK_BASE_URL: env.KEYCLOAK_BASE_URL || "",
      },
    });
  }

  // The SD-JWT VC PRESENTATION workflow driven against walt.id's verifier-api2
  // — an independently written OpenID4VP 1.0 verifier with DCQL — instead of
  // our own mock. The credential it presents is ISSUED BY walt.id in the same
  // run through our issuance pages, so neither end of the exchange is ours.
  // Gated on that container being up, like the issuer's interoperability job;
  // it also needs the walt.id issuer and Keycloak, because that is where the
  // credential comes from.
  if (env.WALTID_VERIFIER_URL) {
    jobs.push({
      name: "VC Presentation — SD-JWT VC against walt.id (OID4VP " +
          "interoperability)",
      script: "sd_jwt_vc_presentation_waltid.js",
      env: {
        WALTID_VERIFIER_URL: env.WALTID_VERIFIER_URL,
        WALTID_ISSUER_URL: env.WALTID_ISSUER_URL || "",
        KEYCLOAK_BASE_URL: env.KEYCLOAK_BASE_URL || "",
      },
    });
  }

  // jwt_vc_json against walt.id: the interoperability half of the two jobs
  // above. Both skip with instructions when walt.id offers no jwt_vc_json
  // configuration, which is the state until its container is restarted onto the
  // configuration in waltid/config/credential-issuer-metadata.conf.
  //
  // The presentation one has a second, deliberate skip: walt.id's own
  // jwt_vc_json profiles bind the holder with a SUBJECT DID where our mock uses
  // cnf.jwk, and a wallet cannot sign a Verifiable Presentation JWT for a key
  // it has never held. That is reported as an interoperability finding rather
  // than failed, because neither implementation is wrong.
  {
    jobs.push({
      name: "VC Issuance — jwt_vc_json against walt.id (OID4VCI " +
          "interoperability)",
      script: "jwt_vc_json_issuance_waltid.js",
      env: {
        WALTID_ISSUER_URL: env.WALTID_ISSUER_URL,
        KEYCLOAK_BASE_URL: env.KEYCLOAK_BASE_URL || "",
      },
    });
  }

  {
    jobs.push({
      name: "VC Presentation — jwt_vc_json against walt.id (OID4VP " +
          "interoperability)",
      script: "jwt_vc_json_presentation_waltid.js",
      env: {
        WALTID_VERIFIER_URL: env.WALTID_VERIFIER_URL,
        WALTID_ISSUER_URL: env.WALTID_ISSUER_URL || "",
        KEYCLOAK_BASE_URL: env.KEYCLOAK_BASE_URL || "",
      },
    });
  }

  // Operations History pane on the WS-Trust pages: records every attempted STS
  // call (timestamp, WS-Trust version, operation, user, result), dispatched as
  // "Sent" and resolved from the RSTR — or the SOAP Fault — on the response
  // page. Needs the STS mock (WSTRUST_STS_URL), like the other WS-Trust jobs.
  if (env.WSTRUST_STS_URL) {
    jobs.push({
      name: "WS-Trust Operations History (attempted STS calls: version, " +
          "operation, user, result)",
      script: "wstrust_operation_history.js",
      env: { WSTRUST_STS_URL: env.WSTRUST_STS_URL },
    });
  }

  jobs.push({
    name: "SAML Operations History (attempted IdP calls: binding, version, " +
        "entity IDs, result)",
    script: "saml_operation_history.js",
    env: {},
  });

  jobs.push({
    name: "SAML Assertion Tool (compose 1.0/1.1/2.0, XML-DSIG sign + verify, " +
        "XML-Enc round-trip)",
    script: "saml_tools.js",
    env: {},
  });
  
 // SAML 2.0 SP-initiated SSO across all three bindings: load IdP metadata, sign
  // the AuthnRequest (redirect = query-string sig; post = enveloped XML-DSIG;
  // artifact = redirect send + SOAP ArtifactResolve back-channel), log in at
  // Keycloak (which validates the request signature), and confirm the
  // ACS-captured SAMLResponse / assertion / NameID render on the response page.
  // The Artifact binding needs the server-side SOAP ArtifactResolve
  // back-channel, so it can't run on a backendless (static) deployment.
  // remote-run-tests.sh sets SAML_BACKEND_AVAILABLE=false for those targets;
  // skip it there rather than fail.
  const samlBackendAvailable = env.SAML_BACKEND_AVAILABLE !== "false";
  for (const SAML_BINDING of ["redirect", "post", "artifact"]) {
    const job = {
      name: `SAML 2.0 SSO — HTTP-${SAML_BINDING === 'post' ?
          'POST' : SAML_BINDING === 'artifact' ?
          'Artifact' : 'Redirect'} binding`,
      script: "saml_sso.js",
      env: {
        SAML_METADATA_URL: env.SAML_METADATA_URL,
        // When set (remote-run-tests.sh), the metadata is uploaded from this
        // local file instead of fetched from the URL — see loadIdpMetadata().
        SAML_METADATA_FILE: env.SAML_METADATA_FILE,
        SAML_SP_ENTITY_ID: env.SAML_SP_ENTITY_ID,
        SAML_USER: env.SAML_USER,
        SAML_BINDING,
      },
    };
    if (SAML_BINDING === "artifact" && !samlBackendAvailable) {
      job.skip = "HTTP-Artifact needs the API backend (server-side SOAP ArtifactResolve); unavailable on the static deployment.";
    }
    jobs.push(job);
  }

  // SAML 2.0 EncryptedAssertion decryption: SSO against a SAML client with
  // saml.encrypt=true (provisioned in common.sh), so Keycloak returns an
  // <saml:EncryptedAssertion>; the Response page decrypts it IN THE BROWSER
  // with the SP private key and renders the plaintext assertion.
  //
  // The decryption has never needed a backend — decryptAssertion() in
  // saml_response.js is node-forge in the page, the same XML-Enc engine the
  // WS-Trust and WS-Federation pages use, with no fetch and no Web Crypto. What
  // this job needs is somewhere for the IdP to POST the response: Keycloak's
  // encrypted client is provisioned saml.force.post.binding=true
  // (common/common.sh), so the response is POSTed whatever the AuthnRequest
  // asks for, and the Redirect-binding fallback the other SAML jobs use on a
  // static target is not available to it.
  //
  // That used to make this "unavailable on the static deployment". It no longer
  // is: infra/edge/saml_landing.js answers /samlacs at the CDN edge. So the
  // gate is whether a landing is actually deployed — remote-run-tests.sh probes
  // for one — not whether there is an api. Unset means "not probed" (the local
  // and containerized runs), where the api's ACS has always been there.
  //
  // It is also the case the profile cares about: an encrypted assertion is
  // ciphertext, which does not DEFLATE, so a redirect-bound one roughly doubles
  // in URL length — which is precisely why saml-profiles-2.0-os section 4.1.2
  // says the Redirect binding MUST NOT carry the Response.
  {
    const encJob = {
      name: "SAML 2.0 EncryptedAssertion — decrypt on Response page",
      script: "saml_encrypted_sso.js",
      env: {
        SAML_METADATA_URL: env.SAML_METADATA_URL,
        SAML_METADATA_FILE: env.SAML_METADATA_FILE,
        SAML_ENC_SP_ENTITY_ID: env.SAML_ENC_SP_ENTITY_ID,
        SAML_USER: env.SAML_USER,
      },
    };
    if (env.SAML_LANDING_AVAILABLE === "false") {
      encJob.skip = "the target has no SAML ACS landing at " +
        (env.SAML_LANDING_URL || "<base>/samlacs") +
         " to receive the IdP's POST, and the encrypted " +
        "client forces the POST binding so the Redirect fallback cannot be " +
            "used. On a static " +
        "deployment, apply the infrastructure (./infra/terraform-local.sh " +
            "test apply) so the " +
        "Lambda@Edge landing exists, and build the site with samlEdgeLanding: true.";
    }
    jobs.push(encJob);
  }

  // SAML 2.0 Single Logout: log in via SSO (to establish the Keycloak session
  // and capture the NameID/SessionIndex), then send a signed LogoutRequest and
  // confirm the LogoutResponse renders with a Success status on the response
  // page.
  jobs.push({
    name: "SAML 2.0 Single Logout (login → LogoutRequest → " +
        "LogoutResponse Success)",
    script: "saml_logout.js",
    env: {
      SAML_METADATA_URL: env.SAML_METADATA_URL,
      // When set (remote-run-tests.sh), the metadata is uploaded from this
      // local file instead of fetched from the URL — see loadIdpMetadata().
      SAML_METADATA_FILE: env.SAML_METADATA_FILE,
      SAML_SP_ENTITY_ID: env.SAML_SP_ENTITY_ID,
      SAML_USER: env.SAML_USER,
    },
  });

  // WS-Federation Passive Requestor Profile SSO, run twice: against the
  // dedicated Keycloak 8.0.1 + cloudtrust keycloak-wsfed side-car (the 26.x
  // Keycloak has no WS-Fed support) and against the mock STS, which grew this
  // profile in 2026-08. Every combination below is pushed once per IdP.
  //
  // Two IdPs rather than one because they fail differently, and each covers what
  // the other cannot:
  //
  //   * **Keycloak is somebody else's implementation.** An EOL server carrying a
  //     third-party extension, provisioned through its admin API, with a real
  //     session cookie and a real login form. It is the only thing here that can
  //     tell us the debugger interoperates with software this project did not
  //     write — which is the entire point of the side-car and the reason it is
  //     kept alive at 8.0.1.
  //   * **The mock STS READS what the debugger sends.** Keycloak's extension
  //     ignores wreq, accepts any wauth and never states a token type, so nine
  //     of these jobs prove only that a request was built and a round trip
  //     completed. The mock refuses a wauth it cannot perform, a token type it
  //     does not offer and a wreqptr outright, each with a reason — so a request
  //     that is well-formed but wrong fails there and passes at Keycloak. It is
  //     also the only WS-Fed IdP available where the side-car is not: it runs in
  //     every stack the suite starts, including the host and live-site runs.
  //
  // Each is gated on its own metadata URL, so an environment with one and not
  // the other runs half of these and skips the other half naming which.
  {
    // The landing gate is shared: it is about the TARGET (does anything at
    // <base>/wsfed answer the IdP's POST), not about which IdP sent it.
    let landingSkip = null;
    if (env.WSFED_LANDING_AVAILABLE === "false") {
      // The other end of the round trip. The Passive Requestor Profile has ONE
      // way to return the token — the IdP auto-POSTs the wresult to wreply —
      // and no redirect alternative to fall back to the way SAML has. So the
      // target needs something at /wsfed that answers a POST.
      //
      // This used to be keyed on SAML_BACKEND_AVAILABLE, i.e. "static
      // deployments cannot do this at all". That was wrong: they can, with a
      // Lambda@Edge on that path (infra/edge/wsfed_landing.js), which is what
      // the hosted sites now run. What actually decides it is whether the
      // landing is DEPLOYED — the site bundle and the Terraform ship
      // independently — so remote-run-tests.sh probes the target with a real
      // POST and sets this. Unset (the containerized and local runs) means "not
      // probed", and the job runs against the api backend's landing as it
      // always has.
      landingSkip = "the target has no WS-Federation landing at " +
        (env.WSFED_LANDING_URL || "<base>/wsfed") +
         " to receive the IdP's wresult POST " +
        "(the profile has no redirect binding). On a static deployment, " +
            "apply the infrastructure " +
        "(./infra/terraform-local.sh test apply) so the Lambda@Edge landing " +
            "exists, and build the " +
        "site with wsfedEdgeLanding: true.";
    }

    // The two IdPs. `env` per IdP is everything wsfed_sso.js needs to know
    // about it — the rest of the job list below is identical for both, which is
    // the property worth keeping: a case added for one is added for the other.
    const wsfedIdps = [
      {
        key: "keycloak",
        label: "Keycloak",
        // common.sh's configureKeycloakWsfed exports this only once the
        // side-car has provisioned AND served its descriptor, so an unset value
        // means the IdP is genuinely absent rather than merely unconfigured.
        skip: env.WSFED_METADATA_URL ? null :
          "WS-Federation side-car (Keycloak 8.0.1 + wsfed) not provisioned (WSFED_METADATA_URL unset).",
        env: {
          WSFED_IDP: "keycloak",
          WSFED_METADATA_URL: env.WSFED_METADATA_URL,
          WSFED_REALM: env.WSFED_REALM,
          WSFED_USER: env.WSFED_USER,
        },
      },
      {
        key: "sts",
        label: "mock STS",
        skip: env.WSFED_STS_METADATA_URL ? null :
          "the mock STS is not reachable by the browser for WS-Federation (WSFED_STS_METADATA_URL unset). " +
          "The launchers set it wherever the STS is reachable — the containerized stack by compose DNS " +
          "name, the host and live-site runs over loopback.",
        env: {
          WSFED_IDP: "sts",
          WSFED_METADATA_URL: env.WSFED_STS_METADATA_URL,
          // The mock registers no relying parties, so the wtrealm is any string
          // and becomes the assertion's audience. It is given one that says
          // where it came from rather than reusing Keycloak's provisioned
          // client id, so an audience seen in a log names its own test.
          WSFED_REALM: env.WSFED_STS_REALM || "urn:wsfed:sts:rp",
          // It authenticates nobody: the username becomes the subject and the
          // only password refused is the literal "invalid".
          WSFED_USER: env.WSFED_STS_USER || "wsfed",
          // Its passive endpoint does not sit under its metadata path the way
          // Keycloak's does. deriveEndpoint() knows the AD FS shape, but this
          // is only a fallback for a failed parse either way, so it is passed
          // explicitly where it is known.
          WSFED_SIGNIN_ENDPOINT: env.WSFED_STS_ENDPOINT ||
            (env.WSFED_STS_METADATA_URL || "").replace(
              /\/FederationMetadata\/[^/]+\/FederationMetadata\.xml.*$/i,
              "/wsfed"),
          // And it READS the inline wreq, refusing a token type it does not
          // offer — so the jobs that send one ask for an assertion type it
          // advertises. See the note on WREQ_TOKEN_TYPE in wsfed_sso.js.
          WSFED_WREQ_TOKEN_TYPE: "urn:oasis:names:tc:SAML:2.0:assertion",
        },
      },
    ];

    // One push per IdP. The name carries the IdP because both appear in the
    // same report and a failure that does not say which one it was sends
    // somebody to the wrong service.
    const pushWsfed = (name, extraEnv) => {
      log.debug("Entering pushWsfed().");
      for (const idp of wsfedIdps) {
        const job = {
          name: name + " [" + idp.label + "]",
          script: "wsfed_sso.js",
          env: Object.assign({}, idp.env, extraEnv),
        };
        // The IdP's own absence is the more specific reason, so it wins over
        // the landing's when both apply.
        if (idp.skip) { job.skip = idp.skip; }
        else if (landingSkip) { job.skip = landingSkip; }
        jobs.push(job);
      }
      log.debug("Leaving pushWsfed().");
    };

    // Every valid combination of the sign-in request options the workflow
    // supports: the signing state (unsigned, or signed with each binding × each
    // algorithm) crossed with where the request is initiated from. The passive
    // request is not verified by the IdP, so a signature never blocks the round
    // trip — wsfed_sso.js asserts the signature was BUILT (client-side) and
    // then confirms the round trip still completes.
    const signStates = [{ key: "unsigned", env: { WSFED_SIGN: "off" } }];
    for (const binding of ["redirect", "enveloped"]) {
      for (const alg of ["rsa-sha256", "rsa-sha1", "rsa-sha384",
           "rsa-sha512"]) {
        signStates.push({
          key: binding + "+" + alg,
          env: { WSFED_SIGN: "on", WSFED_SIG_BINDING: binding,
                WSFED_SIG_ALG: alg },
        });
      }
    }
    for (const s of signStates) {
      for (const initiate of ["back", "front"]) {
        pushWsfed(
          `WS-Federation Sign-in (sign=${s.key}, initiate=${initiate})`,
          Object.assign({ WSFED_MODE: "signin", WSFED_INITIATE: initiate },
                        s.env)
        );
      }
    }

    // Optional passthrough request parameters (wctx/wct/wfresh/wauth/wp),
    // exercised together once. Keycloak largely ignores them, so there this
    // proves the debugger emits them without breaking the round trip; the mock
    // STS reads all five and REFUSES a wauth naming a method it cannot perform
    // or a wfresh that is not a number of minutes, so the same job additionally
    // proves the values are ones an IdP that checks will accept.
    pushWsfed(
      "WS-Federation Sign-in (optional params: wctx/wct/wfresh/wauth/wp)",
      { WSFED_MODE: "signin", WSFED_INITIATE: "back", WSFED_OPT_PARAMS: "true" }
    );
    // Unsigned inline wreq (RequestSecurityToken) once.
    pushWsfed(
      "WS-Federation Sign-in (inline wreq)",
      { WSFED_MODE: "signin", WSFED_INITIATE: "back",
       WSFED_INCLUDE_WREQ: "true" }
    );

    // Sign-out (wa=wsignout1.0) + session-ended check. Must share a browser
    // with a sign-in, so this one job does sign-in → sign-out (the original
    // flow); signing is off here to keep the leg focused on session
    // termination.
    pushWsfed(
      "WS-Federation Passive SSO + Sign-out (Call IdP → login → " +
          "wsfed_response → wsignout1.0)",
      { WSFED_MODE: "signout", WSFED_INITIATE: "back", WSFED_SIGN: "off" }
    );
  }

  // WS-Trust 1.4 against the STS (the mock STS service, or a real Apache CXF
  // STS if WSTRUST_STS_URL points at one). Exercises all four operations —
  // Issue, Renew, Validate, Cancel — plus a signed Issue (WS-Security
  // XML-DSIG). Each job builds a SOAP RequestSecurityToken, sends it through
  // the backend proxy (POST /wstrust), and asserts the RSTR / issued token /
  // status renders on the response page. Renew/Validate/Cancel first Issue a
  // token to act on.
  //
  // Skipped when no STS is reachable (WSTRUST_STS_URL unset) rather than
  // failing. Routing is exercised both ways: "back" sends through the API proxy
  // (POST /wstrust); "front" makes the browser call the STS directly. Issue
  // runs once per route; the other operations use backend routing.
  //
  // On a BACKEND-LESS target (the deployed static site: samlBackendAvailable
  // false) there is no /wstrust proxy — the page disables backend routing and
  // sends every request from the browser. So rewrite "back" to "front" there
  // (rather than letting the report claim backend routing it never used) and
  // skip the one job whose entire subject is backend routing. The live-site run
  // supplies a loopback STS the browser can reach; see remote-run-tests.sh.
  var wstrustStsUrl = env.WSTRUST_STS_URL || "";
  var wstrustSkip = "WS-Trust needs an STS (WSTRUST_STS_URL) — none reachable from this target.";
  var wstrustNoBackendSkip = "This target has no API proxy (POST /wstrust) — backend routing cannot be exercised; the frontend-routing jobs cover the exchange.";
  // Effective routing for a job that asks for the backend proxy.
  var wstrustRoute = function (route) {
    log.debug("Entering wstrustRoute().");
    log.debug("Leaving wstrustRoute().");
    return (route === "back" && !samlBackendAvailable) ? "front" : route;
  };
  var wstrustJobs = [
    { op: "issue", sign: "false", route: "back",
     label: "Issue (backend routing)", backendOnly: true },
    { op: "issue", sign: "false", route: "front",
     label: "Issue (frontend routing)" },
    { op: "issue", sign: "true", route: "back",
     label: "Issue (signed, WS-Security XML-DSIG)" },
    { op: "renew", sign: "false", route: "back", label: "Renew" },
    { op: "validate", sign: "false", route: "back", label: "Validate" },
    { op: "cancel", sign: "false", route: "back", label: "Cancel" },
  ];
  for (const wj of wstrustJobs) {
    const job = {
      name: "WS-Trust 1.4 — " + wj.label,
      script: "wstrust.js",
      env: {
        WSTRUST_STS_URL: wstrustStsUrl,
        WSTRUST_OP: wj.op,
        WSTRUST_SIGN: wj.sign,
        WSTRUST_ROUTE: wstrustRoute(wj.route),
      },
    };
    if (!wstrustStsUrl) {
      job.skip = wstrustSkip;
    } else if (wj.backendOnly && !samlBackendAvailable) {
      job.skip = wstrustNoBackendSkip;
    }
    jobs.push(job);
  }

  // Encrypted-token round-trip: sign the request, ask the STS to encrypt the
  // issued assertion (?encrypt=1) to the requestor cert, then DECRYPT it on the
  // response page and confirm a plaintext assertion (exercises decryptXml).
  var encJob = {
    name: "WS-Trust 1.4 — Issue (encrypted token, decrypt)",
    script: "wstrust.js",
    env: {
      WSTRUST_STS_URL: wstrustStsUrl,
      WSTRUST_OP: "issue",
      WSTRUST_SIGN: "true",
      WSTRUST_ROUTE: wstrustRoute("back"),
      WSTRUST_ENCRYPT: "true",
    },
  };
  if (!wstrustStsUrl) {
    encJob.skip = wstrustSkip;
  }
  jobs.push(encJob);

  // Cycle the WS-Trust protocol version (1.0–1.4) with an Issue each, so each
  // version's trust namespace and option-gating (Bearer key type is 1.3+,
  // ActAs is 1.4) is exercised end to end against the STS.
  for (const wv of ["1.0", "1.1", "1.2", "1.3", "1.4"]) {
    const job = {
      name: "WS-Trust " + wv + " — Issue",
      script: "wstrust.js",
      env: {
        WSTRUST_STS_URL: wstrustStsUrl,
        WSTRUST_OP: "issue",
        WSTRUST_SIGN: "false",
        WSTRUST_ROUTE: wstrustRoute("back"),
        WSTRUST_VERSION: wv,
      },
    };
    if (!wstrustStsUrl) {
      job.skip = wstrustSkip;
    }
    jobs.push(job);
  }

  // XML Signature & XML Encryption interop. A pure-Node test (no browser, no
  // IdP) that runs the WS-Trust workflow's in-browser crypto
  // (client/src/xmldsig.js) and validates its output against official
  // libraries: xml-crypto verifies the WS-Security signature; xml-encryption
  // decrypts the XML-Encryption output.
  jobs.push({
    name: "XML Signature & Encryption interop (xml-crypto / xml-encryption)",
    script: "xmlsec_interop.js",
    env: {},
  });

  // WS-Trust message schema validation. A pure-Node test that builds the RST
  // for every scenario (each version × operation) with the real generator and
  // validates it against a schema derived from the official OASIS WS-Trust 1.3
  // XSD (libxmljs2/libxml2). Self-skips (exit 0) if libxmljs2 — an optional
  // native dependency — isn't installed on the platform.
  jobs.push({
    name: "WS-Trust message schema validation (RST vs OASIS-derived XSD)",
    script: "wstrust_schema_validate.js",
    env: {},
  });

  // ---------------------------------------------------------------------------
  // Kerberos is either present on this target or it is not, and when it is not
  // NONE of its jobs belong in the run — not just the four page ones.
  //
  // The gate used to be called KERBEROS_PAGES_AVAILABLE and was applied only to
  // the pages, which was right as far as it went and left ten jobs behind: the
  // codec, the crypto vectors, the PAC layout, the decoder output, the codec
  // sync, the relay, the two mock-KDC exchanges and the two Windows ones. Those
  // are node-only, so nothing stopped them, and they duly ran against
  // https://test.idptools.com — a deployment that has no Kerberos at all.
  //
  // They should not have. They exercise LOCAL code and say nothing whatever
  // about the deployed site, so on that target they are noise at best. At worst
  // they are misleading, which is what happened on 2026-08-15 and 2026-08-16:
  // remote-run-tests.sh sets CONFIG_FILE=./env/test-idptools-com.js, and
  // sts/helpers.js resolves a relative CONFIG_FILE against sts/ rather than
  // tests/ — where no such file exists, the submodule shipping only local.js,
  // docker-tests.js and test.js. Both mock-KDC jobs died with "Cannot find
  // module './env/test-idptools-com.js'", naming a config file, on a run whose
  // target has nothing to do with the mock. Two red tests, twice, for a
  // protocol that is switched off there.
  //
  // Doing it as a sweep rather than at each push site is deliberate: a Kerberos
  // test added later inherits the gate without anyone remembering to add it,
  // which is exactly how the original ten came to be missed.
  if (kerberosOff) {
    const kerberosSkip =
      "Kerberos is not part of this target. The workflow needs the api's " +
      "port-88 relay, which a static deployment has not got, so " +
      "client/static_site.js leaves all six pages out of the build and both " +
      "landing cards are greyed out. The codec and mock-KDC jobs are skipped " +
      "here too: they exercise local code and report nothing about the " +
      "deployed site, so running them adds noise and, when the run's " +
      "CONFIG_FILE does not resolve inside the sts/ submodule, spurious " +
      "failures. Run them against the containerized stack " +
      "(./docker-run-tests.sh) or a local dev server. Set " +
      "KERBEROS_AVAILABLE=true for a remote target that IS api-backed.";
    let swept = 0;
    for (const job of jobs) {
      if (!/^(krb5_|kerberos_|api_krb5_)/.test(job.script)) { continue; }
      if (job.skip) { continue; }        // a more specific reason already won
      job.skip = kerberosSkip;
      swept += 1;
    }
    log.info("Kerberos is off for this target: skipped " + swept +
      " further job(s) beyond the pages.");
  }

  log.debug("Leaving buildJobs().");
  return jobs;
}

function slug(s) {
  log.debug("Entering slug().");
  log.debug("Leaving slug().");
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
}

function logPathFor(name, index) {
  log.debug("Entering logPathFor().");
  log.debug("Leaving logPathFor().");
  return path.join(LOGS_DIR, `${String(index + 1).padStart(2,
                   "0")}-${slug(name)}.log`);
}

function logHeader(name, script, startedAt) {
  log.debug("Entering logHeader().");
  log.debug("Leaving logHeader().");
  return (
    [
      `Test:     ${name}`,
      `Script:   ${script}`,
      `Base URL: ${BASE_URL}`,
      `Started:  ${startedAt}`,
    ].join("\n") +
    "\n\n===== OUTPUT (stdout + stderr, in the order produced) =====\n"
  );
}

// Run one test, streaming its stdout AND stderr live to the console while
// simultaneously writing them to a per-test log file (a tee). The log is
// opened and the header written before the child starts, and flushed as
// output arrives, so the full output survives even if the suite is killed
// or a test hangs. Returns a Promise resolving to the result.
function runJob(job, index) {
  log.debug("Entering runJob().");
  log.debug("Leaving runJob().");
  return new Promise((resolve) => {
    const startedAt = new Date().toISOString();
    const startMs = Date.now();
    fs.mkdirSync(LOGS_DIR, { recursive: true });
    const logPath = logPathFor(job.name, index);
    const logStream = fs.createWriteStream(logPath);
    logStream.write(logHeader(job.name, job.script, startedAt));

    let output = "";
    const tee = (chunk) => {
      log.debug("Entering tee().");
      const s = chunk.toString();
      output += s;
      logStream.write(s); // capture
      process.stdout.write(s); // live echo
      log.debug("Leaving tee().");
    };

    const finish = (code, codeLabel) => {
      log.debug("Entering finish().");
      const durationMs = Date.now() - startMs;
      const passed = code === 0;
      logStream.end(
        `\n===== RESULT: ${passed ? "PASS" : "FAIL"} ` +
          `(exit ${codeLabel}, ${(durationMs / 1000).toFixed(1)}s) =====\n`
      );
      resolve({
        name: job.name,
        script: job.script,
        passed,
        code: codeLabel,
        durationMs,
        output,
        logFile: path.relative(TESTS_DIR, logPath),
      });
      log.debug("Leaving finish().");
    };

    const child = spawn("node", [path.join(TESTS_DIR, job.script), "--url",
        BASE_URL], {
      env: { ...process.env, ...job.env },
    });
    child.stdout.on("data", tee);
    child.stderr.on("data", tee);
    child.on("error", (err) => {
      // e.g. node binary missing — record it instead of crashing the runner
      tee(`\n[runner] failed to spawn: ${err.message}\n`);
      finish(1, `spawn error: ${err.message}`);
    });
    child.on("close", (code) => finish(code, code));
  });
}

// Record a skipped job (a capability the target can't exercise, e.g. Artifact
// on a backendless deployment). Written to a log + returned as a result that is
// neither pass nor fail, so it doesn't count against the suite.
function makeSkipResult(job, index) {
  log.debug("Entering makeSkipResult().");
  const startedAt = new Date().toISOString();
  fs.mkdirSync(LOGS_DIR, { recursive: true });
  const logPath = logPathFor(job.name, index);
  const reason = job.skip || "skipped";
  fs.writeFileSync(
    logPath,
    logHeader(job.name, job.script, startedAt) +
      "SKIPPED: " + reason + "\n" +
      "\n===== RESULT: SKIP =====\n"
  );
  log.debug("Leaving makeSkipResult().");
  return {
    name: job.name,
    script: job.script,
    passed: true, // not a failure
    skipped: true,
    reason,
    code: "skip",
    durationMs: 0,
    output: "SKIPPED: " + reason,
    logFile: path.relative(TESTS_DIR, logPath),
  };
}

// ---- report rendering ------------------------------------------------------

function esc(s) {
  log.debug("Entering esc().");
  log.debug("Leaving esc().");
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderHtml(results, generatedAt, demo) {
  log.debug("Entering renderHtml().");
  const total = results.length;
  const skipped = results.filter((r) => r.skipped).length;
  const passed = results.filter((r) => r.passed && !r.skipped).length;
  const failed = total - passed - skipped;
  const totalMs = results.reduce((a, r) => a + r.durationMs, 0);

  const rows = results
    .map((r, i) => {
      const cls = r.skipped ? "skip" : r.passed ? "pass" : "fail";
      const badge = r.skipped ? "SKIP" : r.passed ? "PASS" : "FAIL";
      const log = esc((r.output || "").trim());
      const logLink = r.logFile
        ? `<br><a href="logs/${esc(path.basename(r.logFile))}"><code>${esc(
            r.logFile)}</code></a>`
        : "";
      return `
      <tr class="${cls}">
        <td><span class="badge ${cls}">${badge}</span></td>
        <td>${esc(r.name)}<br><code>${esc(r.script)}</code></td>
        <td class="num">${(r.durationMs / 1000).toFixed(1)}s</td>
        <td class="num">${esc(r.code)}</td>
        <td><details><summary>output</summary><pre>${log ||
            "(no output)"}</pre></details>${logLink}</td>
      </tr>`;
    })
    .join("");

  log.debug("Leaving renderHtml().");
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>OAuth2/OIDC Debugger — Selenium Test Report</title>
<style>
  body{font-family:system-ui,Segoe UI,Helvetica,Arial,sans-serif;margin:2rem;color:#1b1b1b}
  h1{margin:0 0 .25rem} .sub{color:#666;margin:0 0 1.5rem}
  .demo{background:#fff3cd;border:1px solid #ffe08a;padding:.6rem 1rem;border-radius:6px;margin-bottom:1rem}
  .cards{display:flex;gap:1rem;margin-bottom:1.5rem;flex-wrap:wrap}
  .card{border:1px solid #e2e2e2;border-radius:8px;padding:1rem 1.4rem;min-width:120px}
  .card .n{font-size:1.8rem;font-weight:700}
  .card.ok .n{color:#1a7f37}.card.bad .n{color:#c1121f}
  table{border-collapse:collapse;width:100%}
  th,td{border-bottom:1px solid #eee;padding:.55rem .6rem;text-align:left;vertical-align:top}
  th{background:#fafafa} .num{text-align:right;white-space:nowrap}
  tr.fail{background:#fff5f5}tr.skip{background:#fbfbf5}
  .badge{font-weight:700;font-size:.75rem;padding:.15rem .5rem;border-radius:4px;color:#fff}
  .badge.pass{background:#1a7f37}.badge.fail{background:#c1121f}.badge.skip{background:#8a6d00}
  code{background:#f3f3f3;padding:.05rem .3rem;border-radius:3px}
  pre{background:#0d1117;color:#e6edf3;padding:.8rem;border-radius:6px;overflow:auto;max-height:360px;font-size:.8rem}
  summary{cursor:pointer;color:#0969da}
</style></head><body>
<h1>OAuth2/OIDC Debugger — Selenium Test Report</h1>
<p class="sub">Generated ${esc(generatedAt)} · base URL <code>${esc(
                               BASE_URL)}</code></p>
${demo ? '<div class="demo"><strong>SAMPLE REPORT</strong> — generated with <code>--demo</code>. No tests were run; the data below is illustrative only.</div>' : ""}
<div class="cards">
  <div class="card"><div class="n">${total}</div><div>total</div></div>
  <div class="card ok"><div class="n">${passed}</div><div>passed</div></div>
  <div class="card bad"><div class="n">${failed}</div><div>failed</div></div>
  ${skipped ? `<div class="card"><div class="n">${skipped}</div><div>skipped</div></div>` : ""}
  <div class="card"><div class="n">${(totalMs / 1000)
      .toFixed(1)}s</div><div>duration</div></div>
</div>
<table>
  <thead><tr><th>Result</th><th>Test</th><th>Time</th><th>Exit</th><th>Output</th></tr></thead>
  <tbody>${rows}</tbody>
</table>
</body></html>`;
}


// Can the browser this run will use side-load an unpacked extension?
//
// BRANDED Google Chrome cannot. It refuses the flags and says so only on stderr
// ("--disable-extensions-except is not allowed in Google Chrome, ignoring"),
// after which the extension is simply absent and every assertion in the
// extension job times out naming nothing. Chrome for Testing — which the tests
// image pins — and Chromium both allow it.
//
// So this is an environment capability, not a defect, and the job SKIPS with
// the browser named rather than failing. It cost a full host run of that job to
// learn: the containerized suite passed it and local-run-tests.sh, which drives
// the host's own Chrome, did not.
function extensionCapableBrowser() {
  log.debug("Entering extensionCapableBrowser().");
  const candidates = [process.env.CHROME_BIN, "chrome", "chromium",
      "chromium-browser",
                      "google-chrome"].filter(Boolean);
  for (const bin of candidates) {
    let out;
    try {
      out = execFileSync(bin, ["--version"],
                         { encoding: "utf8", stdio: ["ignore", "pipe",
                          "ignore"] }).trim();
    } catch (e) {
      // Not on PATH under this name; try the next.
      continue;
    }
    // Resolve to an absolute path, because the job is told to USE this exact
    // binary. Probing one browser and letting Selenium launch another is how a
    // host with both Chromium and branded Chrome would report capable and then
    // fail anyway.
    let resolved = bin;
    if (!path.isAbsolute(bin)) {
      try {
        resolved = execFileSync("which", [bin], { encoding: "utf8" }).trim() ||
            bin;
      } catch (e) {
        // `which` is absent or the name is a shell builtin; the PATH name is
        // the best we have, and Selenium resolves it the same way.
        resolved = bin;
      }
    }
    log.debug("Leaving extensionCapableBrowser().");
    return { bin: resolved, version: out,
            capable: /Chrome for Testing|Chromium/i.test(out) };
  }
  log.debug("Leaving extensionCapableBrowser().");
  return { bin: null, version: null, capable: false };
}

function renderJUnit(results, generatedAt) {
  log.debug("Entering renderJUnit().");
  const total = results.length;
  const failures = results.filter((r) => !r.passed && !r.skipped).length;
  const skips = results.filter((r) => r.skipped).length;
  const totalSec = (results.reduce((a, r) => a + r.durationMs,
      0) / 1000).toFixed(3);
  const cases = results
    .map((r) => {
      const time = (r.durationMs / 1000).toFixed(3);
      const sys = esc((r.output || "").trim());
      const body = r.skipped
        ? `<skipped message="${esc(r.reason || "skipped")}"/>`
        : r.passed
        ? ""
        : `<failure message="exit ${esc(r.code)}">Test exited with status ${esc(
                                        r.code)}</failure>`;
      return `    <testcase classname="selenium" name="${esc(r.name)}" time="${time}">${body}<system-out>${sys}</system-out></testcase>`;
    })
    .join("\n");
  log.debug("Leaving renderJUnit().");
  return `<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="oauth2-oidc-debugger" tests="${total}" failures="${failures}" skipped="${skips}" time="${totalSec}" timestamp="${esc(generatedAt)}">
${cases}
  </testsuite>
</testsuites>
`;
}

function writeReports(results, demo) {
  log.debug("Entering writeReports().");
  const generatedAt = new Date().toISOString();
  fs.mkdirSync(RUN_DIR, { recursive: true });
  fs.writeFileSync(path.join(RUN_DIR, "report.html"), renderHtml(results,
                   generatedAt, demo));
  fs.writeFileSync(path.join(RUN_DIR, "report.xml"), renderJUnit(results,
                   generatedAt));
  updateLatestPointer();
  log.debug("Leaving writeReports().");
}

// Best-effort convenience pointer to the most recent run. Prefers a symlink;
// falls back to a small text file where symlinks aren't permitted (e.g.
// Windows).
function updateLatestPointer() {
  log.debug("Entering updateLatestPointer().");
  const link = path.join(REPORT_DIR, "latest");
  try {
    if (fs.existsSync(link) || fs.lstatSync(link, { throwIfNoEntry: false })) {
      fs.rmSync(link, { recursive: true, force: true });
    }
  } catch (_) {
    /* nothing to remove */
  }
  try {
    fs.symlinkSync(RUN_ID, link, "dir");
  } catch (_) {
    fs.writeFileSync(path.join(REPORT_DIR, "latest.txt"), RUN_ID + "\n");
  }
  log.debug("Leaving updateLatestPointer().");
}

function demoResults() {
  log.debug("Entering demoResults().");
  const startedAt = new Date().toISOString();
  fs.mkdirSync(LOGS_DIR, { recursive: true });
  log.debug("Leaving demoResults().");
  return buildJobs().map((j, i) => {
    const passed = i !== 2; // pretend one failed, for preview
    const output =
      (passed
        ? "Entering populateMetadata().\nFind oidc_discovery_endpoint.\n... (hundreds of lines in a real run) ...\nToken validated.\nTest completed successfully."
        : "Entering populateMetadata().\n... (hundreds of lines in a real " +
            "run) ...\nAssertionError: expected token to contain claim 'aud'") +
            "\n";
    const result = {
      name: j.name,
      script: j.script,
      passed,
      code: passed ? 0 : 1,
      durationMs: 3000 + i * 1500,
      output,
      logFile: path.relative(TESTS_DIR, logPathFor(j.name, i)),
    };
    // Write a demo log file mirroring what a real run produces.
    fs.writeFileSync(
      logPathFor(j.name, i),
      logHeader(j.name, j.script, startedAt) +
        output +
        `\n===== RESULT: ${passed ?
            "PASS" : "FAIL"} (exit ${result.code}, ${(result.durationMs / 1000)
            .toFixed(1)}s) =====\n`
    );
    return result;
  });
}

async function main() {
  log.debug("Entering main().");
  const demo = process.argv.includes("--demo");
  let results;

  if (demo) {
    results = demoResults();
    log.info("Writing SAMPLE report (--demo); no tests executed.");
  } else {
    results = [];
    const jobs = buildJobs();
    log.info(`Running ${jobs.length} test(s) against ${BASE_URL}`);
    for (const [i, job] of jobs.entries()) {
      if (job.skip) {
        log.info(`===== [${i + 1}/${jobs.length}] ${job.name} — SKIPPED =====`);
        log.info(`----- SKIP: ${job.skip}`);
        results.push(makeSkipResult(job, i));
        continue;
      }
      log.info(`===== [${i + 1}/${jobs.length}] ${job.name} =====`);
      const r = await runJob(job,
          i); // sequential: keep streamed output readable
      results.push(r);
      log.info(`----- ${r.passed ? "PASS" : "FAIL"} (${(r.durationMs / 1000)
               .toFixed(1)}s) → ${r.logFile}`);
    }
  }

  writeReports(results, demo);

  const failed = results.filter((r) => !r.passed && !r.skipped).length;
  const skipped = results.filter((r) => r.skipped).length;
  const passed = results.length - failed - skipped;
  const rel = path.relative(process.cwd(), RUN_DIR);
  log.info(`Report written to ${rel}/report.html (and report.xml, logs/)`);
  log.info(`Latest run also at ${path.relative(process.cwd(),
           path.join(REPORT_DIR, "latest"))}`);
  log.info(`Summary: ${passed} passed, ${failed} failed, ${skipped} skipped, ${results.length} total`);

  // Don't fail the demo run; otherwise signal failures to the caller/CI.
  process.exit(demo ? 0 : failed > 0 ? 1 : 0);
  log.debug("Leaving main().");
}

main();
