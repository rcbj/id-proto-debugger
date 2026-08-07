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
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const bunyan = require("bunyan");

// The runner's own progress lines. They used to be console.log, which made this
// the last thing in this directory writing outside bunyan — every test it spawns
// already logs bunyan JSON, so the runner's plain lines were the odd ones out.
//
// Note what this changes and what it does not. These lines now come out as JSON
// like everything else, so pipe the run through `npx bunyan` for the old look. The
// REPORT is unaffected: report.html, report.xml and logs/NN-<test>.log are written
// with fs.writeFileSync and are what CI reads. And the live echo of each child's
// output further down stays process.stdout.write — it forwards another process's
// bytes as they arrive, in arbitrary chunks, so wrapping it would interleave JSON
// records with fragments of the child's own lines and make both unreadable.
//
// The level is guarded because this runner is started without CONFIG_FILE set (it
// sets one per job for the tests it spawns), so a bare require would throw.
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
  const jobs = [];

  // Basic navigation: landing page -> OAuth2/OIDC debugger -> Home -> SAML -> Home.
  jobs.push({
    name: "Navigation (landing page → OAuth2/OIDC → Home → SAML → Home)",
    script: "navigation.js",
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
  // why, since those flows never reach a token endpoint. `off` is what keeps the
  // Bearer path, which is what the specifications describe first, from quietly
  // becoming un-runnable.
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
          // registers no clients and checks no passwords, so there is nothing for
          // the suite to provision and nothing to keep in step here.
          env: { WSTRUST_STS_URL: env.WSTRUST_STS_URL, OIDC_FLOW, OIDC_DPOP },
        });
      }
    }
  }

  // The same twelve against KEYCLOAK, which asks the other half of the question:
  // whether any of it interoperates with a real OP. Gated on the client
  // configureKeycloak() provisions for it (OIDC_ALL_FLOWS_PUBLIC) — one client
  // with standardFlowEnabled AND implicitFlowEnabled, since Keycloak gates the
  // response types on that pair, and without "always use DPoP" so that both
  // halves of the DPoP axis run against it.
  //
  // Note what differs from the mock and is passed in rather than assumed:
  // Keycloak's `sub` is a UUID (OIDC_EXPECT_SUB), which is a different string
  // from the name typed at the login screen (OIDC_LOGIN_USER). The DPoP jobs also
  // need the server started with --features=dpop; the test checks the metadata
  // advertises DPoP and says so by name rather than failing at the last assertion.
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
            SCOPE: `openid profile email ${env.OIDC_ALL_FLOWS_PUBLIC_SCOPE || ""}`.trim(),
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
  // see: every token in the run belongs to the same user, so a link carrying the
  // wrong one still returns a correct-looking answer.
  //
  // Runs against both OPs, like the flow matrix. Unlike it, this one exercises
  // the UserInfo page's DEFAULT configuration, which on a build that HAS the api
  // initiates the call from it — so these two jobs need the api service as well
  // as the OP. On a backend-less target (the deployed static sites) the page
  // disables that option and calls the OP from the browser instead; the test
  // reads which build it is off the page rather than being told here, because it
  // is the page's own state that decides what pressing the button does.
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
        SCOPE: `openid profile email ${env.OIDC_ALL_FLOWS_PUBLIC_SCOPE || ""}`.trim(),
        OIDC_LOGIN_USER: env.OIDC_ALL_FLOWS_PUBLIC_USERNAME,
      },
    });
  }

  // DPoP is OPTIONAL on the OAuth2 / OIDC workflow: off by default, on when the
  // pane asks for it, and — the case this exists for — not decided by the SD-JWT
  // VC workflow's own switch, which is what used to make it mandatory here.
  if (env.WSTRUST_STS_URL) {
    jobs.push({
      name: "OIDC DPoP is optional (RFC 9449: off by default, on when asked, never inherited)",
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
  // target audience client, and the issued token is confirmed via introspection.
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

  // Device Authorization Grant (RFC 8628). Requests a device/user code, approves
  // the device at the Keycloak verification URI, then polls for the access token.
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
  // opens the Tools pane, follows the JWT Tools link, adds string/number/boolean
  // claims and checks RFC compliance, and exercises signing + X.509
  // verification and JWE encryption + decryption, including the PEM/JWK format
  // toggle and the key-download buttons.
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
  // pane it sets a value, generates a key, produces a signature/MAC, confirms it
  // validates, and exercises the keystore downloads. Asymmetric: SLH-DSA (12
  // sets); RSA (v1.5 & PSS × every hash × 2048/3072); ECC (ECDSA over
  // P-256/384/521/secp256k1 × every hash, EdDSA, Schnorr, BLS); ML-DSA (44/65/87).
  // Symmetric MACs: keyed-hash (HMAC/KMAC/BLAKE), block-cipher (CMAC/CBC-MAC/
  // GMAC), universal-hash (Poly1305/SipHash) — compute + verify + tamper check.
  jobs.push({
    name: "Digital Signature (asymmetric sigs + symmetric MACs — generate, sign/MAC, validate, download)",
    script: "digital_signature.js",
    env: {},
  });

  // SAML Assertion Tool. Another fully client-side page needing no IdP: compose
  // an assertion for each SAML version (2.0 / 1.1 / 1.0) with its version-specific
  // structure, toggle the optional elements, add typed + URI-prefixed custom
  // attributes, run the spec-compliance check, then sign it with an enveloped XML
  // Signature (whose placement and Reference URI differ per version), verify it,
  // reject a tampered copy, and round-trip it through XML Encryption. Also checks
  // the Tools pane on the SAML Test Tools page links here.
  // Operations History pane on the SAML request page: records every attempted
  // IdP call (AuthnRequest / Single Logout / metadata load) with its binding,
  // SAML version, entity IDs, and result. Needs no IdP — the failure paths come
  // from the page's own pre-flight checks and the dispatch is aimed at a URL on
  // the site itself.
  // RFC 8414 (OAuth 2.0 Authorization Server Metadata): the document the STS
  // mock serves at /.well-known/oauth-authorization-server (all 23 members,
  // host-derived issuer, verifiable signed_metadata, resolvable jwks_uri) and
  // the Metadata Source selector on debugger.html that retrieves it. Needs the
  // STS mock, like the WS-Trust jobs.
  if (env.WSTRUST_STS_URL) {
    jobs.push({
      name: "OAuth2 Authorization Server Metadata (RFC 8414 endpoint + debugger Metadata Source)",
      script: "oauth2_metadata_rfc8414.js",
      env: { WSTRUST_STS_URL: env.WSTRUST_STS_URL },
    });
  }

  // The mock authorization server the STS service hosts: every endpoint its
  // RFC 8414 document advertises answers, with real RS256 tokens that verify
  // against the advertised JWKS. No browser — it drives the endpoints directly.
  if (env.WSTRUST_STS_URL) {
    jobs.push({
      name: "OAuth2 Authorization Server endpoints (the STS mock's authorize / token / introspect / revoke / register)",
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
    script: "jose_jwe.js",
    env: {},
  });

  // The "save this key pair in browser localStorage" opt-out on the SAML and
  // WS-Trust request pages, exercised in BOTH states. Worth a browser test
  // because the failure mode is silent and reassuring: if the guard in
  // saveState() broke, the box would still untick and the note would still
  // appear while the private key went on being written. Only reading storage
  // shows it. Needs the client alone — no IdP, no STS — so it is never skipped.
  jobs.push({
    name: "Key pair localStorage opt-out (SAML, WS-Trust, WS-Fed, SD-JWT VC — checked and unchecked)",
    script: "keypair_storage_optout.js",
    env: {},
  });

  // The inertness of this app's XML parsing — the invariant behind CodeQL's
  // js/xss-through-dom reports on every DOMParser call in client/src (alert #147
  // and eleven siblings). Those are a modelling artefact: parseFromString with
  // 'application/xml' yields an inert, detached document, and nothing renders it
  // as markup. Sanitizing the input would be the wrong fix — XML-DSIG signs the
  // exact octets that get canonicalized, so rewriting them breaks the signature.
  // What CAN be done is keep the premise true, which is what this asserts.
  // Node only, never skipped.
  jobs.push({
    name: "XML parsing is inert (no DOMParser HTML mode, no markup sink on the XML path)",
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
    script: "url_safety.js",
    env: {},
  });

  // The JWK -> SPKI PEM encoder the JWKS page displays (client/src/jwk_pem.js).
  // It exists so the page does not have to require `jwk-to-pem`, which reaches
  // `elliptic` — GHSA-848j-6mx2-7j84, an ECDSA flaw that can expose a private
  // key, and one with NO patched version in existence. That trade is only sound
  // if the replacement encodes correctly, so this checks the DER against node's
  // own SPKI parser, and additionally fails if any file in client/src takes a
  // require that would put elliptic back into a bundle. Node only, never skipped.
  jobs.push({
    name: "JWK to PEM encoder (SPKI DER correctness; elliptic stays out of the bundles)",
    script: "jwk_pem.js",
    env: {},
  });

  // The wallet's DID module (client/src/did.js): did:jwk, did:key and did:web,
  // reading a DID document, and the DIF Well Known DID Configuration check that
  // proves a DID and an origin are the same entity. Everything here fails
  // silently when it is wrong — a multicodec written as a fixed-width number
  // instead of a varint produces DIDs that decode here and nowhere else, a
  // compressed EC point decompressed with the wrong square root gives the other
  // valid point on the curve, and a Domain Linkage Credential with a typ header
  // or an iat claim is exactly what a JWT library produces by default. It found a
  // real bug on its first run: P-384's and P-521's field primes were truncated.
  // Node only, never skipped.
  jobs.push({
    name: "DID module (did:jwk/key/web, document reading, DIF domain linkage)",
    script: "did_document.js",
    env: {},
  });

  // DPoP's own arithmetic (client/src/dpop.js): the RFC 7638 JWK Thumbprint that
  // becomes cnf.jkt, the htu normalization, the ath hash, and the shape of the
  // proof itself. Every one of those fails SILENTLY when it is wrong — a proof with
  // a wrong thumbprint or a wrong htu is perfectly well formed and simply matches
  // nothing, so the server's refusal reads as "your key is wrong" rather than "your
  // encoding is wrong". The oracle is not a second implementation but the RFCs' own
  // published values: RFC 9449 prints an EC key and the jkt of the token bound to
  // it, RFC 7638 section 3.1 does the same for RSA. Node only, never skipped.
  jobs.push({
    name: "DPoP arithmetic (RFC 7638 thumbprints against the RFCs' own vectors, htu/ath/jti)",
    script: "dpop.js",
    env: {},
  });

  // The api's outbound address policy (api/ssrf_guard.js): the service fetches
  // URLs its caller supplies, so it must refuse loopback and private destinations
  // or it is an SSRF probe into whatever network it runs in. Node only — no
  // browser, no services — so it is never skipped.
  jobs.push({
    name: "API SSRF guard (outbound calls to loopback / private ranges are refused)",
    script: "api_ssrf_guard.js",
    env: {},
  });

  // The api's outbound limits: api/connect_timeout.js plus callTimeout,
  // connectionTimeout, maxContentLength and maxRedirects in api/env/*.js. axios
  // defaults to no timeout, no size cap and 21 redirects, so without these a
  // caller-named host that goes quiet holds a request open for minutes, one that
  // streams fills the heap, and one that redirects can walk the service elsewhere.
  // The interesting half is that a connection which SUCCEEDED must not be cut off
  // by the connect budget — an AbortSignal-based implementation gets that wrong.
  // Node only, so never skipped.
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
      name: "BBS signatures (cross-checked against an independent implementation)",
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
      name: "OID4VCI Credential Request encryption (section 10, issuer-published keys)",
      script: "oid4vci_request_encryption.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL || "",
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
        WALTID_ISSUER_URL: env.WALTID_ISSUER_URL || "",
      },
    });
    jobs.push({
      name: "VC Refresh — ldp_vc / bbs-2023 (OID4VCI 14.5 refresh_token + re-request)",
      script: "ldp_vc_refresh.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL || "",
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
    jobs.push({
      name: "VC Presentation — ldp_vc / bbs-2023 (statement disclosure, unlinkable)",
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
    // that resolves to the wrong key looks like success until something tries to
    // verify with it. Needs only the STS mock.
    // The mock STS's own index of itself: GET /sts-metadata lists every endpoint it
    // registers, with its methods, and every specification it implements. The list
    // is read from the running Express router rather than kept by hand, and this
    // job is what makes that worth something — it fails if a route is registered
    // and undescribed (the page understates what is callable) or described and not
    // registered (the page advertises a 404, which is what a rename produces).
    // Needs only the STS mock.
    // did-tools.html, the general-purpose DID verifier reached from the VC Tools
    // pane on every page of both workflows. The DIDs it works on are GENERATED by
    // the mock STS (GET /did/generate), which hands back a DID together with a
    // credential signed by the key that DID publishes — so the page's verdict can
    // be checked against a known-good answer instead of against "the document
    // parsed". Its two negatives are the point: a document that resolves perfectly
    // but did not sign the held credential must not read as verified, and an origin
    // that vouches for a different DID must not read as linked. Needs the STS and
    // the client; no Keycloak, no walt.id.
    jobs.push({
      name: "DID Tools page (resolve, verify a signing key, verify a domain linkage)",
      script: "did_tools.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL || "",
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
    jobs.push({
      name: "STS metadata page (/sts-metadata lists exactly what the router registers)",
      script: "sts_metadata.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL || "",
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
    jobs.push({
      name: "VC Issuance — issuer named by DID (did:web, domain linkage, both formats)",
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
      name: "bbs-2023 cryptosuite (ldp_vc issue, derive, verify across two implementations)",
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
      name: "Metadata schema validation (OID4VCI and RFC 8414 panes, positive and negative)",
      script: "metadata_schema_validation.js",
      env: {},
    });
  }

  // These four are registered UNCONDITIONALLY, unlike their SD-JWT siblings.
  // A gated job that does not register simply is not in the report, which is the
  // quietest possible way for a credential format to go untested — the run says
  // "all green" and nothing says the format was never exercised. Each of these
  // instead runs and FAILS with what is missing and how to supply it.
  // The SAME issuance workflow in the other credential format this issuer
  // offers: jwt_vc_json, a W3C VC secured as a JWT. Its own job rather than a
  // flag on the one above, because that suite is built around Disclosures and
  // this format has none — a flag would leave most of it skipped and the run
  // would read as though selective disclosure had been declined rather than
  // being unavailable. Skips itself when the issuer offers no such
  // configuration.
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

  // The SD-JWT VC PRESENTATION workflow (OID4VP 1.0 + RFC 9901 section 4.3): the
  // mock Verifier the STS service hosts, the four vc-presentation pages,
  // and the presentation itself — an SD-JWT+KB whose Key Binding JWT is signed
  // over the request's nonce. Needs only the STS (issuer AND verifier), so no
  // identity provider is involved. Carries its own negatives: a replayed
  // presentation, a KB-JWT signed by the wrong key, an invented Disclosure, one
  // removed after signing, and a claim the verifier asked for withheld.
  if (env.WSTRUST_STS_URL) {
    // The SERVER half of DPoP, over HTTP with no browser: all twelve RFC 9449
    // section 4.3 proof checks, the cnf.jkt binding on access and refresh tokens,
    // the dpop_jkt code binding, jti replay detection, and the nonce handshake in
    // both of its shapes. It is almost entirely negatives, because a DPoP server
    // that issues bound tokens and accepts good proofs looks finished and can be
    // worth nothing — the value is all in what it refuses. Needs only the STS.
    jobs.push({
      name: "DPoP server checks (RFC 9449: the twelve proof checks, binding, replay, nonces)",
      script: "sts_dpop.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL,
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
    // And DPoP through the PAGES, which is the part neither of the two above can
    // reach: that the wallet really sends the proofs, that the token which comes
    // back is really bound (checked against the token's own cnf.jkt, not against
    // what the pane says), and that Holder of Key really binds the credential to
    // the DPoP key. Driven with the pre-authorized code grant, so no IdP is needed.
    jobs.push({
      name: "DPoP through the VC Issuance pages (the pane, the real binding, Holder of Key)",
      script: "dpop_workflow.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL,
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
    jobs.push({
      name: "VC Presentation — SD-JWT VC (OID4VP: selective disclosure, positive and negative)",
      script: "sd_jwt_vc_presentation.js",
      env: {
        WSTRUST_STS_URL: env.WSTRUST_STS_URL,
        OID4VCI_ISSUER_URL: env.OID4VCI_ISSUER_URL || "",
      },
    });
  }

  // The PRESENTATION half of the same format: a Verifiable Presentation JWT
  // instead of an SD-JWT+KB, with holder binding done by that JWT's own
  // signature rather than by a Key Binding JWT. Carries its own negatives — a VP
  // JWT signed by the wrong key, a replay, a tampered credential, and an SD-JWT
  // answering a jwt_vc_json query (which matters because a Combined
  // Serialization also splits into three dot-separated parts).
  {
    jobs.push({
      name: "VC Presentation — jwt_vc_json (Verifiable Presentation JWT, positive and negative)",
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
      name: "VC Issuance — SD-JWT VC against walt.id (OID4VCI interoperability)",
      script: "sd_jwt_vc_waltid.js",
      env: {
        WALTID_ISSUER_URL: env.WALTID_ISSUER_URL,
        KEYCLOAK_BASE_URL: env.KEYCLOAK_BASE_URL || "",
      },
    });
  }

  // The SD-JWT VC PRESENTATION workflow driven against walt.id's verifier-api2 —
  // an independently written OpenID4VP 1.0 verifier with DCQL — instead of our own
  // mock. The credential it presents is ISSUED BY walt.id in the same run through
  // our issuance pages, so neither end of the exchange is ours. Gated on that
  // container being up, like the issuer's interoperability job; it also needs the
  // walt.id issuer and Keycloak, because that is where the credential comes from.
  if (env.WALTID_VERIFIER_URL) {
    jobs.push({
      name: "VC Presentation — SD-JWT VC against walt.id (OID4VP interoperability)",
      script: "sd_jwt_vc_presentation_waltid.js",
      env: {
        WALTID_VERIFIER_URL: env.WALTID_VERIFIER_URL,
        WALTID_ISSUER_URL: env.WALTID_ISSUER_URL || "",
        KEYCLOAK_BASE_URL: env.KEYCLOAK_BASE_URL || "",
      },
    });
  }

  // jwt_vc_json against walt.id: the interoperability half of the two jobs above.
  // Both skip with instructions when walt.id offers no jwt_vc_json
  // configuration, which is the state until its container is restarted onto the
  // configuration in waltid/config/credential-issuer-metadata.conf.
  //
  // The presentation one has a second, deliberate skip: walt.id's own
  // jwt_vc_json profiles bind the holder with a SUBJECT DID where our mock uses
  // cnf.jwk, and a wallet cannot sign a Verifiable Presentation JWT for a key it
  // has never held. That is reported as an interoperability finding rather than
  // failed, because neither implementation is wrong.
  {
    jobs.push({
      name: "VC Issuance — jwt_vc_json against walt.id (OID4VCI interoperability)",
      script: "jwt_vc_json_issuance_waltid.js",
      env: {
        WALTID_ISSUER_URL: env.WALTID_ISSUER_URL,
        KEYCLOAK_BASE_URL: env.KEYCLOAK_BASE_URL || "",
      },
    });
  }

  {
    jobs.push({
      name: "VC Presentation — jwt_vc_json against walt.id (OID4VP interoperability)",
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
      name: "WS-Trust Operations History (attempted STS calls: version, operation, user, result)",
      script: "wstrust_operation_history.js",
      env: { WSTRUST_STS_URL: env.WSTRUST_STS_URL },
    });
  }

  jobs.push({
    name: "SAML Operations History (attempted IdP calls: binding, version, entity IDs, result)",
    script: "saml_operation_history.js",
    env: {},
  });

  jobs.push({
    name: "SAML Assertion Tool (compose 1.0/1.1/2.0, XML-DSIG sign + verify, XML-Enc round-trip)",
    script: "saml_tools.js",
    env: {},
  });
  
 // SAML 2.0 SP-initiated SSO across all three bindings: load IdP metadata, sign
  // the AuthnRequest (redirect = query-string sig; post = enveloped XML-DSIG;
  // artifact = redirect send + SOAP ArtifactResolve back-channel), log in at
  // Keycloak (which validates the request signature), and confirm the
  // ACS-captured SAMLResponse / assertion / NameID render on the response page.
  // The Artifact binding needs the server-side SOAP ArtifactResolve back-channel,
  // so it can't run on a backendless (static) deployment. remote-run-tests.sh sets
  // SAML_BACKEND_AVAILABLE=false for those targets; skip it there rather than fail.
  const samlBackendAvailable = env.SAML_BACKEND_AVAILABLE !== "false";
  for (const SAML_BINDING of ["redirect", "post", "artifact"]) {
    const job = {
      name: `SAML 2.0 SSO — HTTP-${SAML_BINDING === 'post' ? 'POST' : SAML_BINDING === 'artifact' ? 'Artifact' : 'Redirect'} binding`,
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
  // <saml:EncryptedAssertion>; the Response page decrypts it IN THE BROWSER with
  // the SP private key and renders the plaintext assertion.
  //
  // The decryption has never needed a backend — decryptAssertion() in
  // saml_response.js is node-forge in the page, the same XML-Enc engine the
  // WS-Trust and WS-Federation pages use, with no fetch and no Web Crypto. What
  // this job needs is somewhere for the IdP to POST the response: Keycloak's
  // encrypted client is provisioned saml.force.post.binding=true
  // (common/common.sh), so the response is POSTed whatever the AuthnRequest asks
  // for, and the Redirect-binding fallback the other SAML jobs use on a static
  // target is not available to it.
  //
  // That used to make this "unavailable on the static deployment". It no longer
  // is: infra/edge/saml_landing.js answers /samlacs at the CDN edge. So the gate
  // is whether a landing is actually deployed — remote-run-tests.sh probes for
  // one — not whether there is an api. Unset means "not probed" (the local and
  // containerized runs), where the api's ACS has always been there.
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
        (env.SAML_LANDING_URL || "<base>/samlacs") + " to receive the IdP's POST, and the encrypted " +
        "client forces the POST binding so the Redirect fallback cannot be used. On a static " +
        "deployment, apply the infrastructure (./infra/terraform-local.sh test apply) so the " +
        "Lambda@Edge landing exists, and build the site with samlEdgeLanding: true.";
    }
    jobs.push(encJob);
  }

  // SAML 2.0 Single Logout: log in via SSO (to establish the Keycloak session and
  // capture the NameID/SessionIndex), then send a signed LogoutRequest and confirm
  // the LogoutResponse renders with a Success status on the response page.
  jobs.push({
    name: "SAML 2.0 Single Logout (login → LogoutRequest → LogoutResponse Success)",
    script: "saml_logout.js",
    env: {
      SAML_METADATA_URL: env.SAML_METADATA_URL,
      // When set (remote-run-tests.sh), the metadata is uploaded from this local
      // file instead of fetched from the URL — see loadIdpMetadata().
      SAML_METADATA_FILE: env.SAML_METADATA_FILE,
      SAML_SP_ENTITY_ID: env.SAML_SP_ENTITY_ID,
      SAML_USER: env.SAML_USER,
    },
  });

  // WS-Federation Passive Requestor Profile SSO against the dedicated Keycloak
  // 8.0.1 + cloudtrust keycloak-wsfed side-car (the 26.x Keycloak has no WS-Fed
  // support). Gated on WSFED_METADATA_URL, which common.sh's configureKeycloakWsfed
  // exports only when the side-car is provisioned — so this SKIPS (not fails) on
  // runs without it (remote/live, or a static deployment).
  {
    const wsfedJob = {
      name: "WS-Federation Passive SSO + Sign-out (Call IdP → Keycloak login → wsfed_response → wsignout1.0)",
      script: "wsfed_sso.js",
      env: {
        WSFED_METADATA_URL: env.WSFED_METADATA_URL,
        WSFED_REALM: env.WSFED_REALM,
        WSFED_USER: env.WSFED_USER,
      },
    };
    if (!env.WSFED_METADATA_URL) {
      wsfedJob.skip = "WS-Federation side-car (Keycloak 8.0.1 + wsfed) not provisioned (WSFED_METADATA_URL unset).";
    } else if (env.WSFED_LANDING_AVAILABLE === "false") {
      // The other end of the round trip. The Passive Requestor Profile has ONE
      // way to return the token — the IdP auto-POSTs the wresult to wreply — and
      // no redirect alternative to fall back to the way SAML has. So the target
      // needs something at /wsfed that answers a POST.
      //
      // This used to be keyed on SAML_BACKEND_AVAILABLE, i.e. "static deployments
      // cannot do this at all". That was wrong: they can, with a Lambda@Edge on
      // that path (infra/edge/wsfed_landing.js), which is what the hosted sites
      // now run. What actually decides it is whether the landing is DEPLOYED —
      // the site bundle and the Terraform ship independently — so
      // remote-run-tests.sh probes the target with a real POST and sets this.
      // Unset (the containerized and local runs) means "not probed", and the job
      // runs against the api backend's landing as it always has.
      wsfedJob.skip = "the target has no WS-Federation landing at " +
        (env.WSFED_LANDING_URL || "<base>/wsfed") + " to receive the IdP's wresult POST " +
        "(the profile has no redirect binding). On a static deployment, apply the infrastructure " +
        "(./infra/terraform-local.sh test apply) so the Lambda@Edge landing exists, and build the " +
        "site with wsfedEdgeLanding: true.";
    }
    jobs.push(wsfedJob);
  }

  // WS-Trust 1.4 against the STS (the mock STS service, or a real Apache CXF STS
  // if WSTRUST_STS_URL points at one). Exercises all four operations — Issue,
  // Renew, Validate, Cancel — plus a signed Issue (WS-Security XML-DSIG). Each
  // job builds a SOAP RequestSecurityToken, sends it through the backend proxy
  // (POST /wstrust), and asserts the RSTR / issued token / status renders on the
  // response page. Renew/Validate/Cancel first Issue a token to act on.
  //
  // Skipped when no STS is reachable (WSTRUST_STS_URL unset) rather than failing.
  // Routing is exercised both ways: "back" sends through the API proxy
  // (POST /wstrust); "front" makes the browser call the STS directly. Issue runs
  // once per route; the other operations use backend routing.
  //
  // On a BACKEND-LESS target (the deployed static site: samlBackendAvailable
  // false) there is no /wstrust proxy — the page disables backend routing and
  // sends every request from the browser. So rewrite "back" to "front" there
  // (rather than letting the report claim backend routing it never used) and skip
  // the one job whose entire subject is backend routing. The live-site run
  // supplies a loopback STS the browser can reach; see remote-run-tests.sh.
  var wstrustStsUrl = env.WSTRUST_STS_URL || "";
  var wstrustSkip = "WS-Trust needs an STS (WSTRUST_STS_URL) — none reachable from this target.";
  var wstrustNoBackendSkip = "This target has no API proxy (POST /wstrust) — backend routing cannot be exercised; the frontend-routing jobs cover the exchange.";
  // Effective routing for a job that asks for the backend proxy.
  var wstrustRoute = function (route) {
    return (route === "back" && !samlBackendAvailable) ? "front" : route;
  };
  var wstrustJobs = [
    { op: "issue", sign: "false", route: "back", label: "Issue (backend routing)", backendOnly: true },
    { op: "issue", sign: "false", route: "front", label: "Issue (frontend routing)" },
    { op: "issue", sign: "true", route: "back", label: "Issue (signed, WS-Security XML-DSIG)" },
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

  // XML Signature & XML Encryption interop. A pure-Node test (no browser, no IdP)
  // that runs the WS-Trust workflow's in-browser crypto (client/src/xmldsig.js)
  // and validates its output against official libraries: xml-crypto verifies the
  // WS-Security signature; xml-encryption decrypts the XML-Encryption output.
  jobs.push({
    name: "XML Signature & Encryption interop (xml-crypto / xml-encryption)",
    script: "xmlsec_interop.js",
    env: {},
  });

  // WS-Trust message schema validation. A pure-Node test that builds the RST for
  // every scenario (each version × operation) with the real generator and
  // validates it against a schema derived from the official OASIS WS-Trust 1.3
  // XSD (libxmljs2/libxml2). Self-skips (exit 0) if libxmljs2 — an optional
  // native dependency — isn't installed on the platform.
  jobs.push({
    name: "WS-Trust message schema validation (RST vs OASIS-derived XSD)",
    script: "wstrust_schema_validate.js",
    env: {},
  });

  return jobs;
}

function slug(s) {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
}

function logPathFor(name, index) {
  return path.join(LOGS_DIR, `${String(index + 1).padStart(2, "0")}-${slug(name)}.log`);
}

function logHeader(name, script, startedAt) {
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
  return new Promise((resolve) => {
    const startedAt = new Date().toISOString();
    const startMs = Date.now();
    fs.mkdirSync(LOGS_DIR, { recursive: true });
    const logPath = logPathFor(job.name, index);
    const logStream = fs.createWriteStream(logPath);
    logStream.write(logHeader(job.name, job.script, startedAt));

    let output = "";
    const tee = (chunk) => {
      const s = chunk.toString();
      output += s;
      logStream.write(s); // capture
      process.stdout.write(s); // live echo
    };

    const finish = (code, codeLabel) => {
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
    };

    const child = spawn("node", [path.join(TESTS_DIR, job.script), "--url", BASE_URL], {
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

// Record a skipped job (a capability the target can't exercise, e.g. Artifact on
// a backendless deployment). Written to a log + returned as a result that is
// neither pass nor fail, so it doesn't count against the suite.
function makeSkipResult(job, index) {
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
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderHtml(results, generatedAt, demo) {
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
        ? `<br><a href="logs/${esc(path.basename(r.logFile))}"><code>${esc(r.logFile)}</code></a>`
        : "";
      return `
      <tr class="${cls}">
        <td><span class="badge ${cls}">${badge}</span></td>
        <td>${esc(r.name)}<br><code>${esc(r.script)}</code></td>
        <td class="num">${(r.durationMs / 1000).toFixed(1)}s</td>
        <td class="num">${esc(r.code)}</td>
        <td><details><summary>output</summary><pre>${log || "(no output)"}</pre></details>${logLink}</td>
      </tr>`;
    })
    .join("");

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
<p class="sub">Generated ${esc(generatedAt)} · base URL <code>${esc(BASE_URL)}</code></p>
${demo ? '<div class="demo"><strong>SAMPLE REPORT</strong> — generated with <code>--demo</code>. No tests were run; the data below is illustrative only.</div>' : ""}
<div class="cards">
  <div class="card"><div class="n">${total}</div><div>total</div></div>
  <div class="card ok"><div class="n">${passed}</div><div>passed</div></div>
  <div class="card bad"><div class="n">${failed}</div><div>failed</div></div>
  ${skipped ? `<div class="card"><div class="n">${skipped}</div><div>skipped</div></div>` : ""}
  <div class="card"><div class="n">${(totalMs / 1000).toFixed(1)}s</div><div>duration</div></div>
</div>
<table>
  <thead><tr><th>Result</th><th>Test</th><th>Time</th><th>Exit</th><th>Output</th></tr></thead>
  <tbody>${rows}</tbody>
</table>
</body></html>`;
}

function renderJUnit(results, generatedAt) {
  const total = results.length;
  const failures = results.filter((r) => !r.passed && !r.skipped).length;
  const skips = results.filter((r) => r.skipped).length;
  const totalSec = (results.reduce((a, r) => a + r.durationMs, 0) / 1000).toFixed(3);
  const cases = results
    .map((r) => {
      const time = (r.durationMs / 1000).toFixed(3);
      const sys = esc((r.output || "").trim());
      const body = r.skipped
        ? `<skipped message="${esc(r.reason || "skipped")}"/>`
        : r.passed
        ? ""
        : `<failure message="exit ${esc(r.code)}">Test exited with status ${esc(r.code)}</failure>`;
      return `    <testcase classname="selenium" name="${esc(r.name)}" time="${time}">${body}<system-out>${sys}</system-out></testcase>`;
    })
    .join("\n");
  return `<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="oauth2-oidc-debugger" tests="${total}" failures="${failures}" skipped="${skips}" time="${totalSec}" timestamp="${esc(generatedAt)}">
${cases}
  </testsuite>
</testsuites>
`;
}

function writeReports(results, demo) {
  const generatedAt = new Date().toISOString();
  fs.mkdirSync(RUN_DIR, { recursive: true });
  fs.writeFileSync(path.join(RUN_DIR, "report.html"), renderHtml(results, generatedAt, demo));
  fs.writeFileSync(path.join(RUN_DIR, "report.xml"), renderJUnit(results, generatedAt));
  updateLatestPointer();
}

// Best-effort convenience pointer to the most recent run. Prefers a symlink;
// falls back to a small text file where symlinks aren't permitted (e.g. Windows).
function updateLatestPointer() {
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
}

function demoResults() {
  const startedAt = new Date().toISOString();
  fs.mkdirSync(LOGS_DIR, { recursive: true });
  return buildJobs().map((j, i) => {
    const passed = i !== 2; // pretend one failed, for preview
    const output =
      (passed
        ? "Entering populateMetadata().\nFind oidc_discovery_endpoint.\n... (hundreds of lines in a real run) ...\nToken validated.\nTest completed successfully."
        : "Entering populateMetadata().\n... (hundreds of lines in a real run) ...\nAssertionError: expected token to contain claim 'aud'") + "\n";
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
        `\n===== RESULT: ${passed ? "PASS" : "FAIL"} (exit ${result.code}, ${(result.durationMs / 1000).toFixed(1)}s) =====\n`
    );
    return result;
  });
}

async function main() {
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
      const r = await runJob(job, i); // sequential: keep streamed output readable
      results.push(r);
      log.info(`----- ${r.passed ? "PASS" : "FAIL"} (${(r.durationMs / 1000).toFixed(1)}s) → ${r.logFile}`);
    }
  }

  writeReports(results, demo);

  const failed = results.filter((r) => !r.passed && !r.skipped).length;
  const skipped = results.filter((r) => r.skipped).length;
  const passed = results.length - failed - skipped;
  const rel = path.relative(process.cwd(), RUN_DIR);
  log.info(`Report written to ${rel}/report.html (and report.xml, logs/)`);
  log.info(`Latest run also at ${path.relative(process.cwd(), path.join(REPORT_DIR, "latest"))}`);
  log.info(`Summary: ${passed} passed, ${failed} failed, ${skipped} skipped, ${results.length} total`);

  // Don't fail the demo run; otherwise signal failures to the caller/CI.
  process.exit(demo ? 0 : failed > 0 ? 1 : 0);
}

main();
