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
  // <saml:EncryptedAssertion>; the Response page decrypts it in-browser with the
  // SP private key and renders the plaintext assertion. Needs the API ACS
  // (POST binding), so it's skipped on a backend-less (static) deployment.
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
    if (!samlBackendAvailable) {
      encJob.skip = "EncryptedAssertion decryption uses the POST binding + API ACS; unavailable on the static deployment.";
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

  // WS-Trust 1.4 against the STS (the mock STS service, or a real Apache CXF STS
  // if WSTRUST_STS_URL points at one). Exercises all four operations — Issue,
  // Renew, Validate, Cancel — plus a signed Issue (WS-Security XML-DSIG). Each
  // job builds a SOAP RequestSecurityToken, sends it through the backend proxy
  // (POST /wstrust), and asserts the RSTR / issued token / status renders on the
  // response page. Renew/Validate/Cancel first Issue a token to act on.
  //
  // Skipped when no STS is reachable (WSTRUST_STS_URL unset) — e.g. the deployed
  // static site, which has no STS and no backend proxy — rather than failing.
  // Routing is exercised both ways: "back" sends through the API proxy
  // (POST /wstrust); "front" makes the browser call the STS directly. Issue runs
  // once per route; the other operations use backend routing.
  var wstrustStsUrl = env.WSTRUST_STS_URL || "";
  var wstrustJobs = [
    { op: "issue", sign: "false", route: "back", label: "Issue (backend routing)" },
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
        WSTRUST_ROUTE: wj.route,
      },
    };
    if (!wstrustStsUrl) {
      job.skip = "WS-Trust needs an STS (WSTRUST_STS_URL) — unavailable on this target (e.g. the backend-less static deployment).";
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
      WSTRUST_ROUTE: "back",
      WSTRUST_ENCRYPT: "true",
    },
  };
  if (!wstrustStsUrl) {
    encJob.skip = "WS-Trust needs an STS (WSTRUST_STS_URL) — unavailable on this target (e.g. the backend-less static deployment).";
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
        WSTRUST_ROUTE: "back",
        WSTRUST_VERSION: wv,
      },
    };
    if (!wstrustStsUrl) {
      job.skip = "WS-Trust needs an STS (WSTRUST_STS_URL) — unavailable on this target (e.g. the backend-less static deployment).";
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
    console.log("Writing SAMPLE report (--demo); no tests executed.");
  } else {
    results = [];
    const jobs = buildJobs();
    console.log(`Running ${jobs.length} test(s) against ${BASE_URL}\n`);
    for (const [i, job] of jobs.entries()) {
      if (job.skip) {
        console.log(`\n===== [${i + 1}/${jobs.length}] ${job.name} — SKIPPED =====`);
        console.log(`----- SKIP: ${job.skip}`);
        results.push(makeSkipResult(job, i));
        continue;
      }
      console.log(`\n===== [${i + 1}/${jobs.length}] ${job.name} =====`);
      const r = await runJob(job, i); // sequential: keep streamed output readable
      results.push(r);
      console.log(`----- ${r.passed ? "PASS" : "FAIL"} (${(r.durationMs / 1000).toFixed(1)}s) → ${r.logFile}`);
    }
  }

  writeReports(results, demo);

  const failed = results.filter((r) => !r.passed && !r.skipped).length;
  const skipped = results.filter((r) => r.skipped).length;
  const passed = results.length - failed - skipped;
  const rel = path.relative(process.cwd(), RUN_DIR);
  console.log(`\nReport written to ${rel}/report.html (and report.xml, logs/)`);
  console.log(`Latest run also at ${path.relative(process.cwd(), path.join(REPORT_DIR, "latest"))}`);
  console.log(`Summary: ${passed} passed, ${failed} failed, ${skipped} skipped, ${results.length} total`);

  // Don't fail the demo run; otherwise signal failures to the caller/CI.
  process.exit(demo ? 0 : failed > 0 ? 1 : 0);
}

main();
