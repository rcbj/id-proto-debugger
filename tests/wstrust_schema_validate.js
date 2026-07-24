// File: wstrust_schema_validate.js
//
// XSD schema validation of the WS-Trust RequestSecurityToken (RST) messages the
// debugger generates, for every tested scenario (each protocol version × each
// operation). Like xmlsec_interop.js it drives no browser — it builds the RST
// with the SAME generator the page uses (client/src/wstrust_msg.js) and validates
// it against a schema derived from the official OASIS WS-Trust 1.3 XSD (see
// tests/schemas/ws-trust-rst.template.xsd for why "derived": libxml2, the engine
// behind every Node XSD validator, cannot compile the official schema's WS-Security
// / WS-Policy imports).
//
// libxmljs2 (native libxml2 binding) is an OPTIONAL dependency: if it isn't
// installed (e.g. no prebuilt binary for the platform and no build toolchain),
// this test SKIPS with exit 0 rather than failing the suite. run-report spawns it
// with a --url argument, which it ignores.

const fs = require("fs");
const path = require("path");

function log(m) { console.log(m); }

// libxmljs2 is optional — skip cleanly if unavailable.
let lib;
try { lib = require("libxmljs2"); }
catch (e) {
  log("SKIP: libxmljs2 is not installed (optional native dependency) — cannot run XSD validation here.");
  log("      Install it (npm i libxmljs2) to enable WS-Trust message schema validation.");
  process.exit(0);
}

function loadFrom(candidates, what) {
  for (const p of candidates) { if (fs.existsSync(p)) return p; }
  throw new Error("could not locate " + what + " (looked in: " + candidates.join(", ") + ")");
}
const wm = require(loadFrom([
  path.join(__dirname, "wstrust_msg.js"),
  path.join(__dirname, "..", "client", "src", "wstrust_msg.js"),
], "client/src/wstrust_msg.js"));
const templatePath = loadFrom([
  path.join(__dirname, "schemas", "ws-trust-rst.template.xsd"),
  path.join(__dirname, "..", "tests", "schemas", "ws-trust-rst.template.xsd"),
], "ws-trust-rst.template.xsd");
const template = fs.readFileSync(templatePath, "utf8");

// Compile the derived schema once per distinct trust namespace.
const schemaCache = {};
function schemaForNs(ns) {
  if (!schemaCache[ns]) schemaCache[ns] = lib.parseXml(template.split("{{NS}}").join(ns));
  return schemaCache[ns];
}

let pass = 0, fail = 0;
function check(name, ok, detail) {
  if (ok) { pass++; log("  PASS  " + name); }
  else { fail++; log("  FAIL  " + name + (detail ? "  -> " + detail : "")); }
}

// A small SAML assertion to stand in as the Renew/Validate/Cancel target token.
const TARGET_TOKEN =
  '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_tok" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">' +
  '<saml:Issuer>urn:wstrust:mock:sts</saml:Issuer></saml:Assertion>';

function optsFor(version, op) {
  const v = wm.versionCfg(version);
  return {
    version: version,
    operation: op,
    tokenType: "saml2",
    // Mirror the page: Bearer is only offered for 1.3+, so use SymmetricKey below.
    keyType: v.bearer ? "bearer" : "symmetric",
    keySize: "256",
    appliesTo: "urn:wstrust:test:rp",
    lifetimeMinutes: "60",
    claims: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name\nhttp://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    // ActAs only for 1.4 (matches the UI gating).
    useActAs: v.actas,
    actAs: v.actas ? TARGET_TOKEN : "",
    targetToken: TARGET_TOKEN,
  };
}

function validate(rstXml, ns) {
  const doc = lib.parseXml(rstXml);
  let ok, detail = "";
  try { ok = doc.validate(schemaForNs(ns)); }
  catch (e) { return { ok: false, detail: "validate threw: " + e.message }; }
  if (!ok) detail = doc.validationErrors.map(e => e.message.trim()).join("; ");
  return { ok, detail };
}

function main() {
  const versions = ["1.0", "1.1", "1.2", "1.3", "1.4"];
  const ops = ["issue", "renew", "validate", "cancel"];

  log("== WS-Trust RST schema validation (derived from OASIS ws-trust-1.3.xsd, via libxmljs2/libxml2) ==");
  for (const version of versions) {
    const ns = wm.versionNs(version);
    for (const op of ops) {
      const rst = wm.buildRst(optsFor(version, op));
      const r = validate(rst, ns);
      check("WS-Trust " + version + " (" + ns.replace(/^https?:\/\//, "") + ") — " + op, r.ok, r.detail);
    }
  }

  // Negative control: a structurally invalid RST (KeySize is not an integer)
  // MUST be rejected — proves the schema is actually enforcing types. Use a
  // SymmetricKey issue so a <wst:KeySize> is present to tamper.
  const ns = wm.versionNs("1.3");
  const symOpts = optsFor("1.3", "issue"); symOpts.keyType = "symmetric";
  const goodIssue = wm.buildRst(symOpts);
  const badIssue = goodIssue.replace("<wst:KeySize>256</wst:KeySize>", "<wst:KeySize>not-an-int</wst:KeySize>");
  const tampered = badIssue !== goodIssue;
  const neg = validate(badIssue, ns);
  check("negative control: non-integer KeySize is REJECTED", tampered && neg.ok === false,
    tampered ? "schema accepted an invalid KeySize" : "tamper no-op (no KeySize present)");

  log("\n== SUMMARY: " + pass + " passed, " + fail + " failed ==");
  process.exit(fail ? 1 : 0);
}

main();
