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
// Validation runs on libxml2 either way, reached by whichever binding is usable:
//
//   1. libxmljs2 — the native Node binding. It is an OPTIONAL dependency and is
//      frequently unusable: there may be no prebuilt binary for the running ABI
//      and no build toolchain to compile one, or (the common case here) a binary
//      built for a different Node version, which fails to load with a
//      NODE_MODULE_VERSION mismatch.
//   2. the xmllint CLI — same libxml2, no native module and no ABI coupling.
//      Shipped by the libxml2-utils package, installed in tests/Dockerfile.
//
// Only when neither is available does this test SKIP with exit 0 rather than
// failing the suite. run-report spawns it with a --url argument, which it ignores.

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

function log(m) { console.log(m); }

// --- validation engine ------------------------------------------------------
// Both engines expose validate(xml, schemaXsd) -> { ok, detail }, caching the
// compiled/written schema per distinct schema text.
let engine = null;

let lib = null;
try {
  lib = require("libxmljs2");
} catch (e) {
  log("note: libxmljs2 unavailable (" + e.message.split("\n")[0].trim() + ")");
}

if (lib) {
  const compiled = {};
  engine = {
    name: "libxmljs2 (native libxml2 binding)",
    validate(xml, xsd) {
      if (!compiled[xsd]) compiled[xsd] = lib.parseXml(xsd);
      const doc = lib.parseXml(xml);
      let ok;
      try {
        ok = doc.validate(compiled[xsd]);
      } catch (e) {
        return { ok: false, detail: "validate threw: " + e.message };
      }
      return { ok, detail: ok ? "" : doc.validationErrors.map(e => e.message.trim()).join("; ") };
    },
  };
} else {
  const probe = spawnSync("xmllint", ["--version"], { encoding: "utf8" });
  if (!probe.error && probe.status === 0) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "wstrust-xsd-"));
    process.on("exit", () => {
      try {
        fs.rmSync(dir, { recursive: true, force: true });
      } catch (e) {
        // A leftover temp directory is not worth failing the run over.
      }
    });
    const xsdFiles = {};
    let n = 0;
    const docFile = path.join(dir, "message.xml");
    engine = {
      name: "xmllint CLI (libxml2 " + (probe.stderr || probe.stdout || "").split("\n")[0].replace(/^xmllint:\s*/, "").trim() + ")",
      validate(xml, xsd) {
        if (!xsdFiles[xsd]) {
          const p = path.join(dir, "schema-" + (++n) + ".xsd");
          fs.writeFileSync(p, xsd);
          xsdFiles[xsd] = p;
        }
        fs.writeFileSync(docFile, xml);
        const r = spawnSync("xmllint", ["--noout", "--schema", xsdFiles[xsd], docFile], { encoding: "utf8" });
        if (r.error) return { ok: false, detail: "xmllint failed to run: " + r.error.message };
        const ok = r.status === 0;
        // On success xmllint prints "<file> validates"; on failure, the errors.
        const detail = ok ? "" : (r.stderr || "").split("\n")
          .filter(l => l.trim() && !/fails to validate$/.test(l.trim()))
          .map(l => l.replace(docFile + ":", "line ").trim()).join("; ");
        return { ok, detail };
      },
    };
  }
}

if (!engine) {
  log("SKIP: no XSD validator available — libxmljs2 does not load and the xmllint CLI is not on PATH.");
  log("      Install either (npm i libxmljs2, or the libxml2-utils package) to enable WS-Trust message schema validation.");
  process.exit(0);
}

function loadFrom(candidates, what) {
  for (const p of candidates) { if (fs.existsSync(p)) return p; }
  throw new Error("could not locate " + what + " (looked in: " + candidates.join(", ") + ")");
}
// requireSharedModule keeps the tests' dependencies resolvable for a module
// loaded out of client/src (wstrust_msg.js logs through bunyan) — see
// module_paths.js.
const { requireSharedModule } = require("./module_paths.js");
const wm = requireSharedModule([
  path.join(__dirname, "wstrust_msg.js"),
  path.join(__dirname, "..", "client", "src", "wstrust_msg.js"),
], "client/src/wstrust_msg.js");
const templatePath = loadFrom([
  path.join(__dirname, "schemas", "ws-trust-rst.template.xsd"),
  path.join(__dirname, "..", "tests", "schemas", "ws-trust-rst.template.xsd"),
], "ws-trust-rst.template.xsd");
const template = fs.readFileSync(templatePath, "utf8");

// The derived schema, specialized per distinct trust namespace. The engine
// caches the compiled/written form keyed by this text.
const schemaCache = {};
function schemaForNs(ns) {
  if (!schemaCache[ns]) schemaCache[ns] = template.split("{{NS}}").join(ns);
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
  return engine.validate(rstXml, schemaForNs(ns));
}

function main() {
  const versions = ["1.0", "1.1", "1.2", "1.3", "1.4"];
  const ops = ["issue", "renew", "validate", "cancel"];

  log("== WS-Trust RST schema validation (derived from OASIS ws-trust-1.3.xsd) ==");
  log("   engine: " + engine.name);
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
