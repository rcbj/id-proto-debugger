// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: saml11_peers.js
//
// SAML 1.1 against the two identity providers that still speak it.
//
// The debugger is the service provider, and its request is
// Shibboleth's AuthnRequest profile exactly: providerId, shire, target
// and time, nothing else (#307; saml_message.saml11AuthnRequestParams).
// The identity provider answers with the profile bound to the shire,
// and returns the relay value as TARGET. This file holds that request
// to the specification and then, when a peer is configured, to the
// peer.
//
// Three parts, and the first one always runs:
//
//   1. The request builder, and a Browser/POST response in both
//      attribute shapes: Shibboleth's URI namespace, where
//      AttributeName is already the whole claim URI, and the older
//      split (namespace + local name) iya-sts still emits.
//   2. iya-sts, when a base is configured (STS_URL, WSTRUST_STS_URL,
//      STS_ADMIN_URL, or the origin of SAML11_METADATA_URL). With a
//      management token the relying party is registered and
//      Browser/POST is completed. Without one the request must at
//      least reach a sign-in or a refusal that echoes the relay
//      value, and nothing is provisioned.
//   3. A Shibboleth identity provider, when SHIBBOLETH_IDP_URL is
//      set (the base that contains /idp). Unset skips that half.
//      A configured peer that does not answer is a failure.
//
// Run from tests/:
//
//   SHIBBOLETH_IDP_URL=http://127.0.0.1:18080/idp \
//   WSTRUST_STS_URL=https://localhost:8081 \
//   CONFIG_FILE=./env/test.js node saml11_peers.js
//
// ---------------------------------------------------------------------------

const assert = require("assert");
const http = require("http");
const https = require("https");
const path = require("path");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "saml11_peers",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

const xmldom = require("@xmldom/xmldom");
global.DOMParser = xmldom.DOMParser;
global.XMLSerializer = xmldom.XMLSerializer;

const sm = paths.requireSharedModule(
  [path.join(__dirname, "saml_message.js"),
   path.join(__dirname, "..", "client", "src", "saml_message.js")],
  "client/src/saml_message.js");

const registry = require("./sts_applications.js");
const authn = require("./authn_signin.js");
const names = require("./random_username.js");

// Product-mode iya-sts checks this password. federation_admin.js
// signs in with the same one. ensurePerson sets it before the call.
const IYA_PASSWORD = "Qk7-signin-vault-42";
const SHIB_URI_NS = "urn:mace:shibboleth:1.0:attributeNamespace:uri";
const BEARER = "urn:oasis:names:tc:SAML:1.0:cm:bearer";

let checks = 0;

function check(what, fn) {
  log.debug("Entering check(). " + what);
  fn();
  checks++;
  log.info("  ok — " + what);
  log.debug("Leaving check().");
}

function queryOf(params) {
  log.debug("Entering queryOf().");
  const parts = [];
  for (let i = 0; i < params.length; i++) {
    parts.push(encodeURIComponent(params[i][0]) + "=" +
        encodeURIComponent(params[i][1]));
  }
  log.debug("Leaving queryOf().");
  return parts.join("&");
}

function CookieJar() {
  log.debug("Entering CookieJar().");
  this.map = {};
  log.debug("Leaving CookieJar().");
}

CookieJar.prototype.store = function (setCookies) {
  log.debug("Entering CookieJar.store().");
  const lines = setCookies || [];
  for (let i = 0; i < lines.length; i++) {
    const pair = String(lines[i]).split(";")[0];
    const at = pair.indexOf("=");
    if (at <= 0) {
      continue;
    }
    const name = pair.slice(0, at).trim();
    const value = pair.slice(at + 1).trim();
    if (!value) {
      delete this.map[name];
    } else {
      this.map[name] = value;
    }
  }
  log.debug("Leaving CookieJar.store().");
};

CookieJar.prototype.header = function () {
  log.debug("Entering CookieJar.header().");
  const self = this;
  const out = Object.keys(this.map).map(function (name) {
    return name + "=" + self.map[name];
  }).join("; ");
  log.debug("Leaving CookieJar.header().");
  return out;
};

function httpCall(method, urlString, options) {
  log.debug("Entering httpCall(). " + method);
  const opts = options || {};
  const url = new URL(urlString);
  const lib = url.protocol === "https:" ? https : http;
  const headers = Object.assign({}, opts.headers || {});
  if (opts.jar) {
    const cookie = opts.jar.header();
    if (cookie) {
      headers.Cookie = cookie;
    }
  }
  const body = opts.body || null;
  if (body) {
    headers["Content-Type"] = opts.contentType ||
        "application/x-www-form-urlencoded";
    headers["Content-Length"] = Buffer.byteLength(body);
  }
  const requestOptions = {
    protocol: url.protocol,
    hostname: url.hostname,
    port: url.port || (url.protocol === "https:" ? 443 : 80),
    path: url.pathname + url.search,
    method: method,
    headers: headers,
    rejectUnauthorized: false
  };
  return new Promise(function (resolve, reject) {
    const req = lib.request(requestOptions, function (res) {
      const chunks = [];
      res.on("data", function (chunk) {
        chunks.push(chunk);
      });
      res.on("end", function () {
        if (opts.jar) {
          opts.jar.store(res.headers["set-cookie"]);
        }
        log.debug("Leaving httpCall(). " + res.statusCode);
        resolve({
          status: res.statusCode,
          headers: res.headers,
          text: Buffer.concat(chunks).toString("utf8")
        });
      });
    });
    req.setTimeout(20000, function () {
      req.destroy(new Error("timed out calling " + urlString));
    });
    req.on("error", function (err) {
      log.debug("Leaving httpCall(). " + err.message);
      reject(err);
    });
    if (body) {
      req.write(body);
    }
    req.end();
  });
}

function decodeEntities(text) {
  log.debug("Entering decodeEntities().");
  const out = String(text || "")
    .replace(/&#x([0-9a-fA-F]+);/g, function (_, hex) {
      return String.fromCodePoint(parseInt(hex, 16));
    })
    .replace(/&#([0-9]+);/g, function (_, num) {
      return String.fromCodePoint(parseInt(num, 10));
    })
    .replace(/&quot;/g, "\"")
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
  log.debug("Leaving decodeEntities().");
  return out;
}

function attrsOf(tag) {
  log.debug("Entering attrsOf().");
  const out = {};
  const re = /([A-Za-z_:][\w:.-]*)\s*=\s*("([^"]*)"|'([^']*)')/g;
  let match;
  while ((match = re.exec(tag))) {
    const raw = match[3] !== undefined ? match[3] : match[4];
    out[match[1].toLowerCase()] = decodeEntities(raw);
  }
  log.debug("Leaving attrsOf().");
  return out;
}

function formsIn(html, pageUrl) {
  log.debug("Entering formsIn().");
  const out = [];
  const re = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let match;
  while ((match = re.exec(html))) {
    const formAttrs = attrsOf(match[1]);
    const controls = [];
    const tagRe = /<(input|button)\b([^>]*)>/gi;
    let tag;
    while ((tag = tagRe.exec(match[2]))) {
      const parsed = attrsOf(tag[2]);
      const kind = tag[1].toLowerCase();
      controls.push({
        tag: kind,
        name: parsed.name || "",
        type: (parsed.type || (kind === "button" ? "submit" : "text"))
            .toLowerCase(),
        value: parsed.value || "",
        checked: Object.prototype.hasOwnProperty.call(parsed, "checked")
      });
    }
    const areaRe = /<textarea\b([^>]*)>([\s\S]*?)<\/textarea>/gi;
    let area;
    while ((area = areaRe.exec(match[2]))) {
      const parsed = attrsOf(area[1]);
      controls.push({
        tag: "textarea",
        name: parsed.name || "",
        type: "textarea",
        value: decodeEntities(area[2] || ""),
        checked: false
      });
    }
    let action = pageUrl;
    try {
      action = new URL(formAttrs.action || pageUrl, pageUrl).toString();
    } catch (err) {
      log.debug("formsIn(): action refused: " + err.message);
    }
    out.push({
      action: action,
      method: (formAttrs.method || "get").toLowerCase(),
      controls: controls
    });
  }
  log.debug("Leaving formsIn(). " + out.length);
  return out;
}

function formWith(html, pageUrl, pred) {
  log.debug("Entering formWith().");
  const forms = formsIn(html, pageUrl);
  for (let i = 0; i < forms.length; i++) {
    if (pred(forms[i])) {
      log.debug("Leaving formWith(). Found.");
      return forms[i];
    }
  }
  log.debug("Leaving formWith(). None.");
  return null;
}

function headingOf(html) {
  log.debug("Entering headingOf().");
  const match = /<h1\b[^>]*>([\s\S]*?)<\/h1>/i.exec(html || "");
  if (!match) {
    log.debug("Leaving headingOf(). None.");
    return "";
  }
  const text = decodeEntities(match[1].replace(/<[^>]+>/g, " "))
    .replace(/\s+/g, " ").trim();
  log.debug("Leaving headingOf().");
  return text;
}

function fieldOf(form, name) {
  log.debug("Entering fieldOf(). " + name);
  const controls = form ? form.controls : [];
  for (let i = 0; i < controls.length; i++) {
    if (controls[i].name === name) {
      log.debug("Leaving fieldOf(). Found.");
      return controls[i].value;
    }
  }
  log.debug("Leaving fieldOf(). Absent.");
  return "";
}

function encodeControls(controls) {
  log.debug("Entering encodeControls().");
  const parts = [];
  for (let i = 0; i < controls.length; i++) {
    if (!controls[i].name) {
      continue;
    }
    parts.push(encodeURIComponent(controls[i].name) + "=" +
        encodeURIComponent(controls[i].value || ""));
  }
  log.debug("Leaving encodeControls().");
  return parts.join("&");
}

// A login form. Unchecked boxes stay out: a browser does not submit
// them, and Shibboleth's donotcache and consent-revoke boxes are
// unchecked. The proceed button is sent by its name.
function loginControls(form, creds) {
  log.debug("Entering loginControls().");
  const out = [];
  let sawUser = false;
  let sawPass = false;
  let sawProceed = false;
  for (let i = 0; i < form.controls.length; i++) {
    const control = form.controls[i];
    const type = control.type;
    if ((type === "checkbox" || type === "radio") && !control.checked) {
      continue;
    }
    if (type === "submit" || type === "button" || type === "image") {
      if (control.name !== "_eventId_proceed") {
        continue;
      }
      sawProceed = true;
    }
    const copy = { name: control.name, value: control.value };
    if (control.name === "j_username" || control.name === "username") {
      copy.value = creds.user;
      sawUser = true;
    }
    if (type === "password" || control.name === "j_password" ||
        control.name === "password") {
      copy.value = creds.password;
      sawPass = true;
    }
    if (copy.name) {
      out.push(copy);
    }
  }
  if (!sawUser) {
    out.push({ name: "j_username", value: creds.user });
  }
  if (!sawPass) {
    out.push({ name: "j_password", value: creds.password });
  }
  if (!sawProceed) {
    out.push({ name: "_eventId_proceed", value: "1" });
  }
  log.debug("Leaving loginControls(). " + out.length);
  return out;
}

function proceedControls(form) {
  log.debug("Entering proceedControls().");
  const out = [];
  let sawProceed = false;
  for (let i = 0; i < form.controls.length; i++) {
    const control = form.controls[i];
    const type = control.type;
    if ((type === "checkbox" || type === "radio") && !control.checked) {
      continue;
    }
    if (type === "submit" || type === "button" || type === "image" ||
        type === "password") {
      if (control.name === "_eventId_proceed") {
        sawProceed = true;
        out.push({ name: control.name, value: control.value || "1" });
      }
      continue;
    }
    if (control.name) {
      out.push({ name: control.name, value: control.value });
    }
  }
  if (!sawProceed) {
    out.push({ name: "_eventId_proceed", value: "1" });
  }
  log.debug("Leaving proceedControls(). " + out.length);
  return out;
}

function pageHasPassword(html, pageUrl) {
  log.debug("Entering pageHasPassword().");
  const form = formWith(html, pageUrl, function (one) {
    return one.controls.some(function (control) {
      return control.type === "password";
    });
  });
  log.debug("Leaving pageHasPassword(). " + !!form);
  return form;
}

function pageHasProceed(html, pageUrl) {
  log.debug("Entering pageHasProceed().");
  const form = formWith(html, pageUrl, function (one) {
    return one.controls.some(function (control) {
      return control.name === "_eventId_proceed";
    });
  });
  log.debug("Leaving pageHasProceed(). " + !!form);
  return form;
}

// Follow redirects and submit the Shibboleth login (and a later
// proceed screen) until the Browser/POST form appears. creds null
// means stop at a login screen instead of signing in. An iya-sts
// sign-in screen is not an HTML form; the caller finishes that one.
async function walk(start, jar, creds) {
  log.debug("Entering walk().");
  let url = start;
  let method = "GET";
  let body = null;
  for (let hop = 0; hop < 16; hop++) {
    log.info("  " + method + " " + url);
    const res = await httpCall(method, url, { jar: jar, body: body });
    const location = res.headers.location;
    if (res.status >= 300 && res.status < 400 && location) {
      url = new URL(location, url).toString();
      method = "GET";
      body = null;
      continue;
    }
    const html = res.text || "";
    const samlForm = formWith(html, url, function (one) {
      return one.controls.some(function (control) {
        return control.name === "SAMLResponse";
      });
    });
    if (samlForm) {
      log.debug("Leaving walk(). SAMLResponse.");
      return { kind: "saml", form: samlForm, status: res.status,
               url: url, html: html };
    }
    if (/\/authn\/login(?:\?|$)/.test(url)) {
      log.debug("Leaving walk(). iya-sts sign-in.");
      return { kind: "iya-login", status: res.status, url: url,
               html: html };
    }
    const login = pageHasPassword(html, url);
    if (login) {
      if (!creds) {
        log.debug("Leaving walk(). Login, not submitted.");
        return { kind: "login", status: res.status, url: url, html: html };
      }
      url = login.action;
      method = (login.method === "get") ? "GET" : "POST";
      body = encodeControls(loginControls(login, creds));
      continue;
    }
    const proceed = pageHasProceed(html, url);
    if (proceed && creds) {
      url = proceed.action;
      method = (proceed.method === "get") ? "GET" : "POST";
      body = encodeControls(proceedControls(proceed));
      continue;
    }
    log.debug("Leaving walk(). Stopped at " + res.status);
    return { kind: "stop", status: res.status, url: url, html: html };
  }
  log.debug("Leaving walk(). Too many hops.");
  throw new Error("SAML 1.1 walk exceeded 16 hops from " + start);
}

function snippet(html) {
  log.debug("Entering snippet().");
  const text = String(html || "").replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ").trim().slice(0, 400);
  log.debug("Leaving snippet().");
  return text;
}

function rowValue(rows, key) {
  log.debug("Entering rowValue(). " + key);
  const list = rows || [];
  for (let i = 0; i < list.length; i++) {
    if (list[i].key === key) {
      log.debug("Leaving rowValue(). Found.");
      return list[i].value;
    }
  }
  log.debug("Leaving rowValue(). Absent.");
  return "";
}

// What saml-profiles-1.1 section 4.2 requires of a Browser/POST
// response the service provider can read: a 1.1 Response, a QName
// success, Recipient, an AssertionID, bearer confirmation, and an
// AudienceRestrictionCondition for this relying party. The profile
// signs the Response (saml-tech-overview-1.1 section 4.2.1). An
// assertion signature is a different choice and is checked only when
// the fixture asks for it.
function assertBrowserPost(summary, expect) {
  log.debug("Entering assertBrowserPost().");
  assert.ok(!summary.error, summary.error || "response was not XML");
  assert.strictEqual(summary.messageType, "Response");
  assert.strictEqual(summary.version, "1.1");
  assert.strictEqual(summary.saml1, true);
  assert.ok(summary.status && summary.status.success,
      "status was " + (summary.status && summary.status.top));
  assert.ok(String(summary.status.top).indexOf(
      "urn:oasis:names:tc:SAML:2.0") < 0,
      "SAML 1.1 status is a QName, got " + summary.status.top);
  assert.strictEqual(summary.status.short, "Success");
  if (expect.recipient) {
    assert.strictEqual(rowValue(summary.rows, "Recipient"),
        expect.recipient);
  }
  const assertion = summary.assertions && summary.assertions[0];
  assert.ok(assertion && assertion.summary, "no assertion");
  const one = assertion.summary;
  assert.ok(one.id, "AssertionID was empty");
  assert.strictEqual(one.saml1, true);
  const audiences = [];
  const entries = (one.conditions && one.conditions.entries) || [];
  for (let i = 0; i < entries.length; i++) {
    if (entries[i].localName === "AudienceRestrictionCondition") {
      audiences.push.apply(audiences, entries[i].values);
    }
  }
  assert.ok(audiences.indexOf(expect.audience) >= 0,
      "audience " + audiences.join(", "));
  const methods = (one.confirmations || []).map(function (row) {
    return row.method;
  });
  assert.ok(methods.indexOf(BEARER) >= 0,
      "confirmation " + methods.join(", "));
  if (expect.signed === "response") {
    assert.ok(summary.signature,
        "Browser/POST response was not signed");
    assert.ok(summary.signature.signatureMethod,
        "response signature had no SignatureMethod");
    const responseId = rowValue(summary.rows, "ID");
    assert.ok(responseId, "ResponseID was empty");
    assert.strictEqual(summary.signature.reference, "#" + responseId,
        "the response signature did not reference ResponseID");
  } else if (expect.signed) {
    assert.ok(one.signature, "Browser/POST assertion was not signed");
  }
  if (expect.attribute) {
    const found = (one.attributes || []).filter(function (attr) {
      return attr.name === expect.attribute.name;
    })[0];
    assert.ok(found, "no attribute named " + expect.attribute.name +
        " among " + (one.attributes || []).map(function (attr) {
          return attr.name;
        }).join(", "));
    assert.strictEqual(found.name, expect.attribute.name);
    if (expect.attribute.namespace) {
      assert.strictEqual(found.namespace, expect.attribute.namespace);
    }
    if (expect.attribute.value) {
      assert.ok(found.values.indexOf(expect.attribute.value) >= 0,
          found.values.join(", "));
    }
  }
  log.debug("Leaving assertBrowserPost().");
}

function responseXml(form) {
  log.debug("Entering responseXml().");
  const encoded = fieldOf(form, "SAMLResponse");
  assert.ok(encoded, "the Browser/POST form had no SAMLResponse");
  const xml = Buffer.from(encoded, "base64").toString("utf8");
  log.debug("Leaving responseXml().");
  return xml;
}

const NS = 'xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" ' +
    'xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"';

function responseFixture(attribute) {
  log.debug("Entering responseFixture().");
  const xml = '<samlp:Response ' + NS + ' MajorVersion="1" ' +
      'MinorVersion="1" ResponseID="_r" ' +
      'IssueInstant="2026-01-01T00:00:00Z" ' +
      'Recipient="https://debugger.example.test/acs">' +
    '<samlp:Status><samlp:StatusCode Value="samlp:Success"/>' +
    '</samlp:Status>' +
    '<saml:Assertion AssertionID="_a" MajorVersion="1" ' +
        'MinorVersion="1" Issuer="https://idp.example.test/saml11" ' +
        'IssueInstant="2026-01-01T00:00:00Z">' +
      '<saml:Conditions>' +
        '<saml:AudienceRestrictionCondition>' +
          '<saml:Audience>https://debugger.example.test/saml11' +
          '</saml:Audience>' +
        '</saml:AudienceRestrictionCondition>' +
      '</saml:Conditions>' +
      '<saml:AuthenticationStatement ' +
          'AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password" ' +
          'AuthenticationInstant="2026-01-01T00:00:00Z">' +
        '<saml:Subject>' +
          '<saml:NameIdentifier>jdoe</saml:NameIdentifier>' +
          '<saml:SubjectConfirmation>' +
            '<saml:ConfirmationMethod>' + BEARER +
            '</saml:ConfirmationMethod>' +
          '</saml:SubjectConfirmation>' +
        '</saml:Subject>' +
      '</saml:AuthenticationStatement>' +
      '<saml:AttributeStatement>' +
        '<saml:Attribute ' + attribute + '>' +
          '<saml:AttributeValue>jdoe@example.org</saml:AttributeValue>' +
        '</saml:Attribute>' +
      '</saml:AttributeStatement>' +
      '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">' +
        '<ds:SignedInfo>' +
          '<ds:SignatureMethod Algorithm=' +
              '"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>' +
        '</ds:SignedInfo>' +
      '</ds:Signature>' +
    '</saml:Assertion></samlp:Response>';
  log.debug("Leaving responseFixture().");
  return xml;
}

function fixtureHalf() {
  log.debug("Entering fixtureHalf().");
  check("the request is Shibboleth's AuthnRequest profile exactly",
      function () {
    const params = sm.saml11AuthnRequestParams({
      target: "https://sp.example.test/home",
      shire: "https://sp.example.test/acs",
      providerId: "https://sp.example.test/saml11",
      time: "1700000000"
    });
    assert.deepStrictEqual(params.map(function (pair) {
      return pair[0];
    }), ["providerId", "shire", "target", "time"],
      "providerId, shire, target and time, and no TARGET, profile or " +
      "format, which no specification defines on the request");
    assert.strictEqual(params[2][1], "https://sp.example.test/home");
  });

  check("a Shibboleth-shaped Browser/POST response is SAML 1.1",
      function () {
    const summary = sm.summarizeResponse(responseFixture(
        'AttributeName="urn:mace:dir:attribute-def:mail" ' +
        'AttributeNamespace="' + SHIB_URI_NS + '"'));
    assertBrowserPost(summary, {
      audience: "https://debugger.example.test/saml11",
      recipient: "https://debugger.example.test/acs",
      signed: true,
      attribute: {
        name: "urn:mace:dir:attribute-def:mail",
        namespace: SHIB_URI_NS,
        value: "jdoe@example.org"
      }
    });
    const mail = summary.assertions[0].summary.attributes[0];
    assert.ok(mail.name.indexOf(SHIB_URI_NS) < 0,
        "the marker namespace was joined onto the claim URI");
  });

  check("an older split attribute name still joins", function () {
    const summary = sm.summarizeResponse(responseFixture(
        'AttributeName="mail" ' +
        'AttributeNamespace="urn:mace:dir:attribute-def"'));
    const mail = summary.assertions[0].summary.attributes[0];
    assert.strictEqual(mail.name, "urn:mace:dir:attribute-def/mail");
    assert.strictEqual(mail.rawName, "mail");
    assert.strictEqual(summary.status.short, "Success");
  });
  log.debug("Leaving fixtureHalf().");
}

function iyaBase() {
  log.debug("Entering iyaBase().");
  let base = registry.stsBaseFromEnv();
  if (!base && process.env.SAML11_METADATA_URL) {
    base = registry.baseOf(process.env.SAML11_METADATA_URL);
  }
  if (!base && process.env.SAML11_STS_URL) {
    base = registry.baseOf(process.env.SAML11_STS_URL);
  }
  log.debug("Leaving iyaBase(). " + (base || "unset"));
  return base || "";
}

function refusalShowsTarget(landed, relay) {
  log.debug("Entering refusalShowsTarget().");
  const html = landed.html || "";
  const ok = landed.status === 403 && html.indexOf(relay) >= 0 &&
      html.indexOf("TARGET") >= 0;
  log.debug("Leaving refusalShowsTarget(). " + ok);
  return ok;
}

async function probeSpelling(base, params, relay) {
  log.debug("Entering probeSpelling().");
  const url = base.replace(/\/$/, "") + "/saml11/sso?" + queryOf(params);
  const landed = await walk(url, new CookieJar(), null);
  const accepted = refusalShowsTarget(landed, relay) ||
      landed.kind === "iya-login" || landed.kind === "saml" ||
      landed.kind === "login";
  assert.ok(accepted,
      "iya-sts did not accept the relay state at " + landed.url +
      " (" + landed.status + "): " + headingOf(landed.html) + " " +
      snippet(landed.html));
  log.debug("Leaving probeSpelling().");
}

async function iyaRoundTrip(base) {
  log.debug("Entering iyaRoundTrip().");
  const user = names.usernameFor("saml11-peers");
  const sp = "https://suite.example.test/saml11/" + user;
  const acs = "https://suite.example.test/acs/" + user;
  const relay = "https://suite.example.test/home/" + user;
  await registry.provision(base, {
    identifier: sp,
    name: "SAML 1.1 peer test",
    protocols: ["saml11"],
    fields: {
      samlEntityId: [sp],
      samlAssertionConsumerService: [acs]
    },
    why: "the relying party the SAML 1.1 peer test is about to present"
  });
  await registry.ensurePerson(base, user, IYA_PASSWORD);
  const params = sm.saml11AuthnRequestParams({
    target: relay, shire: acs, providerId: sp
  });
  const url = base.replace(/\/$/, "") + "/saml11/sso?" + queryOf(params);
  const jar = new CookieJar();
  let landed = await walk(url, jar, null);
  if (landed.kind === "iya-login") {
    const signed = await authn.submit(base, landed.url, {
      action: "login", username: user, password: IYA_PASSWORD
    }, { cookie: jar.header() });
    jar.store(signed.setCookies || []);
    assert.strictEqual(signed.next, "redirect",
        "iya-sts sign-in did not continue: " +
        JSON.stringify(signed.errors || signed.json || signed.next));
    landed = await walk(signed.location, jar, null);
  }
  assert.strictEqual(landed.kind, "saml",
      "iya-sts did not return a Browser/POST form (" + landed.kind +
      " " + landed.status + "): " + headingOf(landed.html) + " " +
      snippet(landed.html));
  assert.strictEqual(fieldOf(landed.form, "TARGET"), relay,
      "the response must echo TARGET, the name the profile defines");
  const summary = sm.summarizeResponse(responseXml(landed.form));
  assertBrowserPost(summary, { audience: sp, recipient: acs });
  log.info("iya-sts Browser/POST completed for " + sp);
  log.debug("Leaving iyaRoundTrip().");
}

async function iyaHalf() {
  log.debug("Entering iyaHalf().");
  const base = iyaBase();
  if (!base) {
    log.info("iya-sts: no base configured. The live half is skipped.");
    log.debug("Leaving iyaHalf(). Skipped.");
    return;
  }
  let admin;
  try {
    admin = await httpCall("GET", base + "/admin-api/config", {
      headers: { Accept: "application/json" }
    });
  } catch (err) {
    log.debug("Leaving iyaHalf(). Unreachable.");
    throw new Error("iya-sts at " + base + " did not answer: " +
        err.message);
  }
  const relay = "https://debugger.example.test/home";
  const acs = "https://debugger.example.test/acs";
  const sp = "https://debugger.example.test/saml11-spell";
  // The request exactly as the page builds it: iya-sts must take it,
  // reaching a sign-in, or a refusal that echoes the relay value.
  const pageShaped = sm.saml11AuthnRequestParams({
    target: relay, shire: acs, providerId: sp, time: "1700000000"
  });
  await probeSpelling(base, pageShaped, relay);
  if (admin.status === 200) {
    await iyaRoundTrip(base);
  } else {
    log.info("iya-sts management API answered " + admin.status +
        ". The signed-in Browser/POST needs the management token. " +
        "The request reached iya-sts and the relay value came back. " +
        "Nothing was provisioned.");
  }
  log.debug("Leaving iyaHalf().");
}

async function shibbolethHalf() {
  log.debug("Entering shibbolethHalf().");
  const base = process.env.SHIBBOLETH_IDP_URL || "";
  if (!base) {
    log.info("Shibboleth: SHIBBOLETH_IDP_URL is unset. That half is " +
        "skipped.");
    log.debug("Leaving shibbolethHalf(). Skipped.");
    return;
  }
  const user = process.env.SHIBBOLETH_IDP_USER || "jdoe";
  const password = process.env.SHIBBOLETH_IDP_PASSWORD ||
      "saml11-shibboleth";
  const sp = process.env.SHIBBOLETH_SP_ENTITY_ID ||
      "https://debugger.example.test/saml11";
  const acs = process.env.SHIBBOLETH_ACS_URL ||
      "https://debugger.example.test/acs";
  const relay = "https://debugger.example.test/home";
  // The request exactly as the page builds it.
  const params = sm.saml11AuthnRequestParams({
    target: relay, shire: acs, providerId: sp
  });
  const root = base.replace(/\/$/, "");
  const url = root + "/profile/Shibboleth/SSO?" + queryOf(params);
  let landed;
  try {
    landed = await walk(url, new CookieJar(),
                        { user: user, password: password });
  } catch (err) {
    log.debug("Leaving shibbolethHalf(). Unreachable.");
    throw new Error("Shibboleth at " + base + " did not answer: " +
        err.message);
  }
  assert.strictEqual(landed.kind, "saml",
      "Shibboleth did not return a Browser/POST form (" + landed.kind +
      " " + landed.status + " " + landed.url + "): " +
      headingOf(landed.html) + " " + snippet(landed.html));
  assert.strictEqual(fieldOf(landed.form, "TARGET"), relay,
      "Browser/POST echoes the relay state as TARGET");
  const summary = sm.summarizeResponse(responseXml(landed.form));
  // Shibboleth.SSO signs the Response and, once
  // includeAttributeStatement is on, releases mail and uid under the
  // URI attribute namespace.
  assertBrowserPost(summary, {
    audience: sp,
    recipient: acs,
    signed: "response",
    attribute: {
      name: "urn:mace:dir:attribute-def:mail",
      namespace: SHIB_URI_NS,
      value: user + "@example.org"
    }
  });
  const uid = summary.assertions[0].summary.attributes.filter(
      function (attr) {
        return attr.rawName === "urn:mace:dir:attribute-def:uid" ||
            attr.rawName === "uid" || attr.name.indexOf("uid") >= 0;
      })[0];
  assert.ok(uid, "uid was not released");
  assert.ok(uid.values.indexOf(user) >= 0, uid.values.join(", "));
  log.info("Shibboleth Browser/POST completed for " + sp);
  log.debug("Leaving shibbolethHalf().");
}

async function test() {
  log.debug("Entering test().");
  fixtureHalf();
  assert.ok(checks >= 3, "the fixture half ran " + checks + " checks");
  await iyaHalf();
  await shibbolethHalf();
  log.info(checks + " fixture checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("saml11_peers")
  .description("SAML 1.1 against Shibboleth and iya-sts. The fixture " +
      "half always runs. SHIBBOLETH_IDP_URL and an iya-sts base each " +
      "enable a live half.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test drives the peers itself)"))
  .parse(process.argv);

test().catch(function (err) {
  log.error(err.stack || err.message);
  process.exit(1);
});
