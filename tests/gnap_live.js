// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: gnap_live.js
//
// ---------------------------------------------------------------------------
// THIS IS A HELPER AND NOT A JOB. The GNAP jobs that talk to iya-sts
// (gnap_protocol.js, api_gnap.js, gnap_page.js) share what is about
// iya-sts rather than about the protocol:
//
//  * the name iya-sts gives the application it creates for an unseen
//    key in development mode: `gnap-` and the key's identity, which is
//    `jkt:` and the RFC 7638 thumbprint for a JWK and `x5t:` and the
//    SHA-256 of the DER for a certificate, with the colon made a dash;
//  * declaring `ssf.read` on that entry through /admin-api, which is
//    what an administrator must do before iya-sts grants an access
//    token to its Shared Signals transmitter (STS-GNAP-0719), and
//    forgetting the entry afterwards;
//  * a self-signed client certificate for the mtls proof, made with the
//    openssl binary the tests image already carries;
//  * the resource owner's half of an interaction: sign in at iya-sts
//    and press Allow, in a browser the caller owns. This file never
//    builds or quits a driver.
//
// /admin-api calls go through fetch(), so tools/attach-admin-token.js,
// which run-report.js preloads into every job, adds the bearer token
// when the run minted one.
// ---------------------------------------------------------------------------
"use strict";

const assert = require("assert");
const childProcess = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "gnap_live",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});

function jwkThumbprint(publicJwk) {
  log.debug("Entering jwkThumbprint().");
  var members;
  if (publicJwk.kty === "OKP") {
    members = { crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x };
  } else if (publicJwk.kty === "RSA") {
    members = { e: publicJwk.e, kty: publicJwk.kty, n: publicJwk.n };
  } else {
    members = { crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x,
      y: publicJwk.y };
  }
  var out = crypto.createHash("sha256")
    .update(JSON.stringify(members)).digest("base64url");
  log.debug("Leaving jwkThumbprint().");
  return out;
}

function certificateThumbprint(certificatePem) {
  log.debug("Entering certificateThumbprint().");
  var der = new crypto.X509Certificate(certificatePem).raw;
  var out = crypto.createHash("sha256").update(der).digest("base64url");
  log.debug("Leaving certificateThumbprint().");
  return out;
}

// The application iya-sts creates in development mode for a key it
// has not seen. `record` is a gnap_client.js key record.
function applicationFor(record) {
  log.debug("Entering applicationFor().");
  var name = record.certificatePem
    ? "gnap-x5t-" + certificateThumbprint(record.certificatePem)
    : "gnap-jkt-" + jwkThumbprint(record.publicJwk);
  log.debug("Leaving applicationFor(). " + name);
  return name;
}

async function adminPost(base, route, body) {
  log.debug("Entering adminPost(). " + route);
  var response = await fetch(base + "/admin-api" + route, {
    method: "POST",
    headers: { "Content-Type": "application/json",
      Accept: "application/json" },
    body: JSON.stringify(body)
  });
  var text = await response.text();
  var json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    json = null;
  }
  log.debug("Leaving adminPost(). HTTP " + response.status);
  return { status: response.status, text: text, json: json };
}

// What an administrator does before iya-sts will grant `ssf.read` to
// this client: declare the scope on its application entry.
async function declareSsfRead(base, application) {
  log.debug("Entering declareSsfRead(). " + application);
  var added = await adminPost(base, "/applications/add", {
    application: application,
    attribute: "oauthAllowedScope",
    value: "ssf.read"
  });
  assert.ok(added.status === 200 && added.json && added.json.ok,
    "declaring ssf.read on " + application + " through /admin-api was " +
    "refused: HTTP " + added.status + " " + added.text.slice(0, 500));
  log.info("Declared ssf.read on " + application + ".");
  log.debug("Leaving declareSsfRead().");
}

async function forgetApplication(base, application) {
  log.debug("Entering forgetApplication(). " + application);
  var gone = await adminPost(base, "/applications/forget",
    { application: application });
  log.info("Forgot " + application + ": HTTP " + gone.status + ".");
  log.debug("Leaving forgetApplication().");
  return gone.status;
}

// A self-signed P-256 certificate and its key, for the mtls proof.
// iya-sts in development mode pins the certificate the key names
// (RFC 9635 section 7.3.2), so no authority is involved.
function makeClientCertificate(commonName) {
  log.debug("Entering makeClientCertificate().");
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "gnap-mtls-"));
  var keyFile = path.join(dir, "client.key");
  var certFile = path.join(dir, "client.crt");
  try {
    childProcess.execFileSync("openssl", ["req", "-x509", "-newkey", "ec",
      "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
      "-keyout", keyFile, "-out", certFile, "-days", "2",
      "-subj", "/CN=" + (commonName || "gnap-debugger-mtls")],
      { stdio: ["ignore", "ignore", "pipe"] });
    var out = {
      certificatePem: fs.readFileSync(certFile, "utf8"),
      keyPem: fs.readFileSync(keyFile, "utf8")
    };
    log.debug("Leaving makeClientCertificate().");
    return out;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// The resource owner's half of RFC 9635 section 4.1.1: open the
// redirect, sign in at iya-sts (development mode checks no password),
// press Allow, and wait for the browser to be sent to the finish URI.
// Answers that URL. `finishPrefix` is the start of the finish URI.
async function approveInBrowser(driver, webdriver, redirectUrl,
    finishPrefix, user, waitMs) {
  log.debug("Entering approveInBrowser().");
  const By = webdriver.By;
  const until = webdriver.until;
  const wait = waitMs || 20000;
  await driver.get(redirectUrl);
  await driver.wait(async function () {
    const here = await driver.getCurrentUrl();
    if (here.indexOf("/gnap/approve") >= 0) {
      return true;
    }
    const boxes = await driver.findElements(By.id("username"));
    return boxes.length > 0;
  }, wait, "neither the sign-in screen nor the approval page appeared " +
    "after opening " + redirectUrl);
  if ((await driver.getCurrentUrl()).indexOf("/gnap/approve") < 0) {
    const username = await driver.findElement(By.id("username"));
    await driver.wait(until.elementIsVisible(username), wait);
    await username.clear();
    await username.sendKeys(user || "alice");
    const passwords = await driver.findElements(By.id("password"));
    if (passwords.length) {
      await passwords[0].clear();
      await passwords[0].sendKeys("no password is checked here");
    }
    await driver.findElement(By.id("kc-login")).click();
  }
  await driver.wait(async function () {
    const here = await driver.getCurrentUrl();
    return here.indexOf("/gnap/approve") >= 0 ||
      here.indexOf(finishPrefix) === 0;
  }, wait, "the browser reached neither the approval page nor the " +
    "finish URI after signing in");
  if ((await driver.getCurrentUrl()).indexOf("/gnap/approve") >= 0) {
    const allow = await driver.wait(until.elementLocated(By.id(
      "gnap-allow")), wait, "the approval page drew no Allow button");
    await driver.wait(until.elementIsVisible(allow), wait);
    await allow.click();
  }
  await driver.wait(async function () {
    return (await driver.getCurrentUrl()).indexOf(finishPrefix) === 0;
  }, wait, "after Allow the browser was not sent to " + finishPrefix);
  const finished = await driver.getCurrentUrl();
  log.debug("Leaving approveInBrowser(). " + finished);
  return finished;
}

module.exports = {
  jwkThumbprint: jwkThumbprint,
  certificateThumbprint: certificateThumbprint,
  applicationFor: applicationFor,
  adminPost: adminPost,
  declareSsfRead: declareSsfRead,
  forgetApplication: forgetApplication,
  makeClientCertificate: makeClientCertificate,
  approveInBrowser: approveInBrowser
};
