// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: saml_wstrust_user_guide.js
//
// Walk the SAML and WS-Trust pages the way docs/saml/ and docs/wstrust/
// tell a reader to, against an identity provider at WSTRUST_STS_URL
// (default https://localhost:8081). Pictures are taken by
// doc_screenshots.js and are inert unless DOC_SCREENSHOT_DIR is set.
// SAML pictures go there; WS-Trust pictures go to WSTRUST_SCREENSHOT_DIR
// when that is set, and otherwise to the same directory.
//
// This job is not in the ordinary suite. Run it when the pictures need
// refreshing. See the "Regenerating the screenshots" section of each
// guide.

const { Builder, By, until, logging } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const { loadPage, loadUrl } = require("./page_load");
const browserFlags = require("./browser_flags.js");
const shots = require("./doc_screenshots");
const registry = require("./sts_applications");

var appconfig = {};
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "saml_wstrust_user_guide",
  level: appconfig.LOG_LEVEL || "info"
});

var baseUrl = "https://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime || 15000;
var stsOrigin = "https://localhost:8081";
var samlUser = process.env.GUIDE_SAML_USER || "guide-saml";
var samlPassword = process.env.GUIDE_SAML_PASSWORD || "";
var wstUser = process.env.GUIDE_WST_USER || "guide-wstrust";
var wstPassword = process.env.GUIDE_WST_PASSWORD || "";
var productMode = false;
var spRegistered = false;

function pause(ms) {
  log.debug("Entering pause().");
  log.debug("Leaving pause().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function setField(driver, id, value) {
  log.debug("Entering setField(). " + id);
  await driver.wait(until.elementLocated(By.id(id)), waitTime);
  await driver.executeScript(
    "var e=document.getElementById(arguments[0]); if(e){" +
    " e.value=arguments[1];" +
    " e.dispatchEvent(new Event('input'));" +
    " e.dispatchEvent(new Event('change')); }",
    id, value);
  log.debug("Leaving setField().");
}

async function setChecked(driver, id, on) {
  log.debug("Entering setChecked(). " + id);
  await driver.wait(until.elementLocated(By.id(id)), waitTime);
  await driver.executeScript(
    "var e=document.getElementById(arguments[0]);" +
    " if(e && e.checked!==arguments[1]){" +
    " e.checked=arguments[1];" +
    " e.dispatchEvent(new Event('change')); }",
    id, !!on);
  log.debug("Leaving setChecked().");
}

async function textOf(driver, id) {
  log.debug("Entering textOf(). " + id);
  var text = await driver.executeScript(
    "var e=document.getElementById(arguments[0]); if(!e) return '';" +
    " return (e.value!==undefined && e.value!==null && e.value!=='') ?" +
    " e.value : (e.textContent||'');",
    id);
  log.debug("Leaving textOf().");
  return text || "";
}

async function clickValue(driver, value) {
  log.debug("Entering clickValue(). " + value);
  var locator = By.xpath("//input[@value='" + value + "']");
  await driver.wait(until.elementLocated(locator), waitTime);
  var el = driver.findElement(locator);
  await driver.wait(until.elementIsVisible(el), waitTime);
  await driver.executeScript(
    "arguments[0].scrollIntoView({block:'center'});" +
    "arguments[0].click();", el);
  log.debug("Leaving clickValue().");
}

async function clickId(driver, id) {
  log.debug("Entering clickId(). " + id);
  var el = await driver.wait(until.elementLocated(By.id(id)), waitTime);
  await driver.executeScript(
    "arguments[0].scrollIntoView({block:'center'});" +
    "arguments[0].click();", el);
  log.debug("Leaving clickId().");
}

// A clip is the rectangle around every named element, so two ids that sit
// on either side of a key textarea photograph the key. Refuse that before
// a picture is written. Runs in the page, so this string has no logger.
var KEY_IN_CLIP =
  "var ids=arguments[0];" +
  "var top=Infinity,bottom=-Infinity,left=Infinity,right=-Infinity;" +
  "ids.forEach(function(id){" +
  " var el=document.getElementById(id); if(!el) return;" +
  " var r=el.getBoundingClientRect();" +
  " if(!r.width||!r.height) return;" +
  " top=Math.min(top,r.top); bottom=Math.max(bottom,r.bottom);" +
  " left=Math.min(left,r.left); right=Math.max(right,r.right);" +
  "});" +
  "if(top===Infinity) return '';" +
  "var nodes=document.querySelectorAll('textarea,input');" +
  "for(var i=0;i<nodes.length;i++){" +
  " var n=nodes[i];" +
  " if(n.type==='password'||n.type==='hidden') continue;" +
  " var v=n.value||'';" +
  " if(v.indexOf('PRIVATE KEY')<0) continue;" +
  " var b=n.getBoundingClientRect();" +
  " if(!b.width||!b.height) continue;" +
  " if(b.bottom<top||b.top>bottom||b.right<left||b.left>right)" +
  " continue;" +
  " return n.id||'(unnamed)';" +
  "}" +
  "return '';";

async function shot(driver, dir, prefix, name, ids) {
  log.debug("Entering shot(). " + prefix + "-" + name);
  if (ids && ids.length) {
    var leak = await driver.executeScript(KEY_IN_CLIP, ids);
    if (leak) {
      log.debug("Leaving shot(). Private key in #" + leak + ".");
      throw new Error("screenshot " + prefix + "-" + name +
                      " would include the private key in #" + leak);
    }
  }
  if (dir) {
    process.env.DOC_SCREENSHOT_DIR = dir;
  }
  shots.setPrefix(prefix);
  await shots.snap(driver, name, { ids: ids || [] });
  log.debug("Leaving shot().");
}

async function waitText(driver, id, predicate, message, timeout) {
  log.debug("Entering waitText(). " + id);
  await driver.wait(async function () {
    try {
      return predicate(await textOf(driver, id));
    } catch (e) {
      return false;
    }
  }, timeout || waitTime, message);
  log.debug("Leaving waitText().");
}

// RFC 6238, computed here so the walk can finish a product-mode sign-in.
// The secret stays in this process. It is never logged and never pictured.
var B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
var totpByUser = {};
var TOTP_FILE = "/tmp/guide-totp.json";
var consentPictured = false;

function loadTotpFile() {
  log.debug("Entering loadTotpFile().");
  var fs = require("fs");
  try {
    if (!fs.existsSync(TOTP_FILE)) {
      log.debug("Leaving loadTotpFile(). None saved.");
      return;
    }
    var parsed = JSON.parse(fs.readFileSync(TOTP_FILE, "utf8"));
    Object.keys(parsed || {}).forEach(function (user) {
      if (parsed[user] && parsed[user].secret) {
        totpByUser[user] = parsed[user];
      }
    });
  } catch (e) {
    log.debug("Leaving loadTotpFile(). Unreadable.");
    return;
  }
  log.debug("Leaving loadTotpFile().");
}

function saveTotpFile() {
  log.debug("Entering saveTotpFile().");
  var fs = require("fs");
  var out = {};
  Object.keys(totpByUser).forEach(function (user) {
    var held = totpByUser[user];
    out[user] = {
      secret: held.secret,
      algorithm: held.algorithm,
      digits: held.digits,
      period: held.period
    };
  });
  fs.writeFileSync(TOTP_FILE, JSON.stringify(out), { mode: 0o600 });
  try {
    fs.chmodSync(TOTP_FILE, 0o600);
  } catch (e) {
    log.debug("saveTotpFile() could not restrict the file.");
  }
  log.debug("Leaving saveTotpFile().");
}

function base32ToBytes(text) {
  log.debug("Entering base32ToBytes().");
  var cleaned = String(text).toUpperCase().replace(/[\s=-]/g, "");
  var bits = 0;
  var value = 0;
  var out = [];
  var i;
  for (i = 0; i < cleaned.length; i++) {
    var index = B32.indexOf(cleaned[i]);
    if (index < 0) {
      log.debug("Leaving base32ToBytes(). Not base32.");
      throw new Error("the authenticator secret is not base32.");
    }
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  log.debug("Leaving base32ToBytes().");
  return Buffer.from(out);
}

function totpCode(held, atMs) {
  log.debug("Entering totpCode().");
  var digits = Number(held.digits || 6);
  var period = Number(held.period || 30);
  var alg = String(held.algorithm || "SHA1").toLowerCase();
  var counter = Math.floor(Number(atMs || Date.now()) / 1000 / period);
  var message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  var digest = crypto.createHmac(alg, base32ToBytes(held.secret))
    .update(message).digest();
  var offset = digest[digest.length - 1] & 0x0f;
  var binary = ((digest[offset] & 0x7f) << 24) |
               ((digest[offset + 1] & 0xff) << 16) |
               ((digest[offset + 2] & 0xff) << 8) |
               (digest[offset + 3] & 0xff);
  var code = String(binary % Math.pow(10, digits))
    .padStart(digits, "0");
  log.debug("Leaving totpCode().");
  return { code: code, counter: counter };
}

async function waitForFreshCounter(held) {
  log.debug("Entering waitForFreshCounter().");
  var period = Number(held.period || 30);
  var counter = Math.floor(Date.now() / 1000 / period);
  if (held.lastCounter === undefined || counter > held.lastCounter) {
    log.debug("Leaving waitForFreshCounter(). Current step is unused.");
    return;
  }
  var delay = ((held.lastCounter + 1) * period * 1000) -
              Date.now() + 750;
  if (delay > 0) {
    await pause(delay);
  }
  log.debug("Leaving waitForFreshCounter().");
}

// Runs in the page. The first <code> on the set-up page is the account
// name. The secret is the long base32 one. This string has no logger.
var READ_TOTP_SECRET =
  "var codes=document.querySelectorAll('code');" +
  "var secret=''; var text='';" +
  "for (var i=0;i<codes.length;i++){" +
  " var raw=(codes[i].textContent||'').replace(/\\s+/g,'');" +
  " if(!/^[A-Z2-7]+=*$/i.test(raw)||raw.length<16) continue;" +
  " secret=raw.toUpperCase();" +
  " text=codes[i].parentElement?" +
  " codes[i].parentElement.textContent:'';" +
  " break;" +
  "}" +
  "var alg=(/SHA\\d+/i.exec(text)||[])[0]||'SHA1';" +
  "var digits=(/(\\d+)\\s+digits/.exec(text)||[])[1]||'6';" +
  "var period=(/every\\s+(\\d+)/.exec(text)||[])[1]||'30';" +
  "return {secret:secret, algorithm:alg.toUpperCase()," +
  " digits:Number(digits), period:Number(period)};";

async function submitTotpCode(driver, user, buttonId) {
  log.debug("Entering submitTotpCode(). " + buttonId);
  var held = totpByUser[user];
  if (!held || !held.secret) {
    log.debug("Leaving submitTotpCode(). No secret.");
    throw new Error("iya-sts asked for an authenticator code and " +
                    "this walk has not enrolled one for " + user + ".");
  }
  await waitForFreshCounter(held);
  var made = totpCode(held, Date.now());
  held.lastCounter = made.counter;
  var field = await driver.wait(
    until.elementLocated(By.id("code")), waitTime);
  await field.clear();
  await field.sendKeys(made.code);
  await clickId(driver, buttonId);
  log.debug("Leaving submitTotpCode().");
}

async function waitOffAuthn(driver, path) {
  log.debug("Entering waitOffAuthn(). " + path);
  var failed = false;
  try {
    await driver.wait(async function () {
      var url = await driver.getCurrentUrl();
      if (url.indexOf(path) < 0) {
        return true;
      }
      var body = "";
      try {
        body = await driver.findElement(By.tagName("body")).getText();
      } catch (e) {
        body = "";
      }
      if (body.indexOf("not right") >= 0 ||
          body.indexOf("expired before") >= 0 ||
          body.indexOf("enrolment has expired") >= 0) {
        failed = true;
        return true;
      }
      return false;
    }, waitTime);
  } catch (e) {
    log.debug("Leaving waitOffAuthn(). Still there.");
    throw e;
  }
  log.debug("Leaving waitOffAuthn(). " + (failed ? "error" : "left"));
  return failed ? "error" : "left";
}

async function enrolAuthenticator(driver, user) {
  log.debug("Entering enrolAuthenticator().");
  var confirm = await driver.findElements(By.id("mfa-setup-confirm"));
  if (!confirm.length) {
    var start = await driver.findElements(By.id("mfa-setup-totp"));
    if (!start.length) {
      log.debug("Leaving enrolAuthenticator(). No authenticator app.");
      throw new Error("the second-factor page offered no " +
                      "authenticator app.");
    }
    await clickId(driver, "mfa-setup-totp");
    await driver.wait(
      until.elementLocated(By.id("mfa-setup-confirm")), waitTime);
  }
  var facts = await driver.executeScript(READ_TOTP_SECRET);
  if (!facts || !facts.secret) {
    log.debug("Leaving enrolAuthenticator(). No secret.");
    throw new Error("the authenticator page did not show a secret.");
  }
  totpByUser[user] = {
    secret: facts.secret,
    algorithm: facts.algorithm,
    digits: facts.digits,
    period: facts.period
  };
  await submitTotpCode(driver, user, "mfa-setup-confirm");
  var outcome = await waitOffAuthn(driver, "/authn/mfa-setup");
  if (outcome === "error") {
    await submitTotpCode(driver, user, "mfa-setup-confirm");
    outcome = await waitOffAuthn(driver, "/authn/mfa-setup");
  }
  if (outcome !== "left") {
    log.debug("Leaving enrolAuthenticator(). Code refused.");
    throw new Error("the authenticator code was not accepted.");
  }
  saveTotpFile();
  log.info("Enrolled an authenticator app for " + user + ".");
  log.debug("Leaving enrolAuthenticator().");
}

async function allowConsent(driver) {
  log.debug("Entering allowConsent().");
  var allow = await driver.findElements(By.id("consent-allow"));
  if (!allow.length) {
    log.debug("Leaving allowConsent(). No Allow button.");
    throw new Error("the consent page has no Allow button.");
  }
  if (!consentPictured) {
    await shot(driver, samlDir, "saml-redirect", "05b-consent", []);
    consentPictured = true;
  }
  await clickId(driver, "consent-allow");
  await waitOffAuthn(driver, "/oauth2/consent");
  log.debug("Leaving allowConsent().");
}

async function completeIdpSteps(driver, user) {
  log.debug("Entering completeIdpSteps().");
  var steps = 0;
  while (steps < 10) {
    steps += 1;
    var url = await driver.getCurrentUrl();
    if (url.indexOf(stsOrigin) !== 0) {
      log.debug("Leaving completeIdpSteps(). Left the identity provider.");
      return;
    }
    if (url.indexOf("/authn/mfa-setup") >= 0) {
      await enrolAuthenticator(driver, user);
      continue;
    }
    if (url.indexOf("/authn/totp") >= 0) {
      await submitTotpCode(driver, user, "totp-submit");
      await waitOffAuthn(driver, "/authn/totp");
      continue;
    }
    if (url.indexOf("/authn/post-login") >= 0) {
      var skip = await driver.findElements(By.id("post-login-skip"));
      if (!skip.length) {
        log.debug("Leaving completeIdpSteps(). Required passkey.");
        throw new Error("iya-sts requires a post-login passkey " +
                        "before this sign-in can finish.");
      }
      await clickId(driver, "post-login-skip");
      await waitOffAuthn(driver, "/authn/post-login");
      continue;
    }
    if (url.indexOf("/oauth2/consent") >= 0) {
      await allowConsent(driver);
      continue;
    }
    if (url.indexOf("/authn/login") >= 0) {
      var body = "";
      try {
        body = await driver.findElement(By.tagName("body")).getText();
      } catch (e) {
        body = "";
      }
      if (body.indexOf("Authentication failed") >= 0) {
        log.debug("Leaving completeIdpSteps(). Refused.");
        throw new Error("the identity provider refused the sign-in " +
                        "(Authentication failed).");
      }
      await pause(400);
      continue;
    }
    log.debug("Leaving completeIdpSteps(). No further sign-in step.");
    return;
  }
  log.debug("Leaving completeIdpSteps(). Too many steps.");
  throw new Error("the identity provider did not finish the sign-in.");
}

async function waitForLoginOrResponse(driver, user, signinShot) {
  log.debug("Entering waitForLoginOrResponse().");
  var needsLogin = false;
  try {
    await driver.wait(async function () {
      var url = "";
      try {
        url = await driver.getCurrentUrl();
      } catch (e) {
        return false;
      }
      if (url.indexOf("saml_response.html") >= 0) {
        return true;
      }
      var fields = [];
      try {
        fields = await driver.findElements(By.id("username"));
      } catch (e) {
        fields = [];
      }
      if (fields.length) {
        needsLogin = true;
        return true;
      }
      return false;
    }, waitTime);
  } catch (e) {
    log.debug("Leaving waitForLoginOrResponse(). Neither page.");
    throw new Error("neither the sign-in page nor the SAML response " +
                    "appeared.");
  }
  if (needsLogin) {
    await loginAtIdp(driver, user, signinShot);
  }
  log.debug("Leaving waitForLoginOrResponse()." +
            (needsLogin ? " Signed in." : " Session reused."));
}

async function loginAtIdp(driver, user, signinShot) {
  log.debug("Entering loginAtIdp().");
  var here = await driver.getCurrentUrl();
  if (here.indexOf("saml_response.html") >= 0) {
    log.debug("Leaving loginAtIdp(). Already on the response page.");
    return;
  }
  var username = By.id("username");
  await driver.wait(until.elementLocated(username), waitTime,
    "the identity provider never showed a #username field.");
  await driver.wait(until.elementIsVisible(
    driver.findElement(username)), waitTime);
  await driver.findElement(username).clear();
  await driver.findElement(username).sendKeys(user);
  if (signinShot) {
    await shot(driver, samlDir, shotsPrefix, "05-signin", []);
  }
  await driver.findElement(By.id("password")).clear();
  await driver.findElement(By.id("password")).sendKeys(samlPassword);
  var buttons = ["kc-login", "saml2-login"];
  var clicked = null;
  for (var i = 0; i < buttons.length; i++) {
    var found = await driver.findElements(By.id(buttons[i]));
    if (found.length) {
      clicked = buttons[i];
      await found[0].click();
      break;
    }
  }
  assert(clicked, "no known sign-in button on " +
         await driver.getCurrentUrl());
  var refused = false;
  try {
    await driver.wait(async function () {
      var url = await driver.getCurrentUrl();
      if (url.indexOf("/authn/login") < 0 &&
          url.indexOf("/login") < 0) {
        return true;
      }
      var body = "";
      try {
        body = await driver.findElement(By.tagName("body")).getText();
      } catch (e) {
        body = "";
      }
      if (body.indexOf("Authentication failed") >= 0) {
        refused = true;
        return true;
      }
      return false;
    }, waitTime);
  } catch (e) {
    log.debug("Leaving loginAtIdp(). Still on the sign-in page.");
    throw e;
  }
  if (refused) {
    log.debug("Leaving loginAtIdp(). Refused.");
    throw new Error("the identity provider refused the sign-in " +
                    "(Authentication failed).");
  }
  await completeIdpSteps(driver, user);
  log.debug("Leaving loginAtIdp(). " + clicked);
}

var shotsPrefix = "saml-redirect";
var samlDir = "";
var wstDir = "";

async function loadMetadata(driver, url) {
  log.debug("Entering loadMetadata().");
  await setField(driver, "saml_metadata_url", url);
  await clickValue(driver, "Load Metadata");
  await waitText(driver, "saml_metadata_status", function (v) {
    return v.indexOf("Loaded and parsed") >= 0 ||
           v.indexOf("failed") >= 0 || v.indexOf("error") >= 0;
  }, "metadata did not finish loading from " + url, waitTime);
  var status = await textOf(driver, "saml_metadata_status");
  assert(status.indexOf("Loaded and parsed") >= 0,
         "metadata load: " + status);
  log.debug("Leaving loadMetadata().");
}

async function ensureSpKey(driver) {
  log.debug("Entering ensureSpKey().");
  var key = await textOf(driver, "saml_sp_private_key");
  if (key.indexOf("PRIVATE KEY") >= 0) {
    await registerServiceProvider(driver);
    log.debug("Leaving ensureSpKey(). Already present.");
    return;
  }
  await clickValue(driver, "Generate Keys");
  await waitText(driver, "saml_sp_private_key", function (v) {
    return v.indexOf("PRIVATE KEY") >= 0;
  }, "SP key pair was not generated.", Math.max(waitTime, 30000));
  await registerServiceProvider(driver);
  log.debug("Leaving ensureSpKey().");
}

async function samlRoundTrip(driver, binding, user) {
  log.debug("Entering samlRoundTrip(). " + binding);
  var request = binding === "post" ? "post" : "redirect";
  var response = binding === "artifact" ? "artifact" : "post";
  await setField(driver, "saml_version", "2.0");
  await driver.executeScript(
    "var s=document.getElementById('saml_nameid_format');" +
    "if(s){ s.value='';" +
    " s.dispatchEvent(new Event('change')); }");
  await setField(driver, "saml_binding", request);
  await setField(driver, "saml_response_binding", response);
  await ensureSpKey(driver);
  await pause(600);
  if (binding === "redirect") {
    await shot(driver, samlDir, "saml-redirect", "03-request", [
      "saml_version", "saml_binding_field",
      "saml_response_binding_field", "saml_sp_entity_id",
      "saml_acs_url"
    ]);
    await shot(driver, samlDir, "saml-redirect", "04-authnrequest", [
      "saml_authn_request"
    ]);
  } else if (binding === "post") {
    await shot(driver, samlDir, "saml-post", "01-binding", [
      "saml_binding_field", "saml_response_binding_field"
    ]);
    await shot(driver, samlDir, "saml-post", "01b-request", [
      "saml_authn_request"
    ]);
  } else {
    await shot(driver, samlDir, "saml-artifact", "01-binding", [
      "saml_binding_field", "saml_response_binding_field"
    ]);
  }
  shotsPrefix = binding === "redirect" ? "saml-redirect" :
                binding === "post" ? "saml-post" : "saml-artifact";
  log.info("Call IdP (" + binding + ").");
  await clickValue(driver, "Call IdP");
  await waitForLoginOrResponse(driver, user, binding === "redirect");
  await driver.wait(until.urlContains("saml_response.html"), waitTime);
  await waitText(driver, "saml_resp_xml", function (v) {
    return v.indexOf("Response") >= 0;
  }, "SAML response was not shown.", waitTime);
  var xml = await textOf(driver, "saml_resp_xml");
  assert(xml.indexOf("no <Assertion") < 0 &&
         xml.indexOf("Assertion") >= 0,
         "response has no assertion:\n" + xml.slice(0, 500));
  var prefix = shotsPrefix;
  if (binding === "redirect") {
    await shot(driver, samlDir, prefix, "06-response", [
      "saml_resp_status", "pane_response"
    ]);
    await clickId(driver, "tab_attrs_btn");
    await pause(300);
    await shot(driver, samlDir, prefix, "07-attributes", [
      "tab_attrs"
    ]);
    await clickValue(driver, "Validate Signatures");
    await waitText(driver, "saml_sig_status", function (v) {
      return v.length > 0;
    }, "signature check did not finish.", waitTime);
    await shot(driver, samlDir, prefix, "08-signatures", [
      "saml_sig_trust", "saml_sig_status", "saml_sig_details"
    ]);
  } else if (binding === "post") {
    await shot(driver, samlDir, prefix, "02-response", [
      "saml_resp_status", "pane_response"
    ]);
  } else {
    await shot(driver, samlDir, prefix, "02-response", [
      "saml_resp_status", "pane_response"
    ]);
  }
  log.debug("Leaving samlRoundTrip().");
}

async function samlLogout(driver) {
  log.debug("Entering samlLogout().");
  await loadPage(driver, baseUrl + "/saml_request.html",
                 "saml_logout_btn", { timeout: waitTime });
  await setField(driver, "saml_binding", "redirect");
  await driver.wait(async function () {
    var nameid = await driver.executeScript(
      "return localStorage.getItem('saml_last_nameid')||'';");
    var slo = await textOf(driver, "saml_slo_redirect");
    return nameid && slo;
  }, waitTime, "logout has no NameID or SLO URL.");
  var button = await driver.findElement(By.id("saml_logout_btn"));
  await driver.executeScript(
    "arguments[0].scrollIntoView({block:'center'});" +
    "arguments[0].click();", button);
  var deadline = Date.now() + Math.max(waitTime, 90000);
  var signedIn = false;
  while (Date.now() < deadline) {
    var url = await driver.getCurrentUrl();
    if (url.indexOf("saml_response.html") >= 0) {
      break;
    }
    var fields = await driver.findElements(By.id("username"));
    if (fields.length && !signedIn) {
      signedIn = true;
      await loginAtIdp(driver, samlUser, false);
      continue;
    }
    await pause(400);
  }
  if ((await driver.getCurrentUrl()).indexOf("saml_response.html") < 0) {
    log.debug("Leaving samlLogout(). No LogoutResponse.");
    throw new Error("LogoutResponse did not arrive.");
  }
  await waitText(driver, "saml_resp_xml", function (v) {
    return v.indexOf("LogoutResponse") >= 0;
  }, "the page is not a LogoutResponse.", waitTime);
  await clickId(driver, "tab_resp_details_btn");
  await pause(300);
  await shot(driver, samlDir, "saml-logout", "01-response", [
    "saml_resp_status", "pane_response"
  ]);
  log.debug("Leaving samlLogout().");
}

async function saml11(driver, user) {
  log.debug("Entering saml11().");
  await loadPage(driver, baseUrl + "/saml_request.html",
                 "saml_metadata_url", { timeout: waitTime });
  var entity = await textOf(driver, "saml_sp_entity_id");
  if (!entity) {
    entity = baseUrl.replace(/\/+$/, "") + "/saml/sp";
    await setField(driver, "saml_sp_entity_id", entity);
  }
  var slug = "app-" + crypto.createHash("sha256").update(entity)
      .digest("hex").slice(0, 12);
  var url = stsOrigin + "/saml11/metadata/" + slug;
  log.info("SAML 1.1 metadata " + url + " for " + entity);
  await loadMetadata(driver, url);
  // iya-sts publishes one document that names both protocols, so the
  // page does not move the selector. A 1.1-only document would have.
  // Runs in the page: no logger there.
  await driver.executeScript(
    "var e=document.getElementById('saml_version');" +
    "if(e && e.value!=='1.1'){ e.value='1.1';" +
    " if(window.saml_request&&window.saml_request.onVersionChange){" +
    "  window.saml_request.onVersionChange(); } }");
  await waitText(driver, "saml_version", function (v) {
    return v === "1.1";
  }, "SAML 1.1 was not selected.", waitTime);
  await waitText(driver, "saml_sso_post", function (v) {
    return v.indexOf("/saml11/sso/") >= 0;
  }, "SAML 1.1 did not fill the inter-site transfer URL.", waitTime);
  await pause(400);
  await shot(driver, samlDir, "saml11", "01-version", [
    "saml_version", "saml_version_warning", "saml_sign_field"
  ]);
  await shot(driver, samlDir, "saml11", "02-request", [
    "saml_authn_request"
  ]);
  shotsPrefix = "saml11";
  await ensureSpKey(driver);
  var meta = await driver.executeScript(
    "return window.saml_request.buildSpMetadata();");
  assert(meta.indexOf("SAML:1.1:protocol") >= 0,
         "the page did not build SAML 1.1 SP metadata");
  var consumed = await registry.adminPost(stsOrigin,
    "/saml2/upload-metadata",
    { sp: entity, document: meta, family: "saml11" });
  assert(consumed && consumed.ok !== false && !consumed.error,
         "iya-sts did not consume the SAML 1.1 SP metadata: " +
         JSON.stringify(consumed && consumed.errors || consumed)
           .slice(0, 400));
  await clickValue(driver, "Call IdP");
  await waitForLoginOrResponse(driver, user, false);
  await driver.wait(until.urlContains("saml_response.html"), waitTime);
  await waitText(driver, "saml_assertion_xml", function (v) {
    return v.indexOf("Assertion") >= 0 &&
           v.indexOf("no <Assertion") < 0;
  }, "SAML 1.1 response has no assertion.", waitTime);
  await shot(driver, samlDir, "saml11", "03-response", [
    "saml_resp_status", "pane_response"
  ]);
  await clickId(driver, "tab_attrs_btn");
  await pause(300);
  await shot(driver, samlDir, "saml11", "04-attributes", [
    "tab_attrs"
  ]);
  log.debug("Leaving saml11().");
}

function wstStatusIsTerminal(status) {
  log.debug("Entering wstStatusIsTerminal().");
  if (!status || status.indexOf("Sending") >= 0 ||
      status.indexOf("Generating") >= 0) {
    log.debug("Leaving wstStatusIsTerminal(). No.");
    return false;
  }
  var terminal = status.indexOf("failed") >= 0 ||
      status.indexOf("Failed") >= 0 ||
      status.indexOf("error") >= 0 ||
      status.indexOf("Error") >= 0 ||
      status.indexOf("Enter the STS") >= 0 ||
      status.indexOf("needs a Target") >= 0 ||
      status.indexOf("Build failed") >= 0 ||
      status.indexOf("certificate") >= 0;
  log.debug("Leaving wstStatusIsTerminal(). " + terminal);
  return terminal;
}

function wstStatusIsCertificate(status) {
  log.debug("Entering wstStatusIsCertificate().");
  var s = String(status || "").toLowerCase();
  var refused = s.indexOf("certificate") >= 0 ||
      s.indexOf("unable to verify") >= 0 ||
      s.indexOf("self-signed") >= 0;
  log.debug("Leaving wstStatusIsCertificate(). " + refused);
  return refused;
}

// The tools page stays put and writes wst_call_status when the proxy
// refuses the call. Navigation is only the success path.
async function waitForWstOutcome(driver) {
  log.debug("Entering waitForWstOutcome().");
  var deadline = Date.now() + waitTime;
  var last = "";
  while (Date.now() < deadline) {
    var url = await driver.getCurrentUrl();
    if (url.indexOf("wstrust_response.html") >= 0) {
      await waitText(driver, "wst_resp_status", function (v) {
        return v.indexOf("response loaded") >= 0 ||
               v.indexOf("could not parse") >= 0 ||
               v.indexOf("Fault") >= 0;
      }, "WS-Trust response was not rendered.", waitTime);
      log.debug("Leaving waitForWstOutcome(). Response page.");
      return "ok";
    }
    last = await textOf(driver, "wst_call_status");
    if (wstStatusIsTerminal(last)) {
      log.debug("Leaving waitForWstOutcome(). Refused on the tools page.");
      return last;
    }
    await pause(250);
  }
  log.debug("Leaving waitForWstOutcome(). Timed out.");
  return last || "the tools page never opened the response.";
}

async function sendWst(driver, opts) {
  log.debug("Entering sendWst().");
  opts = opts || {};
  await clickValue(driver, "Send Request");
  var outcome = await waitForWstOutcome(driver);
  if (outcome === "ok") {
    log.debug("Leaving sendWst().");
    return;
  }
  if (wstStatusIsCertificate(outcome)) {
    log.info("Backend TLS validation refused the STS. " +
             "Retrying with validation off.");
    // Shot before the checkbox change: that change rebuilds the request
    // and replaces the refusal on the status line. The status field sits
    // below the generated SOAP, so the clip is the line alone.
    if (opts.pictureTls) {
      await shot(driver, wstDir, "wst-issue", "04b-tls", [
        "wst_call_status"
      ]);
    }
    await setChecked(driver, "wst_ssl_validate", false);
    await pause(300);
    await clickValue(driver, "Send Request");
    outcome = await waitForWstOutcome(driver);
    if (outcome === "ok") {
      log.debug("Leaving sendWst(). Validation off.");
      return;
    }
  }
  log.debug("Leaving sendWst(). Failed.");
  throw new Error("WS-Trust send failed: " + outcome);
}

async function issueBearer(driver, stsUrl, quiet) {
  log.debug("Entering issueBearer(). quiet=" + !!quiet);
  await loadPage(driver, baseUrl + "/wstrust_tools.html", "wst_sts_url",
                 { timeout: waitTime });
  await setField(driver, "wst_sts_url", stsUrl);
  await setField(driver, "wst_trust_version", "1.4");
  await setField(driver, "wst_operation", "issue");
  await setField(driver, "wst_token_type", "saml2");
  await setField(driver, "wst_key_type", "bearer");
  await setField(driver, "wst_applies_to", "urn:wstrust:test:rp");
  await setField(driver, "wst_cred_mode", "usernametoken");
  await setField(driver, "wst_username", wstUser);
  await setField(driver, "wst_password", wstPassword);
  await setChecked(driver, "wst_sign_request", false);
  await setChecked(driver, "wst_initiateFromBackEnd", true);
  await pause(500);
  if (!quiet) {
    await shot(driver, wstDir, "wst-issue", "01-endpoint", ["pane_sts"]);
    await shot(driver, wstDir, "wst-issue", "02-request", [
      "wst_trust_version", "wst_operation", "wst_token_type",
      "wst_key_type", "wst_applies_to", "wst_lifetime_minutes"
    ]);
    await shot(driver, wstDir, "wst-issue", "03-credentials", [
      "wst_cred_mode", "wst_username", "wst_password",
      "wst_password_type"
    ]);
    await shot(driver, wstDir, "wst-issue", "04-send", [
      "wst_initiateFromBackEnd", "wst_ssl_validate",
      "wst_generated_request"
    ]);
  }
  await sendWst(driver, { pictureTls: !quiet });
  var xml = await textOf(driver, "wst_response_xml");
  assert(xml.indexOf("RequestSecurityTokenResponse") >= 0,
         "Issue did not return an RSTR:\n" + xml.slice(0, 600));
  if (!quiet) {
    await clickId(driver, "tab_resp_btn");
    await pause(300);
    await shot(driver, wstDir, "wst-issue", "05-response", [
      "wst_resp_status", "tab_resp"
    ]);
    await shot(driver, wstDir, "wst-issue", "06-token",
               ["tab_token_xml"]);
    await clickId(driver, "tab_fields_btn");
    await pause(200);
    await shot(driver, wstDir, "wst-issue", "07-fields",
               ["tab_fields"]);
  }
  var token = await issuedAssertion(driver);
  if (token.indexOf("Assertion") < 0) {
    log.debug("Leaving issueBearer(). No assertion bytes.");
    throw new Error("Issue did not keep the issued assertion.");
  }
  log.debug("Leaving issueBearer().");
  return token;
}

// The token box is indented for reading. Product mode verifies the
// signature over the assertion as the service wrote it, so a later
// OnBehalfOf or ActAs has to send those bytes. They are in the stashed
// exchange. This string runs in the page and has no logger.
async function issuedAssertion(driver) {
  log.debug("Entering issuedAssertion().");
  var xml = await driver.executeScript(
    "var s=localStorage.getItem('wstrust_last_exchange');" +
    "if(!s) return '';" +
    "var ex; try { ex=JSON.parse(s); } catch (e) { return ''; }" +
    "var xml=ex.responseXml||'';" +
    "var m=xml.match(/<((?:[\\w.-]+:)?Assertion)\\b/);" +
    "if(!m) return '';" +
    "var end=xml.indexOf('</'+m[1]+'>', m.index);" +
    "if(end<0) return '';" +
    "return xml.slice(m.index, end+m[1].length+3);");
  log.debug("Leaving issuedAssertion(). " +
            (xml && xml.indexOf("<") >= 0 ? "held" : "empty"));
  return xml || "";
}

async function lifecycle(driver, stsUrl, token) {
  log.debug("Entering lifecycle().");
  var ops = [
    ["renew", "wst-renew"],
    ["validate", "wst-validate"],
    ["cancel", "wst-cancel"]
  ];
  for (var i = 0; i < ops.length; i++) {
    var op = ops[i][0];
    var prefix = ops[i][1];
    await loadPage(driver, baseUrl + "/wstrust_tools.html",
                   "wst_sts_url", { timeout: waitTime });
    await setField(driver, "wst_sts_url", stsUrl);
    await setField(driver, "wst_operation", op);
    await setField(driver, "wst_target_token", token);
    await setField(driver, "wst_cred_mode", "usernametoken");
    await setField(driver, "wst_username", wstUser);
    await setField(driver, "wst_password", wstPassword);
    await setChecked(driver, "wst_sign_request", false);
    await pause(400);
    if (op === "renew") {
      await shot(driver, wstDir, prefix, "01-target", [
        "wst_operation", "wst_target_token"
      ]);
    }
    await sendWst(driver);
    var xml = await textOf(driver, "wst_response_xml");
    assert(xml.indexOf("RequestSecurityTokenResponse") >= 0,
           op + " did not return an RSTR:\n" + xml.slice(0, 400));
    await clickId(driver, "tab_fields_btn");
    await pause(200);
    var step = op === "renew" ? "02-response" : "01-status";
    await shot(driver, wstDir, prefix, step, [
      "wst_resp_status", "tab_fields"
    ]);
    if (op === "renew") {
      var renewed = await textOf(driver, "wst_token_xml");
      if (renewed.indexOf("<") >= 0) {
        token = renewed;
      }
    }
  }
  log.debug("Leaving lifecycle().");
}

async function signedIssue(driver, stsUrl) {
  log.debug("Entering signedIssue().");
  await loadPage(driver, baseUrl + "/wstrust_tools.html", "wst_sts_url",
                 { timeout: waitTime });
  await setField(driver, "wst_sts_url", stsUrl);
  await setField(driver, "wst_operation", "issue");
  await setField(driver, "wst_applies_to", "urn:wstrust:test:rp");
  await setField(driver, "wst_cred_mode", "none");
  await setChecked(driver, "wst_sign_request", true);
  if (productMode) {
    await installIssuedSigningKey(driver);
  } else {
    await clickValue(driver, "Generate Keys");
  }
  await waitText(driver, "wst_sp_private_key", function (v) {
    return v.indexOf("PRIVATE KEY") >= 0;
  }, "WS-Trust signing key was not generated.",
  Math.max(waitTime, 30000));
  await waitText(driver, "wst_generated_request", function (v) {
    return v.indexOf("Signature") >= 0;
  }, "the signed request has no Signature.", waitTime);
  await shot(driver, wstDir, "wst-signed", "01-signing", [
    "wst_sign_request", "wst_sign_timestamp", "wst_sig_alg"
  ]);
  await sendWst(driver);
  var xml = await textOf(driver, "wst_response_xml");
  assert(xml.indexOf("RequestSecurityTokenResponse") >= 0,
         "signed Issue failed:\n" + xml.slice(0, 400));
  await clickId(driver, "tab_resp_btn");
  await pause(200);
  await shot(driver, wstDir, "wst-signed", "02-response", [
    "wst_resp_status", "tab_resp"
  ]);
  log.debug("Leaving signedIssue().");
}

async function encryptedIssue(driver, stsUrl) {
  log.debug("Entering encryptedIssue().");
  var url = stsUrl + (stsUrl.indexOf("?") >= 0 ? "&" : "?") +
      "encrypt=1";
  await loadPage(driver, baseUrl + "/wstrust_tools.html", "wst_sts_url",
                 { timeout: waitTime });
  await setField(driver, "wst_sts_url", url);
  await setField(driver, "wst_operation", "issue");
  await setField(driver, "wst_cred_mode", "none");
  await setChecked(driver, "wst_sign_request", true);
  var key = await textOf(driver, "wst_sp_private_key");
  if (key.indexOf("PRIVATE KEY") < 0) {
    if (productMode) {
      await installIssuedSigningKey(driver);
    } else {
      await clickValue(driver, "Generate Keys");
    }
    await waitText(driver, "wst_sp_private_key", function (v) {
      return v.indexOf("PRIVATE KEY") >= 0;
    }, "no key to encrypt to.", Math.max(waitTime, 30000));
  }
  await sendWst(driver);
  var token = await textOf(driver, "wst_token_xml");
  assert(token.indexOf("Encrypted") >= 0,
         "expected an encrypted token:\n" + token.slice(0, 300));
  await shot(driver, wstDir, "wst-encrypted", "01-token", [
    "tab_token_xml"
  ]);
  await clickValue(driver, "Decrypt");
  await waitText(driver, "wst_dec_status", function (v) {
    return v.indexOf("Decrypted") >= 0 || v.indexOf("failed") >= 0;
  }, "decrypt did not finish.", waitTime);
  var plain = await textOf(driver, "wst_token_xml");
  assert(plain.indexOf("Assertion") >= 0 &&
         plain.indexOf("EncryptedData") < 0,
         "decrypt did not yield an assertion: " +
         (await textOf(driver, "wst_dec_status")));
  await shot(driver, wstDir, "wst-encrypted", "02-decrypted", [
    "tab_token_xml"
  ]);
  await shot(driver, wstDir, "wst-encrypted", "02b-status", [
    "wst_dec_status"
  ]);
  log.debug("Leaving encryptedIssue().");
}

async function delegation(driver, stsUrl, assertion) {
  log.debug("Entering delegation().");
  await loadPage(driver, baseUrl + "/wstrust_tools.html", "wst_sts_url",
                 { timeout: waitTime });
  await setField(driver, "wst_sts_url", stsUrl);
  await setField(driver, "wst_trust_version", "1.4");
  await setField(driver, "wst_operation", "issue");
  await setField(driver, "wst_token_type", "saml2");
  await setField(driver, "wst_key_type", "bearer");
  await setField(driver, "wst_applies_to", "https://esb.example.com");
  await setField(driver, "wst_cred_mode", "usernametoken");
  await setField(driver, "wst_username", wstUser);
  await setField(driver, "wst_password", wstPassword);
  await setChecked(driver, "wst_sign_request", false);
  await setChecked(driver, "wst_use_onbehalfof", true);
  await setField(driver, "wst_onbehalfof", assertion);
  await pause(400);
  await shot(driver, wstDir, "wst-onbehalfof", "01-request", [
    "wst_applies_to", "wst_use_onbehalfof", "wst_onbehalfof"
  ]);
  await sendWst(driver);
  var xml = await textOf(driver, "wst_response_xml");
  assert(xml.indexOf("RequestSecurityTokenResponse") >= 0,
         "OnBehalfOf Issue failed:\n" + xml.slice(0, 500));
  await shot(driver, wstDir, "wst-onbehalfof", "02-token", [
    "tab_token_xml"
  ]);
  var acted = await issuedAssertion(driver);

  await loadPage(driver, baseUrl + "/wstrust_tools.html", "wst_sts_url",
                 { timeout: waitTime });
  await setField(driver, "wst_sts_url", stsUrl);
  await setField(driver, "wst_operation", "issue");
  await setField(driver, "wst_applies_to", "https://soap1.example.com");
  await setField(driver, "wst_cred_mode", "usernametoken");
  await setField(driver, "wst_username", wstUser);
  await setField(driver, "wst_password", wstPassword);
  await setChecked(driver, "wst_use_onbehalfof", false);
  await setChecked(driver, "wst_use_actas", true);
  await setField(driver, "wst_actas", acted || assertion);
  await pause(400);
  await shot(driver, wstDir, "wst-actas", "01-request", [
    "wst_applies_to", "wst_use_actas", "wst_actas"
  ]);
  await sendWst(driver);
  xml = await textOf(driver, "wst_response_xml");
  assert(xml.indexOf("RequestSecurityTokenResponse") >= 0,
         "ActAs Issue failed:\n" + xml.slice(0, 500));
  await shot(driver, wstDir, "wst-actas", "02-token", ["tab_token_xml"]);
  log.debug("Leaving delegation().");
}

async function attachAdminApi() {
  log.debug("Entering attachAdminApi().");
  if (process.env.STS_ADMIN_API_TOKEN) {
    require("./tools/attach-admin-token");
    log.debug("Leaving attachAdminApi(). Token already set.");
    return;
  }
  if (!process.env.STS_ADMIN_API_CLIENT_SECRET) {
    log.debug("Leaving attachAdminApi(). No client secret.");
    throw new Error("Set STS_ADMIN_API_CLIENT_SECRET. The walk " +
                    "registers the service provider and the AppliesTo " +
                    "applications on iya-sts.");
  }
  var tokens = require("./tools/admin-api-token");
  process.env.STS_ADMIN_API_TOKEN = await tokens.tokenFor(stsOrigin);
  require("./tools/attach-admin-token");
  log.debug("Leaving attachAdminApi().");
}

async function ensureGuidePerson(username, password) {
  log.debug("Entering ensureGuidePerson(). " + username);
  try {
    await registry.ensurePerson(stsOrigin, username, password);
  } catch (e) {
    var message = String(e && e.message || e);
    if (message.indexOf("password-history") >= 0) {
      log.info(username + " already uses this password.");
      log.debug("Leaving ensureGuidePerson(). Unchanged.");
      return;
    }
    log.debug("Leaving ensureGuidePerson(). Refused.");
    throw e;
  }
  log.debug("Leaving ensureGuidePerson().");
}

async function ensureWstAppPassword() {
  log.debug("Entering ensureWstAppPassword().");
  if (!productMode) {
    log.debug("Leaving ensureWstAppPassword(). Development mode.");
    return;
  }
  var listed = await registry.adminGet(stsOrigin,
    "/users/app-passwords?user=" + encodeURIComponent(wstUser) +
    "&per=50");
  if (listed && listed.enabled === false) {
    log.debug("Leaving ensureWstAppPassword(). Disabled.");
    throw new Error("App passwords are turned off " +
      "(appPasswords.enabled). Product mode refuses the account " +
      "password on the WS-Trust door.");
  }
  var held = (listed && listed.passwords) || [];
  var i;
  for (i = 0; i < held.length; i++) {
    if (held[i].name !== "guide-walk") {
      continue;
    }
    var gone = await registry.adminPost(stsOrigin,
      "/users/revoke-app-password", {
        user: wstUser, id: held[i].id
      });
    if (!gone || gone.ok === false) {
      log.debug("Leaving ensureWstAppPassword(). Revoke refused.");
      throw new Error("could not revoke the previous application " +
        "password: " +
        JSON.stringify(gone && gone.errors || gone).slice(0, 300));
    }
  }
  var made = await registry.adminPost(stsOrigin,
    "/users/create-app-password", {
      user: wstUser,
      name: "guide-walk",
      doors: ["wstrust"]
    });
  if (!made || made.ok === false || !made.appPassword) {
    log.debug("Leaving ensureWstAppPassword(). Refused.");
    throw new Error("could not make a WS-Trust application password: " +
      JSON.stringify(made && made.errors || "none returned")
        .slice(0, 300));
  }
  wstPassword = made.appPassword;
  log.info("UsernameToken will use an application password scoped " +
           "to wstrust.");
  log.debug("Leaving ensureWstAppPassword().");
}

function adminAlready(reply) {
  log.debug("Entering adminAlready().");
  if (!reply || reply.ok !== false) {
    log.debug("Leaving adminAlready(). Not a refusal.");
    return false;
  }
  var msg = JSON.stringify(reply.errors || reply);
  var already = /already|is a member|member of/i.test(msg);
  log.debug("Leaving adminAlready(). " + already);
  return already;
}

// Product mode lets a person call OnBehalfOf or ActAs only with the
// delegation-actor role, impersonation listed on that person, and the
// target application accepting them. The inner token's audience also has
// to be allowed to hand the call on. These writes name the guide account
// and the three guide audiences and nothing else.
async function ensureWstDelegation() {
  log.debug("Entering ensureWstDelegation().");
  var created = await registry.adminPost(stsOrigin,
    "/roles/create-role", {
      role: "DELEGATION_ACTOR",
      description: "People who may request a WS-Trust OnBehalfOf or ActAs."
    });
  if (!created || (created.ok === false && !adminAlready(created))) {
    log.debug("Leaving ensureWstDelegation(). Role refused.");
    throw new Error("could not create DELEGATION_ACTOR: " +
      JSON.stringify(created && created.errors || created).slice(0, 300));
  }
  var member = await registry.adminPost(stsOrigin, "/roles/add-member", {
    role: "DELEGATION_ACTOR", kind: "user", member: wstUser
  });
  if (!member || (member.ok === false && !adminAlready(member))) {
    log.debug("Leaving ensureWstDelegation(). Member refused.");
    throw new Error("could not grant DELEGATION_ACTOR: " +
      JSON.stringify(member && member.errors || member).slice(0, 300));
  }
  var sem = await registry.adminPost(stsOrigin,
    "/users/set-delegation-semantics", {
      user: wstUser,
      semantics: ["delegation", "impersonation"]
    });
  if (!sem || sem.ok === false) {
    log.debug("Leaving ensureWstDelegation(). Semantics refused.");
    throw new Error("could not set delegation semantics: " +
      JSON.stringify(sem && sem.errors || sem).slice(0, 300));
  }
  await registry.allowHop(stsOrigin, {
    actor: "urn:wstrust:test:rp",
    target: "https://esb.example.com",
    why: "the user-guide OnBehalfOf hop"
  });
  await registry.allowHop(stsOrigin, {
    actor: "https://esb.example.com",
    target: "https://soap1.example.com",
    why: "the user-guide ActAs hop"
  });
  await registry.allowDelegation(stsOrigin, {
    application: "https://esb.example.com",
    acceptsFrom: [wstUser],
    why: "the guide account may ask this service for a token"
  });
  await registry.allowDelegation(stsOrigin, {
    application: "https://soap1.example.com",
    acceptsFrom: [wstUser],
    why: "the guide account may ask this service for a token"
  });
  log.info("Delegation policy allows " + wstUser +
           " to call OnBehalfOf and ActAs for the guide audiences.");
  log.debug("Leaving ensureWstDelegation().");
}

async function prepareIdp() {
  log.debug("Entering prepareIdp().");
  if (!samlPassword || !wstPassword) {
    log.debug("Leaving prepareIdp(). No account passwords.");
    throw new Error("Set GUIDE_SAML_PASSWORD and GUIDE_WST_PASSWORD. " +
                    "The walk creates those two accounts on iya-sts.");
  }
  await attachAdminApi();
  productMode = await registry.isProduct(stsOrigin);
  log.info("iya-sts is in " +
           (productMode ? "product" : "development") + " mode.");
  await ensureGuidePerson(samlUser, samlPassword);
  await ensureGuidePerson(wstUser, wstPassword);
  var apps = [
    ["urn:wstrust:test:rp", "Guide relying party"],
    ["https://esb.example.com", "Guide enterprise service bus"],
    ["https://soap1.example.com", "Guide SOAP service"]
  ];
  for (var i = 0; i < apps.length; i++) {
    await registry.provision(stsOrigin, {
      identifier: apps[i][0],
      name: apps[i][1],
      protocols: ["wstrust", "saml2"],
      fields: {
        wstrustAppliesTo: [apps[i][0]],
        samlEntityId: [apps[i][0]]
      },
      why: "the audience the user-guide WS-Trust walk asks for"
    });
  }
  await ensureWstAppPassword();
  if (productMode) {
    await ensureWstDelegation();
  }
  log.debug("Leaving prepareIdp().");
}

// iya-sts stores samlSigningCertificate as bare base64 DER. A PEM and
// that body are the same certificate, and an exact string compare of
// the textarea is not.
function certificateBody(value) {
  log.debug("Entering certificateBody().");
  var body = String(value || "")
    .replace(/-----[^-]+-----/g, "")
    .replace(/\s+/g, "");
  log.debug("Leaving certificateBody().");
  return body;
}

function heldCertificateBodies(entry) {
  log.debug("Entering heldCertificateBodies().");
  var raw = ((entry || {}).fields || {}).samlSigningCertificate;
  var list = raw === undefined || raw === null ? [] :
    (Array.isArray(raw) ? raw : [raw]);
  var bodies = [];
  for (var i = 0; i < list.length; i++) {
    var body = certificateBody(list[i]);
    if (body) {
      bodies.push(body);
    }
  }
  log.debug("Leaving heldCertificateBodies().");
  return bodies;
}

async function registerServiceProvider(driver) {
  log.debug("Entering registerServiceProvider().");
  if (spRegistered) {
    log.debug("Leaving registerServiceProvider(). Already registered.");
    return;
  }
  var entity = (await textOf(driver, "saml_sp_entity_id")).trim();
  var acs = (await textOf(driver, "saml_acs_url")).trim();
  var cert = (await textOf(driver, "saml_sp_public_key"))
      .replace(/\r\n/g, "\n").trim();
  var body = certificateBody(cert);
  assert(entity && acs && /^[A-Za-z0-9+/]+=*$/.test(body),
         "the page has no SP entityID, ACS or certificate to register");
  var meta = await driver.executeScript(
    "return window.saml_request.buildSpMetadata();");
  var sloMatch = /SingleLogoutService[^>]*Location="([^"]+)"/.exec(meta);
  var fields = {
    samlEntityId: [entity],
    samlAssertionConsumerService: [acs]
  };
  if (sloMatch) {
    fields.samlSingleLogoutService = [sloMatch[1]];
  }
  var artifact = acs.replace(/\/samlacs$/, "/samlacs/artifact");
  if (artifact !== acs) {
    fields.samlAssertionConsumerService.push(artifact);
  }
  await registry.provision(stsOrigin, {
    identifier: entity,
    name: "Debugger SAML service provider",
    protocols: ["saml2", "saml11"],
    fields: fields,
    why: "the service provider the user-guide walk signs in as"
  });
  // An add normalises the certificate to bare base64 DER. The PEM the
  // textarea holds is the same key and would fail an exact compare.
  var added = await registry.adminPost(stsOrigin, "/applications/add", {
    application: entity,
    attribute: "samlSigningCertificate",
    value: body
  });
  if (!added || added.ok === false) {
    log.debug("Leaving registerServiceProvider(). Certificate refused.");
    throw new Error("could not register the signing certificate: " +
      JSON.stringify(added && added.errors || added).slice(0, 300));
  }
  var entry = await registry.entryOf(stsOrigin, entity);
  if (heldCertificateBodies(entry).indexOf(body) < 0) {
    log.debug("Leaving registerServiceProvider(). Certificate missing.");
    throw new Error("iya-sts did not store the signing certificate " +
                    "the page just generated.");
  }
  spRegistered = true;
  log.info("Registered " + entity + " with ACS " + acs + ".");
  log.debug("Leaving registerServiceProvider().");
}

async function installIssuedSigningKey(driver) {
  log.debug("Entering installIssuedSigningKey().");
  var passphrase = crypto.randomBytes(18).toString("base64url");
  var issued = await registry.adminPost(stsOrigin,
    "/users/issue-signing-certificate", {
      user: wstUser, keyAlg: "rsa-2048", password: passphrase
    });
  if (!issued || issued.ok === false || !issued.certificate ||
      !issued.files || !issued.files.key) {
    log.debug("Leaving installIssuedSigningKey(). Refused.");
    throw new Error("could not issue a message-signing certificate: " +
      JSON.stringify(issued && issued.errors ||
                     "no certificate in the reply").slice(0, 400));
  }
  var privateKey = crypto.createPrivateKey({
    key: issued.files.key.text, format: "pem", passphrase: passphrase
  });
  var pkcs8 = privateKey.export({ type: "pkcs8", format: "pem" });
  await setField(driver, "wst_sp_private_key", String(pkcs8));
  await setField(driver, "wst_sp_cert",
                 issued.certificate.certificatePem);
  log.debug("Leaving installIssuedSigningKey().");
}

async function samlGuide(driver) {
  log.debug("Entering samlGuide().");
  await loadPage(driver, baseUrl + "/saml_request.html",
                 "saml_metadata_url", { timeout: waitTime });
  await loadMetadata(driver, stsOrigin + "/saml2/metadata");
  await shot(driver, samlDir, "saml-redirect", "01-metadata", [
    "pane_metadata"
  ]);
  await shot(driver, samlDir, "saml-redirect", "02-configuration", [
    "pane_config"
  ]);
  await samlRoundTrip(driver, "redirect", samlUser);
  await samlLogout(driver);
  await loadPage(driver, baseUrl + "/saml_request.html",
                 "saml_metadata_url", { timeout: waitTime });
  await samlRoundTrip(driver, "post", samlUser);
  await loadPage(driver, baseUrl + "/saml_request.html",
                 "saml_metadata_url", { timeout: waitTime });
  await samlRoundTrip(driver, "artifact", samlUser);
  await saml11(driver, samlUser);
  log.debug("Leaving samlGuide().");
}

async function wstGuide(driver) {
  log.debug("Entering wstGuide().");
  var stsUrl = stsOrigin + "/sts";
  var token = await issueBearer(driver, stsUrl);
  await lifecycle(driver, stsUrl, token);
  await signedIssue(driver, stsUrl);
  await encryptedIssue(driver, stsUrl);
  var fresh = await issueBearer(driver, stsUrl, true);
  await delegation(driver, stsUrl, fresh);
  log.debug("Leaving wstGuide().");
}

function redactText(src) {
  log.debug("Entering redactText().");
  var password = new RegExp(
    "<(?:[\\w.-]+:)?Password\\b[^>]*>[\\s\\S]*?" +
    "</(?:[\\w.-]+:)?Password>", "gi");
  var text = String(src || "")
    .replace(/-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g,
             "[redacted key]")
    .replace(/otpauth:\/\/[^\s"'<>]+/gi, "otpauth://redacted")
    .replace(/<code>[^<]*<\/code>/gi, "<code>[redacted]</code>")
    .replace(password, "<Password>[redacted]</Password>");
  log.debug("Leaving redactText().");
  return text;
}

function redactPage(src) {
  log.debug("Entering redactPage().");
  var text = redactText(src).slice(0, 2500);
  log.debug("Leaving redactPage().");
  return text;
}

async function test() {
  log.debug("Entering test().");
  loadTotpFile();
  await prepareIdp();
  const options = new chrome.Options();
  if (headless) {
    options.addArguments("--headless=new");
  }
  options.addArguments("--no-sandbox");
  options.addArguments("--disable-dev-shm-usage");
  options.addArguments("--window-size=1280,1000");
  // Headless Chrome's User-Agent is an automated client. A product-mode
  // iya-sts scores a first sign-in from one as HIGH and the issuance
  // policy refuses it. The screen only says "Authentication failed".
  browserFlags.addDesktopUserAgent(options);
  browserFlags.addBrowserAccessFlags(options, baseUrl, [stsOrigin]);
  const loggingPrefs = new logging.Preferences();
  loggingPrefs.setLevel(logging.Type.BROWSER, logging.Level.ALL);
  const driver = await new Builder()
    .forBrowser("chrome")
    .setChromeOptions(options)
    .setLoggingPrefs(loggingPrefs)
    .build();
  var failed = false;
  try {
    await samlGuide(driver);
    await wstGuide(driver);
    log.info("User-guide walk completed.");
  } catch (error) {
    failed = true;
    log.error(redactText(error && error.stack ? error.stack :
                         String(error)));
    try {
      log.error("URL: " + (await driver.getCurrentUrl())
        .split("#")[0]);
      var src = await driver.getPageSource();
      log.error("Page (first 2500 chars):\n" + redactPage(src));
    } catch (e2) {
      log.error("Could not dump the page: " + e2.message);
    }
  } finally {
    await driver.quit();
  }
  if (failed) {
    log.debug("Leaving test(). Failed.");
    process.exit(1);
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("saml_wstrust_user_guide")
  .description("Walk the SAML and WS-Trust user-guide tutorials.")
  .addOption(new Option("-u, --url <url>", "debugger base URL")
    .default("https://localhost:3000"))
  .addOption(new Option("--sts <url>", "iya-sts origin")
    .default(process.env.WSTRUST_STS_URL || "https://localhost:8081"))
  .option("-b, --no-headless", "show the browser")
  .action(function (opts) {
    log.debug("Entering action().");
    baseUrl = String(opts.url).replace(/\/+$/, "");
    stsOrigin = String(opts.sts).replace(/\/+$/, "")
      .replace(/\/sts$/, "");
    headless = opts.headless !== false;
    samlDir = process.env.DOC_SCREENSHOT_DIR || "";
    wstDir = process.env.WSTRUST_SCREENSHOT_DIR || samlDir;
    waitTime = Math.max(waitTime, 20000);
    log.info("debugger=" + baseUrl + " sts=" + stsOrigin);
    log.debug("Leaving action().");
  });

program.parse(process.argv);
test();
