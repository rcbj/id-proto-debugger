// File: otp_verify.js
//
// What POST /otp/verify will and will not send. It decides; server.js
// posts the body. This file has no axios and no network, so a test
// can refuse a request with nothing listening on the far side.
//
// The page builds and signs the validation request. The API key stays
// in the browser. This service only checks the shape and posts the
// form. The address policy is the one already installed on axios.
// It is not reimplemented here.
//
// Three outcomes, the same three as POST /scim. A refusal by this
// service is a 400. A network failure is a 502. An answer from the
// verifier — including status=BAD_OTP and an HTTP 4xx — is a 200,
// because that answer is what the page exists to show.

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "otp_verify",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var MAX_BODY_BYTES = 2048;
var VERIFY_PATH = "/wsapi/2.0/verify";
var HOSTS = [
  "api.yubico.com",
  "api2.yubico.com",
  "api3.yubico.com",
  "api4.yubico.com",
  "api5.yubico.com"
];
var MODHEX = /^[cbdefghijklnrtuv]+$/;

function reject(message) {
  log.debug("Entering reject().");
  log.debug("Leaving reject().");
  return { ok: false, error: message };
}

function defaultUrl(which) {
  log.debug("Entering defaultUrl().");
  var n = which === undefined || which === null || which === "" ?
      1 : Number(which);
  if (!Number.isInteger(n) || n < 1 || n > HOSTS.length) {
    log.debug("Leaving defaultUrl(). Server.");
    return null;
  }
  var url = "https://" + HOSTS[n - 1] + VERIFY_PATH;
  log.debug("Leaving defaultUrl().");
  return url;
}

function formFields(text) {
  log.debug("Entering formFields().");
  var parts = String(text).split("&");
  var fields = {};
  var i = 0;
  for (i = 0; i < parts.length; i++) {
    if (!parts[i]) {
      continue;
    }
    var eq = parts[i].indexOf("=");
    if (eq < 1) {
      log.debug("Leaving formFields(). Line.");
      return null;
    }
    var name = parts[i].slice(0, eq);
    var value = parts[i].slice(eq + 1);
    try {
      name = decodeURIComponent(name);
      value = decodeURIComponent(value.replace(/\+/g, "%2B"));
    } catch (e) {
      log.debug("Leaving formFields(). Encoding.");
      return null;
    }
    fields[name] = value;
  }
  log.debug("Leaving formFields().");
  return fields;
}

function otpOk(otp) {
  log.debug("Entering otpOk().");
  var s = String(otp || "");
  var ok = s.length >= 32 && s.length <= 48 && (s.length % 2) === 0 &&
      MODHEX.test(s);
  log.debug("Leaving otpOk().");
  return ok;
}

function checkVerifier(raw) {
  log.debug("Entering checkVerifier().");
  var text = String(raw || "").trim();
  if (!text || /[\r\n]/.test(text)) {
    log.debug("Leaving checkVerifier(). Empty.");
    return reject("The verifier URL is empty.");
  }
  var url = null;
  try {
    url = new URL(text);
  } catch (e) {
    log.debug("Leaving checkVerifier(). Parse.");
    return reject("The verifier URL is not a URL.");
  }
  if (url.protocol !== "https:") {
    log.debug("Leaving checkVerifier(). Scheme.");
    return reject("The verifier URL is https.");
  }
  if (url.username || url.password) {
    log.debug("Leaving checkVerifier(). Userinfo.");
    return reject("The verifier URL has no userinfo.");
  }
  if (url.search) {
    log.debug("Leaving checkVerifier(). Query.");
    return reject("The verifier URL has no query string.");
  }
  if (text.indexOf("..") >= 0) {
    log.debug("Leaving checkVerifier(). Path.");
    return reject("The verifier path must not contain '..'.");
  }
  log.debug("Leaving checkVerifier().");
  return { ok: true, url: url.origin + url.pathname };
}

function describeRequest(given) {
  log.debug("Entering describeRequest().");
  var body = given || {};
  var form = body.body;
  if (typeof form !== "string") {
    log.debug("Leaving describeRequest(). Body.");
    return reject("The validation body is a form.");
  }
  if (/[\r\n]/.test(form)) {
    log.debug("Leaving describeRequest(). Line break.");
    return reject("The validation body has a line break.");
  }
  if (Buffer.byteLength(form, "utf8") > MAX_BODY_BYTES) {
    log.debug("Leaving describeRequest(). Size.");
    return reject("The validation body is longer than " +
        MAX_BODY_BYTES + " bytes.");
  }
  var fields = formFields(form);
  if (!fields) {
    log.debug("Leaving describeRequest(). Fields.");
    return reject("The validation body is not a form.");
  }
  var allowed = { id: 1, otp: 1, nonce: 1, h: 1, sl: 1, timeout: 1,
      timestamp: 1 };
  var name = null;
  for (name in fields) {
    if (Object.prototype.hasOwnProperty.call(fields, name) &&
        !allowed[name]) {
      log.debug("Leaving describeRequest(). Field.");
      return reject("The validation body has an unknown field.");
    }
  }
  if (!fields.id || !/^[0-9]+$/.test(fields.id)) {
    log.debug("Leaving describeRequest(). Id.");
    return reject("The client id is digits.");
  }
  if (!otpOk(fields.otp)) {
    log.debug("Leaving describeRequest(). OTP.");
    return reject("A Yubico OTP is 32 to 48 modhex characters. " +
        "The current form is 44.");
  }
  if (!/^[A-Za-z0-9]{16,40}$/.test(fields.nonce || "")) {
    log.debug("Leaving describeRequest(). Nonce.");
    return reject("A validation nonce is 16 to 40 letters and digits.");
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(fields.h || "")) {
    log.debug("Leaving describeRequest(). HMAC.");
    return reject("The signature is base64.");
  }
  var target = null;
  if (body.verifier) {
    var checked = checkVerifier(body.verifier);
    if (!checked.ok) {
      log.debug("Leaving describeRequest(). Verifier.");
      return checked;
    }
    target = checked.url;
  } else {
    target = defaultUrl(body.server);
    if (!target) {
      log.debug("Leaving describeRequest(). Server.");
      return reject("The YubiCloud server is 1 to " + HOSTS.length + ".");
    }
  }
  var sslValidate = !(body.sslValidate === false ||
      body.sslValidate === "false");
  log.debug("Leaving describeRequest().");
  return {
    ok: true,
    url: target,
    body: form,
    sslValidate: sslValidate
  };
}

function readResponse(status, text) {
  log.debug("Entering readResponse().");
  var out = {
    ok: status >= 200 && status < 300,
    status: status,
    body: text == null ? "" : String(text)
  };
  log.debug("Leaving readResponse().");
  return out;
}

function limits() {
  log.debug("Entering limits().");
  var out = {
    maxBodyBytes: MAX_BODY_BYTES,
    contentType: "application/x-www-form-urlencoded",
    defaultVerifier: defaultUrl(1),
    servers: HOSTS.map(function (host, index) {
      return { server: index + 1, host: host };
    }),
    note: "The API key stays in the browser. This service posts a " +
        "request the page already signed."
  };
  log.debug("Leaving limits().");
  return out;
}

module.exports = {
  MAX_BODY_BYTES: MAX_BODY_BYTES,
  HOSTS: HOSTS,
  describeRequest: describeRequest,
  readResponse: readResponse,
  limits: limits,
  defaultUrl: defaultUrl
};
