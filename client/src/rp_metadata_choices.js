// File: rp_metadata_choices.js
//
// ---------------------------------------------------------------------------
// OpenID Connect RP Metadata Choices 1.0 — the relying party's half.
//
// A choice member is a JSON array of values this client can use. Each one
// has a single-valued partner. Section 2: the arrays are registration
// input. A registration response and a later read carry the partner, the
// value the provider selected. Section 4: send both, with the preferred
// value in the partner, and that value is a member of the array.
//
// "Can use" is this client's own code. The signing list is read from
// jws.js and the encryption lists from jose_jwe.js, so an algorithm added
// there enters the registration request with it. A choice whose set is
// empty is omitted from the generated request and still checked when a
// hand-edited request contains it.
//
// Section 3 uses token_endpoint_auth_methods_supported as the client's
// authentication list at the token, revocation, introspection and pushed
// authorization endpoints. The two endpoint-specific auth-method names are
// not client metadata.
//
// No DOM. The registration pane calls in with the metadata object and
// paints what comes back. tests/rp_metadata_choices.js loads this file in
// node for that reason.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var jws = require("./jws");
var jose = require("./jose_jwe");

// The log level comes from the same configuration the pages use. A node
// test may not have one, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "rp_metadata_choices",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// Core 1.0 section 8.1: with pairwise subjects, redirect URIs on more
// than one host need a sector_identifier_uri, which the provider fetches
// and checks against those URIs. This client cannot publish one, so it
// stops offering pairwise rather than naming a document nobody serves.

// Section 3. These names are discovery metadata, not client metadata.
var NOT_CLIENT_CHOICES = [
  "revocation_endpoint_auth_methods_supported",
  "introspection_endpoint_auth_methods_supported"
];

// The nineteen members in section 2, in the order that section lists the
// families. `from` is the specification that defines the partner.
var CHOICES = [
  { choice: "subject_types_supported",
    partner: "subject_type",
    from: "OpenID Connect Core 1.0" },
  { choice: "id_token_signing_alg_values_supported",
    partner: "id_token_signed_response_alg",
    from: "OpenID Connect Dynamic Client Registration 1.0" },
  { choice: "id_token_encryption_alg_values_supported",
    partner: "id_token_encrypted_response_alg",
    from: "OpenID Connect Dynamic Client Registration 1.0" },
  { choice: "id_token_encryption_enc_values_supported",
    partner: "id_token_encrypted_response_enc",
    from: "OpenID Connect Dynamic Client Registration 1.0" },
  { choice: "userinfo_signing_alg_values_supported",
    partner: "userinfo_signed_response_alg",
    from: "OpenID Connect Core 1.0 section 5.3.2" },
  { choice: "userinfo_encryption_alg_values_supported",
    partner: "userinfo_encrypted_response_alg",
    from: "OpenID Connect Core 1.0 section 5.3.2" },
  { choice: "userinfo_encryption_enc_values_supported",
    partner: "userinfo_encrypted_response_enc",
    from: "OpenID Connect Core 1.0 section 5.3.2" },
  { choice: "request_object_signing_alg_values_supported",
    partner: "request_object_signing_alg",
    from: "OpenID Connect Dynamic Client Registration 1.0" },
  { choice: "request_object_encryption_alg_values_supported",
    partner: "request_object_encryption_alg",
    from: "OpenID Connect Dynamic Client Registration 1.0" },
  { choice: "request_object_encryption_enc_values_supported",
    partner: "request_object_encryption_enc",
    from: "OpenID Connect Dynamic Client Registration 1.0" },
  { choice: "token_endpoint_auth_methods_supported",
    partner: "token_endpoint_auth_method",
    from: "OpenID Connect Dynamic Client Registration 1.0" },
  { choice: "token_endpoint_auth_signing_alg_values_supported",
    partner: "token_endpoint_auth_signing_alg",
    from: "OpenID Connect Dynamic Client Registration 1.0" },
  { choice: "backchannel_authentication_request_signing_alg_" +
        "values_supported",
    partner: "backchannel_authentication_request_signing_alg",
    from: "OpenID Connect Client-Initiated Backchannel " +
        "Authentication" },
  { choice: "authorization_signing_alg_values_supported",
    partner: "authorization_signed_response_alg",
    from: "JWT Secured Authorization Response Mode" },
  { choice: "authorization_encryption_alg_values_supported",
    partner: "authorization_encrypted_response_alg",
    from: "JWT Secured Authorization Response Mode" },
  { choice: "authorization_encryption_enc_values_supported",
    partner: "authorization_encrypted_response_enc",
    from: "JWT Secured Authorization Response Mode" },
  { choice: "introspection_signing_alg_values_supported",
    partner: "introspection_signed_response_alg",
    from: "RFC 9701" },
  { choice: "introspection_encryption_alg_values_supported",
    partner: "introspection_encrypted_response_alg",
    from: "RFC 9701" },
  { choice: "introspection_encryption_enc_values_supported",
    partner: "introspection_encrypted_response_enc",
    from: "RFC 9701" }
];

// Header `alg` values jws.js can verify, except `none`. algIds() returns
// table keys, and EdDSA is two keys with one header value, so the wire
// value is spec.alg and duplicates are dropped. OIDC forbids `none` for
// an ID Token except a narrow case this client does not implement.
function signingAlgValues() {
  log.debug("Entering signingAlgValues().");
  var seen = {};
  var values = [];
  jws.algIds().forEach(function (id) {
    var spec = jws.algSpec(id);
    if (!spec || spec.alg === "none" || spec.family === "none") {
      return;
    }
    if (seen[spec.alg]) {
      return;
    }
    seen[spec.alg] = true;
    values.push(spec.alg);
  });
  log.debug("Leaving signingAlgValues().");
  return values;
}

function pushChoice(rows, choice, partner, values, preferred) {
  log.debug("Entering pushChoice(). choice=" + choice);
  if (!values || !values.length || values.indexOf(preferred) < 0) {
    log.debug("Leaving pushChoice(). No usable set.");
    return;
  }
  rows.push({
    choice: choice,
    partner: partner,
    values: values.slice(),
    preferred: preferred
  });
  log.debug("Leaving pushChoice().");
}

// The pairs this client can actually offer. Empty sets are absent, which
// is what makes the generated request omit them.
function supportedChoices() {
  log.debug("Entering supportedChoices().");
  var signing = signingAlgValues();
  var userinfoSigning = signing.slice();
  if (userinfoSigning.indexOf("none") < 0) {
    userinfoSigning.push("none");
  }
  var rows = [];
  pushChoice(rows, "subject_types_supported", "subject_type",
      ["public", "pairwise"], "public");
  pushChoice(rows, "id_token_signing_alg_values_supported",
      "id_token_signed_response_alg", signing, "RS256");
  pushChoice(rows, "userinfo_signing_alg_values_supported",
      "userinfo_signed_response_alg", userinfoSigning, "RS256");
  pushChoice(rows, "userinfo_encryption_alg_values_supported",
      "userinfo_encrypted_response_alg", jose.supportedAlgs(),
      "RSA-OAEP-256");
  pushChoice(rows, "userinfo_encryption_enc_values_supported",
      "userinfo_encrypted_response_enc", jose.supportedEncs(),
      "A128CBC-HS256");
  pushChoice(rows, "token_endpoint_auth_methods_supported",
      "token_endpoint_auth_method", ["client_secret_basic"],
      "client_secret_basic");
  log.debug("Leaving supportedChoices().");
  return rows;
}

function omittedChoices() {
  log.debug("Entering omittedChoices().");
  var live = {};
  supportedChoices().forEach(function (row) {
    live[row.choice] = true;
  });
  var names = [];
  CHOICES.forEach(function (row) {
    if (!live[row.choice]) {
      names.push(row.choice);
    }
  });
  log.debug("Leaving omittedChoices().");
  return names;
}

function isObject(value) {
  log.debug("Entering isObject().");
  var ok = !!value && typeof value === "object" && !Array.isArray(value);
  log.debug("Leaving isObject().");
  return ok;
}

function shallowCopy(source) {
  log.debug("Entering shallowCopy().");
  var copy = {};
  if (!isObject(source)) {
    log.debug("Leaving shallowCopy(). Not an object.");
    return copy;
  }
  Object.keys(source).forEach(function (key) {
    copy[key] = source[key];
  });
  log.debug("Leaving shallowCopy().");
  return copy;
}

// The number of distinct hosts among the redirect URIs. A value that
// does not parse as a URL counts as a host of its own.
function redirectHostCount(redirects) {
  log.debug("Entering redirectHostCount().");
  var hosts = {};
  var count = 0;
  var list = Array.isArray(redirects) ? redirects : [];
  list.forEach(function (uri) {
    var host;
    try {
      host = new URL(String(uri)).host.toLowerCase();
    } catch (e) {
      host = "unparsed:" + String(uri);
    }
    if (!hosts[host]) {
      hosts[host] = true;
      count = count + 1;
    }
  });
  log.debug("Leaving redirectHostCount().");
  return count;
}

function sectorMissing(metadata) {
  log.debug("Entering sectorMissing().");
  var value = metadata.sector_identifier_uri;
  var missing = typeof value !== "string" || value.trim() === "";
  log.debug("Leaving sectorMissing().");
  return missing;
}

// "" when the value is a usable string array, otherwise the rule id.
function arrayRule(value) {
  log.debug("Entering arrayRule().");
  var i;
  if (!Array.isArray(value)) {
    log.debug("Leaving arrayRule(). Not an array.");
    return "not-array";
  }
  if (value.length === 0) {
    log.debug("Leaving arrayRule(). Empty.");
    return "empty-array";
  }
  for (i = 0; i < value.length; i++) {
    if (typeof value[i] !== "string" || value[i].length === 0) {
      log.debug("Leaving arrayRule(). Bad item.");
      return "not-array";
    }
  }
  log.debug("Leaving arrayRule().");
  return "";
}

function finding(member, rule, message) {
  log.debug("Entering finding().");
  log.debug("Leaving finding().");
  return { member: member, rule: rule, message: message };
}

// Merge the supported pairs into a copy. Members this function does not
// own stay as they are. Each partner it writes is a member of the array
// it writes. The two section 3 names are removed.
function applyChoices(metadata) {
  log.debug("Entering applyChoices().");
  var md = shallowCopy(metadata);
  var i;
  for (i = 0; i < NOT_CLIENT_CHOICES.length; i++) {
    delete md[NOT_CLIENT_CHOICES[i]];
  }
  supportedChoices().forEach(function (row) {
    md[row.choice] = row.values.slice();
    md[row.partner] = row.preferred;
  });
  var subjects = md.subject_types_supported;
  var pairwise = Array.isArray(subjects) &&
      subjects.indexOf("pairwise") >= 0;
  if (pairwise && redirectHostCount(md.redirect_uris) > 1 &&
      sectorMissing(md)) {
    md.subject_types_supported = subjects.filter(function (value) {
      return value !== "pairwise";
    });
  }
  log.debug("Leaving applyChoices().");
  return md;
}

function supportedByName() {
  log.debug("Entering supportedByName().");
  var map = {};
  supportedChoices().forEach(function (row) {
    map[row.choice] = row;
  });
  log.debug("Leaving supportedByName().");
  return map;
}

function checkRequest(metadata) {
  log.debug("Entering checkRequest().");
  var findings = [];
  var i;
  var name;
  var row;
  var rule;
  var values;
  var known;
  if (!isObject(metadata)) {
    findings.push(finding("", "not-object",
        "Client metadata must be a JSON object."));
    log.debug("Leaving checkRequest(). Not an object.");
    return findings;
  }
  for (i = 0; i < NOT_CLIENT_CHOICES.length; i++) {
    name = NOT_CLIENT_CHOICES[i];
    if (Object.prototype.hasOwnProperty.call(metadata, name)) {
      findings.push(finding(name, "section-3",
          name + " is not client metadata. Section 3 uses " +
          "token_endpoint_auth_methods_supported for every endpoint " +
          "that authenticates the client."));
    }
  }
  known = supportedByName();
  for (i = 0; i < CHOICES.length; i++) {
    row = CHOICES[i];
    if (!Object.prototype.hasOwnProperty.call(metadata, row.choice)) {
      continue;
    }
    values = metadata[row.choice];
    rule = arrayRule(values);
    if (rule === "empty-array") {
      findings.push(finding(row.choice, "empty-array",
          row.choice + " is empty. Omit the member when none of its " +
          "values can be used."));
    } else if (rule) {
      findings.push(finding(row.choice, "not-array",
          row.choice + " must be an array of non-empty strings."));
    } else {
      checkValues(findings, row, values, known[row.choice]);
    }
    if (Object.prototype.hasOwnProperty.call(metadata, row.partner) &&
        Array.isArray(values) &&
        values.indexOf(metadata[row.partner]) < 0) {
      findings.push(finding(row.choice, "partner-not-in-list",
          row.partner + " is " + JSON.stringify(metadata[row.partner]) +
          ", which is not a member of " + row.choice + "."));
    }
  }
  checkSector(findings, metadata);
  log.debug("Leaving checkRequest(). findings=" + findings.length);
  return findings;
}

function checkValues(findings, row, values, supported) {
  log.debug("Entering checkValues(). choice=" + row.choice);
  var allowed = supported ? supported.values : [];
  var i;
  for (i = 0; i < values.length; i++) {
    if (allowed.indexOf(values[i]) < 0) {
      findings.push(finding(row.choice, "outside-supported-set",
          row.choice + " lists " + JSON.stringify(values[i]) +
          ", which this client cannot use."));
    }
  }
  log.debug("Leaving checkValues().");
}

function checkSector(findings, metadata) {
  log.debug("Entering checkSector().");
  var subjects = metadata.subject_types_supported;
  var redirects = metadata.redirect_uris;
  var pairwise = Array.isArray(subjects) &&
      subjects.indexOf("pairwise") >= 0;
  var many = redirectHostCount(redirects) > 1;
  if (pairwise && many && sectorMissing(metadata)) {
    findings.push(finding("sector_identifier_uri",
        "sector-identifier-required",
        "pairwise is offered with redirect_uris on more than one " +
        "host, so " +
        "sector_identifier_uri is required."));
  }
  log.debug("Leaving checkSector().");
}

// Read a registration response against the request that was sent.
//
// The adopted metadata starts as a copy of the response, so server-issued
// fields (client_id, client_secret, and the rest of a Registration 1.0
// response) stay. A choice array in the response is a section 2 finding:
// it is removed and the array that was sent is restored, so the next
// request is section 4 input again. A returned partner is adopted only
// when it is a member of the array that was sent. A partner outside that
// array is a finding and the preferred value stays. A different partner
// that is inside the offered array is the section 4 selection.
function readResponse(sent, received) {
  log.debug("Entering readResponse().");
  var sentObj = isObject(sent) ? sent : {};
  var receivedObj = isObject(received) ? received : {};
  var metadata = shallowCopy(receivedObj);
  var findings = [];
  var rows = [];
  var i;
  for (i = 0; i < CHOICES.length; i++) {
    adoptOne(CHOICES[i], sentObj, receivedObj, metadata, findings, rows);
  }
  log.debug("Leaving readResponse().");
  return { metadata: metadata, findings: findings, rows: rows };
}

function adoptOne(row, sentObj, receivedObj, metadata, findings, rows) {
  log.debug("Entering adoptOne(). choice=" + row.choice);
  var sentHasArray = Object.prototype.hasOwnProperty.call(
      sentObj, row.choice);
  var sentArray = sentHasArray && Array.isArray(sentObj[row.choice]) ?
      sentObj[row.choice].slice() : null;
  var sentHasPartner = Object.prototype.hasOwnProperty.call(
      sentObj, row.partner);
  var sentPartner = sentHasPartner ? sentObj[row.partner] : undefined;
  var responseHasArray = Object.prototype.hasOwnProperty.call(
      receivedObj, row.choice);
  var responseHasPartner = Object.prototype.hasOwnProperty.call(
      receivedObj, row.partner);
  var returned = responseHasPartner ? receivedObj[row.partner] : undefined;
  var adopted;

  if (responseHasArray) {
    findings.push(finding(row.choice, "section-2-output",
        row.choice + " is registration input. A response carries " +
        row.partner + ", the value the provider selected."));
    delete metadata[row.choice];
  }
  if (sentArray) {
    metadata[row.choice] = sentArray.slice();
  }

  if (responseHasPartner && sentArray &&
      sentArray.indexOf(returned) >= 0) {
    metadata[row.partner] = returned;
    adopted = returned;
  } else if (responseHasPartner && sentArray) {
    findings.push(finding(row.choice, "partner-outside-offered",
        row.partner + " is " + JSON.stringify(returned) +
        ", which is outside the array this client offered."));
    if (sentHasPartner) {
      metadata[row.partner] = sentPartner;
      adopted = sentPartner;
    } else {
      delete metadata[row.partner];
    }
  } else if (!responseHasPartner && sentHasPartner) {
    metadata[row.partner] = sentPartner;
    adopted = sentPartner;
  } else if (responseHasPartner) {
    adopted = returned;
  }

  if (sentArray || responseHasArray || responseHasPartner) {
    rows.push({
      member: row.choice,
      partner: row.partner,
      offered: sentArray ? sentArray.slice() : [],
      preferred: sentHasPartner ? sentPartner : null,
      returned: responseHasPartner ? returned : null,
      adopted: typeof adopted === "undefined" ? null : adopted
    });
  }
  log.debug("Leaving adoptOne().");
}

module.exports = {
  CHOICES: CHOICES,
  NOT_CLIENT_CHOICES: NOT_CLIENT_CHOICES,
  supportedChoices: supportedChoices,
  omittedChoices: omittedChoices,
  applyChoices: applyChoices,
  checkRequest: checkRequest,
  readResponse: readResponse
};
