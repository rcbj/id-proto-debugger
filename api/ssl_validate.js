// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: api/ssl_validate.js
//
// ---------------------------------------------------------------------------
// WHETHER AN OUTBOUND CALL VERIFIES THE FAR END'S CERTIFICATE, read from the
// `sslValidate` a page sent (#434).
//
// The pages send what an <input type="radio"> holds, which is TEXT: the
// OAuth 2.0 / OIDC pages post `sslValidate: "false"` for "SSL Validate: No".
// Until #434 the token, revoke, token exchange, device authorization and
// registration handlers handed that straight to outboundHttpsAgent(), which
// turns verification off only for a JSON `false` — so "No" verified anyway,
// and a self-signed token endpoint failed with a TLS error the user had
// asked not to see. /wstrust and /krb5/spnego already read both spellings;
// this is that one rule, for every handler.
//
// ONLY `false` OR "false" TURNS VERIFICATION OFF. Anything else — absent,
// null, "no", "False ", 0, a typo — verifies, because a missing or odd
// value must fail toward checking certificates, not away from it.
// ---------------------------------------------------------------------------

'use strict';

var bunyan = require('bunyan');
var log = bunyan.createLogger({
  name: 'ssl_validate',
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || 'info';
    } catch (e) {
      return 'info';
    }
  })()
});

/**
 * @param {*} value - a request's `sslValidate`, as it arrived.
 * @returns {boolean} false only for `false` or "false"; true otherwise.
 */
function verifiesCertificates(value) {
  log.debug('Entering verifiesCertificates().');
  const off = value === false || value === 'false';
  log.debug('Leaving verifiesCertificates(). ' + !off);
  return !off;
}

module.exports = { verifiesCertificates: verifiesCertificates };
