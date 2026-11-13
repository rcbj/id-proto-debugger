// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: xacml_runtime.js
//
// Logger and XML escape for the XACML engine copied into this tree.
// The engine files call this the way they called iya-sts's helpers.
// This file lives in client/src so require(process.env.CONFIG_FILE)
// resolves client/src/env, the same way the other client modules do.
// A file under client/src/xacml/ would look for env beside itself.

'use strict';

var bunyan = require("bunyan");

var log = bunyan.createLogger({
  name: "xacml",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

/**
 * Escapes text for XML content and attribute values.
 *
 * @param {*} s - the value; null and undefined escape to ''
 * @returns {string} the escaped text
 */
function xmlEscape(s) {
  log.debug("Entering xmlEscape().");
  log.debug("Leaving xmlEscape().");
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}

module.exports = {
  log: log,
  xmlEscape: xmlEscape
};
