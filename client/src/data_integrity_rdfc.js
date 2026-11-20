// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: data_integrity_rdfc.js
//
// ---------------------------------------------------------------------------
// data_integrity.js WITH RDFC-1.0: loading this module registers jsonld's
// canonicalizer with data_integrity.js and answers that module, so the RDFC
// cryptosuites (eddsa-rdfc-2022, ecdsa-rdfc-2019) and every legacy Linked
// Data proof type work on the page that loaded it. It is a separate module so
// that the pages which never read JSON-LD do not carry jsonld and
// rdf-canonize in their bundles; see the note in data_integrity.js.
// ---------------------------------------------------------------------------

var jsonld = require("jsonld");
var dataIntegrity = require("./data_integrity");

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "data_integrity_rdfc",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

function canonize(doc, options) {
  log.debug("Entering canonize().");
  log.debug("Leaving canonize().");
  return jsonld.canonize(doc, options);
}

dataIntegrity.registerRdfc(canonize, jsonld);
// BbsBlsSignature2020 and its derived proofs need RDFC and the jsonld
// library, both of which are loaded by now; requiring it registers it.
require("./bbs_bls_2020");
// ecdsa-sd-2023 needs RDFC-1.0 too; requiring it registers it (#476).
require("./ecdsa_sd_2023");
log.debug("data_integrity_rdfc: RDFC-1.0 registered.");

module.exports = dataIntegrity;
