// File: pki_history.js
//
// The PKI page's Operations History — the fifth sibling over
// client/src/op_history.js, after SAML, WS-Trust, WS-Federation and Kerberos.
//
// What it logs is not a call to somebody else's server, which is what makes it
// worth having here: three of the four operations on this page (generate a key,
// issue a certificate, export a keystore) never leave the browser, and the
// fourth (the TLS test) is the only one that does. A record of "issued a
// tls-client certificate from the Issuing CA with sha384-ecdsa at 14:02" is
// what makes a failing handshake ten minutes later diagnosable — the question
// is always which certificate was presented, and the store holds the answer
// while this holds the sequence.
//
// The page does not link css/saml_common.css's siblings' stylesheets by
// accident: it links that sheet deliberately (see pki.html), so the default
// `saml` class prefix is correct here and the classes it emits are defined in a
// stylesheet this page actually loads. That is what checkStylesheetsLoaded() in
// tests/navigation.js checks, and it is why kerberos_history.js has to pass a
// prefix and this does not.

var createHistory = require('./op_history').createHistory;

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "pki_history",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// The operation labels, exported for the same reason wsfed_history.js exports
// its two: a pending row is opened under one of these strings and closed by
// matching that same string, so spelling it twice is a row that never closes.
var OP_GENERATE_KEY = 'Generate key pair';
var OP_ISSUE = 'Issue certificate';
var OP_EXPORT = 'Export keystore';
var OP_TLS = 'TLS test connection';

var history = createHistory({
  storeKey: 'pki_operation_history',
  emptyText: 'No PKI operations recorded yet.',
  columns: [
    { key: 'operation', label: 'Operation' },
    { key: 'subject', label: 'Subject / target',
     className: 'saml-history-uri' },
    { key: 'algorithm', label: 'Algorithm' },
    { key: 'issuer', label: 'Issued by', className: 'saml-history-uri' }
  ]
});

history.OP_GENERATE_KEY = OP_GENERATE_KEY;
history.OP_ISSUE = OP_ISSUE;
history.OP_EXPORT = OP_EXPORT;
history.OP_TLS = OP_TLS;

log.debug("pki_history loaded.");

module.exports = history;
