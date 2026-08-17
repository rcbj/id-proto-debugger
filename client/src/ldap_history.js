// File: ldap_history.js
//
// The Operations History log for the LDAP workflow — every operation this page
// asked the api to perform, newest first.
//
// Fifth sibling over ./op_history.js, and the simplest of the five, because
// LDAP has no page-to-page hand-off: the whole workflow is one page and every
// call is answered on the same page that made it. So there is no pending entry
// for a second page to resolve, and nothing here exports an operation label the
// way wsfed_history.js has to.
//
// What it does still need is the three RESULTS, and the middle one is not
// decorative. An operation is recorded `Sent` before the fetch and resolved
// afterwards; a row that stays `Sent` means the api never answered at all,
// which on this workflow is the difference between "the directory refused
// this" and "nothing came back". Those look identical in a status line and are
// the two things a person is most often trying to tell apart.
//
// It uses the `ldap-*` class prefix rather than the SAML family's `saml-*`,
// because ldap.html does not link css/saml_common.css — and a `saml-*` class
// on a page that never loaded that sheet is exactly what
// checkStylesheetsLoaded() in tests/navigation.js fails on. That mistake has
// been made once already, by the Kerberos pages.
var createHistory = require('./op_history').createHistory;

// The log level comes from the same configuration everything else here reads.
// A caller without one still has to be able to load this module, so an
// unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "ldap_history",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

module.exports = createHistory({
  storeKey: 'ldap_operation_history',
  emptyText: 'No directory operations recorded yet.',
  classPrefix: 'ldap',
  resultClasses: { ok: 'ldap-ok', bad: 'ldap-bad', pending: 'ldap-pending' },
  columns: [
    { key: 'operation', label: 'Operation' },
    { key: 'dn', label: 'DN / Base', className: 'ldap-history-dn' },
    { key: 'detailText', label: 'What was asked' },
    { key: 'code', label: 'Result code' },
    { key: 'server', label: 'Directory', className: 'ldap-history-uri' }
  ]
});
