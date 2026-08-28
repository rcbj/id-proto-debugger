// File: scim_history.js
//
// The Operations History log for the SCIM workflow — every request this page
// sent, newest first.
//
// Sixth sibling over ./op_history.js, and like the LDAP one it has no
// page-to-page hand-off: the whole workflow is one page and every call is
// answered on the page that made it. So there is no pending entry for a second
// page to resolve and nothing here exports an operation label.
//
// What it does need, and needs more than any of the five before it, is the
// three RESULTS — because this is the workflow where a row means something a
// reader will act on:
//
//   * **Success** is a 2xx.
//   * **Failure** is a status the server chose. A 409 `uniqueness`, a 404, a
//     403 from an access control policy: the exchange worked and the answer was
//     no. That is a failure of the OPERATION and it is very often the correct
//     outcome — the negative scenarios expect several of them.
//   * **Sent**, still, means nothing came back at all. On this workflow that is
//     usually CORS refusing a browser-direct call before it was made, and it is
//     the state most often confused with the one above it: "the server said no"
//     and "the request never left" look identical in a status line and need
//     completely different fixes.
//
// A scenario run records one row per step, which is the point of keeping this
// log rather than only the Exchange pane: a fifty-step run has one exchange
// visible and fifty results worth reading afterwards.
//
// It uses the `scim-*` class prefix rather than the SAML family's `saml-*`,
// because scim.html does not link css/saml_common.css — and a `saml-*` class on
// a page that never loaded that sheet is exactly what checkStylesheetsLoaded()
// in tests/navigation.js fails on. That mistake has been made twice already, by
// the Kerberos pages and by WS-Federation.
var createHistory = require('./op_history').createHistory;

// The log level comes from the same configuration everything else here reads.
// A caller without one still has to be able to load this module, so an
// unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "scim_history",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

module.exports = createHistory({
  storeKey: 'scim_operation_history',
  emptyText: 'No SCIM requests recorded yet.',
  classPrefix: 'scim',
  resultClasses: { ok: 'scim-ok', bad: 'scim-bad', pending: 'scim-pending' },
  columns: [
    { key: 'operation', label: 'Operation' },
    { key: 'target', label: 'Request', className: 'scim-history-target' },
    { key: 'detailText', label: 'What it was for' },
    { key: 'server', label: 'Server', className: 'scim-history-uri' }
  ]
});
