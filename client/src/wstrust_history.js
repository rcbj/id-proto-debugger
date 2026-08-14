// File: wstrust_history.js
//
// The Operations History log for the WS-Trust workflow — every attempted call
// to the STS, shared between the page that makes the call and the page that
// learns the outcome:
//
//   wstrust_tools.html     records the attempt, then navigates to the response;
//   wstrust_response.html  sees the RSTR (or the SOAP Fault), and resolves it.
//
// Same store and behaviour as the SAML log (./op_history.js), with the columns
// that matter here: the WS-Trust protocol version, the operation, and the user
// the request was made as.
var createHistory = require('./op_history').createHistory;

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "wstrust_history",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

module.exports = createHistory({
  storeKey: 'wstrust_operation_history',
  emptyText: 'No STS calls recorded yet.',
  columns: [
    { key: 'operation', label: 'Operation' },
    { key: 'version', label: 'WS-Trust Version' },
    { key: 'user', label: 'User' },
    { key: 'endpoint', label: 'STS Endpoint', className: 'saml-history-uri' },
  ],
});
