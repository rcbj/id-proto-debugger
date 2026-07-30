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
