// File: saml_history.js
//
// The Operations History log for the SAML workflow — every attempted call to
// the IdP, shared between the page that makes the call and the page that learns
// the outcome:
//
//   saml_request.html   records the attempt, then hands the browser to the IdP;
//   saml_response.html  sees what the IdP actually answered, and resolves it.
//
// Behaviour (Failure / Sent / Success, the cap, the rendering) lives in
// ./op_history.js, which the WS-Trust workflow instantiates the same way with
// its own key and columns.

var createHistory = require('./op_history').createHistory;

module.exports = createHistory({
  storeKey: 'samltools_operation_history',
  emptyText: 'No IdP calls recorded yet.',
  columns: [
    { key: 'operation', label: 'Operation' },
    { key: 'binding', label: 'Binding' },
    { key: 'version', label: 'Version' },
    { key: 'spEntityId', label: 'SP entityID', className: 'saml-history-uri' },
    { key: 'idpEntityId', label: 'IdP entityID', className: 'saml-history-uri' },
  ],
});
