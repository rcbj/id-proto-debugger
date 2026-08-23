// File: spiffe_history.js
//
// The Operations History log for the SPIFFE workflow — every call this page
// asked the api to make, newest first.
//
// Sixth sibling over ./op_history.js, and like ldap_history.js it is one of the
// simple ones: SPIFFE is a single page, so every call is answered on the page
// that made it and there is no pending entry for a second page to resolve.
//
// The three RESULTS carry more here than anywhere else this pattern is used,
// because on this workflow there are FOUR outcomes and only three colours:
//
//   Success   a gRPC status of OK.
//   Failure   a gRPC status that is not OK — PERMISSION_DENIED,
//             UNAUTHENTICATED, UNIMPLEMENTED, INVALID_ARGUMENT. The far end
//             ANSWERED and the answer was no, which on this surface is usually
//             the most interesting thing that can happen. So the status column
//             carries the code, and the row is not the end of the story.
//   Sent      the api never answered at all. Different from Failure, and the
//             two look identical in a status line.
//
// The fourth is a refusal by the api itself, and it is recorded as Failure with
// the api's own code in the status column (ESPIFFEPORTNOTALLOWED and its
// family) rather than as a gRPC status — because no gRPC call was ever made,
// and a row claiming a status the far end never sent would be a lie about
// where the refusal came from.
//
// It uses the `spiffe-*` class prefix rather than the SAML family's `saml-*`,
// because spiffe.html does not link css/saml_common.css — and a `saml-*` class
// on a page that never loaded that sheet is what checkStylesheetsLoaded() in
// tests/navigation.js fails on.
var createHistory = require('./op_history').createHistory;

module.exports = createHistory({
  storeKey: 'spiffe_operation_history',
  emptyText: 'No SPIFFE calls recorded yet.',
  classPrefix: 'spiffe',
  resultClasses: { ok: 'spiffe-ok', bad: 'spiffe-bad',
                   pending: 'spiffe-pending' },
  columns: [
    { key: 'operation', label: 'Method' },
    { key: 'surface', label: 'Surface' },
    { key: 'detailText', label: 'What was asked' },
    { key: 'code', label: 'Status' },
    { key: 'server', label: 'Address', className: 'spiffe-history-uri' }
  ]
});
