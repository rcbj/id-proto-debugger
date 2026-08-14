// File: wsfed_history.js
//
// The Operations History log for the WS-Federation workflow — every attempted
// call to the IdP, shared between the page that makes the call and the page
// that learns the outcome:
//
//   wsfed_request.html   records the attempt, then hands the browser to the IdP;
//   wsfed_response.html  sees the wresult the IdP auto-POSTed back, and resolves it.
//
// The third sibling of ./saml_history.js and ./wstrust_history.js. Behaviour —
// Failure / Sent / Success, the cap, the rendering — lives in ./op_history.js,
// which all three instantiate with their own key and columns.
//
// **The two operation labels are exported from here on purpose.** The passive
// profile has exactly two operations and both pages have to agree on their
// spelling: the request page writes a pending entry under one of these strings
// and the response page resolves it by matching that same string
// (`resolvePending(result, detail, match)`). A label written out by hand in two
// files is a pending row that never closes — it stays `Sent` for ever, which
// reads as "the IdP never answered" when in fact the two pages simply disagreed
// about a word. `tests/wsfed_sso.js` asserts the sign-out label against this
// module's value for the same reason.

var createHistory = require('./op_history').createHistory;

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "wsfed_history",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// The `wa` values of the WS-Federation Passive Requestor Profile, spelled the
// way the profile spells them, because that is what the user sees on the wire.
var OP_SIGN_IN = 'Sign In (wsignin1.0)';
var OP_SIGN_OUT = 'Sign Out (wsignout1.0)';

var history = createHistory({
  storeKey: 'wsfed_operation_history',
  emptyText: 'No IdP calls recorded yet.',
  columns: [
    { key: 'operation', label: 'Operation' },
    { key: 'wtrealm', label: 'wtrealm (RP)', className: 'saml-history-uri' },
    { key: 'wreply', label: 'wreply', className: 'saml-history-uri' },
    { key: 'idp', label: 'IdP endpoint', className: 'saml-history-uri' },
  ],
});

history.OP_SIGN_IN = OP_SIGN_IN;
history.OP_SIGN_OUT = OP_SIGN_OUT;

module.exports = history;
