const appconfig = require(process.env.CONFIG_FILE);
// OpenID Provider Metadata (Discovery 1.0 s3) — shared with oauth2_oidc_1.js
// so both Configuration Parameters panes carry the same fields and defaults.
const opMetadata = require("./op_metadata");
const sdJwtVc = require("./sd_jwt_vc");
const tokenHandoff = require("./token_handoff");
// DPoP for THIS workflow (RFC 9449), kept apart from the VC workflow's copy —
// see oauth_dpop.js for why the two are separate state.
const oauthDpop = require("./oauth_dpop");
const vciWallet = require("./vci_wallet");
const bunyan = require("bunyan");
const DOMPurify = require("dompurify");
const $ = require("jquery");
const log = bunyan.createLogger({ name: 'oauth2_oidc_2',
                                level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());
const { convertToOAuth2Format  } = require('./data.js');
// RFC 9700 (OAuth 2.0 Security BCP), the client half. Every rule it holds is
// behind the checkbox at the top of the Configuration Parameters pane; with
// the box clear nothing in this file consults it.
const rfc9700 = require("./rfc9700");

const TOKEN_HISTORY_LIMIT = 1000;
const OPERATION_HISTORY_LIMIT = 1000;

var displayOpenIDConnectArtifacts = true;
var useRefreshTokenTester = true;
var discoveryInfo = {};
var currentRefreshToken = '';
var usePKCE = true;
var useFrontEnd = false;
var useRefreshFrontEnd = false;
var useRevocationFrontEnd = false;
var useTokenExchangeFrontEnd = false;
var refreshTokenUsed = false;
// The tokens an implicit or hybrid flow returned on the authorization response,
// as resolved by recreateUniqueGrantFlowElements(). document.ready() reads it
// afterwards to record the set in Token History; null when this load carried no
// such response.
var authorizationResponseTokenSet = null;

// ---------------------------------------------------------------------------
// Put a value INTO a generated field, rather than concatenating it into the
// markup that builds the field.
//
// Everything these result panes show is caller-supplied — access, refresh and
// ID tokens, and the error string an authorization endpoint sent back. Building
// "<textarea>" + value + "</textarea>" and handing the result to .html()
// reinterprets that value as markup, which is what CodeQL reports as
// js/xss-through-dom (alerts #34 and #43 were two instances of it). A value
// containing "</textarea>" closes the element early and everything after it is
// parsed as HTML.
//
// DOMPurify does not fix that, and it was wrapped around several of these
// already: <textarea> is on DOMPurify's own allowlist, so a
// "<textarea></textarea><img ...>" payload survives sanitizing intact and still
// breaks out of the enclosing element. Measured, not assumed.
//
// .val() sets the DOM value property and never parses markup, so there is
// nothing to escape and no context to escape from.
//
// Fields are addressed by data-token-field rather than by id because these
// panes do not have the page's ids to themselves: refresh_refresh_token also
// names a static input further down the page, and token_access_token /
// token_id_token are used by whichever of the Authorization Endpoint and Token
// Endpoint result panes is on the screen. An id selector would silently set
// whichever the browser happened to find first. (The implicit-flow panes used
// to go further and give two textareas in one pane the same id; they are one
// pane now, and that pair is gone.)
function fillGeneratedFields(container, values) {
  log.debug("Entering fillGeneratedFields().");
  var pane = (container && container.jquery) ? container : $(container);
  Object.keys(values).forEach(function (field) {
    var value = values[field];
    pane.find('[data-token-field="' + field + '"]').val(value == null ?
              "" : value);
  });
  log.debug("Leaving fillGeneratedFields().");
  return pane;
}

function OnSubmitTokenEndpointForm()
{
  log.debug("Entering OnSubmitTokenEndpointForm().");
  document.token_step.action = "/token";
  log.debug("Leaving OnSubmitTokenEndpointForm().");
  return true;
}

function getParameterByName(name, url)
{
  log.debug("Entering getParameterByName().");
  if (!url)
  {
    // RFC 9700 section 4.12.2 (requirement 10.1): in compliance mode the
    // authorization response is removed from the address bar as soon as it has
    // been read, so that neither the code nor a token survives in browser
    // history. Everything that reads a response parameter after that point
    // would otherwise see an empty query string, so the value taken just
    // before the scrub is what is answered from. Out of mode the snapshot is
    // never taken and this is the query string it always was.
    url = rfc9700ScrubbedSearch !== null ? rfc9700ScrubbedSearch
                                         : window.location.search;
  }
  var urlParams = new URLSearchParams(url);
  log.debug("Leaving getParameterByName().");
  return urlParams.get(name);
}

function logoutButtonClick()  {
  log.debug("Entering logoutButtonClick().");
  log.debug("Logout link clicked.");
  var nameValuePairs = {};

  $('#logout_fieldset input.q').each(function() {
    var className = $(this).attr('name');
    var value = $(this).val();
    if (value!=""){
      nameValuePairs[className] = value;
    }
  });
  log.debug(nameValuePairs); // Log the name-value pairs
  var queryString = $.param(nameValuePairs);

  log.debug(queryString); // Log the query string
  var logoutUrl = DOMPurify.sanitize($("#logout_end_session_endpoint").val()) +
      "?" + DOMPurify.sanitize(queryString);

  clearLocalStorage();
  window.location.href = logoutUrl;

  log.debug("Leaving logoutButtonClick().");
  return false;
};

function tokenButtonClick() {
  log.debug("Entering tokenButtonClick().");
  log.debug("Entering token Submit button clicked function.");
  expandPane('#step3');
  expandPane('#step4');
  expandPane('#step5');
  expandPane('#step6');
  expandPane('#step7');
  expandPane('#operation-history-panel');
  log.debug("Updating local storage.");
  writeValuesToLocalStorage();
  log.debug("Recalculating token request description.");
  recalculateTokenRequestDescription();
  log.debug("Recalculating refresh request description.");
  recalculateRefreshRequestDescription();
  log.debug("Reset error displays.");
  resetErrorDisplays();
  // RFC 9700 sections 4.5 and 2.4: a code is presented once, a rotated refresh
  // token is never presented again, and the password grant is not used at all.
  // Checked before the request is composed rather than after, because the
  // point of each of the three is that the request is not made.
  if (rfc9700.enabled()) {
    var requestVerdict = rfc9700.checkTokenRequest({
      grantType: $("#token_grant_type").val(),
      code: $("#code").val(),
      codeVerifier: $("#token_pkce_code_verifier").val(),
      refreshToken: ""
    });
    renderRfc9700Report("rfc9700_token_report", "Token Request",
                        requestVerdict);
    if (!requestVerdict.ok) {
      log.debug("Leaving tokenButtonClick(). Refused by RFC 9700 mode.");
      return false;
    }
    // Recorded as presented, not as accepted: a code refused by the server is
    // still a code that has left this browser, and presenting it again is
    // still what section 4.5 forbids.
    if ($("#token_grant_type").val() === "authorization_code") {
      rfc9700.noteCodeRedeemed($("#code").val());
    }
  }
  log.debug("Build internal representation of token request data.");
  var formData = buildInternalTokenAPIRequestMessage();
  if (useFrontEnd) {
    log.debug("Using frontend to call Token Endpoint. formData=" +
              JSON.stringify(formData));
    // RFC 9449: when the SD-JWT VC workflow has DPoP switched on, this Token
    // Request carries a proof and the token comes back bound. Building it is
    // asynchronous (Web Crypto), so the call is made from the promise rather
    // than inline — and when DPoP is off, dpopTokenRequestHeaders() resolves to
    // an empty object and this is the request it always was.
    dpopTokenRequestHeaders(localStorage.getItem("token_endpoint"))
      .then(function (headers) {
        var url = localStorage.getItem("token_endpoint");
        var sentBody = convertToOAuth2Format(formData);
        // Recorded for the HTTP tab before the request goes, so that a call
        // which never comes back still shows what left. The headers are the
        // ones this page CHOSE: the browser adds Origin, Referer and
        // User-Agent itself, after script has stopped being able to look, and
        // the pane says so rather than implying this is all of them.
        noteHttpRequestSent("token", {
          via: "browser",
          method: "POST",
          url: url,
          headers: $.extend({
            "Content-Type": "application/x-www-form-urlencoded" }, headers),
          body: sentBody,
          bodyNote: "The browser adds Origin, Referer, User-Agent and the " +
              "rest of its own headers to this request and does not disclose " +
              "them to script, so they are not listed above.",
          note: null });
        $.ajax({
          type: "POST",
          crossdomain: true,
          url: url,
          data: sentBody,
          contentType: "application/x-www-form-urlencoded",
          headers: headers,
          success: successfulInternalTokenAPICall,
          error: errorInternalTokenAPICall
        });
      });
  } else {
    log.debug("Using backend to call Token Endpoint. formData=" +
              JSON.stringify(formData));
    // The proxied call cannot carry a DPoP proof: the api makes the request to
    // the token endpoint, so a proof built here would either name the api as
    // its htu (and be refused) or name an endpoint this browser is not calling.
    // Saying so beats sending an unbound token onward as if it were bound —
    // which is the failure this whole mechanism exists to prevent.
    var dpopOnHere = sdJwtVc.isFlowActive() ?
        sdJwtVc.dpopEnabled() : oauthDpop.enabled();
    if (dpopOnHere) {
      log.debug("DPoP is on, but this call is proxied through the api, which " +
                "does not forward " +
                "DPoP proofs.");
      var proxyNote = "DPoP is on, but this Token Request is being " +
          "<strong>proxied through " +
                      "the api</strong>, which does not forward DPoP proofs " +
                          "\u2014 so the token will " +
                      "come back as an ordinary Bearer token. Choose " +
                          "<em>Front End</em> for " +
                      "<em>Initiate call from</em> to send the request from " +
                          "the browser and have " +
                      "it bound.";
      // Two workflows, two places to say it: the VC workflow has its hand-off
      // banner, and this page's own DPoP pane has a status line. Writing only
      // to the banner (which does not exist here) meant an OAuth2/OIDC user got
      // no warning at all and an unbound token with no explanation.
      if (sdJwtVc.isFlowActive()) {
        $("#sdjwtvc_banner").append("<p class='vc-bad'>" + proxyNote + "</p>");
      } else {
        $("#dpop_status").html(DOMPurify.sanitize("<span class='dbg-bad'>" +
          proxyNote + "</span>"));
      }
    }
    // http_trace asks the api to hand back what it saw of ITS call to the
    // token endpoint (api/server.js, buildHttpTrace()) — the only way this
    // page can show a proxied exchange, since the browser is not party to it.
    // It is a flag for the api and goes no further: convertToOAuth2Format()
    // builds the outbound form body from named parameters, so nothing here
    // reaches the identity provider.
    var proxiedBody = JSON.stringify($.extend({}, formData, {
      http_trace: true }));
    noteHttpRequestSent("token", {
      via: "api",
      method: "POST",
      url: appconfig.apiUrl + "/token",
      headers: {
        "Content-Type": "application/json; charset=utf-8" },
      body: proxiedBody,
      bodyNote: null,
      note: "Waiting for the api, which is making the Token Request." });
    $.ajax({
      type: "POST",
      crossdomain: true,
      url: appconfig.apiUrl + "/token",
      data: proxiedBody,
      contentType: "application/json; charset=utf-8",
      success: successfulInternalTokenAPICall,
      error: errorInternalTokenAPICall
    });
  }
  log.debug("Leaving tokenButtonClick().");
  return false; // don't reload the page.
}

// ---------------------------------------------------------------------------
// The DPoP proof for this page's Token Request (RFC 9449).
//
// This page is shared: it is the OAuth2/OIDC workflow's token exchange AND the
// SD-JWT VC issuance workflow's authorization-code leg. DPoP is a decision the
// VC workflow makes, so it is read from that workflow's state and is simply
// absent for everybody else — which is why this resolves to {} rather than
// refusing when there is nothing to sign with.
//
// It applies only to the BROWSER-DIRECT call. The proxied call goes to the api,
// which then calls the token endpoint itself: a proof made here would name the
// api's URL as its htu and be refused, and one naming the token endpoint would
// be a proof for a request this browser is not making. Forwarding proofs
// through the api is not implemented, so the pane says so instead of sending
// something that cannot work.
// ---------------------------------------------------------------------------
function dpopTokenRequestHeaders(tokenEndpoint) {
  log.debug("Entering dpopTokenRequestHeaders().");
  var context = null;
  try {
    // WHICH workflow is asking. This page is the OAuth2/OIDC token exchange and
    // the VC workflow's authorization-code leg, and each decides DPoP for
    // itself: the VC workflow on issuance step 2, this one in its own DPoP pane
    // below. Reading the VC switch unconditionally — which is what this did —
    // put a proof on every browser-direct Token Request once DPoP had been
    // turned on over there, with nothing on this page able to turn it off
    // again.
    context = sdJwtVc.isFlowActive() ?
        sdJwtVc.dpopContext() : oauthDpop.context();
  } catch (e) {
    // The storage backing either one is unavailable (private mode, or storage
    // disabled). A Bearer request is the right fallback and needs no headers.
    log.debug("dpopTokenRequestHeaders(): no DPoP state is readable: " +
              e.message);
    context = null;
  }
  if (!context) {
    log.debug("Leaving dpopTokenRequestHeaders(). No DPoP context; a " +
              "Bearer request.");
    return Promise.resolve({});
  }
  log.debug("Leaving dpopTokenRequestHeaders().");
  return vciWallet.dpopHeadersFor({
    context: context, method: "POST", url: tokenEndpoint
    // No accessToken: this request is how one is obtained.
  }).then(function (built) {
    log.debug("Leaving dpopTokenRequestHeaders(). A DPoP proof was built.");
    return built.headers;
  }).catch(function (e) {
    // A proof that cannot be built must not silently become a Bearer request:
    // the token would come back unbound and the workflow would carry on as if
    // it were bound. Reported and then sent without, which the step 2 pane will
    // show as "NOT bound".
    log.error("could not build a DPoP proof for the token request: " +
              e.message);
    return {};
  });
}

// ---------------------------------------------------------------------------
// The OAuth2 / OIDC workflow's own DPoP pane.
//
// Three functions and no more, because everything else lives in oauth_dpop.js:
// the checkbox handler, the key generator, and the status line. The pane is the
// only place this workflow's DPoP can be switched on, which is the point — it
// used to have no switch at all and inherited the VC workflow's.
// ---------------------------------------------------------------------------
// Whether the selected flow reaches the token endpoint at all. The three that
// do not are the two OIDC Implicit variants and the OAuth2 Implicit grant:
// their tokens are delivered by the authorization endpoint in the fragment, so
// there is no request for a DPoP proof to ride on and no code for dpop_jkt to
// bind. Everything else here — the Authorization Code flow and all three
// Hybrids — redeems a code, which is exactly where DPoP applies.
function flowHasTokenRequest() {
  log.debug("Entering flowHasTokenRequest().");
  var agt = $("#authorization_grant_type").val() ||
      localStorage.getItem("authorization_grant_type");
  log.debug("Leaving flowHasTokenRequest().");
  return ["implicit_grant", "oidc_implicit_flow",
          "oidc_implicit_flow_id_token"].indexOf(agt) < 0;
}

function setDpopEnabled() {
  log.debug("Entering setDpopEnabled().");
  var on = $("#dpop_enabled").is(":checked");
  oauthDpop.setEnabled(on);
  $("#dpop_controls").toggle(on);
  if (on) {
    // A key is generated on the spot rather than at the first request, because
    // the authorization request needs its thumbprint (dpop_jkt) and is
    // assembled on the OTHER page — synchronously, from storage. No key here
    // means no dpop_jkt there, and a code that is not bound after all.
    ensureDpopKey();
  } else {
    $("#dpop_key_summary").text("");
    renderOauthDpopStatus();
  }
  // The preview shows the request that will actually be sent, headers included.
  recalculateTokenRequestDescription();
  log.debug("Leaving setDpopEnabled().");
  return false;
}

function ensureDpopKey() {
  log.debug("Entering ensureDpopKey().");
  log.debug("Leaving ensureDpopKey().");
  return oauthDpop.ensureKeyPair()
    .then(function (made) {
      renderOauthDpopStatus();
      log.debug("Leaving ensureDpopKey(). jkt=" + (made ? made.jkt : "(none)"));
      return made;
    })
    .catch(function (e) {
      // Web Crypto is absent (an insecure origin) or refused the algorithm.
      // Reported in the pane rather than thrown: the page must stay usable, and
      // the honest state is "DPoP is on and cannot work here".
      log.error("could not generate a DPoP key pair: " + e.message);
      $("#dpop_status").html(DOMPurify.sanitize(
        "<span class='dbg-bad'>No DPoP key pair could be generated: " +
            e.message +
        ". The Token Request will go out unbound.</span>"));
      return null;
    });
}

function generateDpopKey() {
  log.debug("Entering generateDpopKey().");
  // Explicitly a NEW pair, not ensureKeyPair(): the button is there to rotate.
  // Rotating invalidates a code already bound to the old key, which the status
  // line says rather than leaving as a later invalid_grant.
  oauthDpop.generateKeyPair()
    .then(function () {
      renderOauthDpopStatus();
      recalculateTokenRequestDescription();
    })
    .catch(function (e) {
      log.error("could not generate a DPoP key pair: " + e.message);
      $("#dpop_status").html(DOMPurify.sanitize(
        "<span class='dbg-bad'>No DPoP key pair could be generated: " +
            e.message + ".</span>"));
    });
  log.debug("Leaving generateDpopKey().");
  return false;
}

// What the pane says. Called after every state change, and after the token
// response — the verdict there is read off the token itself rather than from
// whether a proof was sent, because those are different facts.
function renderOauthDpopStatus(accessToken) {
  log.debug("Entering renderOauthDpopStatus().");
  var state = oauthDpop.readiness();
  $("#dpop_enabled").prop("checked", state.on);
  $("#dpop_controls").toggle(state.on);
  $("#dpop_key_summary").text(state.ready ? ("jkt: " + state.jkt) : "");
  if (!state.on) {
    $("#dpop_status").html("");
    log.debug("Leaving renderOauthDpopStatus(). DPoP is off.");
    return;
  }
  if (!state.ready) {
    $("#dpop_status").html(DOMPurify.sanitize("<span class='dbg-bad'>" +
      state.problem + "</span>"));
    log.debug("Leaving renderOauthDpopStatus(). On, but not ready.");
    return;
  }
  // A flow with no Token Request has nothing for DPoP to bind, and saying so is
  // the whole job of this line. RFC 9449 sender-constrains a token issued at
  // the TOKEN endpoint: it proves possession on the request that mints the
  // token, and section 10's dpop_jkt binds the authorization CODE. The Implicit
  // flows have neither — the access token arrives in the fragment straight from
  // the authorization endpoint — so a ready key and a ticked box here would
  // otherwise read as "this token will be bound", which it will not be.
  if (!flowHasTokenRequest()) {
    $("#dpop_status").html(DOMPurify.sanitize(
      "<span class='dbg-bad'>DPoP is on, but this flow has no Token Request: " +
          "the access token " +
      "comes straight from the authorization endpoint in the fragment. RFC " +
          "9449 binds tokens " +
      "issued at the token endpoint, so nothing here will be " +
          "sender-constrained. Use a flow " +
      "that returns a <code>code</code> to see the binding.</span>"));
    log.debug("Leaving renderOauthDpopStatus(). On, but this flow has no " +
              "token request.");
    return;
  }
  var sent = oauthDpop.jktSent();
  var lines = [];
  if (sent && sent !== state.jkt) {
    lines.push("<span class='dbg-bad'>The authorization request was sent " +
               "with dpop_jkt=" + sent +
               ", but the key has been regenerated since (" + state.jkt +
                   "). The code cannot be " +
               "redeemed — start the authorization request again.</span>");
  } else if (sent) {
    lines.push("The authorization request carried <code>dpop_jkt=" + sent +
               "</code>, so the code " +
               "is bound to this key as well as the token.");
  }
  var verdict = oauthDpop.bindingVerdict(accessToken);
  if (verdict.state !== "off") {
    lines.push("<span class='" + (verdict.state === "bound" ?
               "dbg-good" : "dbg-bad") + "'>" +
               verdict.text + "</span>");
  }
  $("#dpop_status").html(DOMPurify.sanitize(lines.join("<br/>")));
  log.debug("Leaving renderOauthDpopStatus(). verdict=" + verdict.state);
}

// ---------------------------------------------------------------------------
// THE HTTP TABS, and the four panes that carry one.
//
// What those panes showed before this was a DESCRIPTION of the request,
// composed from the form as it stood — useful, and not the same thing as the
// exchange: it names no headers, it is written before anything is sent, and it
// says nothing at all about what came back or how long it took. These tabs
// show the call that was actually made.
//
// Where the bytes come from depends on which end made the call, and each pane
// says which, because the difference is the whole reason this page offers the
// choice:
//
//   * Front end. The browser calls the token endpoint itself, so the request
//     is this page's own and the response is a jqXHR. What is NOT available is
//     most of the truth about the headers: the browser adds Origin, Referer
//     and User-Agent after script has stopped looking, and CORS hands script
//     only the response headers the server chose to expose. The pane says so
//     rather than presenting a partial list as though it were the whole one.
//
//   * Back end (the default here, because a great many identity providers
//     refuse a browser-origin Token Request outright). The api makes the call,
//     and only the api can see it — so it returns what it saw under
//     `http_exchange`, which this asked for with `http_trace: true`. That is
//     the complete exchange, headers and raw body both ways.
//
// THREE CHANNELS, FOUR PANES, ONE RENDERER. There are two exchanges a reader
// can be looking at on this page and a third they can go back to:
//
//   token    the Token Request. Composed on "Exchange Authorization Code for
//            Access Token" and read on "Token Endpoint Results" — the same
//            exchange in two panes, because a successful call COLLAPSES the
//            form and leaves the results pane as the one on screen.
//   refresh  the Refresh Request, in the same two places: the "Obtain New
//            Access Token Using Refresh Token" form and "Token Endpoint
//            Results for Refresh Token Call".
//   viewing  whichever generation the Token History pane has activated, in
//            the "Currently Viewing" pane. This one is not live: it is read
//            back out of the history entry, which is the only channel that
//            can outlive the page load that produced it.
//
// A channel is a name, the hosts that draw it, and the last view drawn. One
// renderer fills every host a channel has, so a pane that is rebuilt (three of
// the four are built as STRINGS and dropped into a container) gets the current
// view put back into it rather than a second implementation of the drawing.
//
// WHAT IS AND IS NOT WRITTEN DOWN. The live channels keep their view in module
// state for as long as the page lives, verbatim. What goes into `token_history`
// alongside the tokens is a REDACTED copy — see redactExchangeForStorage().
// Everything else about the exchange is kept, which is what makes the Currently
// Viewing pane's HTTP tab worth having.
//
// Be exact about what that buys, because the page's storage rules are not
// uniform and it is easy to claim more than is true. This page already stores
// `token_client_secret` and `refresh_client_secret` as ordinary form state —
// they are what the fields hold, and they come back when the page reloads. The
// PASSWORD is the one the state persistence note in CLAUDE.md excludes, and it
// is not stored anywhere. So the redaction is not what keeps the client secret
// out of this browser; it keeps a SECOND copy of every credential out of a
// record that grows one entry per token call, outlives the form's own state,
// is read back by a pane rather than typed into one, and — unlike a form field
// — carries the api's HTTP Basic header, which is a credential this page never
// composed and had never persisted before.
// ---------------------------------------------------------------------------

// One element, with its text set as TEXT.
//
// Everything these panes draw — header names and values, a request body, a
// response body — is somebody else's bytes, and half of it arrives from the
// far end. Building markup out of it and handing that to .html() is the
// js/xss-through-dom shape that fillGeneratedFields() above exists to avoid,
// and a sanitizer is the wrong answer to it a second time: there is no markup
// wanted here at all, so nothing is parsed as markup.
function httpNode(tag, className, text) {
  log.debug("Entering httpNode().");
  var node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (text !== undefined && text !== null) {
    node.textContent = String(text);
  }
  log.debug("Leaving httpNode().");
  return node;
}

// A two-column table of name/value pairs, sized to the pane rather than to its
// content: `table-layout: fixed` in the stylesheet plus break-anywhere on the
// cells is what keeps a 3,000-character Authorization header inside the pane's
// border instead of widening the column it sits in. Measured with a real
// header, not an empty table — an empty one fits anything.
function httpHeaderTable(headers) {
  log.debug("Entering httpHeaderTable().");
  var table = httpNode("table", "dbg-http-table");
  var body = document.createElement("tbody");
  var names = Object.keys(headers || {}).sort();
  if (names.length === 0) {
    var empty = document.createElement("tr");
    var only = httpNode("td", null, "(none reported)");
    only.colSpan = 2;
    empty.appendChild(only);
    body.appendChild(empty);
  }
  names.forEach(function (name) {
    var value = headers[name];
    var row = document.createElement("tr");
    row.appendChild(httpNode("td", null, name));
    row.appendChild(httpNode("td", null,
        Array.isArray(value) ? value.join(", ") : String(value)));
    body.appendChild(row);
  });
  table.appendChild(body);
  log.debug("Leaving httpHeaderTable(). " + names.length + " header(s).");
  return table;
}

// One HTTP message: its first line, its headers, and its body.
function httpMessage(host, title, firstLine, headers, body, bodyNote) {
  log.debug("Entering httpMessage(). " + title);
  host.appendChild(httpNode("div", "dbg-http-title", title));
  var message = httpNode("div", "dbg-http");
  message.appendChild(httpNode("div", "dbg-http-line", firstLine));
  // The header table gets its own bounded, scrolling box. A header value has
  // no length limit worth relying on — a 3,000-character one measured here
  // took the pane to 1,882 pixels on its own — and this pane shares a screen
  // with the rest of the workflow.
  var headerBox = httpNode("div", "dbg-http-scroll");
  headerBox.appendChild(httpHeaderTable(headers));
  message.appendChild(headerBox);
  if (bodyNote) {
    message.appendChild(httpNode("div", "dbg-http-note", bodyNote));
  }
  message.appendChild(httpNode("div", "dbg-http-body",
      (body === null || body === undefined || body === "") ?
          "(no body)" : String(body)));
  host.appendChild(message);
  log.debug("Leaving httpMessage().");
}

// The headers of an XMLHttpRequest response, parsed out of the one string the
// browser gives for all of them. CORS decides what is in that string, which is
// why the caller labels the list rather than presenting it as complete.
function parseXhrHeaders(raw) {
  log.debug("Entering parseXhrHeaders().");
  var headers = {};
  String(raw || "").split(/\r?\n/).forEach(function (line) {
    var at = line.indexOf(":");
    if (at > 0) {
      headers[line.slice(0, at).trim()] = line.slice(at + 1).trim();
    }
  });
  log.debug("Leaving parseXhrHeaders(). " + Object.keys(headers).length +
            " header(s).");
  return headers;
}

// Draw a view into one host. Everything above assembles one of these; this
// and renderHttpExchange() below are the only functions that touch a
// pane.
//
// view = { note, request: {method, url, headers, body},
//          response: {status, statusText, headers, body, note} | null,
//          timing: [ "…" ], failure: string | null }
//
// `emptyText` is what an absent view says, and it differs by pane because the
// absence means two different things: on the request form nothing has been
// sent YET, while on the results pane the tokens on screen came back from
// localStorage and the exchange that produced them was never kept — a Token
// Request carries the client secret, so it is not written down.
function drawHttpExchange(host, view, emptyText) {
  log.debug("Entering drawHttpExchange().");
  if (!host) {
    log.debug("Leaving drawHttpExchange(). No host element.");
    return;
  }
  while (host.firstChild) {
    host.removeChild(host.firstChild);
  }
  if (!view) {
    host.appendChild(httpNode("div", "dbg-http-note", emptyText));
    log.debug("Leaving drawHttpExchange(). Nothing to show.");
    return;
  }
  if (view.note) {
    host.appendChild(httpNode("div", "dbg-http-note", view.note));
  }
  httpMessage(host, "Request",
              view.request.method + " " + view.request.url,
              view.request.headers, view.request.body, view.request.note);
  if (view.response) {
    httpMessage(host, "Response",
                "HTTP " + view.response.status +
                    (view.response.statusText ?
                        " " + view.response.statusText : ""),
                view.response.headers, view.response.body, view.response.note);
  } else if (view.failure) {
    host.appendChild(httpNode("div", "dbg-http-title", "Response"));
    host.appendChild(httpNode("div", "dbg-http-fail",
        "No response. " + view.failure));
  } else {
    host.appendChild(httpNode("div", "dbg-http-title", "Response"));
    host.appendChild(httpNode("div", "dbg-http-note", "Waiting…"));
  }
  if (view.timing && view.timing.length) {
    host.appendChild(httpNode("div", "dbg-http-title", "Timing"));
    var timing = httpNode("div", "dbg-http");
    view.timing.forEach(function (line) {
      timing.appendChild(httpNode("div", "dbg-http-timing", line));
    });
    host.appendChild(timing);
  }
  log.debug("Leaving drawHttpExchange().");
}

// The three channels, the panes each of them draws into, and what each pane
// says when there is nothing to draw.
//
// `empty` differs by pane because the absence means different things: on a
// request form nothing has been sent YET; on a results pane the tokens on
// screen may have come back from localStorage, with the exchange that produced
// them either kept beside them or — for a set issued by a build before this,
// or by the Authorization Endpoint, which is not an HTTP call this page makes
// — not there at all.
var HTTP_CHANNELS = {
  token: {
    // The tab buttons whose LABEL carries the status, so that a pane collapsed
    // by a successful call still says what came back.
    tabs: ["token_tab_http", "token_result_tab_http"],
    panes: [
      { host: "token_http_exchange",
        empty: "No Token Request has been sent from this page yet. Send one " +
            "with Get Token and the whole exchange appears here." },
      { host: "token_result_http_exchange",
        empty: "No Token Request has been sent since this page was loaded. " +
            "The tokens beside this tab were restored from this browser's " +
            "storage; open the generation in Token History to see the " +
            "exchange that was kept with it." }
    ]
  },
  refresh: {
    tabs: ["refresh_tab_http", "refresh_result_tab_http"],
    panes: [
      { host: "refresh_http_exchange",
        empty: "No Refresh Request has been sent from this page yet. Send " +
            "one with Get Token and the whole exchange appears here." },
      { host: "refresh_result_http_exchange",
        empty: "No Refresh Request has been sent since this page was " +
            "loaded. The tokens beside this tab were restored from this " +
            "browser's storage; open the generation in Token History to see " +
            "the exchange that was kept with it." }
    ]
  },
  viewing: {
    tabs: ["cv_tab_http"],
    panes: [
      { host: "cv_http_exchange",
        empty: "No HTTP exchange was kept with this generation. Either it " +
            "came from the Authorization Endpoint — which this page reaches " +
            "by navigating the browser, not by making a request it can " +
            "trace — or it was issued before this build began keeping them." }
    ]
  }
};

// Per-channel state: the request last sent on it, the last view drawn, and the
// last thing its tab labels said.
//
// All three are kept rather than read back off the DOM because three of the
// four panes are REBUILT from a string — on every call, and again on load — so
// a host element does not exist at the moment the view for it is composed.
// Whichever of the two happens second fills in the other: renderHttpExchange()
// draws into every host that exists now, and attachHttpTab() draws the kept
// view into the host it has just created.
var httpChannelState = {
  token: { sent: null, view: null, label: null },
  refresh: { sent: null, view: null, label: null },
  viewing: { sent: null, view: null, label: null }
};

// The state record for one channel, created on demand so that a typo in a
// channel name is a visible no-op rather than a thrown TypeError in an ajax
// handler, where it would look like the call itself had failed.
function httpChannelStateFor(channel) {
  log.debug("Entering httpChannelStateFor(). channel=" + channel);
  if (!httpChannelState[channel]) {
    log.error("Unknown HTTP exchange channel: " + channel);
    httpChannelState[channel] = { sent: null, view: null, label: null };
  }
  log.debug("Leaving httpChannelStateFor().");
  return httpChannelState[channel];
}

// Draw a channel's view in every pane of it that has somewhere to put it.
function renderHttpExchange(channel, view) {
  log.debug("Entering renderHttpExchange(). channel=" + channel);
  httpChannelStateFor(channel).view = view;
  var config = HTTP_CHANNELS[channel];
  if (!config) {
    log.debug("Leaving renderHttpExchange(). No such channel.");
    return;
  }
  config.panes.forEach(function (pane) {
    drawHttpExchange(document.getElementById(pane.host), view, pane.empty);
  });
  log.debug("Leaving renderHttpExchange().");
}

// The label on a channel's tab buttons, so that a pane collapsed by a
// successful call still says what the exchange came back as.
function setHttpTabLabel(channel, suffix) {
  log.debug("Entering setHttpTabLabel(). channel=" + channel + " suffix=" +
            suffix);
  httpChannelStateFor(channel).label = suffix || null;
  var config = HTTP_CHANNELS[channel];
  if (!config) {
    log.debug("Leaving setHttpTabLabel(). No such channel.");
    return;
  }
  config.tabs.forEach(function (id) {
    var tab = document.getElementById(id);
    if (tab) {
      tab.textContent = suffix ? "HTTP · " + suffix : "HTTP";
    }
  });
  log.debug("Leaving setHttpTabLabel().");
}

// The tab strips. Each pane's first tab is the one a reader came for — the
// form on a request pane, the tokens on a results pane — and none of them is
// switched away from by code: a token call COLLAPSES the pane it was sent
// from, so a tab switched from a response handler would rearrange a pane
// nobody is looking at and hand the next reader who expands it something other
// than what they went there for. The tab's own label carries the status
// instead, which is visible the moment the pane is opened.
function selectTokenTab(name) {
  log.debug("Entering selectTokenTab(). name=" + name);
  var picked = selectPaneTab("token", ["form", "http"], name);
  log.debug("Leaving selectTokenTab().");
  return picked;
}

function selectTokenResultTab(name) {
  log.debug("Entering selectTokenResultTab(). name=" + name);
  var picked = selectPaneTab("token_result", ["tokens", "http"], name);
  log.debug("Leaving selectTokenResultTab().");
  return picked;
}

function selectRefreshTab(name) {
  log.debug("Entering selectRefreshTab(). name=" + name);
  var picked = selectPaneTab("refresh", ["form", "http"], name);
  log.debug("Leaving selectRefreshTab().");
  return picked;
}

function selectRefreshResultTab(name) {
  log.debug("Entering selectRefreshResultTab(). name=" + name);
  var picked = selectPaneTab("refresh_result", ["tokens", "http"], name);
  log.debug("Leaving selectRefreshResultTab().");
  return picked;
}

function selectCurrentlyViewingTab(name) {
  log.debug("Entering selectCurrentlyViewingTab(). name=" + name);
  var picked = selectPaneTab("cv", ["tokens", "http"], name);
  log.debug("Leaving selectCurrentlyViewingTab().");
  return picked;
}

// Turn one tab of a strip on and every other one off. Shared by all four
// panes: the class names and the aria attributes are the contract the
// stylesheet and a screen reader each read, and one pane having its own copy
// of them is how they stop matching. An unknown name selects the first tab
// rather than none — a strip with no panel showing reads as a broken pane.
// Returns false, because a tab click must not navigate.
function selectPaneTab(prefix, names, wanted) {
  log.debug("Entering selectPaneTab(). prefix=" + prefix + " wanted=" +
            wanted);
  var pick = names.indexOf(wanted) >= 0 ? wanted : names[0];
  names.forEach(function (which) {
    var on = which === pick;
    var tab = document.getElementById(prefix + "_tab_" + which);
    var panel = document.getElementById(prefix + "_tabpanel_" + which);
    if (tab) {
      tab.className = "dbg-tab" + (on ? " dbg-tab-on" : "");
      tab.setAttribute("aria-selected", on ? "true" : "false");
    }
    if (panel) {
      panel.className = "dbg-tabpanel" + (on ? "" : " dbg-tabpanel-off");
    }
  });
  log.debug("Leaving selectPaneTab().");
  return false;
}

// One tab button for a generated pane, wired with a listener rather than an
// inline onclick. These strips are built BY the bundle, so the handler is in
// scope by definition — where an inline onclick in generated markup is a call
// into a global that may not exist when the markup lands (see the note on
// inline handlers in client/CLAUDE.md).
function paneTabButton(prefix, which, label, on, onSelect) {
  log.debug("Entering paneTabButton(). prefix=" + prefix + " which=" + which);
  var button = httpNode("button", "dbg-tab" + (on ? " dbg-tab-on" : ""),
                        label);
  button.type = "button";
  button.id = prefix + "_tab_" + which;
  button.setAttribute("role", "tab");
  button.setAttribute("aria-selected", on ? "true" : "false");
  button.setAttribute("aria-controls", prefix + "_tabpanel_" + which);
  button.addEventListener("click", function () {
    onSelect(which);
  });
  log.debug("Leaving paneTabButton().");
  return button;
}

// Give a GENERATED pane its HTTP tab.
//
// Three of the four panes are not in the page. They are built as STRINGS and
// dropped into a container — the token results pane in four branches of this
// file, the refresh results pane in one, the Currently Viewing pane in one —
// so there is no markup here to hang a tab strip on, and putting one in each
// of those branches would be six copies to keep in step, one of which already
// builds a bare <fieldset> with no pane div around it. So this wraps whatever
// was just built: what the branch drew becomes the first panel, and the
// exchange becomes the second.
//
// Idempotent, because those panes are rebuilt on every call and this runs
// after each rebuild: a second strip on the same fieldset would be two sets of
// tabs driving one panel.
//
// `channel` names which exchange the second panel shows, and `paneIndex` which
// of that channel's hosts this pane is — which is what decides the id the host
// is given and the sentence an empty one carries.
function attachHttpTab(options) {
  log.debug("Entering attachHttpTab(). container=" + options.container);
  var container = document.getElementById(options.container);
  var fieldset = container ? container.querySelector("fieldset") : null;
  if (!fieldset) {
    log.debug("Leaving attachHttpTab(). No pane to tab.");
    return;
  }
  if (fieldset.querySelector(".dbg-tabs")) {
    log.debug("Leaving attachHttpTab(). Already tabbed.");
    return;
  }
  var pane = HTTP_CHANNELS[options.channel].panes[options.paneIndex];
  var first = httpNode("div", "dbg-tabpanel");
  first.id = options.prefix + "_tabpanel_" + options.firstTab;
  while (fieldset.firstChild) {
    first.appendChild(fieldset.firstChild);
  }
  var strip = httpNode("div", "dbg-tabs");
  strip.setAttribute("role", "tablist");
  strip.setAttribute("aria-label", options.label);
  strip.appendChild(paneTabButton(options.prefix, options.firstTab,
                                  options.firstTabLabel, true,
                                  options.onSelect));
  strip.appendChild(paneTabButton(options.prefix, "http", "HTTP", false,
                                  options.onSelect));
  var panel = httpNode("div", "dbg-tabpanel dbg-tabpanel-off");
  panel.id = options.prefix + "_tabpanel_http";
  var host = httpNode("div", "dbg-http-host");
  host.id = pane.host;
  panel.appendChild(host);
  fieldset.appendChild(strip);
  fieldset.appendChild(first);
  fieldset.appendChild(panel);
  // The exchange was drawn before this pane existed, and the label was set
  // before this button did, so both are put back here from what was kept.
  var state = httpChannelStateFor(options.channel);
  drawHttpExchange(host, state.view, pane.empty);
  setHttpTabLabel(options.channel, state.label);
  log.debug("Leaving attachHttpTab().");
}

// The Token Endpoint Results pane's HTTP tab.
function attachHttpTabToTokenResults() {
  log.debug("Entering attachHttpTabToTokenResults().");
  attachHttpTab({
    container: "token_endpoint_result",
    prefix: "token_result",
    channel: "token",
    paneIndex: 1,
    firstTab: "tokens",
    firstTabLabel: "Tokens",
    label: "Token endpoint results",
    onSelect: selectTokenResultTab });
  log.debug("Leaving attachHttpTabToTokenResults().");
}

// The Token Endpoint Results for Refresh Token Call pane's HTTP tab.
function attachHttpTabToRefreshResults() {
  log.debug("Entering attachHttpTabToRefreshResults().");
  attachHttpTab({
    container: "refresh_endpoint_result",
    prefix: "refresh_result",
    channel: "refresh",
    paneIndex: 1,
    firstTab: "tokens",
    firstTabLabel: "Tokens",
    label: "Refresh token endpoint results",
    onSelect: selectRefreshResultTab });
  log.debug("Leaving attachHttpTabToRefreshResults().");
}

// The Currently Viewing pane's HTTP tab. Unlike the two above, the view behind
// it is not the live one: it is whatever was kept with the generation the
// Token History pane has activated, which is put on the channel by
// renderCurrentlyViewing() before this runs.
function attachHttpTabToCurrentlyViewing() {
  log.debug("Entering attachHttpTabToCurrentlyViewing().");
  attachHttpTab({
    container: "currently-viewing-panel",
    prefix: "cv",
    channel: "viewing",
    paneIndex: 0,
    firstTab: "tokens",
    firstTabLabel: "Tokens",
    label: "Currently viewing",
    onSelect: selectCurrentlyViewingTab });
  log.debug("Leaving attachHttpTabToCurrentlyViewing().");
}

// Record what is about to go out on a channel, and show it while it is in
// flight. The request is worth showing on its own: a call that never comes
// back is precisely the one whose headers and body the reader needs.
function noteHttpRequestSent(channel, sent) {
  log.debug("Entering noteHttpRequestSent(). channel=" + channel + " " +
            sent.method + " " + sent.url);
  var state = httpChannelStateFor(channel);
  state.sent = sent;
  state.sent.startedAt = Date.now();
  setHttpTabLabel(channel, "sending…");
  renderHttpExchange(channel, {
    note: sent.note,
    request: {
      method: sent.method, url: sent.url, headers: sent.headers,
      body: sent.body, note: sent.bodyNote },
    response: null,
    timing: [],
    failure: null });
  log.debug("Leaving noteHttpRequestSent().");
}

// The api's own account of the call it made, when it made one. Returned under
// `http_exchange` because the api asked for it with `http_trace: true`; absent
// when the call was made from the browser, when the token endpoint answered
// with something that could not carry it (an HTML error page), or when the api
// predates this. Every one of those is handled by falling back to what the
// browser itself saw, which is why this only ever reads and never insists.
function apiHttpExchange(jqXHR, data) {
  log.debug("Entering apiHttpExchange().");
  var carrier = data;
  if (!carrier && jqXHR && jqXHR.responseJSON) {
    carrier = jqXHR.responseJSON;
  }
  var trace = carrier && typeof carrier === "object" ?
      carrier.http_exchange : null;
  if (!trace || typeof trace !== "object" || !trace.request) {
    log.debug("Leaving apiHttpExchange(). None returned.");
    return null;
  }
  log.debug("Leaving apiHttpExchange(). Found one.");
  return trace;
}

// The error view, with the trace taken back out of it.
//
// The error pane below prints `responseText` verbatim, and on a proxied call
// that text now carries the whole HTTP trace — up to sixteen kilobytes of it,
// in a five-row textarea, in front of the error the reader came for. The trace
// has a pane of its own two tabs away, so this hands the error pane the
// response WITHOUT it. The bytes as they actually arrived are in the HTTP tab;
// this is a re-serialization either way, since the api parsed and rebuilt the
// token endpoint's JSON before the browser ever saw it.
function tokenErrorWithoutTrace(jqXHR) {
  log.debug("Entering tokenErrorWithoutTrace().");
  var view = {
    status: jqXHR ? jqXHR.status : 0,
    statusText: jqXHR ? jqXHR.statusText : "",
    readyState: jqXHR ? jqXHR.readyState : 0,
    responseText: jqXHR ? jqXHR.responseText : "" };
  try {
    var parsed = JSON.parse(view.responseText);
    if (parsed && typeof parsed === "object" && parsed.http_exchange) {
      delete parsed.http_exchange;
      view.responseText = JSON.stringify(parsed);
    }
  } catch (e) {
    // Not JSON — an HTML error page, or nothing at all. It carries no trace
    // to remove, so it is shown exactly as it arrived.
    log.debug("tokenErrorWithoutTrace(): the response is not JSON.");
  }
  log.debug("Leaving tokenErrorWithoutTrace().");
  return view;
}

// What each channel calls the request it sends, for the sentences below. The
// pane a reader is looking at already says which call it is about, but the
// note beside the exchange names it too — a reader who has both panes open at
// once is looking at two request/response pairs that are alike in every way
// except this.
var HTTP_CHANNEL_REQUEST_NAME = {
  token: "Token Request",
  refresh: "Refresh Request",
  viewing: "request"
};

// Assemble and draw the finished exchange on a channel. Called from both ajax
// handlers of both live channels, so a refusal is drawn exactly like a success
// — a 400 with an error body is an exchange, and the one whose headers and
// elapsed time are most often the point.
//
// Returns the view it drew, so that the caller which is about to write a token
// set to the history can keep a redacted copy of it beside the tokens without
// composing the thing a second time.
function showHttpExchange(channel, jqXHR, apiTrace) {
  log.debug("Entering showHttpExchange(). channel=" + channel);
  var sent = httpChannelStateFor(channel).sent;
  var requestName = HTTP_CHANNEL_REQUEST_NAME[channel] || "request";
  var roundTripMs = sent && sent.startedAt ? Date.now() - sent.startedAt : null;
  var status = jqXHR && jqXHR.status ? jqXHR.status : 0;
  var timing = [];
  var view = null;
  if (apiTrace) {
    // The exchange with the TOKEN ENDPOINT, as the api saw it. That is the one
    // being debugged; the browser's own call to the api is transport.
    var body = apiTrace.response ? apiTrace.response.body : null;
    var truncated = apiTrace.response && apiTrace.response.bodyTruncated;
    view = {
      note: "Sent by the api on this browser's behalf — " +
            "“Initiate Token Endpoint Call” is set to Back. These " +
            "are the bytes between the api and the token endpoint, which the " +
            "browser cannot see.",
      request: {
        method: apiTrace.request.method, url: apiTrace.request.url,
        headers: apiTrace.request.headers, body: apiTrace.request.body,
        note: null },
      response: apiTrace.response ? {
        status: apiTrace.response.status,
        statusText: apiTrace.response.statusText,
        headers: apiTrace.response.headers,
        body: body,
        note: truncated ? "Body truncated for display — the first " +
            String(body ? body.length : 0) + " of " +
            String(apiTrace.response.bodyLength) + " characters." : null
      } : null,
      timing: timing,
      failure: apiTrace.error };
    if (apiTrace.timing && typeof apiTrace.timing.totalMs === "number") {
      timing.push("Token endpoint call: " + apiTrace.timing.totalMs +
                  " ms, measured by the api around its own request.");
    }
    if (roundTripMs !== null) {
      timing.push("Browser round trip to the api: " + roundTripMs + " ms.");
    }
  } else {
    // The browser's own call: either straight to the token endpoint, or to the
    // api when the api returned no trace of what it did next.
    var direct = sent && sent.via === "browser";
    view = {
      note: direct ?
        "Sent by this browser — “Initiate Token Endpoint Call” " +
        "is set to Front." :
        "Sent by this browser to the api, which then called the token " +
        "endpoint. The api returned no trace of that second call, so what is " +
        "shown here is the first one.",
      request: sent ? {
        method: sent.method, url: sent.url, headers: sent.headers,
        body: sent.body, note: sent.bodyNote } : {
        method: "POST", url: "(not recorded)", headers: {}, body: "",
        note: null },
      response: status ? {
        status: status,
        statusText: jqXHR.statusText || "",
        headers: parseXhrHeaders(jqXHR.getAllResponseHeaders ?
            jqXHR.getAllResponseHeaders() : ""),
        body: jqXHR.responseText,
        note: "Only the response headers CORS exposes to script are listed. " +
              "A cross-origin response carries more than this; the browser " +
              "does not hand them over."
      } : null,
      timing: timing,
      failure: status ? null :
        "The browser reports no status, which is what a CORS refusal, a " +
        "network failure or an aborted request looks like from script." };
    if (roundTripMs !== null) {
      timing.push("Total, measured in the browser around the request: " +
                  roundTripMs + " ms.");
    }
  }
  view.requestName = requestName;
  setHttpTabLabel(channel, view.response ? String(view.response.status) :
                  "no response");
  renderHttpExchange(channel, view);
  log.debug("Leaving showHttpExchange(). status=" +
            (view.response ? view.response.status : "none"));
  return view;
}

// ---------------------------------------------------------------------------
// KEEPING AN EXCHANGE, which is the one thing this page had decided not to do.
//
// The live channels above hold their view for as long as the page lives and
// write nothing down. That was the whole rule, and the reason for it is that a
// Token Request repeats a client secret, carries an Authorization header built
// out of it, and on the password grant carries a password. See the note at the
// top of this section for what the redaction does and does not buy — the
// password is the credential this page genuinely keeps out of storage, and the
// Authorization header is the one it had never persisted before.
//
// What is kept beside a token set in `token_history` is therefore a COPY with
// those values taken out and nothing else changed. The distinction is worth
// being exact about, because it is the whole reason the copy is allowed to
// exist: the method, the URL, every other request header, every other body
// parameter, the status line, every response header, the response body and the
// timing are all kept verbatim — those are what the exchange is FOR — and only
// the values that authenticate the client are replaced. A reader who wants the
// unredacted bytes has them in the live pane for as long as the page is open.
//
// Redaction is by NAME and it is deliberately blunt. A header whose name is in
// the list loses its whole value; a body parameter whose name is in the list
// loses its whole value. Guessing at which PART of a credential is secret is
// how a redactor leaves half of one behind.
// ---------------------------------------------------------------------------

// What a redacted value reads as. One string, so a test can look for it and a
// reader cannot mistake it for something the server sent.
var HTTP_REDACTED = "(redacted — not stored)";

// Request headers whose value is a credential. Compared lower-cased, because a
// header name is case-insensitive and these arrive from two different senders:
// the api reports what it sent (lower-cased by axios), and this page reports
// what it chose (capitalised as written here).
var HTTP_REDACTED_HEADERS = [
  "authorization", "proxy-authorization", "cookie", "dpop"];

// Body parameters whose value is a credential. `client_secret` and `password`
// are the two this page can send; `client_assertion` is here because a private
// key JWT is a bearer credential in exactly the same way, and a build that
// starts sending one must not have to remember this list.
var HTTP_REDACTED_PARAMS = [
  "client_secret", "password", "client_assertion", "assertion"];

// The most of a body that is kept. A response body is a token response —
// three JWTs and some JSON around them — and a request body is smaller than
// that, so this is generous for both; what it is really guarding against is
// an identity provider that answers with a stack trace or an HTML page, times
// the thousand generations TOKEN_HISTORY_LIMIT allows.
var HTTP_STORED_BODY_LIMIT = 8192;

// One header map with the credential-bearing values taken out.
function redactHeadersForStorage(headers) {
  log.debug("Entering redactHeadersForStorage().");
  var out = {};
  Object.keys(headers || {}).forEach(function (name) {
    if (HTTP_REDACTED_HEADERS.indexOf(String(name).toLowerCase()) >= 0) {
      out[name] = HTTP_REDACTED;
    } else {
      out[name] = headers[name];
    }
  });
  log.debug("Leaving redactHeadersForStorage().");
  return out;
}

// One request body with the credential-bearing parameters taken out.
//
// Two shapes reach this, because this page sends two: a form-urlencoded body
// straight to the token endpoint, and a JSON body to the api. Both are handled
// by name; anything that is neither is kept whole, since a body this does not
// understand is one whose parameters it cannot find either — and a body it
// cannot parse is not one it may hand back with a credential still in it, so
// the unknown case keeps only its length.
function redactBodyForStorage(body, contentType) {
  log.debug("Entering redactBodyForStorage().");
  if (body === null || body === undefined || body === "") {
    log.debug("Leaving redactBodyForStorage(). Empty.");
    return body;
  }
  var text = String(body);
  var type = String(contentType || "").toLowerCase();
  if (type.indexOf("json") >= 0 || /^\s*\{/.test(text)) {
    try {
      var parsed = JSON.parse(text);
      if (parsed && typeof parsed === "object") {
        HTTP_REDACTED_PARAMS.forEach(function (name) {
          if (Object.prototype.hasOwnProperty.call(parsed, name)) {
            parsed[name] = HTTP_REDACTED;
          }
        });
        log.debug("Leaving redactBodyForStorage(). JSON.");
        return JSON.stringify(parsed);
      }
    } catch (e) {
      // Not JSON after all — it only looked like it. Fall through to the
      // form-encoded pass below, which leaves a string it does not recognise
      // alone rather than mangling it.
      log.debug("redactBodyForStorage(): the body is not JSON.");
    }
  }
  // Form-urlencoded, by name. The value is replaced with the ENCODED marker so
  // that what is stored is still a body a reader can parse.
  var redacted = text.replace(/([^&=?]+)=([^&]*)/g, function (whole, key) {
    var name = "";
    try {
      name = decodeURIComponent(key).toLowerCase();
    } catch (e) {
      // A malformed percent-escape in a parameter NAME. It is not one of the
      // names below, so the pair is kept as it stands.
      log.debug("redactBodyForStorage(): undecodable parameter name.");
      name = String(key).toLowerCase();
    }
    if (HTTP_REDACTED_PARAMS.indexOf(name) >= 0) {
      return key + "=" + encodeURIComponent(HTTP_REDACTED);
    }
    return whole;
  });
  log.debug("Leaving redactBodyForStorage(). Form-encoded.");
  return redacted;
}

// A body cut down to what is worth keeping, with a line saying so when it was.
function capBodyForStorage(text) {
  log.debug("Entering capBodyForStorage().");
  if (text === null || text === undefined) {
    log.debug("Leaving capBodyForStorage(). Nothing to cap.");
    return { body: text, note: null };
  }
  var s = String(text);
  if (s.length <= HTTP_STORED_BODY_LIMIT) {
    log.debug("Leaving capBodyForStorage(). Kept whole.");
    return { body: s, note: null };
  }
  log.debug("Leaving capBodyForStorage(). Cut to " + HTTP_STORED_BODY_LIMIT +
            ".");
  return {
    body: s.slice(0, HTTP_STORED_BODY_LIMIT),
    note: "Body truncated when it was stored — the first " +
        String(HTTP_STORED_BODY_LIMIT) + " of " + String(s.length) +
        " characters." };
}

// The whole exchange, ready to be written down beside a token set.
//
// The value returned is a view of exactly the shape drawHttpExchange() draws,
// which is what lets the Currently Viewing pane read one back out of storage
// and hand it to the same renderer the live panes use. Nothing about it is
// re-derived on the way out: what is stored is what is shown.
function redactExchangeForStorage(view) {
  log.debug("Entering redactExchangeForStorage().");
  if (!view || !view.request) {
    log.debug("Leaving redactExchangeForStorage(). Nothing to keep.");
    return null;
  }
  var requestType = (view.request.headers || {})["Content-Type"] ||
      (view.request.headers || {})["content-type"] || "";
  var requestBody = capBodyForStorage(
      redactBodyForStorage(view.request.body, requestType));
  var kept = {
    note: view.note || null,
    requestName: view.requestName || null,
    // The instant the set was written, which is what the pane says when it
    // draws an exchange that did not happen on this page load.
    storedAt: new Date().toISOString(),
    request: {
      method: view.request.method,
      url: view.request.url,
      headers: redactHeadersForStorage(view.request.headers),
      body: requestBody.body,
      note: [view.request.note, requestBody.note,
             "Credentials were removed before this exchange was stored."]
          .filter(Boolean).join(" ") },
    response: null,
    timing: (view.timing || []).slice(),
    failure: view.failure || null };
  if (view.response) {
    var responseBody = capBodyForStorage(view.response.body);
    kept.response = {
      status: view.response.status,
      statusText: view.response.statusText,
      // A Set-Cookie is a credential too, and the one header a token endpoint
      // is most likely to send back.
      headers: redactHeadersForStorage(view.response.headers),
      body: responseBody.body,
      note: [view.response.note, responseBody.note].filter(Boolean).join(" ")
          || null };
  }
  log.debug("Leaving redactExchangeForStorage().");
  return kept;
}

// The note a stored exchange is drawn under, which has to say two things the
// live one does not: when it happened, and that what is on screen is the
// redacted copy rather than the bytes.
function storedExchangeForDisplay(kept) {
  log.debug("Entering storedExchangeForDisplay().");
  if (!kept || !kept.request) {
    log.debug("Leaving storedExchangeForDisplay(). Nothing kept.");
    return null;
  }
  var when = kept.storedAt ? kept.storedAt.replace("T", " ").slice(0, 19) +
      " UTC" : "an earlier point in this session";
  var view = {
    note: "The " + (kept.requestName || "request") + " that produced this " +
        "generation, kept with it at " + when + ". Credentials — the " +
        "Authorization header, the client secret, a password — were removed " +
        "before it was stored and read " + HTTP_REDACTED + " below. " +
        (kept.note ? kept.note : ""),
    request: kept.request,
    response: kept.response,
    timing: kept.timing,
    failure: kept.failure };
  log.debug("Leaving storedExchangeForDisplay().");
  return view;
}

function buildInternalTokenAPIRequestMessage() {
  log.debug("Entering buildInternalTokenAPIRequestMessage().");
  // validate and process form here
  var token_endpoint = $("#token_endpoint").val();
  var client_id = $("#token_client_id").val();
  var client_secret = $("#token_client_secret").val();
  var code = $("#code").val();
  var grant_type = $("#token_grant_type").val();
  var redirect_uri = $("#token_redirect_uri").val();
  var username = $("#token_username").val();
  var password = $("#token_password").val();
  var scope = $("#token_scope").val();
  var sslValidate = "";
  var code_verifier = $("#token_pkce_code_verifier").val();
  if($("#SSLValidate-yes").is(":checked"))
  {
    sslValidate = $("#SSLValidate-yes").val();
  } else if ($("#SSLValidate-no").is(":checked")) {
    sslValidate = $("#SSLValidate-no").val();
  } else {
    sslValidate = "true";
  }
  var auth_style = getLSBooleanItem("token_post_auth_style");
   
  var formData = {};
  if(grant_type == "authorization_code")
  {
    formData = {
          grant_type: grant_type,
          client_id: client_id,
          code: code,
          redirect_uri: redirect_uri,
          scope: scope,
          token_endpoint: token_endpoint,
          sslValidate: sslValidate,
          auth_style: auth_style
    };
  } else if( grant_type == "password") {
    formData = {
          grant_type: grant_type,
          client_id: client_id,
          username: username,
          password: password,
          code: code,
          scope: scope,
          token_endpoint: token_endpoint,
          sslValidate: sslValidate,
          auth_style: auth_style
    };
  } else if( grant_type == "client_credentials") {
    formData = {
          grant_type: grant_type,
          client_id: client_id,
          scope: scope,
          token_endpoint: token_endpoint,
          sslValidate: sslValidate,
          auth_style: auth_style
    };
  } else if( grant_type == "urn:ietf:params:oauth:grant-type:device_code") {
    // RFC 8628 Device Access Token Request.
    formData = {
          grant_type: grant_type,
          client_id: client_id,
          device_code: $("#device_code").val(),
          token_endpoint: token_endpoint,
          sslValidate: sslValidate,
          auth_style: auth_style
    };
  }
  log.debug("formData=" + JSON.stringify(formData));
  var yesCheck = $("#yesResourceCheckToken").is(":checked");
  if(yesCheck) //add resource value to OAuth query string
  {
    var resource = $("#token_resource").val();
    if (!!resource)
    {
      formData.resource = resource
    }
  }
  if(!!client_secret)
  {
    formData.client_secret = client_secret
  }
  var tokencustomParametersCheck =
      $("#customTokenParametersCheck-yes").is(":checked");
  log.debug("customTokenParametersCheck: " + tokencustomParametersCheck +
            ", type=" + typeof(tokencustomParametersCheck));
  if(tokencustomParametersCheck) 
  {
    formData.customParams = {};
    const numberCustomParameters =
        parseInt($("#tokenNumberCustomParameters").val());
    log.debug('numberCustomParameters=' + numberCustomParameters);
    var i = 0;
    for(i = 0; i < numberCustomParameters; i++)
    {
      formData.customParams[$("#customTokenParameterName-" + i).val()] =
                            $("#customTokenParameterValue-" + i).val();
    }
  }
  if(usePKCE) {
    formData.code_verifier = code_verifier;
  }
  log.debug("Leaving buildInternalTokenAPIRequestMessage().");
  return formData;
}

function successfulInternalTokenAPICall(data, textStatus, request)
{
  log.debug("Entering successfulInternalTokenAPICall().");
  // The HTTP tab, first, and BEFORE anything else reads the payload: the
  // trace the api attaches is transport, not part of the token response, so
  // it is taken out here rather than left for token history, the RFC 9700
  // checks and the result panes to step around. Drawn before the RFC 9700
  // gate below, which can discard everything else this response carried — a
  // refused response is still an exchange that happened, and hiding it would
  // leave the reader with a verdict and no evidence.
  var apiTrace = apiHttpExchange(request, data);
  if (data && typeof data === "object") {
    delete data.http_exchange;
  }
  var tokenExchangeKept =
      redactExchangeForStorage(showHttpExchange("token", request, apiTrace));
  log.debug("Entering ajax success function for Access Token call: data=" 
          + JSON.stringify(data)
          + ", textStatus="
          + textStatus
          + ", request=" 
          + JSON.stringify(request));
  // RFC 9700 section 4.5.3 (requirement 3.2): the client MUST NOT use any
  // token from this response until the ID Token's nonce has been validated.
  // "Use" includes rendering it, writing it to Token History, and offering it
  // to the UserInfo, introspection and refresh panes — so the refusal is here,
  // at the top of the handler, before any of that has happened. Everything
  // this response carried is discarded.
  if (rfc9700.enabled()) {
    var responseVerdict = rfc9700.checkTokenResponse({
      data: data,
      grantType: $("#token_grant_type").val(),
      clientId: $("#token_client_id").val(),
      requestedScope: $("#token_scope").val(),
      previousRefreshToken: currentRefreshToken
    });
    renderRfc9700Report("rfc9700_token_report", "Token Response",
                        responseVerdict);
    if (!responseVerdict.ok) {
      log.debug("Discarding the token set: RFC 9700 mode refused it.");
      $("#display_token_error_class").html(DOMPurify.sanitize(
        "<fieldset><legend>Token Response Refused</legend><p>The token " +
        "endpoint answered, and RFC 9700 mode discarded what it returned. " +
        "The reasons are in the RFC 9700 report above. Nothing from this " +
        "response has been stored or displayed.</p></fieldset>"));
      log.debug("Leaving successfulInternalTokenAPICall(). Refused.");
      return;
    }
    // Section 4.14.2: once the server has rotated the refresh token, the one
    // it replaced must never be sent again.
    rfc9700.noteRefreshRotated(currentRefreshToken, data.refresh_token);
  }
  var token_endpoint_result_html = "";
  // What the server said about the binding. Recorded rather than inferred,
  // because asking for a DPoP-bound token does not make one: a server that
  // ignored the proof answers Bearer, and both DPoP panes report that
  // difference. Recorded against whichever workflow asked, for the same reason
  // the proof is built from that workflow's key.
  if (!!data.token_type) {
    if (sdJwtVc.isFlowActive()) {
      localStorage.setItem(sdJwtVc.KEYS.DPOP_TOKEN_TYPE,
                           DOMPurify.sanitize(String(data.token_type)));
    } else if (oauthDpop.enabled()) {
      oauthDpop.rememberBinding(DOMPurify.sanitize(String(data.token_type)),
                                oauthDpop.jktOfToken(data.access_token));
    }
  }
  if (!sdJwtVc.isFlowActive()) {
    renderOauthDpopStatus(data.access_token);
  }
  // Deferred to the end of this handler: the verdict describes the RESPONSE, so
  // it belongs with the results rather than with the request form — which this
  // handler collapses (`$("#token_fieldset").hide()`), taking the pane's own
  // status line off the screen with it.
  var dpopVerdictToShow = (!sdJwtVc.isFlowActive() && oauthDpop.enabled())
    ? oauthDpop.bindingVerdict(data.access_token) : null;
  if (!!data.refresh_token && 
      data.refresh_token != 'undefined') {
    currentRefreshToken = DOMPurify.sanitize(data.refresh_token);
  }
  if (!!data.id_token && 
      data.id_token != 'undefined'){
    $("#logout_id_token_hint").val(DOMPurify.sanitize(data.id_token));
  }
  log.debug("displayOpenIDConnectArtifacts=" + displayOpenIDConnectArtifacts);
  if(displayOpenIDConnectArtifacts == true)
  {
    // Display OAuth2/OIDC Artifacts
    token_endpoint_result_html = '<div class="dbg-pane">' +
                                 '<legend class="dbg-legend" data-target="token_result_fieldset">Token Endpoint Results:</legend>' +
                                 '<fieldset id="token_result_fieldset">' +
                                 "<p><em>Most recent results of the OAuth2 " +
                                     "Grant or OIDC Authentication Flow " +
                                     "call.</em></p>" +
				   "<table>" +
				     "<tr>" +
                                       '<td>' +
                                         '<P><a href="/token_detail.html?type=access" onclick="oauth2_oidc_2.clickLink()">Access Token</a></P>' +
                                         '<P style="font-size:50%;"><a href="/introspection.html?type=access" onclick="oauth2_oidc_2.clickLink()">Introspect Token</a></P>' +
                                         '<P><input class="btn2 revoke_token_btn" type="button" value="Revoke Token" data-revoke-type="access" /></P>' + 
                                         '<P><form><input class="btn2" ' +
                                             'type="submit" ' +
                                             'value="Copy Token"' +
                                         ' onclick="return oauth2_oidc_2.onClickCopyToken(\'#token_access_token\');"/></form></P>' +
                                       '</td>' +
                                       '<td>' +
                                         "<textarea rows=5 cols=60 readonly name=token_access_token id=token_access_token data-token-field=\"access\"></textarea>" +
                                       '</td>' +
                                     '</tr>';
    if(useRefreshTokenTester) {
      token_endpoint_result_html +=  '<tr>' +
                                          '<td>' +
                                              '<P><a href="/token_detail.html?type=refresh" onclick="oauth2_oidc_2.clickLink()">Refresh Token</a></P>' +
                                              '<P style="font-size:50%;"><a href="/introspection.html?type=refresh" onclick="oauth2_oidc_2.clickLink()">Introspect Token</a></P>' +
                                         '<P><input class="btn2 revoke_token_btn" type="button" value="Revoke Token" data-revoke-type="refresh" /></P>' +
                                              '<P><form><input class="btn2" ' +
                                                  'type="submit" ' +
                                                  'value="Copy Token"' + 
                                              ' onclick="return oauth2_oidc_2.onClickCopyToken(\'#token_refresh_token\');"/></form></P>' +
                                          '</td>' +
                                          '<td>' +
                                              '<textarea rows=5 cols=60 readonly name=token_refresh_token id=token_refresh_token data-token-field="refresh"></textarea>' +
                                          "</td>" +
                                        "</tr>";
      }
      token_endpoint_result_html +=  "<tr>" +
                                          '<td>' +
                                            '<P><a href="/token_detail.html?type=id" onclick="oauth2_oidc_2.clickLink()">ID Token</a></P>' +
                                            '<P style="font-size:50%;">Get <a href="/userinfo.html?type=token_access_token" onclick="oauth2_oidc_2.clickLink()">UserInfo Data</a></P>' +
                                            '<P><form><input ' +
                                                'class="token_btn" ' +
                                                'type="submit" ' +
                                                'value="Copy Token"' + 
                                            ' onclick="return oauth2_oidc_2.onClickCopyToken(\'#token_id_token\');"/></form></P>' +
                                          '</td>' +
                                          '<td>' +
                                            '<textarea rows=5 cols=60 readonly name=token_id_token id=token_id_token data-token-field="id"></textarea>' +
                                          '</td>' +
                                        "</tr>" +
                                      "</table>" +
                                      "</fieldset>" +
                                      "</div>";
      localStorage.setItem("token_access_token", data.access_token);
      localStorage.setItem("token_refresh_token", data.refresh_token);
      localStorage.setItem("token_id_token", data.id_token);
      rememberAuthorizationDetails(data);
      saveTokenSetToHistory(data.access_token, data.refresh_token,
                            data.id_token, 'token', tokenExchangeKept);
    } else {
      log.debug("Displaying Access Token. No OIDC ID Token: " +
                "data.access_token=" + data.access_token);
      token_endpoint_result_html = '<div class="dbg-pane">' +
                                      '<legend class="dbg-legend" data-target="token_result_fieldset">Token Endpoint Results:</legend>' +
                                      '<fieldset id="token_result_fieldset">' +
                                 "<p><em>Most recent results of the OAuth2 " +
                                     "Grant or OIDC Authentication Flow " +
                                     "call.</em></p>" +
                                      "<table>" +
                                        "<tr>" +
                                          '<td>' +
                                            '<p><a href="/token_detail.html?type=access" onclick="oauth2_oidc_2.clickLink()">Access Token</a></p>' +
                                            '<P><input class="btn2 revoke_token_btn" type="button" value="Revoke Token" data-revoke-type="access" /></P>' +
                                            '<P><form><input class="btn2" ' +
                                                'type="submit" ' +
                                                'value="Copy Token"' +
                                            ' onclick="return oauth2_oidc_2.onClickCopyToken(\'#token_access_token\');"/></form></P>' +
                                          '</td>' +
                                          "<td><textarea rows=5 cols=60 readonly name=token_access_token id=token_access_token data-token-field=\"access\"></textarea>" +
                                          "</td>" +
                                        "</tr>";
      if(useRefreshTokenTester) {
        log.debug("Refresh token found. Generating token: data.refresh_token=" +
                  currentRefreshToken);
        token_endpoint_result_html += "<tr>" +
                                          '<td>' +
                                            '<a href="/token_detail.html?type=id" onclick="oauth2_oidc_2.clickLink()">Refresh Token</a>' +
                                            '<P><input class="btn2 revoke_token_btn" type="button" value="Revoke Token" data-revoke-type="refresh" /></P>' +
                                            '<P><form><input class="btn2" ' +
                                                'type="submit" ' +
                                                'value="Copy Token"' +
                                            ' onclick="return oauth2_oidc_2.onClickCopyToken(\'#token_refresh_token\');"/></form></P>' +
                                          '</td>' +
                                          "<td><textarea rows=5 cols=60 readonly name=token_refresh_token id=token_refresh_token data-token-field=\"refresh\"></textarea>" +
                                          "</td>" +
                                        "</tr>";
      }
      token_endpoint_result_html += "</table>" +
                                    "</fieldset>" +
                                    "</div>";
      localStorage.setItem("token_access_token",
                           DOMPurify.sanitize(data.access_token));
      localStorage.setItem("token_refresh_token",
                           DOMPurify.sanitize(data.refresh_token));
      rememberAuthorizationDetails(data);
      saveTokenSetToHistory(DOMPurify.sanitize(data.access_token),
                            DOMPurify.sanitize(data.refresh_token), null,
                            'token', tokenExchangeKept);
    }
    $("#token_endpoint_result").html(token_endpoint_result_html);
    // The pane was just rebuilt, so its HTTP tab has to be put back
    // on it — with the exchange showHttpExchange() drew a moment ago,
    // before this pane existed to draw it in.
    attachHttpTabToTokenResults();
    // The token values are put in as VALUES, not concatenated into the markup
    // above — which is what CodeQL alert #43 (js/xss-through-dom) was
    // reporting: a value read out of the DOM was being reinterpreted as HTML
    // here.
    //
    // .val() sets the DOM value property and never parses markup, so there is
    // no escaping question and no context to break out of. Interpolating into
    // "<textarea>" + token + "</textarea>" had one: a token containing
    // "</textarea>" closes the element early and the rest is parsed as markup.
    // DOMPurify was applied to some of these and could not fix it — it is an
    // HTML sanitizer, and its own allowlist permits <textarea>, so a
    // "<textarea></textarea>" payload survives it intact and still breaks out.
    //
    // Scoped with .find() rather than $("#id") because `refresh_refresh_token`
    // is a DUPLICATE id: the static input in the Refresh Token pane carries it
    // too, and the generated pane comes FIRST in document order. A bare id
    // selector would set whichever the browser found first. Scoping to the
    // container makes these assignments hit exactly the fields built above and
    // leaves the existing $("#refresh_refresh_token").val(...) calls untouched.
    fillGeneratedFields("#token_endpoint_result", {
      access: data.access_token, refresh: currentRefreshToken, id: data.id_token
    });
    expandPane("#token_endpoint_result");
    $("#refresh_refresh_token").val(currentRefreshToken);
    $("#refresh_client_id").val($("#token_client_id").val());
    $("#refresh_scope").val(localStorage.getItem("scope"));
    $("#refresh_client_secret").val(localStorage.getItem("client_secret"));
    $("#token_fieldset").hide();
    $("#token_expand_button").val("Expand");
    useRefreshTokens();
    if(!!currentRefreshToken) {
      $("#logout_id_token_hint").val(data.id_token);
      $("#logout_client_id").val($("#token_client_id").val());
    } else {
      $("#logout_fieldset").hide();
      $("#logout_expand_button").val("Expand");
      $("#refresh_fieldset").hide();
      $("#refresh_expand_button").val("Expand");
    }
    expandPane('#currently-viewing-panel');
    expandPane('#refresh_endpoint_result');
    recalculateRefreshRequestDescription();
    populateRevocationTokenWithLatestAccessToken();
    populateTokenExchangeSubjectWithLatestAccessToken();
    saveOperationToHistory('Token Endpoint', {
      client_id: $("#token_client_id").val(),
      tokenHistoryIndex: getLatestTokenHistoryIndex()
    });
    // Whether the token actually came back sender-constrained, shown beside the
    // token it is about. Read off the token's own cnf.jkt rather than from the
    // fact that a proof was sent: asking does not make it so, and an
    // authorization server that ignores DPoP answers with a perfectly ordinary
    // Bearer token.
    if (dpopVerdictToShow) {
      $("#token_endpoint_result").append(DOMPurify.sanitize(
        "<p id='dpop_result_status' class='" +
        (dpopVerdictToShow.state === "bound" ? "dbg-good" : "dbg-bad") +
         "'>DPoP: " +
        dpopVerdictToShow.text + "</p>"));
    }
    // If another workflow asked for a token, this is one. Before the SD-JWT
    // VC return below, which navigates away when that workflow is the one
    // waiting — the two are never both active, and the order says which wins
    // if a future one ever is.
    offerTokenToHandoff(data.access_token, 'the token endpoint', {
      idToken: data.id_token, refreshToken: data.refresh_token,
      tokenType: data.token_type, scope: data.scope,
      expiresIn: data.expires_in });
    // If the SD-JWT VC workflow sent us here, the tokens are what it came for.
    returnToSdJwtVcFlow();
  log.debug("Leaving successfulInternalTokenAPICall().");
}

function errorInternalTokenAPICall(request, status, error) {
  log.debug("Entering errorInternalTokenAPICall().");
  log.error("An error occurred calling the token endpoint.");
  // A refusal is an exchange, and the one whose headers, body and elapsed
  // time are most often the point. The api attaches its trace to the error
  // payload as well, so the same view is drawn from the same place.
  showHttpExchange("token", request, apiHttpExchange(request, null));
  if (sdJwtVc.isFlowActive()) {
    // Stay on this page — the error panes below say what went wrong — but end
    // the workflow's hold on it.
    sdJwtVc.endFlow();
    $("#sdjwtvc_banner").html("<strong>SD-JWT VC issuance</strong> — the " +
      "token endpoint call failed, so the " +
      "workflow stopped here. The error is shown below; <a " +
          "href='/vc-issuance-1.html'>step 1</a> " +
      "starts it again.");
  }
  log.error("request: " + JSON.stringify(request));
  log.error("status: " + JSON.stringify(status));
  log.error("error: " + JSON.stringify(error));
  recalculateTokenErrorDescription(tokenErrorWithoutTrace(request));
  saveOperationToHistory('Token Endpoint', {
    client_id: $("#token_client_id").val(),
    detail: 'error'
  });
  log.debug("Leaving errorInternalTokenAPICall().");
}

function buildInternalRefreshAPIRequestMessage() {
  log.debug("Entering buildInternalRefreshAPIRequestMessage().");
  log.debug("Entering buildInternalRefreshAPIRequestMessage()."); 
  // validate and process form here
  var token_endpoint = $("#token_endpoint").val();
  var client_id = $("#refresh_client_id").val();
  var client_secret = $("#refresh_client_secret").val();
  if (client_secret == "undefined") {
    client_secret = "";
  }
  var refresh_token = $("#refresh_refresh_token").val();
  var grant_type = $("#refresh_grant_type").val();
  var scope = $("#refresh_scope").val();
  var sslValidate = "";
  if( $("#SSLValidate-yes").is(":checked"))
  {
    sslValidate = $("#SSLValidate-yes").val();
  } else if ($("#SSLValidate-no").is(":checked")) {
    sslValidate = $("#SSLValidate-no").val();
  } else {
    sslValidate = "true";
  }
  var auth_style = getLSBooleanItem("refresh_post_auth_style");
  var formData = {
    grant_type: grant_type,
    client_id: client_id,
    refresh_token: refresh_token,
    scope: scope,
    token_endpoint: token_endpoint,
    sslValidate: sslValidate,
    auth_style: auth_style
  };
  if(typeof client_secret != "undefined")
  {
    formData.client_secret = client_secret
  }
  log.debug("Leaving buildInternalRefreshAPIRequestMessage().");
  log.debug("Leaving buildInternalRefreshAPIRequestMessage().");
  return formData;
}

// The RFC 9700 gate on a refresh, and on what comes back from one. Split out
// of refreshButtonClick() and successfulInternalRefreshAPICall() so that the
// rule is stated once for a pane that has three call paths through it.
function rfc9700GateRefreshRequest() {
  log.debug("Entering rfc9700GateRefreshRequest().");
  if (!rfc9700.enabled()) {
    log.debug("Leaving rfc9700GateRefreshRequest(). Mode off.");
    return { ok: true, blocked: [], findings: [] };
  }
  var verdict = rfc9700.checkTokenRequest({
    grantType: "refresh_token",
    refreshToken: $("#refresh_refresh_token").val()
  });
  renderRfc9700Report("rfc9700_refresh_report", "Refresh Request", verdict);
  log.debug("Leaving rfc9700GateRefreshRequest(). ok=" + verdict.ok);
  return verdict;
}

function refreshButtonClick() {
  log.debug("Entering refreshButtonClick().");
  log.debug("Entering refresh Submit button clicked function.");
  log.debug("Write values to local storage.");
  writeValuesToLocalStorage();
  log.debug("Recalculate refresh request description.");
  recalculateRefreshRequestDescription();
  log.debug("Reset error displays.");
  resetErrorDisplays();
  // RFC 9700 section 4.14.2: a refresh token the server has already replaced
  // is not sent again. See rfc9700GateRefreshRequest().
  var refreshRequestVerdict = rfc9700GateRefreshRequest();
  if (!refreshRequestVerdict.ok) {
    log.debug("Leaving refreshButtonClick(). Refused by RFC 9700 mode.");
    return false;
  }
  var formData = buildInternalRefreshAPIRequestMessage();
  if(useRefreshFrontEnd) {
    var refreshUrl = localStorage.getItem("token_endpoint");
    var refreshBody = convertToOAuth2Format(formData);
    // Recorded for the HTTP tab before the request goes, so that a call which
    // never comes back still shows what left. The headers are the ones this
    // page CHOSE: the browser adds Origin, Referer and User-Agent itself,
    // after script has stopped being able to look, and the pane says so
    // rather than implying this is all of them.
    noteHttpRequestSent("refresh", {
      via: "browser",
      method: "POST",
      url: refreshUrl,
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: refreshBody,
      bodyNote: "The browser adds Origin, Referer, User-Agent and the rest " +
          "of its own headers to this request and does not disclose them to " +
          "script, so they are not listed above.",
      note: null });
    $.ajax({
      type: "POST",
      crossdomain: true,
      url: refreshUrl,
      data: refreshBody,
      contentType: "application/x-www-form-urlencoded",
      success: successfulInternalRefreshAPICall,
      error: errorInternalRefreshAPICall
    });
  } else {
    // http_trace asks the api to hand back what it saw of ITS call to the
    // token endpoint (api/server.js, buildHttpTrace()) — the only way this
    // page can show a proxied exchange, since the browser is not party to it.
    // It is a flag for the api and goes no further: convertToOAuth2Format()
    // builds the outbound form body from named parameters, so nothing here
    // reaches the identity provider.
    var proxiedRefreshBody = JSON.stringify($.extend({}, formData, {
      http_trace: true }));
    noteHttpRequestSent("refresh", {
      via: "api",
      method: "POST",
      url: appconfig.apiUrl + "/token",
      headers: { "Content-Type": "application/json; charset=utf-8" },
      body: proxiedRefreshBody,
      bodyNote: null,
      note: "Waiting for the api, which is making the Refresh Request." });
    $.ajax({
      type: "POST",
      crossdomain: true,
      url: appconfig.apiUrl + "/token",
      data: proxiedRefreshBody,
      contentType: "application/json; charset=utf-8",
      success: successfulInternalRefreshAPICall,
      error: errorInternalRefreshAPICall
    });
  } 
  log.debug("Leaving refreshButtonClick().");
  return false;
}

function successfulInternalRefreshAPICall(data, textStatus, request) {
  log.debug("Entering successfulInternalRefreshAPICall().");
  // The HTTP tab, first, and BEFORE anything else reads the payload: the
  // trace the api attaches is transport, not part of the token response, so
  // it is taken out here rather than left for token history, the RFC 9700
  // checks and the result panes to step around. Drawn before the RFC 9700
  // gate below, which can discard everything else this response carried — a
  // refused response is still an exchange that happened, and hiding it would
  // leave the reader with a verdict and no evidence.
  var refreshApiTrace = apiHttpExchange(request, data);
  if (data && typeof data === "object") {
    delete data.http_exchange;
  }
  var refreshExchangeKept = redactExchangeForStorage(
      showHttpExchange("refresh", request, refreshApiTrace));
  // RFC 9700 section 4.14.2. The refresh response is judged on the same terms
  // as the token response — the ID Token it may carry, whether the token came
  // back bound, and above all whether the refresh token was ROTATED, which is
  // the property this section is mostly about. A refusal discards the set for
  // the same reason it does there.
  if (rfc9700.enabled()) {
    var refreshVerdict = rfc9700.checkTokenResponse({
      data: data,
      grantType: "refresh_token",
      clientId: $("#refresh_client_id").val(),
      requestedScope: $("#refresh_scope").val(),
      previousRefreshToken: $("#refresh_refresh_token").val()
    });
    renderRfc9700Report("rfc9700_refresh_report", "Refresh Response",
                        refreshVerdict);
    if (!refreshVerdict.ok) {
      log.debug("Discarding the refreshed token set: RFC 9700 mode refused " +
                "it.");
      $("#display_refresh_error_class").html(DOMPurify.sanitize(
        "<fieldset><legend>Refresh Response Refused</legend><p>RFC 9700 " +
        "mode discarded what the token endpoint returned. The reasons are " +
        "in the RFC 9700 report above.</p></fieldset>"));
      log.debug("Leaving successfulInternalRefreshAPICall(). Refused.");
      return;
    }
    rfc9700.noteRefreshRotated($("#refresh_refresh_token").val(),
                               data.refresh_token);
  }
  log.debug("Entering ajax success function for Refresh Token call: data=" 
            + JSON.stringify(data)
            + ", textStatus="
            + textStatus
            + ", request=" 
            + JSON.stringify(request));
  log.debug("displayOpenIDConnectArtifacts=" + displayOpenIDConnectArtifacts);
  refreshTokenUsed=true;
  localStorage.setItem("refresh_token_used", true);
  var currentRefreshToken = "";
  var currentAccessToken = "";
  var currentIDToken = "";
  log.debug('data.refresh_token=' + data.refresh_token);
  log.debug("data.access_token=" + data.access_token);
  log.debug("data.id_token=" + data.id_token);
  if(!!data.refresh_token) {
    log.debug('Setting new Refresh Token.');
    currentRefreshToken = data.refresh_token;
  }
  if(!!data.access_token) {
    log.debug("Setting new Access Token.");
    currentAccessToken = data.access_token;
  }
  if(!!data.id_token) {
    log.debug("Setting new ID Token.");
    currentIDToken = data.id_token;
  }
  saveTokenSetToHistory(currentAccessToken, currentRefreshToken, currentIDToken,
                        'refresh', refreshExchangeKept);
  recreateRefreshTokenDisplay(currentRefreshToken, currentAccessToken,
                              currentIDToken);
  saveOperationToHistory('Token Endpoint (Refresh)', {
    client_id: $("#refresh_client_id").val(),
    tokenHistoryIndex: getLatestTokenHistoryIndex()
  });
  log.debug("Leaving ajax success function for Refresh Token.");
  log.debug("Leaving successfulInternalRefreshAPICall().");
}

function recreateRefreshTokenDisplay(currentRefreshToken, currentAccessToken,
                                     currentIDToken) {
  log.debug("Entering recreateRefreshTokenDisplay().");
  log.debug("Entering recreateRefreshTokenDisplay().");
  var refresh_endpoint_result_html = "";
  log.debug("displayOpenIDConnectArtifacts=" + displayOpenIDConnectArtifacts);
  var iteration = 0;
  if(!!localStorage.getItem("refresh_iteration"))
  {
    //iteration = parseInt($("#refresh-token-results-iteration-count").val()) + 1;
    iteration = parseInt(localStorage.getItem("refresh_iteration")) + 1;
  }
  localStorage.setItem("refresh_iteration", iteration);
  if (!!!currentRefreshToken) {
    currentRefreshToken = localStorage.getItem("refresh_refresh_token");
  }
  if (!!!currentAccessToken) {
    currentAccessToken = localStorage.getItem("refresh_access_token");
  }
  if (!!!currentIDToken) {
    currentIDToken = localStorage.getItem("refresh_id_token");
  }
  refresh_endpoint_result_html = '<div class="dbg-pane">' +
                                      '<legend class="dbg-legend" data-target="refresh_result_fieldset">Token Endpoint Results for Refresh Token Call:</legend>' +
                                      '<fieldset ' +
                                          'id="refresh_result_fieldset">' +
                                      "<p><em>Most recent results of the " +
                                          "Refresh Token call.</em></p>" +
				      "<table>" +
				        "<tr>" +
                                          '<td>' +
                                            '<P><a href="/token_detail.html?type=refresh_access" onclick="oauth2_oidc_2.clickLink()">Latest Access Token</a></P>' +
                                            '<P style="font-size:50%;"><a href="/introspection.html?type=refresh_access" onclick="oauth2_oidc_2.clickLink()">Introspect Token</a></P>' +
                                            '<P><input class="btn2 revoke_token_btn" type="button" value="Revoke Token" data-revoke-type="refresh_access" /></P>' +
                                            '<P><form><input class="btn2" ' +
                                                'type="submit" ' +
                                                'value="Copy Token"' +
                                            ' onclick="return oauth2_oidc_2.onClickCopyToken(\'#refresh_access_token\');"/></form></P>' +
                                          "</td>" +
                                          "<td>" + 
                                            "<textarea rows=5 cols=60 readonly name=refresh_access_token id=refresh_access_token data-token-field=\"access\"></textarea>" +
                                          "</td>" +
                                       "</tr>"; 
  if(!!currentRefreshToken) {
    refresh_endpoint_result_html +=     "<tr>" +
                                          '<td>' +
                                            '<P><a href="/token_detail.html?type=refresh_refresh" onclick="oauth2_oidc_2.clickLink()">Latest Refresh Token</a></P>' +
                                            '<P style="font-size:50%;"><a href="/introspection.html?type=refresh_refresh" onclick="oauth2_oidc_2.clickLink()">Introspect Token</a></P>' +
                                            '<P><input class="btn2 revoke_token_btn" type="button" value="Revoke Token" data-revoke-type="refresh_refresh" /></P>' +
                                            '<P><form><input class="btn2" ' +
                                                'type="submit" ' +
                                                'value="Copy Token"' +
                                            ' onclick="return oauth2_oidc_2.onClickCopyToken(\'#refresh_refresh_token\');"/></form></P>' +
                                          "</td>" +
                                          "<td><textarea rows=5 cols=60 readonly name=refresh_refresh_token id=refresh_refresh_token data-token-field=\"refresh\"></textarea>" +
                                          "</td>" +
                                        "</tr>";
  }
  if(displayOpenIDConnectArtifacts) {
    refresh_endpoint_result_html +=      "<tr>" +
                                          '<td>' +
                                            '<P><a href="/token_detail.html?type=refresh_id" onclick="oauth2_oidc_2.clickLink()">Latest ID Token</a></P>' +
                                            '<P style="font-size:50%;">Get <a href="/userinfo.html?type=refresh_access_token" onclick="oauth2_oidc_2.clickLink()">UserInfo Data</a></P>' +
                                            '<P><form><input class="btn2" ' +
                                                'type="submit" ' +
                                                'value="Copy Token"' +
                                            ' onclick="return oauth2_oidc_2.onClickCopyToken(\'#refresh_id_token\');"/></form></P>' +
                                          "</td>" +
                                          "<td>" +
                                            "<textarea rows=5 cols=60 readonly name=refresh_id_token id=refresh_id_token data-token-field=\"id\"></textarea>" +
                                          "</td>" +
                                        "</tr>";
  }
  refresh_endpoint_result_html +=        "<tr>" +
					  "<td>iteration</td>" +
					  "<td>" +
                                            '<input type="text" ' +
                                                'readonly value="' + iteration +
                                            '" id="refresh-token-results-iteration-count" name="refresh-token-results-iteration-count">' +
                                          "</td>" +
                                        "</tr>" +
                                      "</table>" +
                                      "</fieldset>" +
                                      "</div>";
  $("#refresh_endpoint_result").html(refresh_endpoint_result_html);
  // The pane was just rebuilt, so its HTTP tab has to be put back on it —
  // with whatever the refresh channel last drew, which on a page load is
  // nothing and says so. Called before the fields below are filled because
  // attachHttpTab() MOVES the pane's existing children into the first tab
  // panel; a .find() run before that move would be scoped to a container the
  // fields are about to leave.
  attachHttpTabToRefreshResults();
  // Set as values, not concatenated into the markup — CodeQL alert #34, the
  // same finding as #43 above and fixed the same way. See the note there for
  // why .find() is scoped to the pane rather than using a bare id selector.
  fillGeneratedFields("#refresh_endpoint_result", {
    access: currentAccessToken, refresh: currentRefreshToken, id: currentIDToken
  });
  // Update refresh token field in the refresh token grant pane
  $("#refresh_refresh_token").val(currentRefreshToken);
  // Store new tokens in local storage
  if (!!currentAccessToken) {
    localStorage.setItem("refresh_access_token", currentAccessToken );
    offerTokenToHandoff(currentAccessToken, 'a Refresh Token grant', {
      idToken: currentIDToken, refreshToken: currentRefreshToken });
  }
  if (!!currentRefreshToken) {
    localStorage.setItem("refresh_refresh_token", currentRefreshToken );
  }
  if (!!currentIDToken) {
    localStorage.setItem("refresh_id_token", currentIDToken);
  }
  // Update token in logout pane.
  if(currentRefreshToken) {
    $("#logout_id_token_hint").val(currentIDToken);
  } else {
    $("#logout_fieldset").hide();
  }
  recalculateRefreshRequestDescription();
  if (refreshTokenUsed) {
   expandPane("#refresh_endpoint_result");
  } else {
   collapsePane("#refresh_endpoint_result");
  }
  populateRevocationTokenWithLatestAccessToken();
  populateTokenExchangeSubjectWithLatestAccessToken();
  log.debug("Leaving recreateRefreshTokenDisplay().");
  log.debug("Leaving recreateRefreshTokenDisplay().");
}

function errorInternalRefreshAPICall(request, status, error) {
  log.debug("Entering errorInternalRefreshAPICall().");
  log.error("An error occurred making a token refresh call to token endpoint.");
  // A refusal is an exchange, and the one whose headers, body and elapsed
  // time are most often the point. The api attaches its trace to the error
  // payload as well, so the same view is drawn from the same place.
  showHttpExchange("refresh", request, apiHttpExchange(request, null));
  log.error("request: " + JSON.stringify(request));
  log.error("status: " + JSON.stringify(status));
  log.error("error: " + JSON.stringify(error));
  // The trace is taken back out of the response before the error pane prints
  // it verbatim, for the reason tokenErrorWithoutTrace() gives: it has a pane
  // two tabs away and would otherwise fill a five-row textarea in front of
  // the error the reader came for.
  recalculateRefreshErrorDescription(tokenErrorWithoutTrace(request));
  saveOperationToHistory('Token Endpoint (Refresh)', {
    client_id: $("#refresh_client_id").val(),
    detail: 'error'
  });
  log.debug("Leaving errorInternalRefreshAPICall().");
}

function resetUI(value)
{
    log.debug("Entering resetUI().");
    $("#logout_post_redirect_uri").val((appconfig.uiUrl ?
      appconfig.uiUrl : "https://localhost:3000") + "/logout.html");
    if( value == "client_credential" &&
        getParameterByName("redirectFromTokenDetail") != "true")
    {
      $("#code").hide();
      $("#authzUsernameRow").hide();
      $("#authzPasswordRow").hide();
      $("#step2").hide();
      expandPane("#step3");
      $("#token_grant_type").val("client_credentials");
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
      $("#h2_title_2").innerHTML = "Obtain Access Token";
      $("#token_endpoint_result").html("");
      $("#display_token_request").show();
      $("#usePKCE-yes").prop("checked", false);
      $("#usePKCE-no").prop("checked", true);
      usePKCERFC();
      collapsePane("#step5");
      collapsePane("#step6");
      collapsePane("#step7");
      collapsePane("#operation-history-panel");
      $("#useRefreshToken-yes").prop("checked", false);
      $("#useRefreshToken-no").prop("checked", true);
      useRefreshTokenTester = false;
      $("#yesCheckOIDCArtifacts").prop("checked", "false");
      $("#noCheckOIDCArtifacts").prop("checked", "true");
      displayOpenIDConnectArtifacts = false;
    }
    if( value === "resource_owner" &&
        getParameterByName("redirectFromTokenDetail") != "true")
    {
      $("#code").hide();
      $("#authzUsernameRow").show();
      $("#authzPasswordRow").show();
      $("#step2").hide();
      expandPane("#step3");
      $("#response_type").val("");
      $("#token_grant_type").val("password");
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
      $("#h2_title_2").html("Obtain Access Token");
      $("#authorization_endpoint_result").html("");
      $("#token_endpoint_result").html("");
      $("#display_authz_request_class").hide();
      $("#display_token_request").show();
      displayOpenIDConnectArtifacts = false;
      useRefreshTokenTester = $("#useRefreshToken-yes").is(":checked"); 
    }
    if( value == "implicit_grant" &&
        getParameterByName("redirectFromTokenDetail") != "true")
    {
      $("#config_fieldset").hide();
      $("#config_expand_button").val("Expand");
      collapsePane("#step3");
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
    }
    if( value == "implicit_grant" &&
        getParameterByName("redirectFromTokenDetail") == "true")
    {
      $("#config_fieldset").hide();
      $("#config_expand_button").val("Expand");
      collapsePane("#step3");
    }
    if( value == "device_authorization_grant")
    {
      // RFC 8628 device access token request only needs grant_type, device_code
      // and client_id; hide the fields that do not apply to it.
      $("#authzCodeRow").hide();
      $("#authzUsernameRow").hide();
      $("#authzPasswordRow").hide();
      $("#token_redirect_uri").closest('tr').hide();
      $("#token_scope").closest('tr').hide();
      $("#yesResourceCheckToken").closest('tr').hide();
      $("#authzTokenResourceRow").hide();
      $("#customTokenParametersCheck-yes").closest('tr').hide();
      $("#tokenCustomParametersRow").hide();
      $("#token_custom_parameter_list").closest('tr').hide();
      $("#usePKCE-yes").prop("checked", false);
      $("#usePKCE-no").prop("checked", true);
      usePKCE = false;
      usePKCERFC();
      // Show and populate the device flow fields from the device authorization
      // response stored by oauth2_oidc_1.js.
      $("#deviceUserCodeRow").show();
      $("#deviceVerificationUriRow").show();
      $("#deviceVerificationUriCompleteRow").show();
      $("#deviceCodeRow").show();
      $("#device_code").val(localStorage.getItem("device_code"));
      $("#device_user_code").val(localStorage.getItem("user_code"));
      $("#device_verification_uri")
        .val(localStorage.getItem("verification_uri"));
      $("#device_verification_uri_complete")
        .val(localStorage.getItem("verification_uri_complete"));
      $("#step2").hide();
      expandPane("#step3");
      $("#token_grant_type")
        .val("urn:ietf:params:oauth:grant-type:device_code");
      $("#h2_title_2").html("Exchange Device Code for Access Token");
      $("#authorization_endpoint_result").html("");
      $("#display_token_request").show();
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
    }

    resetErrorDisplays();
    $("#yesResourceCheckToken").prop("checked", false);
    $("#noResourceCheckToken").prop("checked", true);
    $("#customTokenParametersCheck-yes").prop("checked", false);
    $("#customTokenParametersCheck-no").prop("checked", true);
    $("#token_postAuthStyleCheckToken").prop("checked", true);
    $("#token_headerAuthStyleCheckToken").prop("checked", false);
    $("#refresh_postAuthStyleCheckToken").prop("checked", true);
    $("#refresh_headerAuthStyleCheckToken").prop("checked", false);

    recalculateTokenRequestDescription();
    log.debug("Leaving resetUI().");
}

function resetErrorDisplays()
{
  log.debug("Entering resetErrorDisplays().");
  $("#display_authz_error_class").html("");
  $("#display_token_error_class").html("");
  $("#display_refresh_error_class").html("");
  log.debug("Leaving resetErrorDisplays().");
}

function writeValuesToLocalStorage()
{
  log.debug("Entering writeValuesToLocalStorage().");
  // The compliance switch is a configuration setting like everything else in
  // that pane. Both pages write the same key through the same module so that
  // one file owns the spelling and the coercion.
  if ($("#rfc9700_mode").length) {
    rfc9700.setEnabled($("#rfc9700_mode").is(":checked"));
  }
  if (localStorage) {
      localStorage.setItem("token_client_id", $("#token_client_id").val());
      localStorage.setItem("token_client_secret",
                           $("#token_client_secret").val());
      localStorage.setItem("token_redirect_uri",
                           $("#token_redirect_uri").val());
      localStorage.setItem("token_username", $("#token_username").val());
      localStorage.setItem("token_scope", $("#token_scope").val());
      localStorage.setItem("authorization_grant_type",
                           $("#authorization_grant_type").val());
      localStorage.setItem("token_resource", $("#token_resource").val());
      localStorage.setItem("yesResourceCheckToken",
                           $("#yesResourceCheckToken").is(":checked"));
      localStorage.setItem("noResourceCheckToken",
                           $("#noResourceCheckToken").is(":checked"));
      localStorage.setItem("yesCheckOIDCArtifacts",
                           $("#yesCheckOIDCArtifacts").is(":checked"));
      localStorage.setItem("noCheckOIDCArtifacts",
                           $("#noCheckOIDCArtifacts").is(":checked"));
      localStorage.setItem("yesCheck", $("#SSLValidate-yes").is(":checked"));
      localStorage.setItem("noCheck", $("#SSLValidate-no").is(":checked"));
      localStorage.setItem("refresh_client_id", $("#refresh_client_id").val());
      localStorage.setItem("refresh_client_secret",
                           $("#refresh_client_secret").val());
      localStorage.setItem("refresh_scope", $("#refresh_scope").val());
      localStorage.setItem("refresh_refresh_token",
                           $("#refresh_refresh_token").val());
      localStorage.setItem("useRefreshToken_yes",
                           $("#useRefreshToken-yes").is(":checked"));
      localStorage.setItem("useRefreshToken_no",
                           $("#useRefreshToken-no").is(":checked"));
      localStorage.setItem("oidc_userinfo_endpoint",
                           $("#oidc_userinfo_endpoint").val());
      localStorage.setItem("jwks_endpoint", $("#jwks_endpoint").val());
      opMetadata.writeToLocalStorage();
      localStorage.setItem("end_session_endpoint",
                           $("#logout_end_session_endpoint").val());
      localStorage.setItem("logout_client_id", $("#logout_client_id").val());
      localStorage.setItem("customTokenParametersCheck-yes",
                           $("#customTokenParametersCheck-yes").is(":checked"));
      localStorage.setItem("customTokenParametersCheck-no",
                           $("#customTokenParametersCheck-no").is(":checked"));
      localStorage.setItem("tokenNumberCustomParameters",
                           $("#tokenNumberCustomParameters").val());
      if ($("#token_postAuthStyleCheckToken").is(":checked"))
      {
        localStorage.setItem("token_post_auth_style", true);
      } else {
        localStorage.setItem("token_post_auth_style", false);
      }
      if ($("#refresh_postAuthStyleCheckToken").is(":checked"))
      {
        localStorage.setItem("refresh_post_auth_style", true);
      } else {
        localStorage.setItem("refresh_post_auth_style", false);
      }
      if ($("#revocation_postAuthStyleCheckToken").is(":checked"))
      {
        localStorage.setItem("revocation_post_auth_style", true);
      } else {
        localStorage.setItem("revocation_post_auth_style", false);
      }
      if ($("#tokenexchange_postAuthStyle").is(":checked"))
      {
        localStorage.setItem("tokenexchange_post_auth_style", true);
      } else {
        localStorage.setItem("tokenexchange_post_auth_style", false);
      }
      localStorage.setItem("tokenexchange_initiateFromFrontEnd",
          $("#tokenexchange_initiateFromFrontEnd").is(":checked"));
      localStorage.setItem("tokenexchange_initiateFromBackEnd",
          $("#tokenexchange_initiateFromBackEnd").is(":checked"));
      if ($("#customTokenParametersCheck-yes").is(":checked")) {
        var i = 0;
        var tokenNumberCustomParameters =
            parseInt($("#tokenNumberCustomParameters").val());
        for(i = 0; i < tokenNumberCustomParameters; i++)
        {
          log.debug("Writing customTokenParameterName-" + i + " as " +
                    $("#customTokenParameterName-" + i).val() + "\n");
          localStorage.setItem("customTokenParameterName-" + i,
                               $("#customTokenParameterName-" + i).val());
          log.debug("Writing customTokenParameterValue-" + i + " as " +
                    $("#customTokenParameterValue-" + i).val() + "\n");
          localStorage.setItem("customTokenParameterValue-" + i,
                               $("#customTokenParameterValue-" + i).val());
        }
      }
      localStorage.setItem("PKCE_code_challenge",
                           $("#token_pkce_code_challenge").val());
      localStorage.setItem("PKCE_code_challenge_method",
                           $("#token_pkce_code_method").val());
      localStorage.setItem("PKCE_code_verifier",
                           $("#token_pkce_code_verifier").val() );
      localStorage.setItem("usePKCE_yes", $("#usePKCE-yes").is(":checked"));
      localStorage.setItem("usePKCE_no", $("#usePKCE-no").is(":checked"));
      localStorage.setItem("token_initiateFromFrontEnd",
                           $("#token_initiateFromFrontEnd").is(":checked"));
      localStorage.setItem("token_initiateFromBackEnd",
                           $("#token_initiateFromBackEnd").is(":checked"));
      localStorage.setItem("refresh_initiateFromFrontEnd",
                           $("#refresh_initiateFromFrontEnd").is(":checked"));
      localStorage.setItem("refresh_initiateFromBackEnd",
                           $("#refresh_initiateFromBackEnd").is(":checked"));
      localStorage.setItem("refresh_token_used", refreshTokenUsed);
      if (!!$("#revocation_revocation_endpoint").val()) {
        localStorage.setItem("revocation_endpoint",
                             $("#revocation_revocation_endpoint").val());
      }
      if (!!$("#registration_endpoint").val()) {
        localStorage.setItem("registration_endpoint",
                             $("#registration_endpoint").val());
      }
      localStorage.setItem("revocation_initiateFromFrontEnd",
          $("#revocation_initiateFromFrontEnd").is(":checked"));
      localStorage.setItem("revocation_initiateFromBackEnd",
                           $("#revocation_initiateFromBackEnd").is(":checked"));
  }

  log.debug("Leaving writeValuesToLocalStorage().");
}

// helper function to set the Grant Type menu option.
function setAuthorizationGrantType()
{
  log.debug("Entering setAuthorizationGrantType().");
  var authzGrantType = localStorage.getItem("authorization_grant_type");
  log.debug("authzGrantType=" + authzGrantType);
  if (!!authzGrantType)
  {
    $("#authorization_grant_type").val(authzGrantType);
  }
  resetUI(authzGrantType);
  log.debug("Entering setAuthorizationGrantType().");
  log.debug("Leaving setAuthorizationGrantType().");
}

// Whether a stored redirect_uri is one the Token Request could carry at all.
// Deliberately a scheme test and nothing more: RFC 8252 section 7.1's
// private-use scheme (com.example.app:/cb) is a redirect URI a native-app
// client legitimately registers, so requiring "://" would reject one. What
// this is here to catch is the empty or relative value an older build could
// leave behind, where the field would come up blank and the exchange would
// fail without saying why.
function isAbsoluteRedirectUri(value) {
  log.debug("Entering isAbsoluteRedirectUri().");
  var ok = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(String(value || ""));
  log.debug("Leaving isAbsoluteRedirectUri(). ok=" + ok);
  return ok;
}

function loadValuesFromLocalStorage()
{
  log.debug("Entering loadValuesFromLocalStorage().");

  setAuthorizationGrantType();

  $("#authorization_endpoint")
    .val(localStorage.getItem("authorization_endpoint"));
  $("#token_endpoint").val(localStorage.getItem("token_endpoint"));

  if (localStorage.getItem("introspection_endpoint")) {
    $("#introspection_endpoint")
      .val(localStorage.getItem("introspection_endpoint"));
    $("#introspection_endpoint").closest('tr').show();
  } else {
    $("#introspection_endpoint").val("");
    $("#introspection_endpoint").closest('tr').hide();
  }

  if (!!localStorage.getItem("revocation_endpoint")) {
    $("#revocation_endpoint").val(localStorage.getItem("revocation_endpoint"));
    $("#revocation_endpoint").closest('tr').show();
    $("#revocation_revocation_endpoint")
      .val(localStorage.getItem("revocation_endpoint"));
  } else {
    $("#revocation_endpoint").val("");
    $("#revocation_endpoint").closest('tr').hide();
  }

  if (!!localStorage.getItem("registration_endpoint")) {
    $("#registration_endpoint")
      .val(localStorage.getItem("registration_endpoint"));
    $("#registration_endpoint").closest('tr').show();
  } else {
    $("#registration_endpoint").val("");
    $("#registration_endpoint").closest('tr').hide();
  }

  if (!!localStorage.getItem("device_authorization_endpoint")) {
    $("#device_authorization_endpoint")
      .val(localStorage.getItem("device_authorization_endpoint"));
    $("#device_authorization_endpoint").closest('tr').show();
  } else {
    $("#device_authorization_endpoint").val("");
    $("#device_authorization_endpoint").closest('tr').hide();
  }
  $("#revocation_client_id").val(localStorage.getItem("client_id"));
  $("#revocation_client_secret").val(localStorage.getItem("client_secret"));
  if (localStorage.getItem("revocation_initiateFromFrontEnd") !== null) {
    $("#revocation_initiateFromFrontEnd").prop("checked",
      getLSBooleanItem("revocation_initiateFromFrontEnd"));
    $("#revocation_initiateFromBackEnd").prop("checked",
      getLSBooleanItem("revocation_initiateFromBackEnd"));
  }
  if (localStorage.getItem("revocation_post_auth_style") !== null) {
    if (getLSBooleanItem("revocation_post_auth_style")) {
      $("#revocation_postAuthStyleCheckToken").prop("checked", true);
      $("#revocation_headerAuthStyleCheckToken").prop("checked", false);
    } else {
      $("#revocation_postAuthStyleCheckToken").prop("checked", false);
      $("#revocation_headerAuthStyleCheckToken").prop("checked", true);
    }
  }

  // Token Exchange (RFC 8693) pane. The exchange is performed against the Token
  // Endpoint, so its endpoint field mirrors the configured token_endpoint.
  $("#tokenexchange_token_endpoint")
    .val(localStorage.getItem("token_endpoint"));
  $("#tokenexchange_client_id").val(localStorage.getItem("client_id"));
  $("#tokenexchange_client_secret").val(localStorage.getItem("client_secret"));
  if (localStorage.getItem("tokenexchange_initiateFromFrontEnd") !== null) {
    $("#tokenexchange_initiateFromFrontEnd").prop("checked",
      getLSBooleanItem("tokenexchange_initiateFromFrontEnd"));
    $("#tokenexchange_initiateFromBackEnd").prop("checked",
      getLSBooleanItem("tokenexchange_initiateFromBackEnd"));
  }
  if (localStorage.getItem("tokenexchange_post_auth_style") !== null) {
    if (getLSBooleanItem("tokenexchange_post_auth_style")) {
      $("#tokenexchange_postAuthStyle").prop("checked", true);
      $("#tokenexchange_headerAuthStyle").prop("checked", false);
    } else {
      $("#tokenexchange_postAuthStyle").prop("checked", false);
      $("#tokenexchange_headerAuthStyle").prop("checked", true);
    }
  }
  $("#token_client_id").val(localStorage.getItem("client_id"));
  $("#token_client_secret").val(localStorage.getItem("client_secret"));
  // THIS ONE IS NOT A SETTING, WHICH IS WHY IT IS NOT HEALED THE WAY STEP 1
  // HEALS ITS OWN FIELD.
  //
  // It is the redirect_uri the authorization request has ALREADY SENT, and RFC
  // 6749 section 4.1.3 requires the Token Request's copy to be identical to
  // it. Re-pointing it at this deployment's origin is step 1's job, on the
  // field a user configures and before anything has been sent; doing it HERE
  // sends a redirect_uri the code was not issued for, and a conforming
  // authorization server answers that with invalid_grant — which is what the
  // mock STS does in RFC 9700 mode, where the comparison is mandatory rather
  // than only made when the client volunteered the value.
  //
  // The mismatch is ordinary rather than exotic: RFC 8252 — and therefore RFC
  // 9700 requirement 1.3 — puts the callback on a loopback origin, and that is
  // not where the pages are served from when they are served from a container
  // or a deployed site. So what is healed here is only a value that could not
  // be sent at all.
  var redirectBase = (appconfig.uiUrl ?
      appconfig.uiUrl : "https://localhost:3000");
  var storedRedirectUri = localStorage.getItem("redirect_uri");
  if (!isAbsoluteRedirectUri(storedRedirectUri)) {
    storedRedirectUri = redirectBase + "/callback";
    localStorage.setItem("redirect_uri", storedRedirectUri);
  }
  $("#token_redirect_uri").val(storedRedirectUri);
  $("#token_scope").val(localStorage.getItem("token_scope"));
  $("#token_username").val(localStorage.getItem("token_username"));
  $("#token_resource").val(localStorage.getItem("token_resource"));
  $("#SSLValidate-yes").prop("checked", getLSBooleanItem("yesCheck"));
  $("#SSLValidate-no").prop("checked", getLSBooleanItem("noCheck"));
  $("#yesResourceCheckToken").prop("checked",
    getLSBooleanItem("yesResourceCheckToken"));
  $("#noResourceCheckToken").prop("checked",
    getLSBooleanItem("noResourceCheckToken"));
  $("#yesCheckOIDCArtifacts").prop("checked",
    getLSBooleanItem("yesCheckOIDCArtifacts"));
  $("#noCheckOIDCArtifacts").prop("checked",
    getLSBooleanItem("noCheckOIDCArtifacts"));
  $("#usePKCE-yes").prop("checked", getLSBooleanItem("usePKCE_yes"));
  $("#usePKCE-no").prop("checked", getLSBooleanItem("usePKCE_no"));
  // Default to the "Back" radio when nothing has been stored yet, so a radio
  // is always selected on first load (otherwise both would be left unchecked).
  if (localStorage.getItem("token_initiateFromFrontEnd") !== null ||
      localStorage.getItem("token_initiateFromBackEnd") !== null) {
    $("#token_initiateFromFrontEnd").prop("checked",
      getLSBooleanItem("token_initiateFromFrontEnd"));
    $("#token_initiateFromBackEnd").prop("checked",
      getLSBooleanItem("token_initiateFromBackEnd"));
  } else {
    $("#token_initiateFromFrontEnd").prop("checked", false);
    $("#token_initiateFromBackEnd").prop("checked", true);
  }
  if (localStorage.getItem("refresh_initiateFromFrontEnd") !== null ||
      localStorage.getItem("refresh_initiateFromBackEnd") !== null) {
    $("#refresh_initiateFromFrontEnd").prop("checked",
      getLSBooleanItem("refresh_initiateFromFrontEnd"));
    $("#refresh_initiateFromBackEnd").prop("checked",
      getLSBooleanItem("refresh_initiateFromBackEnd"));
  } else {
    $("#refresh_initiateFromFrontEnd").prop("checked", false);
    $("#refresh_initiateFromBackEnd").prop("checked", true);
  }

  $("#refresh_refresh_token")
    .val(localStorage.getItem("refresh_refresh_token"));
  $("#customTokenParametersCheck-no").prop("checked",
    getLSBooleanItem("customTokenParametersCheck-no"));
  $("#refresh_client_id").val(localStorage.getItem("refresh_client_id"));
  $("#refresh_scope").val(localStorage.getItem("refresh_scope"));
  $("#refresh_client_secret")
    .val(localStorage.getItem("refresh_client_secret"));
  $("#useRefreshToken-yes").prop("checked",
    getLSBooleanItem("useRefreshToken_yes"));
  $("#useRefreshToken-no").prop("checked",
    getLSBooleanItem("useRefreshToken_no"));
  $("#oidc_userinfo_endpoint")
    .val(localStorage.getItem("oidc_userinfo_endpoint"));
  $("#jwks_endpoint").val(localStorage.getItem("jwks_endpoint"));
  // Falls back to the dummy defaults for any member not in storage yet (this
  // page can be the first one loaded, e.g. via the /callback redirect).
  opMetadata.loadFromLocalStorage();
  // Show the -->not defined<-- note for members the last loaded discovery
  // document omitted (it is fetched on oauth2_oidc_1.html; the log is shared).
  opMetadata.applyNotesFromStoredDiscovery();
  $("#logout_end_session_endpoint")
    .val(localStorage.getItem("end_session_endpoint"));
  $("#logout_client_id").val(localStorage.getItem("client_id"));
  $("#customTokenParametersCheck-yes").prop("checked",
    getLSBooleanItem("customTokenParametersCheck-yes"));
  $("#customTokenParametersCheck-no").prop("checked",
    getLSBooleanItem("customTokenParametersCheck-no"));
  $("#tokenNumberCustomParameters")
    .val(localStorage.getItem("tokenNumberCustomParameters")?
    localStorage.getItem("tokenNumberCustomParameters"): 1);
  if (getLSBooleanItem("token_post_auth_style")) {
    $("#token_postAuthStyleCheckToken").prop("checked", true);
    $("#token_headerAuthStyleCheckToken").prop("checked", false);
  } else {
    $("#refresh_postAuthStyleCheckToken").prop("checked", false);
    $("#refresh_headerAuthStyleCheckToken").prop("checked", true);
  }

  currentRefreshToken = localStorage.getItem("refresh_refresh_token");
  if ($("#customTokenParametersCheck-yes").is(":checked")) {
    generateCustomParametersListUI();
    var i = 0;
    var tokenNumberCustomParameters =
        parseInt($("#tokenNumberCustomParameters").val());
    for(i = 0; i < tokenNumberCustomParameters; i++)
    {
      log.debug("Reading customTokenParameterName-" + i + " as " +
                localStorage.getItem("customTokenParameterName-" + i + "\n"));
      $("#customTokenParameterName-" +
        i).val(localStorage.getItem("customTokenParameterName-" + i));
      log.debug("Reading customTokenParameterValue-" + i + " as " +
                localStorage.getItem("customTokenParameterValue-" + i + "\n"));
      $("#customTokenParameterValue-" +
        i).val(localStorage.getItem("customTokenParameterValue-" + i));
    }
  }

  if ($("#usePKCE-yes").is(":checked")) {
    $("#token_pkce_code_challenge")
      .val(localStorage.getItem("PKCE_code_challenge"));
    $("#token_pkce_code_verifier")
      .val(localStorage.getItem("PKCE_code_verifier"));
    $("#token_pkce_code_method")
      .val(localStorage.getItem("PKCE_code_challenge_method"));
  }
  usePKCERFC();
  refreshTokenUsed=getLSBooleanItem("refresh_token_used");
  renderTokenHistory();
  var savedActiveIndex =
      parseInt(localStorage.getItem('token_history_active_index'));
  if (!isNaN(savedActiveIndex)) {
    var cvHistory = [];
    try {
      cvHistory = JSON.parse(localStorage.getItem('token_history') || '[]');
    } catch (e) {
      // Absent or unreadable storage: keep the default.
    }
    if (savedActiveIndex >= 0 && savedActiveIndex < cvHistory.length) {
      renderCurrentlyViewing(savedActiveIndex, cvHistory[savedActiveIndex]);
    }
  }
  // The RFC 9700 switch, and the shape it puts this page into. Last, because
  // applyRfc9700Ui() moves the client authentication style, the DPoP switch
  // and the front/back-end choice — doing it any earlier would have every one
  // of those overwritten by the stored values read above.
  $("#rfc9700_mode").prop("checked", rfc9700.enabled());
  applyRfc9700Ui();
  log.debug("Leaving loadValuesFromLocalStorage().");
}

// Which tokens the authorization response itself is expected to carry, by grant
// type. The response types that return only a code are absent on purpose: their
// tokens come back from the token endpoint, and that call has its own result
// pane. A hybrid flow's code is handled separately above — this covers only the
// tokens that ride along beside it.
function authorizationResponseTokenTypes(grantType) {
  log.debug("Entering authorizationResponseTokenTypes().");
  switch (grantType) {
    case "implicit_grant":
      log.debug("Leaving authorizationResponseTokenTypes().");
      return { access: true,  id: false };
    case "oidc_implicit_flow":
      log.debug("Leaving authorizationResponseTokenTypes().");
      return { access: true,  id: true  };
    case "oidc_implicit_flow_id_token":
      log.debug("Leaving authorizationResponseTokenTypes().");
      return { access: false, id: true  };
    case "oidc_hybrid_code_token":
      log.debug("Leaving authorizationResponseTokenTypes().");
      return { access: true,  id: false };
    case "oidc_hybrid_code_id_token":
      log.debug("Leaving authorizationResponseTokenTypes().");
      return { access: false, id: true  };
    case "oidc_hybrid_code_id_token_token":
      log.debug("Leaving authorizationResponseTokenTypes().");
      return { access: true,  id: true  };
    default:
      log.debug("Leaving authorizationResponseTokenTypes().");
      return { access: false, id: false };
  }
}

// One token off the authorization response, from wherever the identity provider
// put it. The fragment is what the token-returning response types are specified
// to use; ADFS and Azure AD put them in the query string instead, so both are
// read. storageKey is the last resort and covers one case only: the return from
// the token detail page, which carries no authorization response of its own and
// so has to redisplay what was saved.
//
// An absent token comes back as "" rather than as a placeholder string. The
// placeholders it replaces were shown in the token's own textarea, where they
// read as something the identity provider had said, and were saved to
// localStorage — so every page reached from a link here was handed one.
function authorizationResponseToken(name, storageKey) {
  log.debug("Entering authorizationResponseToken(). name=" + name);
  var fromQuery = getParameterByName(name);
  if (!!fromQuery) {
    log.debug("Found " + name + " in the query string.");
    log.debug("Leaving authorizationResponseToken().");
    return DOMPurify.sanitize(fromQuery);
  }
  var fromFragment = parseFragment()[name];
  if (!!fromFragment) {
    log.debug("Found " + name + " in the fragment.");
    log.debug("Leaving authorizationResponseToken().");
    return DOMPurify.sanitize(fromFragment);
  }
  var saved = storageKey ? localStorage.getItem(storageKey) : "";
  if (!!saved) {
    log.debug("No " + name + " on this response. Using the saved one.");
    log.debug("Leaving authorizationResponseToken().");
    return saved;
  }
  log.debug("No " + name + " found.");
  log.debug("Leaving authorizationResponseToken().");
  return "";
}

// Which Token History entry holds exactly the tokens this pane is showing, or
// null if it has not been recorded yet.
//
// It exists because localStorage's token_access_token / token_id_token are "the
// most recent token", and for a hybrid flow this pane is NOT the most recent:
// the code exchange that follows overwrites both. Links keyed on those slots
// would then open, introspect, fetch UserInfo for — and revoke — a different
// token from the one displayed beside them, silently. The history entry holds
// the exact bytes, and every page these links reach already implements the
// history_* types Currently Viewing uses, so nothing new has to be taught.
//
// Searched newest-first, since the same response replayed twice is the same
// tokens and the later entry is the one being looked at.
function authorizationTokenHistoryIndex(returned) {
  log.debug("Entering authorizationTokenHistoryIndex().");
  var history = [];
  try {
    history = JSON.parse(localStorage.getItem('token_history') || '[]');
  } catch (e) {
    log.error("Failed to parse token_history: " + e);
    log.debug("Leaving authorizationTokenHistoryIndex().");
    return null;
  }
  for (var i = history.length - 1; i >= 0; i--) {
    if (history[i].source === 'authorization' &&
        (history[i].access_token || '') === (returned.access_token || '') &&
        (history[i].id_token || '') === (returned.id_token || '')) {
      log.debug("Leaving authorizationTokenHistoryIndex().");
      return i;
    }
  }
  log.debug("Leaving authorizationTokenHistoryIndex().");
  return null;
}

// The Authorization Endpoint Results pane, built the way every other pane on
// this page is: a dbg-pane whose fieldset both the pane title and the
// Expand/Collapse all switch collapse, and one row per token carrying the same
// links and buttons that token gets when the token endpoint returns it. An
// implicit flow's access token is an ordinary access token, and it was the only
// one on the page that could not be inspected, introspected, revoked, copied or
// used to fetch UserInfo without being selected out of a textarea by hand.
//
// expected says which rows to draw, returned says what to put in them: a row is
// drawn for a token the flow asked for even when none came back, because
// "response_type asked for an id_token and none arrived" is the single most
// useful thing this pane can say. That row states it in words and leaves its
// field empty, rather than offering links that would act on nothing.
//
// The fields are authz_* rather than the token_* ids the Token Endpoint Results
// pane uses, because both panes can be on the page at once — a hybrid flow
// exchanges its code after the authorization response has already returned an
// id_token, and returning from the token detail page redraws the token endpoint
// pane beside this one. Sharing the ids would leave two elements answering to
// #token_access_token, and each pane's Copy button would take whichever came
// first in the document rather than the token it sits next to.
function renderAuthorizationEndpointResults(expected, returned) {
  log.debug("Entering renderAuthorizationEndpointResults().");
  // Once the set is in Token History every link names it by generation, which
  // is the only way they go on meaning THIS token after a hybrid flow's code
  // exchange replaces the current one. Before it is recorded — this pane is
  // drawn first, and document.ready() re-renders it once the entry exists — the
  // plain slots are correct, because nothing has overwritten them yet.
  var generation = authorizationTokenHistoryIndex(returned);
  var byGeneration = (generation !== null);
  var accessType = byGeneration ? "history_access&generation=" +
      generation : "access";
  var userinfoType = byGeneration ? "history_access&generation=" +
      generation : "token_access_token";
  var idType = byGeneration ? "history_id_token&generation=" +
      generation : "id";
  var revokeAttributes = byGeneration
    ? 'data-revoke-type="history_access" data-revoke-generation="' +
        generation + '"'
    : 'data-revoke-type="access"';
  log.debug("Pane links keyed by " + (byGeneration ? "generation " +
            generation : "the current token slots") + ".");
  var html = '<div class="dbg-pane">' +
             '<legend class="dbg-legend" ' +
                 'data-target="authz_result_fieldset">Authorization Endpoint ' +
                 'Results</legend>' +
             '<fieldset id="authz_result_fieldset">' +
             '<p><em>Tokens returned by the Authorization Endpoint itself ' +
                 'rather than by a call to the Token Endpoint.</em></p>' +
             '<table>';
  if (expected.access) {
    html += '<tr><td>';
    if (returned.access_token) {
      html +=   '<P><a href="/token_detail.html?type=' + accessType +
          '" onclick="oauth2_oidc_2.clickLink()">Access Token</a></P>' +
                '<P style="font-size:50%;"><a href="/introspection.html?type=' +
                    accessType +
                    '" onclick="oauth2_oidc_2.clickLink()">Introspect ' +
                    'Token</a></P>' +
                // UserInfo sits on the ACCESS token's row, not on the ID
                // token's where the Token Endpoint Results pane draws it. The
                // call is authenticated with the access token — the link is
                // literally ?type=token_access_token — so this is the token it
                // belongs to, and hanging it off the ID token row means the
                // flows that return an access token and no id_token (OAuth2
                // Implicit Grant, response_type=code token) never offer it at
                // all, which is how it came to be missing here.
                '<P style="font-size:50%;">Get <a href="/userinfo.html?type=' +
                    userinfoType +
                    '" onclick="oauth2_oidc_2.clickLink()">' +
                    'UserInfo Data</a></P>' +
                '<P><input class="btn2 revoke_token_btn" type="button" ' +
                    'value="Revoke Token" ' + revokeAttributes + ' /></P>' +
                '<P><form><input class="btn2" type="submit" ' +
                    'value="Copy Token"' +
                ' onclick="return oauth2_oidc_2.onClickCopyToken(\'#authz_access_token\');"/></form></P>';
    } else {
      html +=   '<P>Access Token</P>';
    }
    html += '</td><td>' +
              '<textarea rows=5 cols=60 readonly name=authz_access_token id=authz_access_token data-token-field="access"></textarea>';
    if (!returned.access_token) {
      html +=   '<p><em>No access_token was returned on the authorization response.</em></p>';
    }
    html += '</td></tr>';
  }
  if (expected.id) {
    html += '<tr><td>';
    if (returned.id_token) {
      html +=   '<P><a href="/token_detail.html?type=' + idType +
          '" onclick="oauth2_oidc_2.clickLink()">ID Token</a></P>' +
                '<P><form><input class="btn2" type="submit" ' +
                    'value="Copy Token"' +
                ' onclick="return oauth2_oidc_2.onClickCopyToken(\'#authz_id_token\');"/></form></P>';
    } else {
      html +=   '<P>ID Token</P>';
    }
    html += '</td><td>' +
              '<textarea rows=5 cols=60 readonly name=authz_id_token id=authz_id_token data-token-field="id"></textarea>';
    if (!returned.id_token) {
      html +=   '<p><em>No id_token was returned on the authorization response.</em></p>';
    }
    // The Token Endpoint Results pane offers UserInfo beside the ID token, and
    // it is absent here, so say why rather than leaving the comparison to be
    // made twice. UserInfo is authenticated with an access token and this
    // response did not carry one, so the link would be dead the moment it
    // appeared. Worded as "this authorization response" rather than "this flow"
    // because a hybrid flow (code id_token) does get an access token — from the
    // token endpoint, whose own pane carries the link.
    if (returned.id_token && !returned.access_token) {
      html +=   '<p><em>No UserInfo link: that call is made with an ' +
          'access token, ' +
                'and this authorization response returned none.</em></p>';
    }
    html += '</td></tr>';
  }
  html += '</table></fieldset></div>';
  // NOT run through DOMPurify, and that is the point rather than an oversight:
  // the string above is a constant with no value interpolated into it, and
  // DOMPurify strips inline event handlers. Sanitizing it — which is what this
  // pane used to do — removed the very onclick attributes its buttons are made
  // of, so "Copy Token" copied nothing and, being inside a <form>, submitted it
  // and reloaded the page instead. The Token Endpoint Results pane is written
  // to the DOM the same way for the same reason.
  //
  // The tokens themselves go in as VALUES below, never as markup: one
  // containing "</textarea>" would otherwise close the element early and have
  // the rest of it parsed as HTML (see fillGeneratedFields).
  $("#authorization_endpoint_result").html(html);
  fillGeneratedFields("#authorization_endpoint_result", {
    access: returned.access_token, id: returned.id_token
  });
  expandPane("#authorization_endpoint_result");
  // An Implicit or Hybrid flow's access token arrives HERE and never at the
  // token endpoint, so a handoff that only watched that endpoint would leave
  // those two flows with a banner that never resolved.
  // An Implicit or Hybrid flow's ID Token arrives here beside the access
  // token, which is the ONE case where the authorization response carries
  // more than the code — so the set is passed here too rather than only at
  // the token endpoint.
  offerTokenToHandoff(returned.access_token, 'the authorization response',
      { idToken: returned.id_token, tokenType: returned.token_type,
        scope: returned.scope, expiresIn: returned.expires_in });
  log.debug("Leaving renderAuthorizationEndpointResults().");
}

function recreateUniqueGrantFlowElements()
{
  log.debug("Entering recreateUniqueGrantFlowElements().");
  var agt = $("#authorization_grant_type").val();
  var pathname = window.location.pathname;
  log.debug("agt=" + agt);
  log.debug("pathname=" + pathname);
  if (  (agt ==  "authorization_grant" || 
         agt == "oidc_hybrid_code_id_token" || 
         agt == "oidc_hybrid_code_token" || 
         agt == "oidc_hybrid_code_id_token_token" ) &&
	pathname == "/oauth2_oidc_2.html")
  {
    log.debug("Checking for code.  agt=" + agt + ", pathname=" + pathname);
    log.debug("fragement: " + parseFragment());
    code = parseFragment()["code"];
    if(!!!code)
    {
      code = "NO_CODE_PRESENTED_IN_EXPECTED_LOCATIONS";
    }
    log.debug("code=" + code);
    if(!!!$("#code").val())
    {
      log.debug("code not yet set in next form. Doing so now.");
      $("#code").val(code);
    }
  }
  // Implicit and hybrid flows return their tokens on the authorization response
  // itself, so this page is where those tokens are first seen: there is no
  // token endpoint call whose result pane would otherwise render them. Which
  // ones to expect is decided by the grant type, and each is looked for in both
  // places one can arrive.
  //
  // They all go into ONE pane. There was a second container for the id_token,
  // which is why an OIDC Implicit Flow put two panes both titled "Authorization
  // Endpoint Results" on the page — and the second printed the placeholder
  // NO_ID_TOKEN_PRESENTED_IN_EXPECTED_LOCATIONS into a textarea whenever the
  // id_token was not where it looked, which reads as a token rather than as an
  // explanation of why there isn't one. Each of the four flows that land here
  // had its own copy of the markup, and they had drifted: two rendered the
  // token beside a bare "access_token" label with no links at all.
  var expectedTokens = authorizationResponseTokenTypes(agt);
  var returnedTokens = { access_token: "", id_token: "" };
  if ( (expectedTokens.access || expectedTokens.id) &&
       pathname == "/oauth2_oidc_2.html")
  {
    returnedTokens.access_token =
      expectedTokens.access ? authorizationResponseToken("access_token",
          "token_access_token") : "";
    returnedTokens.id_token =
      expectedTokens.id ? authorizationResponseToken("id_token",
          "token_id_token") : "";
    log.debug("Authorization response carried: access_token=" +
              returnedTokens.access_token +
              ", id_token=" + returnedTokens.id_token);
  }
  // Nothing found means no authorization response reached this load at all —
  // the page was opened directly, or the identity provider returned an error,
  // which the error pane below reports. Drawing the pane anyway would announce
  // that no token came back from a call that was never made. It IS drawn when
  // one of two expected tokens arrived, because naming the missing one is then
  // the most useful thing on the page.
  if (returnedTokens.access_token || returnedTokens.id_token)
  {
    // Written only when one actually came back. document.ready() clears these
    // keys at the top of every load that is not a return from the token detail
    // page, so there is nothing stale to leave behind — and on that return the
    // saved token is the one being redisplayed.
    if (returnedTokens.access_token) {
      localStorage.setItem("token_access_token", returnedTokens.access_token);
    }
    if (returnedTokens.id_token) {
      // Stored, not merely displayed: /token_detail.html?type=id reads this
      // key, so the ID Token link below is dead without it.
      localStorage.setItem("token_id_token", returnedTokens.id_token);
      $("#logout_id_token_hint").val(returnedTokens.id_token);
    }
    renderAuthorizationEndpointResults(expectedTokens, returnedTokens);
    // Read by document.ready(), which records the set in Token History and then
    // draws the pane again so its links can name that entry. This is the only
    // place that can record it: no other code on the page ever saw these
    // tokens. Which rows to draw travels with them, so the second render does
    // not have to work the grant type out a second time.
    returnedTokens.expected = expectedTokens;
    authorizationResponseTokenSet = returnedTokens;
  }
  var error = getParameterByName("error",window.location.href);
  var authzGrantType = $("#authorization_grant_type").val();
  if(	pathname == "/oauth2_oidc_2.html" && 
	( authzGrantType == "authorization_grant" ||
          authzGrantType == "implicit_grant" ||
          authzGrantType == "oidc_hybrid_code_id_token") &&
	  (!!error))
  {
    error_html = "<fieldset>" +
                   "<legend>Authorization Endpoint Error</legend>" +
                   "<form action='' name='display_authz_error_form' " +
                       "id='display_authz_error_form'>" +
                     "<table>" +
                       "<tr>" +
                         "<td>" +
                           "<label name='display_authz_error_form_label1' value='' id='display_authz_error_form_label1'>Error</label>" +
                         "</td>" +
                         "<td>" +
                           "<textarea rows='5' cols='50' " +
                               "id='display_authz_error_form_textarea1' " +
                               "data-token-field='error'></textarea>" +
                         "</td>" +
                       "</tr>" +
                     "</table>" +
                   "</form>" +
                 "</fieldset>";
    $("#display_authz_error_class").html(DOMPurify.sanitize(error_html));
    fillGeneratedFields("#display_authz_error_class", { error: error });
  }
  log.debug("Entering recreateUniqueGrantFlowElements().");
  log.debug("Leaving recreateUniqueGrantFlowElements().");
}

function recalculateTokenRequestDescription()
{
  log.debug("Entering recalculateTokenRequestDescription().");
  log.debug("update request field");
  var ta1 = $("#display_token_request_form_textarea1");
  var yesCheck = $("#yesResourceCheckToken").is(":checked");
  var resourceComponent = "";
  if(yesCheck) //add resource value to OAuth query string
  {
    var resource = $("#token_resource").val();
    if (!!resource)
    {
      resourceComponent =  "&resource=" + resource;
    }
  }
  var customParametersComponent = "";
  var tokencustomParametersCheck =
      $("#customTokenParametersCheck-yes").is(":checked");
  log.debug("customTokenParametersCheck: " + tokencustomParametersCheck +
            ", type=" + typeof(tokencustomParametersCheck));
  if(tokencustomParametersCheck) {
    const numberCustomParameters =
        parseInt($("#tokenNumberCustomParameters").val());
    log.debug('numberCustomParameters=' + numberCustomParameters);
    var i = 0;
    for(i = 0; i < numberCustomParameters; i++)
    {
       customParametersComponent = customParametersComponent +
                                   $("#customTokenParameterName-" + i).val() +
                                   '=' + $("#customTokenParameterValue-" +
                                       i).val() + "&" + "\n";
    }
    customParametersComponent = customParametersComponent.substring(0,
        customParametersComponent.length - 2);
    log.debug('customParametersComponent=' + customParametersComponent);
  }
  if (!!ta1)
  {
    var grant_type = $("#token_grant_type").val();
    if(grant_type == "authorization_code")
    {
      $("#display_token_request_form_textarea1")
        .val(                 DOMPurify.sanitize("POST " + $("#token_endpoint")
        .val() + "\n" +
								      "Message Body:\n" +
                                                                      "grant_type=" + $("#token_grant_type").val() + "&" + "\n" +
                                                                      "code=" + $("#code").val() + "&" + "\n" +
                                                                      "client_id=" + $("#token_client_id").val() + "&" + "\n" +
                                                                      "redirect_uri=" + $("#token_redirect_uri").val() + "&" +"\n" +
                                                                      "scope=" + $("#token_scope").val()));
      if(usePKCE) {
        $("#display_token_request_form_textarea1")
          .val( $("#display_token_request_form_textarea1").val() +"&\n" +
          "code_verifier=" + $("#token_pkce_code_verifier").val());
      }
    } else if (grant_type == "client_credentials") {
      $("#display_token_request_form_textarea1")
        .val(		      DOMPurify.sanitize("POST " + $("#token_endpoint").val() +
        "\n" +
                                                                      "Message Body:\n" +
                                                                      "grant_type=" + $("#token_grant_type").val() + "&" + "\n" +
                                                                      "client_id=" + $("#token_client_id").val() + "&" + "\n" +
                                                                      "client_secret=" + $("#token_client_secret").val() + "&" + "\n" +
                                                                      "redirect_uri=" + $("#token_redirect_uri").val() + "&" +"\n" +
                                                                      "scope=" + $("#token_scope").val()));
    } else if (grant_type == "password") {
      $("#display_token_request_form_textarea1")
        .val(                 DOMPurify.sanitize("POST " + $("#token_endpoint")
        .val() + "\n" +
                                                                      "Message Body:\n" +
                                                                      "grant_type=" + $("#token_grant_type").val() + "&" + "\n" +
                                                                      "client_id=" + $("#token_client_id").val() + "&" + "\n" +
                                                                      "client_secret=" + $("#token_client_secret").val() + "&" + "\n" +
                                                                      "username=" + $("#token_username").val() + "&" + "\n" +
                                                                      "password=" + $("#token_password").val() + "&" + "\n" +
                                                                      "scope=" + $("#token_scope").val()));
    } else if (grant_type == "urn:ietf:params:oauth:grant-type:device_code") {
      $("#display_token_request_form_textarea1")
        .val(                 DOMPurify.sanitize("POST " + $("#token_endpoint")
        .val() + "\n" +
                                                                      "Message Body:\n" +
                                                                      "grant_type=" + $("#token_grant_type").val() + "&" + "\n" +
                                                                      "device_code=" + $("#device_code").val() + "&" + "\n" +
                                                                      "client_id=" + $("#token_client_id").val()));
    }
    if ( resourceComponent.length > 0) {
       $("#display_token_request_form_textarea1")
         .val( $("#display_token_request_form_textarea1").val() + "&\n" +
         resourceComponent + "\n");
     }
     if (customParametersComponent.length > 0) {
       $("#display_token_request_form_textarea1")
         .val( $("#display_token_request_form_textarea1").val() + "&\n" +
         customParametersComponent + "\n");
     }
     // RFC 9449: the proof rides in a DPoP header, so a preview that showed
     // only the body would describe a different request from the one being
     // sent. It is named rather than rendered, because a proof covers its own
     // jti and iat and is single use — any proof shown in advance would not be
     // the one that goes.
     if (!sdJwtVc.isFlowActive() && oauthDpop.enabled()) {
       var dpopLine = useFrontEnd
         ? "\n\nHeaders:\nDPoP: <a fresh RFC 9449 proof over POST " +
             $("#token_endpoint").val() +
           ", signed by the key with thumbprint " + (oauthDpop.jkt() ||
               "(none generated yet)") + ">"
         : "\n\n(DPoP is on, but this call is proxied through the api, which " +
             "does not forward " +
           "proofs — the request that reaches the token endpoint will carry none.)";
       $("#display_token_request_form_textarea1").val(
         $("#display_token_request_form_textarea1").val() + dpopLine);
     }
  }
  log.debug("Leaving recalculateTokenRequestDescription().");
}

function recalculateRefreshRequestDescription()
{
  log.debug("Entering recalculateRefreshRequestDescription().");
  log.debug("update request field");
  var ta1 = $("#display_refresh_request_form_textarea1");
  var resourceComponent = "";

  if (!!ta1)
  {
    var grant_type = $("#refresh_grant_type").val();
    if( grant_type == "refresh_token")
    {
      var client_secret = $("#refresh_client_secret").val();
      if(!!client_secret)
      {
        $("#display_refresh_request_form_textarea1")
          .val(DOMPurify.sanitize("POST " + $("#token_endpoint").val() + "\n" +
                                                                      "Message Body:\n" +
                                                                      "grant_type=" + $("#refresh_grant_type").val() + "&" + "\n" +
                                                                      "refresh_token=" + $("#refresh_refresh_token").val() + "&" + "\n" +
                                                                      "client_id=" + $("#refresh_client_id").val() + "&" + "\n" +
                                                                      "client_secret=" + $("#refresh_client_secret").val() + "&" + "\n" +
                                                                      "scope=" + $("#refresh_scope").val() + "\n"));
      } else {
        $("#display_refresh_request_form_textarea1")
          .val(DOMPurify.sanitize("POST " + $("#token_endpoint").val() + "\n" +
                                                                      "Message Body:\n" +
                                                                      "grant_type=" + $("#refresh_grant_type").val() + "&" + "\n" +
                                                                      "refresh_token=" + $("#refresh_refresh_token").val() + "&" + "\n" +
                                                                      "client_id=" + $("#refresh_client_id").val() + "&" + "\n" +
                                                                      "scope=" + $("#refresh_scope").val() + "\n"));
      }
    }
  }
  log.debug("Leaving recalculateRefreshRequestDescription().");
}

function processStateParameter()
{
  log.debug("Entering processStateParameter().");
  // Check if state matches
  log.debug("Checking on state.");
  var state = DOMPurify.sanitize(getParameterByName("state"));
  var stateParameterFound = false;
  if (!!state) {
    log.debug("Found state in query parameters: " + state);
    stateParameterFound = true;
  } else {
    log.debug("Didn't find state in query parameters, attempting to find " +
              "fragment.");
    state = parseFragment()["state"];
    if(!!state) {
      log.debug("Found state in fragment.");
      stateParameterFound = true
    } else {
      log.debug("Didn't find state.");
    }
  }
  var storedState = localStorage.getItem("state");
  // Generate report
  if(stateParameterFound) {
    if ( !!state &&
         !!storedState &&
         state == storedState) {
      log.debug('State matches stored state.');
      var stateReportHTML = '<fieldset>' +
                            '<legend>State Report</legend>' +
                            '<P>' + 'State matches: state=' + state + '</P>' +
                            '</fieldset>';
      $("#state-status").html(DOMPurify.sanitize(stateReportHTML));
    } else {
      log.debug('State does not match: state=' + state + ', storedState=' +
                storedState);
      var stateReportHTML = '<fieldset>' +
                            '<legend>State Report</legend>' +
                            '<P>State does not match: state=' + state +
                                ', storedState=' + storedState + '</P>' +
                            '</fieldset>';
      $("#state-status").html(DOMPurify.sanitize(stateReportHTML));
    }
  }
  log.debug("Leaving processStateParameter().");
}

// On a static build (appconfig.backendAvailable === false) there is no api
// backend, so every "Initiate ... Call From front or backend" control must use
// the frontend. Force the Front radio on and disable (gray out) the Back radio
// for each group, then sync the module flags the call logic reads.
function enforceBackendAvailability() {
  log.debug("Entering enforceBackendAvailability().");
  if (appconfig.backendAvailable === false) {
    var groups = ["token", "refresh", "revocation", "tokenexchange"];
    for (var i = 0; i < groups.length; i++) {
      $("#" + groups[i] + "_initiateFromFrontEnd").prop("checked", true);
      $("#" + groups[i] + "_initiateFromBackEnd").prop("checked",
        false).prop("disabled", true);
    }
    setInitiateFromEnd();
    setInitiateRefreshFromEnd();
    setInitiateRevocationFromEnd();
    setInitiateTokenExchangeFromEnd();
  }
  log.debug("Leaving enforceBackendAvailability().");
}

// The three implicit variants the Authorization Grant Type drop down offers:
// OAuth2 Implicit Grant, and the two OIDC Implicit Flows (id_token token, and
// id_token alone). What they share is the only thing the callers below care
// about — the tokens come back on the authorization response itself, so there
// is no second call for this page to help compose.
function isImplicitGrantType(grantType) {
  log.debug("Entering isImplicitGrantType().");
  log.debug("Leaving isImplicitGrantType().");
  return grantType === "implicit_grant" ||
         grantType === "oidc_implicit_flow" ||
         grantType === "oidc_implicit_flow_id_token";
}

// True when this page load is one the identity provider sent a token to.
//
// Both places a token can arrive are checked: the fragment, which is the
// binding an implicit response uses, and the query string, because ADFS and
// Azure AD put it there instead (recreateUniqueGrantFlowElements() reads both
// for the same reason). localStorage is deliberately NOT consulted — it still
// holds the previous run's token, which would make a return carrying an error
// look like a successful one.
//
// The way back from the token detail page carries no authorization response of
// its own, but it is reachable only from a token that was already returned, so
// it counts.
function implicitTokenReturned() {
  log.debug("Entering implicitTokenReturned().");
  var fragment = parseFragment();
  log.debug("Leaving implicitTokenReturned().");
  return !!fragment["access_token"] ||
         !!fragment["id_token"] ||
         !!getParameterByName("access_token") ||
         !!getParameterByName("id_token") ||
         getParameterByName("redirectFromTokenDetail") === "true";
}

// Collapse the page's first row of panes: Configuration Parameters, Tools, and
// the token request. Only the default state is set here — each pane's title
// still expands it, as does the Expand all panes switch. Tools already ships
// collapsed in the markup and is named anyway, so the row is stated in one
// place rather than depending on three separate defaults staying put.
function collapseFirstPaneRow() {
  log.debug("Entering collapseFirstPaneRow().");
  var panes = [["config_fieldset", "config_expand_button"],
               ["tools_fieldset", "tools_expand_button"],
               ["token_fieldset", "token_expand_button"]];
  for (var i = 0; i < panes.length; i++) {
    $("#" + panes[i][0]).css("display", "none");
    $("#" + panes[i][1]).val("Expand");
  }
  log.debug("Leaving collapseFirstPaneRow().");
}

$(document).ready(function() {
  log.debug("Entering document.ready() function.");

  if (!appconfig) {
    log.debug('Failed to load appconfig.');
  }

  var authorization_grant_type = $("#authorization_grant_type").val();

  $("#authorization_grant_type").change(function() {
    log.debug("Entering selection changed function().");
    var value = $(this).val();
    localStorage.setItem("authorization_grant_type", value);
    if (value != "client_credential") {
      writeValuesToLocalStorage();
      window.location.href = "/oauth2_oidc_1.html";
    }
    if( value == "oidc_authorization_code_flow" ||
       value === "authorization_grant")
    {
      $("#usePKCE-yes").prop("checked", true);
      $("#usePKCE-no").prop("checked", false);
      usePKCE = true
      $("#yesCheckOIDCArtifacts").prop("checked", true);
      $("#noCheckOIDCArtifacts").prop("checked", false);
      displayOpenIDConnectArtifacts = true;
      $("#useRefreshToken-yes").prop("checked", true);
      $("#useRefreshToken-no").prop("checked", false);
      useRefreshTokenTester = true;
      usePKCERFC();
      writeValuesToLocalStorage();
    }
    resetUI(value);
    recalculateTokenRequestDescription();
    recalculateRefreshRequestDescription();
    log.debug("Leaving selection changed function().");
  });
 
  $("#password-form-group1").hide();
  $("#password-form-group2").hide();

  // If we are not coming back from the Token Detail Page clear all saved
  // tokens. It will be reset.
  if(getParameterByName("redirectFromTokenDetail") != "true") {
    // Clear all token values.
    log.debug("Detected page load for new grant/flow workflow. Clearing all " +
              "existing tokens.");
    localStorage.setItem("token_access_token", "");
    localStorage.setItem("token_id_token", "");
    localStorage.setItem("token_refresh_token", "");
    localStorage.setItem("refresh_access_token", "");
    localStorage.setItem("refresh_id_token", "");
    localStorage.setItem("refresh_refresh_token", "");
    localStorage.setItem("refresh_iteration", "");
  }

  processStateParameter();

  // RFC 9700's judgement on the authorization RESPONSE — state, the RFC 9207
  // iss parameter, and whether this browser session started the transaction at
  // all. It runs before the error block below because an error IS a response
  // and section 4.10.1 has something to say about which errors a server should
  // have redirected at all.
  //
  // A refusal stops the page: the token request pane is hidden, because
  // exchanging a code from a response that failed a MUST is precisely what
  // sections 2 and 4.5 exist to prevent.
  if (rfc9700.enabled() && rfc9700AuthorizationResponsePresent()) {
    var authzVerdict = rfc9700.checkAuthorizationResponse({
      state: DOMPurify.sanitize(getParameterByName("state") ||
                                parseFragment()["state"] || ""),
      iss: DOMPurify.sanitize(getParameterByName("iss") ||
                              parseFragment()["iss"] || ""),
      code: DOMPurify.sanitize(getParameterByName("code") ||
                               parseFragment()["code"] || ""),
      error: DOMPurify.sanitize(getParameterByName("error") ||
                                parseFragment()["error"] || "")
    });
    renderRfc9700Report("rfc9700_response_report", "Authorization Response",
                        authzVerdict);
    if (!authzVerdict.ok) {
      log.debug("RFC 9700 mode refused the authorization response.");
      collapsePane("#step3");
      collapsePane("#step4");
      collapsePane("#step5");
      collapsePane("#step6");
      collapsePane("#step7");
      rfc9700ScrubAuthorizationResponse();
      log.debug("Leaving document.ready(). Refused by RFC 9700 mode.");
      return;
    }
    // Only now, and only on a response that passed: consuming a state on a
    // response that was rejected would make the SECOND, legitimate delivery
    // fail for the wrong reason and cite the wrong rule.
    rfc9700.consumeState();
  }

  // an error was returned from the authorization endpoint
  var errorDescriptionParam =
      DOMPurify.sanitize(getParameterByName('error_description'));
  var errorParam = DOMPurify.sanitize(getParameterByName('error'));
  log.debug('errorDescriptionParam=' + errorDescriptionParam + ', errorParam=' +
            errorParam);
  if (!!errorDescriptionParam || 
      !!errorParam) {
    collapsePane('#step0');
    collapsePane('#step3');
    collapsePane('#step4');
    var authzErrorReportHTML = '<fieldset>' +
                               '<legend>Authorization Endpoint Error ' +
                                   'Report</legend>' +
                               '<P>' + 'Error: ' + errorParam + '</P>' +
                               '<P>' + 'Error Description: ' +
                                   errorDescriptionParam + '</P>' +
                               '</fieldset>';
    $('#authz-error-report').html(DOMPurify.sanitize(authzErrorReportHTML));
    log.debug('errorDescriptionParam=' + errorDescriptionParam +
              ', errorParam=' + errorParam); 
    return;
  }

  // Sets the authorization grant type based upon
  // what is in local storage, which must be set.
  // The next call to to resetUI assumes this is set
  // the way it needs to be.
  setAuthorizationGrantType();

  resetUI();
  initFields();
  generateCustomParametersListUI();
  // The authorization code, from wherever the response mode put it.
  //
  // The query string was the only place this looked until form_post: RFC 9700
  // section 4.12.2 recommends that mode, so client/server.js accepts the POST
  // and hands the parameters to this page in the FRAGMENT (a fragment is never
  // sent to a server, which is the point) — and on a plain code flow the code
  // then arrived somewhere nothing read. recreateUniqueGrantFlowElements()
  // already had a fragment fallback, but only for the OAuth2 code grant and
  // the three hybrids, so oidc_authorization_code_flow fell through both and
  // the Token Request pane opened with an empty code field.
  //
  // Reading both places unconditionally is a no-op everywhere else: on a query
  // response the first operand wins, and on a fragment response there was
  // nothing in the query to lose.
  $("#code").val(getParameterByName('code') || parseFragment()['code'] || '');
  $("#customTokenParametersCheck-yes").on("click",
    recalculateTokenRequestDescription);
  $("#customTokenParametersCheck-no").on("click",
    recalculateTokenRequestDescription);

  loadValuesFromLocalStorage();
  enforceBackendAvailability();
  // The DPoP pane reflects stored state on load, so a switch left on in a
  // previous session is visible rather than silently in force — which is the
  // failure this whole pane exists to end.
  renderOauthDpopStatus();
  recreateUniqueGrantFlowElements();
  recalculateAuthorizationErrorDescription();
  recalculateTokenRequestDescription();
  recalculateRefreshRequestDescription();

  // Record the Authorization Endpoint call once when we return from the IdP
  // with an authorization response (code, access_token, or id_token). The
  // signature dedupes so a manual page reload does not record it again.
  if (getParameterByName("redirectFromTokenDetail") != "true") {
    var fragmentParams = parseFragment();
    var authzSignature = DOMPurify.sanitize(getParameterByName('code') ||
                         fragmentParams['code'] ||
                         getParameterByName('access_token') || 
                         fragmentParams['access_token'] ||
                         getParameterByName('id_token') ||
                                            fragmentParams['id_token']);
    if (!!authzSignature &&
        localStorage.getItem('last_authz_signature') !== authzSignature) {
      // An implicit or hybrid flow's tokens came from the response this
      // signature was taken from, so this is the only chance to record them:
      // no token endpoint call will happen, and saveTokenSetToHistory() is
      // otherwise reached only from one. Without it the tokens were missing
      // from Token History, and so from Currently Viewing and every history_*
      // link — an implicit token set looked like it had never been issued.
      //
      // Recorded under the same signature dedupe as the operation, so a reload
      // of the same response does not add a second copy of either.
      var tokenHistoryIndex = null;
      if (authorizationResponseTokenSet &&
          (authorizationResponseTokenSet.access_token ||
           authorizationResponseTokenSet.id_token)) {
        tokenHistoryIndex =
            saveTokenSetToHistory(authorizationResponseTokenSet.access_token,
                                                  '',
                                                  authorizationResponseTokenSet.id_token,
                                                  'authorization');
        // Drawn again now that the entry exists, so the pane's links name it by
        // generation instead of the current-token slots — which a hybrid flow's
        // code exchange is about to overwrite with a different token.
        renderAuthorizationEndpointResults(
            authorizationResponseTokenSet.expected,
                                           authorizationResponseTokenSet);
      }
      saveOperationToHistory('Authorization Endpoint', {
        client_id: localStorage.getItem('client_id'),
        tokenHistoryIndex: tokenHistoryIndex
      });
      localStorage.setItem('last_authz_signature', authzSignature);
    }
  }
  renderOperationHistory();

  var yesCheckedToken = $("#yesResourceCheckToken").is(":checked");
  if(yesCheckedToken)
  {
    $("#authzTokenResourceRow").show();
  } else {
    $("#authzTokenResourceRow").hide();
  }
  if( $("#useRefreshToken-yes").is(":checked"))
  {
    useRefreshTokenTester = $("#useRefreshToken-yes").val();
  } else if ($("#useRefreshToken-no").is(":checked")) {
    useRefreshTokenTester = $("#useRefreshToken-no").val();
  } else {
    useRefreshTokenTester = true;
  }
  if(useRefreshTokenTester == true)
  {
    expandPane("#step4");
  } else {
    collapsePane("#step4");
  }
  var tokencustomParametersCheck =
      $("#customTokenParametersCheck-yes").is(":checked");
  if(tokencustomParametersCheck)
  {
    $("#tokenCustomParametersRow").show();
  } else {
    $("#tokenCustomParametersRow").hide();
  }

  var authzGrantType = localStorage.getItem("authorization_grant_type");
  if (authzGrantType == "client_credential") {
    usePKCE = false;
    $("#usePKCE-yes").prop("checked", false);
    $("#usePKCE-no").prop("checked", true);
    usePKCE = false
    $("#yesCheckOIDCArtifacts").prop("checked", false);
    $("#noCheckOIDCArtifacts").prop("checked", true);
    displayOpenIDConnectArtifacts = false;
    $("#useRefreshToken-yes").prop("checked", false);
    $("#useRefreshToken-no").prop("checked", true);
    useRefreshTokenTester = false;
    usePKCERFC();
  }

  displayTokenCustomParametersCheck();

  if( getParameterByName("redirectFromTokenDetail") == "true" &&
      ( authorization_grant_type != "implicit_grant" && 
        authorization_grant_type != "oidc_implicit_grant"))
  {
    log.debug('Detected redirect back from token detail page.');
    collapsePane("#step3");
    if (useRefreshTokenTester) {
      expandPane("#step4");
    }
    recreateTokenDisplay();
    recreateRefreshTokenDisplay("", "", ""); // no new token
    $("#logout_id_token_hint").val(localStorage.getItem("token_id_token"));
    // Tokens already exist on this path, so show the panes that operate on
    // them (logout, revocation, token exchange) and the operation history.
    expandPane("#step5");
    expandPane("#step6");
    expandPane("#step7");
    expandPane("#operation-history-panel");
  }

  recalculateRefreshRequestDescription();

  $(".token_btn").click(tokenButtonClick);
  $(".refresh_btn").click(refreshButtonClick);

  // The HTTP tab starts out saying that nothing has been sent yet, rather than
  // empty: an empty panel behind a tab reads as a tab that does not work.
  renderHttpExchange("token", null);
  renderHttpExchange("refresh", null);

  // Initialize revocation pane state and keep the request preview in sync.
  useRevocationFrontEnd = $("#revocation_initiateFromFrontEnd").is(":checked");
  $("#revocation_token, #revocation_revocation_endpoint, " +
    "#revocation_client_id, #revocation_client_secret")
    .on("keyup change", recalculateRevocationRequestDescription);
  $("#revocation_token_type_hint").on("change",
    recalculateRevocationRequestDescription);
  // Delegated so it also fires for the dynamically-rendered "Revoke Token"
  // buttons in the result panes (and survives DOMPurify, which keeps data-*
  // attributes but strips inline onclick handlers).
  $(document).on("click", ".revoke_token_btn", function() {
    revokeTokenDirect($(this).attr("data-revoke-type"),
                      $(this).attr("data-revoke-generation"));
    return false;
  });
  // Collapse/expand for the ds-style panes that are rendered dynamically (the
  // result and history panes). Delegated so it fires for markup inserted after
  // load; keyed on data-target (which survives DOMPurify) rather than inline
  // onclick. The static panes use their own inline title onclick handlers.
  $(document).on("click", ".dbg-legend[data-target]", function() {
    var fs = document.getElementById($(this).attr("data-target"));
    if (fs) {
      var shut = fs.style.display === "none";
      fs.style.display = shut ? "block" : "none";
      // Kept in step with collapsePane()'s mark, for the reason given there.
      var pane = $(fs).closest(".dbg-pane").parent();
      if (shut) {
        pane.removeAttr("data-pane-collapsed");
      } else {
        pane.attr("data-pane-collapsed", "1");
      }
    }
    return false;
  });
  populateRevocationTokenWithLatestAccessToken();

  // Initialize Token Exchange pane state and keep the request preview in sync.
  useTokenExchangeFrontEnd =
      $("#tokenexchange_initiateFromFrontEnd").is(":checked");
  $("#tokenexchange_token_endpoint, #tokenexchange_subject_token, " +
    "#tokenexchange_actor_token, #tokenexchange_resource, " +
    "#tokenexchange_audience, #tokenexchange_scope, " +
    "#tokenexchange_client_id, #tokenexchange_client_secret")
    .on("keyup change", recalculateTokenExchangeRequestDescription);
  $("#tokenexchange_subject_token_type, #tokenexchange_actor_token_type, " +
    "#tokenexchange_requested_token_type")
    .on("change", recalculateTokenExchangeRequestDescription);
  setTokenExchangeType();
  populateTokenExchangeSubjectWithLatestAccessToken();

  if (!window.location.search) {
    expandPane('#step3');
    $('#token_fieldset').css('display', 'block');
    $('#token_expand_button').val('Collapse');
    $('#config_fieldset').css('display', 'block');
    $('#config_expand_button').val('Collapse');
    collapsePane('#step4');
    collapsePane('#step5');
    collapsePane('#step6');
    collapsePane('#step7');
    collapsePane('#operation-history-panel');
    collapsePane('#token-history-panel');
    collapsePane('#currently-viewing-panel');
    collapsePane('#token_endpoint_result');
    collapsePane('#refresh_endpoint_result');
  }

  // The authorization-code return path is the one that reaches here with the
  // token pane still shut: `#token_fieldset` is written `style="display:none"`
  // in the markup, and a page carrying a `code` in its query string runs
  // through none of the branches above that open it. So this opens it — a
  // reader who has just come back from the identity provider with a code came
  // here to exchange it.
  //
  // Not on a pane that was collapsed ON PURPOSE, which is what the mark says.
  // This used to read `$('#step3').is(':visible')`, and that was enough while
  // the branch above hid the pane outright: a hidden container is not
  // `:visible`, so the guard skipped it. Now that the pane collapses instead
  // — see collapsePane() — a deliberately shut pane is a visible container
  // over a shut fieldset, which is exactly what this opens, and the
  // redirect-from-token-detail path would have had its collapse undone three
  // lines later.
  if ( $('#step3').attr('data-pane-collapsed') !== '1' &&
       $('#token_fieldset').css('display') === 'none') {
    $('#token_fieldset').css('display', 'block');
    $('#token_expand_button').val('Collapse');
  }

  // All three implicit variants, not the two this listed: an OIDC Implicit Flow
  // returning only an id_token (response_type=id_token) is as much an implicit
  // flow as the other two, and leaving it out left it as the one flow whose
  // Operation History panel stayed hidden — the no-query-string branch above
  // hides it, and this is what puts it back.
  if (isImplicitGrantType(authzGrantType))
  {
    expandPane('#step3');
    expandPane('#step4');
    expandPane('#step5');
    expandPane('#step6');
    expandPane('#step7');
    expandPane('#operation-history-panel');
  }

  // Both history panels were just hidden by the no-query-string branch above,
  // and for these flows that is wrong: an authorization response carrying
  // tokens arrives in the FRAGMENT — implicit and hybrid alike — so there is no
  // query string to tell it apart from a page opened fresh. An authorization
  // code flow never hit this, because its code comes back in the query string,
  // which is why the two histories looked broken only on the flows that return
  // tokens.
  //
  // Gated on a response having actually carried one, so a page opened fresh
  // under one of these grant types is left alone. renderTokenHistory() decides
  // its own panel's visibility from whether there is anything in it; the
  // operation history panel has no such rule, and by this point it certainly
  // has an entry — the Authorization Endpoint call was recorded above.
  if (authorizationResponseTokenSet &&
      (authorizationResponseTokenSet.access_token ||
       authorizationResponseTokenSet.id_token)) {
    renderTokenHistory();
    expandPane('#operation-history-panel');
  }

  // An implicit flow's tokens arrive with the authorization response, so once
  // the identity provider has sent one there is nothing left to fill in on the
  // first row of panes — the token request they sit beside describes a call
  // this flow never makes. Collapse the row so the page opens on the tokens
  // below it.
  //
  // This runs after the blocks above rather than in place of any of them,
  // because two of them expand that row: the no-query-string path (which an
  // implicit response takes, its parameters being in the fragment) expands both
  // Configuration Parameters and the token pane, and the "step3 is visible but
  // its fieldset is collapsed" repair expands the token pane again. Collapsing
  // earlier would simply be undone.
  if (isImplicitGrantType(authzGrantType) && implicitTokenReturned()) {
    log.debug("Implicit flow returned a token. Collapsing the first row " +
              "of panes.");
    collapseFirstPaneRow();
  }

  maybeContinueSdJwtVcFlow();
  maybeShowTokenHandoffBanner();
  // RFC 9700 section 4.12.2 (requirement 10.1). Last thing in this handler,
  // because everything above reads the response out of the live URL and the
  // scrub replaces it. Out of mode the URL is left exactly as the identity
  // provider delivered it, which is frequently the thing somebody came here to
  // copy.
  rfc9700ScrubAuthorizationResponse();
  log.debug("Leaving document.ready().");
});

// ---------------------------------------------------------------------------
// SD-JWT VC issuance.
//
// When the workflow started on vc-issuance-1.html marked itself active,
// this page is a waypoint rather than a destination: exchange the authorization
// code for tokens as usual, then hand the browser back to the workflow, which
// needs the access token to make its OID4VCI Credential Request.
//
// The flag is only ever set by that workflow (and cleared as soon as it is
// used), so an ordinary visit to this page behaves exactly as before.
// ---------------------------------------------------------------------------
function maybeContinueSdJwtVcFlow() {
  log.debug("Entering maybeContinueSdJwtVcFlow().");
  if (!sdJwtVc.isFlowActive()) {
    log.debug("Leaving maybeContinueSdJwtVcFlow().");
    return false;
  }
  var code = getParameterByName('code');
  if (!code) {
    // No authorization code — the flow did not get this far. Say so rather
    // than silently doing nothing; the error panes above have the detail.
    $(".container").prepend(
      "<div class='vc-handoff-banner'><strong>SD-JWT VC issuance</strong> — " +
          "no authorization code came back " +
      "from the identity provider, so there are no tokens to carry into the " +
          "credential request. " +
      "<a href='/vc-issuance-1.html'>Return to step 1</a>.</div>");
    sdJwtVc.endFlow();
    log.debug("Leaving maybeContinueSdJwtVcFlow().");
    return false;
  }
  $(".container").prepend(
    "<div class='vc-handoff-banner' id='sdjwtvc_banner'><strong>SD-JWT VC " +
        "issuance</strong> — exchanging the " +
    "authorization code for tokens, then returning to <a href='" +
        sdJwtVc.STEP2_URL + "'>step 2</a> to request " +
    "the credential.</div>");
  window.setTimeout(tokenButtonClick, 250);
  log.debug("Leaving maybeContinueSdJwtVcFlow().");
  return true;
}

// ---------------------------------------------------------------------------
// ANOTHER WORKFLOW IS WAITING FOR AN ACCESS TOKEN.
//
// The SCIM page sends the reader here with `token_handoff.js` marked active,
// because RFC 7644 section 2 has it authenticate with a bearer token and says
// nothing at all about where one comes from. Whichever of this page's three
// token-bearing responses arrives first fills the slot, and the banner offers
// the way back.
//
// THE BROWSER IS NOT SENT BACK BY ITSELF, which is the difference from the
// SD-JWT VC handoff below. That workflow is a sequence of numbered steps and
// this page is a waypoint in it; a reader who came here for a token is on the
// page that shows them what came back — the claims, the DPoP verdict, the
// whole exchange — and yanking them off it the instant the response lands
// takes away the thing they can only see here. The token is in the slot from
// the moment it arrives, so the button is a convenience: opening the SCIM page
// any other way collects it just the same.
//
// NOTHING IS WRITTEN ANYWHERE unless a handoff is active — `deliver()`
// refuses otherwise — so an ordinary visit to this page is untouched by all of
// this.
// ---------------------------------------------------------------------------
// `set` is the REST of what came back — the ID Token, the refresh token, the
// type, the scope and the lifetime — and it is optional and third for the
// reason token_handoff.js's own header gives: the SCIM page wants a bearer
// token and nothing else, and its answer has to go on meaning what it meant.
// The Shared Signals workflow needs more, because it keeps a token history and
// reports WHO the authenticated user is, and neither is answerable from an
// access token this service issued: they are opaque to a client, and the
// identity is in the ID Token.
function offerTokenToHandoff(token, source, set) {
  log.debug("Entering offerTokenToHandoff(). source=" + source);
  if (!tokenHandoff.deliver(token, source, set)) {
    log.debug("Leaving offerTokenToHandoff(). Not delivered.");
    return false;
  }
  maybeShowTokenHandoffBanner();
  var where = tokenHandoff.returnUrl();
  var who = tokenHandoff.label();
  // Built as markup with no value in it and then filled in as TEXT: the label
  // and the return url both crossed a page load, and one of them is going into
  // an href.
  $("#token_handoff_banner").html("<strong>An access token is ready for " +
      "<span id='token_handoff_who'></span></strong> — it came from <span " +
      "id='token_handoff_source'></span>. <a href='#' " +
      "id='token_handoff_return'>Take it there now</a>, or stay here and " +
      "read what came back; opening that page later collects it just the " +
      "same.");
  $("#token_handoff_who").text(who);
  $("#token_handoff_source").text(source);
  $("#token_handoff_return").on("click", function (event) {
    event.preventDefault();
    log.debug("Token handoff: returning to " + where);
    window.location.href = where;
    return false;
  });
  log.debug("Leaving offerTokenToHandoff(). " + who);
  return true;
}

// The banner itself, put up on load so that a page which is about to send a
// token somewhere else says so BEFORE the reader runs a grant on it, and
// reused by offerTokenToHandoff() once there is one to send.
function maybeShowTokenHandoffBanner() {
  log.debug("Entering maybeShowTokenHandoffBanner().");
  if (!tokenHandoff.isActive()) {
    log.debug("Leaving maybeShowTokenHandoffBanner(). None active.");
    return false;
  }
  if ($("#token_handoff_banner").length) {
    log.debug("Leaving maybeShowTokenHandoffBanner(). Already shown.");
    return true;
  }
  $(".container").prepend("<div class='vc-handoff-banner' " +
      "id='token_handoff_banner'><strong>An access token was asked for by " +
      "<span id='token_handoff_who'></span></strong> — whichever grant " +
      "returns one first, it is carried back there.</div>");
  $("#token_handoff_who").text(tokenHandoff.label());
  log.debug("Leaving maybeShowTokenHandoffBanner(). " +
      tokenHandoff.label());
  return true;
}

// Called from the token endpoint's success handler, once the tokens are in
// local storage where step 2 of the workflow reads them.
function returnToSdJwtVcFlow() {
  log.debug("Entering returnToSdJwtVcFlow().");
  if (!sdJwtVc.isFlowActive()) {
    log.debug("Leaving returnToSdJwtVcFlow().");
    return false;
  }
  var target = sdJwtVc.returnUrl();
  // Consumed here: a later, unrelated token call on this page must not be
  // redirected too.
  sdJwtVc.endFlow();
  log.debug("SD-JWT VC issuance: returning to " + target);
  window.location.href = target;
  log.debug("Leaving returnToSdJwtVcFlow().");
  return true;
}

function generateUUID () { // Public Domain/MIT
    log.debug("Entering generateUUID().");
    var d = new Date().getTime();
    if (typeof performance !== "undefined" &&
        typeof performance.now === "function"){
        d += performance.now(); //use high-precision timer if available
    }
    log.debug("Leaving generateUUID().");
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g,
        function (c) {
        var r = (d + Math.random() * 16) % 16 | 0;
        d = Math.floor(d / 16);
        return (c === "x" ? r : (r & 0x3 | 0x8)).toString(16);
    });
}

function displayResourceCheck()
{
  log.debug("Entering displayResourceCheck().");
  var yesCheck = $("#yesCheck").is(":checked");
  var noCheck = $("#noCheck").is(":checked");
  log.debug("yesCheck=" + yesCheck, "noCheck=" + noCheck);
  if(yesCheck) {
    $("#authzResourceRow").show();
  } else if(noCheck) {
    $("#authzResourceRow").hide();
  }
  recalculateTokenRequestDescription();
  log.debug("Leaving displayResourceCheck().");
}

function displayTokenResourceCheck()
{
  log.debug("Entering displayTokenResourceCheck().");
  var yesCheck = $("#yesResourceCheckToken").is(":checked");
  var noCheck = $("#noResourceCheckToken").is(":checked");
  if( yesCheck) {
    $("#authzTokenResourceRow").show();
  } if(noCheck) {
    $("#authzTokenResourceRow").hide();
  }
  recalculateTokenRequestDescription();
  log.debug("Leaving displayTokenResourceCheck().");
}

$(function() {
$("#auth_step").submit(function () {
    log.debug("Entering auth_step submit function.");
    var resource = $("#resource").val();
    var yesCheck = $("#yesCheck").is(":checked");
    log.debug("yesCheck=" + yesCheck);
    log.debug("resource=" + resource);
    if(yesCheck == false)
    {
      $("#resource").prop("disabled", true); 
      $("#yesCheck").prop("disabled", true);
      $("#noCheck").prop("disabled", true);
    } else {
      $("#resource").prop("disabled", false);
      $("#yesCheck").prop("disabled", false);
      $("#noCheck").prop("disabled", false);
    }
    $(this)
      .find("input[name]")
      .filter(function () {
          return !this.value;
      })
      .prop("name", "");
});
    log.debug("Leaving auth_step submit function.");
});

function recalculateAuthorizationErrorDescription()
{
  log.debug("Entering recalculateAuthorizationErrorDescription().");
  log.debug("update error field");
  var ta1 = $("#display_authz_error_form_textarea1");
  if (!!ta1)
  {
    var grant_type = $("#response_type").val();
    if( grant_type == "code" ||
        grant_type == "code id_token" ||
	grant_type == "code token" ||
	grant_type == "code id_token token")
    {
      var pathname = window.location.pathname;
      log.debug("pathname=" + pathname);
      if (pathname == "/oauth2_oidc_2.html")
      {
        var error = getParameterByName("error",window.location.href);
        var error_description = getParameterByName("error_description",
            window.location.href);
        var error_uri = getParameterByName("error_uri",window.location.href);
        var state = getParameterByName("state",window.location.href);
        $("#display_authz_error_form_textarea1")
          .val(                         DOMPurify.sanitize("error: " + error +
          "\n" +
                                                                              "error_description: " + error_description + "\n" +
                                                                              "error_uri: " + error_uri + "\n" +
                                                                              "state: " + state + "\n"));
      }
    } else if (	grant_type == "token" || 
		grant_type == "id_token" ||
		grant_type == "id_token token") {
      //$("#display_authz_request_form_textarea1").value = "";
      var pathname = window.location.pathname;
      log.debug("pathname=" + pathname);
      if (pathname == "/oauth2_oidc_2.html")
      {
        var error = getParameterByName("error",window.location.href);
        var error_description = getParameterByName("error_description",
            window.location.href);
        var error_uri = getParameterByName("error_uri",window.location.href);
        var state = getParameterByName("state",window.location.href);
        $("#display_authz_error_form_textarea1")
          .val(                         DOMPurify.sanitize("error: " + error +
          "\n" +
                                                                              "error_description: " + error_description + "\n" +
                                                                              "error_uri: " + error_uri + "\n" +
                                                                              "state: " + state + "\n"));
      }
    }
  }
  log.debug("Leaving recalculateAuthorizationErrorDescription().");
}

function recalculateTokenErrorDescription(data)
{
  log.debug("Entering recalculateTokenErrorDescription().");
  var display_token_error_class_html = "<fieldset>" +
                                       "<legend>Token Endpoint Error</legend>" +
                                         "<form action=\"\" name=\"display_token_error_form\" id=\"display_token_error_form\">" +
                                           "<table>" +
                                             "<tr>" +
                                               "<td><label name=\"display_token_error_form_label1\" value=\"\" id=\"display_token_error_form_label1\">Error</label></td>" +
                                               "<td><textarea rows=\"5\" cols=\"60\" id=\"display_token_error_form_textarea1\"></textarea></td>" +
                                             "</tr>" +
                                           "</table>" +
                                         "</form>" +
                                       "</fieldset>";
  $("#display_token_error_class")
    .html(DOMPurify.sanitize(display_token_error_class_html));
  log.debug("update error field");
  var ta1 = $("#display_token_error_form_textarea1");
  if (ta1 != null)
  {
    var grant_type = $("#token_grant_type").val();
    if( grant_type == "authorization_code")
    {
      var status = data.status;
      var statusText = data.statusText;
      var readyState = data.readyState;
      var responseText = data.responseText;
      var responseObject = {};
      try {
        responseObject = JSON.parse(responseText);
      } catch (e) {
        log.warn("Unable to parse response text.");
        responseObject = {};
      }
      $("#display_token_error_form_textarea1")
        .val(                             DOMPurify.sanitize("status: " +
        status + "\n" +
										"statusText: " + statusText + "\n" +
										"readyState: " + readyState + "\n" +
										"responseText: " + responseText +"\n" +
										"OAuth2 Response Error Details:" + "\n" +
										"error: " + responseObject.error + "\n" +
										"error_description: " + responseObject.error_description +"\n"));
    } else if (grant_type == "client_credentials") {
      var status = data.status;
      var statusText = data.statusText;
      var readyState = data.readyState;
      var responseText = data.responseText;
      var responseObject = {};
      try {
        responseObject = JSON.parse(responseText);
      } catch (e) {
        log.warn("Unable to parse response text.");
        responseObject = {};
      }
      $("#display_token_error_form_textarea1")
        .val(                         DOMPurify.sanitize("status: " + status +
        "\n" +
                                                                            "statusText: " + statusText + "\n" +
                                                                            "readyState: " + readyState + "\n" +
                                                                            "responseText: " + responseText +"\n" +
                                                                            "OAuth2 Response Error Details:" + "\n" +
                                                                            "error: " + responseObject.error + "\n" +
                                                                            "error_description: " + responseObject.error_description +"\n"));
    } else if (grant_type == "password") {
      var status = data.status;
      var statusText = data.statusText;
      var readyState = data.readyState;
      var responseText = data.responseText;
      var responseObject = {};
      try {
        responseObject = JSON.parse(responseText);
      } catch (e) {
        log.warn("Unable to parse response text.");
        responseObject = {};
      }
      $("#display_token_error_form_textarea1")
        .val(                         DOMPurify.sanitize("status: " + status +
        "\n" +
                                                                            "statusText: " + statusText + "\n" +
                                                                            "readyState: " + readyState + "\n" +
                                                                            "responseText: " + responseText +"\n" +
                                                                            "OAuth2 Response Error Details:" + "\n" +
                                                                            "error: " + responseObject.error + "\n" +
                                                                            "error_description: " + responseObject.error_description +"\n"));
    } else if (grant_type == "urn:ietf:params:oauth:grant-type:device_code") {
      // RFC 8628 polling errors: authorization_pending, slow_down,
      // access_denied, expired_token.
      var status = data.status;
      var statusText = data.statusText;
      var readyState = data.readyState;
      var responseText = data.responseText;
      var responseObject = {};
      try {
        responseObject = JSON.parse(responseText);
      } catch (e) {
        log.warn("Unable to parse response text.");
        responseObject = {};
      }
      $("#display_token_error_form_textarea1")
        .val(                         DOMPurify.sanitize("status: " + status +
        "\n" +
                                                                            "statusText: " + statusText + "\n" +
                                                                            "readyState: " + readyState + "\n" +
                                                                            "responseText: " + responseText +"\n" +
                                                                            "OAuth2 Response Error Details:" + "\n" +
                                                                            "error: " + responseObject.error + "\n" +
                                                                            "error_description: " + responseObject.error_description +"\n"));
    }
  }
  log.debug("Leaving recalculateTokenErrorDescription().");
}

function recalculateRefreshErrorDescription(data)
{
  log.debug("Entering recalculateRefreshErrorDescription().");
  var display_refresh_error_class = "<fieldset>" +
                                    "<legend>Token Endpoint (For Refresh) " +
                                        "Error</legend>" +
                                       "<form action=\"\" name=\"display_refresh_error_form\" id=\"display_refresh_error_form\">" +
                                         "<table>" +
                                           "<tr>" +
                                             "<td><label name=\"display_refresh_error_form_label1\" value=\"\" id=\"display_refresh_error_form_label1\">Error</label></td>" +
                                             "<td><textarea rows=\"5\" cols=\"60\" id=\"display_refresh_error_form_textarea1\"></textarea></td>" +
                                           "</tr>" +
                                         "</table>" +
                                        "</form>" +
                                      "</fieldset>";
  $("#display_refresh_error_class")
    .html(DOMPurify.sanitize(display_refresh_error_class));
  log.debug("update error field");
  var ta1 = $("#display_refresh_error_form_textarea1");
  if (ta1 != null)
  {
    var grant_type = $("#refresh_grant_type").val();
    if( grant_type == "refresh_token")
    {
      var status = data.status;
      var statusText = data.statusText;
      var readyState = data.readyState;
      var responseText = data.responseText;
      var responseObject = {};
      try {
        responseObject = JSON.parse(responseText);
      } catch (e) {
        log.warn("Unable to parse response text.");
        responseObject = {};
      }
      $("#display_refresh_error_form_textarea1")
        .val(                           DOMPurify.sanitize("status: " + status +
        "\n" +
										"statusText: " + statusText + "\n" +
										"readyState: " + readyState + "\n" +
										"responseText: " + responseText +"\n" +
										"OAuth2 Response Error Details:" + "\n" +
										"error: " + responseObject.error + "\n" +
										"error_description: " + responseObject.error_description +"\n"));
    }
  }
  log.debug("Leaving recalculateRefreshErrorDescription().");
}

function parseFragment()
{
  log.debug("Entering parseFragment().");
  log.debug("hash=" + window.location.hash);
  // As getParameterByName(): after the RFC 9700 scrub the live fragment is
  // gone and the snapshot is the response.
  var live = rfc9700ScrubbedHash !== null ? rfc9700ScrubbedHash
                                          : window.location.hash;
  var hash = live.substr(1);

  var result = hash.split("&").reduce(function (result, item) {
      // Split on the FIRST '=' only. A base64url token has no '=' left in it
      // (the padding is stripped), but a percent-decoded value can, and
      // splitting on all of them silently truncated it.
      var eq = item.indexOf("=");
      var name = (eq === -1) ? item : item.substring(0, eq);
      var value = (eq === -1) ? undefined : item.substring(eq + 1);
      result[decodeFragmentComponent(name)] = decodeFragmentComponent(value);
      return result;
  }, {});
  log.debug("Leaving parseFragment().");
  return result;
}

// Percent-decode one half of a fragment parameter.
//
// This was not done at all until the form_post landing needed it, and the
// reason it went unnoticed for so long is worth recording: the values that
// have always arrived in a fragment are an implicit response's tokens, which
// are base64url and therefore contain nothing that needs escaping — so a
// decode was a no-op for every value this function had ever seen. iss and
// state are not base64url. RFC 6749 section 4.2.2 requires the fragment to be
// application/x-www-form-urlencoded, so decoding is what the specification
// asked for the whole time.
//
// A malformed escape (a bare '%') makes decodeURIComponent throw, which in
// this function would take out the whole page load for one bad character. The
// raw text is returned instead: it is what this code did before, so the worst
// case is the behaviour it always had.
function decodeFragmentComponent(value) {
  log.debug("Entering decodeFragmentComponent().");
  if (value === undefined || value === null) {
    log.debug("Leaving decodeFragmentComponent(). Nothing to decode.");
    return value;
  }
  try {
    var decoded = decodeURIComponent(value);
    log.debug("Leaving decodeFragmentComponent(). Decoded.");
    return decoded;
  } catch (e) {
    log.debug("Leaving decodeFragmentComponent(). Malformed escape, kept " +
              "raw: " + e.message);
    return value;
  }
}

function displayOIDCArtifacts()
{
  log.debug("Entering displayOIDCArtifacts().");
  var yesCheck = $("#yesCheckOIDCArtifacts").is(":checked");
  var noCheck = $("#noCheckOIDCArtifacts").is("checked");
  log.debug("yesCheckOIDCArtifacts=" + yesCheck + ", noCheckOIDCArtifacts=" +
            noCheck + ", typeof=" + typeof(yesCheck));
  if(yesCheck) {
    displayOpenIDConnectArtifacts = true;
  } else if(noCheck) {
    displayOpenIDConnectArtifacts = false;
  } else {
    displayOpenIDConnectArtifacts = true;
  }
  log.debug("displayOpenIDConnectArtifacts=" + displayOpenIDConnectArtifacts);
  log.debug("Leaving displayOIDCArtifacts().");
}

function useRefreshTokens()
{
  log.debug("Entering useRefreshTokens().");
  var yesCheck = $("#useRefreshToken-yes").is(":checked");
  var noCheck = $("#useRefreshToken-no").is(":checked");
  log.debug("useRefreshToken-yes=" + yesCheck, "useRefreshToken-no=" + noCheck);
  if(yesCheck) {
    useRefreshTokenTester = true;
    expandPane("#step4");
  } else if(noCheck) {
    useRefreshTokenTester = false;
    collapsePane("#step4");
  }
  log.debug("useRefreshTokenTester=" + useRefreshTokenTester);
  log.debug("Leaving useRefreshTokens().");
}

$("#tipText").hover(
   function(e){
       $("#tooltip").show();
   },
   function(e){
       $("#tooltip").hide();
  });

function isUrl(url) {
  log.debug('Entering isUrl().');
  try {
    log.debug("Leaving isUrl().");
    return Boolean(new URL(url));
  } catch(e) {
    log.debug('An error occurred: ' + e.stack);
    log.debug("Leaving isUrl().");
    return false;
  }
}

function clearLocalStorage() {
  log.debug("Entering clearLocalStorage().");
  if (localStorage) {
    localStorage.setItem("token_client_secret", "");
    localStorage.setItem("refresh_client_secret", "");
  }
  log.debug("Leaving clearLocalStorage().");
}

// ---- Token History ----

function decodeJwtPayload(token) {
  log.debug("Entering decodeJwtPayload().");
  try {
    var parts = token.split('.');
    if (parts.length < 2) {
      log.debug("Leaving decodeJwtPayload().");
      return null;
    }
    var b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    var pad = '==='.slice(0, (4 - b64.length % 4) % 4);
    log.debug("Leaving decodeJwtPayload().");
    return JSON.parse(atob(b64 + pad));
  } catch (e) {
    log.debug("Leaving decodeJwtPayload().");
    return null;
  }
  log.debug("Leaving decodeJwtPayload().");
}

function extractNonce(id_token) {
  log.debug("Entering extractNonce().");
  if (id_token) {
    var payload = decodeJwtPayload(id_token);
    if (payload && payload.nonce) {
      log.debug("Leaving extractNonce().");
      return payload.nonce;
    }
  }
  log.debug("Leaving extractNonce().");
  return null;
}

// Session ID (sid), used to group the Token History by session. Refresh
// responses preserve the sid of the originating session, unlike nonce (which is
// only present on the original authentication).
//
// The access token is asked first because it is the one every grant returns and
// the one a refresh carries forward. The id_token is a fallback for the two
// response types that return one and no access token — OIDC Implicit Flow
// (id_token) and OIDC Hybrid (code id_token) — whose sets would otherwise land
// in the "No Session ID (sid)" bucket, apart from the token endpoint's own set
// from the very same session. OIDC Session Management defines sid on the
// id_token, and it is the same session either token names.
function extractSid(access_token, id_token) {
  log.debug("Entering extractSid().");
  var tokens = [access_token, id_token];
  for (var i = 0; i < tokens.length; i++) {
    if (tokens[i]) {
      var payload = decodeJwtPayload(tokens[i]);
      if (payload && payload.sid) {
        log.debug("Leaving extractSid().");
        return payload.sid;
      }
    }
  }
  log.debug("Leaving extractSid().");
  return null;
}

// RFC 9396 / OID4VCI section 6.2: when the authorization was expressed as
// authorization_details rather than a scope, the token response says which
// Credential Datasets were granted. The SD-JWT VC workflow has to send one of
// those credential_identifiers in its Credential Request — and MUST NOT send a
// credential_configuration_id then — so what came back is kept for it. Nothing
// else on this page uses it, and a response without it clears the key rather
// than leaving a stale grant behind.
function rememberAuthorizationDetails(data) {
  log.debug("Entering rememberAuthorizationDetails().");
  var details = data && data.authorization_details;
  try {
    if (details) {
      localStorage.setItem("token_authorization_details",
                           JSON.stringify(details));
      log.debug("The token response granted authorization_details.");
    } else {
      localStorage.removeItem("token_authorization_details");
    }
  } catch (e) {
    // No storage, or over quota: the workflow falls back to naming the
    // credential by its configuration id, which is what an authorization
    // without authorization_details would have needed anyway.
    log.debug("rememberAuthorizationDetails(): " + e.message);
  }
  log.debug("Leaving rememberAuthorizationDetails().");
}

// Write the history back, dropping kept exchanges if that is what it takes to
// fit.
//
// An exchange is a great deal larger than the tokens it produced — a request,
// a response, two header maps and up to HTTP_STORED_BODY_LIMIT of body each
// way — and TOKEN_HISTORY_LIMIT allows a thousand generations, which is more
// than a browser's five megabytes will hold. So a quota refusal is not a
// failure here: it means the OLDEST exchanges have to go, and they go one
// generation at a time until the write succeeds. The tokens themselves are
// never dropped — they are what the pane is about, the exchange is the extra —
// and an entry whose exchange has been dropped says so through the same
// sentence an entry that never had one uses.
//
// Returns true if the history was written, false if it could not be.
function writeTokenHistory(history) {
  log.debug("Entering writeTokenHistory(). " + history.length + " entry/ies.");
  var attempt = 0;
  while (attempt <= history.length) {
    try {
      localStorage.setItem('token_history', JSON.stringify(history));
      log.debug("Leaving writeTokenHistory(). Written after " + attempt +
                " exchange(s) dropped.");
      return true;
    } catch (e) {
      // Over quota, or storage refused outright (a private window with
      // storage disabled throws here too). Give up the oldest exchange still
      // held and try again; when there are none left to give up, the write
      // was never going to fit and the caller is told so.
      log.debug("writeTokenHistory(): the write was refused (" + e.name +
                "). Dropping the oldest kept exchange.");
      var dropped = false;
      for (var i = 0; i < history.length && !dropped; i++) {
        if (history[i].http_exchange) {
          delete history[i].http_exchange;
          dropped = true;
        }
      }
      if (!dropped) {
        log.error("Could not write token_history: " + e);
        log.debug("Leaving writeTokenHistory(). Refused.");
        return false;
      }
      attempt++;
    }
  }
  log.debug("Leaving writeTokenHistory(). Refused.");
  return false;
}

// One generation of tokens, and — since this build — the HTTP exchange that
// produced them.
//
// `exchange` is the REDACTED copy from redactExchangeForStorage(), not the
// live view: the live one repeats a client secret and an Authorization header
// and is never written down. It is null for a set that came from the
// Authorization Endpoint, which this page reaches by navigating the browser
// rather than by making a request it could trace, and for any set saved by a
// build before this one — both of which the Currently Viewing pane's HTTP tab
// says out loud rather than showing an empty panel.
function saveTokenSetToHistory(access_token, refresh_token, id_token, source,
                               exchange) {
  log.debug("Entering saveTokenSetToHistory().");
  var history = [];
  try { 
    history = JSON.parse(localStorage.getItem('token_history') || '[]'); 
  } catch(e) 
  {
    log.error("An error occurred while writing to local storage: " + e);
  }
  var nonce = extractNonce(id_token);
  var sid = extractSid(access_token, id_token);
  if (history.length >= TOKEN_HISTORY_LIMIT) {
    localStorage.removeItem('token_history');
    renderTokenHistory();
    // Every generation went with it, including one the Authorization Endpoint
    // Results pane may be naming in its links. Same redraw as
    // clearTokenHistory() does, for the same reason — this is the other way the
    // history is wiped.
    if (authorizationResponseTokenSet) {
      renderAuthorizationEndpointResults(authorizationResponseTokenSet.expected,
                                         authorizationResponseTokenSet);
    }
    // Nothing was stored, so there is no index to hand back — callers that
    // record the index alongside an operation must not point at a set that was
    // just discarded.
    log.debug("Leaving saveTokenSetToHistory().");
    return null;
  }
  var entry = {
    timestamp: new Date().toISOString(),
    nonce: nonce,
    sid: sid,
    source: source || 'token',
    access_token: access_token || '',
    refresh_token: refresh_token || '',
    id_token: id_token || ''
  };
  if (exchange) {
    entry.http_exchange = exchange;
  }
  history.push(entry);
  writeTokenHistory(history);
  renderTokenHistory();
  log.debug("Leaving saveTokenSetToHistory().");
  // The index of the set just added, for callers that cross-reference it from
  // the Operation History entry describing the call that produced it.
  return history.length - 1;
}
function selectTokenSet(index) {
  log.debug("Entering selectTokenSet().");
  var history = [];
  try {
    history = JSON.parse(localStorage.getItem('token_history') || '[]'); 
  } catch(e) { 
    log.error("An error occurred while reading from local storage: " + e);
    log.debug("Leaving selectTokenSet().");
    return false; 
  }
  if (index < 0 ||
      index >= history.length) 
  {
    log.debug("Leaving selectTokenSet().");
    return false;
  }
  var entry = history[index];
  localStorage.setItem('token_access_token', entry.access_token);
  localStorage.setItem('token_refresh_token', entry.refresh_token);
  localStorage.setItem('token_id_token', entry.id_token);
  localStorage.setItem('token_history_active_index', index);
  if (entry.id_token) {
    $("#logout_id_token_hint").val(entry.id_token);
  }
  renderTokenHistory();
  renderCurrentlyViewing(index, entry);
  log.debug("Leaving selectTokenSet().");
  return false;
}

function renderCurrentlyViewing(index, entry) {
  log.debug("Entering renderCurrentlyViewing().");
  var html = '<div class="dbg-pane">' +
               '<legend class="dbg-legend" ' +
                   'data-target="currently_viewing_fieldset">Currently ' +
                   'Viewing</legend>' +
               '<fieldset id="currently_viewing_fieldset">' +
               '<p><em>Token set selected from Token History.</em></p>' +
               '<table>' +
                 '<tr>' +
                   '<td>' +
                     '<P><a href="/token_detail.html?type=history_access&generation=' + index + '" onclick="oauth2_oidc_2.clickLink()">Access Token</a></P>' +
                     '<P style="font-size:50%;"><a href="/introspection.html?type=history_access&generation=' + index + '" onclick="oauth2_oidc_2.clickLink()">Introspect Token</a></P>' +
                     '<P><input class="btn2 revoke_token_btn" type="button" ' +
                         'value="Revoke Token" ' +
                         'data-revoke-type="history_access" ' +
                         'data-revoke-generation="' + index + '" /></P>' +
                     '<P><form><input class="btn2" type="submit" ' +
                         'value="Copy Token"' +
                     ' onclick="return oauth2_oidc_2.onClickCopyToken(\'#cv_access_token\');"/></form></P>' +
                   '</td>' +
                   '<td><textarea rows=5 cols=60 readonly ' +
                       'name=cv_access_token id=cv_access_token ' +
                       'data-token-field="access"></textarea></td>' +
                 '</tr>';
  if (entry.refresh_token) {
    html +=      '<tr>' +
                   '<td>' +
                     '<P><a href="/token_detail.html?type=history_refresh&generation=' + index + '" onclick="oauth2_oidc_2.clickLink()">Refresh Token</a></P>' +
                     '<P style="font-size:50%;"><a href="/introspection.html?type=history_refresh&generation=' + index + '" onclick="oauth2_oidc_2.clickLink()">Introspect Token</a></P>' +
                     '<P><input class="btn2 revoke_token_btn" type="button" ' +
                         'value="Revoke Token" ' +
                         'data-revoke-type="history_refresh" ' +
                         'data-revoke-generation="' + index + '" /></P>' +
                     '<P><form><input class="btn2" type="submit" ' +
                         'value="Copy Token"' +
                     ' onclick="return oauth2_oidc_2.onClickCopyToken(\'#cv_refresh_token\');"/></form></P>' +
                   '</td>' +
                   '<td><textarea rows=5 cols=60 readonly ' +
                       'name=cv_refresh_token id=cv_refresh_token ' +
                       'data-token-field="refresh"></textarea></td>' +
                 '</tr>';
  }
  if (entry.id_token) {
    html +=      '<tr>' +
                   '<td>' +
                     '<P><a href="/token_detail.html?type=history_id_token&generation=' + index + '" onclick="oauth2_oidc_2.clickLink()">ID Token</a></P>' +
                     '<P style="font-size:50%;">Get <a href="/userinfo.html?type=history_access&generation=' + index + '" onclick="oauth2_oidc_2.clickLink()">UserInfo Data</a></P>' +
                     '<P><form><input class="btn2" type="submit" ' +
                         'value="Copy Token"' +
                     ' onclick="return oauth2_oidc_2.onClickCopyToken(\'#cv_id_token\');"/></form></P>' +
                   '</td>' +
                   '<td><textarea rows=5 cols=60 readonly name=cv_id_token ' +
                       'id=cv_id_token data-token-field="id"></textarea></td>' +
                 '</tr>';
  }
  html +=      '<tr>' +
                 '<td><strong>Generation:</strong></td>' +
                 '<td>' + (index + 1) + '</td>' +
               '</tr>' +
               '<tr>' +
                 '<td><strong>Nonce:</strong></td>' +
                 '<td><input type="text" readonly data-token-field="nonce" ' +
                     'style="width:100%;" /></td>' +
               '</tr>' +
               '<tr>' +
                 '<td><strong>Session ID (sid):</strong></td>' +
                 '<td><input type="text" readonly data-token-field="sid" ' +
                     'style="width:100%;" /></td>' +
               '</tr>' +
             '</table>' +
             '</fieldset>' +
             '</div>';
  $('#currently-viewing-panel').html(html);
  // The exchange kept with THIS generation goes onto the viewing channel
  // before the tab is attached, because attachHttpTab() draws whatever the
  // channel holds into the host it has just made. storedExchangeForDisplay()
  // returns null for a generation that has none, and the pane's `empty`
  // sentence then says which of the two reasons it is.
  renderHttpExchange('viewing',
                     storedExchangeForDisplay(entry.http_exchange));
  setHttpTabLabel('viewing',
                  (entry.http_exchange && entry.http_exchange.response) ?
                      String(entry.http_exchange.response.status) : null);
  attachHttpTabToCurrentlyViewing();
  fillGeneratedFields('#currently-viewing-panel', {
    access: entry.access_token, refresh: entry.refresh_token,
        id: entry.id_token,
    nonce: entry.nonce, sid: entry.sid
  });
  expandPane('#currently-viewing-panel');
  log.debug("Leaving renderCurrentlyViewing().");
}

function renderTokenHistory() {
  log.debug("Entering renderTokenHistory().");
  var history = [];
  try {
    history = JSON.parse(localStorage.getItem('token_history') || '[]');
  } catch (e) {
    // Absent or unreadable storage: keep the default.
  }
  if (history.length === 0) {
    collapsePane("#token-history-panel");
    log.debug("Leaving renderTokenHistory().");
    return;
  }
  var activeIndex =
      parseInt(localStorage.getItem('token_history_active_index'));
  if (isNaN(activeIndex)) activeIndex = -1;

  // Group entries by session id (sid) from the access token, preserving
  // first-seen order of each session. sid is stable across refreshes, whereas
  // nonce is only present on the original authentication.
  var sessionOrder = [];
  var sessions = {};
  history.forEach(function(entry, idx) {
    var key = entry.sid || '__no_sid__';
    if (!sessions[key]) {
      sessions[key] = [];
      sessionOrder.push(key);
    }
    sessions[key].push({ index: idx, entry: entry });
  });

  var html = '<div class="dbg-pane"><legend class="dbg-legend" data-target="token_history_fieldset">Token History</legend><fieldset id="token_history_fieldset">';
  html += '<input type="button" value="Clear History" onclick="return oauth2_oidc_2.clearTokenHistory();" />';
  html += '<div style="max-height:450px; overflow-y:auto;">';
  sessionOrder.slice().reverse().forEach(function(sid) {
    var label = sid === '__no_sid__' ?
        'No Session ID (sid)' : 'Session ID (sid): ' + sid;
    html += '<div style="margin-bottom:10px;">';
    html += '<strong>' + escapeHtmlText(label) + '</strong>';
    html += '<table border="1" style="margin-top:4px;">';
    html += '<tr><th style="width:4%">#</th><th style="width:12%">Time</th><th style="width:8%">Source</th><th style="width:19%">Nonce</th><th style="width:19%">Sid</th><th style="width:6%">Access</th><th style="width:6%">Refresh</th><th style="width:8%">ID Token</th><th>Action</th></tr>';
    sessions[sid].slice().reverse().forEach(function(item) {
      var e = item.entry;
      var idx = item.index;
      var isActive = (idx === activeIndex);
      var rowStyle = isActive ? ' style="background-color:#d4edda;"' : '';
      var datePart = e.timestamp.substring(0, 10);
      var timePart = e.timestamp.substring(11, 19);
      html += '<tr' + rowStyle + '>';
      html += '<td>' + (idx + 1) + '</td>';
      html += '<td style="font-size:80%;">' + datePart + '<br>' + timePart +
          '</td>';
      html += '<td>' + e.source + '</td>';
      html += '<td style="font-size:70%; word-break:break-all;">' +
          escapeHtmlText(e.nonce || '') + '</td>';
      html += '<td style="font-size:70%; word-break:break-all;">' +
          escapeHtmlText(e.sid || '') + '</td>';
      html += '<td style="text-align:center;">' + (e.access_token ?
          '&#10003;' : '') + '</td>';
      html += '<td style="text-align:center;">' + (e.refresh_token ?
          '&#10003;' : '') + '</td>';
      html += '<td style="text-align:center;">' + (e.id_token ?
          '&#10003;' : '') + '</td>';
      html += '<td>';
      if (isActive) {
        html += '<strong>Active</strong>';
      } else {
        html += '<input type="button" value="Activate" onclick="return ' +
            'oauth2_oidc_2.selectTokenSet(' + idx + ');" />';
      }
      html += '</td>';
      html += '</tr>';
    });
    html += '</table></div>';
  });
  html += '</div>';
  html += '</fieldset>';
  html += '</div>';

  $("#token-history-panel").html(html);
  expandPane("#token-history-panel");
  log.debug("Leaving renderTokenHistory().");
}

function regenerateState() {
  log.debug("Entering regenerateState().");
  $("#state").val(generateUUID());
  localStorage.setItem('state', $("#state").val());
  log.debug("Leaving regenerateState().");
}

function regenerateNonce() {
  log.debug("Entering regenerateNonce().");
  $("#nonce_field").val(generateUUID());
  localStorage.setItem('nonce_field', $("#nonce_field").val());
  log.debug("Leaving regenerateNonce().");
}

function recreateTokenDisplay()
{
  log.debug("Entering recreateTokenDisplay().");
      var token_endpoint_result_html = "";
      log.debug("displayOpenIDConnectArtifacts=" +
                displayOpenIDConnectArtifacts);
      var refreshToken = localStorage.getItem("token_refresh_token");
      if(displayOpenIDConnectArtifacts == true)
      {
         log.debug("Displaying full OIDC Token results.");
         // Display OAuth2/OIDC Artifacts
         log.debug("RCBJ0001");
         token_endpoint_result_html = '<div class="dbg-pane">' +
                                      '<legend class="dbg-legend" data-target="token_result_fieldset">Token Endpoint Results:</legend>' +
                                      '<fieldset id="token_result_fieldset">' +
                                 "<p><em>Most recent results of the OAuth2 " +
                                     "Grant or OIDC Authentication Flow " +
                                     "call.</em></p>" +
                                      "<table>" +
                                        "<tr>" +
                                          '<td>' +
                                              '<P><a href="/token_detail.html?type=access" onclick="oauth2_oidc_2.clickLink()">Access Token</a></P>' +
                                              '<P style="font-size:50%;"><a href="/introspection.html?type=access" onclick="oauth2_oidc_2.clickLink()">Introspect Token</a></P>' +
                                         '<P><input class="btn2 revoke_token_btn" type="button" value="Revoke Token" data-revoke-type="access" /></P>' + 
                                              '<P><form><input class="btn2" ' +
                                                  'type="submit" ' +
                                                  'value="Copy Token"' +
                                              ' onclick="return oauth2_oidc_2.onClickCopyToken(\'#token_access_token\');"/></form></P>' +
                                          "</td>" +
                                          "<td>" +
                                             "<textarea rows=5 cols=60 readonly name=token_access_token id=token_access_token data-token-field=\"access\"></textarea>" +
                                          "</td>" +
                                        "</tr>";
        if(useRefreshTokenTester) {
           log.debug("Displaying refresh token.");
           token_endpoint_result_html +=  '<tr>' +
                                          '<td>' +
                                              '<P><a href="/token_detail.html?type=refresh" onclick="oauth2_oidc_2.clickLink()">Refresh Token</a></P>' +
                                              '<P style="font-size:50%;"><a href="/introspection.html?type=refresh" onclick="oauth2_oidc_2.clickLink()">Introspect Token</a></P>' +
                                         '<P><input class="btn2 revoke_token_btn" type="button" value="Revoke Token" data-revoke-type="refresh" /></P>' +
                                              '<P><form><input class="btn2" ' +
                                                  'type="submit" ' +
                                                  'value="Copy Token"' + 
                                              ' onclick="return oauth2_oidc_2.onClickCopyToken(\'#token_refresh_token\');"/></form></P>' +
                                          '</td>' +
                                          '<td>' +
                                              '<textarea rows=5 cols=60 readonly name=token_refresh_token id=token_refresh_token data-token-field="refresh"></textarea>' +
                                          "</td>" +
                                        "</tr>";
         }
         token_endpoint_result_html +=  "<tr>" +
                                          '<td>' +
                                            '<P><a href="/token_detail.html?type=id" onclick="oauth2_oidc_2.clickLink()">ID Token</a></P>' +
                                            '<P style="font-size:50%;">Get <a href="/userinfo.html?type=token_access_token" onclick="oauth2_oidc_2.clickLink()">UserInfo Data</a></P>' +
                                            '<P><form><input ' +
                                                'class="token_btn" ' +
                                                'type="submit" ' +
                                                'value="Copy Token"' + 
                                            ' onclick="return oauth2_oidc_2.onClickCopyToken(\'#token_id_token\');"/></form></P>' +
                                          '</td>' +
                                          '<td>' +
                                            '<textarea rows=5 cols=60 readonly name=token_id_token id=token_id_token data-token-field="id"></textarea>' +
                                          '</td>' +
                                        "</tr>" +
                                      "</table>" +
                                      "</fieldset>";

      } else {
         log.debug("Logging access_token only.");
         log.debug("RCBJ0002");
         token_endpoint_result_html = "<fieldset>" +
                                      "<legend>Token Endpoint " +
                                          "Results:</legend>" +
                                 "<p><em>Most recent results of the OAuth2 " +
                                     "Grant or OIDC Authentication Flow " +
                                     "call.</em></p>" +
                                      "<table>" +
                                        "<tr>" +
                                          '<td>' +
                                            '<p><a href="/token_detail.html?type=access" onclick="oauth2_oidc_2.clickLink()">Access Token</a></p>' +
                                            '<P><input class="btn2 revoke_token_btn" type="button" value="Revoke Token" data-revoke-type="access" /></P>' +
                                            '<P><form><input class="btn2" ' +
                                                'type="submit" ' +
                                                'value="Copy Token"' +
                                            ' onclick="return oauth2_oidc_2.onClickCopyToken(\'#token_access_token\');"/></form></P>' +
                                          '</td>' +
                                          "<td><textarea rows=5 cols=60 readonly name=token_access_token id=token_access_token data-token-field=\"access\"></textarea>" +
                                          "</td>" +
                                        "</tr>";
         if(useRefreshTokenTester) {
           log.debug("Displaying refresh token");
           token_endpoint_result_html += "<tr>" +
                                          '<td>' +
                                            '<a href="/token_detail.html?type=refresh" onclick="oauth2_oidc_2.clickLink()">Refresh Token</a>' +
                                            '<P><input class="btn2 revoke_token_btn" type="button" value="Revoke Token" data-revoke-type="refresh" /></P>' +
                                            '<P><form><input class="btn2" ' +
                                                'type="submit" ' +
                                                'value="Copy Token"' +
                                            ' onclick="return oauth2_oidc_2.onClickCopyToken(\'#token_refresh_token\');"/></form></P>' +
                                          '</td>' +
                                          "<td>" +
                                            "<textarea rows=5 cols=60 readonly name=token_refresh_token id=token_refresh_token data-token-field=\"refresh\"></textarea>" +
                                          "</td>" +
                                        "</tr>";
         }
         token_endpoint_result_html += "</table>" +
                                      "</fieldset>" +
                                      "</div>";
      }
      $("#token_endpoint_result").html(token_endpoint_result_html);
      // Rebuilt from localStorage, so there is no exchange to show:
      // the tab says that rather than being absent, which would read
      // as the tab having been lost.
      attachHttpTabToTokenResults();
      fillGeneratedFields("#token_endpoint_result", {
        access: localStorage.getItem("token_access_token"),
        refresh: refreshToken,
        id: localStorage.getItem("token_id_token")
      });
  log.debug("Leaving recreateTokenDisplay().");
}

function displayTokenCustomParametersCheck()
{
  log.debug("Entering displayTokenCustomParametersCheck().");
  var yesCheck = $("#customTokenParametersCheck-yes").is(":checked");
  var noCheck = $("#customTokenParametersCheck-no").is(":checked");
  log.debug("customParamtersYesCheck=" + yesCheck, "customParamtersNoCheck=" +
            noCheck);
  if(yesCheck) {
    $("#tokenCustomParametersRow").show();
    $("#customTokenParametersCheck-no").prop("checked", false);
    $("#customTokenParametersCheck-yes").prop("checked", true);
  } else if(noCheck) {
    $("#tokenCustomParametersRow").hide();
    $("#customTokenParametersCheck-yes").prop("checked", false);
    $("#customTokenParametersCheck-no").prop("checked", true);
    $("#token_custom_parameter_list").html("");
  }
  if (yesCheck) {
    generateCustomParametersListUI();
  }
  recalculateTokenRequestDescription();
  log.debug("Leaving displayTokenCustomParametersCheck()");
}

function generateCustomParametersListUI()
{
  log.debug("Entering generateCustomParametersListUI().");
  var customParametersListHTML = "" +
    "<fieldset>" +
    "<legend>Custom Parameters" +
    "</legend>" +
    "<table>" +
      "<tr>" +
        "<th>&nbsp;</th>" +
        "<th>Name</th>" +
        "<th>Value</th>" +
      "</tr>";
      var i = 0;
      var j = parseInt($("#tokenNumberCustomParameters").val());
      if (j > 10) {
        j = 10; // no more than ten
      }
      for( var i = 0; i < j; i++)
      {
        customParametersListHTML = customParametersListHTML +
        "<tr>" +
          "<td>Custom Parameter #" + i + "</td>" +
          "<td>" +
            '<input class="stored" id="' + 'customTokenParameterName-' + i +
                '" name="' + 'customTokenParameterName-' + i +
                '" type="text" maxlength="64" size="32" />' +
          "</td>" +
          "<td>" +
            '<input class="stored" id="' + 'customTokenParameterValue-' + i +
                '" name="' + 'customTokenParameterValue-' + i +
                '" type="text" maxlength="128" size="64" />' +
          "</td>" +
        "</tr>";
      }
      customParametersListHTML = customParametersListHTML +
        "</table>" +
        "</fieldset>";
      $("#token_custom_parameter_list")
        .html(DOMPurify.sanitize(customParametersListHTML));
  if ($("#customTokenParametersCheck-yes").is(":checked")) {
    var i = 0;
    var authzNumberCustomParameters =
        parseInt($("#tokenNumberCustomParameters").val());
    for(i = 0; i < authzNumberCustomParameters; i++)
    {
      $("#customTokenParameterName-" +
        i).val(localStorage.getItem("customTokenParameterName-" + i));
      $("#customTokenParameterValue-" +
        i).val(localStorage.getItem("customTokenParameterValue-" + i));
      $("#customTokenParameterName-" + i).on("keypress",
        recalculateTokenRequestDescription);
      $("#customTokenParameterValue-" + i).on("keypress",
        recalculateTokenRequestDescription);

    }
  }
  recalculateTokenRequestDescription();
  log.debug("Leaving generateCustomParametersListUI().");
}

// ---------------------------------------------------------------------------
// COLLAPSING A PANE, rather than making it disappear.
//
// This page is a column of panes, and three of its rows put panes SIDE BY SIDE
// in a flex row — Token Endpoint Results next to the refresh results next to
// Currently Viewing, the refresh form next to Token History, logout next to
// revocation. Every one of those was hidden outright at some point in the
// workflow: `$("#step4").hide()`, `$('#currently-viewing-panel').hide()`, and a
// dozen more. A `display: none` on a flex child does not leave a gap where the
// pane was — it removes the child, the row re-divides the width among whatever
// is left, and the panes beside it move and change size. So the page a reader
// meets after a token call is laid out differently from the one they were
// looking at a moment before, and a pane they had found once is not where they
// left it.
//
// Collapsing keeps the pane. Its legend stays on screen and stays clickable —
// which is what makes the state recoverable, where a hidden pane offers
// nothing to click — and only the fieldset inside it goes away. The row keeps
// its columns, the columns keep their widths, and every pane keeps its place.
//
// These two are for PANES. The row-level and field-level `.hide()` calls
// elsewhere in this file (`$("#authzCodeRow").hide()`, the PKCE rows, the
// device-grant rows) are untouched and must stay that way: a table row that
// does not apply to the selected grant is not a pane a reader can go looking
// for, and leaving an empty one behind would be noise rather than structure.
// ---------------------------------------------------------------------------

// The fieldset a pane collapses, given the pane's container. The container is
// sometimes the `.dbg-pane` itself (the static `#stepN` panes) and sometimes a
// wrapper the pane is DROPPED INTO by one of the render functions (the result
// and history panels), so this looks for the fieldset rather than assuming
// which of the two it was handed. A container with nothing in it yet — the
// result panels before their first call — has no fieldset and nothing to
// collapse, which is not a failure: an empty container occupies its column
// and shows nothing, which is exactly the state wanted.
function paneFieldset(selector) {
  log.debug("Entering paneFieldset(). selector=" + selector);
  var found = $(selector).find("fieldset").first();
  log.debug("Leaving paneFieldset(). found=" + (found.length > 0));
  return found;
}

// Collapse a pane: the container and its legend stay, the fieldset goes.
//
// The container is MARKED, and the mark is the point rather than bookkeeping:
// a collapsed pane and a pane whose fieldset has simply never been opened look
// identical from the DOM — both are a visible container over a
// `display: none` fieldset — and one of the two is a state the load path is
// entitled to fix. Before this, `.hide()` told them apart for free, because a
// hidden container failed `:visible`. See the note at the load-path guard on
// `#step3`.
function collapsePane(selector) {
  log.debug("Entering collapsePane(). selector=" + selector);
  $(selector).show().attr("data-pane-collapsed", "1");
  paneFieldset(selector).css("display", "none");
  log.debug("Leaving collapsePane().");
}

// Expand a pane, and make sure the container it lives in is on the page: two
// of them (`#token-history-panel`, `#currently-viewing-panel`) are written
// `style="display:none"` in the markup, because before the first token set
// exists there is nothing in them at all.
function expandPane(selector) {
  log.debug("Entering expandPane(). selector=" + selector);
  $(selector).show().removeAttr("data-pane-collapsed");
  paneFieldset(selector).css("display", "block");
  log.debug("Leaving expandPane().");
}

function onClickShowFieldSet(expand_button_id, field_set_id) {
  log.debug("Entering onClickShowFieldSet().");
  log.debug('Entering onClickShowConfigFieldSet(). expand_button_id='
    + expand_button_id + ', field_set_id=' + field_set_id
    + ', fieldset.style.display=' + $("#" + field_set_id).css("display")
    + ', expand_button.value=' + $("#" + expand_button_id).val());
  // The pane's own mark is kept in step with the click, so that a reader who
  // opens a collapsed pane by hand has opened it as far as collapsePane()'s
  // mark is concerned. Set on the fieldset's PANE rather than on the fieldset,
  // which is where collapsePane() puts it and where the load-path guard on
  // `#step3` looks for it.
  var pane = $("#" + field_set_id).closest(".dbg-pane, .side-by-side-col");
  if($("#" + field_set_id).css("display") == 'block') {
    log.debug('Hide ' + field_set_id + '.');
    $("#" + field_set_id).css("display", "none");
    $("#" + expand_button_id).val("Expand");
    pane.attr("data-pane-collapsed", "1");
  } else {
    log.debug('Show ' + field_set_id + '.');
    $("#" + field_set_id).css("display", "block");
    $("#" + expand_button_id).val("Collapse");
    pane.removeAttr("data-pane-collapsed");
  }
  $("#step0_expand_form").on("click", function(event) {
    event.preventDefault();
  });
  log.debug('Leaving onClickShowFieldSet().');
  log.debug("Leaving onClickShowFieldSet().");
  return false;
}

function initFields() {
  log.debug("Entering initFields().");
  var token_initialize = getLSBooleanItem("token_initialize");
  if(!token_initialize) {
    if ($("#yesCheckOIDCArtifacts")) {
      $("#yesCheckOIDCArtifacts").prop("checked", true);
    }
    if ($("#noCheckOIDCArtifacts")) {
      $("#noCheckOIDCArtifacts").prop("checked", false);
    }
    if ($("#SSLValidate-yes")) {
      $("#SSLValidate-yes").prop("checked", true);
    }
    if ($("#SSLValidate-no")) {
      $("#SSLValidate-no").prop("checked", false);
    }
    if ($("#useRefreshToken-yes")) {
      $("#useRefreshToken-yes").prop("checked", true);
    }
    if ($("#useRefreshToken-no")) {
      $("#useRefreshToken-no").prop("checked", false);
    }
    if ($("#usePKCE-yes")) {
      $("#usePKCE-yes").prop("checked", true);
    }
    if ($("#usePKCE-no")) {
      $("#usePKCE-no").prop("checked", false);
    }
    if ($("#yesResourceCheckToken")) {
        $("#yesResourceCheckToken").prop("checked", false);
        localStorage.setItem("yesResourceCheckToken", false);
    }
    if ($("#noResourceCheckToken")) {
        $("#noResourceCheckToken").prop("checked", true);
        localStorage.setItem("noResourceCheckToken", true);
    }
    if ($("#customTokenParametersCheck-yes")) {
        $("#customTokenParametersCheck-yes").prop("checked", false);
        localStorage.setItem("customTokenParametersCheck-yes", false);
    }
    if ($("#customTokenParametersCheck-no")) {
        $("#customTokenParametersCheck-no").prop("checked", true);
        localStorage.setItem("customTokenParametersCheck-no", true);
    }
    if ($("#token_postAuthStyleCheckToken")) {
        $("#token_postAuthStyleCheckToken").prop("checked", true);
    }
    if ($("#token_headerAuthStyleCheckToken")) {
        $("#token_headerAuthStyleCheckToken").prop("checked", false);
    }
    if ($("#refresh_postAuthStyleCheckToken")) {
        $("#refresh_postAuthStyleCheckToken").prop("checked", true);
    }
    if ($("#refresh_headerAuthStyleCheckToken")) {
        $("#refresh_headerAuthStyleCheckToken").prop("checked", false);
    }
    if ($("#revocation_postAuthStyleCheckToken")) {
        $("#revocation_postAuthStyleCheckToken").prop("checked", true);
    }
    if ($("#revocation_headerAuthStyleCheckToken")) {
        $("#revocation_headerAuthStyleCheckToken").prop("checked", false);
    }
    localStorage.setItem("revocation_post_auth_style", true);
    if ($("#tokenexchange_postAuthStyle")) {
        $("#tokenexchange_postAuthStyle").prop("checked", true);
    }
    if ($("#tokenexchange_headerAuthStyle")) {
        $("#tokenexchange_headerAuthStyle").prop("checked", false);
    }
    localStorage.setItem("tokenexchange_post_auth_style", true);
    if ($("#usePKCE-yes")) {
      $("#usePKCE-yes").prop("checked", true);
    }
    if ($("#usePKCE-no")) {
      $("#usePKCE-no").prop("checked", false);
    }
    if ($("#token_initiateFromFrontEnd")) {
      $("#token_initiateFromFrontEnd").prop("checked", false);
    }
    if ($("#token_initiateFromBackEnd")) {
      $("#token_initiateFromBackEnd").prop("checked", true);
    }
    if ($("#refresh_initiateFromFrontEnd")) {
      $("#refresh_initiateFromFrontEnd").prop("checked", false);
    }
    if ($("#refresh_initiateFromBackEnd")) {
      $("#refresh_initiateFromBackEnd").prop("checked", true);
    }

    localStorage.setItem("refresh_post_auth_style", true);
    localStorage.setItem("token_initialize", true);
    token_initialize = true;
  }
  log.debug("Leaving initFields().");
}

function usePKCERFC()
{
  log.debug("Entering usePKCERFC().");
  if ($("#usePKCE-yes").is(":checked")) {
    usePKCE = true;
  } else {
    usePKCE = false;
  }
  if(usePKCE) {
    log.debug("Show PKCE Data fields.");
    $("#token_pkce_code_challenge_row").show();
    $("#token_pkce_code_verifier_row").show();
    $("#token_pkce_code_method_row").show();
  } else {
    log.debug("Hide PKCE Data fields.");
    $("#token_pkce_code_challenge_row").hide();
    $("#token_pkce_code_verifier_row").hide();
    $("#token_pkce_code_method_row").hide();
  }

  recalculateTokenRequestDescription();
  log.debug("Leaving usePKCERFC().");
}

function getLSBooleanItem(key)
{
  log.debug("Entering getLSBooleanItem().");
  log.debug("Leaving getLSBooleanItem().");
  return localStorage.getItem(key) === 'true';
}

function setPostAuthStyleCheckToken() {
  log.debug("Entering setPostAuthStyleCheckToken().");
  $("#token_postAuthStyleCheckToken").prop("checked", true);
  $("#token_headerAuthStyleCheckToken").prop("checked", false);
  localStorage.setItem("token_post_auth_style", true);
  log.debug("Leaving setPostAuthStyleCheckToken(): token_post_auth_style=" +
            localStorage.getItem("token_post_auth_style") + ".");
  return false;
}

function setHeaderAuthStyleCheckToken() {
  log.debug("Entering setHeaderAuthStyleCheckToken().");
  $("#token_postAuthStyleCheckToken").prop("checked", false);
  $("#token_headerAuthStyleCheckToken").prop("checked", true);
  localStorage.setItem("token_post_auth_style", false);
  log.debug("Leaving setHeaderAuthStyleCheckToken(): token_post_auth_style=" +
            localStorage.getItem("token_post_auth_style") + ".");
  return false;
}

function setPostAuthStyleRefreshToken() {
  log.debug("Entering setPostAuthStyleRefreshToken().");
  $("#refresh_postAuthStyleCheckToken").prop("checked", true);
  $("#refresh_headerAuthStyleCheckToken").prop("checked", false);
  localStorage.setItem("refresh_post_auth_style", true);
  log.debug("Leaving setPostAuthStyleRefreshToken(): token_post_auth_style=" +
            localStorage.getItem("refresh_post_auth_style") + ".");
  return false;
}

function setHeaderAuthStyleRefreshToken() {
  log.debug("Entering setHeaderAuthStyleRefreshToken().");
  $("#refresh_postAuthStyleCheckToken").prop("checked", false);
  $("#refresh_headerAuthStyleCheckToken").prop("checked", true);
  localStorage.setItem("refresh_post_auth_style", false);
  log.debug("Leaving setHeaderAuthStyleRefreshToken(): " +
            "refresh_post_auth_style=" +
            localStorage.getItem("refresh_post_auth_style") + ".");
  return false;
}

function onClickCopyToken(field) {
  log.debug("Entering onClickCopyToken().");
  var copyText = $(field);
  navigator.clipboard.writeText(copyText.val());
  log.debug("Leaving onClickCopyToken().");
  return false;
}

function setInitiateFromEnd() {
  log.debug("Entering setInitiateFromEnd().");
  var frontEndInitiated = $("#token_initiateFromFrontEnd").is(":checked");
  var backEndInitiated = $("#token_initiateFromBackEnd").is(":checked");
  if(frontEndInitiated) {
    useFrontEnd = true;
  } else {
    useFrontEnd = false;
  }
  log.debug("frontEndInitiated: " + frontEndInitiated);
  log.debug("backEndInitiated: " + backEndInitiated);
  log.debug("Leaving setInitiateFromEnd().");
}

function setInitiateRefreshFromEnd() {
  log.debug("Entering setInitiateRefreshFromEnd().");
  var frontEndRefreshInitiated =
      $("#refresh_initiateFromFrontEnd").is(":checked");
  var backEndRefreshInitiated =
      $("#refresh_initiateFromBackEnd").is(":checked");
  if(frontEndRefreshInitiated) {
    useRefreshFrontEnd = true;
  } else {
    useRefreshFrontEnd = false;
  }
  log.debug("frontEndRefreshInitiated: " + frontEndRefreshInitiated);
  log.debug("backEndRefreshInitiated: " + backEndRefreshInitiated);
  log.debug("Leaving setInitiateRefreshFromEnd().");
}

function clickLink() {
  log.debug("Entering clickLink().");
  writeValuesToLocalStorage();
  log.debug("Leaving clickLink().");
  return true;
}

function clearTokenHistory() {
  log.debug("Entering clearTokenHistory().");
  localStorage.removeItem('token_history');
  localStorage.removeItem('token_history_active_index');
  collapsePane('#token-history-panel');
  collapsePane('#currently-viewing-panel');
  // The Authorization Endpoint Results pane names its tokens by generation once
  // they are in the history, so clearing it leaves those links pointing at an
  // entry that no longer exists. Redrawn here, which falls back to the
  // current-token slots — the pane and its tokens are still on the screen.
  if (authorizationResponseTokenSet) {
    renderAuthorizationEndpointResults(authorizationResponseTokenSet.expected,
                                       authorizationResponseTokenSet);
  }
  log.debug("Leaving clearTokenHistory().");
  return false;
}

// ---- Operation History ----

// Escapes text before inserting it into the (non-sanitized) operation history
// markup. The operation history table is rendered without DOMPurify so its
// inline onclick handlers survive, so dynamic values must be escaped here.
function escapeHtmlText(s) {
  log.debug("Entering escapeHtmlText().");
  log.debug("Leaving escapeHtmlText().");
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// The session nonce: preferring the nonce carried in the most recent id_token,
// falling back to the nonce generated for the authorization request.
function getCurrentSessionNonce() {
  log.debug("Entering getCurrentSessionNonce().");
  var idToken = localStorage.getItem('refresh_id_token') ||
      localStorage.getItem('token_id_token');
  var n = extractNonce(idToken);
  if (!!n) {
    log.debug("Leaving getCurrentSessionNonce().");
    return n;
  }
  log.debug("Leaving getCurrentSessionNonce().");
  return localStorage.getItem('nonce_field') || '';
}

// Index of the most recently saved token_history entry, or -1 if none.
function getLatestTokenHistoryIndex() {
  log.debug("Entering getLatestTokenHistoryIndex().");
  var history = [];
  try {
    history = JSON.parse(localStorage.getItem('token_history') || '[]');
  } catch (e) {
    log.error("Failed to parse token_history: " + e);
  }
  log.debug("Leaving getLatestTokenHistoryIndex().");
  return history.length - 1;
}

// Appends an entry to the cumulative operation history. options may include
// detail, client_id, nonce, and tokenHistoryIndex.
function saveOperationToHistory(operation, options) {
  log.debug("Entering saveOperationToHistory().");
  options = options || {};
  var history = [];
  try {
    history = JSON.parse(localStorage.getItem('operation_history') || '[]');
  } catch (e) {
    log.error("Failed to parse operation_history: " + e);
  }
  if (history.length >= OPERATION_HISTORY_LIMIT) {
    history = [];
  }
  history.push({
    timestamp: new Date().toISOString(),
    operation: operation,
    detail: options.detail || '',
    client_id: (options.client_id != null) ? options.client_id : '',
    nonce: (options.nonce != null) ? options.nonce : getCurrentSessionNonce(),
    tokenHistoryIndex: (typeof options.tokenHistoryIndex === 'number') ?
                        options.tokenHistoryIndex : null
  });
  localStorage.setItem('operation_history', JSON.stringify(history));
  renderOperationHistory();
  log.debug("Leaving saveOperationToHistory().");
}

function renderOperationHistory() {
  log.debug("Entering renderOperationHistory().");
  var history = [];
  try {
    history = JSON.parse(localStorage.getItem('operation_history') || '[]');
  } catch (e) {
    log.error("Failed to parse operation_history: " + e);
  }
  var html = '<div class="dbg-pane">' +
               '<legend class="dbg-legend" ' +
                   'data-target="operation_history_fieldset">Operation ' +
                   'History</legend>' +
               '<fieldset id="operation_history_fieldset">' +
               '<p><em>Chronological history of every endpoint operation ' +
                   'performed.</em></p>' +
               '<input type="button" value="Clear History" onclick="return oauth2_oidc_2.clearOperationHistory();" />';
  if (history.length === 0) {
    html += '<p><em>No operations recorded yet.</em></p></fieldset></div>';
    $("#operation-history-panel").html(html);
    log.debug("Leaving renderOperationHistory().");
    return;
  }
  // Cap the visible area to roughly 3-5 rows; a scrollbar appears beyond that.
  html += '<div style="max-height:200px; overflow-y:auto; margin-top:4px;">';
  html += '<table border="1" style="width:100%;">';
  var thStyle = 'position:sticky; top:0; background:#fafafa;';
  html += '<tr><th style="' + thStyle + ' width:5%">#</th><th style="' +
      thStyle + ' width:22%">Time</th><th style="' + thStyle +
      ' width:27%">Operation</th><th style="' + thStyle +
      ' width:18%">Client ID</th><th style="' + thStyle +
      ' width:28%">Nonce</th></tr>';
  history.slice().reverse().forEach(function(item, ridx) {
    var idx = history.length - 1 - ridx;
    var datePart = (item.timestamp || '').substring(0, 10);
    var timePart = (item.timestamp || '').substring(11, 19);
    var op = escapeHtmlText(item.operation) + (item.detail ? ' (' +
        escapeHtmlText(item.detail) + ')' : '');
    html += '<tr>';
    html += '<td>' + (idx + 1) + '</td>';
    html += '<td style="font-size:80%;">' + escapeHtmlText(datePart) + '<br>' +
        escapeHtmlText(timePart) + '</td>';
    html += '<td style="font-size:90%;">' + op + '</td>';
    html += '<td style="word-break:break-all; font-size:80%;">' +
        escapeHtmlText(item.client_id) + '</td>';
    html += '<td style="word-break:break-all; font-size:75%;">' +
        escapeHtmlText(item.nonce) + '</td>';
    html += '</tr>';
  });
  html += '</table></div></fieldset></div>';
  $("#operation-history-panel").html(html);
  log.debug("Leaving renderOperationHistory().");
}

function clearOperationHistory() {
  log.debug("Entering clearOperationHistory().");
  localStorage.removeItem('operation_history');
  renderOperationHistory();
  log.debug("Leaving clearOperationHistory().");
  return false;
}

// ---- Token Revocation (RFC 7009) ----

// Populate the revocation pane with a token selected via one of the
// "Revoke Token" links rendered next to each Access/Refresh Token field.
// type identifies which token to load; generation is the token history index
// (only used for the history_* types).
function loadTokenForRevocation(type, generation) {
  log.debug("Entering loadTokenForRevocation(). type=" + type +
            ", generation=" + generation);
  var token = "";
  var hint = "";
  if (type == "access") {
    token = localStorage.getItem("token_access_token");
    hint = "access_token";
  } else if (type == "refresh") {
    token = localStorage.getItem("token_refresh_token");
    hint = "refresh_token";
  } else if (type == "refresh_access") {
    token = localStorage.getItem("refresh_access_token");
    hint = "access_token";
  } else if (type == "refresh_refresh") {
    token = localStorage.getItem("refresh_refresh_token");
    hint = "refresh_token";
  } else if (type == "history_access" || type == "history_refresh") {
    var history = [];
    try {
      history = JSON.parse(localStorage.getItem('token_history') || '[]');
    } catch (e) {
      log.error("Failed to parse token_history: " + e);
    }
    var idx = parseInt(generation, 10);
    if (!isNaN(idx) && idx >= 0 && idx < history.length) {
      if (type == "history_access") {
        token = history[idx].access_token || "";
        hint = "access_token";
      } else {
        token = history[idx].refresh_token || "";
        hint = "refresh_token";
      }
    } else {
      log.error("Invalid generation index for revocation: " + generation);
    }
  } else {
    log.error("Unknown token type for revocation: " + type);
  }
  $("#revocation_token").val(token || "");
  $("#revocation_token_type_hint").val(hint);
  // Populate endpoint and client credentials from the most recent values.
  if (!!localStorage.getItem("revocation_endpoint")) {
    $("#revocation_revocation_endpoint")
      .val(localStorage.getItem("revocation_endpoint"));
  }
  if (!$("#revocation_client_id").val()) {
    $("#revocation_client_id").val($("#token_client_id").val() ||
      localStorage.getItem("client_id"));
  }
  if (!$("#revocation_client_secret").val()) {
    $("#revocation_client_secret").val($("#token_client_secret").val() ||
      localStorage.getItem("client_secret"));
  }
  // Make sure the revocation pane is visible and expanded.
  expandPane("#step6");
  $("#revocation_fieldset").css("display", "block");
  $("#revocation_expand_button").val("Collapse");
  recalculateRevocationRequestDescription();
  var el = document.getElementById("step6");
  if (el && el.scrollIntoView) {
    el.scrollIntoView({ behavior: "smooth", block: "center" });
  }
  log.debug("Leaving loadTokenForRevocation().");
  return false;
}

// Triggered by the "Revoke Token" buttons rendered next to each Access/Refresh
// token field: populates the Token Revocation pane for the chosen token and
// immediately submits the revocation request.
function revokeTokenDirect(type, generation) {
  log.debug("Entering revokeTokenDirect(). type=" + type + ", generation=" +
            generation);
  loadTokenForRevocation(type, generation);
  log.debug("Leaving revokeTokenDirect().");
  return revokeButtonClick();
}

function buildInternalRevocationRequestMessage() {
  log.debug("Entering buildInternalRevocationRequestMessage().");
  var sslValidate;
  if ($("#SSLValidate-yes").is(":checked")) {
    sslValidate = $("#SSLValidate-yes").val();
  } else if ($("#SSLValidate-no").is(":checked")) {
    sslValidate = $("#SSLValidate-no").val();
  } else {
    sslValidate = "true";
  }
  var formData = {
    revocation_endpoint: $("#revocation_revocation_endpoint").val(),
    token: $("#revocation_token").val(),
    token_type_hint: $("#revocation_token_type_hint").val(),
    client_id: $("#revocation_client_id").val(),
    client_secret: $("#revocation_client_secret").val(),
    auth_style: getLSBooleanItem("revocation_post_auth_style"),
    sslValidate: sslValidate
  };
  log.debug("Leaving buildInternalRevocationRequestMessage().");
  return formData;
}

function revokeButtonClick() {
  log.debug("Entering revokeButtonClick().");
  writeValuesToLocalStorage();
  recalculateRevocationRequestDescription();
  var formData = buildInternalRevocationRequestMessage();
  if (!formData.token) {
    displayRevocationResult("No token specified. Use a \"Revoke Token\" link " +
                            "above a token field, " +
                            "or paste a token into the Token field, then " +
                                "try again.", true);
    log.debug("Leaving revokeButtonClick().");
    return false;
  }
  if (!formData.revocation_endpoint) {
    displayRevocationResult("No revocation endpoint configured. Populate it " +
                            "from the discovery document " +
                            "on the previous page, or enter it manually.",
                                true);
    log.debug("Leaving revokeButtonClick().");
    return false;
  }
  if (useRevocationFrontEnd) {
    log.debug("Using frontend to call Revocation Endpoint. " +
              "auth_style(POST body)=" + formData.auth_style);
    var headers = { "Content-Type": "application/x-www-form-urlencoded" };
    var bodyParams = "token=" + encodeURIComponent(formData.token);
    if (!!formData.token_type_hint) {
      bodyParams += "&token_type_hint=" +
          encodeURIComponent(formData.token_type_hint);
    }
    if (formData.auth_style) {
      // POST body: send client credentials as request parameters.
      if (!!formData.client_id) {
        bodyParams += "&client_id=" + encodeURIComponent(formData.client_id);
      }
      if (!!formData.client_secret) {
        bodyParams += "&client_secret=" +
            encodeURIComponent(formData.client_secret);
      }
    } else {
      // HTTP Basic authorization header.
      if (!!formData.client_secret) {
        headers["Authorization"] = "Basic " + btoa(formData.client_id + ":" +
                formData.client_secret);
      } else if (!!formData.client_id) {
        bodyParams += "&client_id=" + encodeURIComponent(formData.client_id);
      }
    }
    $.ajax({
      type: "POST",
      url: formData.revocation_endpoint,
      crossDomain: true,
      headers: headers,
      data: bodyParams,
      success: successfulRevocationAPICall,
      error: errorRevocationAPICall
    });
  } else {
    log.debug("Using backend to call Revocation Endpoint.");
    $.ajax({
      type: "POST",
      url: appconfig.apiUrl + "/revoke",
      crossDomain: true,
      contentType: "application/json; charset=utf-8",
      data: JSON.stringify(formData),
      success: successfulRevocationAPICall,
      error: errorRevocationAPICall
    });
  }
  log.debug("Leaving revokeButtonClick().");
  return false;
}

function successfulRevocationAPICall(data, textStatus, jqXHR) {
  log.debug("Entering successfulRevocationAPICall(): data=" +
            JSON.stringify(data) + ", textStatus=" + textStatus);
  var status = (jqXHR && jqXHR.status) ? jqXHR.status : 200;
  var statusText = (jqXHR && jqXHR.statusText) ? jqXHR.statusText : "";
  var bodyText = "";
  try {
    bodyText = (typeof data === "string") ? data : JSON.stringify(data, null,
        2);
  } catch (e) {
    bodyText = String(data);
  }
  var message = "Token revocation request accepted.\n" +
                "Per RFC 7009, the authorization server returns HTTP 200 " +
                    "whether or not the token\n" +
                "previously existed, so a 200 here does not by itself " +
                    "confirm a token was active.\n\n" +
                "HTTP Status: " + status + " " + statusText + "\n" +
                "Response Body: " + (bodyText && bodyText !== "{}" ?
                    bodyText : "(empty)");
  displayRevocationResult(message, false);
  saveOperationToHistory('Revocation Endpoint', {
    client_id: $("#revocation_client_id").val(),
    detail: $("#revocation_token_type_hint").val() || 'token'
  });
  log.debug("Leaving successfulRevocationAPICall().");
}

function errorRevocationAPICall(jqXHR, status, error) {
  log.debug("Entering errorRevocationAPICall().");
  log.error("An error occurred calling the revocation endpoint.");
  log.error("status: " + JSON.stringify(status));
  log.error("error: " + JSON.stringify(error));
  var responseText = (jqXHR && jqXHR.responseText) ? jqXHR.responseText : "";
  var responseObject = {};
  try {
    responseObject = JSON.parse(responseText);
  } catch (e) {
    responseObject = {};
  }
  var message = "An error occurred during token revocation.\n" +
                "HTTP Status: " + (jqXHR ? jqXHR.status : "") + " " + (jqXHR ?
                    jqXHR.statusText : "") + "\n" +
                "error: " + (responseObject.error || error || "") + "\n" +
                "error_description: " + (responseObject.error_description ||
                    "") + "\n" +
                "Response Body: " + responseText;
  displayRevocationResult(message, true);
  saveOperationToHistory('Revocation Endpoint', {
    client_id: $("#revocation_client_id").val(),
    detail: ($("#revocation_token_type_hint").val() || 'token') + ', error'
  });
  log.debug("Leaving errorRevocationAPICall().");
}

function displayRevocationResult(message, isError) {
  log.debug("Entering displayRevocationResult(). isError=" + isError);
  var legend = isError ? "Token Revocation Error" : "Token Revocation Results";
  var html = "<fieldset>" +
               "<legend>" + legend + "</legend>" +
               "<p><em>Most recent result of the Token Revocation (RFC 7009) " +
                   "call.</em></p>" +
               "<table>" +
                 "<tr>" +
                   "<td>" +
                     "<textarea rows='9' cols='80' readonly " +
                         "id='revocation_result_textarea' " +
                         "name='revocation_result_textarea'></textarea>" +
                   "</td>" +
                 "</tr>" +
               "</table>" +
             "</fieldset>";
  $("#revocation_endpoint_result").html(DOMPurify.sanitize(html));
  // Set the value separately so the (untrusted) token/endpoint text is never
  // interpreted as markup.
  $("#revocation_result_textarea").val(message);
  $("#revocation_endpoint_result").show();
  log.debug("Leaving displayRevocationResult().");
}

function recalculateRevocationRequestDescription() {
  log.debug("Entering recalculateRevocationRequestDescription().");
  var ta1 = $("#display_revocation_request_form_textarea1");
  if (!ta1) {
    log.debug("Leaving recalculateRevocationRequestDescription().");
    return;
  }
  var endpoint = $("#revocation_revocation_endpoint").val();
  var token = $("#revocation_token").val();
  var hint = $("#revocation_token_type_hint").val();
  var clientId = $("#revocation_client_id").val();
  var clientSecret = $("#revocation_client_secret").val();
  var postAuthStyle = getLSBooleanItem("revocation_post_auth_style");
  var request = "POST " + endpoint + "\n" +
                "Content-Type: application/x-www-form-urlencoded\n";
  if (!postAuthStyle && !!clientSecret) {
    request += "Authorization: Basic base64(" + clientId +
        ":<client_secret>)\n";
  }
  request += "Message Body:\n" +
             "token=" + token;
  if (!!hint) {
    request += "&\n" + "token_type_hint=" + hint;
  }
  if (postAuthStyle) {
    if (!!clientId) {
      request += "&\n" + "client_id=" + clientId;
    }
    if (!!clientSecret) {
      request += "&\n" + "client_secret=<client_secret>";
    }
  } else if (!clientSecret && !!clientId) {
    request += "&\n" + "client_id=" + clientId;
  }
  $("#display_revocation_request_form_textarea1").val(request);
  log.debug("Leaving recalculateRevocationRequestDescription().");
}

function setInitiateRevocationFromEnd() {
  log.debug("Entering setInitiateRevocationFromEnd().");
  var frontEndInitiated = $("#revocation_initiateFromFrontEnd").is(":checked");
  if (frontEndInitiated) {
    useRevocationFrontEnd = true;
  } else {
    useRevocationFrontEnd = false;
  }
  log.debug("useRevocationFrontEnd=" + useRevocationFrontEnd);
  log.debug("Leaving setInitiateRevocationFromEnd().");
}

function setPostAuthStyleRevocation() {
  log.debug("Entering setPostAuthStyleRevocation().");
  $("#revocation_postAuthStyleCheckToken").prop("checked", true);
  $("#revocation_headerAuthStyleCheckToken").prop("checked", false);
  localStorage.setItem("revocation_post_auth_style", true);
  recalculateRevocationRequestDescription();
  log.debug("Leaving setPostAuthStyleRevocation(): " +
            "revocation_post_auth_style=" +
            localStorage.getItem("revocation_post_auth_style") + ".");
  return false;
}

function setHeaderAuthStyleRevocation() {
  log.debug("Entering setHeaderAuthStyleRevocation().");
  $("#revocation_postAuthStyleCheckToken").prop("checked", false);
  $("#revocation_headerAuthStyleCheckToken").prop("checked", true);
  localStorage.setItem("revocation_post_auth_style", false);
  recalculateRevocationRequestDescription();
  log.debug("Leaving setHeaderAuthStyleRevocation(): " +
            "revocation_post_auth_style=" +
            localStorage.getItem("revocation_post_auth_style") + ".");
  return false;
}

// Returns the most recent access token, preferring one obtained from a Refresh
// Token call (if one has been made) over the access token from the initial
// Token Endpoint call.
function getLatestAccessToken() {
  log.debug("Entering getLatestAccessToken().");
  if (getLSBooleanItem("refresh_token_used")) {
    var refreshAccessToken = localStorage.getItem("refresh_access_token");
    if (!!refreshAccessToken) {
      log.debug("Leaving getLatestAccessToken().");
      return refreshAccessToken;
    }
  }
  log.debug("Leaving getLatestAccessToken().");
  return localStorage.getItem("token_access_token") || "";
}

// Pre-populates the Token Revocation pane with the latest access token and an
// initial token_type_hint of "access_token". Used on page load and after every
// Token/Refresh Endpoint call so the pane always targets the current access
// token by default (a "Revoke Token" link can still override it).
function populateRevocationTokenWithLatestAccessToken() {
  log.debug("Entering populateRevocationTokenWithLatestAccessToken().");
  $("#revocation_token").val(getLatestAccessToken());
  $("#revocation_token_type_hint").val("access_token");
  recalculateRevocationRequestDescription();
  log.debug("Leaving populateRevocationTokenWithLatestAccessToken().");
}

// ---- Token Exchange (RFC 8693) ----

var TOKEN_EXCHANGE_GRANT_TYPE =
    "urn:ietf:params:oauth:grant-type:token-exchange";

// Pre-populates the Token Exchange pane's subject_token with the latest access
// token (from the initial Token Endpoint call or a Refresh Token call). Used on
// page load and after every Token/Refresh Endpoint call.
function populateTokenExchangeSubjectWithLatestAccessToken() {
  log.debug("Entering populateTokenExchangeSubjectWithLatestAccessToken().");
  $("#tokenexchange_subject_token").val(getLatestAccessToken());
  recalculateTokenExchangeRequestDescription();
  log.debug("Leaving populateTokenExchangeSubjectWithLatestAccessToken().");
}

// Impersonation: only a subject token is sent. Delegation: an actor token is
// also sent (RFC 8693 Section 1.1). Shows/hides the actor token rows.
function setTokenExchangeType() {
  log.debug("Entering setTokenExchangeType().");
  var delegation = $("#tokenexchange_delegation").is(":checked");
  if (delegation) {
    $("#tokenexchange_actor_token_row").show();
    $("#tokenexchange_actor_token_type_row").show();
  } else {
    $("#tokenexchange_actor_token_row").hide();
    $("#tokenexchange_actor_token_type_row").hide();
  }
  recalculateTokenExchangeRequestDescription();
  log.debug("Leaving setTokenExchangeType(). delegation=" + delegation);
}

function buildInternalTokenExchangeRequestMessage() {
  log.debug("Entering buildInternalTokenExchangeRequestMessage().");
  var sslValidate;
  if ($("#SSLValidate-yes").is(":checked")) {
    sslValidate = $("#SSLValidate-yes").val();
  } else if ($("#SSLValidate-no").is(":checked")) {
    sslValidate = $("#SSLValidate-no").val();
  } else {
    sslValidate = "true";
  }
  var delegation = $("#tokenexchange_delegation").is(":checked");
  var formData = {
    token_endpoint: $("#tokenexchange_token_endpoint").val(),
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: $("#tokenexchange_subject_token").val(),
    subject_token_type: $("#tokenexchange_subject_token_type").val(),
    requested_token_type: $("#tokenexchange_requested_token_type").val(),
    resource: $("#tokenexchange_resource").val(),
    audience: $("#tokenexchange_audience").val(),
    scope: $("#tokenexchange_scope").val(),
    client_id: $("#tokenexchange_client_id").val(),
    client_secret: $("#tokenexchange_client_secret").val(),
    auth_style: getLSBooleanItem("tokenexchange_post_auth_style"),
    sslValidate: sslValidate
  };
  // Only include the actor token for delegation (RFC 8693 Section 2.1).
  if (delegation) {
    formData.actor_token = $("#tokenexchange_actor_token").val();
    formData.actor_token_type = $("#tokenexchange_actor_token_type").val();
  }
  log.debug("Leaving buildInternalTokenExchangeRequestMessage().");
  return formData;
}

// Appends a key=value pair to an x-www-form-urlencoded body string when value
// is non-empty.
function appendFormParam(body, key, value) {
  log.debug("Entering appendFormParam().");
  if (!value) {
    log.debug("Leaving appendFormParam().");
    return body;
  }
  log.debug("Leaving appendFormParam().");
  return (body ? body + "&" : "") + key + "=" + encodeURIComponent(value);
}

function tokenExchangeButtonClick() {
  log.debug("Entering tokenExchangeButtonClick().");
  writeValuesToLocalStorage();
  recalculateTokenExchangeRequestDescription();
  var formData = buildInternalTokenExchangeRequestMessage();
  if (!formData.token_endpoint) {
    displayTokenExchangeResult("No token endpoint configured. Populate it " +
                               "from the discovery document " +
                               "on the previous page, or enter it manually.",
                                   true);
    log.debug("Leaving tokenExchangeButtonClick().");
    return false;
  }
  if (!formData.subject_token) {
    displayTokenExchangeResult("No subject token specified. The subject " +
                               "token defaults to the most recent " +
                               "access token; obtain a token first, or paste " +
                                   "one into the Subject Token field.", true);
    log.debug("Leaving tokenExchangeButtonClick().");
    return false;
  }
  if ($("#tokenexchange_delegation").is(":checked") && !formData.actor_token) {
    displayTokenExchangeResult("Delegation is selected but no actor token " +
                               "was provided. Enter an actor token, " +
                               "or switch to Impersonation.", true);
    log.debug("Leaving tokenExchangeButtonClick().");
    return false;
  }
  if (useTokenExchangeFrontEnd) {
    log.debug("Using frontend to call Token Endpoint for token exchange. " +
              "auth_style(POST body)=" + formData.auth_style);
    var headers = { "Content-Type": "application/x-www-form-urlencoded" };
    var bodyParams = "grant_type=" + encodeURIComponent(formData.grant_type);
    bodyParams = appendFormParam(bodyParams, "subject_token",
        formData.subject_token);
    bodyParams = appendFormParam(bodyParams, "subject_token_type",
        formData.subject_token_type);
    bodyParams = appendFormParam(bodyParams, "actor_token",
        formData.actor_token);
    bodyParams = appendFormParam(bodyParams, "actor_token_type",
        formData.actor_token_type);
    bodyParams = appendFormParam(bodyParams, "requested_token_type",
        formData.requested_token_type);
    bodyParams = appendFormParam(bodyParams, "resource", formData.resource);
    bodyParams = appendFormParam(bodyParams, "audience", formData.audience);
    bodyParams = appendFormParam(bodyParams, "scope", formData.scope);
    if (formData.auth_style) {
      // POST body: send client credentials as request parameters.
      bodyParams = appendFormParam(bodyParams, "client_id", formData.client_id);
      bodyParams = appendFormParam(bodyParams, "client_secret",
          formData.client_secret);
    } else {
      // HTTP Basic authorization header.
      if (!!formData.client_secret) {
        headers["Authorization"] = "Basic " + btoa(formData.client_id + ":" +
                formData.client_secret);
      } else if (!!formData.client_id) {
        bodyParams = appendFormParam(bodyParams, "client_id",
            formData.client_id);
      }
    }
    $.ajax({
      type: "POST",
      url: formData.token_endpoint,
      crossDomain: true,
      headers: headers,
      data: bodyParams,
      success: successfulTokenExchangeAPICall,
      error: errorTokenExchangeAPICall
    });
  } else {
    log.debug("Using backend to call Token Endpoint for token exchange.");
    $.ajax({
      type: "POST",
      url: appconfig.apiUrl + "/tokenexchange",
      crossDomain: true,
      contentType: "application/json; charset=utf-8",
      data: JSON.stringify(formData),
      success: successfulTokenExchangeAPICall,
      error: errorTokenExchangeAPICall
    });
  }
  log.debug("Leaving tokenExchangeButtonClick().");
  return false;
}

function successfulTokenExchangeAPICall(data, textStatus, jqXHR) {
  log.debug("Entering successfulTokenExchangeAPICall(): data=" +
            JSON.stringify(data) + ", textStatus=" + textStatus);
  var status = (jqXHR && jqXHR.status) ? jqXHR.status : 200;
  var statusText = (jqXHR && jqXHR.statusText) ? jqXHR.statusText : "";
  var bodyText = "";
  try {
    bodyText = (typeof data === "string") ? data : JSON.stringify(data, null,
        2);
  } catch (e) {
    bodyText = String(data);
  }
  var message = "Token exchange request succeeded.\n" +
                "HTTP Status: " + status + " " + statusText + "\n" +
                "Response Body:\n" + (bodyText && bodyText !== "{}" ?
                    bodyText : "(empty)");
  displayTokenExchangeResult(message, false);
  saveOperationToHistory('Token Exchange', {
    client_id: $("#tokenexchange_client_id").val(),
    detail: $("#tokenexchange_delegation").is(":checked") ?
              'delegation' : 'impersonation'
  });
  log.debug("Leaving successfulTokenExchangeAPICall().");
}

function errorTokenExchangeAPICall(jqXHR, status, error) {
  log.debug("Entering errorTokenExchangeAPICall().");
  log.error("An error occurred calling the token endpoint for token exchange.");
  log.error("status: " + JSON.stringify(status));
  log.error("error: " + JSON.stringify(error));
  var responseText = (jqXHR && jqXHR.responseText) ? jqXHR.responseText : "";
  var responseObject = {};
  try {
    responseObject = JSON.parse(responseText);
  } catch (e) {
    responseObject = {};
  }
  var message = "An error occurred during token exchange.\n" +
                "HTTP Status: " + (jqXHR ? jqXHR.status : "") + " " + (jqXHR ?
                    jqXHR.statusText : "") + "\n" +
                "error: " + (responseObject.error || error || "") + "\n" +
                "error_description: " + (responseObject.error_description ||
                    "") + "\n" +
                "Response Body: " + responseText;
  displayTokenExchangeResult(message, true);
  saveOperationToHistory('Token Exchange', {
    client_id: $("#tokenexchange_client_id").val(),
    detail: ($("#tokenexchange_delegation").is(":checked") ?
             'delegation' : 'impersonation') + ', error'
  });
  log.debug("Leaving errorTokenExchangeAPICall().");
}

function displayTokenExchangeResult(message, isError) {
  log.debug("Entering displayTokenExchangeResult(). isError=" + isError);
  var legend = isError ? "Token Exchange Error" : "Token Exchange Results";
  var html = "<fieldset>" +
               "<legend>" + legend + "</legend>" +
               "<p><em>Most recent result of the Token Exchange (RFC 8693) " +
                   "call.</em></p>" +
               "<table>" +
                 "<tr>" +
                   "<td>" +
                     "<textarea rows='12' cols='80' readonly " +
                         "id='tokenexchange_result_textarea' " +
                         "name='tokenexchange_result_textarea'></textarea>" +
                   "</td>" +
                 "</tr>" +
               "</table>" +
             "</fieldset>";
  $("#tokenexchange_endpoint_result").html(DOMPurify.sanitize(html));
  // Set the value separately so the (untrusted) token text is never interpreted
  // as markup.
  $("#tokenexchange_result_textarea").val(message);
  $("#tokenexchange_endpoint_result").show();
  log.debug("Leaving displayTokenExchangeResult().");
}

function recalculateTokenExchangeRequestDescription() {
  log.debug("Entering recalculateTokenExchangeRequestDescription().");
  var ta1 = $("#display_tokenexchange_request_form_textarea1");
  if (!ta1) {
    log.debug("Leaving recalculateTokenExchangeRequestDescription().");
    return;
  }
  var endpoint = $("#tokenexchange_token_endpoint").val();
  var clientId = $("#tokenexchange_client_id").val();
  var clientSecret = $("#tokenexchange_client_secret").val();
  var postAuthStyle = getLSBooleanItem("tokenexchange_post_auth_style");
  var delegation = $("#tokenexchange_delegation").is(":checked");
  var request = "POST " + endpoint + "\n" +
                "Content-Type: application/x-www-form-urlencoded\n";
  if (!postAuthStyle && !!clientSecret) {
    request += "Authorization: Basic base64(" + clientId +
        ":<client_secret>)\n";
  }
  request += "Message Body:\n" +
             "grant_type=" + TOKEN_EXCHANGE_GRANT_TYPE;
  var addLine = function (key, value) {
    log.debug("Entering addLine().");
    if (!!value) {
      request += "&\n" + key + "=" + value;
    }
    log.debug("Leaving addLine().");
  };
  addLine("subject_token", $("#tokenexchange_subject_token").val());
  addLine("subject_token_type", $("#tokenexchange_subject_token_type").val());
  if (delegation) {
    addLine("actor_token", $("#tokenexchange_actor_token").val());
    addLine("actor_token_type", $("#tokenexchange_actor_token_type").val());
  }
  addLine("requested_token_type",
          $("#tokenexchange_requested_token_type").val());
  addLine("resource", $("#tokenexchange_resource").val());
  addLine("audience", $("#tokenexchange_audience").val());
  addLine("scope", $("#tokenexchange_scope").val());
  if (postAuthStyle) {
    addLine("client_id", clientId);
    if (!!clientSecret) {
      request += "&\n" + "client_secret=<client_secret>";
    }
  } else if (!clientSecret && !!clientId) {
    addLine("client_id", clientId);
  }
  $("#display_tokenexchange_request_form_textarea1").val(request);
  log.debug("Leaving recalculateTokenExchangeRequestDescription().");
}

function setInitiateTokenExchangeFromEnd() {
  log.debug("Entering setInitiateTokenExchangeFromEnd().");
  var frontEndInitiated =
      $("#tokenexchange_initiateFromFrontEnd").is(":checked");
  if (frontEndInitiated) {
    useTokenExchangeFrontEnd = true;
  } else {
    useTokenExchangeFrontEnd = false;
  }
  log.debug("useTokenExchangeFrontEnd=" + useTokenExchangeFrontEnd);
  log.debug("Leaving setInitiateTokenExchangeFromEnd().");
}

function setPostAuthStyleTokenExchange() {
  log.debug("Entering setPostAuthStyleTokenExchange().");
  $("#tokenexchange_postAuthStyle").prop("checked", true);
  $("#tokenexchange_headerAuthStyle").prop("checked", false);
  localStorage.setItem("tokenexchange_post_auth_style", true);
  recalculateTokenExchangeRequestDescription();
  log.debug("Leaving setPostAuthStyleTokenExchange().");
  return false;
}

function setHeaderAuthStyleTokenExchange() {
  log.debug("Entering setHeaderAuthStyleTokenExchange().");
  $("#tokenexchange_postAuthStyle").prop("checked", false);
  $("#tokenexchange_headerAuthStyle").prop("checked", true);
  localStorage.setItem("tokenexchange_post_auth_style", false);
  recalculateTokenExchangeRequestDescription();
  log.debug("Leaving setHeaderAuthStyleTokenExchange().");
  return false;
}


// ---------------------------------------------------------------------------
// RFC 9700 compliance mode — this page's half.
//
// The rules are in client/src/rfc9700.js. What is here is the wiring: reading
// the response, drawing the verdict, putting the page into the shape the mode
// requires, and removing the authorization response from the address bar.
// Nothing below runs unless the checkbox is ticked.
// ---------------------------------------------------------------------------

// The query string and fragment as they were when the page loaded, or null
// while they are still live. Written by rfc9700ScrubAuthorizationResponse(),
// read by getParameterByName() and parseFragment() — which is what lets the
// response be taken out of the URL without taking it away from the page.
var rfc9700ScrubbedSearch = null;
var rfc9700ScrubbedHash = null;

// True when this page load is one an identity provider sent an authorization
// response to. The gate is asked this first because most loads of this page
// are not: the Client Credentials grant never visits the authorization
// endpoint at all, and the way back from the token detail page carries no
// response of its own. Refusing those for having no transaction would make the
// mode look broken on the two flows it has nothing to say about.
function rfc9700AuthorizationResponsePresent() {
  log.debug("Entering rfc9700AuthorizationResponsePresent().");
  var fragment = parseFragment();
  var present = !!(getParameterByName("code") || fragment["code"] ||
      getParameterByName("state") || fragment["state"] ||
      getParameterByName("error") || fragment["error"] ||
      getParameterByName("access_token") || fragment["access_token"] ||
      getParameterByName("id_token") || fragment["id_token"]);
  log.debug("Leaving rfc9700AuthorizationResponsePresent(). present=" +
            present);
  return present;
}

// Requirement 10.1: take the authorization response out of the address bar and
// out of this history entry.
//
// history.replaceState rather than pushState, so the response does not become
// a second entry the back button can return to — which would put it back in
// history, the one place this rule is about. The snapshot above is what keeps
// every later read working.
function rfc9700ScrubAuthorizationResponse() {
  log.debug("Entering rfc9700ScrubAuthorizationResponse().");
  if (!rfc9700.enabled()) {
    log.debug("Leaving rfc9700ScrubAuthorizationResponse(). Mode off.");
    return;
  }
  if (rfc9700ScrubbedSearch !== null) {
    log.debug("Leaving rfc9700ScrubAuthorizationResponse(). Already done.");
    return;
  }
  if (!window.location.search && !window.location.hash) {
    log.debug("Leaving rfc9700ScrubAuthorizationResponse(). Nothing there.");
    return;
  }
  rfc9700ScrubbedSearch = window.location.search;
  rfc9700ScrubbedHash = window.location.hash;
  try {
    window.history.replaceState(null, "", window.location.pathname);
    log.debug("Authorization response removed from the address bar.");
  } catch (e) {
    // replaceState throws on an opaque origin (a file: URL, a sandboxed
    // frame). Neither is a context this page is served in, but a throw here
    // would take out the whole ready() handler for a cosmetic rule, so it is
    // reported and swallowed. The snapshot is already taken, so the page is
    // consistent either way.
    log.error("Could not scrub the authorization response from the URL: " +
              e.message);
  }
  log.debug("Leaving rfc9700ScrubAuthorizationResponse().");
}

// Draw a verdict into one of the report containers. DOMPurify because the
// findings quote values the server sent.
function renderRfc9700Report(containerId, title, verdict) {
  log.debug("Entering renderRfc9700Report(). containerId=" + containerId);
  var container = $("#" + containerId);
  if (!container.length) {
    log.debug("Leaving renderRfc9700Report(). No container.");
    return;
  }
  if (!verdict) {
    container.html("");
    log.debug("Leaving renderRfc9700Report(). Cleared.");
    return;
  }
  container.html(DOMPurify.sanitize(rfc9700.report(title, verdict)));
  log.debug("Leaving renderRfc9700Report().");
}

// Put the page into the shape the mode requires, or take it back out. As on
// step 1, every change here is reversible: a control left disabled after the
// mode is turned off is indistinguishable from a broken page.
function applyRfc9700Ui() {
  log.debug("Entering applyRfc9700Ui().");
  var on = rfc9700.enabled();

  // Section 1.11 and 5.1: the grants that do not survive.
  $("#authorization_grant_type option").each(function () {
    var value = $(this).val();
    var refused = on && !rfc9700.grantAllowed(value);
    $(this).prop("disabled", refused);
    $(this).attr("title", refused ? rfc9700.grantRefusalReason(value) : null);
  });

  // Section 8.2: certificate validation.
  if (on) {
    $("#SSLValidate-yes").prop("checked", true);
    $("#SSLValidate-no").prop("checked", false).prop("disabled", true);
  } else {
    $("#SSLValidate-no").prop("disabled", false);
  }

  // Requirement 6.2: client_secret_basic rather than client_secret_post, on
  // all four panes that authenticate a client. The secret is not in a URL
  // either way — the rule RFC 9700 states as MUST NOT — so this is the SHOULD
  // half, and it is applied by selecting rather than by disabling: the point
  // of a debugger is that the other style stays reachable.
  if (on) {
    var groups = ["token", "refresh", "revocation"];
    for (var i = 0; i < groups.length; i++) {
      $("#" + groups[i] + "_headerAuthStyleCheckToken").prop("checked", true);
      $("#" + groups[i] + "_postAuthStyleCheckToken").prop("checked", false);
    }
    $("#tokenexchange_headerAuthStyle").prop("checked", true);
    $("#tokenexchange_postAuthStyle").prop("checked", false);
  }

  // Requirement 4.1: sender-constrained access tokens. Two controls move
  // together and they have to, which is why this is one block rather than
  // two: a DPoP proof cannot be carried by the PROXIED token call (the api
  // makes that request, so a proof built here would name the wrong htu), so
  // turning DPoP on without also selecting the front end produces an unbound
  // token and a red warning by default — the mode looking broken on its first
  // use. Both stay reversible; turning either back off yields a SHOULD row in
  // the report rather than a refusal, because RFC 9700 states this at SHOULD.
  if (on && appconfig.backendAvailable !== false) {
    $("#token_initiateFromFrontEnd").prop("checked", true);
    $("#token_initiateFromBackEnd").prop("checked", false);
    setInitiateFromEnd();
  }
  if (on && !$("#dpop_enabled").is(":checked")) {
    $("#dpop_enabled").prop("checked", true);
    setDpopEnabled();
  }

  $("#rfc9700_mode_status").html(DOMPurify.sanitize(on
    ? "<span class='dbg-ok'>Client-side RFC 9700 requirements are being " +
      "enforced on this workflow.</span>"
    : ""));

  log.debug("Leaving applyRfc9700Ui(). on=" + on);
}

// The checkbox's own handler. Returns true so the box actually toggles.
function onRfc9700ModeChange() {
  log.debug("Entering onRfc9700ModeChange().");
  rfc9700.setEnabled($("#rfc9700_mode").is(":checked"));
  if (!rfc9700.enabled()) {
    renderRfc9700Report("rfc9700_response_report", "", null);
    renderRfc9700Report("rfc9700_token_report", "", null);
    renderRfc9700Report("rfc9700_refresh_report", "", null);
  }
  applyRfc9700Ui();
  recalculateTokenRequestDescription();
  recalculateRefreshRequestDescription();
  log.debug("Leaving onRfc9700ModeChange().");
  return true;
}

module.exports = {
  onRfc9700ModeChange,
  applyRfc9700Ui,
  renderRfc9700Report,
  rfc9700AuthorizationResponsePresent,
  rfc9700ScrubAuthorizationResponse,
  rfc9700GateRefreshRequest,
  OnSubmitTokenEndpointForm,
  getParameterByName,
  resetUI,
  resetErrorDisplays,
  writeValuesToLocalStorage,
  loadValuesFromLocalStorage,
  recalculateTokenRequestDescription,
  recalculateRefreshRequestDescription,
  generateUUID,
  displayResourceCheck,
  displayTokenResourceCheck,
  recalculateAuthorizationErrorDescription,
  recalculateTokenErrorDescription,
  recalculateRefreshErrorDescription,
  parseFragment,
  displayOIDCArtifacts,
  useRefreshTokens,
  isUrl,
  regenerateState,
  regenerateNonce,
  recreateTokenDisplay,
  displayTokenCustomParametersCheck,
  generateCustomParametersListUI,
  onClickShowFieldSet,
  // The token exchange pane's tab strip. Exported because the markup calls it
  // through the bundle's standalone name, like every other handler here.
  selectTokenTab,
  selectTokenResultTab,
  selectRefreshTab,
  selectRefreshResultTab,
  selectCurrentlyViewingTab,
  usePKCERFC,
  setPostAuthStyleCheckToken,
  setHeaderAuthStyleCheckToken,
  setPostAuthStyleRefreshToken,
  setHeaderAuthStyleRefreshToken,
  onClickCopyToken,
  setInitiateFromEnd,
  // The OAuth2/OIDC workflow's DPoP pane. Exported because the markup calls
  // them through the bundle's standalone name, like every other handler here.
  setDpopEnabled,
  generateDpopKey,
  setInitiateRefreshFromEnd,
  logoutButtonClick,
  clickLink,
  selectTokenSet,
  clearTokenHistory,
  clearOperationHistory,
  loadTokenForRevocation,
  revokeButtonClick,
  recalculateRevocationRequestDescription,
  setInitiateRevocationFromEnd,
  setPostAuthStyleRevocation,
  setHeaderAuthStyleRevocation,
  tokenExchangeButtonClick,
  recalculateTokenExchangeRequestDescription,
  setInitiateTokenExchangeFromEnd,
  setPostAuthStyleTokenExchange,
  setHeaderAuthStyleTokenExchange,
  setTokenExchangeType,
  // The access token handoff. Not called from the markup: exported because
  // tests/scim_page.js drives the delivery half without an identity provider,
  // which is the only way to assert the whole route from the SCIM page's
  // button to the SCIM page's field.
  offerTokenToHandoff
};
