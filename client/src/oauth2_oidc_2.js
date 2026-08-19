const appconfig = require(process.env.CONFIG_FILE);
// OpenID Provider Metadata (Discovery 1.0 s3) — shared with oauth2_oidc_1.js
// so both Configuration Parameters panes carry the same fields and defaults.
const opMetadata = require("./op_metadata");
const sdJwtVc = require("./sd_jwt_vc");
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
    url = window.location.search;
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
  $('#step3').show();
  $('#step4').show();
  $('#step5').show();
  $('#step6').show();
  $('#step7').show();
  $('#operation-history-panel').show();
  log.debug("Updating local storage.");
  writeValuesToLocalStorage();
  log.debug("Recalculating token request description.");
  recalculateTokenRequestDescription();
  log.debug("Recalculating refresh request description.");
  recalculateRefreshRequestDescription();
  log.debug("Reset error displays.");
  resetErrorDisplays();
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
        $.ajax({
          type: "POST",
          crossdomain: true,
          url: localStorage.getItem("token_endpoint"),
          data: convertToOAuth2Format(formData),
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
    $.ajax({
      type: "POST",
      crossdomain: true,
      url: appconfig.apiUrl + "/token",
      data: JSON.stringify(formData),
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
  log.debug("Entering ajax success function for Access Token call: data=" 
          + JSON.stringify(data)
          + ", textStatus="
          + textStatus
          + ", request=" 
          + JSON.stringify(request));
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
                            data.id_token, 'token');
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
                            'token');
    }
    $("#token_endpoint_result").html(token_endpoint_result_html);
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
    $("#token_endpoint_result").show();
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
    $('#currently-viewing-panel').show();
    $('#refresh_endpoint_result').show();
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
    // If the SD-JWT VC workflow sent us here, the tokens are what it came for.
    returnToSdJwtVcFlow();
  log.debug("Leaving successfulInternalTokenAPICall().");
}

function errorInternalTokenAPICall(request, status, error) {
  log.debug("Entering errorInternalTokenAPICall().");
  log.error("An error occurred calling the token endpoint.");
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
  recalculateTokenErrorDescription(request);
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

function refreshButtonClick() {
  log.debug("Entering refreshButtonClick().");
  log.debug("Entering refresh Submit button clicked function.");
  log.debug("Write values to local storage.");
  writeValuesToLocalStorage();
  log.debug("Recalculate refresh request description.");
  recalculateRefreshRequestDescription();
  log.debug("Reset error displays.");
  resetErrorDisplays();
  var formData = buildInternalRefreshAPIRequestMessage();
  if(useRefreshFrontEnd) {
    $.ajax({
      type: "POST",
      crossdomain: true,
      url: localStorage.getItem("token_endpoint"),
      data: convertToOAuth2Format(formData),
      contentType: "application/x-www-form-urlencoded",
      success: successfulInternalRefreshAPICall,
      error: errorInternalRefreshAPICall
    });
  } else {
    $.ajax({
      type: "POST",
      crossdomain: true,
      url: appconfig.apiUrl + "/token",
      data: JSON.stringify(formData),
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
                        'refresh');
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
   $("#refresh_endpoint_result").show();
  } else {
   $("#refresh_endpoint_result").hide();
  }
  populateRevocationTokenWithLatestAccessToken();
  populateTokenExchangeSubjectWithLatestAccessToken();
  log.debug("Leaving recreateRefreshTokenDisplay().");
  log.debug("Leaving recreateRefreshTokenDisplay().");
}

function errorInternalRefreshAPICall(request, status, error) {
  log.debug("Entering errorInternalRefreshAPICall().");
  log.error("An error occurred making a token refresh call to token endpoint.");
  log.error("request: " + JSON.stringify(request));
  log.error("status: " + JSON.stringify(status));
  log.error("error: " + JSON.stringify(error));
  recalculateRefreshErrorDescription(request);
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
      appconfig.uiUrl : "http://localhost:3000") + "/logout.html");
    if( value == "client_credential" &&
        getParameterByName("redirectFromTokenDetail") != "true")
    {
      $("#code").hide();
      $("#authzUsernameRow").hide();
      $("#authzPasswordRow").hide();
      $("#step2").hide();
      $("#step3").show();
      $("#token_grant_type").val("client_credentials");
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
      $("#h2_title_2").innerHTML = "Obtain Access Token";
      $("#token_endpoint_result").html("");
      $("#display_token_request").show();
      $("#usePKCE-yes").prop("checked", false);
      $("#usePKCE-no").prop("checked", true);
      usePKCERFC();
      $("#step5").hide();
      $("#step6").hide();
      $("#step7").hide();
      $("#operation-history-panel").hide();
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
      $("#step3").show();
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
      $("#step3").hide();
      recalculateTokenRequestDescription();
      recalculateRefreshRequestDescription();
    }
    if( value == "implicit_grant" &&
        getParameterByName("redirectFromTokenDetail") == "true")
    {
      $("#config_fieldset").hide();
      $("#config_expand_button").val("Expand");
      $("#step3").hide();
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
      $("#step3").show();
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
  // Match this deployment's origin (appconfig.uiUrl); heal a stale/empty/
  // cross-origin value persisted by an earlier build or a different origin.
  var redirectBase = (appconfig.uiUrl ?
      appconfig.uiUrl : "http://localhost:3000");
  var storedRedirectUri = localStorage.getItem("redirect_uri");
  if (!storedRedirectUri || storedRedirectUri.indexOf(redirectBase) !== 0) {
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
  $("#authorization_endpoint_result").show();
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

  // an error was returned from the authorization endpoint
  var errorDescriptionParam =
      DOMPurify.sanitize(getParameterByName('error_description'));
  var errorParam = DOMPurify.sanitize(getParameterByName('error'));
  log.debug('errorDescriptionParam=' + errorDescriptionParam + ', errorParam=' +
            errorParam);
  if (!!errorDescriptionParam || 
      !!errorParam) {
    $('#step0').hide();
    $('#step3').hide();
    $('#step4').hide();
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
  $("#code").val(getParameterByName('code'));
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
    $("#step4").show();
  } else {
    $("#step4").hide();
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
    $("#step3").hide();
    if (useRefreshTokenTester) {
      $("#step4").show();
    }
    recreateTokenDisplay();
    recreateRefreshTokenDisplay("", "", ""); // no new token
    $("#logout_id_token_hint").val(localStorage.getItem("token_id_token"));
    // Tokens already exist on this path, so show the panes that operate on
    // them (logout, revocation, token exchange) and the operation history.
    $("#step5").show();
    $("#step6").show();
    $("#step7").show();
    $("#operation-history-panel").show();
  }

  recalculateRefreshRequestDescription();

  $(".token_btn").click(tokenButtonClick);
  $(".refresh_btn").click(refreshButtonClick);

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
    if (fs) { fs.style.display = (fs.style.display === "none") ?
        "block" : "none"; }
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
    $('#step3').show();
    $('#token_fieldset').css('display', 'block');
    $('#token_expand_button').val('Collapse');
    $('#config_fieldset').css('display', 'block');
    $('#config_expand_button').val('Collapse');
    $('#step4').hide();
    $('#step5').hide();
    $('#step6').hide();
    $('#step7').hide();
    $('#operation-history-panel').hide();
    $('#token-history-panel').hide();
    $('#currently-viewing-panel').hide();
    $('#token_endpoint_result').hide();
    $('#refresh_endpoint_result').hide();
  }

  if ( $('#step3').is(':visible') &&
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
    $('#step3').show();
    $('#step4').show();
    $('#step5').show();
    $('#step6').show();
    $('#step7').show();
    $('#operation-history-panel').show();
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
    $('#operation-history-panel').show();
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
  var hash = window.location.hash.substr(1);

  var result = hash.split("&").reduce(function (result, item) {
      var parts = item.split("=");
      result[parts[0]] = parts[1];
      return result;
  }, {});
  log.debug("Leaving parseFragment().");
  return result;
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
    $("#step4").show();
  } else if(noCheck) {
    useRefreshTokenTester = false;
    $("#step4").hide();
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

function saveTokenSetToHistory(access_token, refresh_token, id_token, source) {
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
  history.push({
    timestamp: new Date().toISOString(),
    nonce: nonce,
    sid: sid,
    source: source || 'token',
    access_token: access_token || '',
    refresh_token: refresh_token || '',
    id_token: id_token || ''
  });
  localStorage.setItem('token_history', JSON.stringify(history));
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
  fillGeneratedFields('#currently-viewing-panel', {
    access: entry.access_token, refresh: entry.refresh_token,
        id: entry.id_token,
    nonce: entry.nonce, sid: entry.sid
  });
  $('#currently-viewing-panel').show();
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
    $("#token-history-panel").hide();
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
  $("#token-history-panel").show();
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

function onClickShowFieldSet(expand_button_id, field_set_id) {
  log.debug("Entering onClickShowFieldSet().");
  log.debug('Entering onClickShowConfigFieldSet(). expand_button_id='
    + expand_button_id + ', field_set_id=' + field_set_id
    + ', fieldset.style.display=' + $("#" + field_set_id).css("display")
    + ', expand_button.value=' + $("#" + expand_button_id).val());
  if($("#" + field_set_id).css("display") == 'block') {
    log.debug('Hide ' + field_set_id + '.');
    $("#" + field_set_id).css("display", "none");
    $("#" + expand_button_id).val("Expand");
  } else {
    log.debug('Show ' + field_set_id + '.');
    $("#" + field_set_id).css("display", "block");
    $("#" + expand_button_id).val("Collapse");
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
  $('#token-history-panel').hide();
  $('#currently-viewing-panel').hide();
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
  $("#step6").show();
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

module.exports = {
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
  setTokenExchangeType
};
