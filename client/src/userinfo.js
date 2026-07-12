var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var $ = require("jquery");
var log = bunyan.createLogger({ name: 'userinfo',
                                level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());
const jwt = require('jsonwebtoken');
var initialized = false
var userinfo_endpoint = "";
var userinfo_scope = "";
var userinfo_method = "";
var userinfo_claims = "";
var token_access_token = "";
var query_string = "";

var useFrontEnd = false;

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

window.onload = function() 
{
  log.debug("Entering window.onload() function.");
  initLocalStorage();
  loadValuesFromLocalStorage();
  // Static build (appconfig.backendAvailable === false): no api backend, so
  // force the frontend and disable (gray out) the backend initiation option.
  if (appconfig.backendAvailable === false) {
    $("#userinfo_initiateFromFrontEnd").prop("checked", true);
    $("#userinfo_initiateFromBackEnd").prop("checked", false).prop("disabled", true);
  }
  resetErrorDisplays();
  var frontEndInitiated = $("#userinfo_initiateFromFrontEnd").is(":checked");
  if(frontEndInitiated) {
    useFrontEnd = true;
  } else {
    useFrontEnd = false;
  }
  log.debug("useFrontEnd=" + useFrontEnd + ", typeof(useFrontEnd)=" + typeof(useFrontEnd));
  recalculateUserInfoURL();
  log.debug("Leaving window.onload() function.");
}

function recalculateUserInfoURL()
{
  log.debug("Entering recalculateUserInfoURL() function.");
  if(!!userinfo_scope) {
    query_string = 'scope=' + userinfo_scope;
  }
  if(!!userinfo_claims) {
    query_string += '&claims=' + userinfo_claims;
  }
  query_string = encodeURI(query_string);
  log.debug("Leaving recalcualteUserInfoURL(): query_string=" + query_string);
}

function callUserInfoEndpoint()
{
  log.debug("Entering callUserInfoEndpoint().");
  var url_ = "";
  log.debug("Making Userinfo call. useFrontEnd=" + useFrontEnd);
  const headers = {
    "Authorization": 'Bearer ' + token_access_token,
  };
  if ( userinfo_method === "post" ) {
    headers["Content-Type"] = "application/json";
  }
  if(useFrontEnd) {
    url_ = userinfo_endpoint + "?" + query_string;
  } else {
    url_ = appconfig.apiUrl +
           "/userinfo?" +
           query_string +
           "&userinfo_endpoint=" +
           Buffer.from(userinfo_endpoint +
           "?" +
           query_string).toString('base64');
  }
  log.debug("url_: " + url_);
  $.ajax({
    type: userinfo_method,
    crossdomain: true,
    url: url_,
    headers: headers,
    success: ajaxSuccessFunction,
    error: ajaxErrorFunction
  });
  log.debug("Entering callUserInfoEndpoint().");
}

function ajaxSuccessFunction(data, textStatus, jqXHR) {
  log.debug('Entering ajax success function for Access Token call.');
  log.debug('UserInfo textStatus: ' + JSON.stringify(textStatus));
  log.debug('UserInfo Endpoint Response: ' + JSON.stringify(data));
  log.debug('UserInfo request: ' + JSON.stringify(jqXHR));
  log.debug('UserInfo Response Content-Type: ' + jqXHR.getResponseHeader("Content-Type"));
  log.debug('UserInfo Headers: ' + JSON.stringify(jqXHR.getAllResponseHeaders()));
  var responseContentType = jqXHR.getResponseHeader("Content-Type");
  if (responseContentType.includes('application/json')) {
    log.debug('plaintext response detected, no signature, no encryption');
    log.debug('UserInfo Endpoint Response: ' + JSON.stringify(data, null, 2));
    $("#userinfo_output").val(JSON.stringify(data,null,2));
  } else {
    log.error('Unknown response format.');
  }
}

function ajaxErrorFunction(request, status, error) {
  log.debug("request: " + JSON.stringify(request));
  log.debug("status: " + JSON.stringify(status));
  log.debug("error: " + JSON.stringify(error));
  const errorStatus = {
    request: request,
    status: status,
    error: error
  };
  $("#userinfo_output").val(JSON.stringify(errorStatus,null,2));
}

$(".userinfo_endpoint").keypress(function() {
  log.debug("Entering keypress().");
  localStorage.setItem("userinfo_endpoint", userinfo_endpoint);
});

$(".userinfo_method").keypress(function() {
  log.debug("Entering keypress()."); 
  localStorage.setItem("userinfo_method", userinfo_method);
});

$(".userinfo_scope").keypress(function() {
  log.debug("Entering keypress().");
  localStorage.setItem("userinfo_scope", userinfo_scope);
  recalculateUserInfoURL();
});

$(".userinfo_claims").keypress(function() {
  log.debug("Entering keypress().");
  localStorage.setItem("userinfo_claims", userinfo_claims);
  recalculateUserInfoURL(); 
});

$(".token_access_token").keypress(function() {
  log.debug("Entering keypress().");
  localStorage.setItem("token_access_token", token_access_token);
});

function resetUI(value)
{
  log.debug("Entering resetUI().");
}

function resetErrorDisplays()
{
  log.debug("Entering resetErrorDisplays().");
  log.debug("Leaving resetErrorDisplays().");
}

function writeValuesToLocalStorage()
{
  log.debug("Entering writeValuesToLocalStorage().");
  if (localStorage) {
    localStorage.setItem("userinfo_endpoint", userinfo_endpoint);
    localStorage.setItem("userinfo_method", userinfo_method);
    localStorage.setItem("userinfo_scope", userinfo_scope);
    localStorage.setItem("userinfo_claims", userinfo_claims);
    localStorage.setItem("token_access_token", token_access_token);
  }
  log.debug("Leaving writeValuesToLocalStorage().");
}

function initLocalStorage()
{
  log.debug("Entering initLocalStorage().");
  if(localStorage && !initialized) {
    localStorage.setItem("userinfo_method", "GET");
    localStorage.setItem("userinfo_scope", "profile email address phone");
    var default_claims = {
     "userinfo":
      {
       "given_name": {"essential": true},
       "nickname": null,
       "email": {"essential": true},
       "email_verified": {"essential": true},
       "picture": null,
       "http://example.info/claims/groups": null
      },
     "id_token":
      {
       "auth_time": {"essential": true},
       "acr": {"values": ["urn:mace:incommon:iap:silver"] }
      }
    };
    localStorage.setItem("userinfo_claims", JSON.stringify(default_claims, null, 2));
    initialized = true;
  }
  log.debug("Leaving initLocalStorage().");
}

function loadValuesFromLocalStorage()
{
  log.debug("Entering loadValuesFromLocalStorage().");
  if(localStorage) {
    userinfo_endpoint = localStorage.getItem("oidc_userinfo_endpoint");
    userinfo_method = localStorage.getItem("userinfo_method");
    userinfo_scope = localStorage.getItem("userinfo_scope");
    userinfo_claims = localStorage.getItem("userinfo_claims");
    var type = getParameterByName('type');
    if (type === 'history_access') {
      var generation = parseInt(getParameterByName('generation'), 10);
      var history = [];
      try {
        history = JSON.parse(localStorage.getItem('token_history') || '[]');
      } catch (e) {
        log.error('Failed to parse token_history: ' + e);
      }
      if (!isNaN(generation) && generation >= 0 && generation < history.length) {
        token_access_token = history[generation].access_token || '';
      } else {
        log.error('Invalid generation index: ' + generation);
        token_access_token = '';
      }
    } else if (type === 'refresh_access_token') {
      token_access_token = localStorage.getItem('refresh_access_token');
    } else {
      token_access_token = localStorage.getItem("token_access_token");
    }
  }
  // Set configuration fields
  document.getElementById("userinfo_endpoint").value = userinfo_endpoint;
  document.getElementById("userinfo_method").value = userinfo_method;
  document.getElementById("userinfo_scope").value = userinfo_scope;
  document.getElementById("userinfo_claims").value = userinfo_claims;
  document.getElementById("token_access_token").value = token_access_token;
  log.debug("Leaving loadValuesFromLocalStorage().");
}

function regenerateState() {
  log.debug("Entering regenerateState().");
  document.getElementById("state").value = generateUUID();
  localStorage.setItem('state', document.getElementById("state").value);
  log.debug("Leaving regenerateState().");
}

function onClickToggleConfigurationParameters() {
  log.debug("Entering onClickToggleConfigurationParameters().");
  if(document.getElementById("config_fieldset").style.display == 'block') {
    document.getElementById('config_fieldset').style.display = 'none'
  } else {
    document.getElementById('config_fieldset').style.display = 'block'
  }
  log.debug("Leaving onClickToggleConfigurationParameters().");
}

function setInitiateFromEnd(which_end) {
  log.debug("Entering setInitiateFromEnd(). which_end=" + which_end);
  var frontEndInitiated = $("#userinfo_initiateFromFrontEnd").is(":checked");
  var backEndInitiated = $("#userinfo_initiateFromBackEnd").is(":checked");
  log.debug("typeof(frontEndInitiated): " + typeof(frontEndInitiated));
  if(frontEndInitiated) {
    useFrontEnd = true;
  } else {
    useFrontEnd = false;
  }
  log.debug("frontEndInitiated: " + frontEndInitiated);
  log.debug("backEndInitiated: " + backEndInitiated);
  log.debug("Leaving setInitiateFromEnd().");
}

function getLSBooleanItem(key)
{
  return localStorage.getItem(key) === 'true';
}

function clickLink() {
  log.debug("Entering clickLink().");
  writeValuesToLocalStorage();
  log.debug("Leaving clickLink().");
  return true;
}

module.exports = {
  getParameterByName,
  callUserInfoEndpoint,
  onClickToggleConfigurationParameters,
  setInitiateFromEnd,
  clickLink
};
