var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var $ = require("jquery");
var log = bunyan.createLogger({name: 'introspection', level: appconfig.logLevel});
log.info("Log initialized. logLevel=" + log.level());

var useFrontEnd = false;

const OPERATION_HISTORY_LIMIT = 1000;

// Decodes a JWT payload (no verification) so the session nonce can be read
// from an id_token. Mirrors the helper on the debugger2 page.
function decodeJwtPayload(token) {
  try {
    var parts = token.split('.');
    if (parts.length < 2) return null;
    var b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    var pad = '==='.slice(0, (4 - b64.length % 4) % 4);
    return JSON.parse(atob(b64 + pad));
  } catch (e) {
    return null;
  }
}

function getCurrentSessionNonce() {
  var idToken = localStorage.getItem('refresh_id_token') || localStorage.getItem('token_id_token');
  if (!!idToken) {
    var payload = decodeJwtPayload(idToken);
    if (payload && !!payload.nonce) return payload.nonce;
  }
  return localStorage.getItem('nonce_field') || '';
}

// Appends an entry to the shared operation history shown on the debugger2 page.
function recordOperation(operation, detail, client_id) {
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
    detail: detail || '',
    client_id: client_id || '',
    nonce: getCurrentSessionNonce(),
    tokenHistoryIndex: null
  });
  localStorage.setItem('operation_history', JSON.stringify(history));
}

function getParameterByName(name, url) {
  log.debug("Entering getParameterByName().");
  if (!url)
  {
    url = window.location.search;
  }
  var urlParams = new URLSearchParams(url);
  log.debug("Leaving getParameterByName().");
  return urlParams.get(name);
}

function callIntrospectionEndpoint() {
  log.debug("Entering callIntrospectionEndpoint().");

  var introspection_endpoint = document.getElementById("introspection_endpoint").value;
  var introspection_token = document.getElementById("introspection_token").value;
  var introspection_token_type_hint = document.getElementById("introspection_token_type_hint").value;
  var introspection_authentication_type = document.getElementById("introspection_authentication_type").value;
  var introspection_client_id = document.getElementById("introspection_client_id").value;
  var introspection_client_secret = document.getElementById("introspection_client_secret").value;
  var introspection_bearer_token = document.getElementById("introspection_bearer_token").value;

  var headers = {
        "Authorization": introspection_authentication_type == "basic_auth" ?
          "Basic " + btoa(introspection_client_id + ":" + introspection_client_secret) :
          "Bearer " + introspection_bearer_token,
        "Content-Type": "application/json"
  };
  var body = {
    token: introspection_token,
    token_type_hint: introspection_token_type_hint != "" ? introspection_token_type_hint : undefined,
  }
  var url_ = "";
  log.debug("Making introspection call. useFrontEnd=" + useFrontEnd);
  if(useFrontEnd) {
    url_ = introspection_endpoint;
  } else {
    url_ = appconfig.apiUrl + "/introspection";
    body["introspectionEndpoint"] = introspection_endpoint;
  }
  log.debug("Method: POST");
  log.debug("URL: " + url_);
  log.debug("crossDomainn: true");
  log.debug("body: " + JSON.stringify(body));
  log.debug("Headers: " + JSON.stringify(headers));
  $.ajax({
    type: "POST",
    url: url_,
    crossDomain: true,
    headers: headers,
    data: JSON.stringify(body),
    success: introspectionSuccess,
    error: introspectionError
  });
  recordOperation('Introspection Endpoint', introspection_token_type_hint || 'token', introspection_client_id);
  writeValuesToLocalStorage();
  log.debug("Entering callIntrospectionEndpoint().");
}

function introspectionError(request, status, error) {
  log.debug("request: " + JSON.stringify(request));
  log.debug("status: " + JSON.stringify(status));
  log.debug("error: " + JSON.stringify(error));
  try {
    var errorReport = {
      "request": request,
      "status": status,
      "error": error
    };
    $("#introspection_output").val(JSON.stringify(errorReport));
  } catch (e) {
    log.error("Error occurred while generating error report: " + e.stack);
    $("#introspection_output").val("Error occurred while generating error report: " + e.stack);
  }
}

function introspectionSuccess(data, textStatus, jqXHR) {
  log.debug('Entering ajax success function for Introspection Endpoint call.');
  log.debug('Introspection textStatus: ' + JSON.stringify(textStatus));
  log.debug('Introspection Endpoint Response: ' + JSON.stringify(data));
  log.debug('Introspection request: ' + JSON.stringify(jqXHR));
  log.debug('Introspection Response Content-Type: ' + jqXHR.getResponseHeader("Content-Type"));
  log.debug('Introspection Headers: ' + JSON.stringify(jqXHR.getAllResponseHeaders()));
  var responseContentType = jqXHR.getResponseHeader("Content-Type");
  if (responseContentType.includes('application/json')) {
    log.debug('plaintext response detected, no signature, no encryption');
    log.debug('Introspection Endpoint Response: ' + JSON.stringify(data, null, 2));
    $("#introspection_output").val(JSON.stringify(data,null,2));
  } else {
    log.error('Unknown response format.');
  }
  log.debug("Leaving ajax success function for Introspection Endpoint call.");
}

function loadValuesFromLocalStorage() {
  log.debug("Entering loadValuesFromLocalStorage().");
  if(localStorage) {
    document.getElementById("introspection_endpoint").value = localStorage.getItem("introspection_endpoint");

    const type = getParameterByName('type');
    if (type == 'access') {
      document.getElementById("introspection_token").value = localStorage.getItem("token_access_token");
      document.getElementById("introspection_token_type_hint").value = "access_token";
    } else if (type == 'refresh') {
      document.getElementById("introspection_token").value = localStorage.getItem("token_refresh_token");
      document.getElementById("introspection_token_type_hint").value = "refresh_token";
    } else if (type == 'refresh_access') {
      document.getElementById("introspection_token").value = localStorage.getItem("refresh_access_token");
      document.getElementById("introspection_token_type_hint").value = "access_token";
    } else if (type == 'refresh_refresh') {
      document.getElementById("introspection_token").value = localStorage.getItem("refresh_refresh_token");
      document.getElementById("introspection_token_type_hint").value = "refresh_token";
    } else if (type == 'history_access' || type == 'history_refresh' || type == 'history_id_token') {
      var generation = parseInt(getParameterByName('generation'), 10);
      var history = [];
      try {
        history = JSON.parse(localStorage.getItem('token_history') || '[]');
      } catch (e) {
        log.error('Failed to parse token_history: ' + e);
      }
      if (!isNaN(generation) && generation >= 0 && generation < history.length) {
        var entry = history[generation];
        if (type == 'history_access') {
          document.getElementById("introspection_token").value = entry.access_token || '';
          document.getElementById("introspection_token_type_hint").value = "access_token";
        } else if (type == 'history_refresh') {
          document.getElementById("introspection_token").value = entry.refresh_token || '';
          document.getElementById("introspection_token_type_hint").value = "refresh_token";
        } else if (type == 'history_id_token') {
          document.getElementById("introspection_token").value = entry.id_token || '';
          document.getElementById("introspection_token_type_hint").value = "";
        }
      } else {
        log.error('Invalid generation index: ' + generation);
      }
    } else {
      log.error('Unknown token type encountered.');
    }
  }

  document.getElementById("introspection_client_id").value = localStorage.getItem("introspection_client_id");
  document.getElementById("introspection_bearer_token").value = localStorage.getItem("introspection_bearer_token");
  $("#introspection_initiateFromFrontEnd").prop("checked", getLSBooleanItem("introspection_initiateFromFrontEnd"));
  $("#introspection_initiateFromBackEnd").prop("checked", getLSBooleanItem("introspection_initiateFromBackEnd"));
  log.debug("Leaving loadValuesFromLocalStorage().");
}

function writeValuesToLocalStorage() {
  log.debug("Entering writeValuesToLocalStorage().");
  if (localStorage) {
    localStorage.setItem("introspection_endpoint", document.getElementById("introspection_endpoint").value);
    localStorage.setItem("introspection_client_id", document.getElementById("introspection_client_id").value);
    localStorage.setItem("introspection_bearer_token", document.getElementById("introspection_bearer_token").value);
    localStorage.setItem("introspection_initiateFromFrontEnd", $("#introspection_initiateFromFrontEnd").is(":checked"));
    localStorage.setItem("introspection_initiateFromBackEnd", $("#introspection_initiateFromBackEnd").is(":checked"));
  }
  log.debug("Leaving writeValuesToLocalStorage().");
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

$(document).on("change", "#introspection_authentication_type", function() {
  if (this.value == "basic_auth") {
    $("#introspection_client_id").closest('tr').show();
    $("#introspection_client_secret").closest('tr').show();
    $("#introspection_bearer_token").closest('tr').hide();
  } else if (this.value == "bearer_token") {
    $("#introspection_client_id").closest('tr').hide();
    $("#introspection_client_secret").closest('tr').hide();
    $("#introspection_bearer_token").closest('tr').show();
  } else {
    log.error('Unknown authentication type encountered.');
  }
});

window.onload = function() {
  log.debug("Entering window.onload() function.");
  loadValuesFromLocalStorage();
  // Static build (appconfig.backendAvailable === false): no api backend, so
  // force the frontend and disable (gray out) the backend initiation option.
  if (appconfig.backendAvailable === false) {
    $("#introspection_initiateFromFrontEnd").prop("checked", true);
    $("#introspection_initiateFromBackEnd").prop("checked", false).prop("disabled", true);
  }
  $("#introspection_authentication_type").trigger("change");
  var frontEndInitiated = $("#introspection_initiateFromFrontEnd").is(":checked");
  if(frontEndInitiated) {
    useFrontEnd = true;
  } else {
    useFrontEnd = false;
  }
  log.debug("useFrontEnd=" + useFrontEnd + ", typeof(useFrontEnd)=" + typeof(useFrontEnd));
  log.debug("Leaving window.onload() function.");
}

function setInitiateFromEnd(which_end) {
  log.debug("Entering setInitiateFromEnd(). which_end=" + which_end);
  var frontEndInitiated = $("#introspection_initiateFromFrontEnd").is(":checked");
  var backEndInitiated = $("#introspection_initiateFromBackEnd").is(":checked");
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
  callIntrospectionEndpoint,
  onClickToggleConfigurationParameters,
  setInitiateFromEnd,
  clickLink
};
