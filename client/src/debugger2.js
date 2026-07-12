const appconfig = require(process.env.CONFIG_FILE);
const bunyan = require("bunyan");
const DOMPurify = require("dompurify");
const $ = require("jquery");
const log = bunyan.createLogger({ name: 'debugger2',
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
  return urlParams.get(name);
}

function logoutButtonClick()  {
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
  var logoutUrl = DOMPurify.sanitize($("#logout_end_session_endpoint").val()) + "?" + DOMPurify.sanitize(queryString);

  clearLocalStorage();
  window.location.href = logoutUrl;

  return false;
};

function tokenButtonClick() {
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
    log.debug("Using frontend to call Token Endpoint. formData=" + JSON.stringify(formData));
    $.ajax({
      type: "POST",
      crossdomain: true,
      url: localStorage.getItem("token_endpoint"),
      data: convertToOAuth2Format(formData),
      contentType: "application/x-www-form-urlencoded",
      success: successfulInternalTokenAPICall,
      error: errorInternalTokenAPICall
    });
  } else {
    log.debug("Using backend to call Token Endpoint. formData=" + JSON.stringify(formData));
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
  return false; // don't reload the page.
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
          sslValidate: sslValidate
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
  var tokencustomParametersCheck = $("#customTokenParametersCheck-yes").is(":checked");
  log.debug("customTokenParametersCheck: " + tokencustomParametersCheck + ", type=" + typeof(tokencustomParametersCheck));
  if(tokencustomParametersCheck) 
  {
    formData.customParams = {};
    const numberCustomParameters = parseInt($("#tokenNumberCustomParameters").val());
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
  log.debug("Entering ajax success function for Access Token call: data=" 
          + JSON.stringify(data)
          + ", textStatus="
          + textStatus
          + ", request=" 
          + JSON.stringify(request));
  var token_endpoint_result_html = "";
  if (!!data.refresh_token && 
      data.refresh_token != 'undefined') {
    currentRefreshToken = data.refresh_token;
  }
  if (!!data.id_token && 
      data.id_token != 'undefined'){
    $("#logout_id_token_hint").val(data.id_token);
  }
  log.debug("displayOpenIDConnectArtifacts=" + displayOpenIDConnectArtifacts);
  if(displayOpenIDConnectArtifacts == true)
  {
    // Display OAuth2/OIDC Artifacts
    token_endpoint_result_html = "<fieldset>" +
                                 "<legend>Token Endpoint Results:</legend>" +
                                 "<p><em>Most recent results of the OAuth2 Grant or OIDC Authentication Flow call.</em></p>" +
				   "<table>" +
				     "<tr>" +
                                       '<td>' +
                                         '<P><a href="/token_detail.html?type=access" onclick="debugger2.clickLink()">Access Token</a></P>' +
                                         '<P style="font-size:50%;"><a href="/introspection.html?type=access" onclick="debugger2.clickLink()">Introspect Token</a></P>' +
                                         '<P><input class="btn2 revoke_token_btn" type="button" value="Revoke Token" data-revoke-type="access" /></P>' + 
                                         '<P><form><input class="btn2" type="submit" value="Copy Token"' +
                                         ' onclick="return debugger2.onClickCopyToken(\'#token_access_token\');"/></form></P>' +
                                       '</td>' +
                                       '<td>' +
                                         "<textarea rows=5 cols=60 readonly name=token_access_token id=token_access_token>" + 
                                           data.access_token + 
                                         "</textarea>" +
                                       '</td>' +
                                     '</tr>';
    if(useRefreshTokenTester) {
      token_endpoint_result_html +=  '<tr>' +
                                          '<td>' +
                                              '<P><a href="/token_detail.html?type=refresh" onclick="debugger2.clickLink()">Refresh Token</a></P>' +
                                              '<P style="font-size:50%;"><a href="/introspection.html?type=refresh" onclick="debugger2.clickLink()">Introspect Token</a></P>' +
                                         '<P><input class="btn2 revoke_token_btn" type="button" value="Revoke Token" data-revoke-type="refresh" /></P>' +
                                              '<P><form><input class="btn2" type="submit" value="Copy Token"' + 
                                              ' onclick="return debugger2.onClickCopyToken(\'#token_refresh_token\');"/></form></P>' +
                                          '</td>' +
                                          '<td>' +
                                              '<textarea rows=5 cols=60 readonly name=token_refresh_token id=token_refresh_token>' + 
                                              currentRefreshToken +
                                              "</textarea>" +
                                          "</td>" +
                                        "</tr>";
      }
      token_endpoint_result_html +=  "<tr>" +
                                          '<td>' +
                                            '<P><a href="/token_detail.html?type=id" onclick="debugger2.clickLink()">ID Token</a></P>' +
                                            '<P style="font-size:50%;">Get <a href="/userinfo.html?type=token_access_token" onclick="debugger2.clickLink()">UserInfo Data</a></P>' +
                                            '<P><form><input class="token_btn" type="submit" value="Copy Token"' + 
                                            ' onclick="return debugger2.onClickCopyToken(\'#token_id_token\');"/></form></P>' +
                                          '</td>' +
                                          '<td>' +
                                            '<textarea rows=5 cols=60 readonly name=token_id_token id=token_id_token>' + 
                                            data.id_token + 
                                            "</textarea>" +
                                          '</td>' +
                                        "</tr>" +
                                      "</table>" +
                                      "</fieldset>";
      localStorage.setItem("token_access_token", data.access_token);
      localStorage.setItem("token_refresh_token", data.refresh_token);
      localStorage.setItem("token_id_token", data.id_token);
      saveTokenSetToHistory(data.access_token, data.refresh_token, data.id_token, 'token');
    } else {
      log.debug("Displaying Access Token. No OIDC ID Token: data.access_token=" + data.access_token);
      token_endpoint_result_html = "<fieldset>" +
                                      "<legend>Token Endpoint Results:</legend>" +
                                 "<p><em>Most recent results of the OAuth2 Grant or OIDC Authentication Flow call.</em></p>" +
                                      "<table>" +
                                        "<tr>" +
                                          '<td>' +
                                            '<p><a href="/token_detail.html?type=access" onclick="debugger2.clickLink()">Access Token</a></p>' +
                                            '<P><input class="btn2 revoke_token_btn" type="button" value="Revoke Token" data-revoke-type="access" /></P>' +
                                            '<P><form><input class="btn2" type="submit" value="Copy Token"' +
                                            ' onclick="return debugger2.onClickCopyToken(\'#token_access_token\');"/></form></P>' +
                                          '</td>' +
                                          "<td><textarea rows=5 cols=60 readonly name=token_access_token id=token_access_token>" +
                                            data.access_token +
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>";
      if(useRefreshTokenTester) {
        log.debug("Refresh token found. Generating token: data.refresh_token=" + currentRefreshToken);
        token_endpoint_result_html += "<tr>" +
                                          '<td>' +
                                            '<a href="/token_detail.html?type=id" onclick="debugger2.clickLink()">Refresh Token</a>' +
                                            '<P><input class="btn2 revoke_token_btn" type="button" value="Revoke Token" data-revoke-type="refresh" /></P>' +
                                            '<P><form><input class="btn2" type="submit" value="Copy Token"' +
                                            ' onclick="return debugger2.onClickCopyToken(\'#token_refresh_token\');"/></form></P>' +
                                          '</td>' +
                                          "<td><textarea rows=5 cols=60 readonly name=token_refresh_token id=token_refresh_token>" +
                                           currentRefreshToken +
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>";
      }
      token_endpoint_result_html += "</table>" +
                                    "</fieldset>";
      localStorage.setItem("token_access_token", data.access_token);
      localStorage.setItem("token_refresh_token", data.refresh_token);
      saveTokenSetToHistory(data.access_token, data.refresh_token, null, 'token');
    }
    //$("#token_endpoint_result").html(DOMPurify.sanitize(token_endpoint_result_html));
    $("#token_endpoint_result").html(token_endpoint_result_html);
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
}

function errorInternalTokenAPICall(request, status, error) {
  log.error("An error occurred calling the token endpoint.");
  log.error("request: " + JSON.stringify(request));
  log.error("status: " + JSON.stringify(status));
  log.error("error: " + JSON.stringify(error));
  recalculateTokenErrorDescription(request);
  saveOperationToHistory('Token Endpoint', {
    client_id: $("#token_client_id").val(),
    detail: 'error'
  });
}

function buildInternalRefreshAPIRequestMessage() {
  log.debug("Entering buildInternalTokenAPIRequestMessage()."); 
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
  log.debug("Leaving buildInternalTokenAPIRequestMessage().");
  return formData;
}

function refreshButtonClick() {
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
  return false;
}

function successfulInternalRefreshAPICall(data, textStatus, request) {
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
  saveTokenSetToHistory(currentAccessToken, currentRefreshToken, currentIDToken, 'refresh');
  recreateRefreshTokenDisplay(currentRefreshToken, currentAccessToken, currentIDToken);
  saveOperationToHistory('Token Endpoint (Refresh)', {
    client_id: $("#refresh_client_id").val(),
    tokenHistoryIndex: getLatestTokenHistoryIndex()
  });
  log.debug("Leaving ajax success function for Refresh Token.");
}

function recreateRefreshTokenDisplay(currentRefreshToken, currentAccessToken, currentIDToken) {
  log.debug("Entering displayRefreshTokenPane().");
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
  refresh_endpoint_result_html = "<fieldset>" +
                                      "<legend>Token Endpoint Results for Refresh Token Call:</legend>" +
                                      "<p><em>Most recent results of the Refresh Token call.</em></p>" +
				      "<table>" +
				        "<tr>" +
                                          '<td>' +
                                            '<P><a href="/token_detail.html?type=refresh_access" onclick="debugger2.clickLink()">Latest Access Token</a></P>' +
                                            '<P style="font-size:50%;"><a href="/introspection.html?type=refresh_access" onclick="debugger2.clickLink()">Introspect Token</a></P>' +
                                            '<P><input class="btn2 revoke_token_btn" type="button" value="Revoke Token" data-revoke-type="refresh_access" /></P>' +
                                            '<P><form><input class="btn2" type="submit" value="Copy Token"' +
                                            ' onclick="return debugger2.onClickCopyToken(\'#refresh_access_token\');"/></form></P>' +
                                          "</td>" +
                                          "<td>" + 
                                            "<textarea rows=5 cols=60 readonly name=refresh_access_token id=refresh_access_token>" + 
                                              currentAccessToken + 
                                            "</textarea>" +
                                          "</td>" +
                                       "</tr>"; 
  if(!!currentRefreshToken) {
    refresh_endpoint_result_html +=     "<tr>" +
                                          '<td>' +
                                            '<P><a href="/token_detail.html?type=refresh_refresh" onclick="debugger2.clickLink()">Latest Refresh Token</a></P>' +
                                            '<P style="font-size:50%;"><a href="/introspection.html?type=refresh_refresh" onclick="debugger2.clickLink()">Introspect Token</a></P>' +
                                            '<P><input class="btn2 revoke_token_btn" type="button" value="Revoke Token" data-revoke-type="refresh_refresh" /></P>' +
                                            '<P><form><input class="btn2" type="submit" value="Copy Token"' +
                                            ' onclick="return debugger2.onClickCopyToken(\'#refresh_refresh_token\');"/></form></P>' +
                                          "</td>" +
                                          "<td><textarea rows=5 cols=60 readonly name=refresh_refresh_token id=refresh_refresh_token>" + 
                                              currentRefreshToken +
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>";
  }
  if(displayOpenIDConnectArtifacts) {
    refresh_endpoint_result_html +=      "<tr>" +
                                          '<td>' +
                                            '<P><a href="/token_detail.html?type=refresh_id" onclick="debugger2.clickLink()">Latest ID Token</a></P>' +
                                            '<P style="font-size:50%;">Get <a href="/userinfo.html?type=refresh_access_token" onclick="debugger2.clickLink()">UserInfo Data</a></P>' +
                                            '<P><form><input class="btn2" type="submit" value="Copy Token"' +
                                            ' onclick="return debugger2.onClickCopyToken(\'#refresh_id_token\');"/></form></P>' +
                                          "</td>" +
                                          "<td>" +
                                            "<textarea rows=5 cols=60 readonly name=refresh_id_token id=refresh_id_token>" + 
                                              currentIDToken +
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>";
  }
  refresh_endpoint_result_html +=        "<tr>" +
					  "<td>iteration</td>" +
					  "<td>" +
                                            '<input type="text" readonly value="' + iteration +
                                            '" id="refresh-token-results-iteration-count" name="refresh-token-results-iteration-count">'
                                          "</td>" +
                                        "</tr>" +
                                      "</table>" +
                                      "</fieldset>";
  //$("#refresh_endpoint_result").html(DOMPurify.sanitize(refresh_endpoint_result_html));
  $("#refresh_endpoint_result").html(refresh_endpoint_result_html);
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
  log.debug("Leaving displayRefreshTokenPane().");
}

function errorInternalRefreshAPICall(request, status, error) {
  log.error("An error occurred making a token refresh call to token endpoint.");
  log.error("request: " + JSON.stringify(request));
  log.error("status: " + JSON.stringify(status));
  log.error("error: " + JSON.stringify(error));
  recalculateRefreshErrorDescription(request);
  saveOperationToHistory('Token Endpoint (Refresh)', {
    client_id: $("#refresh_client_id").val(),
    detail: 'error'
  });
}

function resetUI(value)
{
    log.debug("Entering resetUI().");
    $("#logout_post_redirect_uri").val((appconfig.uiUrl ? appconfig.uiUrl : "http://localhost:3000") + "/logout.html");
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
      $("#authorization_endpoint_id_token_result").html("");
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
      // response stored by debugger.js.
      $("#deviceUserCodeRow").show();
      $("#deviceVerificationUriRow").show();
      $("#deviceVerificationUriCompleteRow").show();
      $("#deviceCodeRow").show();
      $("#device_code").val(localStorage.getItem("device_code"));
      $("#device_user_code").val(localStorage.getItem("user_code"));
      $("#device_verification_uri").val(localStorage.getItem("verification_uri"));
      $("#device_verification_uri_complete").val(localStorage.getItem("verification_uri_complete"));
      $("#step2").hide();
      $("#step3").show();
      $("#token_grant_type").val("urn:ietf:params:oauth:grant-type:device_code");
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
      localStorage.setItem("token_client_secret", $("#token_client_secret").val());
      localStorage.setItem("token_redirect_uri", $("#token_redirect_uri").val());
      localStorage.setItem("token_username", $("#token_username").val());
      localStorage.setItem("token_scope", $("#token_scope").val());
      localStorage.setItem("authorization_grant_type", $("#authorization_grant_type").val());
      localStorage.setItem("token_resource", $("#token_resource").val());
      localStorage.setItem("yesResourceCheckToken", $("#yesResourceCheckToken").is(":checked"));
      localStorage.setItem("noResourceCheckToken", $("#noResourceCheckToken").is(":checked"));
      localStorage.setItem("yesCheckOIDCArtifacts", $("#yesCheckOIDCArtifacts").is(":checked"));
      localStorage.setItem("noCheckOIDCArtifacts", $("#noCheckOIDCArtifacts").is(":checked"));
      localStorage.setItem("yesCheck", $("#SSLValidate-yes").is(":checked"));
      localStorage.setItem("noCheck", $("#SSLValidate-no").is(":checked"));
      localStorage.setItem("refresh_client_id", $("#refresh_client_id").val());
      localStorage.setItem("refresh_client_secret", $("#refresh_client_secret").val());
      localStorage.setItem("refresh_scope", $("#refresh_scope").val());
      localStorage.setItem("refresh_refresh_token", $("#refresh_refresh_token").val());
      localStorage.setItem("useRefreshToken_yes", $("#useRefreshToken-yes").is(":checked"));
      localStorage.setItem("useRefreshToken_no", $("#useRefreshToken-no").is(":checked"));
      localStorage.setItem("oidc_userinfo_endpoint", $("#oidc_userinfo_endpoint").val());
      localStorage.setItem("jwks_endpoint", $("#jwks_endpoint").val());
      localStorage.setItem("end_session_endpoint", $("#logout_end_session_endpoint").val());
      localStorage.setItem("logout_client_id", $("#logout_client_id").val());
      localStorage.setItem("customTokenParametersCheck-yes", $("#customTokenParametersCheck-yes").is(":checked"));
      localStorage.setItem("customTokenParametersCheck-no", $("#customTokenParametersCheck-no").is(":checked"));
      localStorage.setItem("tokenNumberCustomParameters", $("#tokenNumberCustomParameters").val());
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
      localStorage.setItem("tokenexchange_initiateFromFrontEnd", $("#tokenexchange_initiateFromFrontEnd").is(":checked"));
      localStorage.setItem("tokenexchange_initiateFromBackEnd", $("#tokenexchange_initiateFromBackEnd").is(":checked"));
      if ($("#customTokenParametersCheck-yes").is(":checked")) {
        var i = 0;
        var tokenNumberCustomParameters = parseInt($("#tokenNumberCustomParameters").val());
        for(i = 0; i < tokenNumberCustomParameters; i++)
        {
          log.debug("Writing customTokenParameterName-" + i + " as " + $("#customTokenParameterName-" + i).val() + "\n");
          localStorage.setItem("customTokenParameterName-" + i, $("#customTokenParameterName-" + i).val());
          log.debug("Writing customTokenParameterValue-" + i + " as " + $("#customTokenParameterValue-" + i).val() + "\n");
          localStorage.setItem("customTokenParameterValue-" + i, $("#customTokenParameterValue-" + i).val());
        }
      }
      localStorage.setItem("PKCE_code_challenge",$("#token_pkce_code_challenge").val());
      localStorage.setItem("PKCE_code_challenge_method", $("#token_pkce_code_method").val());
      localStorage.setItem("PKCE_code_verifier", $("#token_pkce_code_verifier").val() );
      localStorage.setItem("usePKCE_yes", $("#usePKCE-yes").is(":checked"));
      localStorage.setItem("usePKCE_no", $("#usePKCE-no").is(":checked"));
      localStorage.setItem("token_initiateFromFrontEnd", $("#token_initiateFromFrontEnd").is(":checked"));
      localStorage.setItem("token_initiateFromBackEnd", $("#token_initiateFromBackEnd").is(":checked"));
      localStorage.setItem("refresh_initiateFromFrontEnd", $("#refresh_initiateFromFrontEnd").is(":checked"));
      localStorage.setItem("refresh_initiateFromBackEnd", $("#refresh_initiateFromBackEnd").is(":checked"));
      localStorage.setItem("refresh_token_used", refreshTokenUsed);
      if (!!$("#revocation_revocation_endpoint").val()) {
        localStorage.setItem("revocation_endpoint", $("#revocation_revocation_endpoint").val());
      }
      if (!!$("#registration_endpoint").val()) {
        localStorage.setItem("registration_endpoint", $("#registration_endpoint").val());
      }
      localStorage.setItem("revocation_initiateFromFrontEnd", $("#revocation_initiateFromFrontEnd").is(":checked"));
      localStorage.setItem("revocation_initiateFromBackEnd", $("#revocation_initiateFromBackEnd").is(":checked"));
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
}

function loadValuesFromLocalStorage()
{
  log.debug("Entering loadValuesFromLocalStorage().");

  setAuthorizationGrantType();

  $("#authorization_endpoint").val(localStorage.getItem("authorization_endpoint"));
  $("#token_endpoint").val(localStorage.getItem("token_endpoint"));

  if (localStorage.getItem("introspection_endpoint")) {
    $("#introspection_endpoint").val(localStorage.getItem("introspection_endpoint"));
    $("#introspection_endpoint").closest('tr').show();
  } else {
    $("#introspection_endpoint").val("");
    $("#introspection_endpoint").closest('tr').hide();
  }

  if (!!localStorage.getItem("revocation_endpoint")) {
    $("#revocation_endpoint").val(localStorage.getItem("revocation_endpoint"));
    $("#revocation_endpoint").closest('tr').show();
    $("#revocation_revocation_endpoint").val(localStorage.getItem("revocation_endpoint"));
  } else {
    $("#revocation_endpoint").val("");
    $("#revocation_endpoint").closest('tr').hide();
  }

  if (!!localStorage.getItem("registration_endpoint")) {
    $("#registration_endpoint").val(localStorage.getItem("registration_endpoint"));
    $("#registration_endpoint").closest('tr').show();
  } else {
    $("#registration_endpoint").val("");
    $("#registration_endpoint").closest('tr').hide();
  }

  if (!!localStorage.getItem("device_authorization_endpoint")) {
    $("#device_authorization_endpoint").val(localStorage.getItem("device_authorization_endpoint"));
    $("#device_authorization_endpoint").closest('tr').show();
  } else {
    $("#device_authorization_endpoint").val("");
    $("#device_authorization_endpoint").closest('tr').hide();
  }
  $("#revocation_client_id").val(localStorage.getItem("client_id"));
  $("#revocation_client_secret").val(localStorage.getItem("client_secret"));
  if (localStorage.getItem("revocation_initiateFromFrontEnd") !== null) {
    $("#revocation_initiateFromFrontEnd").prop("checked", getLSBooleanItem("revocation_initiateFromFrontEnd"));
    $("#revocation_initiateFromBackEnd").prop("checked", getLSBooleanItem("revocation_initiateFromBackEnd"));
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
  $("#tokenexchange_token_endpoint").val(localStorage.getItem("token_endpoint"));
  $("#tokenexchange_client_id").val(localStorage.getItem("client_id"));
  $("#tokenexchange_client_secret").val(localStorage.getItem("client_secret"));
  if (localStorage.getItem("tokenexchange_initiateFromFrontEnd") !== null) {
    $("#tokenexchange_initiateFromFrontEnd").prop("checked", getLSBooleanItem("tokenexchange_initiateFromFrontEnd"));
    $("#tokenexchange_initiateFromBackEnd").prop("checked", getLSBooleanItem("tokenexchange_initiateFromBackEnd"));
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
  var redirectBase = (appconfig.uiUrl ? appconfig.uiUrl : "http://localhost:3000");
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
  $("#yesResourceCheckToken").prop("checked", getLSBooleanItem("yesResourceCheckToken"));
  $("#noResourceCheckToken").prop("checked", getLSBooleanItem("noResourceCheckToken"));
  $("#yesCheckOIDCArtifacts").prop("checked", getLSBooleanItem("yesCheckOIDCArtifacts"));
  $("#noCheckOIDCArtifacts").prop("checked", getLSBooleanItem("noCheckOIDCArtifacts"));
  $("#usePKCE-yes").prop("checked", getLSBooleanItem("usePKCE_yes"));
  $("#usePKCE-no").prop("checked", getLSBooleanItem("usePKCE_no"));
  // Default to the "Back" radio when nothing has been stored yet, so a radio
  // is always selected on first load (otherwise both would be left unchecked).
  if (localStorage.getItem("token_initiateFromFrontEnd") !== null ||
      localStorage.getItem("token_initiateFromBackEnd") !== null) {
    $("#token_initiateFromFrontEnd").prop("checked", getLSBooleanItem("token_initiateFromFrontEnd"));
    $("#token_initiateFromBackEnd").prop("checked", getLSBooleanItem("token_initiateFromBackEnd"));
  } else {
    $("#token_initiateFromFrontEnd").prop("checked", false);
    $("#token_initiateFromBackEnd").prop("checked", true);
  }
  if (localStorage.getItem("refresh_initiateFromFrontEnd") !== null ||
      localStorage.getItem("refresh_initiateFromBackEnd") !== null) {
    $("#refresh_initiateFromFrontEnd").prop("checked", getLSBooleanItem("refresh_initiateFromFrontEnd"));
    $("#refresh_initiateFromBackEnd").prop("checked", getLSBooleanItem("refresh_initiateFromBackEnd"));
  } else {
    $("#refresh_initiateFromFrontEnd").prop("checked", false);
    $("#refresh_initiateFromBackEnd").prop("checked", true);
  }

  $("#refresh_refresh_token").val(localStorage.getItem("refresh_refresh_token"));
  $("#customTokenParametersCheck-no").prop("checked", getLSBooleanItem("customTokenParametersCheck-no"));$("#refresh_client_id").val(localStorage.getItem("refresh_client_id"));
  $("#refresh_scope").val(localStorage.getItem("refresh_scope"));
  $("#refresh_client_secret").val(localStorage.getItem("refresh_client_secret"));
  $("#useRefreshToken-yes").prop("checked", getLSBooleanItem("useRefreshToken_yes"));
  $("#useRefreshToken-no").prop("checked", getLSBooleanItem("useRefreshToken_no"));
  $("#oidc_userinfo_endpoint").val(localStorage.getItem("oidc_userinfo_endpoint"));
  $("#jwks_endpoint").val(localStorage.getItem("jwks_endpoint"));
  $("#logout_end_session_endpoint").val(localStorage.getItem("end_session_endpoint"));
  $("#logout_client_id").val(localStorage.getItem("client_id"));
  $("#customTokenParametersCheck-yes").prop("checked", getLSBooleanItem("customTokenParametersCheck-yes"));
  $("#customTokenParametersCheck-no").prop("checked", getLSBooleanItem("customTokenParametersCheck-no"));
  $("#tokenNumberCustomParameters").val(localStorage.getItem("tokenNumberCustomParameters")? localStorage.getItem("tokenNumberCustomParameters"): 1);
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
    var tokenNumberCustomParameters = parseInt($("#tokenNumberCustomParameters").val());
    for(i = 0; i < tokenNumberCustomParameters; i++)
    {
      log.debug("Reading customTokenParameterName-" + i + " as " + localStorage.getItem("customTokenParameterName-" + i + "\n"));
      $("#customTokenParameterName-" + i).val(localStorage.getItem("customTokenParameterName-" + i));
      log.debug("Reading customTokenParameterValue-" + i + " as " + localStorage.getItem("customTokenParameterValue-" + i + "\n"));
      $("#customTokenParameterValue-" + i).val(localStorage.getItem("customTokenParameterValue-" + i));
    }
  }

  if ($("#usePKCE-yes").is(":checked")) {
    $("#token_pkce_code_challenge").val(localStorage.getItem("PKCE_code_challenge"));
    $("#token_pkce_code_verifier").val(localStorage.getItem("PKCE_code_verifier"));
    $("#token_pkce_code_method").val(localStorage.getItem("PKCE_code_challenge_method"));
  }
  usePKCERFC();
  refreshTokenUsed=getLSBooleanItem("refresh_token_used");
  renderTokenHistory();
  var savedActiveIndex = parseInt(localStorage.getItem('token_history_active_index'));
  if (!isNaN(savedActiveIndex)) {
    var cvHistory = [];
    try { cvHistory = JSON.parse(localStorage.getItem('token_history') || '[]'); } catch(e) {}
    if (savedActiveIndex >= 0 && savedActiveIndex < cvHistory.length) {
      renderCurrentlyViewing(savedActiveIndex, cvHistory[savedActiveIndex]);
    }
  }
  log.debug("Leaving loadValuesFromLocalStorage().");
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
	pathname == "/debugger2.html")
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
  if ( agt == "implicit_grant" || 
       agt == "oidc_implicit_flow")
  {
    log.debug("Looking for access_token.");
    var access_token = getParameterByName("access_token",window.location.href);
    log.debug("access_token=" + access_token);
    if(!!!access_token)
    {
      //Check to see if passed in as local anchor (ADFS & Azure Active Directory do this)
      log.debug("Didn't find token in query parameter. Looking in fragment.");
      log.debug("fragement: " + parseFragment());
      access_token = parseFragment()["access_token"];
      if(!!!access_token)
      {
        log.debug("Didn't find token in fragment. Checking to see if there is a saved token in local storage.");
        access_token = localStorage.getItem("token_access_token");
        if(!!!access_token)
        {
          log.debug("Didn't find token in local storage. No access_token found.");
          access_token = "NO_ACCESS_TOKEN_PRESENTED_IN_EXPECTED_LOCATIONS(IMPLICIT_GRANT||OIDC_IMPLICIT_FLOW)";
        } else {
          log.debug("Found access_token in local storage.");
        }
      } else {
        log.debug("Found token in fragment.");
      } 
    } else {
     log.debug("Found token in query parameter.");
    } 
    var authorization_endpoint_result_html = "<fieldset>" +
                                             "<legend>Authorization Endpoint Results:</legend>" +
                                             "<table>" + 
                                               "<tr>" +
                                                 "<td>" +
                                                   '<P><a href="/token_detail.html?type=access" onclick="debugger2.clickLink()">Access Token</a></P>' +
                                                   '<P style="font-size:50%;"><a href="/introspection.html?type=access" onclick="debugger2.clickLink()">Introspect Token</a></P>' +
                                         '<P><input class="btn2 revoke_token_btn" type="button" value="Revoke Token" data-revoke-type="access" /></P>' +
                                                   '<P><form><input class="token_btn" type="submit" value="Copy Token"' +
                                                   ' onclick="return debugger2.onClickCopyToken(\'#token_access_token\');"/></form></P>' +
                                                 "</td>" +
                                                 "<td><textarea rows=5 cols=60 name=\"token_access_token\" id=\"token_access_token\">" +
                                                     access_token +
                                                   "</textarea>" +
                                                 "</td>" +
                                               "</tr>" + 
                                             "</table>" +
                                             "</fieldset>";
    $("#authorization_endpoint_result").html(DOMPurify.sanitize(authorization_endpoint_result_html));
    localStorage.setItem("token_access_token", access_token);
  }
  if (  agt == "oidc_hybrid_code_id_token_token" &&
        pathname == "/debugger2.html") //retrieve access code and id_token that is returned from authorization endpoint.
  {
    log.debug("fragement: " + parseFragment());
    access_token = parseFragment()["access_token"];
    if(!access_token)
    {
      access_token = "NO_ACCESS_TOKEN_PRESENTED_IN_EXPECTED_LOCATIONS(oidc_hybrid_code_id_token_token)";
    }
    log.debug("access_token=" + access_token);
    log.debug("fragement: " + parseFragment());
    id_token = parseFragment()["id_token"];
    if(!!id_token)
    {
      id_token = "NO_ID_TOKEN_PRESENTED_IN_EXPECTED_LOCATIONS";
    }
    $("#logout_id_token_hint").val(id_token);
    var authz_endpoint_results_html = "";
    if(displayOpenIDConnectArtifacts == true)
    {
      authz_endpoint_results_html = "<fieldset>" +
                                    "<legend>Authorization Endpoint Results:</legend>" +
				    "<table>" +
				      "<tr>" +
				        "<td>access_token</td>" +
                                        "<td><textarea id=\"implicit_grant_access_token\" rows=3 cols=100>" + access_token + "</textarea></td>"
				      "</tr>" + 
				      "<tr>" +
				        "<td>id_token</td>" + 
				        "<td><textarea id=\"implicit_grant_access_token\" rows=3 cols=100>" + id_token + "</textarea></td>" +
				      "</tr>" +
				    "</table>" +
                                    "</fieldset>";
    } else {
      authz_endpoint_results_html = "<fieldset>" +
                                    "<legend>Authorization Endpoint Results:</legend>" +
                                    "<table>" +
                                      "<tr>" +
                                        "<td>access_token</td>" +
                                        "<td><textarea id=\"implicit_grant_access_token\" rows=3 cols=100>" + access_token + "</textarea></td>"
                                      "</tr>" +
                                    "</table>" +
                                    "</fieldset>";
    }
    $("#authorization_endpoint_result").html(DOMPurify.sanitize(authz_endpoint_results_html));
  }

  if (  agt == "oidc_hybrid_code_token" &&
        pathname == "/debugger2.html") //retrieve access code that is returned from authorization endpoint.
  {
    log.debug("fragement: " + parseFragment());
    access_token = parseFragment()["access_token"];
    if(!access_token)
    {
      access_token = "NO_ACCESS_TOKEN_PRESENTED_IN_EXPECTED_LOCATIONS(oidc_hybrid_code_token)";
    }
    log.debug("access_token=" + access_token);
    $("#authorization_endpoint_result").html(DOMPurify.sanitize("<fieldset>" +
                                                                "  <legend>Authorization Endpoint Results:</legend>" +
                                                                "  <table>" +
                                                                "    <tr>" +
                                                                "      <td>access_token</td>" +
                                                                "      <td>" +
                                                                "        <textarea id='implicit_grant_access_token' rows=3 cols=100>" + access_token + "</textarea>" +
                                                                "      </td>" +
                                                                "    </tr>" +
                                                                "  </table>" +
                                                                "</fieldset>"));
  }
  if ( 	(agt == "oidc_implicit_flow" || agt == "oidc_implicit_flow_id_token" ||  agt == "oidc_hybrid_code_id_token") && 
	pathname == "/debugger2.html") //retrieve access_token for implicit_grant for callback redirect response
  {
    var id_token = getParameterByName("id_token",window.location.href);
    log.debug("id_token=" + access_token);
    if(!id_token)
    {
      //Check to see if passed in as local anchor (ADFS & Azure Active Directory do this)
      log.debug("fragement: " + parseFragment());
      id_token = parseFragment()["id_token"];
      if(!id_token)
      {
        id_token = "NO_ID_TOKEN_PRESENTED_IN_EXPECTED_LOCATIONS";
      }
    }
    log.debug("id_token=" + id_token);
    $("#logout_id_token_hint").val(id_token);
    $("#authorization_endpoint_id_token_result").html(DOMPurify.sanitize("<fieldset>" +
                                                                         "  <legend>Authorization Endpoint Results</legend>" +
                                                                         "  <table>" +
                                                                         "    <tr>" +
                                                                         "      <td>id_token</td>" +
                                                                         "      <td>" +
                                                                         "        <textarea id='implicit_flow_id_token' rows=3 cols=100>" + DOMPurify.sanitize(id_token) + "</textarea>" +
                                                                         "      </td>" +
                                                                         "    </tr>" +
                                                                         "  </table>" +
                                                                         "</fieldset>"));
  }
  var error = getParameterByName("error",window.location.href);
  var authzGrantType = $("#authorization_grant_type").val();
  if(	pathname == "/debugger2.html" && 
	( authzGrantType == "authorization_grant" ||
          authzGrantType == "implicit_grant" ||
          authzGrantType == "oidc_hybrid_code_id_token") &&
	  (!!error))
  {
    error_html = "<fieldset>" +
                   "<legend>Authorization Endpoint Error</legend>" +
                   "<form action='' name='display_authz_error_form' id='display_authz_error_form'>" +
                     "<table>" +
                       "<tr>" +
                         "<td>" +
                           "<label name='display_authz_error_form_label1' value='' id='display_authz_error_form_label1'>Error</label>" +
                         "</td>" +
                         "<td>" +
                           "<textarea rows='5' cols='50' id='display_authz_error_form_textarea1'>" +
                           error +
                           "</textarea>"
                         "</td>" +
                       "</tr>" +
                     "</table>" +
                   "</form>" +
                 "</fieldset>";
    $("#display_authz_error_class").html(DOMPurify.sanitize(error_html));
  }
  log.debug("Entering recreateUniqueGrantFlowElements().");
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
  var tokencustomParametersCheck = $("#customTokenParametersCheck-yes").is(":checked");
  log.debug("customTokenParametersCheck: " + tokencustomParametersCheck + ", type=" + typeof(tokencustomParametersCheck));
  if(tokencustomParametersCheck) {
    const numberCustomParameters = parseInt($("#tokenNumberCustomParameters").val());
    log.debug('numberCustomParameters=' + numberCustomParameters);
    var i = 0;
    for(i = 0; i < numberCustomParameters; i++)
    {
       customParametersComponent = customParametersComponent +
                                   $("#customTokenParameterName-" + i).val() +
                                   '=' + $("#customTokenParameterValue-" + i).val() + "&" + "\n";
    }
    customParametersComponent = customParametersComponent.substring(0,  customParametersComponent.length - 2);
    log.debug('customParametersComponent=' + customParametersComponent);
  }
  if (!!ta1)
  {
    var grant_type = $("#token_grant_type").val();
    if(grant_type == "authorization_code")
    {
      $("#display_token_request_form_textarea1").val(                 "POST " + $("#token_endpoint").val() + "\n" +
								      "Message Body:\n" +
                                                                      "grant_type=" + $("#token_grant_type").val() + "&" + "\n" +
                                                                      "code=" + $("#code").val() + "&" + "\n" +
                                                                      "client_id=" + $("#token_client_id").val() + "&" + "\n" +
                                                                      "redirect_uri=" + $("#token_redirect_uri").val() + "&" +"\n" +
                                                                      "scope=" + $("#token_scope").val());
      if(usePKCE) {
        $("#display_token_request_form_textarea1").val( $("#display_token_request_form_textarea1").val() +"&\n" + "code_verifier=" + $("#token_pkce_code_verifier").val());
      }
    } else if (grant_type == "client_credentials") {
      $("#display_token_request_form_textarea1").val(		      "POST " + $("#token_endpoint").val() + "\n" +
                                                                      "Message Body:\n" +
                                                                      "grant_type=" + $("#token_grant_type").val() + "&" + "\n" +
                                                                      "client_id=" + $("#token_client_id").val() + "&" + "\n" +
                                                                      "client_secret=" + $("#token_client_secret").val() + "&" + "\n" +
                                                                      "redirect_uri=" + $("#token_redirect_uri").val() + "&" +"\n" +
                                                                      "scope=" + $("#token_scope").val());
    } else if (grant_type == "password") {
      $("#display_token_request_form_textarea1").val(                 "POST " + $("#token_endpoint").val() + "\n" +
                                                                      "Message Body:\n" +
                                                                      "grant_type=" + $("#token_grant_type").val() + "&" + "\n" +
                                                                      "client_id=" + $("#token_client_id").val() + "&" + "\n" +
                                                                      "client_secret=" + $("#token_client_secret").val() + "&" + "\n" +
                                                                      "username=" + $("#token_username").val() + "&" + "\n" +
                                                                      "password=" + $("#token_password").val() + "&" + "\n" +
                                                                      "scope=" + $("#token_scope").val());
    } else if (grant_type == "urn:ietf:params:oauth:grant-type:device_code") {
      $("#display_token_request_form_textarea1").val(                 "POST " + $("#token_endpoint").val() + "\n" +
                                                                      "Message Body:\n" +
                                                                      "grant_type=" + $("#token_grant_type").val() + "&" + "\n" +
                                                                      "device_code=" + $("#device_code").val() + "&" + "\n" +
                                                                      "client_id=" + $("#token_client_id").val());
    }
    if ( resourceComponent.length > 0) {
       $("#display_token_request_form_textarea1").val( $("#display_token_request_form_textarea1").val() + "&\n" + resourceComponent + "\n");
     }
     if (customParametersComponent.length > 0) {
       $("#display_token_request_form_textarea1").val( $("#display_token_request_form_textarea1").val() + "&\n" +  customParametersComponent + "\n");
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
        $("#display_refresh_request_form_textarea1").val(DOMPurify.sanitize("POST " + $("#token_endpoint").val() + "\n" +
                                                                      "Message Body:\n" +
                                                                      "grant_type=" + $("#refresh_grant_type").val() + "&" + "\n" +
                                                                      "refresh_token=" + $("#refresh_refresh_token").val() + "&" + "\n" +
                                                                      "client_id=" + $("#refresh_client_id").val() + "&" + "\n" +
                                                                      "client_secret=" + $("#refresh_client_secret").val() + "&" + "\n" +
                                                                      "scope=" + $("#refresh_scope").val() + "\n"));
      } else {
        $("#display_refresh_request_form_textarea1").val(DOMPurify.sanitize("POST " + $("#token_endpoint").val() + "\n" +
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
  var state = getParameterByName("state");
  var stateParameterFound = false;
  if (!!state) {
    log.debug("Found state in query parameters: " + state);
    stateParameterFound = true;
  } else {
    log.debug("Didn't find state in query parameters, attempting to find fragment.");
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
      log.debug('State does not match: state=' + state + ', storedState=' + storedState);
      var stateReportHTML = '<fieldset>' +
                            '<legend>State Report</legend>' +
                            '<P>State does not match: state=' + state + ', storedState=' + storedState + '</P>' +
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
      $("#" + groups[i] + "_initiateFromBackEnd").prop("checked", false).prop("disabled", true);
    }
    setInitiateFromEnd();
    setInitiateRefreshFromEnd();
    setInitiateRevocationFromEnd();
    setInitiateTokenExchangeFromEnd();
  }
  log.debug("Leaving enforceBackendAvailability().");
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
      window.location.href = "/debugger.html";
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

  // If we are not coming back from the Token Detail Page clear all saved tokens. 
  // It will be reset.
  if(getParameterByName("redirectFromTokenDetail") != "true") {
    // Clear all token values.
    log.debug("Detected page load for new grant/flow workflow. Clearing all existing tokens.");
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
  var errorDescriptionParam = getParameterByName('error_description');
  var errorParam = getParameterByName('error');
  log.debug('errorDescriptionParam=' + errorDescriptionParam + ', errorParam=' + errorParam);
  if (!!errorDescriptionParam || 
      !!errorParam) {
    $('#step0').hide();
    $('#step3').hide();
    $('#step4').hide();
    var authzErrorReportHTML = '<fieldset>' +
                               '<legend>Authorization Endpoint Error Report</legend>' +
                               '<P>' + 'Error: ' + errorParam + '</P>' +
                               '<P>' + 'Error Description: ' +  errorDescriptionParam + '</P>' +
                               '</fieldset>';
    $('#authz-error-report').html(DOMPurify.sanitize(authzErrorReportHTML));
    log.debug('errorDescriptionParam=' + errorDescriptionParam + ', errorParam=' + errorParam); 
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
  $("#customTokenParametersCheck-yes").on("click", recalculateTokenRequestDescription);
  $("#customTokenParametersCheck-no").on("click", recalculateTokenRequestDescription);

  loadValuesFromLocalStorage();
  enforceBackendAvailability();
  recreateUniqueGrantFlowElements();
  recalculateAuthorizationErrorDescription();
  recalculateTokenRequestDescription();
  recalculateRefreshRequestDescription();

  // Record the Authorization Endpoint call once when we return from the IdP
  // with an authorization response (code, access_token, or id_token). The
  // signature dedupes so a manual page reload does not record it again.
  if (getParameterByName("redirectFromTokenDetail") != "true") {
    var fragmentParams = parseFragment();
    var authzSignature = getParameterByName('code') || fragmentParams['code'] ||
                         getParameterByName('access_token') || fragmentParams['access_token'] ||
                         getParameterByName('id_token') || fragmentParams['id_token'];
    if (!!authzSignature && localStorage.getItem('last_authz_signature') !== authzSignature) {
      saveOperationToHistory('Authorization Endpoint', { client_id: localStorage.getItem('client_id') });
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
  var tokencustomParametersCheck = $("#customTokenParametersCheck-yes").is(":checked");
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
  $("#revocation_token, #revocation_revocation_endpoint, #revocation_client_id, #revocation_client_secret")
    .on("keyup change", recalculateRevocationRequestDescription);
  $("#revocation_token_type_hint").on("change", recalculateRevocationRequestDescription);
  // Delegated so it also fires for the dynamically-rendered "Revoke Token"
  // buttons in the result panes (and survives DOMPurify, which keeps data-*
  // attributes but strips inline onclick handlers).
  $(document).on("click", ".revoke_token_btn", function() {
    revokeTokenDirect($(this).attr("data-revoke-type"), $(this).attr("data-revoke-generation"));
    return false;
  });
  populateRevocationTokenWithLatestAccessToken();

  // Initialize Token Exchange pane state and keep the request preview in sync.
  useTokenExchangeFrontEnd = $("#tokenexchange_initiateFromFrontEnd").is(":checked");
  $("#tokenexchange_token_endpoint, #tokenexchange_subject_token, #tokenexchange_actor_token, #tokenexchange_resource, #tokenexchange_audience, #tokenexchange_scope, #tokenexchange_client_id, #tokenexchange_client_secret")
    .on("keyup change", recalculateTokenExchangeRequestDescription);
  $("#tokenexchange_subject_token_type, #tokenexchange_actor_token_type, #tokenexchange_requested_token_type")
    .on("change", recalculateTokenExchangeRequestDescription);
  setTokenExchangeType();
  populateTokenExchangeSubjectWithLatestAccessToken();

  if (!window.location.search) {
    $('#step3').show();
    $('#token_fieldset').css('display', 'block');
    $('#token_expand_button').val('Hide');
    $('#config_fieldset').css('display', 'block');
    $('#config_expand_button').val('Hide');
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
    $('#token_expand_button').val('Hide');
  }

  if( authzGrantType === "implicit_grant" ||
      authzGrantType === "oidc_implicit_flow") 
  {
    $('#step3').show();
    $('#step4').show();
    $('#step5').show();
    $('#step6').show();
    $('#step7').show();
    $('#operation-history-panel').show();
  }

  log.debug("Leaving document.ready().");
});

function generateUUID () { // Public Domain/MIT
    log.debug("Entering generateUUID().");
    var d = new Date().getTime();
    if (typeof performance !== "undefined" && typeof performance.now === "function"){
        d += performance.now(); //use high-precision timer if available
    }
    log.debug("Leaving generateUUID().");
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (c) {
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
      if (pathname == "/debugger2.html")
      {
        var error = getParameterByName("error",window.location.href);
        var error_description = getParameterByName("error_description",window.location.href);
        var error_uri = getParameterByName("error_uri",window.location.href);
        var state = getParameterByName("state",window.location.href);
        $("#display_authz_error_form_textarea1").val(                         "error: " + error + "\n" +
                                                                              "error_description: " + error_description + "\n" +
                                                                              "error_uri: " + error_uri + "\n" +
                                                                              "state: " + state + "\n");
      }
    } else if (	grant_type == "token" || 
		grant_type == "id_token" ||
		grant_type == "id_token token") {
      //$("#display_authz_request_form_textarea1").value = "";
      var pathname = window.location.pathname;
      log.debug("pathname=" + pathname);
      if (pathname == "/debugger2.html")
      {
        var error = getParameterByName("error",window.location.href);
        var error_description = getParameterByName("error_description",window.location.href);
        var error_uri = getParameterByName("error_uri",window.location.href);
        var state = getParameterByName("state",window.location.href);
        $("#display_authz_error_form_textarea1").val(                         "error: " + error + "\n" +
                                                                              "error_description: " + error_description + "\n" +
                                                                              "error_uri: " + error_uri + "\n" +
                                                                              "state: " + state + "\n");
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
  $("#display_token_error_class").html(DOMPurify.sanitize(display_token_error_class_html));
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
      $("#display_token_error_form_textarea1").val(                             "status: " + status + "\n" +
										"statusText: " + statusText + "\n" +
										"readyState: " + readyState + "\n" +
										"responseText: " + responseText +"\n" +
										"OAuth2 Response Error Details:" + "\n" +
										"error: " + responseObject.error + "\n" +
										"error_description: " + responseObject.error_description +"\n");
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
      $("#display_token_error_form_textarea1").val(                         "status: " + status + "\n" +
                                                                            "statusText: " + statusText + "\n" +
                                                                            "readyState: " + readyState + "\n" +
                                                                            "responseText: " + responseText +"\n" +
                                                                            "OAuth2 Response Error Details:" + "\n" +
                                                                            "error: " + responseObject.error + "\n" +
                                                                            "error_description: " + responseObject.error_description +"\n");
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
      $("#display_token_error_form_textarea1").val(                         "status: " + status + "\n" +
                                                                            "statusText: " + statusText + "\n" +
                                                                            "readyState: " + readyState + "\n" +
                                                                            "responseText: " + responseText +"\n" +
                                                                            "OAuth2 Response Error Details:" + "\n" +
                                                                            "error: " + responseObject.error + "\n" +
                                                                            "error_description: " + responseObject.error_description +"\n");
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
      $("#display_token_error_form_textarea1").val(                         "status: " + status + "\n" +
                                                                            "statusText: " + statusText + "\n" +
                                                                            "readyState: " + readyState + "\n" +
                                                                            "responseText: " + responseText +"\n" +
                                                                            "OAuth2 Response Error Details:" + "\n" +
                                                                            "error: " + responseObject.error + "\n" +
                                                                            "error_description: " + responseObject.error_description +"\n");
    }
  }
  log.debug("Leaving recalculateTokenErrorDescription().");
}

function recalculateRefreshErrorDescription(data)
{
  log.debug("Entering recalculateRefreshErrorDescription().");
  var display_refresh_error_class = "<fieldset>" +
                                    "<legend>Token Endpoint (For Refresh) Error</legend>" +
                                       "<form action=\"\" name=\"display_refresh_error_form\" id=\"display_refresh_error_form\">" +
                                         "<table>" +
                                           "<tr>" +
                                             "<td><label name=\"display_refresh_error_form_label1\" value=\"\" id=\"display_refresh_error_form_label1\">Error</label></td>" +
                                             "<td><textarea rows=\"5\" cols=\"60\" id=\"display_refresh_error_form_textarea1\"></textarea></td>" +
                                           "</tr>" +
                                         "</table>" +
                                        "</form>" +
                                      "</fieldset>";
  $("#display_refresh_error_class").html(DOMPurify.sanitize(display_refresh_error_class));
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
      $("#display_refresh_error_form_textarea1").val(                           "status: " + status + "\n" +
										"statusText: " + statusText + "\n" +
										"readyState: " + readyState + "\n" +
										"responseText: " + responseText +"\n" +
										"OAuth2 Response Error Details:" + "\n" +
										"error: " + responseObject.error + "\n" +
										"error_description: " + responseObject.error_description +"\n");
    }
  }
  log.debug("Leaving recalculateRefreshErrorDescription().");
}

function parseFragment()
{
  log.debug("hash=" + window.location.hash);
  var hash = window.location.hash.substr(1);

  var result = hash.split("&").reduce(function (result, item) {
      var parts = item.split("=");
      result[parts[0]] = parts[1];
      return result;
  }, {});
  return result;
}

function displayOIDCArtifacts()
{
  log.debug("Entering displayOIDCArtifacts().");
  var yesCheck = $("#yesCheckOIDCArtifacts").is(":checked");
  var noCheck = $("#noCheckOIDCArtifacts").is("checked");
  log.debug("yesCheckOIDCArtifacts=" + yesCheck + ", noCheckOIDCArtifacts=" + noCheck + ", typeof=" + typeof(yesCheck));
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
  log.debug("Entering useRefreshToken().");
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
    return Boolean(new URL(url));
  } catch(e) {
    log.debug('An error occurred: ' + e.stack);
    return false;
  }
}

function clearLocalStorage() {
  if (localStorage) {
    localStorage.setItem("token_client_secret", "");
    localStorage.setItem("refresh_client_secret", "");
  }
}

// ---- Token History ----

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

function extractNonce(id_token) {
  if (id_token) {
    var payload = decodeJwtPayload(id_token);
    if (payload && payload.nonce) return payload.nonce;
  }
  return null;
}

// Session ID (sid) from the OAuth2 access token (JWT). Used to group the Token
// History by session. Refresh responses preserve the sid of the originating
// session, unlike nonce (which is only present on the original authentication).
function extractSid(access_token) {
  if (access_token) {
    var payload = decodeJwtPayload(access_token);
    if (payload && payload.sid) return payload.sid;
  }
  return null;
}

function saveTokenSetToHistory(access_token, refresh_token, id_token, source) {
  var history = [];
  try { 
    history = JSON.parse(localStorage.getItem('token_history') || '[]'); 
  } catch(e) 
  {
    log.error("An error occurred while writing to local storage: " + e);
  }
  var nonce = extractNonce(id_token);
  var sid = extractSid(access_token);
  if (history.length >= TOKEN_HISTORY_LIMIT) {
    localStorage.removeItem('token_history');
    renderTokenHistory();
    return;
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
}

function selectTokenSet(index) {
  var history = [];
  try {
    history = JSON.parse(localStorage.getItem('token_history') || '[]'); 
  } catch(e) { 
    log.error("An error occurred while reading from local storage: " + e);
    return false; 
  }
  if (index < 0 ||
      index >= history.length) 
  {
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
  return false;
}

function renderCurrentlyViewing(index, entry) {
  var html = '<fieldset>' +
               '<legend>Currently Viewing</legend>' +
               '<p><em>Token set selected from Token History.</em></p>' +
               '<table>' +
                 '<tr>' +
                   '<td>' +
                     '<P><a href="/token_detail.html?type=history_access&generation=' + index + '" onclick="debugger2.clickLink()">Access Token</a></P>' +
                     '<P style="font-size:50%;"><a href="/introspection.html?type=history_access&generation=' + index + '" onclick="debugger2.clickLink()">Introspect Token</a></P>' +
                     '<P><input class="btn2 revoke_token_btn" type="button" value="Revoke Token" data-revoke-type="history_access" data-revoke-generation="' + index + '" /></P>' +
                     '<P><form><input class="btn2" type="submit" value="Copy Token"' +
                     ' onclick="return debugger2.onClickCopyToken(\'#cv_access_token\');"/></form></P>' +
                   '</td>' +
                   '<td><textarea rows=5 cols=60 readonly name=cv_access_token id=cv_access_token>' + (entry.access_token || '') + '</textarea></td>' +
                 '</tr>';
  if (entry.refresh_token) {
    html +=      '<tr>' +
                   '<td>' +
                     '<P><a href="/token_detail.html?type=history_refresh&generation=' + index + '" onclick="debugger2.clickLink()">Refresh Token</a></P>' +
                     '<P style="font-size:50%;"><a href="/introspection.html?type=history_refresh&generation=' + index + '" onclick="debugger2.clickLink()">Introspect Token</a></P>' +
                     '<P><input class="btn2 revoke_token_btn" type="button" value="Revoke Token" data-revoke-type="history_refresh" data-revoke-generation="' + index + '" /></P>' +
                     '<P><form><input class="btn2" type="submit" value="Copy Token"' +
                     ' onclick="return debugger2.onClickCopyToken(\'#cv_refresh_token\');"/></form></P>' +
                   '</td>' +
                   '<td><textarea rows=5 cols=60 readonly name=cv_refresh_token id=cv_refresh_token>' + (entry.refresh_token || '') + '</textarea></td>' +
                 '</tr>';
  }
  if (entry.id_token) {
    html +=      '<tr>' +
                   '<td>' +
                     '<P><a href="/token_detail.html?type=history_id_token&generation=' + index + '" onclick="debugger2.clickLink()">ID Token</a></P>' +
                     '<P style="font-size:50%;">Get <a href="/userinfo.html?type=history_access&generation=' + index + '" onclick="debugger2.clickLink()">UserInfo Data</a></P>' +
                     '<P><form><input class="btn2" type="submit" value="Copy Token"' +
                     ' onclick="return debugger2.onClickCopyToken(\'#cv_id_token\');"/></form></P>' +
                   '</td>' +
                   '<td><textarea rows=5 cols=60 readonly name=cv_id_token id=cv_id_token>' + (entry.id_token || '') + '</textarea></td>' +
                 '</tr>';
  }
  html +=      '<tr>' +
                 '<td><strong>Generation:</strong></td>' +
                 '<td>' + (index + 1) + '</td>' +
               '</tr>' +
               '<tr>' +
                 '<td><strong>Nonce:</strong></td>' +
                 '<td><input type="text" readonly value="' + (entry.nonce || '') + '" style="width:100%;" /></td>' +
               '</tr>' +
               '<tr>' +
                 '<td><strong>Session ID (sid):</strong></td>' +
                 '<td><input type="text" readonly value="' + (entry.sid || '') + '" style="width:100%;" /></td>' +
               '</tr>' +
             '</table>' +
             '</fieldset>';
  $('#currently-viewing-panel').html(html);
  $('#currently-viewing-panel').show();
}

function renderTokenHistory() {
  var history = [];
  try { history = JSON.parse(localStorage.getItem('token_history') || '[]'); } catch(e) {}
  if (history.length === 0) {
    $("#token-history-panel").hide();
    return;
  }
  var activeIndex = parseInt(localStorage.getItem('token_history_active_index'));
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

  var html = '<fieldset><legend>Token History</legend>';
  html += '<input type="button" value="Clear History" onclick="return debugger2.clearTokenHistory();" />';
  html += '<div style="max-height:450px; overflow-y:auto;">';
  sessionOrder.slice().reverse().forEach(function(sid) {
    var label = sid === '__no_sid__' ? 'No Session ID (sid)' : 'Session ID (sid): ' + sid;
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
      html += '<td style="font-size:80%;">' + datePart + '<br>' + timePart + '</td>';
      html += '<td>' + e.source + '</td>';
      html += '<td style="font-size:70%; word-break:break-all;">' + escapeHtmlText(e.nonce || '') + '</td>';
      html += '<td style="font-size:70%; word-break:break-all;">' + escapeHtmlText(e.sid || '') + '</td>';
      html += '<td style="text-align:center;">' + (e.access_token ? '&#10003;' : '') + '</td>';
      html += '<td style="text-align:center;">' + (e.refresh_token ? '&#10003;' : '') + '</td>';
      html += '<td style="text-align:center;">' + (e.id_token ? '&#10003;' : '') + '</td>';
      html += '<td>';
      if (isActive) {
        html += '<strong>Active</strong>';
      } else {
        html += '<input type="button" value="Activate" onclick="return debugger2.selectTokenSet(' + idx + ');" />';
      }
      html += '</td>';
      html += '</tr>';
    });
    html += '</table></div>';
  });
  html += '</div>';
  html += '</fieldset>';

  $("#token-history-panel").html(html);
  $("#token-history-panel").show();
}

function regenerateState() {
  $("#state").val(generateUUID());
  localStorage.setItem('state', $("#state").val());
}

function regenerateNonce() {
  $("#nonce_field").val(generateUUID());
  localStorage.setItem('nonce_field', $("#nonce_field").val());
}

function recreateTokenDisplay()
{
      var token_endpoint_result_html = "";
      log.debug("displayOpenIDConnectArtifacts=" + displayOpenIDConnectArtifacts);
      var refreshToken = localStorage.getItem("token_refresh_token");
      if(displayOpenIDConnectArtifacts == true)
      {
         log.debug("Displaying full OIDC Token results.");
         // Display OAuth2/OIDC Artifacts
         log.debug("RCBJ0001");
         token_endpoint_result_html = "<fieldset>" +
                                      "<legend>Token Endpoint Results:</legend>" +
                                 "<p><em>Most recent results of the OAuth2 Grant or OIDC Authentication Flow call.</em></p>" +
                                      "<table>" +
                                        "<tr>" +
                                          '<td>' +
                                              '<P><a href="/token_detail.html?type=access" onclick="debugger2.clickLink()">Access Token</a></P>' +
                                              '<P style="font-size:50%;"><a href="/introspection.html?type=access" onclick="debugger2.clickLink()">Introspect Token</a></P>' +
                                         '<P><input class="btn2 revoke_token_btn" type="button" value="Revoke Token" data-revoke-type="access" /></P>' + 
                                              '<P><form><input class="btn2" type="submit" value="Copy Token"' +
                                              ' onclick="return debugger2.onClickCopyToken(\'#token_access_token\');"/></form></P>' +
                                          "</td>" +
                                          "<td>" +
                                             "<textarea rows=5 cols=60 readonly name=token_access_token id=token_access_token>" + 
                                               localStorage.getItem("token_access_token") + 
                                             "</textarea>" +
                                          "</td>" +
                                        "</tr>";
        if(useRefreshTokenTester) {
           log.debug("Displaying refresh token.");
           token_endpoint_result_html +=  '<tr>' +
                                          '<td>' +
                                              '<P><a href="/token_detail.html?type=refresh" onclick="debugger2.clickLink()">Refresh Token</a></P>' +
                                              '<P style="font-size:50%;"><a href="/introspection.html?type=refresh" onclick="debugger2.clickLink()">Introspect Token</a></P>' +
                                         '<P><input class="btn2 revoke_token_btn" type="button" value="Revoke Token" data-revoke-type="refresh" /></P>' +
                                              '<P><form><input class="btn2" type="submit" value="Copy Token"' + 
                                              ' onclick="return debugger2.onClickCopyToken(\'#token_refresh_token\');"/></form></P>' +
                                          '</td>' +
                                          '<td>' +
                                              '<textarea rows=5 cols=60 readonly name=token_refresh_token id=token_refresh_token>' + 
                                                refreshToken +
                                              "</textarea>" +
                                          "</td>" +
                                        "</tr>";
         }
         token_endpoint_result_html +=  "<tr>" +
                                          '<td>' +
                                            '<P><a href="/token_detail.html?type=id" onclick="debugger2.clickLink()">ID Token</a></P>' +
                                            '<P style="font-size:50%;">Get <a href="/userinfo.html?type=token_access_token" onclick="debugger2.clickLink()">UserInfo Data</a></P>' +
                                            '<P><form><input class="token_btn" type="submit" value="Copy Token"' + 
                                            ' onclick="return debugger2.onClickCopyToken(\'#token_id_token\');"/></form></P>' +
                                          '</td>' +
                                          '<td>' +
                                            '<textarea rows=5 cols=60 readonly name=token_id_token id=token_id_token>' + 
                                              localStorage.getItem("token_id_token") + 
                                            "</textarea>" +
                                          '</td>' +
                                        "</tr>" +
                                      "</table>" +
                                      "</fieldset>";

      } else {
         log.debug("Logging access_token only.");
         log.debug("RCBJ0002");
         token_endpoint_result_html = "<fieldset>" +
                                      "<legend>Token Endpoint Results:</legend>" +
                                 "<p><em>Most recent results of the OAuth2 Grant or OIDC Authentication Flow call.</em></p>" +
                                      "<table>" +
                                        "<tr>" +
                                          '<td>' +
                                            '<p><a href="/token_detail.html?type=access" onclick="debugger2.clickLink()">Access Token</a></p>' +
                                            '<P><input class="btn2 revoke_token_btn" type="button" value="Revoke Token" data-revoke-type="access" /></P>' +
                                            '<P><form><input class="btn2" type="submit" value="Copy Token"' +
                                            ' onclick="return debugger2.onClickCopyToken(\'#token_access_token\');"/></form></P>' +
                                          '</td>' +
                                          "<td><textarea rows=5 cols=60 readonly name=token_access_token id=token_access_token>" +
                                              localStorage.getItem("token_access_token") + 
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>";
         if(useRefreshTokenTester) {
           log.debug("Displaying refresh token");
           token_endpoint_result_html += "<tr>" +
                                          '<td>' +
                                            '<a href="/token_detail.html?type=refresh" onclick="debugger2.clickLink()">Refresh Token</a>' +
                                            '<P><input class="btn2 revoke_token_btn" type="button" value="Revoke Token" data-revoke-type="refresh" /></P>' +
                                            '<P><form><input class="btn2" type="submit" value="Copy Token"' +
                                            ' onclick="return debugger2.onClickCopyToken(\'#token_refresh_token\');"/></form></P>' +
                                          '</td>' +
                                          "<td>" +
                                            "<textarea rows=5 cols=60 readonly name=token_refresh_token id=token_refresh_token>" +
                                              refreshToken +
                                            "</textarea>" +
                                          "</td>" +
                                        "</tr>";
         }
         token_endpoint_result_html += "</table>" +
                                      "</fieldset>";
      }
      //$("#token_endpoint_result").html(DOMPurify.sanitize(token_endpoint_result_html));
      $("#token_endpoint_result").html(token_endpoint_result_html);
}

function displayTokenCustomParametersCheck()
{
  log.debug("Entering displayTokenCustomParametersCheck().");
  var yesCheck = $("#customTokenParametersCheck-yes").is(":checked");
  var noCheck = $("#customTokenParametersCheck-no").is(":checked");
  log.debug("customParamtersYesCheck=" + yesCheck, "customParamtersNoCheck=" + noCheck);
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
            '<input class="stored" id="' + 'customTokenParameterName-' + i + '" name="' + 'customTokenParameterName-' + i + '" type="text" maxlength="64" size="32" />' +
          "</td>" +
          "<td>" +
            '<input class="stored" id="' + 'customTokenParameterValue-' + i + '" name="' + 'customTokenParameterValue-' + i + '" type="text" maxlength="128" size="64" />' +
          "</td>" +
        "</tr>";
      }
      customParametersListHTML = customParametersListHTML +
        "</table>" +
        "</fieldset>";
      $("#token_custom_parameter_list").html(DOMPurify.sanitize(customParametersListHTML));
  if ($("#customTokenParametersCheck-yes").is(":checked")) {
    var i = 0;
    var authzNumberCustomParameters = parseInt($("#tokenNumberCustomParameters").val());
    for(i = 0; i < authzNumberCustomParameters; i++)
    {
      $("#customTokenParameterName-" + i).val(localStorage.getItem("customTokenParameterName-" + i));
      $("#customTokenParameterValue-" + i).val(localStorage.getItem("customTokenParameterValue-" + i));
      $("#customTokenParameterName-" + i).on("keypress", recalculateTokenRequestDescription);
      $("#customTokenParameterValue-" + i).on("keypress", recalculateTokenRequestDescription);

    }
  }
  recalculateTokenRequestDescription();
}

function onClickShowFieldSet(expand_button_id, field_set_id) {
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
    $("#" + expand_button_id).val("Hide");
  }
  $("#step0_expand_form").on("click", function(event) {
    event.preventDefault();
  });
  log.debug('Leaving onClickShowConfigFieldSet().');
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
  return localStorage.getItem(key) === 'true';
}

function setPostAuthStyleCheckToken() {
  log.debug("Entering setPostAuthStyleCheckToken().");
  $("#token_postAuthStyleCheckToken").prop("checked", true);
  $("#token_headerAuthStyleCheckToken").prop("checked", false);
  localStorage.setItem("token_post_auth_style", true);
  log.debug("Leaving setPostAuthStyleCheckToken(): token_post_auth_style=" + localStorage.getItem("token_post_auth_style") + ".");
  return false;
}

function setHeaderAuthStyleCheckToken() {
  log.debug("Entering setHeaderAuthStyleCheckToken().");
  $("#token_postAuthStyleCheckToken").prop("checked", false);
  $("#token_headerAuthStyleCheckToken").prop("checked", true);
  localStorage.setItem("token_post_auth_style", false);
  log.debug("Leaving setHeaderAuthStyleCheckToken(): token_post_auth_style=" + localStorage.getItem("token_post_auth_style") + ".");
  return false;
}

function setPostAuthStyleRefreshToken() {
  log.debug("Entering setPostAuthStyleRefreshToken().");
  $("#refresh_postAuthStyleCheckToken").prop("checked", true);
  $("#refresh_headerAuthStyleCheckToken").prop("checked", false);
  localStorage.setItem("refresh_post_auth_style", true);
  log.debug("Leaving setPostAuthStyleRefreshToken(): token_post_auth_style=" + localStorage.getItem("refresh_post_auth_style") + ".");
  return false;
}

function setHeaderAuthStyleRefreshToken() {
  log.debug("Entering setHeaderAuthStyleRefreshToken().");
  $("#refresh_postAuthStyleCheckToken").prop("checked", false);
  $("#refresh_headerAuthStyleCheckToken").prop("checked", true);
  localStorage.setItem("refresh_post_auth_style", false);
  log.debug("Leaving setHeaderAuthStyleRefreshToken(): refresh_post_auth_style=" + localStorage.getItem("refresh_post_auth_style") + ".");
  return false;
}

function onClickCopyToken(field) {
  log.debug("Entering copyToken().");
  var copyText = $(field);
  navigator.clipboard.writeText(copyText.val());
  log.debug("Leaving copyToken().");
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
  var frontEndRefreshInitiated = $("#refresh_initiateFromFrontEnd").is(":checked");
  var backEndRefreshInitiated = $("#refresh_initiateFromBackEnd").is(":checked");
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
  localStorage.removeItem('token_history');
  localStorage.removeItem('token_history_active_index');
  $('#token-history-panel').hide();
  $('#currently-viewing-panel').hide();
  return false;
}

// ---- Operation History ----

// Escapes text before inserting it into the (non-sanitized) operation history
// markup. The operation history table is rendered without DOMPurify so its
// inline onclick handlers survive, so dynamic values must be escaped here.
function escapeHtmlText(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// The session nonce: preferring the nonce carried in the most recent id_token,
// falling back to the nonce generated for the authorization request.
function getCurrentSessionNonce() {
  var idToken = localStorage.getItem('refresh_id_token') || localStorage.getItem('token_id_token');
  var n = extractNonce(idToken);
  if (!!n) {
    return n;
  }
  return localStorage.getItem('nonce_field') || '';
}

// Index of the most recently saved token_history entry, or -1 if none.
function getLatestTokenHistoryIndex() {
  var history = [];
  try {
    history = JSON.parse(localStorage.getItem('token_history') || '[]');
  } catch (e) {
    log.error("Failed to parse token_history: " + e);
  }
  return history.length - 1;
}

// Appends an entry to the cumulative operation history. options may include
// detail, client_id, nonce, and tokenHistoryIndex.
function saveOperationToHistory(operation, options) {
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
    tokenHistoryIndex: (typeof options.tokenHistoryIndex === 'number') ? options.tokenHistoryIndex : null
  });
  localStorage.setItem('operation_history', JSON.stringify(history));
  renderOperationHistory();
}

function renderOperationHistory() {
  var history = [];
  try {
    history = JSON.parse(localStorage.getItem('operation_history') || '[]');
  } catch (e) {
    log.error("Failed to parse operation_history: " + e);
  }
  var html = '<fieldset>' +
               '<legend>Operation History</legend>' +
               '<p><em>Chronological history of every endpoint operation performed.</em></p>' +
               '<input type="button" value="Clear History" onclick="return debugger2.clearOperationHistory();" />';
  if (history.length === 0) {
    html += '<p><em>No operations recorded yet.</em></p></fieldset>';
    $("#operation-history-panel").html(html);
    return;
  }
  // Cap the visible area to roughly 3-5 rows; a scrollbar appears beyond that.
  html += '<div style="max-height:200px; overflow-y:auto; margin-top:4px;">';
  html += '<table border="1" style="width:100%;">';
  var thStyle = 'position:sticky; top:0; background:#fafafa;';
  html += '<tr><th style="' + thStyle + ' width:5%">#</th><th style="' + thStyle + ' width:22%">Time</th><th style="' + thStyle + ' width:27%">Operation</th><th style="' + thStyle + ' width:18%">Client ID</th><th style="' + thStyle + ' width:28%">Nonce</th></tr>';
  history.slice().reverse().forEach(function(item, ridx) {
    var idx = history.length - 1 - ridx;
    var datePart = (item.timestamp || '').substring(0, 10);
    var timePart = (item.timestamp || '').substring(11, 19);
    var op = escapeHtmlText(item.operation) + (item.detail ? ' (' + escapeHtmlText(item.detail) + ')' : '');
    html += '<tr>';
    html += '<td>' + (idx + 1) + '</td>';
    html += '<td style="font-size:80%;">' + escapeHtmlText(datePart) + '<br>' + escapeHtmlText(timePart) + '</td>';
    html += '<td style="font-size:90%;">' + op + '</td>';
    html += '<td style="word-break:break-all; font-size:80%;">' + escapeHtmlText(item.client_id) + '</td>';
    html += '<td style="word-break:break-all; font-size:75%;">' + escapeHtmlText(item.nonce) + '</td>';
    html += '</tr>';
  });
  html += '</table></div></fieldset>';
  $("#operation-history-panel").html(html);
}

function clearOperationHistory() {
  localStorage.removeItem('operation_history');
  renderOperationHistory();
  return false;
}

// ---- Token Revocation (RFC 7009) ----

// Populate the revocation pane with a token selected via one of the
// "Revoke Token" links rendered next to each Access/Refresh Token field.
// type identifies which token to load; generation is the token history index
// (only used for the history_* types).
function loadTokenForRevocation(type, generation) {
  log.debug("Entering loadTokenForRevocation(). type=" + type + ", generation=" + generation);
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
    $("#revocation_revocation_endpoint").val(localStorage.getItem("revocation_endpoint"));
  }
  if (!$("#revocation_client_id").val()) {
    $("#revocation_client_id").val($("#token_client_id").val() || localStorage.getItem("client_id"));
  }
  if (!$("#revocation_client_secret").val()) {
    $("#revocation_client_secret").val($("#token_client_secret").val() || localStorage.getItem("client_secret"));
  }
  // Make sure the revocation pane is visible and expanded.
  $("#step6").show();
  $("#revocation_fieldset").css("display", "block");
  $("#revocation_expand_button").val("Hide");
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
  log.debug("Entering revokeTokenDirect(). type=" + type + ", generation=" + generation);
  loadTokenForRevocation(type, generation);
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
    displayRevocationResult("No token specified. Use a \"Revoke Token\" link above a token field, " +
                            "or paste a token into the Token field, then try again.", true);
    return false;
  }
  if (!formData.revocation_endpoint) {
    displayRevocationResult("No revocation endpoint configured. Populate it from the discovery document " +
                            "on the previous page, or enter it manually.", true);
    return false;
  }
  if (useRevocationFrontEnd) {
    log.debug("Using frontend to call Revocation Endpoint. auth_style(POST body)=" + formData.auth_style);
    var headers = { "Content-Type": "application/x-www-form-urlencoded" };
    var bodyParams = "token=" + encodeURIComponent(formData.token);
    if (!!formData.token_type_hint) {
      bodyParams += "&token_type_hint=" + encodeURIComponent(formData.token_type_hint);
    }
    if (formData.auth_style) {
      // POST body: send client credentials as request parameters.
      if (!!formData.client_id) {
        bodyParams += "&client_id=" + encodeURIComponent(formData.client_id);
      }
      if (!!formData.client_secret) {
        bodyParams += "&client_secret=" + encodeURIComponent(formData.client_secret);
      }
    } else {
      // HTTP Basic authorization header.
      if (!!formData.client_secret) {
        headers["Authorization"] = "Basic " + btoa(formData.client_id + ":" + formData.client_secret);
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
  return false;
}

function successfulRevocationAPICall(data, textStatus, jqXHR) {
  log.debug("Entering successfulRevocationAPICall(): data=" + JSON.stringify(data) + ", textStatus=" + textStatus);
  var status = (jqXHR && jqXHR.status) ? jqXHR.status : 200;
  var statusText = (jqXHR && jqXHR.statusText) ? jqXHR.statusText : "";
  var bodyText = "";
  try {
    bodyText = (typeof data === "string") ? data : JSON.stringify(data, null, 2);
  } catch (e) {
    bodyText = String(data);
  }
  var message = "Token revocation request accepted.\n" +
                "Per RFC 7009, the authorization server returns HTTP 200 whether or not the token\n" +
                "previously existed, so a 200 here does not by itself confirm a token was active.\n\n" +
                "HTTP Status: " + status + " " + statusText + "\n" +
                "Response Body: " + (bodyText && bodyText !== "{}" ? bodyText : "(empty)");
  displayRevocationResult(message, false);
  saveOperationToHistory('Revocation Endpoint', {
    client_id: $("#revocation_client_id").val(),
    detail: $("#revocation_token_type_hint").val() || 'token'
  });
  log.debug("Leaving successfulRevocationAPICall().");
}

function errorRevocationAPICall(jqXHR, status, error) {
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
                "HTTP Status: " + (jqXHR ? jqXHR.status : "") + " " + (jqXHR ? jqXHR.statusText : "") + "\n" +
                "error: " + (responseObject.error || error || "") + "\n" +
                "error_description: " + (responseObject.error_description || "") + "\n" +
                "Response Body: " + responseText;
  displayRevocationResult(message, true);
  saveOperationToHistory('Revocation Endpoint', {
    client_id: $("#revocation_client_id").val(),
    detail: ($("#revocation_token_type_hint").val() || 'token') + ', error'
  });
}

function displayRevocationResult(message, isError) {
  log.debug("Entering displayRevocationResult(). isError=" + isError);
  var legend = isError ? "Token Revocation Error" : "Token Revocation Results";
  var html = "<fieldset>" +
               "<legend>" + legend + "</legend>" +
               "<p><em>Most recent result of the Token Revocation (RFC 7009) call.</em></p>" +
               "<table>" +
                 "<tr>" +
                   "<td>" +
                     "<textarea rows='9' cols='80' readonly id='revocation_result_textarea' name='revocation_result_textarea'></textarea>" +
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
    request += "Authorization: Basic base64(" + clientId + ":<client_secret>)\n";
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
  log.debug("Leaving setPostAuthStyleRevocation(): revocation_post_auth_style=" + localStorage.getItem("revocation_post_auth_style") + ".");
  return false;
}

function setHeaderAuthStyleRevocation() {
  log.debug("Entering setHeaderAuthStyleRevocation().");
  $("#revocation_postAuthStyleCheckToken").prop("checked", false);
  $("#revocation_headerAuthStyleCheckToken").prop("checked", true);
  localStorage.setItem("revocation_post_auth_style", false);
  recalculateRevocationRequestDescription();
  log.debug("Leaving setHeaderAuthStyleRevocation(): revocation_post_auth_style=" + localStorage.getItem("revocation_post_auth_style") + ".");
  return false;
}

// Returns the most recent access token, preferring one obtained from a Refresh
// Token call (if one has been made) over the access token from the initial
// Token Endpoint call.
function getLatestAccessToken() {
  if (getLSBooleanItem("refresh_token_used")) {
    var refreshAccessToken = localStorage.getItem("refresh_access_token");
    if (!!refreshAccessToken) {
      return refreshAccessToken;
    }
  }
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

var TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";

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
  if (!value) {
    return body;
  }
  return (body ? body + "&" : "") + key + "=" + encodeURIComponent(value);
}

function tokenExchangeButtonClick() {
  log.debug("Entering tokenExchangeButtonClick().");
  writeValuesToLocalStorage();
  recalculateTokenExchangeRequestDescription();
  var formData = buildInternalTokenExchangeRequestMessage();
  if (!formData.token_endpoint) {
    displayTokenExchangeResult("No token endpoint configured. Populate it from the discovery document " +
                               "on the previous page, or enter it manually.", true);
    return false;
  }
  if (!formData.subject_token) {
    displayTokenExchangeResult("No subject token specified. The subject token defaults to the most recent " +
                               "access token; obtain a token first, or paste one into the Subject Token field.", true);
    return false;
  }
  if ($("#tokenexchange_delegation").is(":checked") && !formData.actor_token) {
    displayTokenExchangeResult("Delegation is selected but no actor token was provided. Enter an actor token, " +
                               "or switch to Impersonation.", true);
    return false;
  }
  if (useTokenExchangeFrontEnd) {
    log.debug("Using frontend to call Token Endpoint for token exchange. auth_style(POST body)=" + formData.auth_style);
    var headers = { "Content-Type": "application/x-www-form-urlencoded" };
    var bodyParams = "grant_type=" + encodeURIComponent(formData.grant_type);
    bodyParams = appendFormParam(bodyParams, "subject_token", formData.subject_token);
    bodyParams = appendFormParam(bodyParams, "subject_token_type", formData.subject_token_type);
    bodyParams = appendFormParam(bodyParams, "actor_token", formData.actor_token);
    bodyParams = appendFormParam(bodyParams, "actor_token_type", formData.actor_token_type);
    bodyParams = appendFormParam(bodyParams, "requested_token_type", formData.requested_token_type);
    bodyParams = appendFormParam(bodyParams, "resource", formData.resource);
    bodyParams = appendFormParam(bodyParams, "audience", formData.audience);
    bodyParams = appendFormParam(bodyParams, "scope", formData.scope);
    if (formData.auth_style) {
      // POST body: send client credentials as request parameters.
      bodyParams = appendFormParam(bodyParams, "client_id", formData.client_id);
      bodyParams = appendFormParam(bodyParams, "client_secret", formData.client_secret);
    } else {
      // HTTP Basic authorization header.
      if (!!formData.client_secret) {
        headers["Authorization"] = "Basic " + btoa(formData.client_id + ":" + formData.client_secret);
      } else if (!!formData.client_id) {
        bodyParams = appendFormParam(bodyParams, "client_id", formData.client_id);
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
  return false;
}

function successfulTokenExchangeAPICall(data, textStatus, jqXHR) {
  log.debug("Entering successfulTokenExchangeAPICall(): data=" + JSON.stringify(data) + ", textStatus=" + textStatus);
  var status = (jqXHR && jqXHR.status) ? jqXHR.status : 200;
  var statusText = (jqXHR && jqXHR.statusText) ? jqXHR.statusText : "";
  var bodyText = "";
  try {
    bodyText = (typeof data === "string") ? data : JSON.stringify(data, null, 2);
  } catch (e) {
    bodyText = String(data);
  }
  var message = "Token exchange request succeeded.\n" +
                "HTTP Status: " + status + " " + statusText + "\n" +
                "Response Body:\n" + (bodyText && bodyText !== "{}" ? bodyText : "(empty)");
  displayTokenExchangeResult(message, false);
  saveOperationToHistory('Token Exchange', {
    client_id: $("#tokenexchange_client_id").val(),
    detail: $("#tokenexchange_delegation").is(":checked") ? 'delegation' : 'impersonation'
  });
  log.debug("Leaving successfulTokenExchangeAPICall().");
}

function errorTokenExchangeAPICall(jqXHR, status, error) {
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
                "HTTP Status: " + (jqXHR ? jqXHR.status : "") + " " + (jqXHR ? jqXHR.statusText : "") + "\n" +
                "error: " + (responseObject.error || error || "") + "\n" +
                "error_description: " + (responseObject.error_description || "") + "\n" +
                "Response Body: " + responseText;
  displayTokenExchangeResult(message, true);
  saveOperationToHistory('Token Exchange', {
    client_id: $("#tokenexchange_client_id").val(),
    detail: ($("#tokenexchange_delegation").is(":checked") ? 'delegation' : 'impersonation') + ', error'
  });
}

function displayTokenExchangeResult(message, isError) {
  log.debug("Entering displayTokenExchangeResult(). isError=" + isError);
  var legend = isError ? "Token Exchange Error" : "Token Exchange Results";
  var html = "<fieldset>" +
               "<legend>" + legend + "</legend>" +
               "<p><em>Most recent result of the Token Exchange (RFC 8693) call.</em></p>" +
               "<table>" +
                 "<tr>" +
                   "<td>" +
                     "<textarea rows='12' cols='80' readonly id='tokenexchange_result_textarea' name='tokenexchange_result_textarea'></textarea>" +
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
    request += "Authorization: Basic base64(" + clientId + ":<client_secret>)\n";
  }
  request += "Message Body:\n" +
             "grant_type=" + TOKEN_EXCHANGE_GRANT_TYPE;
  var addLine = function (key, value) {
    if (!!value) {
      request += "&\n" + key + "=" + value;
    }
  };
  addLine("subject_token", $("#tokenexchange_subject_token").val());
  addLine("subject_token_type", $("#tokenexchange_subject_token_type").val());
  if (delegation) {
    addLine("actor_token", $("#tokenexchange_actor_token").val());
    addLine("actor_token_type", $("#tokenexchange_actor_token_type").val());
  }
  addLine("requested_token_type", $("#tokenexchange_requested_token_type").val());
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
  var frontEndInitiated = $("#tokenexchange_initiateFromFrontEnd").is(":checked");
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
