var appconfig = require(process.env.CONFIG_FILE);
// OpenID Provider Metadata (Discovery 1.0 s3) — the table and its
// defaults/persistence/populate helpers, shared with debugger2.js.
var opMetadata = require("./op_metadata");
var metadataClient = require("./metadata_client");
var sdJwtVc = require("./sd_jwt_vc");
// DPoP for THIS workflow (RFC 9449), kept apart from the VC workflow's copy —
// see oauth_dpop.js for why the two are separate state.
var oauthDpop = require("./oauth_dpop");
var bunyan = require("bunyan");
var DOMPurify = require("dompurify");
// DOMPurify above is for markup going into the DOM, which is what it is for.
// URLs going into a navigation sink need a scheme allowlist instead — see
// url_safety.js.
var urlSafety = require("./url_safety");
var $ = require("jquery");
console.log("logLevel: " + appconfig.logLevel);
var log = bunyan.createLogger({ name: 'debugger',
                                level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());
var displayOpenIDConnectArtifacts = true;
var useRefreshTokenTester = true;
var usePKCE = true;
var discoveryInfo = {};
var initialized = false;

function OnSubmitForm()
{
  log.debug("Entering OnSubmitForm().");
  writeValuesToLocalStorage();
  recalculateAuthorizationRequestDescription();
  log.debug("Leaving OnSubmitForm().");
  return true;
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

$(document).ready(function() {
  log.debug("Entering ready function.");
  // Eliminating use of window.onload function.
  onload();
  $("#authorization_grant_type").change(function() {
    log.debug("Entering selection changed function().");
    var value = $(this).val();
    resetUI(value);
    recalculateAuthorizationRequestDescription();
    if(value == "client_credential" ||
       value === "resource_owner") {
      writeValuesToLocalStorage();
      window.location.href = "/debugger2.html";
    }
    if( value === "oidc_authorization_code_flow" ||
        value === "authorization_grant") 
    {
      $("#usePKCE-yes").prop("checked", true);
      $("#usePKCE-no").prop("checked", false);
      usePKCE = true
      $("#yesCheckOIDCArtifacts").prop("checked", true);
      $("#noCheckOIDCArtifacts").prop("checked", false);
      displayOpenIDConnectArtifacts
      $("#useRefreshToken-yes").prop("checked", true);
      $("#useRefreshToken-no").prop("checked", false);
      useRefreshTokenTester = true;
      usePKCERFC();
      writeValuesToLocalStorage();
    }
    log.debug("Leaving selection changed function().");
  });
  var value = $("#authorization_grant_type").val();
  resetUI(value);
  if( value == "client_credential" ||
      value === "resource_owner") {
    writeValuesToLocalStorage();
    window.location.href = "/debugger2.html";
  }
  if( value === "oidc_authorization_code_flow" ||
      value === "authorization_grant")
  {
    log.debug("Setting Configuration Options to Authorization Code " +
              "flow/grant.");
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
//    writeValuesToLocalStorage();
  }
  recalculateAuthorizationRequestDescription();
  initializeUIPostDebuggerInitialization();
  log.debug("Leaving ready function.");
});

function initializeUIPostDebuggerInitialization()
{
  log.debug("Entering initializeUIPostDebuggerInitialization().");
  var debuggerInitialized = false;
  if (localStorage) {
    debuggerInitialized = getLSBooleanItem("debugger_initialized");
  }
  log.debug("debugger_initialized: " + debuggerInitialized);
  if (debuggerInitialized) {
    log.debug("The debugger configuration has been initialized through " +
              "Discovery.");
    $("#oidc_fieldset").hide();
    $("#oidc_expand_button").val("Expand");
    $("#config_fieldset").hide();
    $("#config_expand_button").val("Expand");
    $("#authz_fieldset").show();
    $("#authz_expand_button").val("Collapse");
  }
  log.debug("Leaving initializeUIPostDebuggerInitialization().");
}

function resetUI(value)
{
    log.debug("Entering resetUI().");
    // Re-show the fields that the Device Authorization Grant hides, so that
    // switching back to another grant restores them.
    $("#state").closest('tr').show();
    $("#nonce_field").closest('tr').show();
    $("#redirect_uri").closest('tr').show();
    if( value == "device_authorization_grant")
    {
      $("#step2").show();
      $("#response_type").val("");
      // The device authorization request (RFC 8628 Section 3.1) only needs
      // client_id and scope; hide the fields that do not apply.
      $("#state").closest('tr').hide();
      $("#nonce_field").closest('tr').hide();
      $("#redirect_uri").closest('tr').hide();
      $("#usePKCE-yes").prop("checked", false);
      $("#usePKCE-no").prop("checked", true);
      usePKCE = false;
      usePKCERFC();
      $("#h2_title_1").html("Request Device Authorization");
      $("#authorization_endpoint_result").html("");
      $("#display_authz_request_class").show();
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
    }
    if( value == "implicit_grant" )
    {
      $("#code").hide();
      $("#step2").show();
      $("#nonce").show();
      $("#response_type").val("token");
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      $("#token_grant_type").val("");
      $("#h2_title_1").html("Request Access Token");
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#token_endpoint_result").html("");
      $("#display_authz_request_class").show();
      $("#display_token_request").hide();
    }
    if( value == "authorization_grant")
    {
      $("#code").show();
      $("#step2").show();
      $("#nonce").hide();
      $("#response_type").val("code");
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      $("#h2_title_1").html("Request Authorization Code");
      $("#authorization_endpoint_result").html("");
      $("#display_authz_request_class").show();
    }
    if ( value == "oidc_implicit_flow")
    {
      $("#code").hide();
      $("#step2").show();
      $("#nonce").show();
      $("#response_type").val("id_token token");
      if($("#scope").val() == "") {
        $("#scope").val("openid profile");
      }
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      $("#h2_title_1").html("Request Access Token");
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#display_authz_request_class").show();
      displayOpenIDConnectArtifacts = true;
    }
    if ( value == "oidc_implicit_flow_id_token")
    {
      $("#code").hide();
      $("#step2").show();
      $("#nonce").show();
      $("#response_type").val("id_token");
      if($("#scope").val() == "") {
        $("#scope").val("openid profile");
      }
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      $("#h2_title_1").html("Request Access Token");
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#display_authz_request_class").show();
      displayOpenIDConnectArtifacts = true;
    }
    if( value == "oidc_authorization_code_flow")
    {
      $("#code").show();
      $("#step2").show();
      $("#nonce").show();
      $("#response_type").val("code");
      if($("#scope").val() == "") {
        $("#scope").val("openid profile");
      }
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      $("#h2_title_1").html("Request Authorization Code");
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#display_authz_request_class").show();
      displayOpenIDConnectArtifacts = true;
    }
    if( value == "oidc_hybrid_code_id_token")
    {
      $("#code").show();
      $("#step2").show();
      $("#nonce").show();
      $("#response_type").val("code id_token");
      if($("#scope").val() == "") {
        $("#scope").val("openid profile");
      }
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      $("#h2_title_1").html("Request Authorization Code");
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#display_authz_request_class").show();
      if($("#code")){
        $("#code").val("");
      };
      displayOpenIDConnectArtifacts = true;
    }
    if( value == "oidc_hybrid_code_token")
    {
      $("#code").show();
      $("#step2").show();
      $("#nonce").show();
      $("#response_type").val("code token");
      if($("#scope").val() == "") {
        $("#scope").val("openid profile");
      }
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      $("#h2_title_1").html("Request Authorization Code");
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#display_authz_request_class").show();
      displayOpenIDConnectArtifacts = true;
    }
    if( value == "oidc_hybrid_code_id_token_token")
    {
      $("#code").show();
      $("#step2").show();
      $("#nonce").show();
      $("#response_type").val("code id_token token");
      if($("#scope").val() == "") {
        $("#scope").val("openid profile");
      }
      recalculateAuthorizationRequestDescription();
      recalculateAuthorizationErrorDescription();
      $("#h2_title_1").html("Request Authorization Code");
      $("#authorization_endpoint_result").html("");
      $("#authorization_endpoint_id_token_result").html("");
      $("#display_authz_request_class").show();
      displayOpenIDConnectArtifacts = true;
    }
    resetErrorDisplays();
    log.debug("Leaving resetUI().");
}

function resetErrorDisplays()
{
  log.debug("Entering resetErrorDisplays().");
  $("#display_authz_error_class").html("");
  log.debug("Leaving resetErrorDisplays().");
}

function writeValuesToLocalStorage()
{
  log.debug("Entering writeValuesToLocalStorage().");
  if (localStorage) {
      localStorage.setItem("authorization_grant_type",
                           $("#authorization_grant_type").val());
      localStorage.setItem("yesCheck", $("#SSLValidate-yes").is(":checked"));
      localStorage.setItem("noCheck", $("#SSLValidate-no").is(":checked"));
      localStorage.setItem("yesResourceCheck",
                           $("#yesResourceCheck").is(":checked"));
      localStorage.setItem("noResourceCheck",
                           $("#noResourceCheck").is(":checked"));
      localStorage.setItem("yesCheckOIDCArtifacts",
                           $("#yesCheckOIDCArtifacts").is(":checked"));
      localStorage.setItem("noCheckOIDCArtifacts",
                           $("#noCheckOIDCArtifacts").is(":checked"));
      localStorage.setItem("useRefreshToken_yes",
                           $("#useRefreshToken-yes").is(":checked"));
      localStorage.setItem("usePKCE_yes", $("#usePKCE-yes").is(":checked"));
      localStorage.setItem("client_id", $("#client_id").val());
      localStorage.setItem("redirect_uri", $("#redirect_uri").val());
      localStorage.setItem("scope", $("#scope").val());
      localStorage.setItem("useRefreshToken_no",
                           $("#useRefreshToken-no").is(":checked"));
      localStorage.setItem("usePKCE_no", $("#usePKCE-no").is(":checked"));
      localStorage.setItem("oidc_discovery_endpoint",
                           $("#oidc_discovery_endpoint").val());
      localStorage.setItem("metadata_source", metadataSource());
      localStorage.setItem("oidc_userinfo_endpoint",
                           $("#oidc_userinfo_endpoint").val());
      localStorage.setItem("jwks_endpoint", $("#jwks_endpoint").val());
      opMetadata.writeToLocalStorage();
      localStorage.setItem("authzcustomParametersCheck-yes",
                           $("#authzcustomParametersCheck-yes").is(":checked"));
      localStorage.setItem("authzcustomParametersCheck-no",
                           $("#authzcustomParametersCheck-no").is(":checked"));
      localStorage.setItem("authzNumberCustomParameters",
                           $("#authzNumberCustomParameters").val());
      if ( $("#authzcustomParametersCheck-yes").is(":checked")) {
        var i = 0;
        var authzNumberCustomParameters =
            parseInt($("#authzNumberCustomParameters").val());
        for(i = 0; i < authzNumberCustomParameters; i++)
        {
          if($("#customParameterName-" + i)){
            log.debug("Writing customParameterName-" + i + " as " +
                      $("#customParameterName-" + i).val() + "\n");
            localStorage.setItem("customParameterName-" + i,
                                 $("#customParameterName-" + i).val());
            log.debug("Writing customParameterValue-" + i + " as " +
                      $("#customParameterValue-" + i).val() + "\n");
            localStorage.setItem("customParameterValue-" + i,
                                 $("#customParameterValue-" + i).val());
          };
        }
      }
      setPKCEValues();
  }
  log.debug("Leaving writeValuesToLocalStorage().");
}

function initValuesToLocalStorage()
{
  log.debug("Entering initValuesToLocalStorage().");
  var initialized = getLSBooleanItem("initialized");
  if ( localStorage && 
       !initialized) {
      localStorage.setItem("authorization_grant_type",
                           "oidc_authorization_code_flow");
      localStorage.setItem("authorization_endpoint",
                           "https://localhost/oauth2/authorization");
      localStorage.setItem("token_endpoint","https://localhost/oauth2/token");
      localStorage.setItem("introspection_endpoint",
                           "https://localhost/oauth2/token/introspect");
      localStorage.setItem("revocation_endpoint",
                           "https://localhost/oauth2/revoke");
      localStorage.setItem("registration_endpoint",
                           "https://localhost/oauth2/register");
      localStorage.setItem("device_authorization_endpoint",
                           "https://localhost/oauth2/device");
      localStorage.setItem("yesResourceCheck", false);
      localStorage.setItem("noResourceCheck", true);
      localStorage.setItem("yesCheck", true);
      localStorage.setItem("noCheck", false);
      localStorage.setItem("yesCheckOIDCArtifacts", true);
      localStorage.setItem("noCheckOIDCArtifacts", false);
      localStorage.setItem("useRefreshToken_yes", true);
      localStorage.setItem("usePKCE_yes", true);
      localStorage.setItem("client_id", "abcxyz");
      localStorage.setItem("redirect_uri", (appconfig.uiUrl ?
                           appconfig.uiUrl : "http://localhost:3000") +
                           "/callback");
      localStorage.setItem("scope", "openid profile");
      localStorage.setItem("useRefreshToken_no", false);
      localStorage.setItem("usePKCE_no", false);
      localStorage.setItem("oidc_discovery_endpoint",
          METADATA_SOURCES[defaultMetadataSource()].defaultUrl);
      localStorage.setItem("oidc_userinfo_endpoint",
                           "https://localhost/oidc/userinfo");
      localStorage.setItem("jwks_endpoint",
                           "https://localhost/oidc/.well-known/jwks");
      opMetadata.initDefaults();
      localStorage.setItem("authzcustomParametersCheck-yes", false);
      localStorage.setItem("authzcustomParametersCheck-no", true);
      localStorage.setItem("authzNumberCustomParameters", 1);
      if ($("#authzcustomParametersCheck-yes").is(":checked")) {
        var i = 0;
        var authzNumberCustomParameters =
            parseInt($("#authzNumberCustomParameters").val());
        for(i = 0; i < authzNumberCustomParameters; i++)
        {
          log.debug("Writing customParameterName-" + i + " as " + "xyz" + "\n");
          localStorage.setItem("customParameterName-" + i, "xyz");
          log.debug("Writing customParameterValue-" + i + " as " + "xyz" +
                    "\n");
          localStorage.setItem("customParameterValue-" + i, "xyz");
        }
      }
      setPKCEValues();
      localStorage.setItem("initialized", "true");
      initialized = true;
  }
  log.debug("Leaving initValuesToLocalStorage().");
}

function loadValuesFromLocalStorage()
{
  log.debug("Entering loadValuesFromLocalStorage().");
  var authzGrantType = localStorage.getItem("authorization_grant_type");
  log.debug("authzGrantType=" + authzGrantType);
  if ( authzGrantType == "" || 
       typeof(authzGrantType) == "undefined" || 
       authzGrantType == "null" ||
       authzGrantType == "undefined")
  {
    $("#authorization_grant_type").val("oidc_authorization_code_flow");
    resetUI("authorization_grant");
  } else {
    $("#authorization_grant_type").val(authzGrantType);
    resetUI(authzGrantType);
  }
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
  } else {
    $("#revocation_endpoint").val("");
    $("#revocation_endpoint").closest('tr').hide();
  }

  // The Registration Endpoint is always listed in the Configuration pane.
  $("#registration_endpoint")
    .val(localStorage.getItem("registration_endpoint") || "");
  $("#registration_endpoint").closest('tr').show();

  if (!!localStorage.getItem("device_authorization_endpoint")) {
    $("#device_authorization_endpoint")
      .val(localStorage.getItem("device_authorization_endpoint"));
    $("#device_authorization_endpoint").closest('tr').show();
  } else {
    $("#device_authorization_endpoint").val("");
    $("#device_authorization_endpoint").closest('tr').hide();
  }

  // Ensure the redirect URI matches this deployment's origin (appconfig.uiUrl).
  // Heals a stale/empty/cross-origin value persisted by an earlier build or a
  // different origin, so switching sites (e.g. localhost -> test.idptools.com)
  // re-defaults the field instead of keeping the old value.
  var redirectBase = (appconfig.uiUrl ?
      appconfig.uiUrl : "http://localhost:3000");
  var storedRedirectUri = localStorage.getItem("redirect_uri");
  if (!storedRedirectUri || storedRedirectUri.indexOf(redirectBase) !== 0) {
    storedRedirectUri = redirectBase + "/callback";
    localStorage.setItem("redirect_uri", storedRedirectUri);
  }
  $("#redirect_uri").val(storedRedirectUri);
  $("#client_id").val(localStorage.getItem("client_id"));
  $("#scope").val(localStorage.getItem("scope"));
  $("#resource").val(localStorage.getItem("resource"));
  $("#SSLValidate-yes").prop("checked", getLSBooleanItem("yesCheck"));
  $("#SSLValidate-no").prop("checked", getLSBooleanItem("noCheck"));
  $("#yesResourceCheck").prop("checked", getLSBooleanItem("yesResourceCheck"));
  $("#noResourceCheck").prop("checked", getLSBooleanItem("noResourceCheck"));
  $("#yesCheckOIDCArtifacts").prop("checked",
    getLSBooleanItem("yesCheckOIDCArtifacts"));
  $("#noCheckOIDCArtifacts").prop("checked",
    getLSBooleanItem("noCheckOIDCArtifacts"));
  $("#useRefreshToken-yes").prop("checked",
    getLSBooleanItem("useRefreshToken_yes"));
  $("#useRefreshToken-no").prop("checked",
    getLSBooleanItem("useRefreshToken_no"));
  $("#usePKCE-yes").prop("checked", getLSBooleanItem("usePKCE_yes"));
  $("#usePKCE-no").prop("checked", getLSBooleanItem("usePKCE_no"));
  $("#oidc_discovery_endpoint")
    .val(localStorage.getItem("oidc_discovery_endpoint"));
  var savedSource = localStorage.getItem("metadata_source");
  $("#metadata_source_rfc8414").prop("checked", savedSource === "rfc8414");
  $("#metadata_source_oidc").prop("checked", savedSource !== "rfc8414");
  // Source-dependent UI only: never rewrite a stored URL on load.
  updateMetadataSourceUi();
  $("#oidc_userinfo_endpoint")
    .val(localStorage.getItem("oidc_userinfo_endpoint"));
  $("#jwks_endpoint").val(localStorage.getItem("jwks_endpoint"));
  opMetadata.loadFromLocalStorage();
  $("#authzcustomParametersCheck-yes").prop("checked",
    getLSBooleanItem("authzcustomParametersCheck-yes"));
  $("#authzcustomParametersCheck-no").prop("checked",
    getLSBooleanItem("authzcustomParametersCheck-no"));
  $("#authzNumberCustomParameters")
    .val(localStorage.getItem("authzNumberCustomParameters")?
    localStorage.getItem("authzNumberCustomParameters") : 1);

  $("#authz_pkce_code_challenge")
    .val(localStorage.getItem("PKCE_code_challenge"));
  $("#authz_pkce_code_verifier")
    .val(localStorage.getItem("PKCE_code_verifier"));
  $("#authz_pkce_code_method")
    .val(localStorage.getItem("PKCE_code_challenge_method"));

  recalculateAuthorizationRequestDescription();

  if ($("#authzcustomParametersCheck-yes").is(":checked")) {
    generateCustomParametersListUI();
    var i = 0;
    var authzNumberCustomParameters =
        parseInt($("#authzNumberCustomParameters").val());  
    for(i = 0; i < authzNumberCustomParameters; i++)
    {
      log.debug("Reading customParameterName-" + i + " as " +
                localStorage.getItem("customParameterName-" + i + "\n"));
      $("#customParameterName-" +
        i).val(localStorage.getItem("customParameterName-" + i));
      log.debug("Reading customParameterValue-" + i + " as " +
                localStorage.getItem("customParameterValue-" + i + "\n"));
      $("#customParameterValue-" +
        i).val(localStorage.getItem("customParameterValue-" + i));
    }
  }
  setPKCEValues();
  var agt = $("#authorization_grant_type").val();

  var pathname = window.location.pathname;
  log.debug("agt=" + agt);
  log.debug("pathname=" + pathname);
  if (  (agt ==  "authorization_grant" || 
         agt == "oidc_hybrid_code_id_token" || 
         agt == "oidc_hybrid_code_token" || 
         agt == "oidc_hybrid_code_id_token_token" ) &&
	pathname == "/callback")
  {
    log.debug("Checking for code.  agt=" + agt + ", pathname=" + pathname);
    log.debug("fragement: " + parseFragment());
    code = parseFragment()["code"];
    if(code == null || code == "null" || code == "" ||
       typeof code == "undefined")
    {
      code = "NO_CODE_PRESENTED_IN_EXPECTED_LOCATIONS";
    }
    log.debug("code=" + code);
    if($("#code").val() == "")
    {
      log.debug("code not yet set in next form. Doing so now.");
      $("#code").val(code);
    }
  }
  if ( 	(agt == "implicit_grant" || 
         agt == "oidc_implicit_flow" ) &&
	pathname == "/callback") //retrieve access_token for implicit_grant for callback redirect response
  {
    var access_token = getParameterByName("access_token",window.location.href);
    log.debug("access_token=" + access_token);
    if(access_token == null || 
       access_token == "null" || 
       access_token == "" || 
       typeof access_token == "undefined")
    {
      //Check to see if passed in as local anchor (ADFS & Azure Active Directory do this)
      log.debug("fragement: " + parseFragment());
      access_token = parseFragment()["access_token"];
      if(access_token == null || access_token == "null" || access_token == "" ||
         typeof access_token == "undefined")
      {
        access_token = "NO_ACCESS_TOKEN_PRESENTED_IN_EXPECTED_LOCATIONS";
      }
    }
    log.debug("access_token=" + access_token);
    var authorization_endpoint_result_html = "<fieldset>" +
                                             "<legend>Authorization Endpoint " +
                                                 "Results:</legend>" +
                                             "<table>" + 
                                               "<tr>" +
                                                 "<td>access_token</td>" +
                                                 "<td><textarea id=\"implicit_grant_access_token\" rows=5 cols=100>" 
                                                   + access_token + 
                                                   "</textarea>" +
                                                 "</td>" +
                                               "</tr>" + 
                                             "</table>" +
                                             "</fieldset>";
    $("#authorization_endpoint_result")
      .html(DOMPurify.sanitize(authorization_endpoint_result_html));
  }
  if (  agt == "oidc_hybrid_code_id_token_token" &&
        pathname == "/callback") //retrieve access code and id_token that is returned from authorization endpoint.
  {
    log.debug("fragement: " + parseFragment());
    access_token = parseFragment()["access_token"];
    if(	access_token == null ||
	access_token == "null" || 
	access_token == "" ||
	typeof access_token == "undefined")
    {
      access_token = "NO_ACCESS_TOKEN_PRESENTED_IN_EXPECTED_LOCATIONS";
    }
    log.debug("access_token=" + access_token);
    log.debug("fragement: " + parseFragment());
    id_token = parseFragment()["id_token"];
    if(	id_token == null ||
	id_token == "null" ||
	id_token == "" ||
	typeof id_token == "undefined")
    {
      id_token = "NO_ID_TOKEN_PRESENTED_IN_EXPECTED_LOCATIONS";
    }
    var authz_endpoint_results_html = "";
    if(displayOpenIDConnectArtifacts == true)
    {
      authz_endpoint_results_html = "<fieldset>" +
                                    "<legend>Authorization Endpoint " +
                                        "Results:</legend>" +
				    "<table>" +
				      "<tr>" +
				        "<td>access_token</td>" +
                                        "<td><textarea id=\"implicit_grant_access_token\" rows=5 cols=100>" + access_token + "</textarea></td>"
				      "</tr>" + 
				      "<tr>" +
				        "<td>id_token</td>" + 
				        "<td><textarea id=\"implicit_grant_access_token\" rows=5 " +
				            "cols=100>" + id_token + "</textarea></td>" +
				      "</tr>" +
				    "</table>" +
                                    "</fieldset>";
    } else {
      authz_endpoint_results_html = "<fieldset>" +
                                    "<legend>Authorization Endpoint " +
                                        "Results:</legend>" +
                                    "<table>" +
                                      "<tr>" +
                                        "<td>access_token</td>" +
                                        "<td><textarea id=\"implicit_grant_access_token\" rows=5 cols=100>" + access_token + "</textarea></td>"
                                      "</tr>" +
                                    "</table>" +
                                    "</fieldset>";
    }
    $("#authorization_endpoint_result")
      .html(DOMPurify.sanitize(authz_endpoint_results_html));
  }

  if (  agt == "oidc_hybrid_code_token" &&
        pathname == "/callback") //retrieve access code that is returned from authorization endpoint.
  {
    log.debug("fragement: " + parseFragment());
    access_token = parseFragment()["access_token"];
    if(	access_token == null ||
	access_token == "null" ||
	access_token == "" ||
	typeof access_token == "undefined")
    {
      access_token = "NO_ACCESS_TOKEN_PRESENTED_IN_EXPECTED_LOCATIONS";
    }
    log.debug("access_token=" + access_token);
    $("#authorization_endpoint_result").html(DOMPurify.sanitize("<fieldset>"
    + "<legend>Authorization Endpoint Results:</legend>"
    + "<table>"
    +   "<tr>"
    +     "<td>access_token</td>"
    +     "<td>"
    +       "<textarea id='implicit_grant_access_token' rows=5 cols=100>"
    +         access_token
    +       "</textarea>"
    +     "</td>"
    +   "</tr>"
    + "</table>"
    + "</fieldset>"));
  }
  if ( 	(agt == "oidc_implicit_flow" || agt == "oidc_implicit_flow_id_token" ||
      agt == "oidc_hybrid_code_id_token") && 
	pathname == "/callback") //retrieve access_token for implicit_grant for callback redirect response
  {
    var id_token = getParameterByName("id_token",window.location.href);
    log.debug("id_token=" + access_token);
    if(id_token == null || id_token == "null" || id_token == "" ||
       typeof id_token == "undefined")
    {
      //Check to see if passed in as local anchor (ADFS & Azure Active Directory do this)
      log.debug("fragement: " + parseFragment());
      id_token = parseFragment()["id_token"];
      if(id_token == null || id_token == "null" || id_token == "" ||
         typeof id_token == "undefined")
      {
        id_token = "NO_ID_TOKEN_PRESENTED_IN_EXPECTED_LOCATIONS";
      }
    }
    log.debug("id_token=" + id_token);
    $("#authorization_endpoint_id_token_result")
      .html(DOMPurify.sanitize("<fieldset>"
      +  "<legend>Authorization Endpoint Results</legend>"
      +  "<table>"
      +      "<tr>"
      +        "<td>id_token</td>"
      +        "<td>" 
      +          "<textarea id='implicit_flow_id_token' rows=5 cols=100>"
      +            id_token
      +          "</textarea>"
      +        "</td>"
      +      "</tr>"
      +    "</table>"
      +  "</fieldset>"));
  }
  var error = getParameterByName("error",window.location.href);
  var authzGrantType = $("#authorization_grant_type").val();
  if(	pathname == "/callback" && 
	(authzGrantType == "authorization_grant" ||
  authzGrantType == "implicit_grant" ||
  authzGrantType == "oidc_hybrid_code_id_token") &&
	(error != null && error != "null" && typeof error != "undefined" &&
  error != ""))
  {
    $("#display_authz_error_class").html(DOMPurify.sanitize("<fieldset>"
       + "<legend>Authorization Endpoint Error</legend><form action=''"
       + "name='display_authz_error_form'" 
       + "id='display_authz_error_form'>"
       + "<table>"
       +   "<tr>"
       +     "<td>"
       +       "<label name='display_authz_error_form_label1'"
       +         " value='' id='display_authz_error_form_label1'>Error</label>"
       +     "</td>"
       +     "<td>"
       +       "<textarea rows='10' cols='100'"
       +         " id='display_authz_error_form_textarea1'>"
       +     "</td>"
       +   "</tr>"
       + "</table>"
       + "</textarea></form></fieldset>"));
  }
  $("#state").val(generateUUID());
  localStorage.setItem('state', $("#state").val());
  $("#nonce_field").val(generateUUID());
  localStorage.setItem('nonce_field', $("#nonce_field").val());
  loadDcrValuesFromLocalStorage();
  recalculateDcrRequestDescription();
  recalculateAuthorizationRequestDescription();
  log.debug("Leaving loadValuesFromLocalStorage().");
}

function recalculateAuthorizationRequestDescription()
{
  log.debug("Entering recalculateAuthorizationRequestDescription().");
  log.debug("update request field");
  var ta1 =$("#display_authz_request_form_textarea1");
  log.debug("ta1=" + JSON.stringify(ta1));
  if ($("#authorization_grant_type").val() == "device_authorization_grant") {
    if (ta1 != null) {
      $("#display_authz_request_form_textarea1").val(
        "POST " + $("#device_authorization_endpoint").val() + "\n" +
        "Content-Type: application/x-www-form-urlencoded\n" +
        "Message Body:\n" +
        "client_id=" + $("#client_id").val() + "&\n" +
        "scope=" + $("#scope").val());
    }
    log.debug("Leaving recalculateAuthorizationRequestDescription().");
    return;
  }
  var yesCheck = $("#yesResourceCheck").is(":checked");
  log.debug("yesCheck=" + yesCheck);
  var resourceComponent = "";
  if(yesCheck) //add resource value to OAuth query string
  {
    var resource = $("#resource").val();
    if (resource != "" && typeof resource != "undefined" && resource != null &&
        resource != "null")
    {
      resourceComponent =  "&resource=" + resource;
    }
  }
  log.debug("resourceComponent=" + resourceComponent);
  var customParametersComponent = "";
  var authzcustomParametersCheck =
      $("#authzcustomParametersCheck-yes").is(":checked");
  log.debug("authzcustomParametersCheck: " + authzcustomParametersCheck +
            ", type=" + typeof(authzcustomParametersCheck));
  if(authzcustomParametersCheck) {
    const numberCustomParameters =
        parseInt($("#authzNumberCustomParameters").val());
    log.debug('numberCustomParameters=' + numberCustomParameters);
    var i = 0;
    for(i = 0; i < numberCustomParameters; i++) 
    {
         try {
           customParametersComponent = customParametersComponent +
                                       $("#customParameterName-" + i).val() +
                                       '=' + $("#customParameterValue-" +
                                           i).val() + "&" + "\n";
         } catch (e) {
           log.error("Unable to read custom parameter. Skipping.");
         }
    }
    customParametersComponent = customParametersComponent.substring(0,
        customParametersComponent.length - 2);
    log.debug('customParametersComponent=' + customParametersComponent);
  }
  if (ta1 != null)
  {
    var grant_type = $("#response_type").val();
    log.debug("grant_type=" + grant_type);
    if( grant_type == "code" ||
	grant_type == "code id_token" ||
	grant_type == "code token" ||
	grant_type == "code id_token token")
    {
      $("#display_authz_request_form_textarea1").val(                  "GET " +
        $("#authorization_endpoint").val() + "?" + "\n" +
                                                                      "state=" + $("#state").val() + "&" + "\n" +
                                                                      "nonce=" + $("#nonce_field").val() + "&" + "\n" +
                                                                      "response_type=" + $("#response_type").val() + "&" + "\n" +
                                                                      "client_id=" + $("#client_id").val() + "&" + "\n" +
                                                                      "redirect_uri=" + $("#redirect_uri").val() + "&" +"\n" +
                                                                      "scope=" + $("#scope").val());
       if ( resourceComponent.length > 0) {
         $("#display_authz_request_form_textarea1")
           .val( $("#display_authz_request_form_textarea1").val() + "&\n" +
           resourceComponent + "\n");
       }
       if (customParametersComponent.length > 0) {
         $("#display_authz_request_form_textarea1")
           .val( $("#display_authz_request_form_textarea1").val() + "&\n" +
           customParametersComponent + "\n");
       }
       if (usePKCE) {
         $("#display_authz_request_form_textarea1")
           .val( $("#display_authz_request_form_textarea1").val() + "&\n" +
           "code_challenge=" + $("#authz_pkce_code_challenge").val()  + "&\n" +
                                                                                          "code_challenge_method=" + $("#authz_pkce_code_method").val());
       }
       // OID4VCI: an authorization request that follows a Credential Offer
       // sends the offer's issuer_state back (section 4.1.1).
       var sdJwtVcIssuerState = sdJwtVc.get("sdjwtvc_issuer_state");
       if (sdJwtVcIssuerState) {
         $("#display_authz_request_form_textarea1").val(
           $("#display_authz_request_form_textarea1").val() + "&\n" +
           "issuer_state=" + encodeURIComponent(sdJwtVcIssuerState));
       }
       // And OID4VCI's other way of saying which credential is wanted: RFC 9396
       // authorization_details of type openid_credential, instead of relying on
       // the scope. The workflow decides which; this page only carries it.
       var sdJwtVcAuthzDetails = sdJwtVc.get("sdjwtvc_authorization_details");
       if (sdJwtVcAuthzDetails) {
         $("#display_authz_request_form_textarea1").val(
           $("#display_authz_request_form_textarea1").val() + "&\n" +
           "authorization_details=" + encodeURIComponent(sdJwtVcAuthzDetails));
       }
       // RFC 9449 section 10: dpop_jkt names the DPoP key the client intends to
       // use, which binds the authorization CODE to it. That closes a window
       // PKCE does not: an attacker holding both the code and the code_verifier
       // still cannot redeem it without the private key. It has to travel on
       // the authorization request, which is why it is here rather than on step
       // 2 with the rest of the DPoP pane.
       //
       // WHICH workflow's DPoP, though. This page serves two, and they answer
       // the question separately: the VC workflow decides on issuance step 2,
       // the OAuth2/OIDC workflow on debugger2.html's own DPoP pane. Reading
       // the VC switch unconditionally — which is what this did — meant that
       // turning DPoP on there put a dpop_jkt on every OAuth2/OIDC
       // authorization request too, with no control on these pages to stop it.
       var dpopJkt = sdJwtVc.isFlowActive()
         ? (sdJwtVc.dpopEnabled() ? (sdJwtVc.get(sdJwtVc.KEYS.DPOP_JKT) ||
             "") : "")
         : (oauthDpop.enabled() ? oauthDpop.jkt() : "");
       if (dpopJkt) {
         $("#display_authz_request_form_textarea1").val(
           $("#display_authz_request_form_textarea1").val() + "&\n" +
           "dpop_jkt=" + encodeURIComponent(dpopJkt));
       }
       // Recorded so the next page can report whether the code was bound, and
       // to WHICH key: a jkt sent for a key that has since been regenerated
       // makes the code unredeemable, and that is worth naming rather than
       // presenting as a mysterious invalid_grant. Written on both sides of the
       // branch, because a stale "yes it was sent" is exactly the reading that
       // would mislead.
       if (sdJwtVc.isFlowActive()) {
         sdJwtVc.set("dpop_jkt_sent", dpopJkt);
       } else {
         oauthDpop.rememberJktSent(dpopJkt);
       }
    } else if (	grant_type == "token" || 
		grant_type == "id_token token" || 
		grant_type == "id_token") {
      $("#display_authz_request_form_textarea1").val( 		      "GET " +
        $("#authorization_endpoint").val() + "?" + "\n" +
                                                                      "state=" + $("#state").val() + "&" + "\n" +
                                                                      "nonce=" + $("#nonce_field").val() + "&" + "\n" +
                                                                      "response_type=" + $("#response_type").val() + "&" + "\n" +
                                                                      "client_id=" + $("#client_id").val() + "&" + "\n" +
                                                                      "redirect_uri=" + $("#redirect_uri").val() + "&" +"\n" +
                                                                      "scope=" + $("#scope").val());
      if ( resourceComponent.length > 0) {
        $("#display_authz_request_form_textarea1")
          .val( $("#display_authz_request_form_textarea1").val() + "&" +
          resourceComponent + "\n");
      }
      if (customParametersComponent.length > 0) {
        $("#display_authz_request_form_textarea1")
          .val( $("#display_authz_request_form_textarea1").val() + "&" +
          customParametersComponent + "\n");
      }
    } else {
      $("#display_authz_request_form_textarea1").val("UNKNOWN_GRANT_TYPE");
    }
  }
  log.debug('display_authz_request_form_textarea1=' +
            $("#display_authz_request_form_textarea1").val());
  log.debug("Leaving recalculateAuthorizationRequestDescription().");
}

function triggerAuthZEndpointCall()
{
  log.debug("Entering triggerAuthZEndpointCall().");
  // The Device Authorization Grant (RFC 8628) is not a browser redirect; it is
  // an HTTP POST to the device authorization endpoint.
  if ($("#authorization_grant_type").val() == "device_authorization_grant") {
    log.debug("Leaving triggerAuthZEndpointCall().");
    return triggerDeviceAuthorizationCall();
  }
  writeValuesToLocalStorage();
  recalculateAuthorizationRequestDescription();
  // The authorization request URL is assembled from fields the user typed, so
  // it reaches this navigation sink caller-supplied. DOMPurify was applied here
  // and did nothing for it: it is an HTML sanitizer, so it returns a
  // `javascript:` URL unchanged (and escapes the `&` between query parameters).
  // The scheme allowlist is the check this sink actually needs.
  var authzRequestUrl =
      $("#display_authz_request_form_textarea1").val().substring(4,
    $("#display_authz_request_form_textarea1").val().length
  ).replace("\n","");
  try {
    window.location.href = urlSafety.safeExternalUrl(authzRequestUrl,
        'The authorization endpoint');
  } catch (e) {
    log.error("triggerAuthZEndpointCall: " + e.message);
    $("#display_authz_error_class").html(DOMPurify.sanitize(
      "<fieldset><legend>Error</legend><p>" + e.message + "</p></fieldset>"));
    log.debug("Leaving triggerAuthZEndpointCall().");
    return false;
  }
  log.debug("Leaving triggerAuthZEndpointCall().");
}

// Performs the RFC 8628 Device Authorization Request (POST to the device
// authorization endpoint, via the backend proxy to avoid browser CORS),
// stashes the resulting device_code/user_code/verification_uri in local
// storage, and proceeds to the token exchange page.
function triggerDeviceAuthorizationCall()
{
  log.debug("Entering triggerDeviceAuthorizationCall().");
  writeValuesToLocalStorage();
  recalculateAuthorizationRequestDescription();
  var sslValidate = "true";
  if ($("#SSLValidate-yes").is(":checked")) {
    sslValidate = $("#SSLValidate-yes").val();
  } else if ($("#SSLValidate-no").is(":checked")) {
    sslValidate = $("#SSLValidate-no").val();
  }
  var formData = {
    device_authorization_endpoint: $("#device_authorization_endpoint").val(),
    client_id: $("#client_id").val(),
    scope: $("#scope").val(),
    sslValidate: sslValidate
  };
  // Shared success/error handlers for the device authorization response,
  // whether it comes from the backend proxy or a direct (frontend) call.
  var onDeviceSuccess = function(data) {
    log.debug("Entering onDeviceSuccess().");
    log.debug("Device Authorization Endpoint Response: " +
              JSON.stringify(data));
    if (localStorage) {
      localStorage.setItem("device_code", data.device_code || "");
      localStorage.setItem("user_code", data.user_code || "");
      localStorage.setItem("verification_uri", data.verification_uri || "");
      localStorage.setItem("verification_uri_complete",
                           data.verification_uri_complete || "");
      localStorage.setItem("device_expires_in", data.expires_in || "");
      localStorage.setItem("device_interval", data.interval || "");
    }
    window.location.href = "/debugger2.html";
    log.debug("Leaving onDeviceSuccess().");
  };
  var onDeviceError = function(request, status, error) {
    log.debug("Entering onDeviceError().");
    log.error("An error occurred calling the device authorization endpoint.");
    log.error("request: " + JSON.stringify(request));
    log.error("status: " + JSON.stringify(status));
    var errorHtml = "<fieldset>" +
                      "<legend>Device Authorization Endpoint Error</legend>" +
                      "<table><tr><td>" +
                        "<textarea rows='6' cols='80' readonly " +
                            "id='device_authz_error_textarea' " +
                            "name='device_authz_error_textarea'></textarea>" +
                      "</td></tr></table>" +
                    "</fieldset>";
    $("#display_authz_error_class").html(DOMPurify.sanitize(errorHtml));
    $("#device_authz_error_textarea").val(
      "HTTP Status: " + (request ? request.status : "") + " " + (request ?
          request.statusText : "") + "\n" +
      "Response Body: " + (request ? request.responseText : ""));
    log.debug("Leaving onDeviceError().");
  };

  if (appconfig.backendAvailable === false) {
    // Static build (no api backend): call the device authorization endpoint
    // directly from the browser. Keycloak CORS-enables this endpoint for the
    // client's web origins (public client, no secret).
    $.ajax({
      type: "POST",
      url: $("#device_authorization_endpoint").val(),
      crossDomain: true,
      contentType: "application/x-www-form-urlencoded",
      data: "client_id=" + encodeURIComponent($("#client_id").val()) +
            "&scope=" + encodeURIComponent($("#scope").val()),
      success: onDeviceSuccess,
      error: onDeviceError
    });
  } else {
    $.ajax({
      type: "POST",
      url: appconfig.apiUrl + "/deviceauthorization",
      crossDomain: true,
      contentType: "application/json; charset=utf-8",
      data: JSON.stringify(formData),
      success: onDeviceSuccess,
      error: onDeviceError
    });
  }
  log.debug("Leaving triggerDeviceAuthorizationCall().");
  return false;
}

function onload() {
  log.debug("Entering onload().");
  log.debug("Entering onload function.");
  $("#password-form-group1").hide();
  $("#password-form-group2").hide();

  $("#authorization_endpoint").on("keypress",
    recalculateAuthorizationRequestDescription);
  $("#state").on("keypress", recalculateAuthorizationRequestDescription);
  $("#nonce_field").on("keypress", recalculateAuthorizationRequestDescription);
  $("#response_type").on("keypress",
    recalculateAuthorizationRequestDescription);
  $("#client_id").on("keypress", recalculateAuthorizationRequestDescription);
  $("#redirect_uri").on("keypress", recalculateAuthorizationRequestDescription);
  $("#scope").on("keypress", recalculateAuthorizationRequestDescription);
  $("#resource").on("keypress", recalculateAuthorizationRequestDescription);
  $("#yesResourceCheck").on("click",
    recalculateAuthorizationRequestDescription);
  $("#noResourceCheck").on("click", recalculateAuthorizationRequestDescription);
  $("#yesCheckOIDCArtifacts").on("click",
    recalculateAuthorizationRequestDescription);
  $("#noCheckOIDCArtifacts").on("click",
    recalculateAuthorizationRequestDescription);
  $("#authzcustomParametersCheck-yes").on("click",
    recalculateAuthorizationRequestDescription);
  $("#authzcustomParametersCheck-no").on("click",
    recalculateAuthorizationRequestDescription);
  $("#usePKCE-yes").on("click", usePKCERFC);
  $("#usePKCE-no").on("click", usePKCERFC);

  // Keep the Registration Endpoint in the Configuration pane and its copy in
  // the Dynamic Client Registration pane in sync (mirrors the
  // revocation_endpoint / revocation_revocation_endpoint pattern), and refresh
  // the request preview.
  $("#registration_endpoint").on("input", function () {
    $("#dcr_registration_endpoint").val($(this).val());
    recalculateDcrRequestDescription();
    writeDcrValuesToLocalStorage();
  });
  $("#dcr_registration_endpoint").on("input", function () {
    $("#registration_endpoint").val($(this).val());
    recalculateDcrRequestDescription();
    writeDcrValuesToLocalStorage();
  });
  $("#dcr_initial_access_token").on("input", function () {
    recalculateDcrRequestDescription();
    writeDcrValuesToLocalStorage();
  });
  $("#dcr_client_metadata").on("input", function () {
    recalculateDcrRequestDescription();
    writeDcrValuesToLocalStorage();
  });

  // Set initial values in case this is the first time the page was hit
  onSubmitClearAllForms(); 
  initValuesToLocalStorage();

  if (localStorage) {
    // Add an event listener for form submissions
    $("#auth_step").on("submit", function() {
      log.debug("Entering auth_step submit event listner function.");
      localStorage.setItem("client_id", $("#client_id").val());
      localStorage.setItem("scope", $("#scope").val());
      localStorage.setItem("authorization_endpoint",
                           $("#authorization_endpoint").val());
      localStorage.setItem("token_endpoint", $("#token_endpoint").val());

      if ($("#introspection_endpoint").val()) {
        localStorage.setItem("introspection_endpoint",
                             $("#introspection_endpoint").val());
      } else {
        localStorage.setItem("introspection_endpoint", "")
      }

      if (!!$("#revocation_endpoint").val()) {
        localStorage.setItem("revocation_endpoint",
                             $("#revocation_endpoint").val());
      } else {
        localStorage.setItem("revocation_endpoint", "")
      }

      if (!!$("#registration_endpoint").val()) {
        localStorage.setItem("registration_endpoint",
                             $("#registration_endpoint").val());
      } else {
        localStorage.setItem("registration_endpoint", "")
      }

      if (!!$("#device_authorization_endpoint").val()) {
        localStorage.setItem("device_authorization_endpoint",
                             $("#device_authorization_endpoint").val());
      } else {
        localStorage.setItem("device_authorization_endpoint", "")
      }

      localStorage.setItem("redirect_uri", $("#redirect_uri").val());
      localStorage.setItem("authorization_grant_type",
                           $("#authorization_grant_type").val());
      localStorage.setItem("resource", $("#resource").val());
      localStorage.setItem("yesCheck", $("#yesCheck").is(":checked"));
      localStorage.setItem("noCheck", $("#noCheck").is(":checked"));
      localStorage.setItem("yesCheckOIDCArtifacts",
                           $("#yesCheckOIDCArtifacts").is(":checked"));
      localStorage.setItem("noCheckOIDCArtifacts",
                           $("#noCheckOIDCArtifacts").is(":checked"));
      localStorage.setItem("authzcustomParametersCheck-yes",
                           $("#authzcustomParametersCheck-yes").is(":checked"));
      localStorage.setItem("authzcustomParametersCheck-no",
                           $("#authzcustomParametersCheck-no").is(":checked"));
      localStorage.setItem("usePKCE-yes", $("#usePKCE-yes").is(":checked"));
      localStorage.setItem("usePKCE-no", $("#usePKCE-no").is(":checked"));
      log.debug("Leaving auth_step submit event listener function.");
    });
  }
  loadValuesFromLocalStorage();
  restoreDiscoveryInfo();
  generateCustomParametersListUI
  recalculateAuthorizationRequestDescription();
  recalculateAuthorizationErrorDescription();
  if($("#yesResourceCheck").is(":checked"))
  {
    $("#authzResourceRow").show();
  } else {
    $("#authzResourceRow").hide();
  }
  if($("#useRefreshToken-yes").is(":checked"))
  {
    useRefreshTokenTester = $("#useRefreshToken-yes").val();
  } else if ($("#useRefreshToken-no").is(":checked")) {
    useRefreshTokenTester = $("#useRefreshToken-no").val();
  } else {
    useRefreshTokenTester = true;
  }
  var authzcustomParametersCheck =
      $("#authzcustomParametersCheck-yes").is(":checked");
  if(authzcustomParametersCheck)
  {
    $("#authzCustomParametersRow").show();
  } else {
    $("#authzCustomParametersRow").hide();
  }
  displayAuthzCustomParametersCheck();

  usePKCERFC();
  
  recalculateAuthorizationRequestDescription();

  var type = $("#response_type").val();
  if(type === "client_credential" || 
     type ==="resource_owner") {
    writeValuesToLocalStorage();
    window.location.href = "/debugger2.html";
  }
  maybeStartSdJwtVcFlow();
  log.debug("Leaving onload().");
  log.debug("Leaving onload().");
}

// ---------------------------------------------------------------------------
// SD-JWT VC issuance (?sdjwtvc=1).
//
// OID4VCI authorizes credential issuance with an ordinary OAuth 2.0 / OIDC
// Authorization Code flow, so the SD-JWT VC workflow reuses this page rather
// than reimplementing it. The query parameter is what says so: it marks the
// workflow active (which is what tells debugger2.html to come back to it once
// it has the tokens) and starts the authorization request with whatever the
// Configuration Parameters pane currently holds — which step 1 of the workflow
// has just written, since both pages keep it under the same names.
//
// Without the parameter none of this runs, so every other flow on this page is
// untouched.
// ---------------------------------------------------------------------------
function maybeStartSdJwtVcFlow() {
  if (getParameterByName("sdjwtvc") !== "1") {
    log.debug("Leaving maybeStartSdJwtVcFlow().");
    return false;
  }
  log.debug("Entering maybeStartSdJwtVcFlow().");
  sdJwtVc.startFlow();
  var banner = "<div class='vc-handoff-banner' id='sdjwtvc_banner'>" +
               "<strong>SD-JWT VC issuance</strong> — authorizing credential " +
                   "issuance through the OIDC " +
               "Authorization Code flow. You will be sent to the identity " +
                   "provider to authenticate, and back " +
               "to <a href='" + sdJwtVc.STEP2_URL + "'>step 2</a> afterwards." +
               "</div>";
  $(".container").prepend(banner);
  if (!$("#authorization_endpoint").val() || !$("#client_id").val()) {
    $("#sdjwtvc_banner").append(
      "<p class='vc-bad'>The authorization endpoint or client id is not " +
          "configured, so the flow was not " +
      "started. Go back to <a href='/vc-issuance-1.html'>step 1</a> and " +
          "retrieve the metadata.</p>");
    log.debug("Leaving maybeStartSdJwtVcFlow().");
    return false;
  }
  // An issuer-initiated issuance (OID4VCI Appendix H.1) carries an issuer_state
  // from the Credential Offer; the authorization request has to send it back so
  // the issuer can tie the two together. It rides in as a custom authorization
  // parameter, which this page already knows how to append.
  var issuerState = sdJwtVc.get("sdjwtvc_issuer_state");
  if (issuerState) {
    log.debug("SD-JWT VC issuance: adding issuer_state to the " +
              "authorization request.");
    $("#sdjwtvc_banner").append(
      "<p>The Credential Offer's <code>issuer_state</code> is being sent " +
          "with the authorization request.</p>");
  }
  var authzDetails = sdJwtVc.get("sdjwtvc_authorization_details");
  if (authzDetails) {
    log.debug("SD-JWT VC issuance: adding authorization_details to the " +
              "authorization request.");
    $("#sdjwtvc_banner").append(
      "<p>The credential is being asked for with " +
          "<code>authorization_details</code> (RFC 9396) rather than a " +
      "scope, so the token response should grant a " +
          "<code>credential_identifiers</code> value to name it with.</p>");
  }
  if (sdJwtVc.dpopEnabled()) {
    var dpopJkt = sdJwtVc.get(sdJwtVc.KEYS.DPOP_JKT) || "";
    log.debug("SD-JWT VC issuance: DPoP is on. dpop_jkt=" + (dpopJkt ||
              "(no key yet)"));
    $("#sdjwtvc_banner").append(dpopJkt
      ? "<p>DPoP is on (RFC 9449). <code>dpop_jkt=" + dpopJkt +
          "</code> is being sent with the " +
        "authorization request, which binds the authorization code to that " +
            "key \u2014 a stolen code " +
        "cannot be redeemed without it, even with the PKCE <code>code_verifier</code>.</p>"
      : "<p class='vc-pending'>DPoP is on, but no key pair has been " +
          "generated yet, so the " +
        "authorization request carries no <code>dpop_jkt</code> and the code " +
            "will not be bound. " +
        "Generate one in step 2's DPoP pane first if you want the code bound " +
            "as well as the " +
        "token.</p>");
  }

  // Let the rest of onload() finish laying the page out before navigating.
  window.setTimeout(triggerAuthZEndpointCall, 250);
  log.debug("Leaving maybeStartSdJwtVcFlow().");
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
  if($("#yesResourceCheck").is(":checked")) {
    log.debug("Showing authzResourceRow.");
    $("#authzResourceRow").show();
  } else if($("#noResourceCheck").is(":checked")) {
    log.debug("Hiding authzResourceRow.");
    $("#authzResourceRow").hide();
  }
  recalculateAuthorizationRequestDescription();
  log.debug("Leaving displayResourceCheck().");
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
    log.debug("Registered auth_step submit function.");
});

function recalculateAuthorizationErrorDescription()
{
  log.debug("Entering recalculateAuthorizationErrorDescription().");
  log.debug("update error field");
  var ta1 = $("#display_authz_error_form_textarea1");
  if (ta1 != null)
  {
    var grant_type = $("#response_type").val();
    if( grant_type == "code" ||
        grant_type == "code id_token" ||
	grant_type == "code token" ||
	grant_type == "code id_token token")
    {
      var pathname = window.location.pathname;
      log.debug("pathname=" + pathname);
      if (pathname == "/callback")
      {
        var error = getParameterByName("error",window.location.href);
        var error_description = getParameterByName("error_description",
            window.location.href);
        var error_uri = getParameterByName("error_uri",window.location.href);
        var state = getParameterByName("state", window.location.href);
        $("#display_authz_error_form_textarea1")
          .val(                          "error: " + error + "\n" +
                                                                              "error_description: " + error_description + "\n" +
                                                                              "error_uri: " + error_uri + "\n" +
                                                                              "state: " + state + "\n");
      }
    } else if (	grant_type == "token" || 
		grant_type == "id_token" ||
		grant_type == "id_token token") {
      //document.getElementById("display_authz_request_form_textarea1").value = "";
      var pathname = window.location.pathname;
      log.debug("pathname=" + pathname);
      if (pathname == "/callback")
      {
        var error = getParameterByName("error",window.location.href);
        var error_description = getParameterByName("error_description",
            window.location.href);
        var error_uri = getParameterByName("error_uri",window.location.href);
        var state = getParameterByName("state",window.location.href);
        $("#display_authz_error_form_textarea1")
          .val(                          "error: " + error + "\n" +
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
                                               "<td><textarea rows=\"10\" cols=\"100\" id=\"display_token_error_form_textarea1\"></textarea></td>" +
                                             "</tr>" +
                                           "</table>" +
                                         "</form>" +
                                       "</fieldset>";
  $("#display_token_error_class").html(display_token_error_class_html);
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
      var responseObject = JSON.parse(responseText);
      $("#display_token_error_form_textarea1")
        .val(                             "status: " + status + "\n" +
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
      var responseObject = JSON.parse(responseText);
      $("#display_token_error_form_textarea1")
        .val(                         "status: " + status + "\n" +
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
      var responseObject = JSON.parse(responseText);
      $("#display_token_error_form_textarea1")
        .val(                         "status: " + status + "\n" +
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
                                    "<legend>Token Endpoint (For Refresh) " +
                                        "Error</legend>" +
                                       "<form action=\"\" name=\"display_refresh_error_form\" id=\"display_refresh_error_form\">" +
                                         "<table>" +
                                           "<tr>" +
                                             "<td><label name=\"display_refresh_error_form_label1\" value=\"\" id=\"display_refresh_error_form_label1\">Error</label></td>" +
                                             "<td><textarea rows=\"10\" cols=\"100\" id=\"display_refresh_error_form_textarea1\"></textarea></td>" +
                                           "</tr>" +
                                         "</table>" +
                                        "</form>" +
                                      "</fieldset>";
  $("#display_refresh_error_class").html(display_refresh_error_class);
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
      var responseObject = JSON.parse(responseText);
      $("#display_refresh_error_form_textarea1")
        .val(                           "status: " + status + "\n" +
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
  var noCheck = $("#noCheckOIDCArtifacts").is(":checked");
  log.debug("yesCheckOIDCArtifacts=" + yesCheck, "noCheckOIDCArtifacts=" +
            noCheck);
  if(yesCheck) {
    displayOpenIDConnectArtifacts = true;
  } else if(noCheck) {
    displayOpenIDConnectArtifacts = false;
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

function usePKCERFC()
{
  log.debug("Entering usePKCERFC().");
  var yesCheck = $("#usePKCE-yes").is(":checked");
  var noCheck = $("#usePKCE-no").is(":checked");
  log.debug("usePKCE-yes=" + yesCheck, "useRefreshToken-no=" + noCheck);
  if (yesCheck) {
    usePKCE = true;
  } else {
    usePKCE = false;
  }
  if(usePKCE) {
    log.debug("Show PKCE Data fields.");
    $("#authz_pkce_code_challenge_row").show();
    $("#authz_pkce_code_verifier_row").show();
    $("#authz_pkce_code_method_row").show();
    $("#authz_pkce_code_challenge")
      .val(localStorage.getItem("PKCE_code_challenge"));
    $("#authz_pkce_code_verifier")
      .val(localStorage.getItem("PKCE_code_verifier"));
    $("#authz_pkce_code_method")
      .val(localStorage.getItem("PKCE_code_challenge_method"));
  } else {
    log.debug("Hide PKCE Data fields.");
    $("#authz_pkce_code_challenge_row").hide();
    $("#authz_pkce_code_verifier_row").hide();
    $("#authz_pkce_code_method_row").hide();
  }
  recalculateAuthorizationRequestDescription();
  log.debug("Leaving usePKCERFC().");
}

$("#tipText").hover(
   function(e){
       $("#tooltip").show();
   },
   function(e){
       $("#tooltip").hide();
  });

// ---------------------------------------------------------------------------
// RFC 8414 section 2.1 — signed_metadata.
//
// The metadata document may carry a JWT of itself, signed by the issuer. This
// verifies it in the browser with the Web Crypto API against a key from the
// document's own jwks_uri, and reports what RFC 8414 asks a client to check:
// the signature, that the iss claim is the issuer, and whether any signed claim
// disagrees with the plain JSON member (the signed claim takes precedence, so a
// disagreement means the JSON cannot be trusted).
// ---------------------------------------------------------------------------
var b64uToBytes = metadataClient.b64uToBytes;
var b64uToJson = metadataClient.b64uToJson;
var verifyJwsWithJwks = metadataClient.verifyJwsWithJwks;

// Button handler in the discovery pane.
function validateSignedMetadata(evt) {
  log.debug("Entering validateSignedMetadata().");
  // Keep the click off the form's onclick, which would fire a retrieval.
  if (evt && evt.stopPropagation) evt.stopPropagation();
  var out = function (text) {
    log.debug("Entering out().");
    $("#signed_metadata_status").text(text);
    log.debug("Leaving out().");
  };
  // The document this page is showing, falling back to the stored copy — so the
  // button works when the table was restored from a previous visit and not only
  // in the visit that retrieved it.
  var chosen = metadataClient.documentForValidation(
    { read: function () {
        try {
          return JSON.parse(localStorage.getItem(DISCOVERY_INFO_KEY) || "null");
        } catch (e) {
          return null;
        }
      } },
    discoveryInfo);
  if (!chosen.doc) {
    out($("#discovery_info_table").find("tr").length
      ? "The table above was drawn from a document this browser no longer " +
          "has, so there is nothing to " +
        "validate against. Retrieve it again."
      : "Retrieve a metadata document first.");
    log.debug("Leaving validateSignedMetadata().");
    return false;
  }
  metadataClient.validateSignedMetadata(chosen.doc, {
    issuerMember: "issuer",
    noSignedMetadataNote: "(signed_metadata is an RFC 8414 member; OIDC " +
        "Discovery does not define it.)",
    progress: out
  }).then(out)
    .catch(function (e) { out("Could not validate the signature: " +
           e.message); });
  log.debug("Leaving validateSignedMetadata().");
  return false;
}

// ---------------------------------------------------------------------------
// Metadata source: OpenID Connect Discovery 1.0 or RFC 8414 (OAuth 2.0
// Authorization Server Metadata).
//
// The two documents are fetched, stored, tabulated, and populated by exactly
// the same code — an RFC 8414 document is largely a subset of Discovery 1.0
// with the same member names, so populateFromDiscovery() maps it as-is, and any
// member the document omits gets the usual -->not defined<-- note. The source
// only decides which well-known path the URL should end in and which spec to
// point at.
// ---------------------------------------------------------------------------
var METADATA_SOURCES = {
  oidc: {
    wellKnown: "/.well-known/openid-configuration",
    // The dummy default this pane has always offered for an OIDC Discovery URL.
    defaultUrl: "https://localhost/oidc/.well-known",
    label: "An OIDC Discovery endpoint uses a path that ends in ",
    specUrl: "https://openid.net/specs/openid-connect-discovery-1_0.html",
    specText: "OpenID Connect Discovery 1.0",
    docLabel: "OpenID Connect Discovery 1.0"
  },
  rfc8414: {
    wellKnown: "/.well-known/oauth-authorization-server",
    // The mock authorization server the STS service publishes (empty on a
    // deployment that has no such service — the user supplies the URL).
    defaultUrl: appconfig.rfc8414MetadataUrlDefault || "",
    label: "An OAuth 2.0 Authorization Server Metadata endpoint uses a path " +
        "that ends in ",
    specUrl: "https://www.rfc-editor.org/rfc/rfc8414.html",
    specText: "RFC 8414",
    docLabel: "OAuth 2.0 Authorization Server Metadata (RFC 8414)"
  }
};

// The source a browser with nothing stored starts on.
function defaultMetadataSource() {
  log.debug("Entering defaultMetadataSource().");
  log.debug("Leaving defaultMetadataSource().");
  return "oidc";
}

function metadataSource() {
  log.debug("Entering metadataSource().");
  log.debug("Leaving metadataSource().");
  return $("#metadata_source_rfc8414").is(":checked") ? "rfc8414" : "oidc";
}

// Everything in the pane that depends on which source is selected: the hint
// (static text only — no document data goes near this markup) and the Validate
// Signature button, which only means something for RFC 8414 (signed_metadata is
// an RFC 8414 member; OIDC Discovery does not define it).
function updateMetadataSourceUi() {
  log.debug("Entering updateMetadataSourceUi().");
  var which = metadataSource();
  var src = METADATA_SOURCES[which];
  $("#metadata_source_hint").html(
    src.label + "<code>" + src.wellKnown + "</code>. See the " +
    '<a href="' + src.specUrl + '" target="_blank" rel="noopener noreferrer">' +
        src.specText + "</a> spec.");
  if (which === "rfc8414") {
    $("#signed_metadata_row").show();
  } else {
    $("#signed_metadata_row").hide();
    $("#signed_metadata_status").text("");
  }
  log.debug("Leaving updateMetadataSourceUi().");
}

// Picking a source retunes the hint and offers that source's URL:
//
//   * a URL ending in the other source's well-known path has just that suffix
//     swapped, so the host the user is pointed at is kept;
//   * a field still holding the OTHER source's default (or nothing) is replaced
//     with this source's default — that is what makes the RFC 8414 endpoint the
//     default value of the field when RFC 8414 is what you asked for;
//   * anything else the user typed is left alone.
function onMetadataSourceChange(evt) {
  log.debug("Entering onMetadataSourceChange().");
  // The enclosing <form> carries onclick="return
  // OnSubmitOIDCDiscoveryEndpointForm()", so a click on these radios would
  // otherwise bubble up, retrieve the document before the source had changed,
  // and — because that handler returns false — cancel the click's default
  // action, leaving the radio unchecked.
  if (evt && evt.stopPropagation) evt.stopPropagation();
  var src = metadataSource();
  updateMetadataSourceUi();
  var url = $("#oidc_discovery_endpoint").val() || "";
  var otherSource = METADATA_SOURCES[src === "oidc" ? "rfc8414" : "oidc"];
  if (url.length >= otherSource.wellKnown.length &&
      url.slice(-otherSource.wellKnown.length) === otherSource.wellKnown) {
    // A real endpoint: keep the host the user is pointed at, swap the path.
    $("#oidc_discovery_endpoint").val(
      url.slice(0, url.length - otherSource.wellKnown.length) +
                METADATA_SOURCES[src].wellKnown);
  } else if ((!url || url === otherSource.defaultUrl) &&
             METADATA_SOURCES[src].defaultUrl) {
    $("#oidc_discovery_endpoint").val(METADATA_SOURCES[src].defaultUrl);
  }
  if (localStorage) localStorage.setItem("metadata_source", src);
  // NOT false: this is a radio's onclick, and returning false would cancel the
  // default action, leaving the button unchecked while the rest of the page
  // acted on the new source.
  log.debug("Leaving onMetadataSourceChange().");
  return true;
}

function OnSubmitOIDCDiscoveryEndpointForm()
{
  log.debug("Entering OnSubmitOIDCDiscoveryEndpointForm(). source=" +
            metadataSource());
  writeValuesToLocalStorage();
  var oidcDiscoveryEndpoint = $("#oidc_discovery_endpoint").val();
  log.debug('URL: ' + oidcDiscoveryEndpoint);
  if (isUrl(oidcDiscoveryEndpoint)) {
    log.debug('valid URL: ' + oidcDiscoveryEndpoint);
    $.ajax({ type: 'GET',
             crossOrigin: true,
             url: oidcDiscoveryEndpoint,
             success: function(result) {
               log.debug("OIDC Discovery Endpoint Result: " +
                         JSON.stringify(result));
               discoveryInfo = result;
               saveDiscoveryInfo(result);
               parseDiscoveryInfo(result);
               buildDiscoveryInfoTable(result);
             },
             error: function (request, status, error) {
               log.debug("request: " + JSON.stringify(request));
               log.debug("status: " + JSON.stringify(status));
               log.debug("error: " + JSON.stringify(error));
             }
           });
    log.debug("Leaving OnSubmitOIDCDiscoveryEndpointForm()");
    return false;
  } else {
    log.debug('Not a valid URL.');
    log.debug("Leaving OnSubmitOIDCDiscoveryEndpointForm()");
    return false;
  }
}

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

function parseDiscoveryInfo(discoveryInfo) {
  log.debug("Entering parseDiscoveryInfo().");
  var authorizationEndpoint = discoveryInfo["authorization_endpoint"];
  var idTokenSigningAlgValuesSupported =
      discoveryInfo["id_token_signing_alg_values_supported"];
  var issuer = discoveryInfo["issuer"];
  var jwksUri = discoveryInfo["jwks_uri"];
  var responseTypesSupported = discoveryInfo["response_types_supported"];
  var scopesSupported = discoveryInfo["scopes_supported"];
  var subjectTypesSupported = discoveryInfo["subject_types_supported"];
  var tokenEndpoint = discoveryInfo["token_endpoint"];
  var tokenEndpointAuthMethodsSupported =
      discoveryInfo["token_endpoint_auth_methods_supported"];
  var introspectionEndpoint = discoveryInfo["introspection_endpoint"];
  var revocationEndpoint = discoveryInfo["revocation_endpoint"];
  var userInfoEndpoint = discoveryInfo["userinfo_endpoint"];
  var endSessionEndpoint = discoveryInfo["end_session_endpoint"];

  log.debug("authorizationEndpoint: " + authorizationEndpoint);
  log.debug("idTokenSigningAlgValuesSupported: " +
            JSON.stringify(idTokenSigningAlgValuesSupported));
  log.debug("issuer: " + issuer);
  log.debug("jwksUri: " + jwksUri);
  log.debug("responseTypesSupported: " +
            JSON.stringify(responseTypesSupported));
  log.debug("scopesSupported: " + JSON.stringify(scopesSupported));
  log.debug("subjectTypesSupported: " + JSON.stringify(subjectTypesSupported));
  log.debug("tokenEndpoint: " + tokenEndpoint);
  log.debug("tokenEndpointAuthMethodsSupported: " +
            JSON.stringify(tokenEndpointAuthMethodsSupported));
  log.debug("introspectionEndpoint: " + introspectionEndpoint);
  log.debug("revocationEndpoint: " + revocationEndpoint);
  log.debug("userInfoEndpoint: " + userInfoEndpoint);
  log.debug("endSessionEndpoint: " + endSessionEndpoint);
  log.debug("Leaving parseDiscoveryInfo()."); 
}

// Escapes a discovery value before it goes into the table markup, which is
// built by string concatenation from a document fetched off the network.
var escapeHtmlText = metadataClient.escapeHtmlText;

// ---------------------------------------------------------------------------
// The fetched discovery document is kept in local storage so the table it is
// rendered into survives a page reload. The DOCUMENT is stored, not the table
// markup: the table is rebuilt from it on load, which also restores the
// in-memory copy that "Populate Meta Data" reads — so that button keeps working
// after a refresh instead of silently populating nothing.
// ---------------------------------------------------------------------------
var DISCOVERY_INFO_KEY = opMetadata.DISCOVERY_INFO_KEY;
var DISCOVERY_SOURCE_KEY = "discovery_info_source";
// { source: "oidc" | "rfc8414", url: "<where it was fetched from>" }
var discoveryProvenance = null;

function saveDiscoveryInfo(info) {
  log.debug("Entering saveDiscoveryInfo().");
  discoveryProvenance = { source: metadataSource(),
      url: $("#oidc_discovery_endpoint").val() || "" };
  if (!localStorage) {
    log.debug("Leaving saveDiscoveryInfo().");
    return;
  }
  try {
    localStorage.setItem(DISCOVERY_INFO_KEY, JSON.stringify(info));
    localStorage.setItem(DISCOVERY_SOURCE_KEY,
                         JSON.stringify(discoveryProvenance));
  } catch (e) {
    log.error("Could not store the discovery document: " + e.message);
  }
  log.debug("Leaving saveDiscoveryInfo().");
}

// Take the table off the screen. Safe during page load: restoreDiscoveryInfo()
// puts it back from storage afterwards.
function clearDiscoveryInfoTable() {
  log.debug("Entering clearDiscoveryInfoTable().");
  $("#discovery_info_table").html("");
  // The "Populate Meta Data" button is rendered with the table; with no
  // document behind it there is nothing for it to populate from.
  $("#discovery_info_meta_data_populate").html("");
  log.debug("Leaving clearDiscoveryInfoTable().");
}

// Drop the document for good — Clear button only.
function forgetDiscoveryInfo() {
  log.debug("Entering forgetDiscoveryInfo().");
  discoveryInfo = {};
  discoveryProvenance = null;
  opMetadata.clearNotes();
  if (localStorage) {
    localStorage.removeItem(DISCOVERY_INFO_KEY);
    localStorage.removeItem(DISCOVERY_SOURCE_KEY);
  }
  clearDiscoveryInfoTable();
  log.debug("Leaving forgetDiscoveryInfo().");
}

function restoreDiscoveryInfo() {
  log.debug("Entering restoreDiscoveryInfo().");
  if (!localStorage) {
    log.debug("Leaving restoreDiscoveryInfo().");
    return;
  }
  var saved = localStorage.getItem(DISCOVERY_INFO_KEY);
  if (!saved) {
    log.debug("Leaving restoreDiscoveryInfo().");
    return;
  }
  try {
    discoveryProvenance =
        JSON.parse(localStorage.getItem(DISCOVERY_SOURCE_KEY) || "null");
  } catch (e) {
    discoveryProvenance = null;
  }
  try {
    var info = JSON.parse(saved);
    if (!info || typeof info !== "object") {
      log.debug("Leaving restoreDiscoveryInfo().");
      return;
    }
    discoveryInfo = info;
    buildDiscoveryInfoTable(info);
    // Re-apply the -->not defined<-- notes for members this document omits.
    opMetadata.applyNotes(info);
    log.debug("Restored the discovery document from local storage.");
  } catch (e) {
    log.error("Could not read the stored discovery document: " + e.message);
    localStorage.removeItem(DISCOVERY_INFO_KEY);
  }
  log.debug("Leaving restoreDiscoveryInfo().");
}

function buildDiscoveryInfoTable(discoveryInfo) {
  log.debug("Entering buildDiscoveryInfoTable().");
  var src = discoveryProvenance ?
      METADATA_SOURCES[discoveryProvenance.source] : null;
  var html = metadataClient.buildInfoTable(discoveryInfo, discoveryProvenance &&
      {
    docLabel: (src || METADATA_SOURCES.oidc).docLabel,
    url: discoveryProvenance.url
  });
  var discovery_info_meta_data_html = '<table>' +
                                      '<form>' +
                                        '<td>' +
                                          '<input class="btn_oidc_populate_meta_data" type="button" value="Populate Meta Data" onclick="return debug.onSubmitPopulateFormsWithDiscoveryInformation();"/>' +
                                        '</td>' +
                                      '</form>' +
                                      '</table>';
  $("#discovery_info_meta_data_populate").html(discovery_info_meta_data_html);
  $("#discovery_info_table").html(html);
  log.debug("Leaving buildDiscoveryInfoTable().");
}

function onSubmitPopulateFormsWithDiscoveryInformation() {
  log.debug("Entering onSubmitPopulateFormsWithDiscoveryInformation().");
  log.debug('Entering onSubmitPopulateFormsWithDiscoveryInformation().');
  var authorizationEndpoint = discoveryInfo["authorization_endpoint"];
  var idTokenSigningAlgValuesSupported =
      discoveryInfo["id_token_signing_alg_values_supported"];
  var issuer = discoveryInfo["issuer"];
  var jwksUri = discoveryInfo["jwks_uri"];
  var responseTypesSupported = discoveryInfo["response_types_supported"];
  var scopesSupported =
      discoveryInfo["scopes_supported"].toString().replace(/,/g, " ");
  var subjectTypesSupported = discoveryInfo["subject_types_supported"];
  var tokenEndpoint = discoveryInfo["token_endpoint"];
  var tokenEndpointAuthMethodsSupported =
      discoveryInfo["token_endpoint_auth_methods_supported"];
  var introspectionEndpoint = discoveryInfo["introspection_endpoint"];
  var revocationEndpoint = discoveryInfo["revocation_endpoint"];
  var registrationEndpoint = discoveryInfo["registration_endpoint"];
  var deviceAuthorizationEndpoint =
      discoveryInfo["device_authorization_endpoint"];
  var userInfoEndpoint = discoveryInfo["userinfo_endpoint"];
  var endSessionEndpoint = discoveryInfo["end_session_endpoint"];
  var issuer = discoveryInfo["issuer"];

  $("#authorization_endpoint").val(authorizationEndpoint);
  $("#token_endpoint").val(tokenEndpoint);

  if (introspectionEndpoint) {
    $("#introspection_endpoint").val(introspectionEndpoint);
    $("#introspection_endpoint").closest('tr').show();
  } else {
    $("#introspection_endpoint").val("");
    $("#introspection_endpoint").closest('tr').hide();
  }

  if (!!revocationEndpoint) {
    $("#revocation_endpoint").val(revocationEndpoint);
    $("#revocation_endpoint").closest('tr').show();
  } else {
    $("#revocation_endpoint").val("");
    $("#revocation_endpoint").closest('tr').hide();
  }

  // Auto-populate the Registration Endpoint from the discovery metadata in both
  // the Configuration pane and the Dynamic Client Registration pane copy. The
  // row is always shown.
  $("#registration_endpoint").val(registrationEndpoint || "");
  $("#dcr_registration_endpoint").val(registrationEndpoint || "");
  $("#registration_endpoint").closest('tr').show();

  if (!!deviceAuthorizationEndpoint) {
    $("#device_authorization_endpoint").val(deviceAuthorizationEndpoint);
    $("#device_authorization_endpoint").closest('tr').show();
  } else {
    $("#device_authorization_endpoint").val("");
    $("#device_authorization_endpoint").closest('tr').hide();
  }

  $("#scope").val(scopesSupported);
  $("#oidc_userinfo_endpoint").val(userInfoEndpoint);
  $("#jwks_endpoint").val(jwksUri);
  // Every remaining OpenID Provider Metadata member (Discovery 1.0 section 3).
  opMetadata.populateFromDiscovery(discoveryInfo);
  if (localStorage) {
      log.debug('Adding to local storage.');
      localStorage.setItem("authorization_endpoint", authorizationEndpoint );
      localStorage.setItem("token_endpoint", tokenEndpoint );

      if (introspectionEndpoint) {
        localStorage.setItem("introspection_endpoint", introspectionEndpoint );
      } else {
        localStorage.setItem("introspection_endpoint", "" );
      }

      if (!!revocationEndpoint) {
        localStorage.setItem("revocation_endpoint", revocationEndpoint );
      } else {
        localStorage.setItem("revocation_endpoint", "" );
      }

      if (!!registrationEndpoint) {
        localStorage.setItem("registration_endpoint", registrationEndpoint );
      } else {
        localStorage.setItem("registration_endpoint", "" );
      }

      if (!!deviceAuthorizationEndpoint) {
        localStorage.setItem("device_authorization_endpoint",
                             deviceAuthorizationEndpoint );
      } else {
        localStorage.setItem("device_authorization_endpoint", "" );
      }

      localStorage.setItem("scope", scopesSupported);
      localStorage.setItem("token_scope", scopesSupported );
      localStorage.setItem("jwks_endpoint", jwksUri);
      localStorage.setItem("end_session_endpoint", endSessionEndpoint);
      localStorage.setItem("debugger_initialized", true);
      localStorage.setItem("issuer", issuer);
  }
  // Pre-fill the Dynamic Client Registration pane (registration_endpoint and a
  // default client metadata document) from the discovery metadata.
  populateClientMetadataFromDiscovery();
  log.debug('Leaving onSubmitPopulateFormsWithDiscoveryInformation().');
  log.debug("Leaving onSubmitPopulateFormsWithDiscoveryInformation().");
  return true;
}

// Reset all forms and clear local storage
// The Clear button in the Metadata Retrieval pane.
//
// Distinct from onSubmitClearAllForms(), which only resets the DOM and IS
// CALLED ON EVERY PAGE LOAD to put the pane in a known state before the stored
// values are read back into it. Clearing storage there would wipe the user's
// configuration on every refresh — so it happens here, on the click, only.
function onClickClearAllForms() {
  log.debug("Entering onClickClearAllForms().");
  onSubmitClearAllForms();
  clearConfigurationStorage();
  forgetDiscoveryInfo();
  log.debug("Leaving onClickClearAllForms().");
  return false;
}

// Mirror the cleared pane into local storage, so the next page load does not
// restore what was just cleared.
function clearConfigurationStorage() {
  log.debug("Entering clearConfigurationStorage().");
  if (!localStorage) {
    log.debug("Leaving clearConfigurationStorage().");
    return;
  }
  ["authorization_endpoint", "token_endpoint", "introspection_endpoint",
   "revocation_endpoint", "device_authorization_endpoint",
       "registration_endpoint",
   "oidc_userinfo_endpoint", "jwks_endpoint", "oidc_discovery_endpoint",
   "client_id", "scope", "resource", "redirect_uri",
   "registration_client_uri", "registration_access_token",
   "dcr_initial_access_token", "dcr_client_metadata"].forEach(function (key) {
    localStorage.setItem(key, "");
  });
  // The select and the radio pairs are RESET rather than blanked, so store the
  // value they were reset to (their storage keys differ from the element ids).
  localStorage.setItem("authorization_grant_type",
                       "oidc_authorization_code_flow");
  localStorage.setItem("yesCheck", true);
  localStorage.setItem("noCheck", false);
  localStorage.setItem("yesCheckOIDCArtifacts", true);
  localStorage.setItem("noCheckOIDCArtifacts", false);
  localStorage.setItem("useRefreshToken_yes", true);
  localStorage.setItem("useRefreshToken_no", false);
  localStorage.setItem("usePKCE_yes", true);
  localStorage.setItem("usePKCE_no", false);
  localStorage.setItem("authzcustomParametersCheck-yes", true);
  localStorage.setItem("authzcustomParametersCheck-no", false);
  opMetadata.clearStorage();
  log.debug("Leaving clearConfigurationStorage().");
}

function onSubmitClearAllForms() {
  log.debug("Entering onSubmitClearAllForms().");
  if ($("#authorization_endpoint")) {
    $("#authorization_endpoint").val("");
  }
  if ( $("#token_endpoint")) {
     $("#token_endpoint").val("");
  }
  if ( $("#introspection_endpoint")) {
    $("#introspection_endpoint").val("");
  }
  if ( $("#revocation_endpoint")) {
    $("#revocation_endpoint").val("");
  }
  if ( $("#device_authorization_endpoint")) {
    $("#device_authorization_endpoint").val("");
  }
  if ( $("#authorization_grant_type")) {
    $("#authorization_grant_type").val("oidc_authorization_code_flow");
  }
  if ( $("#token_resource")) {
    $("#token_resource").val("");
  }
  if ( $("#SSLValidate-yes")) {
    $("#SSLValidate-yes").prop("checked", true);
  }
  if ( $("#SSLValidate-no")) {
    $("#SSLValidate-no").prop("checked", false);
  }
  if ( $("#yesCheckOIDCArtifacts")) {
    $("#yesCheckOIDCArtifacts").prop("checked", true);
  }
  if ( $("#noCheckOIDCArtifacts")) {
    $("#noCheckOIDCArtifacts").prop("checked", false);
  }
  if ( $("#useRefreshToken-yes")) {
    $("#useRefreshToken-yes").prop("checked", true);
  }
  if ( $("#useRefreshToken-no")) {
    $("#useRefreshToken-no").prop("checked", false);
  }
  if ( $("#usePKCE-yes")) {
    $("#usePKCE-yes").prop("checked", true);
  }
  if ( $("#usePKCE-no")) {
    $("#usePKCE-no").prop("checked", false);
  }

  if ( $("#refresh_client_id")) {
    $("#refresh_client_id").val("");
  }
  if ( $("#refresh_client_secret")) {
    $("#refresh_client_secret").val("");
  }
  if ( $("#refresh_scope")) {
    $("#refresh_scope").val("");
  }
  if ( $("#useRefreshToken-yes")) {
    $("#useRefreshToken-yes").prop("checked", true);
  }
  if ( $("#useRefreshToken-no")) {
    $("#useRefreshToken-no").prop("checked", false);
  }
  if ( $("#authzcustomParametersCheck-yes")) {
    $("#authzcustomParametersCheck-yes").prop("checked", true);
  }
  if ( $("#authzcustomParametersCheck-no")) {
    $("#authzcustomParametersCheck-no").prop("checked", false);
  }
  if ( $("#oidc_discovery_endpoint")) {
    $("#oidc_discovery_endpoint").val("");
  }
  $("#metadata_source_oidc").prop("checked", true);
  $("#metadata_source_rfc8414").prop("checked", false);
  updateMetadataSourceUi();
  if ( $("#client_id")) {
    $("#client_id").val("");
  }
  if ( $("#scope")) {
    $("#scope").val("");
  }
  if ( $("#resource")) {
    $("#resource").val("");
  }
  if ( $("#redirect_uri")) {
    $("#redirect_uri").val("");
  }
  if ( $("#oidc_userinfo_endpoint")) {
    $("#oidc_userinfo_endpoint").val("");
  }
  if ( $("#jwks_endpoint")) {
    $("#jwks_endpoint").val("");
  }
  if ( $("#registration_endpoint") ) {
    $("#registration_endpoint").val("");
  }
  if ( $("#dcr_registration_endpoint") ) {
    $("#dcr_registration_endpoint").val("");
  }
  if ( $("#dcr_initial_access_token") ) {
    $("#dcr_initial_access_token").val("");
  }
  if ( $("#dcr_request_textarea") ) {
    $("#dcr_request_textarea").val("");
  }
  if ( $("#dcr_client_metadata") ) {
    $("#dcr_client_metadata").val("");
  }
  if ( $("#registration_client_uri") ) {
    $("#registration_client_uri").val("");
  }
  if ( $("#registration_access_token") ) {
    $("#registration_access_token").val("");
  }
  if ( $("#dcr_response_textarea") ) {
    $("#dcr_response_textarea").val("");
  }

  // Every OpenID Provider Metadata member (Discovery 1.0 section 3), on screen.
  opMetadata.clearFields();
  clearDiscoveryInfoTable();

  log.debug("Leaving onSubmitClearAllForms().");
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

function displayAuthzCustomParametersCheck()
{
  log.debug("Entering displayAuthzCustomParametersCheck().");
  if($("#authzcustomParametersCheck-yes").is(":checked")) {
    $("#authzCustomParametersRow").show();
    $("#authzcustomParametersCheck-no").prop("checked", false);
    $("#authzcustomParametersCheck-yes").prop("checked", true);
    generateCustomParametersListUI();
  } else if($("#authzcustomParametersCheck-no").is(":checked")) {
    $("#authzCustomParametersRow").hide();
    $("#authzcustomParametersCheck-yes").prop("checked", false);
    $("#authzcustomParametersCheck-no").prop("checked", true);
    $("#authz_custom_parameter_list").html("");
  }
  recalculateAuthorizationRequestDescription();
  log.debug("Leaving displayAuthzCustomParametersCheck()");
}

function generateCustomParametersListUI()
{
  log.debug("Entering generateCustomParametersListUI().");
  var customParametersListHTML = "" +
    "<legend>Custom Parameters" +
    "</legend>" +
    "<table>" +
      "<tr>" +
        "<th>&nbsp;</th>" +
        "<th>Name</th>" +
        "<th>Value</th>" +
      "</tr>";
      var i = 0;
      var j = parseInt($("#authzNumberCustomParameters").val());
      if (j > 10) {
        j = 10; // no more than ten
      }
      for( var i = 0; i < j; i++)
      {
        customParametersListHTML = customParametersListHTML +
        "<tr>" +
          "<td>Custom Parameter #" + i + "</td>" +
          "<td>" +
            '<input class="stored" id="' + 'customParameterName-' + i +
                '" name="' + 'customParameterName-' + i +
                '" type="text" maxlength="64" size="32" />' +
          "</td>" +
          "<td>" +
            '<input class="stored" id="' + 'customParameterValue-' + i +
                '" name="' + 'customParameterValue-' + i +
                '" type="text" maxlength="128" size="64" />' +
          "</td>" +
        "</tr>";
      }
      customParametersListHTML = customParametersListHTML +
        "</table>";
      $("#authz_custom_parameter_list").html(customParametersListHTML); 
  if ( $("#authzcustomParametersCheck-yes").is(":checked")) {
    var i = 0;
    var authzNumberCustomParameters =
        parseInt($("#authzNumberCustomParameters").val());
    for(i = 0; i < authzNumberCustomParameters; i++)
    {
      $("#customParameterName-" +
        i).val(localStorage.getItem("customParameterName-" + i));
      $("#customParameterValue-" +
        i).val(localStorage.getItem("customParameterValue-" + i));
      $("#customParameterName-" + i).on("keypress",
        recalculateAuthorizationRequestDescription);
      $("#customParameterValue-" + i).on("keypress",
        recalculateAuthorizationRequestDescription);
    }
  }
  recalculateAuthorizationRequestDescription();
  log.debug("Leaving generateCustomParametersListUI().");
}

function onClickShowAuthzFieldSet(id) {
  log.debug("Entering onClickShowAuthzFieldSet(). id=" + id + ". display=" +
            $("#" + id).css("display"));
  if(id == "authz_fieldset") {
    if($("#" + id).css("display") == 'block') {
       log.debug('Hide ' + id + '.');
       $("#" + id).hide();
       $('#authz_expand_button').val("Expand");
       $('#config_fieldset').show();
       $('#config_expand_button').val("Collapse");
       $('#oidc_fieldset').show();
       $('#oidc_expand_button').val("Collapse");
    } else {
      log.debug('Show ' + id + '.');
      $("#" + id).show();
      $("#authz_expand_button").val("Collapse");
      $('#config_fieldset').hide();
      $("#config_expand_button").val("Expand");
      $('#oidc_fieldset').hide();
      $('#oidc_expand_button').val("Expand");
    }
  } else {
    if($("#" + id).css("display") == 'block') {
      log.debug('Hide ' + id + '.');
      $("#" + id).hide();
      $("#oidc_expand_button").val("Expand");
    } else {
      log.debug('Show ' + id + '.');
      $("#" + id).show();
      $("#oidc_expand_button").val("Hide");
    }
  }
  log.debug('Leaving onClickShowAuthzFieldSet().');
  log.debug("Leaving onClickShowAuthzFieldSet().");
  return false;
}

function onClickShowGenericFieldSet(id) {
  log.debug("Entering onClickShowGenericFieldSet().");
  log.debug('Entering onClickShowConfigFieldSet(). id=' 
            + id + ', style.display='
            + $("#" + id).css("display"));
  var jid = "#" + id;
  if($(jid).css("display") == 'block') {
    $(jid).val("Expand");
    $(jid).hide();
  } else {
    $(jid).val('Hide');
    $(jid).show();
  }
  log.debug('Leaving onClickShowGenericFieldSet().');
  log.debug("Leaving onClickShowGenericFieldSet().");
  return false;
}

function onClickClearLocalStorage()
{
  log.debug("Entering onClickClearLocalStorage().");
  if (localStorage) {
    localStorage.clear(); 
  }
  onSubmitClearAllForms();
  log.debug("Leaving onClickClearLocalStorage().");
  return false;
}

function generateCodeChallenge(codeVerifier) {
  log.debug("Entering generateCodeChallenge().");
  // create-hash, not require('crypto'). browserify fills a bare 'crypto' in
  // with crypto-browserify, which is the whole shim — including
  // browserify-sign and create-ecdh, and so `elliptic`, which carries
  // GHSA-848j-6mx2-7j84 with no patched version in existence. create-hash IS
  // the piece crypto-browserify uses for createHash, so this is the same
  // implementation and the same digest, minus an ECDSA implementation this
  // page never calls. Web Crypto would be the other option and is not used
  // here: crypto.subtle.digest is async, this function is called synchronously
  // from setPKCEValues(), and crypto.subtle does not exist at all on the
  // containerized suite's http://client:3000 origin.
  const createHash = require('create-hash');
  const hash = createHash('sha256');
  log.debug("Leaving generateCodeChallenge().");
  return hash.update(codeVerifier).digest("base64").replace(/=/g,
                     '').replace(/\+/g, '-').replace(/\//g, '_');
}

//function generatePKCECodeVerifier()
function setPKCEValues()
{
  log.debug("Entering setPKCEValues().");
  var code_verifier = Buffer.from(generateUUID() + generateUUID(),
      'binary').toString('base64').replace(/=/g, '').replace(/\+/g,
      '-').replace(/\//g, '_');
  log.debug("code_verifier: " + code_verifier);
  var code_challenge = generateCodeChallenge(code_verifier);
  log.debug("code_challenge: " + code_challenge);
  localStorage.setItem("PKCE_code_challenge", code_challenge);
  localStorage.setItem("PKCE_code_challenge_method", "S256");
  localStorage.setItem("PKCE_code_verifier", code_verifier );
  $("#authz_pkce_code_challenge")
    .val(localStorage.getItem("PKCE_code_challenge"));
  $("#authz_pkce_code_verifier")
    .val(localStorage.getItem("PKCE_code_verifier"));
  $("#authz_pkce_code_method")
    .val(localStorage.getItem("PKCE_code_challenge_method"));
  recalculateAuthorizationRequestDescription();
  log.debug("leaving setPKCEValues().");
  log.debug("Leaving setPKCEValues().");
  return code_challenge
}

function getLSBooleanItem(key)
{
  log.debug("Entering getLSBooleanItem().");
  log.debug("Leaving getLSBooleanItem().");
  return localStorage.getItem(key) === 'true';
}

function clickLink() {
  log.debug("Entering clickLink().");
  writeValuesToLocalStorage();
  log.debug("Leaving clickLink().");
  return true;
}

// ---- OIDC Dynamic Client Registration ----
// Implements create/read/update/delete against the OIDC Dynamic Client
// Registration endpoints (OpenID Connect Dynamic Client Registration 1.0,
// RFC 7591 for registration and RFC 7592 for the management protocol). All
// calls are proxied through the API service (POST /register) to avoid browser
// CORS restrictions, mirroring the other endpoint wrappers on this page.

// Reuse the page's SSL Certificate Validation setting for registration calls.
function getDcrSslValidate() {
  log.debug("Entering getDcrSslValidate().");
  log.debug("Leaving getDcrSslValidate().");
  return $("#SSLValidate-no").is(":checked") ? false : true;
}

// Build a default client metadata object, populated as much as possible from
// the OIDC discovery metadata (discoveryInfo) and the Redirect URL field above.
function buildDefaultClientMetadata() {
  log.debug("Entering buildDefaultClientMetadata().");
  var redirectUri = $("#redirect_uri").val();
  if (!redirectUri) {
    redirectUri = (appconfig.uiUrl ?
        appconfig.uiUrl : "http://localhost:3000") + "/callback";
  }
  // A generic, spec-aligned default client metadata document. The field names
  // and the placeholder client.example.org values follow the client metadata
  // and registration request example in OpenID Connect Dynamic Client
  // Registration 1.0 (Sections 2 and 3.1). Discovery-derived values are
  // overlaid below.
  var md = {
    application_type: "web",
    redirect_uris: [ redirectUri ],
    client_name: "OAuth2 OIDC Debugger Client",
    client_uri: "https://client.example.org/",
    logo_uri: "https://client.example.org/logo.png",
    policy_uri: "https://client.example.org/policy.html",
    tos_uri: "https://client.example.org/tos.html",
    contacts: ["admin@example.org"],
    subject_type: "public",
    token_endpoint_auth_method: "client_secret_basic",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    scope: "openid profile email",
    jwks_uri: "https://client.example.org/my_public_keys.jwks",
    id_token_signed_response_alg: "RS256",
    default_max_age: 3600,
    require_auth_time: true
  };
  if (discoveryInfo) {
    if (discoveryInfo.token_endpoint_auth_methods_supported &&
        discoveryInfo.token_endpoint_auth_methods_supported.length) {
      // Prefer a secret-based method that works without extra material (a JWKS
      // for private_key_jwt, a cert for tls_client_auth). Fall back to whatever
      // the provider lists first.
      var methods = discoveryInfo.token_endpoint_auth_methods_supported;
      var preferred = ["client_secret_basic", "client_secret_post",
          "client_secret_jwt"];
      var chosen =
          preferred.filter(function (m) { return methods.indexOf(m) >= 0; })[0];
      md.token_endpoint_auth_method = chosen || methods[0];
    }
    if (discoveryInfo.subject_types_supported &&
        discoveryInfo.subject_types_supported.length) {
      md.subject_type = discoveryInfo.subject_types_supported[0];
    }
    if (discoveryInfo.id_token_signing_alg_values_supported &&
        discoveryInfo.id_token_signing_alg_values_supported.length) {
      var algs = discoveryInfo.id_token_signing_alg_values_supported;
      var nonNone = algs.filter(function (a) { return a !== "none"; });
      md.id_token_signed_response_alg = algs.indexOf("RS256") >= 0 ?
          "RS256" : (nonNone[0] || algs[0]);
    }
    if (discoveryInfo.scopes_supported &&
        discoveryInfo.scopes_supported.length) {
      md.scope = discoveryInfo.scopes_supported.join(" ");
    }
  }
  log.debug("Leaving buildDefaultClientMetadata().");
  return md;
}

// Fill the Registration Endpoint and Client Metadata fields from discovery.
function populateClientMetadataFromDiscovery() {
  log.debug("Entering populateClientMetadataFromDiscovery().");
  if (discoveryInfo && discoveryInfo.registration_endpoint) {
    // Keep the Configuration-pane field and the DCR-pane copy in sync.
    $("#registration_endpoint").val(discoveryInfo.registration_endpoint);
    $("#dcr_registration_endpoint").val(discoveryInfo.registration_endpoint);
  }
  $("#dcr_client_metadata").val(JSON.stringify(buildDefaultClientMetadata(),
    null, 2));
  writeDcrValuesToLocalStorage();
  recalculateDcrRequestDescription();
  log.debug("Leaving populateClientMetadataFromDiscovery().");
  return false;
}

// Parse the Client Metadata textarea as JSON; surfaces a friendly error on
// failure and returns null.
function parseDcrMetadata() {
  log.debug("Entering parseDcrMetadata().");
  try {
    log.debug("Leaving parseDcrMetadata().");
    return JSON.parse($("#dcr_client_metadata").val());
  } catch (e) {
    displayDcrError(null, "Client Metadata is not valid JSON: " + e.message);
    log.debug("Leaving parseDcrMetadata().");
    return null;
  }
}

// Capture the client configuration endpoint and the (possibly rotated)
// registration access token from a registration response. Identity providers
// such as Keycloak rotate the registration_access_token on every read/update,
// returning the new value, so this must run after every successful operation
// that returns one or the subsequent call would fail to authenticate.
function captureRegistrationArtifacts(data) {
  log.debug("Entering captureRegistrationArtifacts().");
  if (!data) {
    log.debug("Leaving captureRegistrationArtifacts().");
    return;
  }
  if (data.registration_client_uri) {
    $("#registration_client_uri").val(data.registration_client_uri);
  }
  if (data.registration_access_token) {
    $("#registration_access_token").val(data.registration_access_token);
  }
  writeDcrValuesToLocalStorage();
  log.debug("Leaving captureRegistrationArtifacts().");
}

// Common proxy invocation for all four registration operations.
function callRegistrationProxy(method, url, bearerToken, metadataObj,
                               successHandler) {
  log.debug("Entering callRegistrationProxy(). method=" + method + ", url=" +
            url);
  if (!url) {
    displayDcrError(null,
        "No target URL. For create, set the Registration Endpoint; " +
      "for read/update/delete, set the Registration Client URI.");
    log.debug("Leaving callRegistrationProxy().");
    return false;
  }
  var payload = {
    method: method,
    url: url,
    bearer_token: bearerToken,
    sslValidate: getDcrSslValidate()
  };
  if (metadataObj) {
    payload.metadata = metadataObj;
  }
  $("#display_dcr_error_class").html("");
  $.ajax({
    type: "POST",
    url: appconfig.apiUrl + "/register",
    crossDomain: true,
    contentType: "application/json; charset=utf-8",
    data: JSON.stringify(payload),
    success: function (data) {
      log.debug("Registration endpoint response: " + JSON.stringify(data));
      if (successHandler) {
        successHandler(data);
      }
      displayDcrResponse(data);
    },
    error: function (request, status, error) {
      log.error("Error calling registration endpoint. status=" +
                JSON.stringify(status));
      displayDcrError(request, null);
    }
  });
  log.debug("Leaving callRegistrationProxy().");
  return false;
}

// Create (register) a new client: POST the client metadata to the Registration
// Endpoint (OIDC Registration 1.0 Section 3.1 / RFC 7591 Section 3.1).
function registerClient() {
  log.debug("Entering registerClient().");
  writeDcrValuesToLocalStorage();
  var md = parseDcrMetadata();
  if (!md) {
    log.debug("Leaving registerClient().");
    return false;
  }
  log.debug("Leaving registerClient().");
  return callRegistrationProxy("POST", $("#dcr_registration_endpoint").val(),
    $("#dcr_initial_access_token").val(), md, function (data) {
      // Capture the issued credentials and the client configuration endpoint.
      captureRegistrationArtifacts(data);
      if (data.client_id) {
        // Make the new client immediately usable by the flow above.
        $("#client_id").val(data.client_id);
        recalculateAuthorizationRequestDescription();
        if (localStorage) {
          localStorage.setItem("client_id", data.client_id);
        }
      }
      if (localStorage && typeof data.client_secret !== "undefined") {
        localStorage.setItem("client_secret", data.client_secret);
      }
    });
}

// Read the current client registration: GET the client configuration endpoint
// (RFC 7592 Section 2.1) using the registration_access_token.
function readClient() {
  log.debug("Entering readClient().");
  writeDcrValuesToLocalStorage();
  log.debug("Leaving readClient().");
  return callRegistrationProxy("GET", $("#registration_client_uri").val(),
    $("#registration_access_token").val(), null, function (data) {
      // Reflect the current registration back into the metadata editor and pick
      // up any rotated registration access token.
      captureRegistrationArtifacts(data);
      $("#dcr_client_metadata").val(JSON.stringify(data, null, 2));
      recalculateDcrRequestDescription();
    });
}

// Update the client registration: PUT the full client metadata to the client
// configuration endpoint (RFC 7592 Section 2.2).
function updateClient() {
  log.debug("Entering updateClient().");
  writeDcrValuesToLocalStorage();
  var md = parseDcrMetadata();
  if (!md) {
    log.debug("Leaving updateClient().");
    return false;
  }
  log.debug("Leaving updateClient().");
  return callRegistrationProxy("PUT", $("#registration_client_uri").val(),
    $("#registration_access_token").val(), md, function (data) {
      // Reflect the updated registration and pick up any rotated token.
      captureRegistrationArtifacts(data);
      $("#dcr_client_metadata").val(JSON.stringify(data, null, 2));
      recalculateDcrRequestDescription();
    });
}

// Delete the client registration: DELETE the client configuration endpoint
// (RFC 7592 Section 2.3).
function deleteClient() {
  log.debug("Entering deleteClient().");
  writeDcrValuesToLocalStorage();
  log.debug("Leaving deleteClient().");
  return callRegistrationProxy("DELETE", $("#registration_client_uri").val(),
    $("#registration_access_token").val(), null, null);
}

function displayDcrResponse(data) {
  log.debug("Entering displayDcrResponse().");
  $("#dcr_response_textarea").val(JSON.stringify(data, null, 2));
  log.debug("Leaving displayDcrResponse().");
}

function displayDcrError(request, message) {
  log.debug("Entering displayDcrError().");
  var text;
  if (message) {
    text = message;
  } else if (request) {
    text = "HTTP Status: " + (request.status || "") + " " +
        (request.statusText || "") + "\n" +
           "Response Body: " + (request.responseText || "");
  } else {
    text = "An unknown error occurred.";
  }
  var errorHtml = "<fieldset>" +
                    "<legend>Dynamic Client Registration Error</legend>" +
                    "<table><tr><td>" +
                      "<textarea rows='8' cols='100' readonly " +
                          "id='dcr_error_textarea' " +
                          "name='dcr_error_textarea'></textarea>" +
                    "</td></tr></table>" +
                  "</fieldset>";
  $("#display_dcr_error_class").html(DOMPurify.sanitize(errorHtml));
  $("#dcr_error_textarea").val(text);
  log.debug("Leaving displayDcrError().");
}

function writeDcrValuesToLocalStorage() {
  log.debug("Entering writeDcrValuesToLocalStorage().");
  if (localStorage) {
    // The Registration Endpoint shares the "registration_endpoint" key with the
    // Configuration pane; only persist it when set so a blank DCR copy does not
    // wipe a value entered in the Configuration pane.
    var dcrRegistrationEndpoint = $("#dcr_registration_endpoint").val();
    if (!!dcrRegistrationEndpoint) {
      localStorage.setItem("registration_endpoint", dcrRegistrationEndpoint);
    }
    localStorage.setItem("registration_client_uri",
                         $("#registration_client_uri").val());
    localStorage.setItem("registration_access_token",
                         $("#registration_access_token").val());
    localStorage.setItem("dcr_initial_access_token",
                         $("#dcr_initial_access_token").val());
    localStorage.setItem("dcr_client_metadata",
                         $("#dcr_client_metadata").val());
  }
  log.debug("Leaving writeDcrValuesToLocalStorage().");
}

function loadDcrValuesFromLocalStorage() {
  log.debug("Entering loadDcrValuesFromLocalStorage().");
  if (localStorage) {
    if (localStorage.getItem("registration_endpoint")) {
      $("#dcr_registration_endpoint")
        .val(localStorage.getItem("registration_endpoint"));
    }
    if (localStorage.getItem("registration_client_uri")) {
      $("#registration_client_uri")
        .val(localStorage.getItem("registration_client_uri"));
    }
    if (localStorage.getItem("registration_access_token")) {
      $("#registration_access_token")
        .val(localStorage.getItem("registration_access_token"));
    }
    // Initial access token: use the stored value if present (default is blank).
    $("#dcr_initial_access_token")
      .val(localStorage.getItem("dcr_initial_access_token") || "");
    // Client metadata: prefer the stored document; otherwise seed a default
    // one. Persist whatever value ends up in the field so it is available next
    // time.
    var clientMetadata = localStorage.getItem("dcr_client_metadata");
    if (!clientMetadata) {
      clientMetadata = JSON.stringify(buildDefaultClientMetadata(), null, 2);
    }
    $("#dcr_client_metadata").val(clientMetadata);
    localStorage.setItem("dcr_client_metadata", clientMetadata);
  }
  log.debug("Leaving loadDcrValuesFromLocalStorage().");
}

// Render a preview of the HTTP request that "Register New Client" will send to
// the Registration Endpoint (a POST of the client metadata, RFC 7591 Section
// 3.1), analogous to the request preview in the Request Authorization Code
// pane.
function recalculateDcrRequestDescription() {
  log.debug("Entering recalculateDcrRequestDescription().");
  var ta = $("#dcr_request_textarea");
  if (!ta || ta.length === 0) {
    log.debug("Leaving recalculateDcrRequestDescription().");
    return;
  }
  var endpoint = $("#dcr_registration_endpoint").val() ||
      $("#registration_endpoint").val() || "";
  var token = $("#dcr_initial_access_token").val();
  var request = "POST " + endpoint + "\n";
  if (!!token) {
    request += "Authorization: Bearer " + token + "\n";
  }
  request += "Content-Type: application/json\n" +
             "Accept: application/json\n" +
             "\n";
  // Pretty-print the metadata body when it is valid JSON; otherwise show it
  // as-is.
  var body = $("#dcr_client_metadata").val();
  try {
    body = JSON.stringify(JSON.parse(body), null, 2);
  } catch (e) {
    // Leave the body verbatim so the user can see/fix invalid JSON.
  }
  ta.val(request + body);
  log.debug("Leaving recalculateDcrRequestDescription().");
}

module.exports = {
  OnSubmitForm,
  OnSubmitTokenEndpointForm,
  getParameterByName,
  resetUI,
  resetErrorDisplays,
  writeValuesToLocalStorage,
  loadValuesFromLocalStorage,
  recalculateAuthorizationRequestDescription,
  generateUUID,
  displayResourceCheck,
  recalculateAuthorizationErrorDescription,
  parseFragment,
  displayOIDCArtifacts,
  useRefreshTokens,
  OnSubmitOIDCDiscoveryEndpointForm,
  onMetadataSourceChange,
  validateSignedMetadata,
  isUrl,
  parseDiscoveryInfo,
  buildDiscoveryInfoTable,
  onSubmitPopulateFormsWithDiscoveryInformation,
  onSubmitClearAllForms,
  onClickClearAllForms,
  regenerateState,
  regenerateNonce,
  displayAuthzCustomParametersCheck,
  generateCustomParametersListUI,
  triggerAuthZEndpointCall,
  onClickShowAuthzFieldSet,
  onClickShowGenericFieldSet,
  onClickClearLocalStorage,
  usePKCERFC,
  clickLink,
  registerClient,
  readClient,
  updateClient,
  deleteClient
};
