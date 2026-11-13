// File: jwks.js
// Author: Robert C. Broeckelmann Jr.
// Date: 05/28/2020
// Notes:
//
var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var $ = require("jquery");
// The token-request scope is not scopes_supported. This page's populate
// path writes the same localStorage keys the OAuth2 workflow reads.
var oauthScope = require("./oauth_scope");
var log = bunyan.createLogger({ name: 'jwks',
                                level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());
// ./jwk_pem rather than the `jwk-to-pem` package: that package builds the EC
// point through `elliptic`, which browserify then bundles into this page, and
// `elliptic` carries GHSA-848j-6mx2-7j84 with no patched version in existence.
// The local module emits byte-identical PEMs and signs nothing.
const jwkToPem = require('./jwk_pem');
// pem-file, @fidm/x509 and @peculiar/asn1-pkcs8 were required here and never
// called — the only references were the two commented-out lines below. They are
// not free imports: @fidm/x509 requires 'crypto', which browserify fills in
// with the whole crypto-browserify shim, and so this page shipped `elliptic`
// (and tweetnacl) to display a table of public keys.

// This page builds its tables by string concatenation, so anything quoted out
// of a fetched JWKS has to be escaped on the way in.
function escapeHtmlText(value) {
  log.debug("Entering escapeHtmlText().");
  log.debug("Leaving escapeHtmlText().");
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

window.onload = function() {
  log.debug("Entering onload().");
  log.debug("Entering onload function.");
  loadValuesFromLocalStorage();
  log.debug("Leaving onload().");
}

function loadValuesFromLocalStorage()
{
  log.debug("Entering loadValuesFromLocalStorage().");
  document.getElementById("jwks_endpoint").value =
                          localStorage.getItem("jwks_endpoint");
  log.debug("Leaving loadValuesFromLocalStorage().");
}

//function OnSubmitJWKSEndpointForm() {
//  log.debug("Entering OnSubmitJWKSEndpointForm().");
// }

function OnSubmitJWKSEndpointForm()
{
  log.debug("Entering OnSubmitJWKSEndpointForm().");
  var jwksEndpoint = document.getElementById("jwks_endpoint").value;
  log.debug('URL: ' + jwksEndpoint);
  if (isUrl(jwksEndpoint)) {
    log.debug('valid URL: ' + jwksEndpoint);
    $.ajax({ type: 'GET',
             crossOrigin: true,
             url: jwksEndpoint,
             success: function(result) {
               log.debug("JWKS Endpoint Result: " + JSON.stringify(result));
               jwksInfo = result;
               parseJWKSInfo(result);
               buildJWKSInfoTable(result);
             },
             error: function (request, status, error) {
               log.debug("request: " + JSON.stringify(request));
               log.debug("status: " + JSON.stringify(status));
               log.debug("error: " + JSON.stringify(error));
             }
           });
    log.debug("Leaving OnSubmitJWKSEndpointForm()");
    return false;
  } else {
    log.debug('Not a valid URL.');
    log.debug("Leaving OnSubmitJWKSEndpointForm()");
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

function parseJWKSInfo(discoveryInfo) {
  log.debug("Entering parseJWKSInfo().");
  log.debug("Leaving parseJWKSInfo().");
}

function buildJWKSInfoTable(discoveryInfo) {
  log.debug("Entering buildJWKSInfoTable().");
  var discovery_info_table_html = "";
   var i = 0;
   for( i = 0; i < discoveryInfo.keys.length; i++) {
     log.debug('iteration: ' + i);
     discovery_info_table_html = discovery_info_table_html +
                                 "<fieldset><legend>Signer Certificate #" + i +
                                     "</legend>";
     discovery_info_table_html = discovery_info_table_html +
                                    "<fieldset><legend>JWKS Format</legend>" +
                                    "<table border='2' style='border:2px;'>" +
                                    "<tr>" +
                                      "<th>Attribute</th>" +
                                      '<th style="max-width: 50px; ' +
                                          'word-wrap: break-word;">Value</th>' +
                                    "</tr>";
     // Both halves are escaped, and the NAME as well as the value: a JWKS is a
     // JSON object whose member names this page did not choose, so `key` is as
     // much someone else's string as what it points at. The textarea branch is
     // not the safer one for being a textarea — a value containing
     // "</textarea>" closes the element early and everything after it is parsed
     // as markup, which is the case that reaches the DOM as HTML.
     Object.keys(discoveryInfo.keys[i]).forEach( (key) => {
       if ( key == 'n') {
         discovery_info_table_html = discovery_info_table_html +
                                 "<tr>" +
                                   "<td>" + escapeHtmlText(key) + "</td>" +
                                   '<td><textarea id="jwks-' + i +
                                       '" name="jwks-' + i + '" rows="10" ' +
                                       'cols="70" readonly="true">' +
                                       escapeHtmlText(discoveryInfo.keys[i][key]) +
                                       "</textarea></td>" +
                                 "</tr>";
       } else {
        discovery_info_table_html = discovery_info_table_html +
                                 "<tr>" +
                                   "<td>" + escapeHtmlText(key) + "</td>" +
                                   "<td>" + escapeHtmlText(discoveryInfo.keys[i][key]) +
                                       "</td>" +
                                 "</tr>";
       }
     });

     discovery_info_table_html = discovery_info_table_html +
                                "</table></fieldset>";

     // An identity provider may publish a key this encoder does not cover — an
     // OKP key, say. `jwk-to-pem` threw on those as well, and the throw escaped
     // to the caller and left the whole JWKS table unrendered. Report the one
     // key that could not be encoded and carry on with the others. The message
     // quotes a value from a fetched document, so it cannot go into the markup
     // raw — but it is escaped at the interpolation below rather than here, so
     // that both branches are escaped exactly once. Escaping into `pem` instead
     // left the success path unescaped and the log line pre-mangled.
     var pem;
     try {
       pem = jwkToPem(discoveryInfo.keys[i]);
     } catch (e) {
       log.warn('Could not encode key ' + i + ' as a PEM: ' + e.message);
       pem = 'No PEM available for this key: ' + e.message;
     }
     log.debug('cert: ' + pem);
     discovery_info_table_html = discovery_info_table_html +
                                 "<fieldset><legend>PEM Format</legend>" +
                                 '<textarea id="x509-' + i + '" name="x509-' +
                                     i +
                                     '" rows="10" cols="70" readonly="true">' +
                                     escapeHtmlText(pem) + '</textarea>' +
                                 "</fieldset>";

    discovery_info_table_html = discovery_info_table_html +
                                "</fieldset>";

     
  }
  log.debug('certData: ' + discovery_info_table_html);
  $("#jwks_info_table").html(discovery_info_table_html);
  log.debug("Leaving buildJWKSInfoTable().");
}

// This page does not carry the OAuth2 form. Assign only when the
// element is here, and still write localStorage, which the workflow
// reads on its own pages.
function setNamedValue(id, value) {
  log.debug("Entering setNamedValue().");
  var el = document.getElementById(id);
  if (el) {
    el.value = value;
  }
  log.debug("Leaving setNamedValue().");
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
  var rawScopes = discoveryInfo["scopes_supported"];
  var scopesSupported = rawScopes == null ? "" :
      oauthScope.joinAdvertised(rawScopes);
  // No grant is selected on this page. A code exchange sends no scope,
  // which is what tokenRequestScope() returns for an empty grant.
  var tokenScope = oauthScope.tokenRequestScope("", "", "", rawScopes);
  var subjectTypesSupported = discoveryInfo["subject_types_supported"];
  var tokenEndpoint = discoveryInfo["token_endpoint"];
  var tokenEndpointAuthMethodsSupported =
      discoveryInfo["token_endpoint_auth_methods_supported"];
  var userInfoEndpoint = discoveryInfo["userinfo_endpoint"];

  setNamedValue("authorization_endpoint", authorizationEndpoint);
  setNamedValue("token_endpoint", tokenEndpoint);
  setNamedValue("token_scope", tokenScope);
  setNamedValue("scope", scopesSupported);
  setNamedValue("oidc_userinfo_endpoint", userInfoEndpoint);
  setNamedValue("jwks_endpoint", jwksUri);
  if (localStorage) {
      log.debug('Adding to local storage.');
      localStorage.setItem("authorization_endpoint", authorizationEndpoint );
      localStorage.setItem("token_endpoint", tokenEndpoint );
      if (rawScopes != null) {
        localStorage.setItem("scope", scopesSupported);
      }
      localStorage.setItem("token_scope", tokenScope);
      localStorage.setItem("jwks_endpoint", jwksUri);
  }
  log.debug('Leaving onSubmitPopulateFormsWithDiscoveryInformation().');
  log.debug("Leaving onSubmitPopulateFormsWithDiscoveryInformation().");
  return true;
}
// document.getElementById("step0").style.display = "none";

// Reset all forms and clear local storage
function onSubmitClearAllForms() {
  log.debug("Entering onSubmitClearAllForms().");
  if (localStorage) {
  }
  $("#jwks_info_table").html("");
  log.debug("Leaving onSubmitClearAllForms().");
}

function clickLink() {
  log.debug("Entering clickLink().");
  log.debug("Leaving clickLink().");
  return true;
}

module.exports = {
 loadValuesFromLocalStorage,
 OnSubmitJWKSEndpointForm,
 onSubmitClearAllForms,
 OnSubmitJWKSEndpointForm,
 isUrl,
 parseJWKSInfo,
 buildJWKSInfoTable,
 onSubmitPopulateFormsWithDiscoveryInformation,
 clickLink
};
