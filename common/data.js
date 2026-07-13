const appconfig = require(process.env.CONFIG_FILE);
const bunyan = require("bunyan");
const log = bunyan.createLogger({ name: 'common',
                                level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());

function convertToOAuth2Format(formData) {
  log.debug("Entering convertToOAuth2Format(): formData=" + JSON.stringify(formData));
  try {
    const body = formData;
    log.debug('body: ' + JSON.stringify(body));
    var grantType = body.grant_type;  				//=authorization_code
    var clientId = body.client_id;  				//=5qqbus6ukft6srjgqlijvk2465
    var code = body.code; 					//=2a795117-43d5-4d4c-bdd6-0fc9632c0594
    var redirectUri = body.redirect_uri; 			//=http%3A%2F%2Flocalhost%3A3000%2Fcallback
    var scope = body.scope || ""; 				//=openid+email+phone+profile
    var tokenEndpoint = body.token_endpoint; 			//=https%3A%2F%2Fblogpost1.auth.us-west-2.amazoncognito.com%2Foauth2%2Ftoken
    var sslValidate = body.sslValidate; 			//=true
    var clientSecret = "";
    if(!!body.client_secret) {
      clientSecret = encodeURIComponent(body.client_secret);  //=tester
    }
    var username = body.username || "";
    var password = body.password || "";
    var refreshToken = body.refresh_token || "";
    var deviceCode = body.device_code || "";
    var resource = body.resource || "";
    var customParams = body.customParams || {};
    var code_verifier = body.code_verifier;
    var auth_style = body.auth_style;

    log.debug('grantType: ' + grantType);
    log.debug('clientId: ' + clientId);
    log.debug('code: ' + code);
    log.debug('redirectUri: ' + redirectUri);
    log.debug('scope: ' + scope);
    log.debug('tokenEndpoint: ' + tokenEndpoint);
    log.debug('sslValidate: ' + sslValidate);
    log.debug('clientSecret: ' + clientSecret);
    log.debug('username: ' + username);
    log.debug('password: ' + password);
    log.debug('refreshToken: ' + refreshToken);
    log.debug('resource: ' + resource);
    Object.keys(customParams).forEach( (key) => {
      log.debug(key + ':' + customParams[key]);
    });
    log.debug("code_verifier: " + code_verifier);
    log.debug("auth_style: " + auth_style);
    var parameterObject = {};
    if(grantType == "authorization_code") {
      parameterObject = {
        grant_type: grantType,
        client_id: clientId,
        code: code,
        redirect_uri: redirectUri,
      };
      if (!!code_verifier) {
        parameterObject.code_verifier = code_verifier
      }
      log.debug("clientSecret: " + clientSecret);
      log.debug("auth_style: " + auth_style);
      if (!!clientSecret && auth_style) {
        parameterObject.client_secret = clientSecret;
      }
    } else if(grantType == "client_credentials") {
       parameterObject =  {
         grant_type: grantType
       };
       log.debug("clientSecret: " + clientSecret);
       log.debug("auth_style: " + auth_style);
       if (!!clientSecret
           && auth_style) {
         parameterObject.client_secret = clientSecret;
       }
    } else if(grantType == "password") {
       parameterObject = {
        grant_type: grantType,
        username: username,
        password: password
       };
       log.debug("clientSecret: " + clientSecret);
       log.debug("auth_style: " + auth_style);
       if (!!clientSecret && auth_style) {
         parameterObject.client_secret = clientSecret;
       }
    } else if(grantType == "refresh_token") {
      parameterObject = {
        grant_type: grantType,
        client_id: clientId,
        refresh_token: refreshToken,
      };
      log.debug("clientSecret: " + clientSecret);
      log.debug("auth_style: " + auth_style);
      if (!!clientSecret
         && auth_style) {
        parameterObject.client_secret = clientSecret;
      }
    } else if(grantType == "urn:ietf:params:oauth:grant-type:device_code") {
      // RFC 8628 Device Access Token Request.
      parameterObject = {
        grant_type: grantType,
        client_id: clientId,
        device_code: deviceCode,
      };
      log.debug("clientSecret: " + clientSecret);
      log.debug("auth_style: " + auth_style);
      if (!!clientSecret
         && auth_style) {
        parameterObject.client_secret = clientSecret;
      }
    }
    if(auth_style) {
        parameterObject.client_id = clientId;
    }
    if(!!resource) {
      parameterObject.resource = resource;
    }

    if(!!scope) {
      parameterObject.scope = scope;
    }
    if (Object.keys(customParams).length > 0) {
      Object.keys(customParams).forEach( (key) => {
        parameterObject[key] = customParams[key];
      });
    }
    log.debug("parameterObject: " + JSON.stringify(parameterObject));

    var parameterString = "";
    Object.keys(parameterObject).forEach( (key) => {
      parameterString = parameterString +
                      key +
                      "=" +
                      parameterObject[key] +
                      "&";
    });
    parameterString = parameterString.substring(0, parameterString.length - 1);
    log.debug("Leaving convertToOAuth2Format().");
    return parameterString;
  } catch (e) {
    log.error("An error occurred: " + e);
  }
}

module.exports = {
  convertToOAuth2Format
};
