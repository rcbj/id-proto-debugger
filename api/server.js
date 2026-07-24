'use strict';

var appconfig = require(process.env.CONFIG_FILE);
const express = require('express');
const expressLogging = require('express-logging');
const bunyan = require("bunyan");
const axios = require('axios');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const { convertToOAuth2Format  } = require('./data.js');

// Constants
const PORT = appconfig.port || 4000;
const HOST = appconfig.host || '0.0.0.0';
const LOG_LEVEL = appconfig.logLevel || 'debug';
const uiUrl = appconfig.uiUrl || 'http://localhost:3000';

const STATUS_200 = 200;
const STATUS_400 = 400;
const STATUS_401 = 401;
const STATUS_403 = 403;
const STATUS_404 = 404;
const STATUS_500 = 500;

var log = bunyan.createLogger({ name: 'server',
                                level: LOG_LEVEL });
log.info("Log initialized. logLevel=" + log.level());

// Ephemeral, in-memory store for SAML exchanges. The ACS endpoint stashes the
// (potentially large) SAMLResponse here and redirects the browser to the client
// results page with a short id; the client then fetches the XML by id. This is
// deliberate, single-instance, short-lived state (the app is otherwise
// stateless) — not for the static/backend-less deployment.
var samlExchanges = new Map();
const SAML_EXCHANGE_TTL_MS = 10 * 60 * 1000; // 10 minutes
function sweepSamlExchanges() {
  var now = Date.now();
  samlExchanges.forEach(function (v, k) {
    if (now - v.createdAt > SAML_EXCHANGE_TTL_MS) samlExchanges.delete(k);
  });
}
function stashSamlResponse(xml, relayState) {
  sweepSamlExchanges();
  var id = crypto.randomBytes(16).toString('hex');
  samlExchanges.set(id, { responseXml: xml, relayState: relayState || '', createdAt: Date.now() });
  return id;
}

// When a request asks for the artifact response binding, the SP context needed
// to resolve the artifact later (ARS URL + SP signing key) is stashed here and
// referenced by the RelayState (art:<id>) the IdP echoes back to the ACS.
var samlArtifactCtx = new Map();
function stashArtifactCtx(ctx) {
  sweepSamlArtifactCtx();
  var id = crypto.randomBytes(16).toString('hex');
  samlArtifactCtx.set(id, Object.assign({ createdAt: Date.now() }, ctx));
  return id;
}
function sweepSamlArtifactCtx() {
  var now = Date.now();
  samlArtifactCtx.forEach(function (v, k) {
    if (now - v.createdAt > SAML_EXCHANGE_TTL_MS) samlArtifactCtx.delete(k);
  });
}

// jwt.xml is a local copy of https://www.iana.org/assignments/jwt/jwt.xml.
// A local copy is used to avoid latency and availability issues fetching the
// online copy from IANA, which has been an ongoing reliability problem.
var claimDescriptions = fs.readFileSync(path.join(__dirname, 'jwt.xml'), 'utf8');
var cachedClaimDescriptions = true;

const app = express();
const expressSwagger = require('express-swagger-generator')(app);

app.use(bodyParser.json());
// SAML ACS receives application/x-www-form-urlencoded POSTs (SAMLResponse,
// RelayState, SAMLart) from the IdP; enable urlencoded parsing for those.
app.use(bodyParser.urlencoded({ extended: true, limit: '5mb' }));
var corsOptions = {
  origin: '*',
  optionsSuccessStatus: 204
};
// app.use(expressLogging(logger));
app.options("*", cors(corsOptions));
app.use(cors(corsOptions));

/**
 * @typedef HealthcheckResponse
 * @property {string} message - Status message
 */
/**
 * System healthcheck
 * @route GET /healthcheck
 * @group System - Support operations
 * @returns {HealthcheckResponse.model} 200 - Health Check Response
 * @returns {Error.model} 400 - Syntax error
 * @returns {Error.model} 500 - Unexpected error
 */
app.get('/healthcheck', function (req, res) {
  res
  .status(STATUS_200)
  .json({ message: 'Success' });
});

/**
 * Retrieve Claims Description.
 * @route GET /claimdescription
 * @group Metadata - Support operations
 * @returns {HealthcheckResponse.model} 200 - Claim Description Response
 * @returns {Error.model} 400 - Syntax error
 * @returns {Error.model} 500 - Unexpected error
 */
app.get('/claimdescription', function(req, res) {
  console.log("Entering GET /claimdescription.");
  try {
    if(cachedClaimDescriptions) {
      console.debug("Using cached claim descriptions.");
      res
      .append('Content-Type', 'application/xml')
      .status(STATUS_200)
      .send(claimDescriptions);
    } else {
      log.debug("Pulling claim descriptions");
      fetch("https://www.iana.org/assignments/jwt/jwt.xml")
      .then((response) => {
        response
        .text()
        .then( (text) => {
          log.debug("Retrieved: " + text);
          res
          .append('Content-Type', 'application/xml')
          .send(text);
          cachedClaimDescriptions = true;
          claimDescriptions = text;
        });
      })
      .catch(function (error) {
        log.error('Error from claimsdescription endpoint: ' + error.stack);
      if(!!error.response) {
        if(!!error.response.status) {
          log.error("Error Status: " + error.response.status);
        }
        if(!!error.response.data) {
          log.error("Error Response body: " + JSON.stringify(error.response.data));
        }
        if(!!error.response.headers) {
          log.error("Error Response headers: " + error.response.headers);
        }
        if (!!error.response) {
          res.status(error.response.status);
          res.json(error.response.data);
        } else {
          res.status(STATUS_500);
          res.json(error.message);
        }
      }
    });
   }
  } catch(e) {
    log.error("An error occurred while retrieving the claim description XML: " + e.stack);
    res.status(STATUS_500)
       .render('error', { error: e });
  }
});

/**
 * Proxy-fetch a SAML metadata document server-side.
 *
 * The SAML config page needs the IdP's metadata XML, but fetching it directly
 * from the browser is blocked by CORS (the IdP descriptor endpoint sends no
 * Access-Control-Allow-Origin). This endpoint fetches it on the server and
 * returns the XML. Like the token proxy, it fetches a caller-supplied URL, so
 * it is a dev/debugger-only tool (SSRF by design); do not expose publicly.
 *
 * The target URL is passed base64-encoded in ?url= to survive query escaping.
 * @route GET /samlmetadata
 * @group SAML - SAML support operations
 * @returns {string} 200 - The metadata XML document
 * @returns {Error.model} 400 - Missing/invalid url parameter
 * @returns {Error.model} 500 - Fetch error
 */
app.get('/samlmetadata', function (req, res) {
  log.debug('Entering GET /samlmetadata.');
  var target;
  try {
    target = Buffer.from(String(req.query.url || ''), 'base64').toString('utf8').trim();
  } catch (e) {
    return res.status(STATUS_400).json({ error: 'Invalid url parameter (expected base64).' });
  }
  if (!/^https?:\/\//i.test(target)) {
    return res.status(STATUS_400).json({ error: 'url must be an absolute http(s) URL.' });
  }
  var https = require('https');
  axios.get(target, {
    responseType: 'text',
    // Allow self-signed IdP TLS in test/dev environments.
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    headers: { 'Accept': 'application/samlmetadata+xml, application/xml, text/xml, */*' }
  })
  .then(function (response) {
    res.append('Content-Type', 'application/xml').status(STATUS_200).send(response.data);
  })
  .catch(function (error) {
    log.error('Error fetching SAML metadata from ' + target + ': ' + (error && error.stack ? error.stack : error));
    if (error && error.response) {
      res.status(error.response.status || STATUS_500).send(String(error.response.data || 'metadata fetch failed'));
    } else {
      res.status(STATUS_500).json({ error: 'metadata fetch failed: ' + (error && error.message ? error.message : String(error)) });
    }
  });
});

// ---------------------------------------------------------------------------
// SAML request signing.
//
// Signing is done server-side because the HTTP-POST binding needs an enveloped
// XML digital signature (XML-DSIG / exclusive C14N), which is impractical in the
// browser. The browser posts the unsigned AuthnRequest XML plus the SP private
// key; this returns what the browser needs to reach the IdP:
//   * redirect (and artifact response) binding: a full GET Location URL whose
//     query string (SAMLRequest DEFLATE+base64, SigAlg, Signature) is signed
//     per the SAML HTTP-Redirect binding (signature over the octet string, NOT
//     an XML signature).
//   * post binding: { location, params:{ SAMLRequest, RelayState } } for the
//     browser to auto-submit; SAMLRequest is base64 of the enveloped-signed XML.
// The SP private key is transmitted to this local API; keep this dev-only.
// ---------------------------------------------------------------------------
function xmlTextEscape(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function signXmlEnveloped(xml, privateKeyPem, certPem, rootLocalName) {
  var root = rootLocalName || 'AuthnRequest';
  var xmlcrypto = require('xml-crypto');
  var SignedXml = xmlcrypto.SignedXml;
  // The root element's ID becomes the signature Reference URI (#ID).
  var m = xml.match(/\bID="([^"]+)"/);
  var id = m ? m[1] : '';
  var sig = new SignedXml({
    privateKey: privateKeyPem,
    publicCert: certPem || undefined
  });
  sig.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
  sig.canonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#';
  sig.addReference({
    xpath: "/*[local-name(.)='" + root + "']",
    transforms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#'
    ],
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
    uri: id ? ('#' + id) : ''
  });
  // Per the SAML schema the <Signature> must follow <Issuer>.
  sig.computeSignature(xml, {
    location: { reference: "/*[local-name(.)='" + root + "']/*[local-name(.)='Issuer']", action: 'after' }
  });
  return sig.getSignedXml();
}

/**
 * Sign a SAML AuthnRequest for the chosen binding.
 * @route POST /samlsign
 * @group SAML - SAML support operations
 */
app.post('/samlsign', function (req, res) {
  log.debug('Entering POST /samlsign.');
  try {
    var b = req.body || {};
    var binding = b.binding || 'redirect';
    var xml = b.xml;
    var dest = b.destination;
    var privateKeyPem = b.privateKeyPem;
    var certPem = b.certPem || '';
    var sigAlg = b.sigAlg || 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    var relayState = b.relayState || '';
    var rootElement = b.rootElement || 'AuthnRequest'; // AuthnRequest | LogoutRequest
    if (!xml || !privateKeyPem) {
      return res.status(STATUS_400).json({ error: 'xml and privateKeyPem are required.' });
    }

    if (binding === 'post') {
      var signedXml = signXmlEnveloped(xml, privateKeyPem, certPem, rootElement);
      var params = { SAMLRequest: Buffer.from(signedXml, 'utf8').toString('base64') };
      if (relayState) params.RelayState = relayState;
      // signedXml is also returned so the UI can display the enveloped-signed
      // document (e.g. the "Build Request" button).
      return res.json({ mode: 'post', location: dest || '', params: params, signedXml: signedXml });
    }

    // redirect binding (also used to send the request when the response is
    // requested via the artifact binding). For artifact responses, stash the SP
    // context needed to resolve the artifact and carry its id in RelayState.
    if (binding === 'artifact') {
      var ctxId = stashArtifactCtx({
        arsUrl: b.arsUrl || '',
        privateKeyPem: privateKeyPem,
        certPem: certPem,
        spEntityId: b.spEntityId || '',
        sigAlg: sigAlg
      });
      relayState = 'art:' + ctxId;
    }
    // HTTP-Redirect binding signature (saml-bindings-2.0-os §3.4.4.1): sign the
    // octet string SAMLRequest[&RelayState]&SigAlg (URL-encoded, in that order),
    // then append &Signature. It is a detached signature over the query string,
    // NOT an XML signature in the document.
    var deflated = zlib.deflateRawSync(Buffer.from(xml, 'utf8'));
    var samlRequest = deflated.toString('base64');
    var qs = 'SAMLRequest=' + encodeURIComponent(samlRequest);
    if (relayState) qs += '&RelayState=' + encodeURIComponent(relayState);
    qs += '&SigAlg=' + encodeURIComponent(sigAlg);
    var signer = crypto.createSign('RSA-SHA256');
    signer.update(qs);
    var signature = signer.sign(privateKeyPem, 'base64');
    qs += '&Signature=' + encodeURIComponent(signature);
    // Full GET URL when a destination is known; otherwise just the signed query
    // string (e.g. "Build Request" before metadata is loaded).
    var location = dest ? (dest + (dest.indexOf('?') >= 0 ? '&' : '?') + qs) : qs;
    return res.json({ mode: 'redirect', location: location, queryString: qs });
  } catch (e) {
    log.error('samlsign: ' + (e && e.stack ? e.stack : e));
    res.status(STATUS_500).json({ error: 'sign failed: ' + (e && e.message ? e.message : String(e)) });
  }
});

/**
 * Register SP context for an artifact-response flow. AuthnRequest signing now
 * happens in the browser, but resolving the artifact at the ACS is a server-side
 * SOAP back-channel that needs the SP signing key + the IdP's ARS URL. The
 * browser registers them here and gets back the RelayState (art:<id>) to carry
 * in its (browser-signed) redirect request.
 * @route POST /samlartifactctx
 * @group SAML - SAML support operations
 */
app.post('/samlartifactctx', function (req, res) {
  var b = req.body || {};
  if (!b.privateKeyPem || !b.arsUrl) {
    return res.status(STATUS_400).json({ error: 'privateKeyPem and arsUrl are required.' });
  }
  var id = stashArtifactCtx({
    arsUrl: b.arsUrl,
    privateKeyPem: b.privateKeyPem,
    certPem: b.certPem || '',
    spEntityId: b.spEntityId || '',
    sigAlg: b.sigAlg || 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    // Optional WS-Addressing headers for the ArtifactResolve SOAP envelope.
    wsa: b.wsa || {}
  });
  res.json({ relayState: 'art:' + id });
});

// Decode a SAML protocol message from a binding parameter: POST binding is raw
// base64 XML; Redirect binding is DEFLATE (raw) then base64.
function decodeSamlMessage(b64) {
  var buf = Buffer.from(String(b64 || ''), 'base64');
  if (buf.length && buf[0] === 0x3c /* '<' */) return buf.toString('utf8');
  try { return zlib.inflateRawSync(buf).toString('utf8'); }
  catch (e) { return buf.toString('utf8'); }
}

// Pull the <samlp:Response> element out of a SOAP <ArtifactResponse> envelope.
function extractResponseFromArtifactResponse(soapXml) {
  var xmldom = require('@xmldom/xmldom');
  var xpath = require('xpath');
  var doc = new xmldom.DOMParser().parseFromString(soapXml, 'text/xml');
  var nodes = xpath.select(
    "//*[local-name(.)='Response' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']",
    doc
  );
  if (!nodes || !nodes.length) return '';
  return new xmldom.XMLSerializer().serializeToString(nodes[0]);
}

// Resolve an artifact via the SOAP back-channel: build + sign an ArtifactResolve
// with the SP context stashed at request time (looked up via RelayState), POST
// it to the IdP's Artifact Resolution Service, and return the embedded Response.
function resolveArtifact(artifact, relayState) {
  return new Promise(function (resolve, reject) {
    var ctxId = (relayState && relayState.indexOf('art:') === 0) ? relayState.slice(4) : '';
    var ctx = ctxId ? samlArtifactCtx.get(ctxId) : null;
    if (!ctx || !ctx.arsUrl) {
      return reject(new Error('no artifact context / ARS URL (RelayState missing or expired)'));
    }
    var id = '_' + crypto.randomBytes(16).toString('hex');
    var instant = new Date().toISOString();
    var ar = '<samlp:ArtifactResolve xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
             ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
             ' ID="' + id + '" Version="2.0" IssueInstant="' + instant + '">' +
             '<saml:Issuer>' + (ctx.spEntityId || '') + '</saml:Issuer>' +
             '<samlp:Artifact>' + artifact + '</samlp:Artifact>' +
             '</samlp:ArtifactResolve>';
    var signed;
    try { signed = signXmlEnveloped(ar, ctx.privateKeyPem, ctx.certPem, 'ArtifactResolve'); }
    catch (e) { return reject(new Error('signing ArtifactResolve failed: ' + e.message)); }

    // Optional WS-Addressing SOAP headers. WS-Addressing is a SOAP-layer
    // mechanism (not part of the AuthnRequest); it applies only to this SOAP
    // ArtifactResolve back-channel.
    var wsa = ctx.wsa || {};
    var wsaNs = '';
    var soapHeader = '';
    if (wsa.enabled) {
      wsaNs = ' xmlns:wsa="http://www.w3.org/2005/08/addressing"';
      var to = wsa.to || ctx.arsUrl;
      var msgId = wsa.messageId || ('urn:uuid:' + crypto.randomUUID());
      var hdr = '<wsa:MessageID>' + xmlTextEscape(msgId) + '</wsa:MessageID>' +
                '<wsa:To>' + xmlTextEscape(to) + '</wsa:To>';
      if (wsa.action) hdr += '<wsa:Action>' + xmlTextEscape(wsa.action) + '</wsa:Action>';
      if (wsa.replyTo) hdr += '<wsa:ReplyTo><wsa:Address>' + xmlTextEscape(wsa.replyTo) + '</wsa:Address></wsa:ReplyTo>';
      if (wsa.from) hdr += '<wsa:From><wsa:Address>' + xmlTextEscape(wsa.from) + '</wsa:Address></wsa:From>';
      soapHeader = '<soap:Header>' + hdr + '</soap:Header>';
    }
    var soap = '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"' + wsaNs + '>' +
               soapHeader + '<soap:Body>' + signed + '</soap:Body></soap:Envelope>';
    var https = require('https');
    axios.post(ctx.arsUrl, soap, {
      headers: { 'Content-Type': 'text/xml; charset=utf-8', 'SOAPAction': '""' },
      httpsAgent: new https.Agent({ rejectUnauthorized: false }),
      responseType: 'text'
    }).then(function (resp) {
      var respXml = extractResponseFromArtifactResponse(resp.data);
      if (!respXml) return reject(new Error('no <Response> found in ArtifactResponse'));
      resolve(respXml);
    }).catch(function (e) {
      reject(new Error('ARS SOAP call failed: ' + (e && e.message ? e.message : String(e))));
    });
  });
}

/**
 * SAML Assertion Consumer Service (ACS). Receives the IdP's SAMLResponse
 * (POST form field or GET query) or a SAMLart artifact, stashes the response,
 * and redirects the browser to the client results page with the stash id.
 * @route POST /samlacs
 * @route GET /samlacs
 * @group SAML - SAML support operations
 */
function handleSamlAcs(req, res) {
  log.debug('Entering ' + req.method + ' /samlacs.');
  try {
    var samlResponse = (req.body && req.body.SAMLResponse) || req.query.SAMLResponse;
    var relayState = (req.body && req.body.RelayState) || req.query.RelayState || '';
    var artifact = (req.body && req.body.SAMLart) || req.query.SAMLart;

    if (samlResponse) {
      var xml = decodeSamlMessage(samlResponse);
      var id = stashSamlResponse(xml, relayState);
      res.writeHead(302, { 'Location': uiUrl + '/saml_response.html?id=' + encodeURIComponent(id) });
      return res.end();
    }
    if (artifact) {
      return resolveArtifact(artifact, relayState)
        .then(function (respXml) {
          var artId = stashSamlResponse(respXml, relayState);
          res.writeHead(302, { 'Location': uiUrl + '/saml_response.html?id=' + encodeURIComponent(artId) });
          res.end();
        })
        .catch(function (e) {
          log.error('artifact resolve: ' + (e && e.stack ? e.stack : e));
          res.status(STATUS_500).send('Artifact resolution failed: ' + (e && e.message ? e.message : String(e)));
        });
    }
    res.status(STATUS_400).send('ACS: no SAMLResponse or SAMLart present.');
  } catch (e) {
    log.error('samlacs: ' + (e && e.stack ? e.stack : e));
    res.status(STATUS_500).send('ACS error: ' + (e && e.message ? e.message : String(e)));
  }
}
app.post('/samlacs', handleSamlAcs);
app.get('/samlacs', handleSamlAcs);

// Single Logout service. Receives the IdP's LogoutResponse (or an IdP-initiated
// LogoutRequest) and shows it on the results page. Reuses the ACS handler, which
// decodes/stashes any SAMLResponse and redirects to the viewer.
app.post('/samlslo', handleSamlAcs);
app.get('/samlslo', handleSamlAcs);

/**
 * Fetch a stashed SAMLResponse by id (set by the ACS redirect).
 * @route GET /samlresponse
 * @group SAML - SAML support operations
 */
app.get('/samlresponse', function (req, res) {
  sweepSamlExchanges();
  var ex = samlExchanges.get(String(req.query.id || ''));
  if (!ex) return res.status(STATUS_404).json({ error: 'not found or expired' });
  res.json({ responseXml: ex.responseXml, relayState: ex.relayState });
});

// ---------------------------------------------------------------------------
// WS-Trust STS SOAP proxy.
//
// The WS-Trust workflow builds a SOAP RequestSecurityToken (RST) in the browser
// and can send it to the STS one of two ways (a radio, like the OAuth2 token
// call): directly from the browser, or through this backend proxy. The proxy
// path exists because a SOAP STS endpoint almost never sends the CORS headers a
// cross-origin browser fetch requires — the same reason the token call is
// proxied. It also allows disabling TLS validation for a self-signed STS in dev.
//
// The browser posts { url, soap, soapVersion, action, sslValidate }; the proxy
// forwards the SOAP body with the correct content-type/SOAPAction for the SOAP
// version and returns { status, body } (the raw RSTR envelope) for the client to
// render. Like the token / metadata proxies, it POSTs to a caller-supplied URL,
// so it is a dev/debugger-only tool (SSRF by design) — do not expose publicly.
// ---------------------------------------------------------------------------
/**
 * Proxy a WS-Trust RequestSecurityToken to an STS (dodges CORS).
 * @route POST /wstrust
 * @group WS-Trust - WS-Trust support operations
 * @returns {object} 200 - { status, body } from the STS
 * @returns {Error.model} 400 - Missing url/soap
 * @returns {Error.model} 500 - STS call error
 */
app.post('/wstrust', function (req, res) {
  log.debug('Entering POST /wstrust.');
  var b = req.body || {};
  var url = b.url;
  var soap = b.soap;
  var soapVersion = String(b.soapVersion || '1.2');
  var action = b.action || '';
  // Default to validating TLS; only skip it when the caller explicitly opts out.
  var sslValidate = (b.sslValidate === false || b.sslValidate === 'false') ? false : true;
  if (!url || !soap) {
    return res.status(STATUS_400).json({ error: 'url and soap are required.' });
  }
  if (!/^https?:\/\//i.test(url)) {
    return res.status(STATUS_400).json({ error: 'url must be an absolute http(s) URL.' });
  }
  // SOAP 1.2 carries the action inside the content-type; SOAP 1.1 uses a separate
  // SOAPAction header with a text/xml body.
  var headers;
  if (soapVersion === '1.1') {
    headers = { 'Content-Type': 'text/xml; charset=utf-8', 'SOAPAction': '"' + action + '"' };
  } else {
    headers = { 'Content-Type': 'application/soap+xml; charset=utf-8' + (action ? ('; action="' + action + '"') : '') };
  }
  axios.post(url, soap, {
    responseType: 'text',
    transformResponse: [function (d) { return d; }],
    // The STS may return a SOAP Fault with a 4xx/5xx status; capture the body
    // rather than throwing so the client can display the fault.
    validateStatus: function () { return true; },
    httpsAgent: new (require('https').Agent)({ rejectUnauthorized: sslValidate }),
    headers: headers
  })
  .then(function (response) {
    res.status(STATUS_200).json({ status: response.status, body: String(response.data == null ? '' : response.data) });
  })
  .catch(function (error) {
    log.error('wstrust proxy error to ' + url + ': ' + (error && error.stack ? error.stack : error));
    res.status(STATUS_500).json({ error: 'STS call failed: ' + (error && error.message ? error.message : String(error)) });
  });
});

/**
 * @typedef TokenRequest
 * @property {string} grant_type.required - The OAuth2 / OIDC Grant / Flow Type
 * @property {string} client_id.required - The OAuth2 client identifier
 * @property {string} code.required - The OAuth2 Authorization Code
 * @property {string} redirect_uri.required - The registered redirect (callback) URI for the OAuth2 application definition.
 * @property {string} scope.required - The requested OAuth2 scope.
 * @property {string} token_endpoint.required - The Token Endpoint URL for this OAuth2 Provider
 * @property {boolean} sslValidate.required - Validate the token endpoint SSL/TLS certificate
 * @property {string} resource - Resource parameter
 * @property {string} refresh_token - OAuth2 Refresh Token needed for Refresh Grant
 * @property {string} username - The username used with the OAuth2 Resource Owner Credential Grant
 * @property {string} password - The password used with the OAuth2 Resource Owner Credential Grant
 * @property {string} client_secret - The client secret for a confidential client
 * @property {object} customParams - List of key:value pairs
 * @property {string} code_verifier - PKCE RFC code_verifier parameter
 */

/**
 * @typedef TokenResponse
 * @property {string} access_token.required - The OAuth2 Access Token
 * @property {string} id_token - The OpenID Connect ID Token
 * @property {string} refresh_token - The OAuth2 Refresh Token
 * @property {string} expires_in.required - How long the access token is valid (seconds)
 * @property {string} token_type - The OAuth2 Access Token type
 */

/**
 * @typedef Error
 * @property {boolean} status.required
 * @property {string} code.required
 */

/**
 * Wrapper around OAuth2 Token Endpoint
 * @route POST /token
 * @group Debugger - Operations for OAuth2/OIDC Debugger
 * @param {TokenRequest.model} req.body.required - Token Endpoint Request
 * @returns {TokenResponse.model} 200 - Token Endpoint Response
 * @returns {Error.model} 400 - Syntax error
 * @returns {Error.model} 500 - Unexpected error
 */
app.post('/token', (req, res) => {
  try {
    log.info('Entering app.post for /token.');
    const body = req.body;
    log.debug('body: ' + JSON.stringify(body));
    const parameterString = convertToOAuth2Format(body);
    var headers = {
      'content-type' : 'application/x-www-form-urlencoded'
    };
    const grantType = body.grant_type;
    const clientSecret = encodeURIComponent(body.client_secret);
    const code_verifier = body.code_verifier;
    if ( typeof code_verifier != "undefined" ||
         (grantType == "refresh_token" &&
          !clientSecret)) {
      headers.origin = uiUrl;
    }
    const auth_style = body.auth_style;
    var clientId = body.client_id;
    if (!auth_style) {
      // Put client_id + client_secret in Authorization header
      headers.authorization = 'Basic ' + Buffer.from(clientId + ":" + clientSecret).toString('base64');
    }
    var tokenEndpoint = body.token_endpoint;
    var sslValidate = body.sslValidate; 
    log.debug("Making call to Token Endpoint.");
    log.debug("POST " + tokenEndpoint);
    log.debug("Headers: " + JSON.stringify(headers));
    log.debug("Body: " + parameterString);
    axios({
      method: 'post',
      url: tokenEndpoint,
      headers: headers,
      data: parameterString,
      httpsAgent: new (require('https').Agent)({ rejectUnauthorized: sslValidate })
    })
    .then(function (response) {
      log.debug('Response from OAuth2 Token Endpoint: ' + JSON.stringify(response.data));
      log.debug('Headers: ' + response.headers);
      res.status(response.status);
      res.json(response.data);
    })
    .catch(function (error) {
      log.error('Error from OAuth2 Token Endpoint: ' + error);
      if(!!error.response) {
        if(!!error.response.status) {
          log.error("Error Status: " + error.response.status);
        }
        if(!!error.response.data) {
          log.error("Error Response body: " + JSON.stringify(error.response.data));
        }
        if(!!error.response.headers) {
          log.error("Error Response headers: " + error.response.headers);
        }
        if (!!error.response) {
          res.status(error.response.status);
          res.json(error.response.data);
        } else {
          res.status(500);
          res.json(error.message);
        }
      }
    });
  } catch (e) {
    log.error('An error occurred: ' + e);
    res.status(STATUS_500);
    res.json({ "error": e });
  }
});

/**
 * @typedef IntrospectionRequest
 * @property {string} grant_type.required - The OAuth2 / OIDC Grant / Flow Type
 * @property {string} client_id.required - The OAuth2 client identifier
 */

/**
 * @typedef IntrospectionResponse
 * @property {string} access_token.required - The OAuth2 Access Token
 * @property {string} id_token - The OpenID Connect ID Token
 */

/**
 * Wrapper around OAuth2 Introspection Endpoint
 * @route POST /introspection
 * @group Debugger - Operations for OAuth2/OIDC Debugger
 * @param {IntrospectionRequest.model} req.body.required - Token Endpoint Request
 * @returns {IntrospectionResponse.model} 200 - Token Endpoint Response
 * @returns {Error.model} 400 - Syntax error
 * @returns {Error.model} 500 - Unexpected error
 */
app.post('/introspection', (req, res) => {
try {
  log.info('Entering app.post for /introspection.');
  const body = req.body;
  log.debug('body: ' + JSON.stringify(body));
  var headers = {
    "Authorization": req.headers.authorization,
    "Content-Type": "application/x-www-form-urlencoded"
  };
  var introspectionRequestMessage = {
    token: body.token,
    token_type_hint: body.token_type_hint
  }
  const parameterString = JSON.stringify(introspectionRequestMessage);
  log.debug("Method: POST");
  log.debug("URL: " + body.introspectionEndpoint);
  log.debug("headers: " + JSON.stringify(headers));
  log.debug("body: " + parameterString);
  axios({
      method: 'post',
      url: body.introspectionEndpoint,
      headers: headers,
      data: introspectionRequestMessage,
      httpsAgent: new (require('https').Agent)({ rejectUnauthorized: true })
    })
    .then(function (response) {
      log.debug('Response from OAuth2 Introspection Endpoint: ' + JSON.stringify(response.data));
      log.debug('Headers: ' + response.headers);
      res.status(response.status);
      res.json(response.data);
    })
    .catch(function (error) {
      log.error('Error from OAuth2 Introspection Endpoint: ' + error);
      if(!!error.response) {
        if(!!error.response.status) {
          log.error("Error Status: " + error.response.status);
        }
        if(!!error.response.data) {
          log.error("Error Response body: " + JSON.stringify(error.response.data));
        }
        if(!!error.response.headers) {
          log.error("Error Response headers: " + error.response.headers);
        }
        if (!!error.response) {
          res.status(error.response.status);
          res.json(error.response.data);
        } else {
          res.status(STATUS_500);
          res.json(error.message);
        }
      }
    });
  } catch(e) {
    log.error("Error from OAuth2 Introspection Endpoint: " + error);
  }
});

/**
 * @typedef RevocationRequest
 * @property {string} revocation_endpoint.required - The OAuth2 Token Revocation Endpoint URL (RFC 7009)
 * @property {string} token.required - The token (access or refresh) to revoke
 * @property {string} token_type_hint - Hint about the token type (access_token | refresh_token)
 * @property {string} client_id - The OAuth2 client identifier
 * @property {string} client_secret - The client secret for a confidential client
 * @property {boolean} sslValidate - Validate the revocation endpoint SSL/TLS certificate
 */

/**
 * Wrapper around the OAuth2 Token Revocation Endpoint (RFC 7009)
 * @route POST /revoke
 * @group Debugger - Operations for OAuth2/OIDC Debugger
 * @param {RevocationRequest.model} req.body.required - Token Revocation Request
 * @returns {object} 200 - Token Revocation Response
 * @returns {Error.model} 400 - Syntax error
 * @returns {Error.model} 500 - Unexpected error
 */
app.post('/revoke', (req, res) => {
  try {
    log.info('Entering app.post for /revoke.');
    const body = req.body;
    log.debug('body: ' + JSON.stringify(body));
    var headers = {
      'content-type': 'application/x-www-form-urlencoded'
    };
    var clientId = body.client_id;
    var clientSecret = body.client_secret;
    // auth_style truthy => send client credentials in the POST body;
    // falsy => authenticate via the HTTP Basic header (RFC 6749 Section 2.3.1).
    var auth_style = body.auth_style;
    // Build the application/x-www-form-urlencoded body. token is required;
    // token_type_hint is optional per RFC 7009 Section 2.1.
    var parameters = ['token=' + encodeURIComponent(body.token)];
    if (!!body.token_type_hint) {
      parameters.push('token_type_hint=' + encodeURIComponent(body.token_type_hint));
    }
    if (auth_style) {
      // POST body authentication.
      if (!!clientId) {
        parameters.push('client_id=' + encodeURIComponent(clientId));
      }
      if (!!clientSecret) {
        parameters.push('client_secret=' + encodeURIComponent(clientSecret));
      }
    } else if (!!clientSecret) {
      // Confidential client: authenticate via HTTP Basic.
      headers.authorization = 'Basic ' +
        Buffer.from(encodeURIComponent(clientId) + ':' + encodeURIComponent(clientSecret)).toString('base64');
    } else if (!!clientId) {
      // Public client with no secret: include client_id in the request body.
      parameters.push('client_id=' + encodeURIComponent(clientId));
    }
    const parameterString = parameters.join('&');
    var revocationEndpoint = body.revocation_endpoint;
    var sslValidate = body.sslValidate;
    log.debug("Making call to Revocation Endpoint.");
    log.debug("POST " + revocationEndpoint);
    log.debug("Headers: " + JSON.stringify(headers));
    log.debug("Body: " + parameterString);
    axios({
      method: 'post',
      url: revocationEndpoint,
      headers: headers,
      data: parameterString,
      httpsAgent: new (require('https').Agent)({ rejectUnauthorized: sslValidate })
    })
    .then(function (response) {
      // RFC 7009: a successful revocation returns HTTP 200 with an empty body.
      log.debug('Response from OAuth2 Revocation Endpoint: ' + JSON.stringify(response.data));
      res.status(response.status);
      res.json({
        message: 'Token revocation request accepted (RFC 7009).',
        status: response.status,
        statusText: response.statusText,
        data: response.data
      });
    })
    .catch(function (error) {
      log.error('Error from OAuth2 Revocation Endpoint: ' + error);
      if(!!error.response) {
        if(!!error.response.status) {
          log.error("Error Status: " + error.response.status);
        }
        if(!!error.response.data) {
          log.error("Error Response body: " + JSON.stringify(error.response.data));
        }
        res.status(error.response.status);
        res.json(error.response.data);
      } else {
        res.status(STATUS_500);
        res.json({ error: error.message });
      }
    });
  } catch (e) {
    log.error('An error occurred: ' + e);
    res.status(STATUS_500);
    res.json({ "error": e });
  }
});

/**
 * @typedef TokenExchangeRequest
 * @property {string} token_endpoint.required - The OAuth2 Token Endpoint URL
 * @property {string} grant_type.required - urn:ietf:params:oauth:grant-type:token-exchange
 * @property {string} subject_token.required - The token representing the subject
 * @property {string} subject_token_type.required - The subject token type identifier (URN)
 * @property {string} actor_token - The token representing the acting party (delegation)
 * @property {string} actor_token_type - The actor token type identifier (URN)
 * @property {string} requested_token_type - The requested token type identifier (URN)
 * @property {string} resource - Target resource URI
 * @property {string} audience - Target service logical name
 * @property {string} scope - Requested scope
 * @property {string} client_id - The OAuth2 client identifier
 * @property {string} client_secret - The client secret for a confidential client
 * @property {boolean} sslValidate - Validate the token endpoint SSL/TLS certificate
 */

/**
 * Wrapper around the OAuth2 Token Endpoint for Token Exchange (RFC 8693)
 * @route POST /tokenexchange
 * @group Debugger - Operations for OAuth2/OIDC Debugger
 * @param {TokenExchangeRequest.model} req.body.required - Token Exchange Request
 * @returns {object} 200 - Token Exchange Response
 * @returns {Error.model} 400 - Syntax error
 * @returns {Error.model} 500 - Unexpected error
 */
app.post('/tokenexchange', (req, res) => {
  try {
    log.info('Entering app.post for /tokenexchange.');
    const body = req.body;
    log.debug('body: ' + JSON.stringify(body));
    var headers = {
      'content-type': 'application/x-www-form-urlencoded'
    };
    var clientId = body.client_id;
    var clientSecret = body.client_secret;
    // auth_style truthy => send client credentials in the POST body;
    // falsy => authenticate via the HTTP Basic header (RFC 6749 Section 2.3.1).
    var auth_style = body.auth_style;
    // Build the application/x-www-form-urlencoded body (RFC 8693 Section 2.1).
    var parameters = ['grant_type=' + encodeURIComponent(body.grant_type)];
    var addParam = function (key, value) {
      if (!!value) {
        parameters.push(key + '=' + encodeURIComponent(value));
      }
    };
    addParam('subject_token', body.subject_token);
    addParam('subject_token_type', body.subject_token_type);
    addParam('actor_token', body.actor_token);
    addParam('actor_token_type', body.actor_token_type);
    addParam('requested_token_type', body.requested_token_type);
    addParam('resource', body.resource);
    addParam('audience', body.audience);
    addParam('scope', body.scope);
    if (auth_style) {
      // POST body authentication.
      addParam('client_id', clientId);
      addParam('client_secret', clientSecret);
    } else if (!!clientSecret) {
      // Confidential client: authenticate via HTTP Basic.
      headers.authorization = 'Basic ' +
        Buffer.from(encodeURIComponent(clientId) + ':' + encodeURIComponent(clientSecret)).toString('base64');
    } else if (!!clientId) {
      // Public client with no secret: include client_id in the request body.
      addParam('client_id', clientId);
    }
    const parameterString = parameters.join('&');
    var tokenEndpoint = body.token_endpoint;
    var sslValidate = body.sslValidate;
    log.debug("Making Token Exchange call to Token Endpoint.");
    log.debug("POST " + tokenEndpoint);
    log.debug("Headers: " + JSON.stringify(headers));
    log.debug("Body: " + parameterString);
    axios({
      method: 'post',
      url: tokenEndpoint,
      headers: headers,
      data: parameterString,
      httpsAgent: new (require('https').Agent)({ rejectUnauthorized: sslValidate })
    })
    .then(function (response) {
      log.debug('Response from OAuth2 Token Endpoint (token exchange): ' + JSON.stringify(response.data));
      res.status(response.status);
      res.json(response.data);
    })
    .catch(function (error) {
      log.error('Error from OAuth2 Token Endpoint (token exchange): ' + error);
      if(!!error.response) {
        if(!!error.response.status) {
          log.error("Error Status: " + error.response.status);
        }
        if(!!error.response.data) {
          log.error("Error Response body: " + JSON.stringify(error.response.data));
        }
        res.status(error.response.status);
        res.json(error.response.data);
      } else {
        res.status(STATUS_500);
        res.json({ error: error.message });
      }
    });
  } catch (e) {
    log.error('An error occurred: ' + e);
    res.status(STATUS_500);
    res.json({ "error": e });
  }
});

/**
 * @typedef DeviceAuthorizationRequest
 * @property {string} device_authorization_endpoint.required - The Device Authorization Endpoint URL (RFC 8628)
 * @property {string} client_id.required - The OAuth2 client identifier
 * @property {string} client_secret - The client secret for a confidential client
 * @property {string} scope - The requested scope
 * @property {boolean} sslValidate - Validate the endpoint SSL/TLS certificate
 */

/**
 * Wrapper around the OAuth2 Device Authorization Endpoint (RFC 8628)
 * @route POST /deviceauthorization
 * @group Debugger - Operations for OAuth2/OIDC Debugger
 * @param {DeviceAuthorizationRequest.model} req.body.required - Device Authorization Request
 * @returns {object} 200 - Device Authorization Response (device_code, user_code, verification_uri, ...)
 * @returns {Error.model} 400 - Syntax error
 * @returns {Error.model} 500 - Unexpected error
 */
app.post('/deviceauthorization', (req, res) => {
  try {
    log.info('Entering app.post for /deviceauthorization.');
    const body = req.body;
    log.debug('body: ' + JSON.stringify(body));
    var headers = {
      'content-type': 'application/x-www-form-urlencoded'
    };
    var clientId = body.client_id;
    var clientSecret = body.client_secret;
    var auth_style = body.auth_style;
    // Build the application/x-www-form-urlencoded body (RFC 8628 Section 3.1).
    var parameters = [];
    if (!!body.scope) {
      parameters.push('scope=' + encodeURIComponent(body.scope));
    }
    if (auth_style) {
      // POST body authentication.
      if (!!clientId) {
        parameters.push('client_id=' + encodeURIComponent(clientId));
      }
      if (!!clientSecret) {
        parameters.push('client_secret=' + encodeURIComponent(clientSecret));
      }
    } else if (!!clientSecret) {
      // Confidential client: authenticate via HTTP Basic.
      headers.authorization = 'Basic ' +
        Buffer.from(encodeURIComponent(clientId) + ':' + encodeURIComponent(clientSecret)).toString('base64');
    } else if (!!clientId) {
      // Public client: include client_id in the request body.
      parameters.push('client_id=' + encodeURIComponent(clientId));
    }
    const parameterString = parameters.join('&');
    var deviceAuthorizationEndpoint = body.device_authorization_endpoint;
    var sslValidate = body.sslValidate;
    log.debug("Making call to Device Authorization Endpoint.");
    log.debug("POST " + deviceAuthorizationEndpoint);
    log.debug("Headers: " + JSON.stringify(headers));
    log.debug("Body: " + parameterString);
    axios({
      method: 'post',
      url: deviceAuthorizationEndpoint,
      headers: headers,
      data: parameterString,
      httpsAgent: new (require('https').Agent)({ rejectUnauthorized: sslValidate })
    })
    .then(function (response) {
      log.debug('Response from OAuth2 Device Authorization Endpoint: ' + JSON.stringify(response.data));
      res.status(response.status);
      res.json(response.data);
    })
    .catch(function (error) {
      log.error('Error from OAuth2 Device Authorization Endpoint: ' + error);
      if(!!error.response) {
        if(!!error.response.status) {
          log.error("Error Status: " + error.response.status);
        }
        if(!!error.response.data) {
          log.error("Error Response body: " + JSON.stringify(error.response.data));
        }
        res.status(error.response.status);
        res.json(error.response.data);
      } else {
        res.status(STATUS_500);
        res.json({ error: error.message });
      }
    });
  } catch (e) {
    log.error('An error occurred: ' + e);
    res.status(STATUS_500);
    res.json({ "error": e });
  }
});

/**
 * @typedef RegistrationRequest
 * @property {string} method.required - The HTTP method to use against the registration/configuration endpoint (POST | GET | PUT | DELETE)
 * @property {string} url.required - The target URL (registration_endpoint for create, registration_client_uri for read/update/delete)
 * @property {string} bearer_token - Bearer token (initial access token for create, or registration_access_token for read/update/delete)
 * @property {object} metadata - The OIDC/RFC7591 client metadata to send (POST/PUT only)
 * @property {boolean} sslValidate - Validate the endpoint SSL/TLS certificate
 */

/**
 * Wrapper around the OIDC Dynamic Client Registration endpoints
 * (OpenID Connect Dynamic Client Registration 1.0 / RFC 7591 / RFC 7592).
 * Proxies create (POST registration_endpoint), read (GET), update (PUT) and
 * delete (DELETE) against the client configuration endpoint so the browser is
 * not blocked by CORS.
 * @route POST /register
 * @group Debugger - Operations for OAuth2/OIDC Debugger
 * @param {RegistrationRequest.model} req.body.required - Dynamic Client Registration Request
 * @returns {object} 200 - Registration Endpoint Response
 * @returns {Error.model} 400 - Syntax error
 * @returns {Error.model} 500 - Unexpected error
 */
app.post('/register', (req, res) => {
  try {
    log.info('Entering app.post for /register.');
    const body = req.body;
    log.debug('body: ' + JSON.stringify(body));
    // Normalize the HTTP method; create=POST, read=GET, update=PUT, delete=DELETE.
    var method = (body.method || 'POST').toLowerCase();
    var url = body.url;
    var bearerToken = body.bearer_token;
    var sslValidate = body.sslValidate;
    // Client metadata is only sent on create (POST) and update (PUT).
    var payload = (method === 'post' || method === 'put') ? body.metadata : undefined;
    var headers = {
      'Accept': 'application/json'
    };
    if (method === 'post' || method === 'put') {
      headers['Content-Type'] = 'application/json';
    }
    // The registration access token (or an initial access token for create) is
    // presented as a Bearer token per OIDC Registration 1.0 Section 4 / RFC 7592.
    if (!!bearerToken) {
      headers.authorization = 'Bearer ' + bearerToken;
    }
    log.debug("Making call to Dynamic Client Registration endpoint.");
    log.debug(method.toUpperCase() + " " + url);
    log.debug("Headers: " + JSON.stringify(headers));
    log.debug("Body: " + JSON.stringify(payload));
    axios({
      method: method,
      url: url,
      headers: headers,
      data: payload,
      httpsAgent: new (require('https').Agent)({ rejectUnauthorized: sslValidate })
    })
    .then(function (response) {
      log.debug('Response from Dynamic Client Registration endpoint: ' + JSON.stringify(response.data));
      // A successful DELETE (RFC 7592 Section 2.3) returns HTTP 204 with no body.
      // Normalize that to 200 with a JSON summary so the browser reliably
      // receives a body (a body sent with 204 is dropped by HTTP clients).
      if (response.status === 204 || !response.data) {
        res.status(STATUS_200).json({
          message: 'Client registration request succeeded.',
          status: response.status,
          statusText: response.statusText
        });
      } else {
        res.status(response.status).json(response.data);
      }
    })
    .catch(function (error) {
      log.error('Error from Dynamic Client Registration endpoint: ' + error);
      if(!!error.response) {
        if(!!error.response.status) {
          log.error("Error Status: " + error.response.status);
        }
        if(!!error.response.data) {
          log.error("Error Response body: " + JSON.stringify(error.response.data));
        }
        res.status(error.response.status);
        res.json(error.response.data);
      } else {
        res.status(STATUS_500);
        res.json({ error: error.message });
      }
    });
  } catch (e) {
    log.error('An error occurred: ' + e);
    res.status(STATUS_500);
    res.json({ "error": e });
  }
});

app.post('/userinfo', (req, res) => {
  log.info('Entering app.post for /userinfo.');
  userinfo_common(req, res);
  log.debug("Leaving app.post for /userinfo.");
});

/**
 * Wrapper around OIDC UserInfo Endpoint
 * @route POST /userinfo
 * @group Debugger - Operations for OAuth2/OIDC Debugger
 * @param {UserInfoRequest.model} req.body.required - UserInfo Endpoint Request
 * @returns {UserInfoResponse.model} 200 - UserInfo Endpoint Response
 * @returns {Error.model} 400 - Syntax error
 * @returns {Error.model} 500 - Unexpected error
 */
app.get('/userinfo', (req, res) => {
  log.info("Entering app.get for /userinfo.");
  userinfo_common(req, res);
  log.debug("Leaving app.get for /userinfo.");
});

function userinfo_common(req, res) {
try {
  log.info('Entering app.get for /userinfo.');
  var headers = {
    "Authorization": req.headers.authorization,
  };
  // All types of requests are converted to GET.
  log.debug("Method: GET");
  log.debug("URL: " + Buffer.from(req.query.userinfo_endpoint, 'base64').toString('utf-8'));
  log.debug("headers: " + JSON.stringify(headers));
  axios({
      method: 'get',
      url: Buffer.from(req.query.userinfo_endpoint, 'base64').toString('utf-8'),
      headers: headers,
      httpsAgent: new (require('https').Agent)({ rejectUnauthorized: true })
    })
    .then(function (response) {
      log.debug('Response from OIDC UserInfo Endpoint: ' + JSON.stringify(response.data));
      log.debug('Headers: ' + response.headers);
      res.status(response.status);
      res.json(response.data);
    })
    .catch(function (error) {
      log.error('Error from OIDC UserInfo Endpoint: ' + error);
      if(!!error.response) {
        if(!!error.response.status) {
          log.error("Error Status: " + error.response.status);
        }
        if(!!error.response.data) {
          log.error("Error Response body: " + JSON.stringify(error.response.data));
        }
        if(!!error.response.headers) {
          log.error("Error Response headers: " + error.response.headers);
        }
        if (!!error.response) {
          res.status(error.response.status);
          res.json(error.response.data);
        } else {
          res.status(STATUS_500);
          res.json(error.message);
        }
      }
    });
  } catch(e) {
    log.error("Error from OIDC UserInfo Endpoint: " + error);
  }
}

let options = {
    swaggerDefinition: {
        info: {
            description: 'IDPTools API',
            title: 'Swagger',
            version: '1.0.0',
        },
        host: 'localhost:4000',
        basePath: '/',
        produces: [
            "application/json",
        ],
        schemes: ['http', 'https'],
        securityDefinitions: {
        }
    },
    basedir: __dirname, //app absolute path
    files: ['server.js'] //Path to the API handle folder
};
expressSwagger(options)
app.listen(PORT, HOST);
log.info(`Running on http://${HOST}:${PORT}`);

// When running under coverage (c8), exit cleanly on container stop so the V8
// coverage is flushed to NODE_V8_COVERAGE before the process is terminated.
if (process.env.COVERAGE === 'true') {
  ['SIGTERM', 'SIGINT'].forEach(function (signal) {
    process.on(signal, function () {
      log.info('Received ' + signal + '; exiting to flush coverage.');
      process.exit(0);
    });
  });
}
