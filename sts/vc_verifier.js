'use strict';
//
// File: vc_verifier.js
//
// ===========================================================================
// OpenID for Verifiable Presentations (OID4VP 1.0) — mock Verifier
//
// The other half of the SD-JWT VC story: the issuance flow above puts a
// credential in a wallet, and this is the Verifier that asks for part of it.
//
//   GET  /oid4vp/verifier          the Verifier's web page (where a
//                                  presentation starts, same device)
//   GET  /oid4vp/start             builds an Authorization Request and either
//                                  sends the browser to the wallet with it or
//                                  displays it as a QR code (cross device)
//   GET  /oid4vp/request/:id       the signed Request Object, fetched by
//                                  reference (RFC 9101 / OID4VP request_uri)
//   POST /oid4vp/response          the Response URI: response_mode direct_post,
//                                  where the vp_token arrives and is VERIFIED
//   GET  /oid4vp/result/:state     non-spec: the verdict, so the wallet page and
//                                  the tests can read what the Verifier decided
//   GET  /oid4vp/done              the Verifier's "thank you" page
//
// What it checks is the whole point, so it checks properly (RFC 9901 section 7.3
// plus OID4VP's rules for the Key Binding JWT):
//
//   * the presentation is an SD-JWT+KB: <Issuer-signed JWT>~<Disclosure>*~<KB-JWT>
//   * the Issuer-signed JWT verifies against the issuer's key, and its typ is an
//     SD-JWT VC media type
//   * every Disclosure presented hashes to a digest in _sd — a Disclosure the
//     issuer never signed is the forgery this catches
//   * the KB-JWT has typ kb+jwt, an alg that is not none, and verifies against
//     the cnf key IN THE CREDENTIAL — key binding means nothing if the presenter
//     may nominate the key
//   * its sd_hash equals the hash of exactly the bytes presented, so disclosures
//     cannot be added or removed after it was signed
//   * its nonce is the nonce from THIS request (replay) and its aud is this
//     Verifier's Client Identifier (an honest presentation to someone else is
//     not a presentation to us)
//   * the credential is inside its validity window, and every claim the DCQL
//     query asked for is actually there
// ===========================================================================
//
// It shares nothing with vc_issuer.js but the key: this is the OTHER side of the
// exchange, and it verifies what arrives from first principles rather than by
// asking the issuer module what it produced. That is deliberate — a verifier that
// called the issuer's own code to check a presentation would agree with it about
// any mistake they had in common.
// ---------------------------------------------------------------------------

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const qrcode = require('qrcode');
const app = require('./app');
const bbs2023 = require('./bbs2023.js');
const { log, logArtifact, STS, baseUrlOf, b64u, b64uDecode, jsonFromB64u, nowSec,
        randomId, xmlEscape, bbsKeyPair, parseBody, oauthError, signJwt,
        WALLET_BASE_URL } = require('./helpers');
const { VCI_JWT_TYPES, VCI_VCT } = require('./vc_configs');
const VP_CLIENT_ID = process.env.OID4VP_CLIENT_ID || 'sts-mock-verifier';
const VP_WALLET_URL = process.env.OID4VP_WALLET_URL || WALLET_BASE_URL;

const VP_TTL_MS = 10 * 60 * 1000;

// How old a Key Binding JWT may be. It is signed for one presentation, so this is
// short on purpose.
const VP_KB_MAX_AGE_S = Number(process.env.OID4VP_KB_MAX_AGE_S || 600);

// The claims this Verifier asks for: enough to show selective disclosure doing
// its job — it wants two of the six claims the credential can carry.
const VP_REQUESTED_CLAIMS = (process.env.OID4VP_CLAIMS || 'given_name,family_name').split(',');

const VP_DCQL_ID = 'identity_credential';

// state -> { id, nonce, state, responseMode, clientId, requestObject, dcql,
//            expires, verdict }
const vpTransactions = new Map();

// id -> state, so a Request Object fetched by reference can find its transaction.
const vpRequests = new Map();

function sweepVpTransactions() {
  const now = Date.now();
  vpTransactions.forEach(function (v, k) {
    if (v.expires < now) {
      vpRequests.delete(v.id);
      vpTransactions.delete(k);
    }
  });
}

// The DCQL query (OID4VP section 6): which credential, of which format, with
// which claims. `claims` is what makes this a selective-disclosure request — the
// Verifier names the paths it needs and has no way to ask for "everything".
// The DCQL credential query, which differs by format in two ways that matter.
//
// How the credential is IDENTIFIED: an SD-JWT VC by its vct, a W3C VC by its
// type array — hence `vct_values` against `type_values`, and note type_values
// is an array OF ARRAYS (each entry is a complete type set that would satisfy
// the query).
//
// Where the CLAIMS live: an SD-JWT VC keeps them at the top level of the
// payload, a W3C VC under credentialSubject — so the same claim is asked for as
// ["given_name"] in one format and ["credentialSubject","given_name"] in the
// other. Getting that path wrong does not fail loudly; it asks for a claim that
// is not there and the presentation looks like it withheld something.
function vpDcqlQuery(format) {
  log.debug("Entering vpDcqlQuery(). format=" + (format || 'dc+sd-jwt'));
  if (format === 'ldp_vc') {
    // A W3C credential identified by its type array, like jwt_vc_json — what
    // differs is how it is SECURED, not how it is named.
    const ldp = {
      id: VP_DCQL_ID,
      format: 'ldp_vc',
      meta: { type_values: [VCI_JWT_TYPES] },
      claims: VP_REQUESTED_CLAIMS.map(function (name) {
        return { path: ['credentialSubject', name] };
      })
    };
    const ldpQuery = { credentials: [ldp] };
    logArtifact('OID4VP DCQL query', 'as built (ldp_vc)', ldpQuery);
    log.debug("Leaving vpDcqlQuery(). ldp_vc, " + VP_REQUESTED_CLAIMS.length + " claim(s).");
    return ldpQuery;
  }
  const jwtVcJson = format === 'jwt_vc_json';
  const credential = jwtVcJson
    ? {
        id: VP_DCQL_ID,
        format: 'jwt_vc_json',
        meta: { type_values: [VCI_JWT_TYPES] },
        claims: VP_REQUESTED_CLAIMS.map(function (name) {
          return { path: ['credentialSubject', name] };
        })
      }
    : {
        id: VP_DCQL_ID,
        format: 'dc+sd-jwt',
        meta: { vct_values: [VCI_VCT] },
        claims: VP_REQUESTED_CLAIMS.map(function (name) { return { path: [name] }; })
      };
  const query = { credentials: [credential] };
  logArtifact('OID4VP DCQL query', 'as built', query);
  log.debug("Leaving vpDcqlQuery(). " + VP_REQUESTED_CLAIMS.length + " claim(s) requested as " +
            credential.format + ".");
  return query;
}

// One Authorization Request, in the two shapes this mock offers:
//
//   by value      client_id uses the redirect_uri prefix, so the request needs no
//                 signature — and cannot have one, because the Wallet has no way
//                 to obtain a key for a client identified only by a URL
//                 (OID4VP section 5.10).
//   by reference  a pre-registered client_id and a SIGNED Request Object at
//                 request_uri, verifiable against this service's published JWKS.
function buildVpRequest(req, opts) {
  log.debug("Entering buildVpRequest(). byReference=" + !!opts.byReference +
            ", format=" + (opts.format || 'dc+sd-jwt'));
  const base = baseUrlOf(req);
  const responseUri = base + '/oid4vp/response';
  const id = randomId(16);
  const nonce = randomId(18);
  const state = randomId(18);
  const clientId = opts.byReference ? VP_CLIENT_ID : ('redirect_uri:' + responseUri);
  const request = {
    client_id: clientId,
    response_type: 'vp_token',
    response_mode: 'direct_post',
    response_uri: responseUri,
    nonce: nonce,
    state: state,
    dcql_query: vpDcqlQuery(opts.format),
    client_metadata: {
      client_name: 'Mock Verifier (bar door)',
      // Both formats are advertised whichever one this request asks for: this is
      // what the Verifier CAN accept, not what it wants this time — the DCQL
      // query is what says that.
      vp_formats_supported: {
        'dc+sd-jwt': { 'sd-jwt_alg_values': ['RS256', 'ES256'], 'kb-jwt_alg_values': ['ES256'] },
        'jwt_vc_json': { alg_values: ['RS256', 'ES256'] },
        'ldp_vc': { cryptosuites: ['bbs-2023'] }
      }
    }
  };
  const record = {
    id: id, nonce: nonce, state: state, clientId: clientId,
    responseMode: 'direct_post', request: request, byReference: !!opts.byReference,
    // Which format this Verifier asked for. The response is verified against
    // THIS, not against whatever shape happens to turn up, so a wallet that
    // answers a jwt_vc_json query with an SD-JWT is refused rather than quietly
    // accepted by the other code path.
    format: opts.format === 'jwt_vc_json' ? 'jwt_vc_json'
          : opts.format === 'ldp_vc' ? 'ldp_vc'
          : 'dc+sd-jwt',
    expires: Date.now() + VP_TTL_MS, verdict: null
  };
  logArtifact('OID4VP Authorization Request', 'as built', request);
  if (opts.byReference) {
    // RFC 9101: the Request Object is a signed JWT. iss/aud are the client and
    // the wallet; the wallet checks the signature against the client's key,
    // which for a pre-registered client it has out of band — here, this
    // service's JWKS.
    const payload = Object.assign({
      iss: clientId,
      aud: 'https://self-issued.me/v2',
      iat: nowSec(),
      exp: nowSec() + Math.floor(VP_TTL_MS / 1000)
    }, request);
    record.requestObject = signJwt(Object.assign({ typ: 'oauth-authz-req+jwt' }, payload));
    logArtifact('OID4VP Request Object', 'after signing', record.requestObject);
    vpRequests.set(id, state);
  }
  vpTransactions.set(state, record);
  sweepVpTransactions();
  log.debug("Leaving buildVpRequest(). state=" + state + ", nonce=" + nonce);
  return record;
}

// The query the wallet is handed: by value it carries the whole request, by
// reference only client_id and request_uri (OID4VP section 5.2).
function vpRequestQuery(req, record) {
  log.debug("Entering vpRequestQuery().");
  const base = baseUrlOf(req);
  const params = record.byReference
    ? { client_id: record.clientId, request_uri: base + '/oid4vp/request/' + record.id,
        request_uri_method: 'get' }
    : {
        client_id: record.clientId,
        response_type: record.request.response_type,
        response_mode: record.request.response_mode,
        response_uri: record.request.response_uri,
        nonce: record.nonce,
        state: record.state,
        dcql_query: JSON.stringify(record.request.dcql_query),
        client_metadata: JSON.stringify(record.request.client_metadata)
      };
  const query = Object.keys(params)
    .map(function (k) { return encodeURIComponent(k) + '=' + encodeURIComponent(params[k]); })
    .join('&');
  log.debug("Leaving vpRequestQuery(). " + Object.keys(params).length + " parameter(s).");
  return query;
}

// The Verifier's own web page — where a same-device presentation starts.
app.get('/oid4vp/verifier', function (req, res) {
  log.debug("Entering the verifier web page. format=" + (req.query.format || 'dc+sd-jwt'));
  const base = baseUrlOf(req);
  // Which format this verifier will ask for. A wallet arriving from the
  // debugger's presentation step 0 names the format it is actually holding,
  // because the format is the VERIFIER's choice and a wallet cannot convert a
  // credential into another one. Without carrying it through these links, every
  // button below would start a dc+sd-jwt request whatever the holder has.
  const pageFormat = String(req.query.format || '');
  const knownFormat = pageFormat === 'jwt_vc_json' || pageFormat === 'ldp_vc' ||
                      pageFormat === 'dc+sd-jwt' ? pageFormat : '';
  const withFormat = function (path) {
    if (!knownFormat) return path;
    return path + (path.indexOf('?') === -1 ? '?' : '&') + 'format=' + encodeURIComponent(knownFormat);
  };
  const askingFor = knownFormat || 'dc+sd-jwt';
  const page = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<title>The Bar Door — are you over 21?</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
    'display:flex;align-items:center;justify-content:center;min-height:100vh;color:#222}' +
    '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:30px 34px;width:560px;' +
    'box-shadow:0 6px 24px rgba(0,0,0,.08)}h1{font-size:1.3em;margin:0 0 6px}' +
    'p{line-height:1.5;color:#333}a.cta{display:inline-block;margin-top:14px;margin-right:10px;padding:10px 16px;' +
    'border-radius:6px;background:#12107c;color:#fff;text-decoration:none;font-weight:600}' +
    'a.cta.secondary{background:#fff;color:#12107c;border:1px solid #12107c}' +
    'p.alt{margin-top:20px;font-size:.92em;color:#555}' +
    '.meta{margin-top:22px;padding-top:14px;border-top:1px solid #eee;font-size:.78em;color:#777}' +
    'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}</style></head><body><div class="card">' +
    '<h1>The Bar Door</h1>' +
    '<p>We need to see that you are who you say you are — but only that. Present the ' +
    '<code>' + xmlEscape(VP_REQUESTED_CLAIMS.join(', ')) + '</code> claim(s) from a credential of type ' +
    '<code>' + xmlEscape(VCI_VCT) + '</code>, and nothing else.</p>' +
    '<p><a class="cta" id="present_by_value" href="' + xmlEscape(withFormat('/oid4vp/start')) +
    '">Present your credential</a>' +
    '<a class="cta secondary" id="present_by_reference" href="' +
    xmlEscape(withFormat('/oid4vp/start?by=reference')) + '">' +
    'Present it (signed request by reference)</a></p>' +
    '<p class="alt">Wallet on another device?<br>' +
    '<a class="cta secondary" id="present_cross_device" href="' +
    xmlEscape(withFormat('/oid4vp/start?mode=cross-device')) + '">' +
    'Show a QR code (cross-device)</a></p>' +
    '<p class="alt">This request asks for a <code>' + xmlEscape(askingFor) + '</code> credential. ' +
    'A presentation cannot convert between formats, so a wallet holding a different one has nothing ' +
    'to answer with — pick the format you hold:<br>' +
    '<a class="cta secondary" id="present_sd_jwt_vc" href="/oid4vp/start?format=dc+sd-jwt">' +
    'Present an SD-JWT VC</a> ' +
    '<a class="cta secondary" id="present_jwt_vc_json" href="/oid4vp/start?format=jwt_vc_json">' +
    'Present a JWT VC</a> ' +
    '<a class="cta secondary" id="present_ldp_vc" href="/oid4vp/start?format=ldp_vc">' +
    'Present an LDP VC (BBS)</a></p>' +
    '<p class="alt"><code>jwt_vc_json</code> has no selective disclosure, so presenting it hands over ' +
    'every claim it carries. <code>ldp_vc</code> discloses over canonical statements with a bbs-2023 ' +
    'derived proof, and each presentation is unlinkable to the last.</p>' +
    '<div class="meta">This is the Verifier in OID4VP. It builds an Authorization Request with ' +
    '<code>response_type=vp_token</code>, a <code>dcql_query</code> naming the claims above, a fresh ' +
    '<code>nonce</code>, and <code>response_mode=direct_post</code> — so your wallet POSTs the presentation ' +
    'to <code>' + xmlEscape(base) + '/oid4vp/response</code> rather than putting it in a URL. The wallet is at ' +
    '<code>' + xmlEscape(VP_WALLET_URL) + '</code>.</div>' +
    '</div></body></html>\n';
  res.status(200).type('text/html').send(page);
  log.debug("Leaving the verifier web page.");
});

// The link on that page: build the request and hand it to the wallet.
app.get('/oid4vp/start', function (req, res) {
  log.debug("Entering the presentation start endpoint. mode=" + (req.query.mode || 'same-device') +
            ", format=" + (req.query.format || 'dc+sd-jwt'));
  const byReference = String(req.query.by || '') === 'reference';
  const mode = String(req.query.mode || 'same-device');
  // Which credential format to ask for. Anything unrecognised falls back to
  // dc+sd-jwt, which is what this Verifier has always asked for.
  const requested = String(req.query.format || '');
  const format = requested === 'jwt_vc_json' ? 'jwt_vc_json'
               : requested === 'ldp_vc' ? 'ldp_vc'
               : 'dc+sd-jwt';
  const record = buildVpRequest(req, { byReference: byReference, format: format });
  const query = vpRequestQuery(req, record);
  const wallet = String(req.query.wallet || VP_WALLET_URL).replace(/\/+$/, '') +
                 '/vc-presentation-1.html';

  if (mode !== 'cross-device') {
    // Same device: the browser IS the wallet's user agent, so send it there.
    res.redirect(302, wallet + '?' + query);
    log.debug("Leaving the presentation start endpoint. Redirected to the wallet.");
    return;
  }
  // Cross device: display the request for the wallet on the other device to
  // scan, as the openid4vp URI a wallet registers for.
  renderVpQrPage(res, {
    base: baseUrlOf(req),
    requestUri: 'openid4vp://?' + query,
    walletUrl: wallet + '?' + query,
    record: record
  });
  log.debug("Leaving the presentation start endpoint. Displayed a QR code.");
});

// The Verifier's screen in a cross-device presentation.
function renderVpQrPage(res, opts) {
  log.debug("Entering renderVpQrPage().");
  qrcode.toDataURL(opts.requestUri, { errorCorrectionLevel: 'M', margin: 2, width: 320 })
    .then(function (dataUrl) {
      const page = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
        '<title>The Bar Door — scan to present</title><style>' +
        'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
        'display:flex;align-items:center;justify-content:center;min-height:100vh;color:#222}' +
        '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:30px 34px;width:560px;' +
        'box-shadow:0 6px 24px rgba(0,0,0,.08);text-align:center}h1{font-size:1.25em;margin:0 0 6px}' +
        'p{line-height:1.5;color:#333}img.qr{margin:14px auto;display:block;border:1px solid #eee;border-radius:8px}' +
        '.uri{word-break:break-all;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.72em;' +
        'color:#555;background:#fafafa;border:1px solid #eee;border-radius:6px;padding:8px;text-align:left}' +
        '.meta{margin-top:20px;padding-top:14px;border-top:1px solid #eee;font-size:.78em;color:#777;text-align:left}' +
        'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}' +
        '</style></head><body><div class="card">' +
        '<h1>Scan this with your wallet</h1>' +
        '<p>Your wallet will show you exactly which claims we are asking for before anything is sent.</p>' +
        '<img class="qr" id="request_qr" alt="OID4VP Authorization Request QR code" src="' + dataUrl + '">' +
        '<div class="uri" id="request_uri">' + xmlEscape(opts.requestUri) + '</div>' +
        '<div class="meta">OID4VP cross-device flow. The wallet is on your other device, so it cannot be ' +
        'redirected — it reads the request from this code and POSTs the presentation straight back to us ' +
        '(<code>response_mode=direct_post</code>). The <code>nonce</code> in the request is what stops a ' +
        'presentation from being replayed. If your wallet is on this device, ' +
        '<a id="open_in_wallet" href="' + xmlEscape(opts.walletUrl) + '">open it here</a>.' +
        '</div></div></body></html>\n';
      res.status(200).type('text/html').send(page);
      log.debug("Leaving renderVpQrPage().");
    })
    .catch(function (e) {
      log.error("could not render the presentation QR code: " + e.message);
      res.status(500).type('text/plain').send('Could not render the Authorization Request QR code: ' + e.message);
    });
}

// The Request Object, fetched by reference (request_uri). Signed, and served with
// the media type RFC 9101 defines for it.
app.get('/oid4vp/request/:id', function (req, res) {
  log.debug("Entering the request object endpoint. id=" + req.params.id);
  const state = vpRequests.get(String(req.params.id));
  const record = state ? vpTransactions.get(state) : null;
  if (!record || !record.requestObject) {
    log.debug("Leaving the request object endpoint. No such request.");
    return oauthError(res, 404, 'invalid_request', 'No such Request Object.');
  }
  res.status(200).type('application/oauth-authz-req+jwt').send(record.requestObject);
  log.debug("Leaving the request object endpoint. Served a signed Request Object.");
});

// ---------------------------------------------------------------------------
// Verifying a presentation (RFC 9901 section 7.3, plus OID4VP's rules for the
// Key Binding JWT).
//
// Every check is recorded with its own verdict rather than collapsed into one
// boolean: "the presentation was refused" is not a useful answer to a wallet
// developer, and a debugger's job is to say WHICH rule was broken.
// ---------------------------------------------------------------------------
function vpCheck(checks, name, ok, detail) {
  checks.push({ name: name, ok: !!ok, detail: detail });
  log.debug("vpCheck(): " + name + " -> " + (ok ? "OK" : "FAILED") + " (" + detail + ")");
  return !!ok;
}

// base64url(hash) of the US-ASCII of everything before the KB-JWT, which is what
// sd_hash has to be (RFC 9901 section 4.3.1).
function sdHashOf(presentedWithoutKb, sdAlg) {
  const alg = String(sdAlg || 'sha-256').toLowerCase();
  const nodeAlg = { 'sha-256': 'sha256', 'sha-384': 'sha384', 'sha-512': 'sha512' }[alg];
  if (!nodeAlg) return null;
  return b64u(crypto.createHash(nodeAlg).update(presentedWithoutKb, 'ascii').digest());
}

// A W3C Verifiable Presentation secured as a JWT, carrying a jwt_vc_json
// credential (OID4VP with format jwt_vc_json).
//
// The checks are the same QUESTIONS the SD-JWT path asks, answered against a
// different artefact — which is the point of running both formats through this
// workflow:
//
//   who signed the credential          the issuer's key, as before
//   is it still valid                  nbf/exp, as before
//   is the holder the one it was bound to
//                                      here the VP JWT's signature against the
//                                      credential's cnf.jwk, where an SD-JWT
//                                      uses a Key Binding JWT
//   is this presentation fresh and for us
//                                      nonce and aud, as before — but they are
//                                      claims of the VP JWT, not of a KB-JWT
//   what was disclosed                 everything in credentialSubject, because
//                                      this format cannot withhold anything
//
// There is deliberately no sd_hash equivalent: an SD-JWT's KB-JWT commits to the
// exact bytes presented because a presentation can be a SUBSET. A VP JWT signs
// over the whole credential it embeds, so the commitment is the signature.
// A bbs-2023 derived proof (OID4VP format ldp_vc).
//
// The same questions as the other two formats, asked of a very different
// artefact. There is no issuer signature to check on what arrives — a derived
// proof IS the signature, re-randomised — so "did the issuer sign this" and "is
// this the holder presenting it" collapse into one check.
//
// SHAPE NOTE, a stated simplification: a full bbs-2023 presentation
// reconstructs a JSON-LD document from the disclosed statements. This mock is
// handed the statements and their indexes directly, beside the proof and the
// issuer's proof options. Everything cryptographic is real — the proof is
// verified against this service's BBS key over exactly those statements, with
// this request's nonce as the presentation header — but another verifier would
// expect a document.
async function verifyLdpVc(presentation, record) {
  log.debug("Entering verifyLdpVc().");
  const checks = [];
  const result = { ok: false, checks, claims: {}, disclosed: [], vct: '', sub: '', extraDisclosed: [] };

  let payload;
  try {
    payload = typeof presentation === 'string' ? JSON.parse(presentation) : presentation;
  } catch (e) {
    vpCheck(checks, 'Format', false, 'an ldp_vc presentation here is a JSON object carrying the ' +
      'derived proof and the statements it discloses; this is not JSON: ' + e.message);
    return result;
  }
  const proofBytes = payload.proof ? bbs2023.b64uToBytes(payload.proof) : null;
  const statements = [].concat(payload.disclosedStatements || []);
  const indexes = [].concat(payload.disclosedIndexes || []);
  if (!proofBytes || !statements.length || statements.length !== indexes.length) {
    vpCheck(checks, 'Format', false,
      'expected proof, disclosedStatements and disclosedIndexes of equal length; got ' +
      statements.length + ' statement(s) and ' + indexes.length + ' index(es).');
    return result;
  }
  vpCheck(checks, 'Format', true,
    'a bbs-2023 derived proof disclosing ' + statements.length + ' canonical statement(s).');

  const keys = await bbsKeyPair();
  let header;
  try {
    header = await bbs2023.headerFor(payload.proofOptions || {});
  } catch (e) {
    vpCheck(checks, 'Proof options', false, 'could not be canonicalized: ' + e.message);
    return result;
  }
  vpCheck(checks, 'Proof options', true, 'canonicalized to the header the base proof was bound to.');

  const ok = await bbs2023.verifyDerived(keys.publicKey, proofBytes, header,
    Buffer.from(String(record.nonce), 'utf8'), statements, indexes);
  vpCheck(checks, 'Derived proof', ok, ok
    ? "verifies against this issuer's BBS key over exactly the statements disclosed, and against this " +
      "request's nonce — so it was derived for THIS request and cannot be replayed."
    : 'does not verify. Either it was not derived from a credential this issuer signed, the statements ' +
      'do not match what was proved, or it was derived against a different nonce.');

  statements.forEach(function (line, i) {
    result.claims['statement ' + (indexes[i] + 1)] = String(line).trim();
  });
  result.disclosed = indexes.map(function (i) { return 'statement ' + (i + 1); });
  result.ok = checks.every(function (c) { return c.ok; });
  log.debug("Leaving verifyLdpVc(). " + (result.ok ? 'accepted' : 'REFUSED'));
  return result;
}

function verifyVpJwt(presentation, record) {
  log.debug("Entering verifyVpJwt().");
  logArtifact('OID4VP Verifiable Presentation (jwt_vc_json)', 'as received', presentation);
  const checks = [];
  const result = { ok: false, checks: checks, claims: {}, disclosed: [], vct: '', sub: '',
                   extraDisclosed: [] };

  // The tilde test comes FIRST, and it has to. An SD-JWT Combined Serialization
  // is <JWT>~<Disclosure>*~ — splitting THAT on "." also yields three parts,
  // because the tildes hang off the end of the signature segment. So a
  // part-count check alone lets an SD-JWT through to be reported as an
  // undecodable JWT, which names the wrong problem: the wallet answered in the
  // wrong FORMAT, and that is what it needs to be told.
  const raw = String(presentation || '');
  if (raw.indexOf('~') >= 0) {
    vpCheck(checks, 'Format', false,
      'this is an SD-JWT Combined Serialization (it contains "~"), but this request asked for ' +
      'jwt_vc_json, whose presentation is a Verifiable Presentation JWT.');
    log.debug("Leaving verifyVpJwt(). An SD-JWT answered a jwt_vc_json query.");
    return result;
  }
  const vpParts = raw.split('.');
  if (vpParts.length !== 3) {
    vpCheck(checks, 'Format', false,
      'a jwt_vc_json presentation is a Verifiable Presentation JWT (three parts); this has ' +
      vpParts.length + ' part(s).');
    log.debug("Leaving verifyVpJwt(). Not a JWS.");
    return result;
  }
  let vpHeader = {}, vpPayload = {};
  try {
    vpHeader = jsonFromB64u(vpParts[0]);
    vpPayload = jsonFromB64u(vpParts[1]);
  } catch (e) {
    vpCheck(checks, 'Format', false, 'the presentation JWT cannot be decoded: ' + e.message);
    return result;
  }
  const vp = vpPayload.vp || {};
  const embedded = [].concat(vp.verifiableCredential || []);
  if (!embedded.length || typeof embedded[0] !== 'string') {
    vpCheck(checks, 'Format', false,
      'the vp claim carries no verifiableCredential; a jwt_vc_json presentation embeds the credential JWT there.');
    log.debug("Leaving verifyVpJwt(). No credential inside.");
    return result;
  }
  vpCheck(checks, 'Format', true,
    'Verifiable Presentation JWT carrying ' + embedded.length + ' credential(s); no Disclosures, because ' +
    'jwt_vc_json has no selective disclosure.');

  // --- the credential inside -----------------------------------------------
  const vcJwt = embedded[0];
  let vcHeader = {}, vcPayload = {};
  try {
    vcHeader = jsonFromB64u(vcJwt.split('.')[0]);
    vcPayload = jsonFromB64u(vcJwt.split('.')[1]);
  } catch (e) {
    vpCheck(checks, 'Credential', false, 'the embedded credential cannot be decoded: ' + e.message);
    return result;
  }
  const vc = vcPayload.vc || {};
  const subject = vc.credentialSubject || {};
  result.sub = vcPayload.sub || subject.id || '';

  let issuerSignatureOk = false;
  try {
    jwt.verify(vcJwt, STS.certPem, { algorithms: ['RS256'] });
    issuerSignatureOk = true;
  } catch (e) {
    vpCheck(checks, 'Issuer signature', false, 'does not verify: ' + e.message);
  }
  if (issuerSignatureOk) {
    vpCheck(checks, 'Issuer signature', true, "verifies against the issuer's key (alg " + vcHeader.alg + ').');
  }
  const now = nowSec();
  vpCheck(checks, 'Validity window',
    (!vcPayload.exp || vcPayload.exp > now) && (!vcPayload.nbf || vcPayload.nbf <= now),
    'nbf ' + (vcPayload.nbf || '—') + ', exp ' + (vcPayload.exp || '—') + ', now ' + now + '.');

  const types = [].concat(vc.type || []);
  const wantedTypes = VCI_JWT_TYPES;
  const typesOk = wantedTypes.every(function (t) { return types.indexOf(t) >= 0; });
  vpCheck(checks, 'Credential type', typesOk,
    'type is [' + types.join(', ') + ']; this Verifier asked for [' + wantedTypes.join(', ') + '].');

  // --- holder binding: the VP JWT is signed by the key the credential names --
  const cnfJwk = (vcPayload.cnf || {}).jwk;
  if (!cnfJwk) {
    vpCheck(checks, 'Holder binding', false,
      'the credential carries no cnf.jwk, so nothing says which key may present it.');
  } else {
    let holderOk = false;
    try {
      const holderKey = crypto.createPublicKey({ key: cnfJwk, format: 'jwk' });
      holderOk = crypto.verify(
        vpHeader.alg === 'RS256' ? 'sha256' : null,
        Buffer.from(vpParts[0] + '.' + vpParts[1]),
        vpHeader.alg === 'RS256'
          ? holderKey
          : { key: holderKey, dsaEncoding: 'ieee-p1363' },
        Buffer.from(vpParts[2], 'base64url'));
    } catch (e) {
      vpCheck(checks, 'Holder binding', false, 'the presentation signature could not be checked: ' + e.message);
    }
    if (holderOk) {
      vpCheck(checks, 'Holder binding', true,
        'the presentation JWT is signed by the key the credential is bound to (cnf.jwk, alg ' +
        vpHeader.alg + ').');
    } else {
      vpCheck(checks, 'Holder binding', false,
        'the presentation JWT is NOT signed by the key the credential is bound to (cnf.jwk).');
    }
  }

  // --- freshness and audience ----------------------------------------------
  vpCheck(checks, 'Nonce', vpPayload.nonce === record.nonce,
    'nonce is "' + (vpPayload.nonce || '—') + '"; this request used "' + record.nonce + '".');
  vpCheck(checks, 'Audience', String(vpPayload.aud) === String(record.clientId),
    'aud is "' + vpPayload.aud + '"; this Verifier is "' + record.clientId + '".');

  // --- what arrived ---------------------------------------------------------
  // Everything in credentialSubject came, because this format cannot send less.
  // `id` is the subject identifier rather than a claim, so it is not counted.
  const present = Object.keys(subject).filter(function (k) { return k !== 'id'; });
  present.forEach(function (name) { result.claims[name] = subject[name]; });
  result.disclosed = present;
  const missing = VP_REQUESTED_CLAIMS.filter(function (name) { return present.indexOf(name) < 0; });
  result.extraDisclosed = present.filter(function (name) { return VP_REQUESTED_CLAIMS.indexOf(name) < 0; });
  vpCheck(checks, 'Requested claims', missing.length === 0,
    missing.length
      ? 'missing: ' + missing.join(', ') + '.'
      : 'all ' + VP_REQUESTED_CLAIMS.length + ' requested claim(s) arrived' +
        (result.extraDisclosed.length
          ? ', along with ' + result.extraDisclosed.length + ' this Verifier did not ask for (' +
            result.extraDisclosed.join(', ') + ') — jwt_vc_json cannot withhold them.'
          : '.'));

  result.ok = checks.every(function (c) { return c.ok; });
  log.debug("Leaving verifyVpJwt(). " + (result.ok ? "accepted" : "REFUSED") + ", " +
            checks.filter(function (c) { return !c.ok; }).length + " failed check(s).");
  return result;
}

function verifyPresentation(presentation, record) {
  log.debug("Entering verifyPresentation().");
  logArtifact('OID4VP Verifiable Presentation', 'as received', presentation);
  const checks = [];
  const result = { ok: false, checks: checks, claims: {}, disclosed: [], vct: '', sub: '' };
  const parts = String(presentation || '').split('~');
  if (parts.length < 2) {
    vpCheck(checks, 'Format', false,
      'a presentation is <Issuer-signed JWT>~<Disclosure>*~<KB-JWT>; this has ' + parts.length + ' part(s).');
    log.debug("Leaving verifyPresentation(). Not a Combined Serialization.");
    return result;
  }
  const issuerJwt = parts[0];
  const kbJwt = parts[parts.length - 1];
  const disclosures = parts.slice(1, parts.length - 1).filter(function (d) { return d !== ''; });
  vpCheck(checks, 'Format', true,
    'SD-JWT+KB with ' + disclosures.length + ' Disclosure(s) and a Key Binding JWT.');

  // --- the issuer-signed JWT ------------------------------------------------
  let header = {};
  let payload = {};
  try {
    header = jsonFromB64u(issuerJwt.split('.')[0]);
    payload = jsonFromB64u(issuerJwt.split('.')[1]);
  } catch (e) {
    vpCheck(checks, 'Issuer-signed JWT', false, 'cannot be decoded: ' + e.message);
    log.debug("Leaving verifyPresentation(). Undecodable credential.");
    return result;
  }
  result.vct = payload.vct || '';
  result.sub = payload.sub || '';
  vpCheck(checks, 'Media type (typ)', ['dc+sd-jwt', 'vc+sd-jwt'].indexOf(String(header.typ)) >= 0,
    'typ is "' + header.typ + '".');
  let issuerSignatureOk = false;
  try {
    jwt.verify(issuerJwt, STS.certPem, { algorithms: ['RS256'] });
    issuerSignatureOk = true;
  } catch (e) {
    // Not signed by us — or expired, which jsonwebtoken reports here too. Both
    // are reasons to refuse, and the message says which.
    vpCheck(checks, 'Issuer signature', false, 'does not verify: ' + e.message);
  }
  if (issuerSignatureOk) {
    vpCheck(checks, 'Issuer signature', true, 'verifies against the issuer\'s key (alg RS256).');
  }
  const now = nowSec();
  vpCheck(checks, 'Validity window',
    (!payload.exp || payload.exp > now) && (!payload.nbf || payload.nbf <= now),
    'nbf ' + (payload.nbf || '—') + ', exp ' + (payload.exp || '—') + ', now ' + now + '.');
  vpCheck(checks, 'Credential type (vct)', payload.vct === VCI_VCT,
    'vct is "' + payload.vct + '"; this Verifier asked for "' + VCI_VCT + '".');

  // --- the Disclosures presented -------------------------------------------
  // Every one must hash to a digest the issuer signed. This is the check that
  // catches a Disclosure invented by whoever is presenting.
  const sdAlg = payload._sd_alg || 'sha-256';
  const nodeAlg = { 'sha-256': 'sha256', 'sha-384': 'sha384', 'sha-512': 'sha512' }[String(sdAlg).toLowerCase()];
  const signedDigests = [];
  (function collect(node) {
    log.debug("Entering collect().");
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) {
      node.forEach(function (item) {
        if (item && typeof item === 'object' && typeof item['...'] === 'string') signedDigests.push(item['...']);
        else collect(item);
      });
      return;
    }
    Object.keys(node).forEach(function (k) {
      if (k === '_sd' && Array.isArray(node[k])) node[k].forEach(function (d) { signedDigests.push(d); });
      else if (typeof node[k] === 'object') collect(node[k]);
    });
    log.debug("Leaving collect().");
  })(payload);

  let unmatched = 0;
  disclosures.forEach(function (encoded) {
    let arr = null;
    try {
      arr = JSON.parse(b64uDecode(encoded).toString('utf8'));
    } catch (e) {
      unmatched++;
      log.error('a presented Disclosure is not base64url JSON: ' + e.message);
      return;
    }
    const digest = nodeAlg ? b64u(crypto.createHash(nodeAlg).update(encoded, 'ascii').digest()) : '';
    if (signedDigests.indexOf(digest) === -1) {
      unmatched++;
      log.error('a presented Disclosure hashes to a digest the issuer never signed: ' + digest);
      return;
    }
    if (Array.isArray(arr) && arr.length === 3) {
      result.claims[arr[1]] = arr[2];
      result.disclosed.push(arr[1]);
    }
  });
  vpCheck(checks, 'Disclosure digests', unmatched === 0,
    unmatched === 0
      ? 'all ' + disclosures.length + ' presented Disclosure(s) hash to a digest in _sd.'
      : unmatched + ' presented Disclosure(s) were not signed by the issuer.');

  // The always-visible claims are part of what was presented too.
  Object.keys(payload).forEach(function (k) {
    if (['_sd', '_sd_alg', 'cnf'].indexOf(k) >= 0) return;
    if (!(k in result.claims)) result.claims[k] = payload[k];
  });

  // --- the Key Binding JWT --------------------------------------------------
  let kbHeader = {};
  let kbPayload = {};
  let kbReadable = false;
  try {
    kbHeader = jsonFromB64u(kbJwt.split('.')[0]);
    kbPayload = jsonFromB64u(kbJwt.split('.')[1]);
    kbReadable = kbJwt.split('.').length === 3;
  } catch (e) {
    kbReadable = false;
  }
  if (!kbReadable) {
    vpCheck(checks, 'Key Binding JWT', false,
      'the last element is not a readable three-part JWS, so the presentation has no holder proof at all.');
    result.ok = checks.every(function (c) { return c.ok; });
    log.debug("Leaving verifyPresentation(). No usable KB-JWT.");
    return result;
  }
  logArtifact('OID4VP Key Binding JWT', 'as received', { header: kbHeader, payload: kbPayload });
  vpCheck(checks, 'KB-JWT media type', String(kbHeader.typ) === 'kb+jwt',
    'typ is "' + kbHeader.typ + '"; RFC 9901 section 4.3 requires kb+jwt.');
  vpCheck(checks, 'KB-JWT algorithm', !!kbHeader.alg && kbHeader.alg !== 'none',
    'alg is ' + kbHeader.alg + '.');
  vpCheck(checks, 'KB-JWT nonce', kbPayload.nonce === record.nonce,
    kbPayload.nonce === record.nonce
      ? 'matches the nonce in this Authorization Request.'
      : 'is "' + kbPayload.nonce + '", but this request\'s nonce is "' + record.nonce +
        '" — a presentation made for another request, or replayed.');
  vpCheck(checks, 'KB-JWT audience', kbPayload.aud === record.clientId,
    kbPayload.aud === record.clientId
      ? 'is this Verifier\'s Client Identifier.'
      : 'is "' + kbPayload.aud + '", not "' + record.clientId + '" — this presentation was made for someone else.');
  vpCheck(checks, 'KB-JWT freshness',
    !!kbPayload.iat && Math.abs(now - Number(kbPayload.iat)) <= VP_KB_MAX_AGE_S,
    'iat is ' + kbPayload.iat + ' (' + (kbPayload.iat ? (now - Number(kbPayload.iat)) + 's ago' : 'absent') +
    '); at most ' + VP_KB_MAX_AGE_S + 's is accepted.');

  // sd_hash ties the KB-JWT to exactly these bytes: the issuer-signed JWT and the
  // Disclosures presented, each followed by a tilde.
  const withoutKb = parts.slice(0, parts.length - 1).join('~') + '~';
  const expectedSdHash = sdHashOf(withoutKb, sdAlg);
  vpCheck(checks, 'KB-JWT sd_hash', !!expectedSdHash && kbPayload.sd_hash === expectedSdHash,
    kbPayload.sd_hash === expectedSdHash
      ? 'is the hash of exactly the bytes presented, so no Disclosure was added or removed after it was signed.'
      : 'is "' + kbPayload.sd_hash + '" but these bytes hash to "' + expectedSdHash +
        '" — the presentation was altered after the holder signed it.');

  // The signature must verify against the key the CREDENTIAL names, not one the
  // presenter chose: that is what key binding means.
  const cnfJwk = (payload.cnf && payload.cnf.jwk) || null;
  if (!cnfJwk) {
    vpCheck(checks, 'KB-JWT signature', false,
      'the credential carries no cnf.jwk, so there is no key this presentation could be bound to.');
  } else {
    try {
      const holderKey = crypto.createPublicKey({ key: cnfJwk, format: 'jwk' });
      jwt.verify(kbJwt, holderKey, { algorithms: ['ES256', 'ES384', 'RS256', 'PS256'] });
      vpCheck(checks, 'KB-JWT signature', true,
        'verifies against the cnf key in the credential (' + cnfJwk.kty + ' ' + (cnfJwk.crv || '') + ').');
    } catch (e) {
      vpCheck(checks, 'KB-JWT signature', false,
        'does NOT verify against the cnf key in the credential: ' + e.message);
    }
  }

  // --- did we get what we asked for? ---------------------------------------
  const missing = VP_REQUESTED_CLAIMS.filter(function (name) { return !(name in result.claims); });
  vpCheck(checks, 'Requested claims', missing.length === 0,
    missing.length === 0
      ? 'every claim the DCQL query asked for is present (' + VP_REQUESTED_CLAIMS.join(', ') + ').'
      : 'missing: ' + missing.join(', ') + '.');
  // Not a failure — the holder may disclose more than was asked — but worth
  // saying, because over-disclosure is the thing SD-JWT VC exists to prevent.
  const extra = result.disclosed.filter(function (name) { return VP_REQUESTED_CLAIMS.indexOf(name) === -1; });
  result.extraDisclosed = extra;

  result.ok = checks.every(function (c) { return c.ok; });
  log.debug("Leaving verifyPresentation(). ok=" + result.ok + ", " + checks.length + " check(s), " +
            result.disclosed.length + " disclosed claim(s), " + extra.length + " more than asked for.");
  return result;
}

// The Response URI (OID4VP section 8.2): response_mode direct_post, so the
// Authorization Response arrives as a form POST rather than in a URL.
app.post('/oid4vp/response', async function (req, res) {
  log.debug("Entering the OID4VP response endpoint.");
  const body = parseBody(req);
  const state = String(body.state || '');
  const record = vpTransactions.get(state);
  if (!record) {
    log.debug("Leaving the OID4VP response endpoint. Unknown state.");
    return oauthError(res, 400, 'invalid_request',
      'Unknown or expired state: this Verifier has no such Authorization Request outstanding.');
  }
  if (body.error) {
    // The wallet refused, which is a legitimate answer (section 8.4).
    record.verdict = { ok: false, refused: true, error: String(body.error),
                       errorDescription: String(body.error_description || ''), checks: [], at: new Date().toISOString() };
    res.status(200).type('application/json').send(JSON.stringify({
      redirect_uri: baseUrlOf(req) + '/oid4vp/done?state=' + encodeURIComponent(state)
    }));
    log.debug("Leaving the OID4VP response endpoint. The wallet refused: " + body.error);
    return;
  }

  // vp_token is a JSON object keyed by the DCQL credential query id, each value
  // an array of presentations (section 8.1).
  let presentations = [];
  let tokenShapeOk = true;
  try {
    const parsed = typeof body.vp_token === 'string' ? JSON.parse(body.vp_token) : body.vp_token;
    const forQuery = parsed && parsed[VP_DCQL_ID];
    if (Array.isArray(forQuery)) presentations = forQuery;
    else if (typeof forQuery === 'string') presentations = [forQuery];
    else tokenShapeOk = false;
  } catch (e) {
    log.error('the vp_token is not the JSON object OID4VP defines: ' + e.message);
    tokenShapeOk = false;
  }
  if (!tokenShapeOk || !presentations.length) {
    record.verdict = {
      ok: false, at: new Date().toISOString(),
      checks: [{ name: 'vp_token', ok: false,
                 detail: 'vp_token must be a JSON object keyed by the DCQL credential query id ("' +
                         VP_DCQL_ID + '"), each value an array of presentations.' }]
    };
    res.status(400).type('application/json').send(JSON.stringify({
      error: 'invalid_request',
      error_description: 'vp_token is not the JSON object OID4VP section 8.1 defines.'
    }));
    log.debug("Leaving the OID4VP response endpoint. Malformed vp_token.");
    return;
  }

  // Verified against the format THIS request asked for, so answering a
  // jwt_vc_json query with an SD-JWT (or the reverse) is refused rather than
  // silently handled by the other code path.
  const verified = record.format === 'ldp_vc'
    ? await verifyLdpVc(presentations[0], record)
    : record.format === 'jwt_vc_json'
      ? verifyVpJwt(presentations[0], record)
      : verifyPresentation(presentations[0], record);
  record.verdict = {
    ok: verified.ok,
    at: new Date().toISOString(),
    checks: verified.checks,
    claims: verified.claims,
    disclosed: verified.disclosed,
    extraDisclosed: verified.extraDisclosed || [],
    requested: VP_REQUESTED_CLAIMS,
    vct: verified.vct,
    sub: verified.sub,
    presentation: presentations[0]
  };
  logArtifact('OID4VP verification result', verified.ok ? 'accepted' : 'REFUSED', record.verdict);

  if (!verified.ok) {
    // Section 8.4: an invalid presentation is invalid_request. The failing checks
    // go in the description, because a wallet developer cannot fix "no".
    const failed = verified.checks.filter(function (c) { return !c.ok; });
    res.status(400).type('application/json').send(JSON.stringify({
      error: 'invalid_request',
      error_description: 'The presentation was refused: ' +
        failed.map(function (c) { return c.name + ' — ' + c.detail; }).join(' | ')
    }));
    log.debug("Leaving the OID4VP response endpoint. Refused " + failed.length + " check(s).");
    return;
  }
  res.status(200).type('application/json').send(JSON.stringify({
    redirect_uri: baseUrlOf(req) + '/oid4vp/done?state=' + encodeURIComponent(state)
  }));
  log.debug("Leaving the OID4VP response endpoint. Accepted.");
});

// Not in the spec: the verdict, so the wallet's own page (and the test suite) can
// show what this Verifier decided and why. A real Verifier tells the End-User in
// its own UI; this makes the same information machine-readable.
app.get('/oid4vp/result/:state', function (req, res) {
  log.debug("Entering the presentation result endpoint. state=" + req.params.state);
  const record = vpTransactions.get(String(req.params.state));
  if (!record) {
    log.debug("Leaving the presentation result endpoint. Unknown state.");
    return oauthError(res, 404, 'invalid_request', 'No such presentation.');
  }
  res.set('Access-Control-Allow-Origin', '*');
  res.status(200).type('application/json').send(JSON.stringify({
    state: record.state,
    nonce: record.nonce,
    client_id: record.clientId,
    requested: VP_REQUESTED_CLAIMS,
    dcql_query: record.request.dcql_query,
    received: !!record.verdict,
    verdict: record.verdict
  }));
  log.debug("Leaving the presentation result endpoint. received=" + !!record.verdict);
});

// Where the wallet sends the End-User once the Verifier has answered.
app.get('/oid4vp/done', function (req, res) {
  log.debug("Entering the verifier done page.");
  const record = vpTransactions.get(String(req.query.state || ''));
  const verdict = record && record.verdict;
  const ok = !!(verdict && verdict.ok);
  const page = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<title>The Bar Door — ' + (ok ? 'come on in' : 'not today') + '</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
    'display:flex;align-items:center;justify-content:center;min-height:100vh;color:#222}' +
    '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:30px 34px;width:560px;' +
    'box-shadow:0 6px 24px rgba(0,0,0,.08)}h1{font-size:1.3em;margin:0 0 6px}' +
    'p{line-height:1.5;color:#333}ul{line-height:1.5}.ok{color:#2e7d32;font-weight:700}' +
    '.bad{color:#b00020;font-weight:700}' +
    'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}</style></head><body><div class="card">' +
    '<h1>The Bar Door</h1>' +
    (verdict
      ? '<p class="' + (ok ? 'ok' : 'bad') + '" id="verdict">' +
        (ok ? 'Presentation accepted.' : 'Presentation refused.') + '</p>' +
        '<ul id="claims">' + Object.keys(verdict.claims || {}).map(function (k) {
          return '<li><code>' + xmlEscape(k) + '</code>: <code>' +
                 xmlEscape(typeof verdict.claims[k] === 'object'
                   ? JSON.stringify(verdict.claims[k]) : String(verdict.claims[k])) + '</code></li>';
        }).join('') + '</ul>' +
        '<p style="font-size:.85em;color:#666">We asked for <code>' +
        xmlEscape((verdict.requested || []).join(', ')) + '</code> and that is all we know about you.</p>'
      : '<p id="verdict">Nothing has been presented for this request yet.</p>') +
    '</div></body></html>\n';
  res.status(200).type('text/html').send(page);
  log.debug("Leaving the verifier done page. ok=" + ok);
});

module.exports = {
  verifyPresentation: verifyPresentation,
  buildVpRequest: buildVpRequest,
  vpDcqlQuery: vpDcqlQuery
};
