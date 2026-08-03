'use strict';
//
// File: vc_offers.js
//
// ---------------------------------------------------------------------------
// Credential Offer (OID4VCI section 4) — the issuer-initiated half of issuance.
//
// Appendix H.1 "Credential Offer - Same-Device": the End-User is browsing the
// issuer's site, follows a "request your digital diploma" link, and is taken to
// their Wallet with a Credential Offer in hand. That is what these three
// endpoints are:
//
//   GET /issuer                     the issuer's web page, with the link
//   GET /issuer/offer               builds an offer and redirects to the wallet,
//                                   by value (credential_offer) or by reference
//                                   (credential_offer_uri)
//   GET /oid4vci/credential-offer/:id  serves an offer fetched by reference
//
// The offer names this issuer, the credential configuration(s) on offer, and the
// grant. For H.1 that grant is authorization_code carrying an issuer_state,
// which the Wallet must hand back on the authorization request so the issuer can
// tie the two together.
//
// The Wallet a browser page can be sent to is a URL, not the openid-credential-offer://
// scheme a native wallet would register — OID4VCI_WALLET_URL says where it lives.
// ---------------------------------------------------------------------------
//
// This module owns the STATE the offer creates — the offers themselves, the
// issuer_states, the pre-authorized codes and the deferred transactions — and
// that ownership is the reason it is a module rather than part of vc_issuer.js.
// The pre-authorized code grant is redeemed at the TOKEN ENDPOINT, which belongs
// to the authorization server, and issuer_state is read on the AUTHORIZATION
// request. So this state is shared between OID4VCI and OAuth2 by design, and
// putting it in either of them would make those two require each other.
// ---------------------------------------------------------------------------

const qrcode = require('qrcode');
const app = require('./app');
const { log, logArtifact, baseUrlOf, randomId, xmlEscape, vciError, userFor,
        WALLET_BASE_URL } = require('./helpers');
const { VCI_CONFIG_ID, vciConfigIds } = require('./vc_configs');
const credentialOffers = new Map();     // id -> { offer, issuerState, expires }

const issuerStates = new Map();         // issuer_state -> { configurationIds, expires }

// Pre-authorized codes (OID4VCI Appendix H.2 / H.3): the End-User authorized the
// issuance out of band, so there is no authorization request at all — the code
// in the offer IS the authorization. `txCode` is the Transaction Code the issuer
// shows on its own screen and the End-User types into the wallet; `deferred`
// marks an issuance the credential endpoint will not complete immediately.
const preAuthorizedCodes = new Map();   // code -> { configurationIds, txCode, user, deferred, expires }

// Deferred issuance transactions (OID4VCI section 9): the credential endpoint
// answered 202 with one of these instead of a credential.
const deferredTransactions = new Map(); // transaction_id -> { claims, holderJwk, readyAt, expires }

// Access tokens minted from a deferred offer: the credential endpoint answers
// 202 for these instead of issuing straight away.
const deferredAccessTokens = new Set();

// How long a deferred issuance "takes". Short enough for a test to wait for it,
// long enough that the first poll genuinely comes back still-pending.
const DEFERRED_READY_MS = Number(process.env.OID4VCI_DEFERRED_READY_MS || 4000);

const DEFERRED_INTERVAL_S = Number(process.env.OID4VCI_DEFERRED_INTERVAL_S || 2);

const OFFER_TTL_MS = 10 * 60 * 1000;

// A pre-authorized offer is made to an End-User the issuer has ALREADY
// identified (H.2: they uploaded documents to an employee portal days before),
// so the issuer knows the subject without anyone signing in.
const VCI_OFFER_USERNAME = process.env.OID4VCI_OFFER_USERNAME || 'diploma.student';

// Build a Credential Offer for one of the Appendix H use cases.
//
//   same-device  (H.1) authorization_code + issuer_state: the wallet still has
//                      to take the End-User through the authorization server.
//   cross-device (H.2) pre-authorized_code + tx_code: the End-User already
//                      identified themselves to the issuer by some other route,
//                      so the code IS the authorization and the Transaction
//                      Code shown on the issuer's screen is what ties the
//                      wallet on the other device to this End-User.
//   deferred     (H.3) the same pre-authorized offer, but flagged so the
//                      credential endpoint answers 202 with a transaction_id
//                      instead of a credential.
function buildCredentialOffer(req, configurationIds, mode) {
  log.debug("Entering buildCredentialOffer(). mode=" + mode);
  const base = baseUrlOf(req);
  const expires = Date.now() + OFFER_TTL_MS;
  const offer = {
    credential_issuer: base,
    credential_configuration_ids: configurationIds
  };
  let issuerState = "";
  let preAuthorizedCode = "";
  let txCodeValue = "";

  if (mode === 'cross-device' || mode === 'deferred') {
    preAuthorizedCode = randomId(24);
    // Five numeric digits, which is what the issuer's page displays. The value
    // never travels in the offer — only its shape does — because the whole
    // point is that it reaches the End-User by a different channel.
    txCodeValue = String(Math.floor(Math.random() * 90000) + 10000);
    preAuthorizedCodes.set(preAuthorizedCode, {
      configurationIds: configurationIds,
      txCode: txCodeValue,
      user: userFor(VCI_OFFER_USERNAME),
      deferred: mode === 'deferred',
      expires: expires
    });
    offer.grants = {
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code': preAuthorizedCode,
        tx_code: {
          input_mode: 'numeric',
          length: txCodeValue.length,
          // No apostrophe: this string is URL-encoded into the offer, and an
          // apostrophe survives encodeURIComponent only to be XML-escaped into
          // "&apos;" when the offer URI is displayed — which turns one query
          // parameter into two for anything reading it off the page.
          description: 'Type the ' + txCodeValue.length + '-digit code shown by the issuer.'
        },
        interval: 5
      }
    };
  } else {
    issuerState = randomId(18);
    issuerStates.set(issuerState, { configurationIds: configurationIds, expires: expires });
    offer.grants = { authorization_code: { issuer_state: issuerState } };
  }

  logArtifact('OID4VCI Credential Offer', 'as built', offer);
  log.debug("Leaving buildCredentialOffer(). mode=" + mode + ", issuer_state=" + issuerState +
            ", pre-authorized=" + (preAuthorizedCode ? "yes" : "no"));
  return { offer: offer, issuerState: issuerState,
           preAuthorizedCode: preAuthorizedCode, txCode: txCodeValue, mode: mode || 'same-device' };
}

// The issuer's own web page — where H.1 starts.
app.get('/issuer', function (req, res) {
  log.debug("Entering the issuer web page.");
  const base = baseUrlOf(req);
  const configId = VCI_CONFIG_ID;
  const page = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
    '<title>Mock University — digital diploma</title><style>' +
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
    'display:flex;align-items:center;justify-content:center;min-height:100vh;color:#222}' +
    '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:30px 34px;width:520px;' +
    'box-shadow:0 6px 24px rgba(0,0,0,.08)}h1{font-size:1.3em;margin:0 0 6px}' +
    'p{line-height:1.5;color:#333}a.cta{display:inline-block;margin-top:14px;margin-right:10px;padding:10px 16px;' +
    'border-radius:6px;background:#12107c;color:#fff;text-decoration:none;font-weight:600}' +
    'a.cta.secondary{background:#fff;color:#12107c;border:1px solid #12107c}' +
    'p.alt{margin-top:20px;font-size:.92em;color:#555}' +
    '.meta{margin-top:22px;padding-top:14px;border-top:1px solid #eee;font-size:.78em;color:#777}' +
    'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}</style></head><body><div class="card">' +
    '<h1>Mock University</h1>' +
    '<p>Congratulations on your graduation. Your diploma is available as a digital credential ' +
    '(<code>' + xmlEscape(configId) + '</code>) that you can keep in your wallet.</p>' +
    '<p><a class="cta" href="/issuer/offer">Request your digital diploma</a>' +
    '<a class="cta secondary" href="/issuer/offer?by=reference">Request it (offer by reference)</a></p>' +
    '<p class="alt">On a different device? These show a QR code to scan with your wallet instead:<br>' +
    '<a class="cta secondary" href="/issuer/offer?mode=cross-device">Show a QR code (cross-device)</a>' +
    '<a class="cta secondary" href="/issuer/offer?mode=deferred">Show a QR code (issuance takes a while)</a></p>' +
    '<div class="meta">This is the Credential Issuer\'s web page in OID4VCI Appendix H. The first two links ' +
    'build a Credential Offer and send you to your wallet at <code>' + xmlEscape(WALLET_BASE_URL) + '</code> ' +
    '(H.1, same device). The other two hand the offer over by QR code and a Transaction Code instead — H.2, ' +
    'and H.3 where the issuer needs time to produce the credential. The issuer is ' +
    '<code>' + xmlEscape(base) + '</code>.</div>' +
    '</div></body></html>\n';
  res.status(200).type('text/html').send(page);
  log.debug("Leaving the issuer web page.");
});

// The link on that page: build the offer and send the End-User to their wallet.
app.get('/issuer/offer', function (req, res) {
  log.debug("Entering the credential offer endpoint.");
  const base = baseUrlOf(req);
  const configurationIds = req.query.credential_configuration_ids
    ? String(req.query.credential_configuration_ids).split(',').filter(Boolean)
    : [VCI_CONFIG_ID];
  const mode = String(req.query.mode || 'same-device');
  const built = buildCredentialOffer(req, configurationIds, mode);
  const wallet = String(req.query.wallet || WALLET_BASE_URL).replace(/\/+$/, '') +
                 '/vc-issuance-1.html';

  // Sweep expired offers/states/codes while we are here.
  const now = Date.now();
  credentialOffers.forEach(function (v, k) { if (v.expires < now) credentialOffers.delete(k); });
  issuerStates.forEach(function (v, k) { if (v.expires < now) issuerStates.delete(k); });
  preAuthorizedCodes.forEach(function (v, k) { if (v.expires < now) preAuthorizedCodes.delete(k); });
  deferredTransactions.forEach(function (v, k) { if (v.expires < now) deferredTransactions.delete(k); });

  // How the offer reaches the wallet: in the URL, or behind a URI it fetches.
  let offerQuery;
  if (String(req.query.by || '') === 'reference') {
    const id = randomId(12);
    credentialOffers.set(id, { offer: built.offer, expires: now + OFFER_TTL_MS });
    const offerUri = base + '/oid4vci/credential-offer/' + id;
    offerQuery = 'credential_offer_uri=' + encodeURIComponent(offerUri);
    log.debug("The offer is passed by reference: " + offerUri);
  } else {
    offerQuery = 'credential_offer=' + encodeURIComponent(JSON.stringify(built.offer));
    log.debug("The offer is passed by value.");
  }

  // Same device (H.1): the wallet is right here, so send the browser to it.
  if (built.mode !== 'cross-device' && built.mode !== 'deferred') {
    res.redirect(302, wallet + '?' + offerQuery);
    log.debug("Leaving the credential offer endpoint. Sent the End-User to " + wallet + ".");
    return;
  }

  // Cross device (H.2 / H.3): the wallet is on the End-User's OTHER device, so
  // the offer is displayed for it to scan — as the openid-credential-offer URI
  // a wallet registers for — and the Transaction Code is shown here, on the
  // issuer's screen, never in the offer.
  const offerUri = 'openid-credential-offer://?' + offerQuery;
  renderOfferQrPage(res, {
    base: base,
    mode: built.mode,
    offerUri: offerUri,
    walletUrl: wallet + '?' + offerQuery,
    txCode: built.txCode,
    offer: built.offer
  });
  log.debug("Leaving the credential offer endpoint. Displayed a QR code for the wallet to scan.");
});

// The issuer's screen in a cross-device flow: a QR code carrying the Credential
// Offer, and — separately, which is the whole point — the Transaction Code.
function renderOfferQrPage(res, opts) {
  log.debug("Entering renderOfferQrPage(). mode=" + opts.mode);
  qrcode.toDataURL(opts.offerUri, { errorCorrectionLevel: 'M', margin: 2, width: 320 })
    .then(function (dataUrl) {
      const deferred = opts.mode === 'deferred';
      const page = '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
        '<title>Mock University — scan to receive your credential</title><style>' +
        'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;background:#f4f4f7;margin:0;' +
        'display:flex;align-items:center;justify-content:center;min-height:100vh;color:#222}' +
        '.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:30px 34px;width:560px;' +
        'box-shadow:0 6px 24px rgba(0,0,0,.08);text-align:center}h1{font-size:1.25em;margin:0 0 6px}' +
        'p{line-height:1.5;color:#333}img.qr{margin:14px auto;display:block;border:1px solid #eee;border-radius:8px}' +
        '.txcode{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:2.1em;letter-spacing:.28em;' +
        'font-weight:700;color:#12107c;background:#f0f0fa;border-radius:8px;padding:12px 6px;margin:6px 0 2px}' +
        '.uri{word-break:break-all;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.72em;' +
        'color:#555;background:#fafafa;border:1px solid #eee;border-radius:6px;padding:8px;text-align:left}' +
        '.meta{margin-top:20px;padding-top:14px;border-top:1px solid #eee;font-size:.78em;color:#777;text-align:left}' +
        'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}' +
        '</style></head><body><div class="card">' +
        '<h1>Scan this with your wallet</h1>' +
        '<p>Your digital diploma is ready to be claimed' +
        (deferred ? ', though issuing it will take us a little time once you ask.' : '.') + '</p>' +
        '<img class="qr" id="offer_qr" alt="Credential Offer QR code" src="' + dataUrl + '">' +
        '<p>Then type this Transaction Code into your wallet:</p>' +
        '<div class="txcode" id="tx_code">' + xmlEscape(opts.txCode) + '</div>' +
        '<p style="font-size:.8em;color:#777">It is shown here, and only here — it does not travel in the QR code.</p>' +
        '<div class="uri" id="offer_uri">' + xmlEscape(opts.offerUri) + '</div>' +
        '<div class="meta">OID4VCI Appendix ' + (deferred ? 'H.3' : 'H.2') + '. The offer uses the ' +
        '<code>pre-authorized_code</code> grant: you already identified yourself to this issuer, so your wallet ' +
        'goes straight to the token endpoint — there is no authorization request. ' +
        (deferred ? 'The credential endpoint will answer with a <code>transaction_id</code> and your wallet will ' +
                    'have to come back for the credential. ' : '') +
        'If your wallet is on this device, <a id="open_in_wallet" href="' + xmlEscape(opts.walletUrl) + '">open it here</a>.' +
        '</div></div></body></html>\n';
      res.status(200).type('text/html').send(page);
      log.debug("Leaving renderOfferQrPage(). Rendered a QR code.");
    })
    .catch(function (e) {
      log.error("could not render the offer QR code: " + e.message);
      res.status(500).type('text/plain').send('Could not render the Credential Offer QR code: ' + e.message);
    });
}

app.get('/oid4vci/credential-offer/:id', function (req, res) {
  log.debug("Entering the credential offer retrieval endpoint. id=" + req.params.id);
  const record = credentialOffers.get(req.params.id);
  if (!record || record.expires < Date.now()) {
    credentialOffers.delete(req.params.id);
    log.debug("Leaving the credential offer retrieval endpoint. No such offer.");
    return vciError(res, 404, 'invalid_request', 'No such Credential Offer, or it has expired.');
  }
  res.status(200).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(record.offer, null, 2));
  log.debug("Leaving the credential offer retrieval endpoint.");
});

module.exports = {
  credentialOffers: credentialOffers,
  issuerStates: issuerStates,
  preAuthorizedCodes: preAuthorizedCodes,
  deferredTransactions: deferredTransactions,
  deferredAccessTokens: deferredAccessTokens,
  DEFERRED_READY_MS: DEFERRED_READY_MS,
  DEFERRED_INTERVAL_S: DEFERRED_INTERVAL_S,
  OFFER_TTL_MS: OFFER_TTL_MS,
  VCI_OFFER_USERNAME: VCI_OFFER_USERNAME,
  buildCredentialOffer: buildCredentialOffer,
  renderOfferQrPage: renderOfferQrPage
};
