'use strict';
//
// File: tests/sts_saml11.js
//
// ===========================================================================
// THE MOCK STS'S SAML 1.1 BROWSER PROFILES, END TO END, OVER HTTP, WITH NO
// BROWSER.
//
// It sits here beside the four other tests that drive that service DIRECTLY —
// `sts_metadata.js`, `sts_dpop.js`, `admin_api.js`, `vc_did.js` — rather than in
// the mock's own repository, where it was written on 2026-08-25 and from where
// it was moved the same day. The reason for the move is not tidiness: a second
// suite, with a second runner, a second report and a second reason to be
// forgotten, is how a test stops being run. Everything in this file that is not
// about SAML 1.1 — the `--url` option nothing reads, the bunyan level off
// `CONFIG_FILE`, the generated username — is that move rather than the profile.
//
// **NOTHING IN THE DEBUGGER IS UNDER TEST HERE**, and that is the whole point
// of the file rather than a limitation of it. It is named `sts_saml11.js` for
// the same reason `sts_dpop.js` and `sts_metadata.js` are named as they are:
// the mock is the thing under test.
//
// **It was called `saml11_sso.js` until the debugger grew a SAML 1.1 service
// provider**, at which point that name belonged to the Selenium job that drives
// it — `tests/saml11_sso.js`, which is `saml_sso.js`'s sibling and runs the
// same round trip through the pages. The two are complementary and neither
// replaces the other:
//
//   * This file writes its OWN relying party, in the spirit of `sts_dpop.js`
//     writing its own DPoP client rather than importing the wallet's: if both
//     ends of the exchange came from one implementation, a shared
//     misunderstanding would pass and interoperate with nobody. It is also
//     almost entirely negatives, which a browser cannot easily reach — a
//     one-shot artifact resolved twice, an `InResponseTo` on a profile with no
//     request, a signature reference through the real `AssertionID`.
//   * `saml11_sso.js` proves the DEBUGGER builds a request that identity
//     provider accepts and renders the answer, which this file cannot say
//     anything about.
//
// The header sentence that used to be here — that the debugger's SAML workflow
// is SAML 2.0 SP-initiated and that selecting 1.1 returns an XML comment where
// a request would be — was true when this was written and is not true now.
//
// Needs the STS mock and nothing else — no browser, no Keycloak — so it is
// skipped only when there is no STS to talk to.
//
// ---------------------------------------------------------------------------
// WHAT IT IS FOR, WHICH IS NOT "THE HAPPY PATH WORKS".
//
// A SAML 1.1 identity provider that hands a working relying party a signed
// assertion looks finished and can be worth very little: the assertion verifies,
// somebody is signed in, and four of the things this profile most easily gets
// wrong are invisible. `tests/sts_dpop.js` says the same thing about DPoP and is
// almost entirely negatives; this file is written the same way. The four:
//
//   1. **THE CONFIRMATION METHOD.** saml-profile-1.1 section 4.1.1.4 requires
//      `cm:artifact` for Browser/Artifact and section 4.2.1.4 requires
//      `cm:bearer` for Browser/POST. A relying party that does not check works
//      perfectly with either, so nothing fails until it meets one that does —
//      and then the assertion is refused for a reason that reads like a
//      signature problem.
//   2. **THE SIGNATURE REFERENCE.** SAML 1.1 spells its ids `AssertionID` and
//      `ResponseID`, which xml-crypto does not know: told nothing, it INVENTS
//      `Id="_0"` and points the reference at that instead. It still verifies,
//      which is how it survived in that repository for years — until a document
//      carried TWO signatures and both got `Id="_0"`. The checks below verify
//      each signature THROUGH THE REAL ATTRIBUTE, which is the only way that
//      regression shows.
//   3. **`InResponseTo` ON A PROFILE WITH NO REQUEST.** Porting SAML 2.0 code
//      puts one there. It names a RequestID nobody minted, and a strict relying
//      party rejects it.
//   4. **THE ONE-SHOT ARTIFACT.** Section 3.2.3 makes an artifact resolvable
//      exactly once. Resolving twice is the single easiest thing to get wrong
//      and the hardest to notice, because the happy path passes either way.
//
// ---------------------------------------------------------------------------
// RUNNING IT
//
//   node tests/saml11_sso.js                    # with an STS mock listening
//
// `WSTRUST_STS_URL` or `OID4VCI_ISSUER_URL` — which every launcher here already
// sets — locates the service, exactly as the other four STS tests take theirs;
// `SAML11_IDP_URL` overrides both. The `--url` the runner hands every job is
// accepted and ignored: this test needs no browser.
//
// **IT RESTORES EVERYTHING IT CHANGES**, and restores it with
// `/admin-api/config/reset` rather than by writing the old value back. That
// distinction is `tests/CLAUDE.md`'s and it has already cost a run: the mock
// records where each value came from, a `set` always produces `source:
// override` even when the value is byte-identical, and `admin_api.js`'s "no
// runtime override should be in force" check then fails on the NEXT run against
// that same container, naming settings and no test at all. A setting that was
// ALREADY an override when this test arrived is put back with a `set`, because
// for that one an override is what it goes back to.
//
// **IT MUST SURVIVE BEING RUN TWICE, and the first version did not.** The mock
// holds everything in memory and never restarts between jobs, so the three
// profile counters are asserted as DELTAS against a baseline read at the top of
// the run rather than as absolutes, and the flow the `defaultProfile` check
// starts is COMPLETED and its artifact spent — an incomplete one was held for
// ten minutes and failed the second run on `flowsHeldForSignIn`.
//
// **THE USERNAMES AND THE RELYING PARTY IDENTIFIER ARE GENERATED**, from
// `random_username.js`, for the reason that module exists: nothing in the mock's
// user table, audit log or applications registry is ever pruned, so a fixed name
// makes every run of every test one person and a leftover row says nothing about
// which file put it there.
//
// IT DOES NOT CHECK THAT ANYBODY IS WHO THEY SAY THEY ARE, because the service
// does not: any username signs in, and the assertion describes whoever was
// typed. A test that asserted otherwise would be asserting a bug.
// ===========================================================================

const assert = require('assert');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { URL } = require('url');
const { Command, Option } = require('commander');
const { usernameFor, runStamp } = require('./random_username.js');
const registry = require('./sts_applications.js');
var appconfig = require(process.env.CONFIG_FILE);
const bunyan = require('bunyan');
const { DOMParser } = require('@xmldom/xmldom');
const { SignedXml } = require('xml-crypto');

const log = bunyan.createLogger({ name: 'saml11_sso',
                                  level: appconfig.LOG_LEVEL || 'info' });
log.info('Log initialized. logLevel=' + log.level());

// The base URL, in the order the other four STS tests take theirs. Trimming a
// trailing /sts means WSTRUST_STS_URL — which every launcher here already sets —
// locates this service without a third variable being invented.
const BASE = (process.env.SAML11_IDP_URL ||
              process.env.OID4VCI_ISSUER_URL ||
              (process.env.WSTRUST_STS_URL || '').replace(/\/sts\/?$/, '') ||
              'https://localhost:8081').replace(/\/$/, '');

// The relying party this run uses, and the three identities it signs in as.
// Both carry this process's stamp: nothing here is ever deleted from the mock's
// directory, so two runs against one instance would otherwise read each other's
// registry entry — and a row left behind names the file that made it.
const RP = 'urn:test:saml11:' + runStamp();

const USER_POST = usernameFor('saml11-post');

const USER_ARTIFACT = usernameFor('saml11-artifact');

const USER_UNREGISTERED = usernameFor('saml11-unregistered');

const CLAIM_NS = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims';

const NS_SAML = 'urn:oasis:names:tc:SAML:1.0:assertion';

const NS_SAMLP = 'urn:oasis:names:tc:SAML:1.0:protocol';

const CM_BEARER = 'urn:oasis:names:tc:SAML:1.0:cm:bearer';

const CM_ARTIFACT = 'urn:oasis:names:tc:SAML:1.0:cm:artifact';

// ---------------------------------------------------------------------------
// The harness. Every check is RECORDED rather than thrown, and the assert comes
// once at the end — because a profile test that dies on the first failure hides
// how much else is broken, and the useful output of a run against a half-built
// change is the whole list.
// ---------------------------------------------------------------------------
let passed = 0;
const failures = [];
let section = '';

function heading(title) {
  section = title;
  log.info('== ' + title + ' ==');
}

function check(name, ok, detail) {
  if (ok) {
    passed++;
    log.info('  ok   ' + name);
    return true;
  }
  failures.push(section + ' :: ' + name + (detail ? ' :: ' + detail : ''));
  log.error('  FAIL ' + name + (detail === undefined ? '' : ' :: ' + detail));
  return false;
}

// --- HTTP, with a cookie jar, and NO redirect following by default ---------
// Not following redirects is the point rather than a limitation: the artifact
// profile's answer IS a redirect, and a client that followed it would test the
// relying party instead of the identity provider. `signIn()` below follows
// exactly the hops of the sign-in dance and stops at the first one that leaves
// it.
let cookie = '';

function request(method, path, body, headers) {
  return new Promise(function (resolve, reject) {
    const url = new URL(path.indexOf('http') === 0 ? path : BASE + path);
    const opts = {
      method: method,
      headers: Object.assign({}, headers || {})
    };
    if (cookie) {
      opts.headers.Cookie = cookie;
    }
    if (body) {
      opts.headers['Content-Length'] = Buffer.byteLength(body);
    }
    const lib = url.protocol === 'https:' ? https : http;
    const req = lib.request(url, opts, function (res) {
      let data = '';
      res.on('data', function (chunk) { data += chunk; });
      res.on('end', function () {
        const set = res.headers['set-cookie'];
        if (set) {
          cookie = set.map(function (c) { return c.split(';')[0]; }).join('; ');
        }
        resolve({ status: res.statusCode, headers: res.headers, body: data });
      });
    });
    req.on('error', reject);
    if (body) {
      req.write(body);
    }
    req.end();
  });
}

function form(obj) {
  return Object.keys(obj).map(function (k) {
    return encodeURIComponent(k) + '=' + encodeURIComponent(obj[k]);
  }).join('&');
}

const FORM = { 'Content-Type': 'application/x-www-form-urlencoded' };

const XML = { 'Content-Type': 'text/xml; charset=utf-8' };

const JSON_H = { 'Content-Type': 'application/json' };

function api(path, payload) {
  return request('POST', path, JSON.stringify(payload), JSON_H);
}

// --- XML ------------------------------------------------------------------
function parse(xml) {
  return new DOMParser().parseFromString(xml, 'text/xml');
}

function byLocal(root, name) {
  const els = root.getElementsByTagNameNS('*', name);
  return els && els.length ? els[0] : null;
}

function textOf(root, name) {
  const el = byLocal(root, name);
  return el ? (el.textContent || '').trim() : '';
}

// A DIRECT child by local name. Not `byLocal`, which searches the whole subtree
// — and on a Response wrapping an Assertion the two answer different questions:
// the Response's own signature and the assertion's are both `Signature`, and
// searching finds whichever comes first in the document.
function childByLocal(el, name) {
  for (let i = 0; el && i < el.childNodes.length; i++) {
    const child = el.childNodes[i];
    if (child.nodeType === 1 && child.localName === name) {
      return child;
    }
  }
  return null;
}

// **THE REGRESSION GUARD FOR THE `Id="_0"` BUG**, and the reason this function
// takes an id attribute name at all.
//
// xml-crypto resolves a reference URI against `Id`, `ID` and `id` only. SAML 1.1
// uses neither on either document — `AssertionID` on an assertion, `ResponseID`
// on a response — so a verifier that is not told the name resolves `#_abc` to
// nothing and reports a good signature as broken. Naming it is also what proves
// the SIGNER did the right thing: if the signer left it unnamed, xml-crypto
// invented `Id="_0"` and pointed the reference there, and verifying through the
// real attribute then fails. So this one function catches both halves.
//
// It is safe to name these two because neither is already on that default list.
// Naming `ID` — SAML 2.0's — would unshift a DUPLICATE onto it and trip
// xml-crypto's signature-wrapping guard on a healthy document.
function verifySignature(xml, rootLocalName, idAttribute, certPem) {
  const doc = parse(xml);
  const root = rootLocalName === 'Response'
    ? doc.documentElement
    : byLocal(doc.documentElement, 'Assertion');
  if (!root) {
    return { ok: false, present: false, why: 'there is no <' + rootLocalName + '>' };
  }
  const sigEl = childByLocal(root, 'Signature');
  if (!sigEl) {
    return { ok: false, present: false,
             why: 'the ' + rootLocalName + ' carries no ds:Signature' };
  }
  try {
    const sig = new SignedXml({ publicCert: certPem, idAttribute: idAttribute });
    sig.loadSignature(sigEl);
    const ok = sig.checkSignature(xml);
    return { ok: !!ok, present: true, why: ok ? '' : 'the signature did not verify' };
  } catch (e) {
    // xml-crypto throws rather than returning false for most failures, and the
    // message names which — an unresolvable reference reads quite differently
    // from a digest mismatch, and that distinction is the diagnosis.
    return { ok: false, present: true, why: e.message };
  }
}

// The signing certificate, off the identity provider's own metadata. Taken from
// there rather than from a file so the test needs no fixture and cannot go stale
// against a key that is regenerated on every start.
let signingCertPem = '';

function pemOf(b64) {
  return '-----BEGIN CERTIFICATE-----\n' +
    (b64.match(/.{1,64}/g) || []).join('\n') + '\n-----END CERTIFICATE-----\n';
}

// ---------------------------------------------------------------------------
// Sign in at the inter-site transfer service and stop at whatever it answers
// with. `username` is whatever is typed: this service checks no password, which
// is why there is not one here.
//
// The hops followed are exactly the sign-in dance — /authn/* and back to
// /saml11/sso — and NOTHING ELSE. The redirect OUT to the assertion consumer is
// the artifact profile's answer and is returned rather than followed.
// ---------------------------------------------------------------------------
async function signIn(query, username) {
  cookie = '';
  return resume('/saml11/sso?' + form(query), username);
}

// The same, keeping whatever session the cookie jar already holds — which is how
// single sign-on is tested: a second flow that never sees the screen.
async function resume(path, username) {
  let res = await request('GET', path);
  if (res.status === 303 && /\/authn\/login/.test(res.headers.location || '')) {
    const id = decodeURIComponent(/authn=([^&]+)/.exec(res.headers.location)[1]);
    res = await request('POST', '/authn/login',
                        form({ authn_id: id, username: username }), FORM);
  }
  let hops = 0;
  while ((res.status === 302 || res.status === 303) && hops++ < 8) {
    const where = (res.headers.location || '').replace(BASE, '');
    if (!/^(\/authn\/|\/saml11\/sso)/.test(where)) {
      break;
    }
    res = await request('GET', where);
  }
  return res;
}

function samlResponseIn(page) {
  const m = /name="SAMLResponse" value="([^"]+)"/.exec(page);
  return m ? Buffer.from(m[1], 'base64').toString('utf8') : '';
}

function soap(inner) {
  return '<?xml version="1.0" encoding="UTF-8"?>' +
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' +
    '<soap:Body>' + inner + '</soap:Body></soap:Envelope>';
}

function samlRequest(inner, id) {
  return soap('<samlp:Request xmlns:samlp="' + NS_SAMLP + '" ' +
    'xmlns:saml="' + NS_SAML + '" RequestID="' + (id || ('_r' + Date.now())) + '" ' +
    'MajorVersion="1" MinorVersion="1" IssueInstant="' + new Date().toISOString() + '">' +
    inner + '</samlp:Request>');
}

function statusOf(doc) {
  const el = byLocal(doc, 'StatusCode');
  return el ? (el.getAttribute('Value') || '') : '';
}

// A setting, changed and remembered so the end of the run can put it back.
//
// The SOURCE is remembered beside the value, and that is not bookkeeping for
// its own sake — it is the whole of the difference between restoring a setting
// and merely covering it. See restoreSettings().
const changedSettings = {};

async function setSetting(key, value) {
  if (!(key in changedSettings)) {
    const before = await request('GET', '/admin-api/config');
    const all = JSON.parse(before.body);
    const row = (all.settings || []).filter(function (s) { return s.key === key; })[0];
    changedSettings[key] = { value: row ? row.value : undefined,
                             wasOverride: !!row && row.source === 'override' };
  }
  const body = {};
  body[key] = value;
  return api('/admin-api/config/set-many', body);
}

// ---------------------------------------------------------------------------
// PUTTING A SETTING BACK IS `reset`, NOT `set` WITH THE OLD VALUE, and the
// difference has already cost a run in this suite.
//
// The mock records where every value came from — `appconfig` for one the
// process started with, `override` for one changed at runtime — and a `set`
// always produces the second, even when the value written back is byte
// identical to what was there. A test that "restored" its settings with `set`
// therefore leaves a row reading `source: override` on a live container for
// ever, and `admin_api.js`'s "no runtime override should be in force before
// this check runs" then fails on the NEXT run against that same container,
// naming settings and no test at all. `spiffe_protocol.js` did exactly that
// with four of them.
//
// So `reset` is the operation that undoes an override rather than covering it,
// and the ONE exception is a setting that was ALREADY an override when this
// test arrived: for that one an override is what it goes back to, so it is put
// back with a `set`. `reset` also refuses a key with no override in force
// rather than reporting success, which is why the two cases are told apart here
// instead of being tried in turn.
// ---------------------------------------------------------------------------
async function restoreSettings() {
  const keys = Object.keys(changedSettings);
  if (!keys.length) {
    return;
  }
  const putBack = keys.filter(function (k) {
    return changedSettings[k].wasOverride;
  });
  const dropped = keys.filter(function (k) {
    return !changedSettings[k].wasOverride;
  });
  if (putBack.length) {
    const body = {};
    putBack.forEach(function (k) { body[k] = changedSettings[k].value; });
    await api('/admin-api/config/set-many', body);
  }
  for (const key of dropped) {
    await api('/admin-api/config/reset', { key: key });
  }
  log.info('restored ' + keys.length + ' setting(s): ' + dropped.length +
           ' reset' + (putBack.length ? ', ' + putBack.length +
           ' put back as the override each already was' : '') + ' :: ' +
           keys.join(', '));
}

// ===========================================================================
async function main() {
  log.debug('Entering main().');
  log.info('driving the SAML 1.1 browser profiles at ' + BASE +
           '. relyingParty=' + RP);

  // NOTHING LISTENING IS A SKIP; A SERVICE WITHOUT THE PROFILE IS A FAILURE.
  // The two are different facts and collapsing them loses the one that matters.
  // `sts_dpop.js` skips the same way and for the same reason — an environment
  // with no STS in it has not failed this test — but a service that ANSWERS and
  // has no /saml11 on it is a submodule pinned before the profile landed, and a
  // job that skipped there would report a whole protocol family as green while
  // never having exercised a line of it.
  let reachable = null;
  try {
    reachable = await request('GET', '/saml11');
  } catch (e) {
    log.warn('SKIPPED — nothing is listening at ' + BASE + ' (' + e.message +
             '). Set WSTRUST_STS_URL or OID4VCI_ISSUER_URL, or start the sts ' +
             'service.');
    log.debug('Leaving main().');
    return;
  }
  assert.strictEqual(reachable.status, 200,
    'GET /saml11 answered ' + reachable.status + ' at ' + BASE + '. This is a ' +
    'mock STS without the SAML 1.1 browser profiles on it — they landed in ' +
    'that repository on 2026-08-24, so the sts/ submodule is pinned before ' +
    'them. Bump the gitlink (see sts/docs/parent-project-migration.md) or ' +
    'point WSTRUST_STS_URL at a service that has them.');

  // The three profile counters BEFORE this run touches anything. They are
  // asserted as deltas below rather than as absolutes, and that is not
  // fastidiousness: the instance may be one somebody else is already driving,
  // and an earlier run of this very file leaves assertions cached by design.
  // Absolutes made the second run against one instance fail, which is the
  // failure that produced this baseline.
  let baseline = { artifactsAwaitingResolution: 0, assertionsHeldByReference: 0,
                   flowsHeldForSignIn: 0 };
  try {
    baseline = JSON.parse((await request('GET', '/admin-api/saml11')).body);
  } catch (e) {
    // The management API is not gated, so this should not fail — but a baseline
    // of zeroes only makes the deltas below stricter, never looser, so there is
    // nothing to abandon the run over.
    log.warn('could not read the counter baseline (' + e.message + '); using zeroes.');
  }

  // -------------------------------------------------------------------------
  heading('the pages a person reaches by clicking');
  check('GET /saml11 describes the profile',
        /inter-site transfer service/i.test(reachable.body));
  check('it says up front that SAML 1.1 has no request message',
        /no request message/i.test(reachable.body));
  let res = await request('GET', '/saml11/sso');
  check('GET /saml11/sso with no parameters describes itself rather than 400ing',
        res.status === 200 && /TARGET/.test(res.body), 'status ' + res.status);
  res = await request('GET', '/saml11/responder');
  check('GET on the responder describes it rather than 405ing',
        res.status === 200 && /AssertionArtifact/.test(res.body), 'status ' + res.status);
  check('the responder page says nothing authenticates a caller',
        /Nothing authenticates a caller/i.test(res.body));

  // -------------------------------------------------------------------------
  heading('the metadata');
  res = await request('GET', '/saml11/metadata');
  check('it answers 200', res.status === 200, 'status ' + res.status);
  check('its content type is application/samlmetadata+xml',
        /samlmetadata/.test(res.headers['content-type'] || ''),
        res.headers['content-type']);
  // The signing key is regenerated on every start, so a cached copy describes a
  // key that is gone and the failure looks like a broken signature.
  check('it is served no-store', res.headers['cache-control'] === 'no-store',
        res.headers['cache-control']);
  let doc = parse(res.body);
  const unscopedEntityId = doc.documentElement.getAttribute('entityID');
  check('protocolSupportEnumeration names the SAML 1.1 PROTOCOL',
        res.body.indexOf('protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol"') >= 0);
  check('there is an IDPSSODescriptor', !!byLocal(doc, 'IDPSSODescriptor'));
  // A Shibboleth service provider looks for its attribute authority in the
  // second descriptor and will not find it inside the first.
  check('there is an AttributeAuthorityDescriptor for the query half',
        !!byLocal(doc, 'AttributeAuthorityDescriptor'));
  check('it advertises Browser/POST',
        res.body.indexOf('urn:oasis:names:tc:SAML:1.0:profiles:browser-post') >= 0);
  check('it advertises Browser/Artifact',
        res.body.indexOf('urn:oasis:names:tc:SAML:1.0:profiles:artifact-01') >= 0);
  check('it advertises Shibboleth\'s AuthnRequest profile',
        res.body.indexOf('urn:mace:shibboleth:1.0:profiles:AuthnRequest') >= 0);
  check('it publishes an AttributeService over the SOAP binding',
        /AttributeService Binding="urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding"/.test(res.body));
  // Not an omission: SAML 1.1 has no Single Logout. Publishing one would be
  // advertising an endpoint the protocol cannot reach.
  check('there is NO SingleLogoutService, because SAML 1.1 has no Single Logout',
        res.body.indexOf('SingleLogoutService') < 0);
  check('ds:Signature is the FIRST child of EntityDescriptor',
        doc.documentElement.firstChild &&
        doc.documentElement.firstChild.localName === 'Signature',
        doc.documentElement.firstChild ? doc.documentElement.firstChild.localName : 'nothing');
  const certEl = byLocal(doc, 'X509Certificate');
  check('it publishes a signing certificate', !!certEl);
  if (certEl) {
    signingCertPem = pemOf((certEl.textContent || '').replace(/\s+/g, ''));
  }

  res = await request('GET', '/saml11/metadata/' + encodeURIComponent(RP));
  doc = parse(res.body);
  const scopedEntityId = doc.documentElement.getAttribute('entityID');
  check('a scoped document names a providerID of its own',
        scopedEntityId !== unscopedEntityId &&
        scopedEntityId.indexOf(unscopedEntityId + ':') === 0,
        scopedEntityId + ' vs ' + unscopedEntityId);
  check('its endpoints carry the same path segment',
        res.body.indexOf('/saml11/sso/') >= 0 && res.body.indexOf('/saml11/responder/') >= 0);
  // The ask is what registers it: a relying party can be pointed at this service
  // before anything at all has been provisioned.
  res = await request('GET', '/saml11/metadata/' + encodeURIComponent('urn:test:never:seen'));
  check('a document is minted for an identifier nobody registered', res.status === 200,
        'status ' + res.status);

  // -------------------------------------------------------------------------
  heading('Browser/POST, end to end');
  const target = BASE + '/done?x=1';
  const acs = BASE + '/saml11/rp';

  // THE RELYING PARTY, IN THE REGISTRY, BEFORE THE FIRST FLOW.
  //
  // It goes here rather than at the top of main() because `acs` is what makes
  // it worth registering, and this is the line that settles it. The section
  // just above proved the OTHER half of the same fact — that a metadata
  // document is minted for an identifier nobody registered — and the two are
  // not in tension: the mock REQUIRES no registration, and an entry created by
  // a sighting knows the identifier and nothing else. This one knows where a
  // response is posted and what family this party was declared for.
  //
  // `RP` carries this process's stamp, so nothing here is shared with another
  // run and every assertion below is still on this job's own litter.
  await registry.provision(registry.baseOf(BASE), {
    identifier: RP,
    name: 'SAML 1.1 protocol test relying party',
    protocols: ['saml11'],
    fields: {
      samlEntityId: [RP],
      samlAssertionConsumerService: [acs]
    },
    why: 'the relying party providerId names in every flow below'
  });
  res = await signIn({ providerId: RP, shire: acs, TARGET: target, profile: 'post' }, USER_POST);
  check('the flow ends on the auto-post page',
        res.status === 200 && /saml11-form/.test(res.body), 'status ' + res.status);
  const csp = res.headers['content-security-policy'] || '';
  const scriptSrc = (/script-src ([^;]*)/.exec(csp) || [])[1] || '';
  // The exception is exactly as wide as one named resource and no wider. The
  // whole family of reflected-content problems depends on it staying that way.
  check('script-src is relaxed to \'self\' and no wider', scriptSrc.trim() === "'self'",
        'script-src ' + scriptSrc);
  // RFC 9700 §4.14, and the clause has no fallback from default-src — a page
  // that sets the whole header can lose it with nothing failing.
  check('frame-ancestors survived the relaxation', /frame-ancestors/.test(csp), csp);
  // With scripting off the button is the whole mechanism, so it is a real
  // control and not a hidden fallback.
  check('the page carries a real submit button', /<button type="submit">/.test(res.body));
  check('the form posts to the shire', res.body.indexOf('action="' + acs + '"') >= 0);
  // SAML 1.1's RelayState. An identity provider that decoded and re-encoded it
  // produces the same symptom as a lost session.
  check('TARGET is echoed back byte for byte',
        res.body.indexOf('value="' + target.replace(/&/g, '&amp;') + '"') >= 0 ||
        res.body.indexOf('value="' + target + '"') >= 0);

  const postXml = samlResponseIn(res.body);
  check('there is a SAMLResponse', !!postXml);
  doc = parse(postXml);
  let root = doc.documentElement;
  check('it is a samlp:Response in the 1.0 PROTOCOL namespace — 1.1 renamed neither schema',
        root.localName === 'Response' && root.namespaceURI === NS_SAMLP, root.namespaceURI);
  check('it is identified by ResponseID, not ID',
        !!root.getAttribute('ResponseID') && !root.getAttribute('ID'));
  check('the version is two attributes, MajorVersion and MinorVersion',
        root.getAttribute('MajorVersion') === '1' && root.getAttribute('MinorVersion') === '1');
  // §4.2.1.4. It is what stops a response being replayed at another relying
  // party.
  check('Recipient names the assertion consumer', root.getAttribute('Recipient') === acs,
        root.getAttribute('Recipient'));
  // Trap 3. Porting SAML 2.0 code puts one here, naming a RequestID nobody minted.
  check('InResponseTo is ABSENT — there was no request to be in response to',
        !root.getAttribute('InResponseTo'), root.getAttribute('InResponseTo'));
  // Trap: a SAML 1.1 status is a QName resolved against the document's
  // namespaces, not a URI. The 2.0 spelling resolves to nothing at all.
  check('the status is the QName samlp:Success, not a URI',
        statusOf(doc) === 'samlp:Success', statusOf(doc));
  check('ds:Signature is the FIRST child of the Response',
        root.firstChild && root.firstChild.localName === 'Signature',
        root.firstChild ? root.firstChild.localName : 'nothing');

  let assertionEl = byLocal(root, 'Assertion');
  check('it carries an assertion', !!assertionEl);
  check('the assertion is in the 1.0 assertion namespace',
        assertionEl.namespaceURI === NS_SAML, assertionEl.namespaceURI);
  check('the assertion is identified by AssertionID, not ID',
        !!assertionEl.getAttribute('AssertionID') && !assertionEl.getAttribute('ID'));
  // The bug this whole file exists partly to guard: an invented Id attribute
  // that the schema does not have and that the reference then points at.
  check('the assertion carries NO invented Id attribute',
        !assertionEl.getAttribute('Id'), assertionEl.getAttribute('Id'));
  check('the Response carries no invented Id attribute either',
        !root.getAttribute('Id'), root.getAttribute('Id'));
  const refUri = (/<(?:ds:)?Reference URI="([^"]*)"/.exec(postXml) || [])[1] || '';
  check('the first signature reference names a real id, not #_0',
        refUri !== '#_0' && refUri.length > 1, refUri);
  // The Issuer is an ATTRIBUTE in SAML 1.1. A 2.0-shaped reader looking for a
  // child element finds nothing.
  check('the Issuer is an ATTRIBUTE of Assertion, not a child element',
        !!assertionEl.getAttribute('Issuer') && !childByLocal(assertionEl, 'Issuer'),
        assertionEl.getAttribute('Issuer'));
  check('the issuer is this relying party\'s own providerID',
        assertionEl.getAttribute('Issuer') === scopedEntityId,
        assertionEl.getAttribute('Issuer') + ', expected ' + scopedEntityId);
  check('ds:Signature is the LAST child of the assertion',
        assertionEl.lastChild && assertionEl.lastChild.localName === 'Signature',
        assertionEl.lastChild ? assertionEl.lastChild.localName : 'nothing');
  check('the condition is AudienceRestrictionCondition, not AudienceRestriction',
        !!byLocal(assertionEl, 'AudienceRestrictionCondition'));
  check('the audience is the relying party', textOf(assertionEl, 'Audience') === RP,
        textOf(assertionEl, 'Audience'));
  // Trap 1.
  check('the confirmation method is cm:bearer for Browser/POST',
        textOf(assertionEl, 'ConfirmationMethod') === CM_BEARER,
        textOf(assertionEl, 'ConfirmationMethod'));
  // The single-use policy: the assertion passed through the browser, so the
  // relying party is told not to keep it.
  check('a DoNotCacheCondition is present on the POST profile',
        !!byLocal(assertionEl, 'DoNotCacheCondition'));
  check('there is a SubjectLocality recording where the browser was',
        !!byLocal(assertionEl, 'SubjectLocality'));
  check('there is an AuthenticationStatement',
        !!byLocal(assertionEl, 'AuthenticationStatement'));
  const nameIdEl = byLocal(assertionEl, 'NameIdentifier');
  check('the subject is whoever was typed at the screen',
        (nameIdEl.textContent || '').trim() === USER_POST);
  check('the NameIdentifier carries a NameQualifier',
        !!nameIdEl.getAttribute('NameQualifier'), nameIdEl.getAttribute('NameQualifier'));
  const attrEls = assertionEl.getElementsByTagNameNS('*', 'Attribute');
  check('attributes are AttributeName + AttributeNamespace pairs, not one Name',
        attrEls.length > 0 && !!attrEls[0].getAttribute('AttributeName') &&
        !!attrEls[0].getAttribute('AttributeNamespace') && !attrEls[0].getAttribute('Name'),
        attrEls.length + ' attribute(s)');
  let sawMace = false;
  for (let i = 0; i < attrEls.length; i++) {
    if ((attrEls[i].getAttribute('AttributeNamespace') || '').indexOf('urn:mace:dir') === 0) {
      sawMace = true;
    }
  }
  // Sent beside the AD FS claim URIs so the mock is usable against a service
  // provider configured for either without a mapper being written first.
  check('the Shibboleth urn:mace attributes are sent as well as the claim URIs', sawMace);

  // Trap 2, both halves at once.
  heading('the signatures, resolved through the attributes SAML 1.1 actually uses');
  let sig = verifySignature(postXml, 'Response', 'ResponseID', signingCertPem);
  check('the Response signature verifies through ResponseID', sig.ok,
        sig.present ? sig.why : 'unsigned');
  sig = verifySignature(postXml, 'Assertion', 'AssertionID', signingCertPem);
  check('the assertion signature verifies through AssertionID', sig.ok,
        sig.present ? sig.why : 'unsigned');
  // Two signed elements in one document is exactly what used to make xml-crypto
  // refuse both, reporting a signature-wrapping attack on a document this
  // service built itself. Both verifying above is the regression guard; this
  // says why it is two rather than one.
  check('BOTH documents are signed, which is the case the Id="_0" collision broke',
        !!childByLocal(root, 'Signature') && !!childByLocal(assertionEl, 'Signature'));

  // -------------------------------------------------------------------------
  heading('Browser/Artifact, end to end');
  res = await signIn({ providerId: RP, shire: acs, TARGET: target, profile: 'artifact' }, USER_ARTIFACT);
  check('the artifact profile answers with a redirect, not a form',
        res.status === 303, 'status ' + res.status);
  const location = res.headers.location || '';
  check('the redirect carries SAMLart', /[?&]SAMLart=/.test(location));
  check('the redirect carries TARGET', /[?&]TARGET=/.test(location));
  const artifact = decodeURIComponent((/[?&]SAMLart=([^&]+)/.exec(location) || [])[1] || '');
  const raw = Buffer.from(artifact, 'base64');
  // SAML 2.0's is 44 bytes and type 0x0004: it added a two-byte EndpointIndex
  // that 1.1 has no field for. A relying party assuming the newer layout reads
  // the SourceID two bytes late and matches no identity provider it knows.
  check('the artifact is 42 bytes, not SAML 2.0\'s 44', raw.length === 42, raw.length + ' bytes');
  check('its type code is 0x0001, not 0x0004', raw.length >= 2 && raw.readUInt16BE(0) === 1,
        raw.length >= 2 ? '0x' + raw.readUInt16BE(0).toString(16) : 'too short');
  check('its SourceID is the SHA-1 of the issuing providerID',
        raw.length === 42 &&
        raw.slice(2, 22).equals(crypto.createHash('sha1').update(scopedEntityId, 'utf8').digest()));

  const requestId = '_req' + Date.now();
  const resolveBody = samlRequest('<samlp:AssertionArtifact>' + artifact +
                                  '</samlp:AssertionArtifact>', requestId);
  res = await request('POST', '/saml11/responder', resolveBody, XML);
  check('the responder answers 200', res.status === 200, 'status ' + res.status);
  check('the answer is a SOAP envelope', /soap:Envelope/i.test(res.body));
  doc = parse(res.body);
  check('the resolved status is samlp:Success', statusOf(doc) === 'samlp:Success', statusOf(doc));
  // The Response is built AT RESOLUTION TIME, which is what lets it name the
  // SOAP request. Stashing a pre-built one — what porting the SAML 2.0 code
  // does — cannot.
  check('the Response names the SOAP request in InResponseTo',
        byLocal(doc, 'Response').getAttribute('InResponseTo') === requestId,
        byLocal(doc, 'Response').getAttribute('InResponseTo'));
  const artAssertion = byLocal(doc, 'Assertion');
  check('an assertion came back', !!artAssertion);
  // Trap 1, the other half. These two values are not interchangeable.
  check('the confirmation method is cm:artifact, NOT bearer',
        textOf(artAssertion, 'ConfirmationMethod') === CM_ARTIFACT,
        textOf(artAssertion, 'ConfirmationMethod'));
  check('there is NO DoNotCacheCondition — it never passed through the browser',
        !byLocal(artAssertion, 'DoNotCacheCondition'));
  check('the subject is the person who signed in',
        (byLocal(artAssertion, 'NameIdentifier').textContent || '').trim() === USER_ARTIFACT);
  sig = verifySignature(res.body, 'Assertion', 'AssertionID', signingCertPem);
  check('the artifact-borne assertion\'s signature verifies', sig.ok,
        sig.present ? sig.why : 'unsigned');

  // Trap 4.
  res = await request('POST', '/saml11/responder', resolveBody, XML);
  doc = parse(res.body);
  check('resolving the same artifact a second time is REFUSED',
        statusOf(doc) === 'samlp:Requester', statusOf(doc));
  check('the refusal explains the one-shot rule rather than saying "not found"',
        /one-shot/i.test(textOf(doc, 'StatusMessage')), textOf(doc, 'StatusMessage'));
  check('the refusal still names the SOAP request',
        byLocal(doc, 'Response').getAttribute('InResponseTo') === requestId);
  check('no assertion comes back with the refusal', !byLocal(doc, 'Assertion'));

  // -------------------------------------------------------------------------
  heading('the SAML responder: the other three request types');
  const heldId = artAssertion.getAttribute('AssertionID');
  res = await request('POST', '/saml11/responder',
                      samlRequest('<samlp:AssertionIDReference>' + heldId +
                                  '</samlp:AssertionIDReference>', '_r2'), XML);
  doc = parse(res.body);
  check('an AssertionIDReference returns the assertion',
        statusOf(doc) === 'samlp:Success' &&
        byLocal(doc, 'Assertion').getAttribute('AssertionID') === heldId, statusOf(doc));
  res = await request('POST', '/saml11/responder',
                      samlRequest('<samlp:AssertionIDReference>' + heldId +
                                  '</samlp:AssertionIDReference>', '_r3'), XML);
  doc = parse(res.body);
  // NOT one-shot, and the difference from an artifact is the point: a reference
  // is not a credential, because whoever holds it holds the assertion already.
  check('an AssertionIDReference is NOT one-shot, unlike an artifact',
        statusOf(doc) === 'samlp:Success', statusOf(doc));
  res = await request('POST', '/saml11/responder',
                      samlRequest('<samlp:AssertionIDReference>_no_such_assertion' +
                                  '</samlp:AssertionIDReference>', '_r3b'), XML);
  doc = parse(res.body);
  check('an unknown AssertionID is refused', statusOf(doc) === 'samlp:Requester', statusOf(doc));

  res = await request('POST', '/saml11/responder', samlRequest(
    '<samlp:AttributeQuery Resource="' + RP + '"><saml:Subject>' +
    '<saml:NameIdentifier>carol</saml:NameIdentifier></saml:Subject>' +
    '</samlp:AttributeQuery>', '_r4'), XML);
  doc = parse(res.body);
  check('an AttributeQuery is answered', statusOf(doc) === 'samlp:Success', statusOf(doc));
  check('it is about the subject that was asked for',
        (byLocal(doc, 'NameIdentifier').textContent || '').trim() === 'carol');
  check('it carries an AttributeStatement', !!byLocal(doc, 'AttributeStatement'));
  check('the audience is the query\'s Resource',
        textOf(byLocal(doc, 'Assertion'), 'Audience') === RP,
        textOf(byLocal(doc, 'Assertion'), 'Audience'));
  // The posture, asserted rather than left to be discovered: nobody
  // authenticated to ask this, and the subject never signed in.
  check('a query about somebody who never signed in is ANSWERED, not refused',
        !!byLocal(doc, 'Assertion'));

  res = await request('POST', '/saml11/responder', samlRequest(
    '<samlp:AuthenticationQuery><saml:Subject>' +
    '<saml:NameIdentifier>dave</saml:NameIdentifier></saml:Subject>' +
    '</samlp:AuthenticationQuery>', '_r5'), XML);
  doc = parse(res.body);
  check('an AuthenticationQuery is answered', statusOf(doc) === 'samlp:Success', statusOf(doc));
  check('it carries an AuthenticationStatement and NO AttributeStatement',
        !!byLocal(doc, 'AuthenticationStatement') && !byLocal(doc, 'AttributeStatement'));

  res = await request('POST', '/saml11/responder',
                      samlRequest('<samlp:AuthorizationDecisionQuery/>', '_r6'), XML);
  doc = parse(res.body);
  check('an AuthorizationDecisionQuery is refused BY NAME',
        statusOf(doc) === 'samlp:Requester' &&
        /AuthorizationDecision/i.test(textOf(doc, 'StatusMessage')), textOf(doc, 'StatusMessage'));
  res = await request('POST', '/saml11/responder', '<not xml at all <<<', XML);
  doc = parse(res.body);
  // A SOAP fault is an HTTP-layer failure and this is a SAML-layer refusal;
  // collapsing the two makes a client throw a transport error where it should be
  // reading a status code.
  check('a body that is not XML is a SAML status and still HTTP 200',
        res.status === 200 && statusOf(doc) === 'samlp:Requester', 'status ' + res.status);
  res = await request('POST', '/saml11/responder',
                      soap('<samlp:ArtifactResolve xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>'),
                      XML);
  doc = parse(res.body);
  check('a SAML 2.0 ArtifactResolve is refused and pointed at /saml2/ars',
        /saml2\/ars/.test(textOf(doc, 'StatusMessage')), textOf(doc, 'StatusMessage'));

  // -------------------------------------------------------------------------
  heading('the scoped endpoints the per-relying-party metadata publishes');
  const slug = scopedEntityId.slice(unscopedEntityId.length + 1);
  // Driven through resume() rather than signIn(), because signIn() always starts
  // at the unscoped path and the scoped one is the whole point here.
  cookie = '';
  res = await resume('/saml11/sso/' + encodeURIComponent(slug) + '?' +
                     form({ shire: acs, TARGET: target, profile: 'post' }), 'erin');
  const scopedXml = samlResponseIn(res.body);
  check('a scoped inter-site transfer service answers', !!scopedXml, 'status ' + res.status);
  if (scopedXml) {
    // The path segment is what names the relying party when nothing else does —
    // which matters more here than in SAML 2.0, where the request's own Issuer
    // always could.
    check('the path segment named the relying party with no providerId sent',
          textOf(parse(scopedXml), 'Audience') === RP, textOf(parse(scopedXml), 'Audience'));
  }
  res = await request('POST', '/saml11/responder/' + encodeURIComponent(slug),
                      samlRequest('<samlp:AssertionIDReference>' + heldId +
                                  '</samlp:AssertionIDReference>', '_r7'), XML);
  check('a scoped responder answers the same as the unscoped one',
        statusOf(parse(res.body)) === 'samlp:Success', statusOf(parse(res.body)));

  // -------------------------------------------------------------------------
  heading('the NameIdentifier formats');
  // SAML 1.1 has no NameIDPolicy to ask in, so the non-spec `format` parameter
  // is the only way to exercise these at all — and every one of them is a branch
  // that would otherwise never run.
  const formats = [
    ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', function (v) {
      return v.indexOf('@') > 0; }, 'a mail address'],
    ['urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName', function (v) {
      return v.indexOf('CN=') === 0; }, 'an X.509 subject name'],
    ['urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName', function (v) {
      return v.indexOf('\\') > 0; }, 'a domain-qualified name'],
    ['urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', function (v) {
      return v === 'frank'; }, 'the username']
  ];
  for (const [format, ok, what] of formats) {
    cookie = '';
    res = await resume('/saml11/sso?' + form({ providerId: RP, shire: acs, TARGET: target,
                                               profile: 'post', format: format }), 'frank');
    const xml = samlResponseIn(res.body);
    const el = xml ? byLocal(parse(xml), 'NameIdentifier') : null;
    const value = el ? (el.textContent || '').trim() : '';
    check('format ' + format.split(':').pop() + ' is answered with ' + what,
          !!el && el.getAttribute('Format') === format && ok(value), value);
  }
  // A format nobody has ever heard of is answered with it, rather than refused:
  // handing a relying party back its own format is the behaviour worth
  // exercising.
  cookie = '';
  res = await resume('/saml11/sso?' + form({ providerId: RP, shire: acs, TARGET: target,
                                             profile: 'post', format: 'urn:made:up' }), 'frank');
  let madeUp = samlResponseIn(res.body);
  check('a format nobody has heard of is answered with that format, not refused',
        !!madeUp && byLocal(parse(madeUp), 'NameIdentifier').getAttribute('Format') === 'urn:made:up');

  // -------------------------------------------------------------------------
  heading('the custom attributes reach a browser-profile assertion');
  // THE POINT OF NOT WRITING A SECOND BUILDER. The 1.1 set on
  // /admin/saml-attributes has always reached WS-Federation and WS-Trust
  // assertions; if the browser profiles had their own builder this would pass
  // there and silently fail here, and nothing would say so.
  let added = false;
  res = await api('/admin-api/saml-attributes/add',
                  { set: 'saml11', name: 'dept', value: 'engineering' });
  added = res.status === 200;
  check('a custom SAML 1.1 attribute can be configured', added, res.body.slice(0, 120));
  if (added) {
    cookie = '';
    res = await resume('/saml11/sso?' + form({ providerId: RP, shire: acs, TARGET: target,
                                               profile: 'post' }), 'grace');
    const xml = samlResponseIn(res.body);
    const els = xml ? parse(xml).getElementsByTagNameNS('*', 'Attribute') : [];
    let found = null;
    for (let i = 0; i < els.length; i++) {
      if (els[i].getAttribute('AttributeName') === 'dept') {
        found = els[i];
      }
    }
    check('it appears in an assertion issued by the browser profile', !!found);
    check('its value is what was configured',
          !!found && (found.textContent || '').trim() === 'engineering',
          found ? found.textContent : '');
    check('it carries the default SAML 1.1 namespace',
          !!found && found.getAttribute('AttributeNamespace') === CLAIM_NS,
          found ? found.getAttribute('AttributeNamespace') : '');
    await api('/admin-api/saml-attributes/remove', { set: 'saml11', name: 'dept' });
  }

  // -------------------------------------------------------------------------
  heading('single sign-on across the flows and the other protocols');
  cookie = '';
  res = await resume('/saml11/sso?' + form({ providerId: RP, shire: acs, TARGET: target,
                                             profile: 'post' }), 'heidi');
  check('the first flow signs somebody in', !!samlResponseIn(res.body));
  // The same cookie jar, and no username typed. A second screen here would mean
  // this profile had a session of its own, which is exactly what it must not
  // have.
  const before = cookie;
  res = await request('GET', '/saml11/sso?' + form({ providerId: RP, shire: acs,
                                                     TARGET: target, profile: 'post' }));
  const second = samlResponseIn(res.body);
  check('a second flow in the same session never sees the sign-in screen',
        res.status === 200 && !!second, 'status ' + res.status);
  check('and it is the same person',
        !!second && (byLocal(parse(second), 'NameIdentifier').textContent || '').trim() === 'heidi');
  check('the session cookie was not replaced', cookie === before);
  // The session is authn.js's, shared with OAuth, WS-Federation and SAML 2.0.
  res = await request('GET', '/saml2/sp');
  check('the SAML 2.0 profile is still reachable in the same session', res.status === 200,
        'status ' + res.status);

  // -------------------------------------------------------------------------
  heading('refusals at the inter-site transfer service');
  cookie = '';
  res = await request('GET', '/saml11/sso?' + form({ TARGET: target, profile: 'paos' }));
  check('a profile that is not one of the two is refused BY NAME',
        res.status === 400 && /paos/.test(res.body), 'status ' + res.status);
  res = await request('GET', '/saml11/sso?' + form({ providerId: RP, shire: '/relative' }));
  check('a relative assertion consumer URL is refused',
        res.status === 400 && /absolute/i.test(res.body), 'status ' + res.status);
  res = await request('GET', '/saml11/sso?' + form({ fid: 'no-such-flow-id' }));
  check('a held flow that has expired says so rather than starting a new one',
        res.status === 400 && /expired/i.test(res.body), 'status ' + res.status);

  // -------------------------------------------------------------------------
  heading('the guess this service makes out loud');
  // With no providerId and no scoped path, the audience comes from the origin of
  // the TARGET. It is the one thing in the assertion that is not a fact, and a
  // relying party expecting its own name refuses the assertion inside a
  // signature check with nothing saying why.
  cookie = '';
  res = await resume('/saml11/sso?' + form({ TARGET: 'https://guessed.example.com/app/page',
                                             shire: acs, profile: 'post' }), 'ivan');
  const guessedXml = samlResponseIn(res.body);
  check('a flow naming no relying party still completes', !!guessedXml, 'status ' + res.status);
  if (guessedXml) {
    check('the audience is the ORIGIN of the TARGET, and not its full URL',
          textOf(parse(guessedXml), 'Audience') === 'https://guessed.example.com',
          textOf(parse(guessedXml), 'Audience'));
  }
  res = await request('GET', '/admin-api/saml11?rp=' +
                      encodeURIComponent('https://guessed.example.com'));
  const guessedRow = JSON.parse(res.body);
  check('the console flags a bare-origin identifier as probably guessed',
        guessedRow.identifierLooksGuessed === true, JSON.stringify(guessedRow.identifierLooksGuessed));

  // -------------------------------------------------------------------------
  heading('the registry');
  res = await request('GET', '/admin-api/saml11');
  const view = JSON.parse(res.body);
  const mine = (view.relyingParties || []).filter(function (r) {
    return r.identifier === RP;
  })[0];
  check('the relying party was registered on sight', !!mine);
  if (mine) {
    check('its assertion consumer was recorded',
          (mine.assertionConsumerServices || []).indexOf(acs) >= 0,
          JSON.stringify(mine.assertionConsumerServices));
    check('BOTH browser profiles it used were recorded',
          (mine.profiles || []).length === 2, JSON.stringify(mine.profiles));
    check('its metadata URL is a per-row fact, not a constant',
          !!mine.metadataUrl && mine.metadataUrl.indexOf('/saml11/metadata/') >= 0,
          mine.metadataUrl);
    check('the slug is the SAME one the SAML 2.0 profile uses for this application',
          mine.slug === slug, mine.slug + ' vs ' + slug);
  }
  // A count that only ever rises is a leak. Read as DELTAS against the baseline
  // taken at the top, so that another run's state cannot make this pass or fail.
  // The middle one is capped rather than swept, so sitting at its ceiling is its
  // healthy state and only the direction is worth asserting.
  check('this run left no artifact unresolved',
        view.artifactsAwaitingResolution - baseline.artifactsAwaitingResolution === 0,
        view.artifactsAwaitingResolution + ' now, ' + baseline.artifactsAwaitingResolution +
        ' before');
  check('assertions are held for AssertionIDReference', view.assertionsHeldByReference > 0,
        String(view.assertionsHeldByReference));
  check('this run left no flow held for sign-in',
        view.flowsHeldForSignIn - baseline.flowsHeldForSignIn === 0,
        view.flowsHeldForSignIn + ' now, ' + baseline.flowsHeldForSignIn + ' before');

  // -------------------------------------------------------------------------
  heading('the settings, one at a time');
  // An unsigned assertion being ACCEPTED by a relying party is the finding that
  // matters, and no happy path shows it. Each of these is restored at the end.
  await setSetting('saml11.signAssertion', false);
  cookie = '';
  res = await resume('/saml11/sso?' + form({ providerId: RP, shire: acs, TARGET: target,
                                             profile: 'post' }), 'judy');
  let xml = samlResponseIn(res.body);
  check('saml11.signAssertion=false issues an UNSIGNED assertion',
        !!xml && !childByLocal(byLocal(parse(xml), 'Assertion'), 'Signature'));
  check('and the Response around it is still signed',
        !!xml && !!childByLocal(parse(xml).documentElement, 'Signature'));
  await setSetting('saml11.signAssertion', true);

  await setSetting('saml11.signResponse', false);
  cookie = '';
  res = await resume('/saml11/sso?' + form({ providerId: RP, shire: acs, TARGET: target,
                                             profile: 'post' }), 'judy');
  xml = samlResponseIn(res.body);
  check('saml11.signResponse=false issues an unsigned Response',
        !!xml && !childByLocal(parse(xml).documentElement, 'Signature'));
  check('and the assertion inside it is still signed',
        !!xml && !!childByLocal(byLocal(parse(xml), 'Assertion'), 'Signature'));
  await setSetting('saml11.signResponse', true);

  await setSetting('saml11.perApplicationProviderId', false);
  res = await request('GET', '/saml11/metadata/' + encodeURIComponent(RP));
  check('perApplicationProviderId=false makes every document name one identity provider',
        parse(res.body).documentElement.getAttribute('entityID') === unscopedEntityId,
        parse(res.body).documentElement.getAttribute('entityID'));
  // The endpoints stay per-application either way, because that is what makes
  // the documents worth having separately.
  check('but the ENDPOINTS stay per-application', res.body.indexOf('/saml11/sso/') >= 0);
  await setSetting('saml11.perApplicationProviderId', true);

  await setSetting('saml11.defaultProfile', 'artifact');
  cookie = '';
  // No `profile` parameter at all: the setting is what decides, because nothing
  // in SAML 1.1 lets a relying party ask. The flow is COMPLETED rather than
  // abandoned at the sign-in screen — an earlier version of this check stopped
  // at the redirect and left a held flow behind, which made the SECOND run
  // against one instance fail. A test that leaks state is a test that has to be
  // run first.
  res = await resume('/saml11/sso?' + form({ providerId: RP, shire: acs, TARGET: target }),
                     'lana');
  const wentByArtifact = res.status === 303 && /[?&]SAMLart=/.test(res.headers.location || '');
  check('saml11.defaultProfile decides the profile when the request does not',
        wentByArtifact, 'status ' + res.status);
  if (wentByArtifact) {
    // Spend it, so this run leaves the artifact store as it found it.
    const spent = decodeURIComponent(
      (/[?&]SAMLart=([^&]+)/.exec(res.headers.location) || [])[1] || '');
    await request('POST', '/saml11/responder',
                  samlRequest('<samlp:AssertionArtifact>' + spent +
                              '</samlp:AssertionArtifact>', '_r8'), XML);
  }
  await setSetting('saml11.defaultProfile', 'post');

  await setSetting('saml11.autocreateApplications', false);
  const unregistered = 'urn:test:not:registered:' + process.pid;
  cookie = '';
  res = await resume('/saml11/sso?' + form({ providerId: unregistered, shire: acs,
                                             TARGET: target, profile: 'post' }), USER_UNREGISTERED);
  check('autocreateApplications=false still ANSWERS the flow', !!samlResponseIn(res.body),
        'status ' + res.status);
  res = await request('GET', '/admin-api/saml11?rp=' + encodeURIComponent(unregistered));
  check('it simply records nothing', JSON.parse(res.body).registered === false,
        res.body.slice(0, 120));
  await setSetting('saml11.autocreateApplications', true);

  // -------------------------------------------------------------------------
  heading('the other two doors still carry the same builder');
  // The browser profiles and WS-Federation share `saml11.js`. This is the check
  // that a change made for one has not broken the other — which is not
  // hypothetical: fixing the reference attribute for these profiles changed
  // every WS-Federation assertion this service issues.
  res = await request('GET', '/wsfed?' + form({ wa: 'wsignin1.0', wtrealm: 'urn:test:wsfed',
                                                wreply: BASE + '/wsfed/rp' }));
  check('WS-Federation still answers', res.status === 200 || res.status === 303,
        'status ' + res.status);
  res = await request('GET', '/saml2/metadata');
  check('the SAML 2.0 profile still publishes its metadata', res.status === 200,
        'status ' + res.status);
  // The drift checks the parent project's tests/sts_metadata.js enforces. Even
  // without that test here, a 200 with the group on it says the endpoints were
  // described rather than silently added.
  res = await request('GET', '/admin-api/sts-metadata');
  if (res.status === 200) {
    check('every /saml11 route is described on /admin/sts-metadata',
          res.body.indexOf('/saml11/sso') >= 0 && res.body.indexOf('/saml11/responder') >= 0);
  }

  await restoreSettings();

  // -------------------------------------------------------------------------
  log.info('===============================');
  log.info(passed + ' passed, ' + failures.length + ' failed');
  if (failures.length) {
    log.error('FAILURES:');
    failures.forEach(function (f) { log.error('  - ' + f); });
  }
  assert.strictEqual(failures.length, 0,
    failures.length + ' SAML 1.1 check(s) failed. The list is above.');
  log.info('SAML 1.1 browser profiles: ' + passed + ' checks passed.');
  log.info('Test completed successfully.');
  log.debug('Leaving main().');
}

const program = new Command();
program
  .name('saml11_sso')
  .description('Drive the mock STS\'s SAML 1.1 browser profiles — ' +
      'Browser/POST, Browser/Artifact, the SOAP responder and the metadata — ' +
      'over HTTP with no browser.')
  // Accepted and ignored: run-report.js passes --url to every job, and
  // commander exits 1 on an option it has not been told about.
  .addOption(new Option('-u, --url <url>',
      'base url (unused: this test needs no browser)'))
  .parse(process.argv);

main().then(function () {
  process.exit(0);
}).catch(async function (e) {
  // Settings are restored even on the way out, so a run that dies half way
  // through does not leave an instance somebody else is using in a state they
  // did not choose.
  try {
    await restoreSettings();
  } catch (restoreError) {
    // Nothing useful to do about it, and the original failure is what matters —
    // but saying so beats a silent second failure inside the first.
    log.error('could not restore settings: ' + restoreError.message);
  }
  log.error(e && e.stack ? e.stack : (e && e.message ? e.message : e));
  process.exit(1);
});
