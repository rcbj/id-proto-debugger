// File: saml_message_engine.js
//
// ---------------------------------------------------------------------------
// THE SAML WIRE READER, DRIVEN IN NODE WITH NO SERVER AND NO BROWSER.
//
// `client/src/saml_message.js` is everything the SAML pages do that is not
// cryptography: work out which BINDING a blob arrived on, undo that binding's
// encoding, rebuild the octets a Redirect signature was computed over, pull
// apart an artifact, and summarise a request or a RESPONSE in both protocol
// versions. It has 1,747 lines, two DOM references and no page state at all —
// every function takes a string or a node and returns a value.
//
// **WHY THIS FILE EXISTS, AND THE ANSWER IS A MEASUREMENT.** That module was
// the second-biggest block of untested code in this tree: 700 uncovered lines
// at 59.9% on the merged report of 2026-08-29 (tests/coverage_merge.js), and
// what was uncovered was not scattered branches but whole functions never
// entered once — `summarize()` (198 lines), `summarizeResponse()` (157),
// `assertionSummary()` (126), `classify()` (96). Two page tests build fixtures
// WITH this module (`saml_authnrequest_page.js` and
// `saml_response_decoder_page.js` both parse and serialize through it) and
// neither reads one, so the readers were exercised only through a browser
// rendering their output — where a wrong row is a wrong cell in a table and
// nothing says which of the two dozen readers produced it.
//
// **WHAT A DEFECT HERE LOOKS LIKE**, and it is the reason this is worth a file
// of its own rather than another page assertion. Every failure this module can
// have presents as a BLANK or as a plausible wrong value, never as an error:
//
//   * a reader written for SAML 2.0 renders a perfectly good 1.1 message as a
//     page of empty cells — the issuer is an attribute rather than a child
//     element, the id is `ResponseID` rather than `ID`, the status is a QName
//     rather than a URI, the confirmation method is a child element rather
//     than an attribute, and an attribute's name is split across two
//     attributes. Five separate places, each of which fails silently.
//   * a Redirect signature rebuilt in the wrong parameter ORDER gets a clean
//     INVALID for a signature that is fine, which in a browser is
//     indistinguishable from a wrong key.
//   * an assertion serialized out of its response WITHOUT the namespace
//     declarations it inherited verifies against nothing, for the same reason
//     and with the same message.
//   * an <samlp:ArtifactResponse>'s own Success reported as the result is a
//     failed sign-in reported as a successful one.
//
// Not one of those raises. All of them are visible here, against documents
// this file writes.
//
// It needs no server, no browser and no network, so it never skips.
//
// TEN SECTIONS:
//
//   1. classification — which binding, from the blob alone, in five shapes
//   2. the artifact — 2.0 type 0x0004 and both 1.1 types
//   3. the Redirect signed octets — order, and what is left out
//   4. summarize() — a request, in both versions
//   5. status — the URI, the QName, and the nested chain
//   6. an assertion's parts — attributes, confirmations, conditions, authn
//   7. assertionSummary() — the rows a details table draws
//   8. serializeSubtree() — an assertion that still verifies out of its
//      document
//   9. assertionsOf() — plaintext, advice and encrypted, in document order
//  10. summarizeResponse() — both versions, the envelope, and a bare assertion
// ---------------------------------------------------------------------------

const assert = require("assert");
const path = require("path");
const { Command, Option } = require("commander");
const paths = require("./module_paths.js");

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "saml_message_engine",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// The browser's XML parser, which node does not have. @xmldom stands in, as it
// does in the two page tests that build their fixtures with this module — and
// `parseXml()` is written knowing the difference: @xmldom THROWS on a
// namespace error where a browser returns a document containing a
// <parsererror>, which is why that function catches as well as checking.
const xmldom = require("@xmldom/xmldom");
global.DOMParser = xmldom.DOMParser;
global.XMLSerializer = xmldom.XMLSerializer;

// The module under test. requireSharedModule() is what makes a module borrowed
// from client/src resolve its own dependencies — node resolves those relative
// to where the MODULE lives, and a checkout that installed only the tests'
// dependencies has no client/node_modules. See tests/module_paths.js.
// In a checkout it is under client/src; the tests image copies it flat beside
// the test scripts (tests/Dockerfile), which is also why this file cannot be
// called saml_message.js.
const sm = paths.requireSharedModule(
  [path.join(__dirname, "saml_message.js"),
   path.join(__dirname, "..", "client", "src", "saml_message.js")],
  "client/src/saml_message.js");

let checks = 0;

function check(what, fn) {
  log.debug("Entering check(). " + what);
  fn();
  checks++;
  log.info("  ok — " + what);
  log.debug("Leaving check().");
}

// The value of one row of a summary, by its key. The summaries are ORDERED
// lists of { key, value, note } rather than objects, because the page draws
// them in order — so a lookup helper is what a test wants and an object is not
// what the module should return.
function rowValue(rows, key) {
  log.debug("Entering rowValue(). " + key);
  for (var i = 0; i < rows.length; i++) {
    if (rows[i].key === key) {
      log.debug("Leaving rowValue(). Found.");
      return rows[i].value;
    }
  }
  log.debug("Leaving rowValue(). Absent.");
  return null;
}

function rowKeys(rows) {
  log.debug("Entering rowKeys().");
  const out = rows.map(function (row) {
    return row.key;
  });
  log.debug("Leaving rowKeys().");
  return out;
}

function b64(text) {
  log.debug("Entering b64().");
  const out = Buffer.from(text, "utf8").toString("base64");
  log.debug("Leaving b64().");
  return out;
}

// ---------------------------------------------------------------------------
// THE FIXTURES.
//
// Written out here rather than generated, and rather than recorded off a live
// identity provider. A recorded document rots and cannot be reasoned about; a
// generated one agrees with the generator by construction. These are small,
// hand-written, and each carries exactly the feature the check below it is
// about — several of them deliberately MALFORMED in one specific way, which is
// the half a live IdP will never produce.
// ---------------------------------------------------------------------------

const NS2 = 'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"';
const NS1 = 'xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" ' +
    'xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"';
const NSDS = 'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"';

// A SAML 2.0 AuthnRequest carrying every optional part summarize() reads.
const AUTHN_REQUEST_20 =
  '<samlp:AuthnRequest ' + NS2 + ' ID="_req1" Version="2.0" ' +
      'IssueInstant="2026-09-01T10:00:00Z" ' +
      'Destination="https://idp.example.com/sso" ' +
      'Consent="urn:oasis:names:tc:SAML:2.0:consent:obtained" ' +
      'ForceAuthn="true" IsPassive="false" ' +
      'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ' +
      'AssertionConsumerServiceURL="https://sp.example.com/acs" ' +
      'AttributeConsumingServiceIndex="3" ProviderName="Example SP">' +
    '<saml:Issuer>https://sp.example.com</saml:Issuer>' +
    '<samlp:NameIDPolicy ' +
        'Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" ' +
        'SPNameQualifier="https://sp.example.com" AllowCreate="true"/>' +
    '<saml:Subject>' +
      '<saml:NameID ' +
          'Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" ' +
          'NameQualifier="idp" SPNameQualifier="sp">bob@example.com' +
      '</saml:NameID>' +
    '</saml:Subject>' +
    '<saml:Conditions NotBefore="2026-09-01T09:55:00Z" ' +
        'NotOnOrAfter="2026-09-01T10:05:00Z">' +
      '<saml:AudienceRestriction>' +
        '<saml:Audience>https://sp.example.com</saml:Audience>' +
        '<saml:Audience>https://other.example.com</saml:Audience>' +
      '</saml:AudienceRestriction>' +
    '</saml:Conditions>' +
    '<samlp:RequestedAuthnContext Comparison="minimum">' +
      '<saml:AuthnContextClassRef>' +
        'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport' +
      '</saml:AuthnContextClassRef>' +
      '<saml:AuthnContextDeclRef>https://example.com/decl' +
      '</saml:AuthnContextDeclRef>' +
    '</samlp:RequestedAuthnContext>' +
    '<samlp:Scoping ProxyCount="2">' +
      '<samlp:IDPList>' +
        '<samlp:IDPEntry ProviderID="https://idp1.example.com"/>' +
        '<samlp:IDPEntry ProviderID="https://idp2.example.com"/>' +
      '</samlp:IDPList>' +
      '<samlp:RequesterID>https://proxy.example.com</samlp:RequesterID>' +
    '</samlp:Scoping>' +
    '<samlp:Extensions><foo xmlns="urn:example"/></samlp:Extensions>' +
  '</samlp:AuthnRequest>';

// The same message signed. The signature is structurally complete and
// cryptographically meaningless — this module reports what a signature SAYS
// about itself and verifies nothing, which is common/xmldsig.js's job.
const SIGNED_AUTHN_REQUEST =
  '<samlp:AuthnRequest ' + NS2 + ' ' + NSDS + ' ID="_req2" Version="2.0" ' +
      'IssueInstant="2026-09-01T10:00:00Z">' +
    '<saml:Issuer>https://sp.example.com</saml:Issuer>' +
    '<ds:Signature>' +
      '<ds:SignedInfo>' +
        '<ds:CanonicalizationMethod ' +
            'Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
        '<ds:SignatureMethod ' +
            'Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>' +
        '<ds:Reference URI="#_req2">' +
          '<ds:DigestMethod ' +
              'Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>' +
          '<ds:DigestValue>ZGlnZXN0</ds:DigestValue>' +
        '</ds:Reference>' +
      '</ds:SignedInfo>' +
      '<ds:SignatureValue>c2ln</ds:SignatureValue>' +
      '<ds:KeyInfo><ds:X509Data>' +
        '<ds:X509Certificate>Q0VSVA==</ds:X509Certificate>' +
      '</ds:X509Data></ds:KeyInfo>' +
    '</ds:Signature>' +
  '</samlp:AuthnRequest>';

// ---------------------------------------------------------------------------
// 1. CLASSIFICATION.
//
// Five shapes reach this function and the user chose which — a full URL, a
// bare query string, a form body, a naked parameter value, or the XML itself.
// The answer records which one it was, because "I pasted the XML" and "I
// pasted a POST body" want different things said about the signature.
// ---------------------------------------------------------------------------
function everyPastedShapeIsClassified() {
  log.debug("Entering everyPastedShapeIsClassified().");

  check('an empty paste is not an error', function () {
    const out = sm.classify('   ');
    assert.strictEqual(out.kind, '');
    assert.strictEqual(out.binding, 'none');
    assert.deepStrictEqual(out.pairs, []);
  });

  check('XML is XML, and is not decoded', function () {
    const out = sm.classify('  ' + AUTHN_REQUEST_20 + '  ');
    assert.strictEqual(out.kind, 'xml');
    assert.strictEqual(out.binding, 'post');
    assert.strictEqual(out.message, '',
        'There is nothing still ENCODED here, and a caller that treats the ' +
        'document as a message to decode would base64-decode a <.');
    assert.ok(out.xml.indexOf('<samlp:AuthnRequest') === 0);
    assert.ok(/Redirect-binding message is signed over the/.test(out.note));
  });

  check('a GET carrying the message IS the Redirect binding', function () {
    const out = sm.classify('https://idp.example.com/sso?SAMLRequest=abc' +
        '&RelayState=xyz&SigAlg=alg&Signature=sss');
    assert.strictEqual(out.kind, 'url');
    assert.strictEqual(out.binding, 'redirect');
    assert.strictEqual(out.endpoint, 'https://idp.example.com/sso');
    assert.strictEqual(out.direction, 'request');
    assert.strictEqual(out.relayState, 'xyz');
    assert.strictEqual(out.signature, 'sss');
  });

  check('a fragment is not part of the query', function () {
    // A message that ended up after a `#` is a message nothing at the far end
    // ever received, so it must not be read back out as though it had been
    // sent.
    const out = sm.classify(
        'https://idp.example.com/sso?SAMLRequest=abc#SAMLResponse=nope');
    assert.strictEqual(out.message, 'abc');
    assert.strictEqual(out.direction, 'request');
    assert.strictEqual(sm.pairValue(out.pairs, 'SAMLResponse'), '',
        'A parameter after the fragment was never on the wire.');
  });

  check('a form body with no SigAlg reads as POST, and says why that is ' +
      'not certain', function () {
    const out = sm.classify('SAMLResponse=abc&RelayState=xyz');
    assert.strictEqual(out.kind, 'query');
    assert.strictEqual(out.binding, 'post');
    assert.strictEqual(out.direction, 'response');
    assert.ok(/only Redirect is DEFLATE-compressed/.test(out.note),
        'A Redirect message that was never signed looks exactly like a POST ' +
        'body, and only the decode tells them apart.');
  });

  check('a body WITH a SigAlg is a Redirect that lost its endpoint',
      function () {
    const out = sm.classify('SAMLRequest=abc&SigAlg=alg');
    assert.strictEqual(out.kind, 'query');
    assert.strictEqual(out.binding, 'redirect');
    assert.strictEqual(out.note, '');
  });

  check('a bare parameter value is the commonest paste of all', function () {
    const out = sm.classify('PHNhbWxwOkF1dGhuUmVxdWVzdC8+');
    assert.strictEqual(out.kind, 'param');
    assert.strictEqual(out.binding, 'post');
    assert.strictEqual(out.message, 'PHNhbWxwOkF1dGhuUmVxdWVzdC8+');
    assert.ok(/decided by decoding it, not by this/.test(out.note));
  });

  check('SAMLart makes it the artifact binding, message or no message',
      function () {
    const out = sm.classify(
        'https://sp.example.com/acs?SAMLart=AAQAAA&RelayState=r');
    assert.strictEqual(out.binding, 'artifact');
    assert.strictEqual(out.artifact, 'AAQAAA');
    assert.ok(/travels over the SOAP back-channel/.test(out.note));
  });

  check('a SAML 1.1 TARGET with no SAMLart is an inter-site transfer',
      function () {
    const out = sm.classify('https://idp.example.com/transfer?TARGET=' +
        'https%3A%2F%2Fsp.example.com%2Fhome');
    assert.strictEqual(out.binding, 'artifact');
    assert.strictEqual(out.target, 'https://sp.example.com/home');
    assert.ok(/SAML 1.1 has no request document at all/.test(out.note),
        'There is nothing to decode, and saying so beats an empty XML pane.');
  });

  check('a payload that merely BEGINS with the letters SAML is not a ' +
      'parameter list', function () {
    // The `=` is part of the parameter test on purpose: base64 is full of
    // padding, and this value is a bare parameter rather than a query string
    // with no parameters in it.
    const out = sm.classify('SAMLisnotaparametername');
    assert.strictEqual(out.kind, 'param');
  });

  check('the pairs keep their ORDER and stay percent-encoded', function () {
    // Both properties are what the Redirect signature is computed over, so a
    // classifier that used URLSearchParams would have produced a different
    // message.
    const out = sm.classify('https://idp/sso?SigAlg=a%2Bb&SAMLRequest=Zm9v' +
        '&RelayState=x%20y');
    assert.deepStrictEqual(rowKeysOfPairs(out.pairs),
        ['SigAlg', 'SAMLRequest', 'RelayState']);
    assert.strictEqual(out.pairs[0][1], 'a%2Bb', 'still encoded');
    assert.strictEqual(out.sigAlg, 'a+b', 'decoded on the way out');
    assert.strictEqual(out.relayState, 'x y', '+ and %20 both mean a space');
  });

  check('a parameter with no `=` is kept with an empty value', function () {
    const pairs = sm.queryPairs('a=1&bare&c=3');
    assert.deepStrictEqual(pairs, [['a', '1'], ['bare', ''], ['c', '3']]);
  });

  log.debug("Leaving everyPastedShapeIsClassified().");
}

function rowKeysOfPairs(pairs) {
  log.debug("Entering rowKeysOfPairs().");
  const out = pairs.map(function (pair) {
    return pair[0];
  });
  log.debug("Leaving rowKeysOfPairs().");
  return out;
}

// ---------------------------------------------------------------------------
// 2. THE ARTIFACT.
//
// Not a message: 44 bytes of binary for SAML 2.0 type 0x0004 and 42 for the
// two SAML 1.1 types. Nothing here can resolve one — the MessageHandle is a
// one-shot ticket redeemed over the SOAP back-channel — so showing what it
// SAYS is the whole of what a decoder can do, and it is more than it looks: a
// SourceID that does not match the identity provider you think you are talking
// to is a complete diagnosis.
// ---------------------------------------------------------------------------
function theArtifactIsBytesAndNotAMessage() {
  log.debug("Entering theArtifactIsBytesAndNotAMessage().");

  function artifact(bytes) {
    log.debug("Entering artifact().");
    const out = Buffer.from(bytes).toString("base64");
    log.debug("Leaving artifact().");
    return out;
  }

  check('SAML 2.0 type 0x0004 splits into endpoint, source and handle',
      function () {
    const bytes = [0, 4, 0, 7];
    for (var i = 0; i < 20; i++) bytes.push(0xAA);
    for (var j = 0; j < 20; j++) bytes.push(0xBB);
    const out = sm.parseArtifact(artifact(bytes));
    assert.strictEqual(out.typeCode, 4);
    assert.strictEqual(out.type, 'SAML 2.0 type 0x0004');
    assert.strictEqual(out.endpointIndex, 7);
    assert.strictEqual(out.sourceId, 'aa'.repeat(20));
    assert.strictEqual(out.messageHandle, 'bb'.repeat(20));
    assert.strictEqual(out.length, 44);
    assert.ok(!out.warning, 'A 44-byte type 4 artifact is the right length.');
  });

  check('SAML 1.1 type 0x0001 is SourceID then AssertionHandle', function () {
    const bytes = [0, 1];
    for (var i = 0; i < 20; i++) bytes.push(0x11);
    for (var j = 0; j < 20; j++) bytes.push(0x22);
    const out = sm.parseArtifact(artifact(bytes));
    assert.strictEqual(out.type, 'SAML 1.1 type 0x0001');
    assert.strictEqual(out.sourceId, '11'.repeat(20));
    assert.strictEqual(out.assertionHandle, '22'.repeat(20));
    assert.strictEqual(out.length, 42);
    assert.strictEqual(out.endpointIndex, undefined,
        'Type 1 has no EndpointIndex — those two bytes are the SourceID.');
  });

  check('SAML 1.1 type 0x0002 ends in a URL, not a handle', function () {
    const bytes = [0, 2];
    for (var i = 0; i < 20; i++) bytes.push(0x33);
    Buffer.from('https://idp.example.com', 'utf8').forEach(function (b) {
      bytes.push(b);
    });
    const out = sm.parseArtifact(artifact(bytes));
    assert.strictEqual(out.type, 'SAML 1.1 type 0x0002');
    assert.strictEqual(out.assertionHandle, '33'.repeat(20));
    assert.strictEqual(out.sourceLocation, 'https://idp.example.com',
        'The remainder is TEXT for this type, and reading it as another ' +
        '20-byte handle produces 40 hex digits of a URL.');
    assert.strictEqual(out.expectedLength, undefined,
        'A type 2 artifact has no fixed length; the URL decides it.');
  });

  check('a type 4 artifact of the wrong length is reported, not rejected',
      function () {
    const bytes = [0, 4, 0, 0];
    for (var i = 0; i < 30; i++) bytes.push(0);
    const out = sm.parseArtifact(artifact(bytes));
    assert.strictEqual(out.expectedLength, 44);
    assert.ok(/is 44 bytes; this one is 34/.test(out.warning),
        'The fields are still shown — a truncated artifact is exactly what ' +
        'somebody needs to see.');
  });

  check('an unknown TypeCode is named in hex', function () {
    const out = sm.parseArtifact(artifact([0x00, 0x09, 1, 2, 3, 4]));
    assert.strictEqual(out.type, 'unrecognised (TypeCode 0x0009)');
    assert.ok(!out.sourceId);
  });

  check('too short and not-base64 are told apart', function () {
    assert.ok(/at least 4 bytes/.test(sm.parseArtifact(artifact([0, 4]))
        .error));
    const bad = sm.parseArtifact('!!!!not base64!!!!');
    assert.ok(bad.error && /not valid base64/.test(bad.error));
  });

  check('base64url and whitespace are both normalized', function () {
    // An artifact copied out of a log arrives wrapped, and one copied out of a
    // JSON body may be base64url. Neither is a malformed artifact.
    const bytes = [0, 4, 0, 1];
    for (var i = 0; i < 40; i++) bytes.push(0xFE);
    const plain = artifact(bytes);
    const wrapped = plain.substring(0, 20) + '\n  ' + plain.substring(20);
    assert.strictEqual(sm.parseArtifact(wrapped).raw,
        sm.parseArtifact(plain).raw);
    const urlSafe = plain.replace(/\+/g, '-').replace(/\//g, '_')
      .replace(/=+$/, '');
    assert.strictEqual(sm.parseArtifact(urlSafe).raw,
        sm.parseArtifact(plain).raw);
  });

  log.debug("Leaving theArtifactIsBytesAndNotAMessage().");
}

// ---------------------------------------------------------------------------
// 3. THE REDIRECT SIGNED OCTETS.
//
// saml-bindings-2.0-os section 3.4.4.1: the signature covers the query string
// AS SENT, with SigAlg included and Signature itself removed. Anything that
// re-orders, decodes or adds has produced a different message and gets a clean
// INVALID for a signature that is perfectly good — which in a browser is
// indistinguishable from a wrong key, and is the reason this check exists in
// node rather than on a page.
// ---------------------------------------------------------------------------
function theRedirectOctetsAreTheOnesThatWereSent() {
  log.debug("Entering theRedirectOctetsAreTheOnesThatWereSent().");

  check('the order is the order they arrived in, not a canonical one',
      function () {
    const out = sm.classify('https://idp/sso?RelayState=r&SAMLRequest=m' +
        '&SigAlg=a&Signature=s');
    assert.strictEqual(sm.redirectSignedOctets(out.pairs),
        'RelayState=r&SAMLRequest=m&SigAlg=a',
        'The specification says AS SENT. Sorting these is the single ' +
        'commonest way to get a valid signature reported invalid.');
  });

  check('Signature is removed and everything else that is not a SAML ' +
      'parameter is too', function () {
    const pairs = sm.queryPairs('SAMLResponse=m&utm_source=x&SigAlg=a' +
        '&Signature=s&RelayState=r');
    assert.strictEqual(sm.redirectSignedOctets(pairs),
        'SAMLResponse=m&SigAlg=a&RelayState=r',
        'A tracking parameter appended by something in the middle is not ' +
        'part of the signed set, and including it invalidates everything.');
  });

  check('the values stay percent-encoded', function () {
    const pairs = sm.queryPairs('SAMLRequest=a%2Bb%3D&SigAlg=x%3Ay');
    assert.strictEqual(sm.redirectSignedOctets(pairs),
        'SAMLRequest=a%2Bb%3D&SigAlg=x%3Ay');
  });

  check('a query with no SAML parameters signs nothing', function () {
    assert.strictEqual(sm.redirectSignedOctets(sm.queryPairs('a=1&b=2')), '');
  });

  log.debug("Leaving theRedirectOctetsAreTheOnesThatWereSent().");
}

// ---------------------------------------------------------------------------
// 4. summarize() — A REQUEST, IN BOTH VERSIONS.
// ---------------------------------------------------------------------------
function aRequestIsSummarizedInBothVersions() {
  log.debug("Entering aRequestIsSummarizedInBothVersions().");

  check('a SAML 2.0 AuthnRequest reports every part it carries', function () {
    const out = sm.summarize(AUTHN_REQUEST_20);
    assert.strictEqual(out.messageType, 'AuthnRequest');
    assert.strictEqual(out.version, '2.0');
    assert.strictEqual(rowValue(out.rows, 'ID'), '_req1');
    assert.strictEqual(rowValue(out.rows, 'Issuer'), 'https://sp.example.com');
    assert.strictEqual(rowValue(out.rows, 'Destination'),
        'https://idp.example.com/sso');
    assert.strictEqual(rowValue(out.rows, 'ForceAuthn'), 'true');
    assert.strictEqual(rowValue(out.rows, 'AssertionConsumerServiceURL'),
        'https://sp.example.com/acs');
    assert.strictEqual(rowValue(out.rows, 'NameIDPolicy AllowCreate'), 'true');
    assert.strictEqual(rowValue(out.rows, 'Subject NameID'),
        'bob@example.com');
    assert.strictEqual(rowValue(out.rows, 'Audience Restriction'),
        'https://sp.example.com, https://other.example.com');
    assert.strictEqual(rowValue(out.rows, 'Scoping ProxyCount'), '2');
    assert.strictEqual(rowValue(out.rows, 'Scoping IDPList'),
        'https://idp1.example.com\nhttps://idp2.example.com');
    assert.strictEqual(rowValue(out.rows, 'Extensions'), 'present');
  });

  check('an absent boolean is a ROW rather than a blank', function () {
    // "IsPassive: (absent — false)" and no row at all mean the same thing to
    // the specification and very different things to somebody who thinks they
    // set it.
    const out = sm.summarize(AUTHN_REQUEST_20);
    assert.strictEqual(rowValue(out.rows, 'IsPassive'), 'false');
    const bare = sm.summarize('<samlp:AuthnRequest ' + NS2 +
        ' ID="_r" Version="2.0"/>');
    assert.strictEqual(rowValue(bare.rows, 'IsPassive'), '(absent — false)');
    assert.strictEqual(rowValue(bare.rows, 'ForceAuthn'), '(absent — false)');
  });

  check('the RequestedAuthnContext refs keep their order', function () {
    // With Comparison="exact" the identity provider matches the LIST, so a
    // reader that sorted or de-duplicated them would hide the reason a request
    // is being refused.
    const out = sm.summarize(AUTHN_REQUEST_20);
    assert.strictEqual(rowValue(out.rows, 'RequestedAuthnContext Comparison'),
        'minimum');
    assert.strictEqual(rowValue(out.rows, 'AuthnContext Class/Decl Refs'),
        'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport' +
        '\nhttps://example.com/decl');
  });

  check('an absent Comparison is reported as the default it means',
      function () {
    const out = sm.summarize('<samlp:AuthnRequest ' + NS2 + ' Version="2.0">' +
      '<samlp:RequestedAuthnContext>' +
        '<saml:AuthnContextClassRef>x</saml:AuthnContextClassRef>' +
      '</samlp:RequestedAuthnContext></samlp:AuthnRequest>');
    assert.strictEqual(rowValue(out.rows, 'RequestedAuthnContext Comparison'),
        '(absent — exact)');
  });

  check('a LogoutRequest reports the NameID and every SessionIndex',
      function () {
    const out = sm.summarize('<samlp:LogoutRequest ' + NS2 +
        ' ID="_lo" Version="2.0" Reason="urn:oasis:names:tc:SAML:2.0:' +
        'logout:user" NotOnOrAfter="2026-09-01T11:00:00Z">' +
      '<saml:Issuer>https://sp.example.com</saml:Issuer>' +
      '<saml:NameID Format="persistent" SPNameQualifier="sp">u1</saml:NameID>' +
      '<samlp:SessionIndex>s1</samlp:SessionIndex>' +
      '<samlp:SessionIndex>s2</samlp:SessionIndex>' +
      '</samlp:LogoutRequest>');
    assert.strictEqual(out.messageType, 'LogoutRequest');
    assert.strictEqual(rowValue(out.rows, 'NameID'), 'u1');
    assert.strictEqual(rowValue(out.rows, 'SPNameQualifier'), 'sp');
    assert.strictEqual(rowValue(out.rows, 'SessionIndex'), 's1\ns2');
    assert.ok(/logout:user$/.test(rowValue(out.rows, 'Reason')));
    assert.strictEqual(out.subject.value, 'u1',
        'A LogoutRequest puts the NameID directly under the message rather ' +
        'than inside a <saml:Subject>, and a reader that only looks in a ' +
        'Subject reports a logout for nobody.');
  });

  check('an ArtifactResolve and an AttributeQuery each report their own part',
      function () {
    const ar = sm.summarize('<samlp:ArtifactResolve ' + NS2 +
      ' Version="2.0"><samlp:Artifact>AAQAAA==</samlp:Artifact>' +
      '</samlp:ArtifactResolve>');
    assert.strictEqual(rowValue(ar.rows, 'Artifact'), 'AAQAAA==');
    const aq = sm.summarize('<samlp:AttributeQuery ' + NS2 +
        ' Version="2.0" Resource="https://sp/resource">' +
      '<saml:Subject><saml:NameID Format="f">bob</saml:NameID></saml:Subject>' +
      '</samlp:AttributeQuery>');
    assert.strictEqual(rowValue(aq.rows, 'Subject NameID'), 'bob');
    assert.strictEqual(rowValue(aq.rows, 'Resource'), 'https://sp/resource');
  });

  check('SAML 1.1 reads its version off MajorVersion/MinorVersion',
      function () {
    // The 1.0 and 1.1 schemas share every namespace they have — the version
    // travels in these two attributes, so a reader that guessed from the
    // namespace would call every 1.1 message 1.0.
    const out = sm.summarize('<samlp:Request ' + NS1 +
        ' RequestID="_q1" MajorVersion="1" MinorVersion="1" ' +
        'IssueInstant="2026-09-01T10:00:00Z">' +
      '<samlp:AttributeQuery Resource="https://sp/r">' +
        '<saml:Subject>' +
          '<saml:NameIdentifier Format="email">bob@example.com' +
          '</saml:NameIdentifier>' +
        '</saml:Subject>' +
      '</samlp:AttributeQuery></samlp:Request>');
    assert.strictEqual(out.version, '1.1');
    assert.strictEqual(rowValue(out.rows, 'ID'), '_q1',
        'SAML 1.1 spells the message id RequestID.');
    assert.strictEqual(rowValue(out.rows, 'Query Type'), 'AttributeQuery');
    assert.strictEqual(rowValue(out.rows, 'Subject NameIdentifier'),
        'bob@example.com');
    assert.strictEqual(rowValue(out.rows, 'Resource'), 'https://sp/r');
  });

  check('a SAML 1.1 Request carrying an artifact reports the artifact',
      function () {
    const out = sm.summarize('<samlp:Request ' + NS1 +
        ' MajorVersion="1" MinorVersion="1">' +
      '<samlp:AssertionArtifact>AAEAAA==</samlp:AssertionArtifact>' +
      '</samlp:Request>');
    assert.strictEqual(rowValue(out.rows, 'Query Type'), 'AssertionArtifact');
    assert.strictEqual(rowValue(out.rows, 'AssertionArtifact'), 'AAEAAA==');
  });

  check('a 1.x message with neither version attribute still says 1.x',
      function () {
    const out = sm.summarize('<samlp:Request ' + NS1 + '/>');
    assert.strictEqual(out.version, '1.x',
        'The namespace alone is enough to know it is not 2.0, which is what ' +
        'every other reader in the module branches on.');
  });

  check('a signature is reported by what it SAYS about itself', function () {
    const out = sm.summarize(SIGNED_AUTHN_REQUEST);
    assert.ok(out.signature);
    assert.strictEqual(rowValue(out.rows, 'Signature'), 'present (enveloped)');
    assert.ok(/rsa-sha256$/.test(rowValue(out.rows, 'Signature Method')));
    assert.ok(/xml-exc-c14n#$/.test(rowValue(out.rows, 'Canonicalization')));
    assert.strictEqual(rowValue(out.rows, 'Signed Reference URI'), '#_req2');
    assert.strictEqual(rowValue(out.rows, 'KeyInfo certificate'), 'present');
  });

  check('an unsigned message SAYS it is unsigned', function () {
    const out = sm.summarize(AUTHN_REQUEST_20);
    assert.strictEqual(out.signature, null);
    assert.strictEqual(rowValue(out.rows, 'Signature'),
        'no enveloped <ds:Signature> on the message',
        'A blank row here reads as "not checked yet" rather than as ' +
        '"nothing signed this".');
  });

  check('a signature nested deeper is NOT the message signature', function () {
    // A signature inside an assertion belongs to the assertion. Reporting it
    // as the message's is how a debugger tells somebody their unsigned
    // response is signed.
    const out = sm.summarize('<samlp:AuthnRequest ' + NS2 + ' ' + NSDS +
        ' Version="2.0"><saml:Subject><ds:Signature/></saml:Subject>' +
        '</samlp:AuthnRequest>');
    assert.strictEqual(out.signature, null);
  });

  check('an encrypted root is one row saying so, not a table of blanks',
      function () {
    const out = sm.summarize(
      '<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" ' +
          'Type="http://www.w3.org/2001/04/xmlenc#Element">' +
        '<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#' +
            'aes256-gcm"/>' +
        '<xenc:CipherData><xenc:CipherValue>Y2lwaGVy</xenc:CipherValue>' +
        '</xenc:CipherData></xenc:EncryptedData>');
    assert.strictEqual(out.messageType, 'EncryptedData');
    assert.ok(/aes256-gcm$/.test(rowValue(out.rows, 'Encryption (data)')));
    assert.ok(/Supply the recipient private key/.test(
        rowValue(out.rows, 'Status')));
    assert.strictEqual(rowValue(out.rows, 'SAML Version'), null,
        'There is no request in there to describe until a key is applied.');
  });

  check('an EncryptedID subject is named rather than left blank', function () {
    const out = sm.summarize('<samlp:AuthnRequest ' + NS2 + ' Version="2.0">' +
      '<saml:Subject><saml:EncryptedID>' +
        '<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/>' +
      '</saml:EncryptedID></saml:Subject></samlp:AuthnRequest>');
    assert.ok(/<saml:EncryptedID>/.test(rowValue(out.rows, 'Subject')));
    assert.ok(out.encrypted,
        'A request whose subject is encrypted is the ordinary reason an ' +
        'AuthnRequest needs a key at all.');
  });

  check('a value that is not XML is a sentence, not a throw', function () {
    const out = sm.summarize('this is not xml at all');
    assert.deepStrictEqual(out.rows, []);
    assert.strictEqual(out.error, 'The decoded value is not well-formed XML.');
  });

  log.debug("Leaving aRequestIsSummarizedInBothVersions().");
}

// ---------------------------------------------------------------------------
// 5. STATUS — A URI IN 2.0, A QName IN 1.1, AND A CHAIN IN BOTH.
// ---------------------------------------------------------------------------
function theStatusIsReadInBothSpellings() {
  log.debug("Entering theStatusIsReadInBothSpellings().");

  check('the short form is the last segment, in either spelling', function () {
    assert.strictEqual(
        sm.shortStatus('urn:oasis:names:tc:SAML:2.0:status:Success'),
        'Success');
    assert.strictEqual(sm.shortStatus('samlp:Success'), 'Success');
    assert.strictEqual(sm.shortStatus('Success'), 'Success');
    assert.strictEqual(sm.shortStatus(''), '');
  });

  check('a lookalike is not a success', function () {
    assert.ok(sm.isSuccessStatus('urn:…:status:Success'));
    assert.ok(!sm.isSuccessStatus('urn:…:status:RequesterSuccess'));
    assert.ok(!sm.isSuccessStatus('Success is what we wanted'));
    assert.ok(!sm.isSuccessStatus(''));
  });

  check('a QName resolves against the declarations in scope', function () {
    const doc = sm.parseXml('<samlp:Response ' + NS2 + '><samlp:Status>' +
      '<samlp:StatusCode Value="samlp:Requester"/></samlp:Status>' +
      '</samlp:Response>');
    const status = sm.statusOf(doc.documentElement);
    assert.strictEqual(status.top, 'samlp:Requester');
    assert.strictEqual(status.topResolved,
        '{urn:oasis:names:tc:SAML:2.0:protocol}Requester');
  });

  check('a prefix declared NOWHERE is said out loud', function () {
    // Every lenient reader in the world accepts this document. This is the
    // only place it will ever be mentioned.
    const doc = sm.parseXml('<Response xmlns="urn:x"><Status>' +
      '<StatusCode Value="nosuch:Success"/></Status></Response>');
    const status = sm.statusOf(doc.documentElement);
    assert.ok(/declared nowhere in this document/.test(status.topResolved));
  });

  check('a URI and a bare local part both resolve to nothing, and neither ' +
      'is an error', function () {
    const doc = sm.parseXml('<Response xmlns="urn:x"/>');
    const el = doc.documentElement;
    assert.strictEqual(sm.resolveQName(el,
        'urn:oasis:names:tc:SAML:2.0:status:Success'), '',
        'A 2.0 status code has several colons and is not a QName.');
    assert.strictEqual(sm.resolveQName(el, 'Success'), '');
    assert.strictEqual(sm.resolveQName(el, '1bad:Success'), '',
        'An NCName cannot start with a digit.');
    assert.strictEqual(sm.resolveQName(null, 'a:b'), '');
  });

  check('nested codes are a CHAIN and the note describes the most specific',
      function () {
    // saml-core-2.0-os section 3.2.2.1 nests them to QUALIFY the one above, so
    // "Responder then NoPassive" is one answer with two parts — and a
    // top-level Responder says only that it was not the request's fault.
    const doc = sm.parseXml('<samlp:Response ' + NS2 + '><samlp:Status>' +
      '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:' +
          'Responder">' +
        '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:' +
            'NoPassive"/>' +
      '</samlp:StatusCode>' +
      '<samlp:StatusMessage>no passive auth</samlp:StatusMessage>' +
      '<samlp:StatusDetail><x xmlns="urn:e"/></samlp:StatusDetail>' +
      '</samlp:Status></samlp:Response>');
    const status = sm.statusOf(doc.documentElement);
    assert.strictEqual(status.chain.length, 2);
    assert.strictEqual(status.short, 'Responder');
    assert.strictEqual(status.success, false);
    assert.strictEqual(status.message, 'no passive auth');
    assert.ok(status.detail.indexOf('StatusDetail') >= 0);
    assert.strictEqual(status.note, sm.STATUS_NOTES.NoPassive,
        'The note follows the MOST SPECIFIC code. Reporting the top one ' +
        'says "the responder had a problem" about a request that asked for ' +
        'something the responder cannot do.');
  });

  check('no <samlp:Status> at all is reported as absent', function () {
    const doc = sm.parseXml('<samlp:Response ' + NS2 + '/>');
    const status = sm.statusOf(doc.documentElement);
    assert.strictEqual(status.present, false);
    assert.deepStrictEqual(status.chain, []);
    assert.strictEqual(sm.statusOf(null).present, false);
  });

  log.debug("Leaving theStatusIsReadInBothSpellings().");
}

// ---------------------------------------------------------------------------
// 6. AN ASSERTION'S PARTS.
// ---------------------------------------------------------------------------
function anAssertionsPartsAreReadInBothVersions() {
  log.debug("Entering anAssertionsPartsAreReadInBothVersions().");

  check('SAML 1.1 splits an attribute name across TWO attributes', function () {
    // 2.0 writes one `Name` URI; 1.1 writes `AttributeNamespace` and
    // `AttributeName`, and a reader that knows only `Name` shows a column of
    // blanks on a document that is perfectly well formed.
    const doc = sm.parseXml('<saml:Assertion ' + NS1 + '>' +
      '<saml:AttributeStatement>' +
        '<saml:Attribute AttributeName="emailAddress" ' +
            'AttributeNamespace="urn:example:claims/">' +
          '<saml:AttributeValue>bob@example.com</saml:AttributeValue>' +
        '</saml:Attribute>' +
      '</saml:AttributeStatement></saml:Assertion>');
    const attrs = sm.attributesOf(doc.documentElement);
    assert.strictEqual(attrs.length, 1);
    assert.strictEqual(attrs[0].name, 'urn:example:claims/emailAddress',
        'The two halves are joined back into the claim URI they came from, ' +
        'and the trailing slash is not doubled.');
    assert.strictEqual(attrs[0].rawName, 'emailAddress');
    assert.strictEqual(attrs[0].namespace, 'urn:example:claims/');
    assert.deepStrictEqual(attrs[0].values, ['bob@example.com']);
  });

  check('a SAML 2.0 Name is used as it stands', function () {
    const doc = sm.parseXml('<saml:Assertion ' + NS2 + '>' +
      '<saml:AttributeStatement>' +
        '<saml:Attribute Name="urn:oid:1.2.3" FriendlyName="uid" ' +
            'NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">' +
          '<saml:AttributeValue>a</saml:AttributeValue>' +
          '<saml:AttributeValue>b</saml:AttributeValue>' +
        '</saml:Attribute>' +
      '</saml:AttributeStatement></saml:Assertion>');
    const attrs = sm.attributesOf(doc.documentElement);
    assert.strictEqual(attrs[0].name, 'urn:oid:1.2.3');
    assert.strictEqual(attrs[0].friendlyName, 'uid');
    assert.deepStrictEqual(attrs[0].values, ['a', 'b']);
  });

  check('SAML 2.0 puts the confirmation method in an attribute', function () {
    const doc = sm.parseXml('<saml:Assertion ' + NS2 + '><saml:Subject>' +
      '<saml:NameID>bob</saml:NameID>' +
      '<saml:SubjectConfirmation ' +
          'Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">' +
        '<saml:SubjectConfirmationData Recipient="https://sp/acs" ' +
            'NotOnOrAfter="2026-09-01T10:05:00Z" InResponseTo="_req1" ' +
            'Address="10.0.0.1"/>' +
      '</saml:SubjectConfirmation></saml:Subject></saml:Assertion>');
    const subject = sm.parseXml(sm.serialize(doc.documentElement));
    const confs = sm.subjectConfirmations(
        sm.directChild(subject.documentElement, 'Subject'));
    assert.strictEqual(confs.length, 1);
    assert.ok(/cm:bearer$/.test(confs[0].method));
    assert.strictEqual(confs[0].recipient, 'https://sp/acs');
    assert.strictEqual(confs[0].inResponseTo, '_req1');
    assert.strictEqual(confs[0].address, '10.0.0.1');
  });

  check('SAML 1.1 puts it in CHILD ELEMENTS, and there may be several',
      function () {
    // saml-profile-1.1 section 4.1.1.4 requires cm:artifact for
    // Browser/Artifact and 4.2.1.4 requires cm:bearer for Browser/POST. A
    // reader that looks only for @Method reports the profile as unstated on
    // every 1.1 assertion, which in the 1.1 browser profiles is the whole of
    // what distinguishes the two.
    const doc = sm.parseXml('<saml:Assertion ' + NS1 + '><saml:Subject>' +
      '<saml:NameIdentifier>bob</saml:NameIdentifier>' +
      '<saml:SubjectConfirmation>' +
        '<saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer' +
        '</saml:ConfirmationMethod>' +
        '<saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:artifact' +
        '</saml:ConfirmationMethod>' +
      '</saml:SubjectConfirmation></saml:Subject></saml:Assertion>');
    const confs = sm.subjectConfirmations(
        sm.directChild(doc.documentElement, 'Subject'));
    assert.strictEqual(confs.length, 2, 'One row per method, not one row.');
    assert.ok(/cm:bearer$/.test(confs[0].method));
    assert.ok(/cm:artifact$/.test(confs[1].method));
  });

  check('no Subject means no confirmations, and that is not an error',
      function () {
    assert.deepStrictEqual(sm.subjectConfirmations(null), []);
  });

  check('EVERY condition is reported, including one nothing here recognises',
      function () {
    // saml-core-2.0-os section 2.5.1: a condition a relying party does not
    // understand is one it MUST reject, so silently dropping it is the single
    // thing a reader must not do here.
    const doc = sm.parseXml('<saml:Assertion ' + NS2 + '>' +
      '<saml:Conditions NotBefore="2026-09-01T09:55:00Z" ' +
          'NotOnOrAfter="2026-09-01T10:05:00Z">' +
        '<saml:AudienceRestriction>' +
          '<saml:Audience>https://sp.example.com</saml:Audience>' +
        '</saml:AudienceRestriction>' +
        '<saml:OneTimeUse/>' +
        '<saml:ProxyRestriction Count="0"/>' +
      '</saml:Conditions></saml:Assertion>');
    const conds = sm.conditionsOf(doc.documentElement);
    assert.strictEqual(conds.notBefore, '2026-09-01T09:55:00Z');
    assert.deepStrictEqual(conds.entries.map(function (e) {
      return e.localName;
    }), ['AudienceRestriction', 'OneTimeUse', 'ProxyRestriction']);
    assert.deepStrictEqual(conds.entries[0].values,
        ['https://sp.example.com']);
    assert.strictEqual(sm.conditionsOf(sm.parseXml('<saml:Assertion ' + NS2 +
        '/>').documentElement), null);
  });

  check('the 1.1 spelling of the audience condition keeps its own name',
      function () {
    // AudienceRestriction (2.0) and AudienceRestrictionCondition (1.1) are the
    // same condition under two names, and WHICH ONE ARRIVED is exactly what
    // somebody reads this for.
    const doc = sm.parseXml('<saml:Assertion ' + NS1 + '><saml:Conditions>' +
      '<saml:AudienceRestrictionCondition>' +
        '<saml:Audience>https://sp.example.com</saml:Audience>' +
      '</saml:AudienceRestrictionCondition></saml:Conditions>' +
      '</saml:Assertion>');
    const conds = sm.conditionsOf(doc.documentElement);
    assert.strictEqual(conds.entries[0].localName,
        'AudienceRestrictionCondition');
  });

  check('the authn statement is read in both spellings', function () {
    const two = sm.parseXml('<saml:Assertion ' + NS2 + '>' +
      '<saml:AuthnStatement AuthnInstant="2026-09-01T10:00:00Z" ' +
          'SessionIndex="sess1" ' +
          'SessionNotOnOrAfter="2026-09-01T18:00:00Z">' +
        '<saml:SubjectLocality Address="10.0.0.1" ' +
            'DNSName="host.example.com"/>' +
        '<saml:AuthnContext><saml:AuthnContextClassRef>' +
          'urn:oasis:names:tc:SAML:2.0:ac:classes:Password' +
        '</saml:AuthnContextClassRef></saml:AuthnContext>' +
      '</saml:AuthnStatement></saml:Assertion>');
    const a = sm.authnStatementOf(two.documentElement);
    assert.strictEqual(a.element, 'AuthnStatement');
    assert.strictEqual(a.instant, '2026-09-01T10:00:00Z');
    assert.strictEqual(a.sessionIndex, 'sess1');
    assert.strictEqual(a.locality, '10.0.0.1 / host.example.com');
    assert.ok(/classes:Password$/.test(a.contextRefs[0]));

    const one = sm.parseXml('<saml:Assertion ' + NS1 + '>' +
      '<saml:AuthenticationStatement ' +
          'AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password" ' +
          'AuthenticationInstant="2026-09-01T10:00:00Z">' +
        '<saml:SubjectLocality IPAddress="10.0.0.2" ' +
            'DNSAddress="h2.example.com"/>' +
      '</saml:AuthenticationStatement></saml:Assertion>');
    const b = sm.authnStatementOf(one.documentElement);
    assert.strictEqual(b.element, 'AuthenticationStatement');
    assert.strictEqual(b.instant, '2026-09-01T10:00:00Z',
        'AuthenticationInstant, not AuthnInstant — a reader written for 2.0 ' +
        'reports a sign-in with no time on it.');
    assert.ok(/am:password$/.test(b.method));
    assert.strictEqual(b.locality, '10.0.0.2 / h2.example.com',
        'IPAddress/DNSAddress in 1.1, Address/DNSName in 2.0.');
    assert.strictEqual(sm.authnStatementOf(sm.parseXml('<saml:Assertion ' +
        NS2 + '/>').documentElement), null);
  });

  log.debug("Leaving anAssertionsPartsAreReadInBothVersions().");
}

// ---------------------------------------------------------------------------
// 7. assertionSummary() — THE ROWS A DETAILS TABLE DRAWS.
// ---------------------------------------------------------------------------

const ASSERTION_20 =
  '<saml:Assertion ' + NS2 + ' ' + NSDS + ' ID="_a1" Version="2.0" ' +
      'IssueInstant="2026-09-01T10:00:01Z">' +
    '<saml:Issuer>https://idp.example.com</saml:Issuer>' +
    '<ds:Signature><ds:SignedInfo>' +
      '<ds:CanonicalizationMethod ' +
          'Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
      '<ds:SignatureMethod ' +
          'Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>' +
      '<ds:Reference URI="#_a1"><ds:DigestMethod ' +
          'Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>' +
        '<ds:DigestValue>ZA==</ds:DigestValue></ds:Reference>' +
    '</ds:SignedInfo><ds:SignatureValue>cw==</ds:SignatureValue>' +
    '</ds:Signature>' +
    '<saml:Subject>' +
      '<saml:NameID Format="persistent" NameQualifier="idp" ' +
          'SPNameQualifier="sp">bob</saml:NameID>' +
      '<saml:SubjectConfirmation ' +
          'Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">' +
        '<saml:SubjectConfirmationData Recipient="https://sp/acs" ' +
            'InResponseTo="_req1" NotOnOrAfter="2026-09-01T10:05:00Z"/>' +
      '</saml:SubjectConfirmation>' +
    '</saml:Subject>' +
    '<saml:Conditions NotOnOrAfter="2026-09-01T10:05:00Z">' +
      '<saml:AudienceRestriction>' +
        '<saml:Audience>https://sp.example.com</saml:Audience>' +
      '</saml:AudienceRestriction>' +
    '</saml:Conditions>' +
    '<saml:AuthnStatement AuthnInstant="2026-09-01T10:00:00Z" ' +
        'SessionIndex="sess1">' +
      '<saml:AuthnContext><saml:AuthnContextClassRef>' +
        'urn:oasis:names:tc:SAML:2.0:ac:classes:Password' +
      '</saml:AuthnContextClassRef></saml:AuthnContext>' +
    '</saml:AuthnStatement>' +
    '<saml:AttributeStatement>' +
      '<saml:Attribute Name="urn:oid:1.2.3">' +
        '<saml:AttributeValue>a</saml:AttributeValue>' +
      '</saml:Attribute>' +
    '</saml:AttributeStatement>' +
  '</saml:Assertion>';

function anAssertionSummaryDrawsTheRightRows() {
  log.debug("Entering anAssertionSummaryDrawsTheRightRows().");

  check('a signed SAML 2.0 assertion reports every part', function () {
    const doc = sm.parseXml(ASSERTION_20);
    const out = sm.assertionSummary(doc.documentElement);
    assert.strictEqual(out.id, '_a1');
    assert.strictEqual(out.version, '2.0');
    assert.strictEqual(out.saml1, false);
    assert.strictEqual(out.issuer, 'https://idp.example.com');
    assert.strictEqual(out.subject.value, 'bob');
    assert.strictEqual(out.confirmations.length, 1);
    assert.strictEqual(out.attributes.length, 1);
    assert.deepStrictEqual(out.statements,
        ['AuthnStatement', 'AttributeStatement']);
    assert.ok(out.signature);
    assert.strictEqual(rowValue(out.rows, 'Assertion Signature'),
        'present (enveloped)');
    assert.strictEqual(rowValue(out.rows, 'Confirmation InResponseTo'),
        '_req1');
    assert.strictEqual(rowValue(out.rows, 'Condition: AudienceRestriction'),
        'https://sp.example.com');
    assert.strictEqual(rowValue(out.rows, 'Attributes'), '1');
  });

  check('an UNSIGNED assertion says so in the same row', function () {
    const doc = sm.parseXml('<saml:Assertion ' + NS2 + ' ID="_a2" ' +
        'Version="2.0"><saml:Issuer>i</saml:Issuer></saml:Assertion>');
    const out = sm.assertionSummary(doc.documentElement);
    assert.strictEqual(out.signature, null);
    assert.ok(/carries no enveloped <ds:Signature> of its own/.test(
        rowValue(out.rows, 'Assertion Signature')),
        '"The response is signed" and "the assertion is signed" are ' +
        'different security claims, and only the second survives the ' +
        'assertion being lifted out of the response.');
  });

  check('an assertion with no statement at all is shown as such', function () {
    // Legal in 2.0, and it says nothing about anybody — worth showing rather
    // than rendering as an empty table.
    const doc = sm.parseXml('<saml:Assertion ' + NS2 + ' Version="2.0"/>');
    const out = sm.assertionSummary(doc.documentElement);
    assert.deepStrictEqual(out.statements, []);
    assert.strictEqual(rowValue(out.rows, 'Statements'), null);
  });

  check('an authorization decision is read in both spellings', function () {
    const two = sm.parseXml('<saml:Assertion ' + NS2 + ' Version="2.0">' +
      '<saml:AuthzDecisionStatement Resource="https://sp/r" Decision="Deny">' +
        '<saml:Action>GET</saml:Action><saml:Action>POST</saml:Action>' +
      '</saml:AuthzDecisionStatement></saml:Assertion>');
    const a = sm.assertionSummary(two.documentElement);
    assert.strictEqual(a.authzDecisions.length, 1);
    assert.strictEqual(a.authzDecisions[0].decision, 'Deny');
    assert.deepStrictEqual(a.authzDecisions[0].actions, ['GET', 'POST']);
    assert.strictEqual(rowValue(a.rows, 'AuthzDecision Actions'), 'GET\nPOST');

    const one = sm.parseXml('<saml:Assertion ' + NS1 + ' MajorVersion="1" ' +
        'MinorVersion="1"><saml:AuthorizationDecisionStatement ' +
        'Resource="https://sp/r" Decision="Permit">' +
        '<saml:Action>GET</saml:Action>' +
        '</saml:AuthorizationDecisionStatement></saml:Assertion>');
    const b = sm.assertionSummary(one.documentElement);
    assert.strictEqual(b.saml1, true);
    assert.strictEqual(b.authzDecisions[0].decision, 'Permit');
  });

  check('SAML 1.1 reads the issuer off an ATTRIBUTE', function () {
    const doc = sm.parseXml('<saml:Assertion ' + NS1 + ' AssertionID="_s1" ' +
        'MajorVersion="1" MinorVersion="1" Issuer="https://idp.example.com" ' +
        'IssueInstant="2026-09-01T10:00:00Z"/>');
    const out = sm.assertionSummary(doc.documentElement);
    assert.strictEqual(out.id, '_s1', 'AssertionID rather than ID.');
    assert.strictEqual(out.issuer, 'https://idp.example.com');
    assert.strictEqual(out.version, '1.1');
  });

  check('an <saml:Advice> is flagged as supporting material', function () {
    const doc = sm.parseXml('<saml:Assertion ' + NS2 + ' Version="2.0">' +
      '<saml:Advice><saml:Assertion ' + NS2 + ' ID="_inner" Version="2.0"/>' +
      '</saml:Advice></saml:Assertion>');
    const out = sm.assertionSummary(doc.documentElement);
    assert.strictEqual(out.advice, true);
    assert.ok(/a relying party may ignore them entirely/.test(
        rowValue(out.rows, 'Advice')));
  });

  check('no assertion is null rather than a throw', function () {
    assert.strictEqual(sm.assertionSummary(null), null);
  });

  log.debug("Leaving anAssertionSummaryDrawsTheRightRows().");
}

// ---------------------------------------------------------------------------
// 8. serializeSubtree() — AN ASSERTION THAT STILL VERIFIES OUT OF ITS
// DOCUMENT.
//
// A <saml:Assertion> is signed in place and then read on its own: the
// signature pane is handed the assertion, not the response around it. A
// serializer performs namespace fixup as it goes, so a prefix the subtree
// actually USES is declared for you — but a declaration that is merely IN
// SCOPE is not carried down, and there are two of those that matter. Under
// INCLUSIVE C14N the apex of a subtree carries every namespace in scope, so a
// dropped declaration changes the digest and the signature reports INVALID on
// a message that is perfectly good.
// ---------------------------------------------------------------------------
function anAssertionCarriesItsInheritedNamespaces() {
  log.debug("Entering anAssertionCarriesItsInheritedNamespaces().");

  check('a declaration inherited from the response is carried down',
      function () {
    const doc = sm.parseXml(
      '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
          'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
          'xmlns:extra="urn:example:extra">' +
        '<saml:Assertion ID="_a1"><saml:Issuer>i</saml:Issuer>' +
        '</saml:Assertion></samlp:Response>');
    const assertion = sm.tags(doc.documentElement, 'Assertion')[0];
    const xml = sm.serializeSubtree(assertion);
    assert.ok(xml.indexOf('xmlns:extra="urn:example:extra"') >= 0,
        'Nothing in the subtree USES this prefix, so no serializer emits it ' +
        '— and under inclusive C14N its absence changes the digest.');
    assert.ok(sm.parseXml(xml), 'and the fragment still parses');
  });

  check('a declaration the serializer emits itself is NOT added twice',
      function () {
    // A duplicate `xmlns:` attribute is not well-formed XML at all, so this is
    // the failure that turns a fixup into a fragment nothing can read.
    const doc = sm.parseXml(
      '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
          'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">' +
        '<saml:Assertion ID="_a1"/></samlp:Response>');
    const xml = sm.serializeSubtree(
        sm.tags(doc.documentElement, 'Assertion')[0]);
    const declarations = xml.match(/xmlns:saml=/g) || [];
    assert.strictEqual(declarations.length, 1,
        'The serializer declares saml: itself because the element uses it.');
    assert.ok(sm.parseXml(xml), 'the fragment parses');
  });

  check('a prefix used only in an ATTRIBUTE VALUE is carried down',
      function () {
    // No serializer can see one — SAML 1.1's status code is a QName and
    // `xsi:type` on an <saml:AttributeValue> is another — so the fragment
    // would otherwise name a prefix bound to nothing.
    const doc = sm.parseXml(
      '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" ' +
          'xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" ' +
          'xmlns:xs="http://www.w3.org/2001/XMLSchema">' +
        '<saml:Assertion AssertionID="_a1">' +
          '<saml:AttributeStatement><saml:Attribute AttributeName="n">' +
            '<saml:AttributeValue>v</saml:AttributeValue>' +
          '</saml:Attribute></saml:AttributeStatement>' +
        '</saml:Assertion></samlp:Response>');
    const xml = sm.serializeSubtree(
        sm.tags(doc.documentElement, 'Assertion')[0]);
    assert.ok(xml.indexOf('xmlns:xs=') >= 0);
  });

  check('usedPrefixes() ignores the xmlns declarations themselves',
      function () {
    const doc = sm.parseXml('<a:root xmlns:a="urn:a" xmlns:b="urn:b">' +
      '<a:kid b:attr="1"/></a:root>');
    const used = sm.usedPrefixes(doc.documentElement);
    assert.strictEqual(used.a, true, 'element prefixes count');
    assert.strictEqual(used.b, true, 'attribute NAME prefixes count');
    assert.strictEqual(used.xmlns, undefined,
        'A declaration is not a use, and counting it would suppress the ' +
        'carry-down of the very namespace it declares.');
  });

  check('nothing to carry down returns the plain serialization', function () {
    const doc = sm.parseXml('<saml:Assertion ' + NS2 + ' ID="_a1"/>');
    assert.strictEqual(sm.serializeSubtree(doc.documentElement),
        sm.serialize(doc.documentElement));
    assert.strictEqual(sm.serializeSubtree(null), '');
  });

  log.debug("Leaving anAssertionCarriesItsInheritedNamespaces().");
}

// ---------------------------------------------------------------------------
// 9 & 10. assertionsOf() AND summarizeResponse().
// ---------------------------------------------------------------------------

const RESPONSE_20 =
  '<samlp:Response ' + NS2 + ' ' + NSDS + ' ID="_resp1" Version="2.0" ' +
      'IssueInstant="2026-09-01T10:00:02Z" InResponseTo="_req1" ' +
      'Destination="https://sp.example.com/acs">' +
    '<saml:Issuer>https://idp.example.com</saml:Issuer>' +
    '<samlp:Status><samlp:StatusCode ' +
        'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
    ASSERTION_20 +
  '</samlp:Response>';

function everyAssertionIsFoundAndLabelled() {
  log.debug("Entering everyAssertionIsFoundAndLabelled().");

  check('plaintext, advice and encrypted assertions are told apart',
      function () {
    // WHERE an assertion sits decides what it means: one inside an
    // <saml:Advice> is supporting material rather than the subject of the
    // response, and one inside an <saml:EncryptedAssertion> cannot be read at
    // all until a key is applied.
    const doc = sm.parseXml('<samlp:Response ' + NS2 +
        ' xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Version="2.0">' +
      '<saml:Assertion ID="_main" Version="2.0">' +
        '<saml:Issuer>https://idp.example.com</saml:Issuer>' +
        '<saml:Advice><saml:Assertion ID="_adv" Version="2.0"/></saml:Advice>' +
      '</saml:Assertion>' +
      '<saml:EncryptedAssertion>' +
        '<xenc:EncryptedData>' +
          '<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/' +
              'xmlenc11#aes256-gcm"/>' +
        '</xenc:EncryptedData>' +
        '<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm=' +
            '"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>' +
        '</xenc:EncryptedKey>' +
      '</saml:EncryptedAssertion></samlp:Response>');
    const found = sm.assertionsOf(doc.documentElement);
    assert.strictEqual(found.length, 3);
    assert.deepStrictEqual(found.map(function (a) {
      return a.kind;
    }), ['assertion', 'advice', 'encrypted'],
        'Document order, with the encrypted ones after — and the ADVICE one ' +
        'labelled, because counting it as an assertion of the response is ' +
        'how a debugger reports supporting material as the answer.');
    assert.strictEqual(found[1].advice, true);
    assert.ok(/aes256-gcm$/.test(found[2].dataAlg));
    assert.ok(/rsa-oaep-mgf1p$/.test(found[2].keyAlg));
    assert.strictEqual(found[2].summary, null);
  });

  check('an assertion pasted on its own IS the message', function () {
    const doc = sm.parseXml(ASSERTION_20);
    const found = sm.assertionsOf(doc.documentElement);
    assert.strictEqual(found.length, 1);
    assert.strictEqual(found[0].kind, 'assertion');
    assert.strictEqual(found[0].summary.id, '_a1');
  });

  check('no message means no assertions', function () {
    assert.deepStrictEqual(sm.assertionsOf(null), []);
  });

  log.debug("Leaving everyAssertionIsFoundAndLabelled().");
}

function aResponseIsSummarizedInBothVersions() {
  log.debug("Entering aResponseIsSummarizedInBothVersions().");

  check('a SAML 2.0 Response reports its status, its assertion and both ' +
      'signature levels', function () {
    const out = sm.summarizeResponse(RESPONSE_20);
    assert.strictEqual(out.messageType, 'Response');
    assert.strictEqual(out.saml1, false);
    assert.strictEqual(rowValue(out.rows, 'In Response To'), '_req1');
    assert.strictEqual(rowValue(out.rows, 'Status'), 'Success');
    assert.strictEqual(out.status.success, true);
    assert.strictEqual(rowValue(out.rows, 'Assertions'), '1');
    assert.strictEqual(rowValue(out.rows, 'Encrypted assertions'), null);
    assert.ok(/no enveloped <ds:Signature> on the message itself/.test(
        rowValue(out.rows, 'Message Signature')),
        'The assertion inside IS signed, and saying only that would let a ' +
        'reader believe the status and the InResponseTo were covered too.');
    assert.ok(out.assertions[0].summary.signature,
        'the assertion signature is still reported, one level down');
  });

  check('a failure status is marked as one and carries its note', function () {
    const out = sm.summarizeResponse('<samlp:Response ' + NS2 +
        ' Version="2.0"><samlp:Status><samlp:StatusCode Value=' +
        '"urn:oasis:names:tc:SAML:2.0:status:Requester">' +
        '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:' +
        'RequestDenied"/></samlp:StatusCode></samlp:Status>' +
        '</samlp:Response>');
    assert.strictEqual(rowValue(out.rows, 'Status'),
        'Requester — NOT a success');
    assert.ok(/RequestDenied$/.test(rowValue(out.rows, 'Sub-status 1')));
  });

  check('a message with no Status at all is not a response', function () {
    const out = sm.summarizeResponse('<samlp:LogoutResponse ' + NS2 +
        ' Version="2.0"/>');
    assert.strictEqual(rowValue(out.rows, 'Status'), 'no <samlp:Status> ' +
        'element');
  });

  check('a SAML 1.1 Response reads its own spellings and BORROWS the ' +
      'assertion\'s issuer', function () {
    // On a 1.1 Browser/POST Response there is frequently no issuer on the
    // message at all — the assertion inside carries it — and an empty Issuer
    // row above a signed assertion reads as an unidentified identity provider.
    const out = sm.summarizeResponse('<samlp:Response ' + NS1 +
        ' ResponseID="_r1" MajorVersion="1" MinorVersion="1" ' +
        'Recipient="https://sp.example.com/acs" ' +
        'IssueInstant="2026-09-01T10:00:00Z">' +
      '<samlp:Status><samlp:StatusCode Value="samlp:Success"/>' +
      '</samlp:Status>' +
      '<saml:Assertion AssertionID="_a1" MajorVersion="1" MinorVersion="1" ' +
          'Issuer="https://idp.example.com"/>' +
      '</samlp:Response>');
    assert.strictEqual(out.saml1, true);
    assert.strictEqual(rowValue(out.rows, 'ID'), '_r1', 'ResponseID.');
    assert.strictEqual(rowValue(out.rows, 'Recipient'),
        'https://sp.example.com/acs', 'Recipient, which is 2.0 Destination.');
    assert.strictEqual(rowValue(out.rows, 'Issuer'),
        'https://idp.example.com');
    assert.strictEqual(out.status.success, true,
        'A QName status must be recognised as a success, or every SAML 1.1 ' +
        'sign-in is reported as a failure.');
    assert.ok(/means nothing without the namespace/.test(
        (out.rows.filter(function (r) {
          return r.key === 'Status Code (resolved)';
        })[0] || {}).note || ''));
  });

  check('an ArtifactResponse is an ENVELOPE and the inner status is the ' +
      'answer', function () {
    // Its own Status says only whether the artifact resolved. Reporting that
    // Success as the result is how a debugger reports a failed sign-in as a
    // successful one.
    const out = sm.summarizeResponse('<samlp:ArtifactResponse ' + NS2 +
        ' ID="_env" Version="2.0">' +
      '<saml:Issuer>https://idp.example.com</saml:Issuer>' +
      '<samlp:Status><samlp:StatusCode ' +
          'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>' +
      '</samlp:Status>' +
      '<samlp:Response ID="_inner" Version="2.0"><samlp:Status>' +
        '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:' +
            'Responder"/></samlp:Status></samlp:Response>' +
      '</samlp:ArtifactResponse>');
    assert.strictEqual(out.status.success, true, 'the envelope resolved');
    assert.strictEqual(rowValue(out.rows, 'Carried message'), 'Response');
    assert.ok(out.nested, 'and the message inside was summarized');
    assert.strictEqual(out.nested.status.short, 'Responder');
    assert.strictEqual(out.nested.status.success, false);
  });

  check('the envelope is unwrapped exactly ONE level', function () {
    // An envelope containing itself is a document somebody built to see what
    // would happen, so the depth is guarded rather than trusted.
    const inner = '<samlp:ArtifactResponse ' + NS2 + ' ID="_i" Version="2.0">' +
      '<samlp:Status><samlp:StatusCode Value="urn:x:Success"/>' +
      '</samlp:Status>' +
      '<samlp:Response ID="_deep" Version="2.0"/></samlp:ArtifactResponse>';
    const out = sm.summarizeResponse('<samlp:ArtifactResponse ' + NS2 +
        ' ID="_o" Version="2.0"><samlp:Status><samlp:StatusCode ' +
        'Value="urn:x:Success"/></samlp:Status>' + inner +
        '</samlp:ArtifactResponse>');
    assert.ok(out.nested, 'one level down is summarized');
    assert.strictEqual(out.nested.nested, null,
        'and it stops there rather than recursing on a document written to ' +
        'make it recurse.');
  });

  check('the envelope\'s own Issuer, Status and Signature are not mistaken ' +
      'for the carried message', function () {
    const out = sm.summarizeResponse('<samlp:ArtifactResponse ' + NS2 + ' ' +
        NSDS + ' Version="2.0">' +
      '<saml:Issuer>i</saml:Issuer><ds:Signature/>' +
      '<samlp:Extensions/>' +
      '<samlp:Status><samlp:StatusCode Value="urn:x:Success"/>' +
      '</samlp:Status>' +
      '<samlp:LogoutResponse ID="_carried" Version="2.0"/>' +
      '</samlp:ArtifactResponse>');
    assert.strictEqual(rowValue(out.rows, 'Carried message'),
        'LogoutResponse');
  });

  check('a bare assertion does not report its signature TWICE', function () {
    // When the message IS the assertion there is one signature and it is the
    // assertion's. Reporting it again as the message's would make a caller
    // check the identical bytes twice and count two, which reads as a response
    // signed at both levels — the opposite of what is in front of them.
    const out = sm.summarizeResponse(ASSERTION_20);
    assert.strictEqual(out.messageType, 'Assertion');
    assert.strictEqual(out.signature, null);
    assert.strictEqual(rowValue(out.rows, 'Message Signature'), null);
    assert.strictEqual(rowValue(out.rows, 'Status'), null,
        'and no "no <samlp:Status>" row either: an assertion is not a ' +
        'response and does not carry one.');
    assert.strictEqual(rowValue(out.rows, 'ID'), '_a1', 'from AssertionID.');
    assert.ok(out.assertions[0].summary.signature,
        'the one signature is reported once, as the assertion\'s');
  });

  check('an encrypted assertion is counted as one and reported as encrypted',
      function () {
    const out = sm.summarizeResponse('<samlp:Response ' + NS2 +
        ' xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Version="2.0">' +
      '<samlp:Status><samlp:StatusCode Value="urn:x:Success"/>' +
      '</samlp:Status>' +
      '<saml:EncryptedAssertion><xenc:EncryptedData>' +
        '<xenc:EncryptionMethod Algorithm="urn:aes"/>' +
      '</xenc:EncryptedData></saml:EncryptedAssertion></samlp:Response>');
    assert.strictEqual(rowValue(out.rows, 'Assertions'), '1');
    assert.strictEqual(rowValue(out.rows, 'Encrypted assertions'), '1');
    assert.ok(out.encrypted, 'and the document is flagged as carrying XML ' +
        'Encryption, which is what enables the decryption pane');
  });

  check('a response that is not XML is a sentence, not a throw', function () {
    const out = sm.summarizeResponse(b64('<samlp:Response/>'));
    assert.strictEqual(out.error, 'The decoded value is not well-formed XML.');
    assert.deepStrictEqual(out.assertions, []);
  });

  check('an encrypted ROOT is one row saying so', function () {
    const out = sm.summarizeResponse('<saml:EncryptedAssertion ' + NS2 +
        ' xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">' +
      '<xenc:EncryptedData><xenc:EncryptionMethod Algorithm="urn:aes"/>' +
      '</xenc:EncryptedData></saml:EncryptedAssertion>');
    assert.strictEqual(out.messageType, 'EncryptedAssertion');
    assert.strictEqual(rowValue(out.rows, 'Encryption (data)'), 'urn:aes');
    assert.ok(/Supply the recipient private key/.test(
        rowValue(out.rows, 'Status')));
  });

  log.debug("Leaving aResponseIsSummarizedInBothVersions().");
}

function test() {
  log.debug("Entering test().");
  everyPastedShapeIsClassified();
  theArtifactIsBytesAndNotAMessage();
  theRedirectOctetsAreTheOnesThatWereSent();
  aRequestIsSummarizedInBothVersions();
  theStatusIsReadInBothSpellings();
  anAssertionsPartsAreReadInBothVersions();
  anAssertionSummaryDrawsTheRightRows();
  anAssertionCarriesItsInheritedNamespaces();
  everyAssertionIsFoundAndLabelled();
  aResponseIsSummarizedInBothVersions();
  // A count, and it is asserted rather than only printed: this file needs no
  // server and no browser, so there is no legitimate reason for it to run
  // fewer checks than it has. A sudden drop means a section stopped being
  // called, which is the way a suite quietly stops testing something.
  log.info(checks + " checks passed.");
  assert.ok(checks >= 55,
      'Only ' + checks + ' checks ran and this file defines well over ' +
      'fifty. A section has stopped being called.');
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("saml_message_engine")
  .description("Drive client/src/saml_message.js in node with no server and " +
      "no browser: which binding a blob arrived on, the artifact, the " +
      "Redirect signed octets, and the request and response readers in both " +
      "protocol versions.")
  // Accepted and ignored: run-report.js passes --url to every job, and
  // commander exits 1 on an option it has not been told about.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

try {
  test();
} catch (e) {
  log.error(e.stack || e.message);
  process.exit(1);
}
