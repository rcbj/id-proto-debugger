// File: x509.js
//
// ---------------------------------------------------------------------------
// X.509 certificates: authoring one, describing one, and checking a chain.
//
// This is the protocol half of the PKI workflow (client/public/pki.html) and it
// has NO DOM in it, which is the point: the whole matrix — every key algorithm
// against every signature algorithm, every extension, a four-deep chain — is
// driven from node by tests/pki_x509.js and checked against OpenSSL, which is
// the only way "every combination" can mean anything. A page that built its
// certificates inside its own event handlers could only ever be tested one
// click at a time.
//
// Keys are client/src/key_material.js's job and stay there; this module takes
// PEM in and gives DER/PEM out. The dependency runs one way only.
//
// ---------------------------------------------------------------------------
// THREE THINGS THAT ARE NOT OBVIOUS AND COST TIME IF REDISCOVERED
//
//   * **pkijs cannot import an Ed25519 public key and cannot sign with one.**
//     `subjectPublicKeyInfo.importKey()` throws "Error during exporting public
//     key: Incorrect key data" and `cert.sign()` never gets that far. Both are
//     avoidable: an SPKI is already the exact DER that field holds, so it is
//     parsed in with `fromSchema()` for EVERY algorithm rather than only for
//     the one that needs it (one path, so the odd one out is not the untested
//     one), and Ed25519 signing is done by hand — set both
//     AlgorithmIdentifiers
//     to 1.3.101.112, encode the TBS, sign it with Web Crypto, drop the result
//     in as the BIT STRING. OpenSSL verifies the result.
//
//   * **The hash a key was IMPORTED with is the hash that ends up in the
//     certificate.** pkijs reads `privateKey.algorithm` to build the
//     signatureAlgorithm field, so importing an RSA key as SHA-256 and then
//     asking `sign()` for SHA-512 produces a certificate whose declared
//     algorithm and actual signature disagree. Every path here imports the
//     issuer key with the descriptor of the SIGNATURE algorithm chosen, not
//     with the descriptor of the key. `openssl verify` is what catches getting
//     this wrong, and it reports it as a bad signature — naming neither hash.
//
//   * **A DN attribute's string type is part of interoperability, not taste.**
//     `C` must be PrintableString, `emailAddress` and `domainComponent` must be
//     IA5String, and everything else is UTF8String here. Encoding a country as
//     UTF8String produces a certificate that parses perfectly and that several
//     validators refuse, which reads as a signature problem.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var jose = require("./jose_jwe");
var keys = require("./key_material");
var pkijs = require("pkijs");
var asn1js = require("asn1js");

var log = bunyan.createLogger({
  name: "x509",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var derToPem = jose.derToPem;
var pemToDer = jose.pemToDer;

// ---------------------------------------------------------------------------
// Signature algorithms — the issuer's key type crossed with a digest.
//
// `kind` names the key family the SIGNER must have, so a page can offer only
// the algorithms a chosen CA key can actually produce. The two SHA-1 entries
// are deliberate and marked `weak`: this is a debugger, and "does my TLS stack
// refuse a SHA-1 certificate?" is a question it should be able to ask. Nothing
// defaults to them.
// ---------------------------------------------------------------------------
var SIG_ALGS = {
  'sha256-rsa': { kind: 'rsa', hash: 'SHA-256', pss: false,
                 label: 'RSASSA-PKCS1-v1_5 with SHA-256' },
  'sha384-rsa': { kind: 'rsa', hash: 'SHA-384', pss: false,
                 label: 'RSASSA-PKCS1-v1_5 with SHA-384' },
  'sha512-rsa': { kind: 'rsa', hash: 'SHA-512', pss: false,
                 label: 'RSASSA-PKCS1-v1_5 with SHA-512' },
  'sha1-rsa': { kind: 'rsa', hash: 'SHA-1', pss: false, weak: true,
               label: 'RSASSA-PKCS1-v1_5 with SHA-1 (legacy, weak)' },
  'sha256-rsapss': { kind: 'rsa', hash: 'SHA-256', pss: true,
                    label: 'RSASSA-PSS with SHA-256' },
  'sha384-rsapss': { kind: 'rsa', hash: 'SHA-384', pss: true,
                    label: 'RSASSA-PSS with SHA-384' },
  'sha512-rsapss': { kind: 'rsa', hash: 'SHA-512', pss: true,
                    label: 'RSASSA-PSS with SHA-512' },
  'sha256-ecdsa': { kind: 'ec', hash: 'SHA-256',
                   label: 'ECDSA with SHA-256' },
  'sha384-ecdsa': { kind: 'ec', hash: 'SHA-384',
                   label: 'ECDSA with SHA-384' },
  'sha512-ecdsa': { kind: 'ec', hash: 'SHA-512',
                   label: 'ECDSA with SHA-512' },
  'sha1-ecdsa': { kind: 'ec', hash: 'SHA-1', weak: true,
                 label: 'ECDSA with SHA-1 (legacy, weak)' },
  'ed25519': { kind: 'okp', name: 'Ed25519', label: 'Ed25519 (EdDSA)' }
};

var SIG_ALG_ORDER = ['sha256-rsa', 'sha384-rsa', 'sha512-rsa',
                     'sha256-rsapss', 'sha384-rsapss', 'sha512-rsapss',
                     'sha1-rsa', 'sha256-ecdsa', 'sha384-ecdsa',
                     'sha512-ecdsa', 'sha1-ecdsa', 'ed25519'];

var ED25519_OID = '1.3.101.112';

function sigAlg(id) {
  log.debug("Entering sigAlg(). id=" + id);
  var found = SIG_ALGS[String(id || '').toLowerCase()];
  log.debug("Leaving sigAlg().");
  return found ? Object.assign({ id: String(id).toLowerCase() }, found) : null;
}

// Which signature algorithms a key of this family can produce. A page calls
// this when the CA key changes: offering ECDSA against an RSA key produces a
// Web Crypto error about key usage, which names neither.
function signatureAlgorithmsFor(keyKindOrDesc) {
  log.debug("Entering signatureAlgorithmsFor().");
  var kind = typeof keyKindOrDesc === 'string'
    ? keyKindOrDesc
    : (keyKindOrDesc || {}).kind;
  var out = SIG_ALG_ORDER.filter(function (id) {
    return SIG_ALGS[id].kind === kind;
  });
  log.debug("Leaving signatureAlgorithmsFor(). " + out.length + " of them.");
  return out;
}

// The default signature algorithm for a key — the strongest non-weak one its
// family has at the digest size that matches it.
function defaultSignatureAlgorithm(desc) {
  log.debug("Entering defaultSignatureAlgorithm().");
  var kind = (desc || {}).kind;
  if (kind === 'okp') {
    log.debug("Leaving defaultSignatureAlgorithm().");
    return 'ed25519';
  }
  if (kind === 'ec') {
    var byCurve = { 'P-256': 'sha256-ecdsa', 'P-384': 'sha384-ecdsa',
                   'P-521': 'sha512-ecdsa' };
    log.debug("Leaving defaultSignatureAlgorithm().");
    return byCurve[desc.curve] || 'sha256-ecdsa';
  }
  log.debug("Leaving defaultSignatureAlgorithm().");
  return 'sha256-rsa';
}

// The descriptor to import the ISSUER's private key with, for this signature
// algorithm. See the header: this is the hash that lands in the certificate.
function signerDescriptor(sig, keyDesc) {
  log.debug("Entering signerDescriptor().");
  var out;
  if (sig.kind === 'rsa') {
    out = { kind: 'rsa', hash: sig.hash, pss: !!sig.pss };
  } else if (sig.kind === 'okp') {
    out = { kind: 'okp', name: sig.name || 'Ed25519' };
  } else {
    out = { kind: 'ec', curve: (keyDesc || {}).curve || 'P-256',
            hash: sig.hash };
  }
  log.debug("Leaving signerDescriptor().");
  return out;
}

// ---------------------------------------------------------------------------
// Distinguished names
//
// Every attribute a page offers, with the OID and the ASN.1 string type each
// one is supposed to use. `type` is the asn1js class name rather than the class
// itself so this table stays data.
// ---------------------------------------------------------------------------
var DN_ATTRS = {
  CN: { oid: '2.5.4.3', type: 'utf8', label: 'Common Name' },
  SN: { oid: '2.5.4.4', type: 'utf8', label: 'Surname' },
  serialNumber: { oid: '2.5.4.5', type: 'printable',
                 label: 'Serial Number (DN)' },
  C: { oid: '2.5.4.6', type: 'printable', label: 'Country' },
  L: { oid: '2.5.4.7', type: 'utf8', label: 'Locality' },
  ST: { oid: '2.5.4.8', type: 'utf8', label: 'State or Province' },
  STREET: { oid: '2.5.4.9', type: 'utf8', label: 'Street Address' },
  O: { oid: '2.5.4.10', type: 'utf8', label: 'Organization' },
  OU: { oid: '2.5.4.11', type: 'utf8', label: 'Organizational Unit' },
  title: { oid: '2.5.4.12', type: 'utf8', label: 'Title' },
  description: { oid: '2.5.4.13', type: 'utf8', label: 'Description' },
  businessCategory: { oid: '2.5.4.15', type: 'utf8',
                     label: 'Business Category' },
  postalCode: { oid: '2.5.4.17', type: 'utf8', label: 'Postal Code' },
  GN: { oid: '2.5.4.42', type: 'utf8', label: 'Given Name' },
  initials: { oid: '2.5.4.43', type: 'utf8', label: 'Initials' },
  generationQualifier: { oid: '2.5.4.44', type: 'utf8',
                        label: 'Generation Qualifier' },
  dnQualifier: { oid: '2.5.4.46', type: 'printable',
                label: 'DN Qualifier' },
  pseudonym: { oid: '2.5.4.65', type: 'utf8', label: 'Pseudonym' },
  DC: { oid: '0.9.2342.19200300.100.1.25', type: 'ia5',
       label: 'Domain Component' },
  UID: { oid: '0.9.2342.19200300.100.1.1', type: 'utf8', label: 'User ID' },
  emailAddress: { oid: '1.2.840.113549.1.9.1', type: 'ia5',
                 label: 'Email Address' },
  jurisdictionC: { oid: '1.3.6.1.4.1.311.60.2.1.3', type: 'printable',
                  label: 'Jurisdiction Country (EV)' },
  jurisdictionST: { oid: '1.3.6.1.4.1.311.60.2.1.2', type: 'utf8',
                   label: 'Jurisdiction State (EV)' },
  jurisdictionL: { oid: '1.3.6.1.4.1.311.60.2.1.1', type: 'utf8',
                  label: 'Jurisdiction Locality (EV)' }
};

// Reverse lookup, so a parsed certificate's OIDs come back as names.
var DN_BY_OID = (function buildDnByOid() {
  var out = {};
  Object.keys(DN_ATTRS).forEach(function (name) {
    out[DN_ATTRS[name].oid] = name;
  });
  return out;
})();

function asn1String(type, value) {
  log.debug("Entering asn1String().");
  if (type === 'printable') {
    log.debug("Leaving asn1String(). PrintableString.");
    return new asn1js.PrintableString({ value: value });
  }
  if (type === 'ia5') {
    log.debug("Leaving asn1String(). IA5String.");
    return new asn1js.IA5String({ value: value });
  }
  log.debug("Leaving asn1String(). Utf8String.");
  return new asn1js.Utf8String({ value: value });
}

// Build the RDN sequence from a list of {name|oid, value} in the order given —
// the order IS the DN, and reordering it produces a different name that chains
// to nothing.
// A Name is an RDNSequence: a SEQUENCE of SETs, ONE SET PER ATTRIBUTE. pkijs's
// RelativeDistinguishedNames builds a single SET holding every attribute
// instead — a multi-valued RDN — and that is a different name: OpenSSL renders
// it "CN = localhost + O = Example + C = US", the `+` being the tell, and a
// certificate whose issuer field is a multi-valued RDN chains to nothing
// because the CA's own subject is the ordinary kind. jwt_tools.js never saw it,
// having only ever put a CN in.
//
// So the DER is built here and handed to pkijs as a parsed schema: its
// toSchema() returns `valueBeforeDecode` verbatim when it has one, which makes
// that the supported way to keep an encoding it would not have chosen.
function buildDn(attributes) {
  log.debug("Entering buildDn().");
  var rdns = [];
  (attributes || []).forEach(function (attr) {
    if (!attr || attr.value === undefined || attr.value === null ||
        String(attr.value) === '') return;
    var known = DN_ATTRS[attr.name];
    var oid = attr.oid || (known && known.oid);
    if (!oid) throw new Error('Unknown DN attribute: ' + attr.name);
    var type = attr.type || (known && known.type) || 'utf8';
    rdns.push(new asn1js.Set({ value: [
      new asn1js.Sequence({ value: [
        new asn1js.ObjectIdentifier({ value: oid }),
        asn1String(type, String(attr.value))
      ] })
    ] }));
  });
  var seq = new asn1js.Sequence({ value: rdns });
  var parsed = asn1js.fromBER(seq.toBER(false));
  log.debug("Leaving buildDn(). " + rdns.length + " attribute(s).");
  return new pkijs.RelativeDistinguishedNames({ schema: parsed.result });
}

// An RDN sequence as the one-line string every UI and log shows.
function dnToString(rdn) {
  log.debug("Entering dnToString().");
  var parts = ((rdn && rdn.typesAndValues) || []).map(function (tv) {
    var name = DN_BY_OID[tv.type] || tv.type;
    return name + '=' + (tv.value.valueBlock.value !== undefined
      ? tv.value.valueBlock.value
      : String(tv.value.valueBlock.toString()));
  });
  log.debug("Leaving dnToString().");
  return parts.join(', ');
}

// "CN=Example Root CA, O=Example, C=US" -> the attribute list buildDn() takes.
// Written because a stored CA keeps its subject as a string and the page has to
// be able to re-issue against it without the operator retyping the fields.
function parseDnString(text) {
  log.debug("Entering parseDnString().");
  var out = [];
  String(text || '').split(/,(?![^(]*\))/).forEach(function (piece) {
    var trimmed = piece.trim();
    if (!trimmed) return;
    var eq = trimmed.indexOf('=');
    if (eq < 0) return;
    var name = trimmed.slice(0, eq).trim();
    var value = trimmed.slice(eq + 1).trim();
    if (DN_ATTRS[name]) {
      out.push({ name: name, value: value });
    } else if (/^[0-9]+(\.[0-9]+)+$/.test(name)) {
      out.push({ oid: name, value: value });
    }
  });
  log.debug("Leaving parseDnString(). " + out.length + " attribute(s).");
  return out;
}

// ---------------------------------------------------------------------------
// General names — the value type behind subjectAltName, issuerAltName, the CRL
// distribution points, the AIA locations and the name constraints.
// ---------------------------------------------------------------------------
var GN_TYPES = {
  otherName: 0,
  email: 1,
  dns: 2,
  x400: 3,
  dirName: 4,
  ediParty: 5,
  uri: 6,
  ip: 7,
  registeredID: 8
};

// Microsoft's userPrincipalName, and the Kerberos principal from RFC 4556 —
// the two otherNames anybody actually asks for, offered by name so nobody has
// to hand-encode them.
var OTHERNAME_UPN = '1.3.6.1.4.1.311.20.2.3';
var OTHERNAME_KRB5 = '1.3.6.1.5.2.2';

function ipv4Bytes(text) {
  log.debug("Entering ipv4Bytes().");
  var parts = String(text).split('.');
  if (parts.length !== 4) {
    log.debug("Leaving ipv4Bytes(). Not four octets.");
    return null;
  }
  var out = new Uint8Array(4);
  for (var i = 0; i < 4; i++) {
    var n = parseInt(parts[i], 10);
    if (!(n >= 0 && n <= 255) || String(n) !== parts[i].replace(/^0+(?=\d)/,
        '')) {
      log.debug("Leaving ipv4Bytes(). Octet out of range.");
      return null;
    }
    out[i] = n;
  }
  log.debug("Leaving ipv4Bytes().");
  return out;
}

function ipv6Bytes(text) {
  log.debug("Entering ipv6Bytes().");
  var s = String(text);
  if (s.indexOf(':') < 0) {
    log.debug("Leaving ipv6Bytes(). Not an IPv6 literal.");
    return null;
  }
  var halves = s.split('::');
  if (halves.length > 2) {
    log.debug("Leaving ipv6Bytes(). More than one '::'.");
    return null;
  }
  function groups(part) {
    log.debug("Entering groups().");
    var list = part ? part.split(':').filter(function (g) { return g !== ''; })
                    : [];
    log.debug("Leaving groups().");
    return list;
  }
  var head = groups(halves[0]);
  var tail = halves.length === 2 ? groups(halves[1]) : [];
  if (halves.length === 1 && head.length !== 8) {
    log.debug("Leaving ipv6Bytes(). Wrong group count.");
    return null;
  }
  var fill = 8 - head.length - tail.length;
  if (fill < 0) {
    log.debug("Leaving ipv6Bytes(). Too many groups.");
    return null;
  }
  var all = head.concat(new Array(halves.length === 2 ? fill : 0).fill('0'))
                .concat(tail);
  var out = new Uint8Array(16);
  for (var i = 0; i < 8; i++) {
    var v = parseInt(all[i], 16);
    if (isNaN(v) || v < 0 || v > 65535) {
      log.debug("Leaving ipv6Bytes(). Bad group.");
      return null;
    }
    out[i * 2] = (v >> 8) & 0xff;
    out[i * 2 + 1] = v & 0xff;
  }
  log.debug("Leaving ipv6Bytes().");
  return out;
}

function ipBytes(text) {
  log.debug("Entering ipBytes().");
  var v4 = ipv4Bytes(text);
  if (v4) {
    log.debug("Leaving ipBytes(). IPv4.");
    return v4;
  }
  var v6 = ipv6Bytes(text);
  if (v6) {
    log.debug("Leaving ipBytes(). IPv6.");
    return v6;
  }
  log.debug("Leaving ipBytes(). Neither.");
  throw new Error('Not an IP address: ' + text);
}

// An IP name constraint is the address FOLLOWED BY ITS MASK — 8 bytes for v4,
// 32 for v6 — which is the one place a general name's iPAddress is not just an
// address, and encoding it as one silently constrains nothing.
function ipConstraintBytes(text) {
  log.debug("Entering ipConstraintBytes().");
  var slash = String(text).indexOf('/');
  var addrText = slash < 0 ? String(text) : String(text).slice(0, slash);
  var prefix = slash < 0 ? null : parseInt(String(text).slice(slash + 1), 10);
  var addr = ipBytes(addrText);
  var bits = addr.length * 8;
  if (prefix === null) prefix = bits;
  if (!(prefix >= 0 && prefix <= bits)) {
    log.debug("Leaving ipConstraintBytes(). Prefix out of range.");
    throw new Error('Prefix length out of range for ' + text);
  }
  var out = new Uint8Array(addr.length * 2);
  out.set(addr, 0);
  for (var i = 0; i < addr.length; i++) {
    var take = Math.min(8, Math.max(0, prefix - i * 8));
    out[addr.length + i] = take === 0 ? 0 : (0xff << (8 - take)) & 0xff;
  }
  log.debug("Leaving ipConstraintBytes().");
  return out;
}

// `spec` is {kind, value} where kind is a GN_TYPES name, 'upn', 'krb5' or
// 'otherName' (with `oid` and base64 DER `value`).
function buildGeneralName(spec, options) {
  log.debug("Entering buildGeneralName(). kind=" + (spec || {}).kind);
  var opts = options || {};
  var kind = (spec || {}).kind;
  var value = (spec || {}).value;
  if (kind === 'dns' || kind === 'email' || kind === 'uri') {
    log.debug("Leaving buildGeneralName(). " + kind);
    return new pkijs.GeneralName({ type: GN_TYPES[kind],
        value: String(value) });
  }
  if (kind === 'ip') {
    var bytes = opts.constraint ? ipConstraintBytes(value) : ipBytes(value);
    log.debug("Leaving buildGeneralName(). ip");
    return new pkijs.GeneralName({ type: GN_TYPES.ip,
        value: new asn1js.OctetString({ valueHex: bytes.buffer.slice(
            bytes.byteOffset, bytes.byteOffset + bytes.byteLength) }) });
  }
  if (kind === 'dirName') {
    log.debug("Leaving buildGeneralName(). dirName");
    return new pkijs.GeneralName({ type: GN_TYPES.dirName,
        value: buildDn(parseDnString(value)) });
  }
  if (kind === 'registeredID') {
    log.debug("Leaving buildGeneralName(). registeredID");
    return new pkijs.GeneralName({ type: GN_TYPES.registeredID,
        value: String(value) });
  }
  if (kind === 'upn' || kind === 'krb5' || kind === 'otherName') {
    log.debug("Leaving buildGeneralName(). otherName");
    return otherNameGeneralName(spec);
  }
  log.debug("Leaving buildGeneralName(). Unknown kind.");
  throw new Error('Unknown general name kind: ' + kind);
}

// An otherName cannot go through pkijs.GeneralName, and the failure is quiet.
//
// GeneralName's otherName is `[0] IMPLICIT OtherName`, so the [0] tag REPLACES
// the SEQUENCE tag and the OID and the [0] EXPLICIT value sit directly inside
// it. pkijs's toSchema() for type 0 wraps whatever it is given in a further
// [0], which produces a name that parses, displays plausibly in `openssl x509
// -text`, and makes OpenSSL refuse the whole certificate at verification time
// with `ossl_x509v3_cache_extensions:reason(158)` — an error naming no
// extension, no name and no field. So the DER is built here, and returned as a
// duck-typed object with the toSchema() its callers use: everything that holds
// general names asks for exactly that method.
function otherNameGeneralName(spec) {
  log.debug("Entering otherNameGeneralName(). kind=" + spec.kind);
  var oid = spec.kind === 'upn' ? OTHERNAME_UPN
    : spec.kind === 'krb5' ? OTHERNAME_KRB5
      : String(spec.oid || '');
  if (!oid) {
    log.debug("Leaving otherNameGeneralName(). No OID.");
    throw new Error('An otherName needs an OID.');
  }
  var inner;
  if (spec.kind === 'otherName') {
    // Raw DER, base64, so any otherName at all can be written.
    inner = derFromBase64(spec.value, 'otherName ' + oid);
  } else {
    inner = new asn1js.Utf8String({ value: String(spec.value) });
  }
  var asn1 = new asn1js.Constructed({
    idBlock: { tagClass: 3, tagNumber: GN_TYPES.otherName },
    value: [
      new asn1js.ObjectIdentifier({ value: oid }),
      new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 },
          value: [inner] })
    ]
  });
  log.debug("Leaving otherNameGeneralName(). " + oid);
  return { otherName: true, oid: oid, toSchema: function () {
    log.debug("Entering toSchema().");
    log.debug("Leaving toSchema().");
    return asn1;
  } };
}

// ---------------------------------------------------------------------------
// Extensions
// ---------------------------------------------------------------------------
var EXT_OIDS = {
  subjectKeyIdentifier: '2.5.29.14',
  keyUsage: '2.5.29.15',
  privateKeyUsagePeriod: '2.5.29.16',
  subjectAltName: '2.5.29.17',
  issuerAltName: '2.5.29.18',
  basicConstraints: '2.5.29.19',
  nameConstraints: '2.5.29.30',
  cRLDistributionPoints: '2.5.29.31',
  certificatePolicies: '2.5.29.32',
  policyMappings: '2.5.29.33',
  authorityKeyIdentifier: '2.5.29.35',
  policyConstraints: '2.5.29.36',
  extKeyUsage: '2.5.29.37',
  freshestCRL: '2.5.29.46',
  inhibitAnyPolicy: '2.5.29.54',
  authorityInfoAccess: '1.3.6.1.5.5.7.1.1',
  subjectInfoAccess: '1.3.6.1.5.5.7.1.11',
  tlsFeature: '1.3.6.1.5.5.7.1.24',
  ocspNoCheck: '1.3.6.1.5.5.7.48.1.5',
  netscapeCertType: '2.16.840.1.113730.1.1',
  netscapeComment: '2.16.840.1.113730.1.13'
};

var EXT_BY_OID = (function buildExtByOid() {
  var out = {};
  Object.keys(EXT_OIDS).forEach(function (name) {
    out[EXT_OIDS[name]] = name;
  });
  return out;
})();

// KeyUsage, in the bit order RFC 5280 section 4.2.1.3 gives — bit 0 is the
// MOST significant bit of the first byte, which is why this is a table and not
// a shift.
var KEY_USAGE_BITS = [
  { name: 'digitalSignature', bit: 0 },
  { name: 'nonRepudiation', bit: 1 },
  { name: 'keyEncipherment', bit: 2 },
  { name: 'dataEncipherment', bit: 3 },
  { name: 'keyAgreement', bit: 4 },
  { name: 'keyCertSign', bit: 5 },
  { name: 'cRLSign', bit: 6 },
  { name: 'encipherOnly', bit: 7 },
  { name: 'decipherOnly', bit: 8 }
];

// Extended key usages, by the name a page shows.
var EKU_OIDS = {
  serverAuth: '1.3.6.1.5.5.7.3.1',
  clientAuth: '1.3.6.1.5.5.7.3.2',
  codeSigning: '1.3.6.1.5.5.7.3.3',
  emailProtection: '1.3.6.1.5.5.7.3.4',
  ipsecEndSystem: '1.3.6.1.5.5.7.3.5',
  ipsecTunnel: '1.3.6.1.5.5.7.3.6',
  ipsecUser: '1.3.6.1.5.5.7.3.7',
  timeStamping: '1.3.6.1.5.5.7.3.8',
  ocspSigning: '1.3.6.1.5.5.7.3.9',
  ipsecIKE: '1.3.6.1.5.5.7.3.17',
  anyExtendedKeyUsage: '2.5.29.37.0',
  msSmartcardLogon: '1.3.6.1.4.1.311.20.2.2',
  msDocumentSigning: '1.3.6.1.4.1.311.10.3.12',
  msEncryptingFileSystem: '1.3.6.1.4.1.311.10.3.4',
  kdcAuthentication: '1.3.6.1.5.2.3.5',
  pkinitClientAuth: '1.3.6.1.5.2.3.4'
};

var EKU_BY_OID = (function buildEkuByOid() {
  var out = {};
  Object.keys(EKU_OIDS).forEach(function (name) {
    out[EKU_OIDS[name]] = name;
  });
  return out;
})();

// Netscape cert-type bits, kept for the same reason SHA-1 is: somebody's old
// appliance still reads them, and this tool is where you find that out.
var NS_CERT_TYPE_BITS = [
  { name: 'sslClient', bit: 0 },
  { name: 'sslServer', bit: 1 },
  { name: 'sslCA', bit: 5 },
  { name: 'emailCA', bit: 6 },
  { name: 'objectSigningCA', bit: 7 }
];

function bitStringFor(bits, table) {
  log.debug("Entering bitStringFor().");
  var wanted = (bits || []).map(function (b) { return String(b); });
  var numbers = table.filter(function (entry) {
    return wanted.indexOf(entry.name) >= 0;
  }).map(function (entry) { return entry.bit; });
  if (!numbers.length) {
    log.debug("Leaving bitStringFor(). Nothing set.");
    return null;
  }
  var highest = Math.max.apply(null, numbers);
  var byteCount = Math.floor(highest / 8) + 1;
  var bytes = new Uint8Array(byteCount);
  numbers.forEach(function (bit) {
    bytes[Math.floor(bit / 8)] |= 0x80 >> (bit % 8);
  });
  var unused = (byteCount * 8) - (highest + 1);
  log.debug("Leaving bitStringFor().");
  return { bytes: bytes, unusedBits: unused };
}

function extension(oid, critical, valueAsn1) {
  log.debug("Entering extension(). oid=" + oid);
  var ext = new pkijs.Extension({
    extnID: oid,
    critical: !!critical,
    extnValue: new asn1js.OctetString({
        valueHex: valueAsn1.toBER(false) }).valueBlock.valueHexView
  });
  log.debug("Leaving extension().");
  return ext;
}

// The SHA-1 of the subjectPublicKey BIT STRING's contents — RFC 5280 section
// 4.2.1.2's method (1), which is what every other implementation computes, so
// key identifiers match across tools.
async function keyIdentifier(spkiDer) {
  log.debug("Entering keyIdentifier().");
  var spki = pkijs.PublicKeyInfo.fromBER(spkiDer);
  var bits = spki.subjectPublicKey.valueBlock.valueHexView;
  var digest = await crypto.subtle.digest('SHA-1', bits);
  log.debug("Leaving keyIdentifier().");
  return new Uint8Array(digest);
}

function buildBasicConstraints(spec) {
  log.debug("Entering buildBasicConstraints().");
  var bc = new pkijs.BasicConstraints({ cA: !!spec.ca });
  if (spec.ca && spec.pathLen !== undefined && spec.pathLen !== null &&
      spec.pathLen !== '') {
    bc.pathLenConstraint = parseInt(spec.pathLen, 10);
  }
  log.debug("Leaving buildBasicConstraints().");
  // RFC 5280: this extension MUST be critical in a CA certificate.
  return extension(EXT_OIDS.basicConstraints,
      spec.critical === undefined ? !!spec.ca : !!spec.critical,
      bc.toSchema());
}

function buildKeyUsage(spec) {
  log.debug("Entering buildKeyUsage().");
  var built = bitStringFor(spec.usages, KEY_USAGE_BITS);
  if (!built) {
    log.debug("Leaving buildKeyUsage(). No bits set.");
    return null;
  }
  var bitString = new asn1js.BitString({
    unusedBits: built.unusedBits,
    valueHex: built.bytes.buffer.slice(built.bytes.byteOffset,
        built.bytes.byteOffset + built.bytes.byteLength)
  });
  log.debug("Leaving buildKeyUsage().");
  return extension(EXT_OIDS.keyUsage,
      spec.critical === undefined ? true : !!spec.critical, bitString);
}

function buildExtKeyUsage(spec) {
  log.debug("Entering buildExtKeyUsage().");
  var oids = (spec.usages || []).map(function (usage) {
    return EKU_OIDS[usage] || usage;
  }).filter(Boolean);
  if (!oids.length) {
    log.debug("Leaving buildExtKeyUsage(). None.");
    return null;
  }
  var eku = new pkijs.ExtKeyUsage({ keyPurposes: oids });
  log.debug("Leaving buildExtKeyUsage().");
  return extension(EXT_OIDS.extKeyUsage, !!spec.critical, eku.toSchema());
}

function buildAltName(oid, spec) {
  log.debug("Entering buildAltName(). oid=" + oid);
  var names = (spec.names || []).map(function (name) {
    return buildGeneralName(name).toSchema();
  });
  if (!names.length) {
    log.debug("Leaving buildAltName(). No names.");
    return null;
  }
  // GeneralNames is a plain SEQUENCE OF GeneralName, emitted here rather than
  // through pkijs.GeneralNames so that otherNameGeneralName()'s hand-built DER
  // is accepted alongside the pkijs ones.
  log.debug("Leaving buildAltName().");
  return extension(oid, !!spec.critical,
      new asn1js.Sequence({ value: names }));
}

function buildCrlDistributionPoints(oid, spec) {
  log.debug("Entering buildCrlDistributionPoints().");
  var points = (spec.urls || []).map(function (url) {
    return new pkijs.DistributionPoint({
      distributionPoint: [new pkijs.GeneralName({ type: GN_TYPES.uri,
          value: String(url) })]
    });
  });
  if (!points.length) {
    log.debug("Leaving buildCrlDistributionPoints(). None.");
    return null;
  }
  var cdp = new pkijs.CRLDistributionPoints({ distributionPoints: points });
  log.debug("Leaving buildCrlDistributionPoints().");
  return extension(oid, !!spec.critical, cdp.toSchema());
}

// Authority / subject information access. `entries` is
// [{method:'ocsp'|'caIssuers'|oid, url}].
var AIA_METHODS = {
  ocsp: '1.3.6.1.5.5.7.48.1',
  caIssuers: '1.3.6.1.5.5.7.48.2',
  timeStamping: '1.3.6.1.5.5.7.48.3',
  caRepository: '1.3.6.1.5.5.7.48.5'
};

var AIA_BY_OID = (function buildAiaByOid() {
  var out = {};
  Object.keys(AIA_METHODS).forEach(function (name) {
    out[AIA_METHODS[name]] = name;
  });
  return out;
})();

function buildInfoAccess(oid, spec) {
  log.debug("Entering buildInfoAccess().");
  var descriptions = (spec.entries || []).map(function (entry) {
    return new pkijs.AccessDescription({
      accessMethod: AIA_METHODS[entry.method] || entry.method,
      accessLocation: new pkijs.GeneralName({ type: GN_TYPES.uri,
          value: String(entry.url) })
    });
  });
  if (!descriptions.length) {
    log.debug("Leaving buildInfoAccess(). None.");
    return null;
  }
  var access = new pkijs.InfoAccess({ accessDescriptions: descriptions });
  log.debug("Leaving buildInfoAccess().");
  return extension(oid, !!spec.critical, access.toSchema());
}

// certificatePolicies, with the two qualifiers RFC 5280 defines: a CPS URI and
// a user notice.
function buildCertificatePolicies(spec) {
  log.debug("Entering buildCertificatePolicies().");
  var infos = (spec.policies || []).map(function (policy) {
    var qualifiers = [];
    if (policy.cps) {
      qualifiers.push(new pkijs.PolicyQualifierInfo({
        policyQualifierId: '1.3.6.1.5.5.7.2.1',
        qualifier: new asn1js.IA5String({ value: String(policy.cps) })
      }));
    }
    if (policy.notice) {
      qualifiers.push(new pkijs.PolicyQualifierInfo({
        policyQualifierId: '1.3.6.1.5.5.7.2.2',
        qualifier: new asn1js.Sequence({ value: [
          new asn1js.Utf8String({ value: String(policy.notice) })
        ] })
      }));
    }
    var info = new pkijs.PolicyInformation({
        policyIdentifier: String(policy.oid) });
    if (qualifiers.length) info.policyQualifiers = qualifiers;
    return info;
  });
  if (!infos.length) {
    log.debug("Leaving buildCertificatePolicies(). None.");
    return null;
  }
  var policies = new pkijs.CertificatePolicies({ certificatePolicies: infos });
  log.debug("Leaving buildCertificatePolicies().");
  return extension(EXT_OIDS.certificatePolicies, !!spec.critical,
      policies.toSchema());
}

function buildPolicyMappings(spec) {
  log.debug("Entering buildPolicyMappings().");
  var mappings = (spec.mappings || []).map(function (mapping) {
    return new pkijs.PolicyMapping({
      issuerDomainPolicy: String(mapping.issuer),
      subjectDomainPolicy: String(mapping.subject)
    });
  });
  if (!mappings.length) {
    log.debug("Leaving buildPolicyMappings(). None.");
    return null;
  }
  var ext = new pkijs.PolicyMappings({ mappings: mappings });
  log.debug("Leaving buildPolicyMappings().");
  // RFC 5280 says this one SHOULD be critical.
  return extension(EXT_OIDS.policyMappings,
      spec.critical === undefined ? true : !!spec.critical, ext.toSchema());
}

function buildPolicyConstraints(spec) {
  log.debug("Entering buildPolicyConstraints().");
  var has = false;
  var pc = new pkijs.PolicyConstraints();
  var explicit = spec.requireExplicitPolicy;
  if (explicit !== undefined && explicit !== null && explicit !== '') {
    pc.requireExplicitPolicy = parseInt(spec.requireExplicitPolicy, 10);
    has = true;
  }
  if (spec.inhibitPolicyMapping !== undefined &&
      spec.inhibitPolicyMapping !== null && spec.inhibitPolicyMapping !== '') {
    pc.inhibitPolicyMapping = parseInt(spec.inhibitPolicyMapping, 10);
    has = true;
  }
  if (!has) {
    log.debug("Leaving buildPolicyConstraints(). Neither field set.");
    return null;
  }
  log.debug("Leaving buildPolicyConstraints().");
  return extension(EXT_OIDS.policyConstraints,
      spec.critical === undefined ? true : !!spec.critical, pc.toSchema());
}

function buildNameConstraints(spec) {
  log.debug("Entering buildNameConstraints().");
  function subtrees(list) {
    log.debug("Entering subtrees().");
    var out = (list || []).map(function (entry) {
      var tree = new pkijs.GeneralSubtree({
          base: buildGeneralName(entry, { constraint: true }) });
      if (entry.minimum !== undefined && entry.minimum !== null &&
          entry.minimum !== '') {
        tree.minimum = parseInt(entry.minimum, 10);
      }
      if (entry.maximum !== undefined && entry.maximum !== null &&
          entry.maximum !== '') {
        tree.maximum = parseInt(entry.maximum, 10);
      }
      return tree;
    });
    log.debug("Leaving subtrees().");
    return out;
  }
  var permitted = subtrees(spec.permitted);
  var excluded = subtrees(spec.excluded);
  if (!permitted.length && !excluded.length) {
    log.debug("Leaving buildNameConstraints(). Neither list set.");
    return null;
  }
  var nc = new pkijs.NameConstraints();
  if (permitted.length) nc.permittedSubtrees = permitted;
  if (excluded.length) nc.excludedSubtrees = excluded;
  log.debug("Leaving buildNameConstraints().");
  // RFC 5280: MUST be critical.
  return extension(EXT_OIDS.nameConstraints,
      spec.critical === undefined ? true : !!spec.critical, nc.toSchema());
}

function generalizedTime(date) {
  log.debug("Entering generalizedTime().");
  var d = new Date(date);
  function pad(n, width) {
    log.debug("Entering pad().");
    var s = String(n);
    while (s.length < (width || 2)) s = '0' + s;
    log.debug("Leaving pad().");
    return s;
  }
  var text = pad(d.getUTCFullYear(), 4) + pad(d.getUTCMonth() + 1) +
      pad(d.getUTCDate()) + pad(d.getUTCHours()) + pad(d.getUTCMinutes()) +
      pad(d.getUTCSeconds()) + 'Z';
  log.debug("Leaving generalizedTime().");
  return text;
}

function buildPrivateKeyUsagePeriod(spec) {
  log.debug("Entering buildPrivateKeyUsagePeriod().");
  var values = [];
  if (spec.notBefore) {
    values.push(new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 0 },
        valueHex: new TextEncoder().encode(
            generalizedTime(spec.notBefore)).buffer }));
  }
  if (spec.notAfter) {
    values.push(new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 1 },
        valueHex: new TextEncoder().encode(
            generalizedTime(spec.notAfter)).buffer }));
  }
  if (!values.length) {
    log.debug("Leaving buildPrivateKeyUsagePeriod(). Neither field set.");
    return null;
  }
  log.debug("Leaving buildPrivateKeyUsagePeriod().");
  return extension(EXT_OIDS.privateKeyUsagePeriod, !!spec.critical,
      new asn1js.Sequence({ value: values }));
}

function buildInhibitAnyPolicy(spec) {
  log.debug("Entering buildInhibitAnyPolicy().");
  if (spec.skipCerts === undefined || spec.skipCerts === null ||
      spec.skipCerts === '') {
    log.debug("Leaving buildInhibitAnyPolicy(). Not set.");
    return null;
  }
  log.debug("Leaving buildInhibitAnyPolicy().");
  return extension(EXT_OIDS.inhibitAnyPolicy,
      spec.critical === undefined ? true : !!spec.critical,
      new asn1js.Integer({ value: parseInt(spec.skipCerts, 10) }));
}

// RFC 7633's TLS Feature extension. Its one interesting value is 5,
// status_request — "must-staple".
function buildTlsFeature(spec) {
  log.debug("Entering buildTlsFeature().");
  var features = (spec.features || []).map(function (f) {
    return parseInt(f, 10);
  }).filter(function (f) { return !isNaN(f); });
  if (!features.length) {
    log.debug("Leaving buildTlsFeature(). None.");
    return null;
  }
  log.debug("Leaving buildTlsFeature().");
  return extension(EXT_OIDS.tlsFeature, !!spec.critical,
      new asn1js.Sequence({ value: features.map(function (f) {
        return new asn1js.Integer({ value: f });
      }) }));
}

function buildOcspNoCheck(spec) {
  log.debug("Entering buildOcspNoCheck().");
  if (!spec.present) {
    log.debug("Leaving buildOcspNoCheck(). Absent.");
    return null;
  }
  log.debug("Leaving buildOcspNoCheck().");
  return extension(EXT_OIDS.ocspNoCheck, !!spec.critical, new asn1js.Null());
}

function buildNetscapeCertType(spec) {
  log.debug("Entering buildNetscapeCertType().");
  var built = bitStringFor(spec.types, NS_CERT_TYPE_BITS);
  if (!built) {
    log.debug("Leaving buildNetscapeCertType(). None.");
    return null;
  }
  log.debug("Leaving buildNetscapeCertType().");
  return extension(EXT_OIDS.netscapeCertType, !!spec.critical,
      new asn1js.BitString({ unusedBits: built.unusedBits,
          valueHex: built.bytes.buffer.slice(built.bytes.byteOffset,
              built.bytes.byteOffset + built.bytes.byteLength) }));
}

function buildNetscapeComment(spec) {
  log.debug("Entering buildNetscapeComment().");
  if (!spec.text) {
    log.debug("Leaving buildNetscapeComment(). Absent.");
    return null;
  }
  log.debug("Leaving buildNetscapeComment().");
  return extension(EXT_OIDS.netscapeComment, !!spec.critical,
      new asn1js.IA5String({ value: String(spec.text) }));
}

// Parse base64 DER given by a caller, and say which of the two ways it was
// wrong.
//
// The two are worth separating, and it took a test to notice: `atob` throws
// `Invalid character` for text that is not base64 at all, which names neither
// the field nor the OID and reads as an internal fault. And a value that IS
// base64 but does not decode to a DER element is a different mistake with a
// different fix. Note also the trap api/CLAUDE.md records from the other end —
// node's own base64 decoder is LENIENT, silently dropping what it does not
// recognise — so the alphabet is checked here rather than trusted to whichever
// decoder happens to run.
function derFromBase64(text, what) {
  log.debug("Entering derFromBase64(). what=" + what);
  var normalised = String(text || '').replace(/\s+/g, '')
      .replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalised) ||
      normalised.length % 4 === 1 || !normalised.length) {
    log.debug("Leaving derFromBase64(). Not base64.");
    throw new Error(what + ': the value is not base64. It must be the DER ' +
                    'encoding of the value, base64 or base64url.');
  }
  var parsed = asn1js.fromBER(pemToDer(normalised));
  if (parsed.offset === -1) {
    log.debug("Leaving derFromBase64(). Not DER.");
    throw new Error(what + ': the value decoded from base64 but is not DER — ' +
                    'it must be one complete ASN.1 element.');
  }
  log.debug("Leaving derFromBase64().");
  return parsed.result;
}

// Anything at all: an OID, a critical flag, and base64 DER. Without this the
// extension set is whatever this file knows about, which is not what a
// debugger is for.
function buildCustomExtension(spec) {
  log.debug("Entering buildCustomExtension(). oid=" + (spec || {}).oid);
  if (!spec.oid || !spec.value) {
    log.debug("Leaving buildCustomExtension(). Incomplete.");
    return null;
  }
  var value = derFromBase64(spec.value, 'Extension ' + spec.oid);
  log.debug("Leaving buildCustomExtension().");
  return extension(String(spec.oid), !!spec.critical, value);
}

// ---------------------------------------------------------------------------
// Certificate profiles — the extension set each kind of certificate starts
// with. Everything below is a DEFAULT the page then lets you edit, including
// the criticality flags: the point of the tool is to be able to issue the
// certificate that is wrong in exactly one way and watch what refuses it.
//
// `cn` is the subject Common Name that goes with the kind of certificate this
// is — `RootCA`, `IntermediateCA`, `IssuingCA` for the three authorities, and
// `server` / `client` for the two TLS profiles, which is what the hierarchy
// reads as in a chain view and in a store listing. It is here rather than in
// the page for the same reason the extension defaults are: the node tests then
// start from what the browser starts from. An empty CN is a legal DN and a
// certificate nobody can tell apart from the next one in the store, which is
// what typing four of them by hand before the first handshake actually costs.
//
// These were `Example Root CA`, `localhost` and so on until 2026-08-18. Two
// things went with the rename: the TLS profiles no longer default to a name a
// local server answers to (issue for `localhost` by typing it, which is one
// field), and `server` / `client` are short enough to be words somebody might
// type themselves — `isDefaultSubjectCN()` cannot tell those apart from one of
// ours and will replace them on the next profile change. That was already true
// of `localhost`; it is more likely now.
// ---------------------------------------------------------------------------
var PROFILES = {
  'root-ca': {
    label: 'Root CA (self-signed)',
    cn: 'RootCA',
    ca: true,
    selfSigned: true,
    years: 20,
    keyUsage: ['keyCertSign', 'cRLSign', 'digitalSignature'],
    pathLen: null
  },
  'intermediate-ca': {
    label: 'Intermediate CA',
    cn: 'IntermediateCA',
    ca: true,
    years: 10,
    keyUsage: ['keyCertSign', 'cRLSign', 'digitalSignature'],
    pathLen: 1
  },
  'issuing-ca': {
    label: 'Issuing CA',
    cn: 'IssuingCA',
    ca: true,
    years: 5,
    keyUsage: ['keyCertSign', 'cRLSign', 'digitalSignature'],
    pathLen: 0
  },
  'tls-server': {
    label: 'TLS Server',
    cn: 'server',
    years: 1,
    keyUsage: ['digitalSignature', 'keyEncipherment'],
    extKeyUsage: ['serverAuth']
  },
  'tls-client': {
    label: 'TLS Client (mutual auth)',
    cn: 'client',
    years: 1,
    keyUsage: ['digitalSignature', 'keyEncipherment'],
    extKeyUsage: ['clientAuth']
  },
  'tls-server-client': {
    label: 'TLS Server + Client',
    cn: 'server',
    years: 1,
    keyUsage: ['digitalSignature', 'keyEncipherment'],
    extKeyUsage: ['serverAuth', 'clientAuth']
  },
  'digital-signature': {
    label: 'Digital Signature / non-repudiation',
    cn: 'Signer',
    years: 3,
    keyUsage: ['digitalSignature', 'nonRepudiation']
  },
  'key-encipherment': {
    label: 'Key Encipherment (encryption)',
    cn: 'Recipient',
    years: 3,
    keyUsage: ['keyEncipherment', 'dataEncipherment']
  },
  'code-signing': {
    label: 'Code Signing',
    cn: 'CodeSigner',
    years: 3,
    keyUsage: ['digitalSignature'],
    extKeyUsage: ['codeSigning']
  },
  'email': {
    label: 'S/MIME (email protection)',
    cn: 'EmailUser',
    years: 3,
    keyUsage: ['digitalSignature', 'keyEncipherment', 'nonRepudiation'],
    extKeyUsage: ['emailProtection']
  },
  'ocsp-responder': {
    label: 'OCSP Responder',
    cn: 'OCSPResponder',
    years: 1,
    keyUsage: ['digitalSignature'],
    extKeyUsage: ['ocspSigning'],
    ocspNoCheck: true
  },
  'timestamping': {
    label: 'Time Stamping',
    cn: 'TimeStampingAuthority',
    years: 5,
    keyUsage: ['digitalSignature', 'nonRepudiation'],
    extKeyUsage: ['timeStamping'],
    ekuCritical: true
  },
  'smartcard-logon': {
    label: 'Smartcard Logon',
    cn: 'SmartcardUser',
    years: 2,
    keyUsage: ['digitalSignature', 'keyEncipherment'],
    extKeyUsage: ['clientAuth', 'msSmartcardLogon']
  },
  'kdc': {
    label: 'Kerberos KDC (PKINIT)',
    cn: 'kdc',
    years: 2,
    keyUsage: ['digitalSignature', 'keyEncipherment'],
    extKeyUsage: ['kdcAuthentication']
  }
};

var PROFILE_ORDER = ['root-ca', 'intermediate-ca', 'issuing-ca', 'tls-server',
                     'tls-client', 'tls-server-client', 'digital-signature',
                     'key-encipherment', 'code-signing', 'email',
                     'ocsp-responder', 'timestamping', 'smartcard-logon',
                     'kdc'];

function profileIds() {
  log.debug("Entering profileIds().");
  log.debug("Leaving profileIds().");
  return PROFILE_ORDER.slice();
}

function profile(id) {
  log.debug("Entering profile(). id=" + id);
  var found = PROFILES[id];
  log.debug("Leaving profile().");
  return found ? Object.assign({ id: id }, found) : null;
}

// The subject CN a profile starts from. Empty for a profile that has none,
// which is not one of the fourteen but is what an unknown id gives back.
function defaultSubjectCN(profileId) {
  log.debug("Entering defaultSubjectCN(). profile=" + profileId);
  var p = profile(profileId) || {};
  log.debug("Leaving defaultSubjectCN(). " + (p.cn || '(none)'));
  return p.cn || '';
}

// Whether a CN is one THIS table wrote. The page needs the question to tell a
// default it put there itself — which it may replace when the profile changes
// — from a name somebody typed, which it must not touch. Comparing against the
// current profile's own default is not enough: by the time the question is
// asked the dropdown has already moved on, and the value in the field belongs
// to the profile that was selected a moment ago.
function isDefaultSubjectCN(value) {
  log.debug("Entering isDefaultSubjectCN(). value=" + value);
  var wanted = String(value || '').trim();
  var found = PROFILE_ORDER.some(function (id) {
    return PROFILES[id].cn === wanted;
  });
  log.debug("Leaving isDefaultSubjectCN(). " + found);
  return found;
}

// The rest of the subject DN, which does NOT vary by profile.
//
// A distinguished name with nothing but a CN is a legal name and a poor
// example of one: the O/OU/L/ST/C an operator actually meets are what makes
// the DN encoding — the PrintableString of a country code, the ordered
// RDNSequence — visible in the first certificate somebody issues here rather
// than in the fifth. They are obviously-fictional values for the same reason
// the CNs are: this page issues test certificates.
//
// Unlike the CN there is no "is this still a default" question to answer,
// because none of these follow the profile: the page fills an EMPTY field and
// never replaces one that has anything in it.
var DEFAULT_DN = {
  O: 'Example Corp',
  OU: 'Information Technology',
  L: 'Austin',
  ST: 'Texas',
  C: 'US'
};

// The subjectAltName a profile starts from, in the page's own list syntax.
//
// Only the profiles that carry serverAuth get one, and it is `dns:` + the
// profile's own CN — because for a TLS server the CN is not what is checked.
// Every current browser ignores it and reads subjectAltName, so a server
// certificate whose SAN does not repeat the name in the CN is the one shape of
// certificate this page could hand somebody that no client will accept. It is
// derived from `extKeyUsage` rather than written into each profile so that a
// new server-ish profile cannot be added without one.
function defaultSubjectAltName(profileId) {
  log.debug("Entering defaultSubjectAltName(). profile=" + profileId);
  var p = profile(profileId) || {};
  var eku = p.extKeyUsage || [];
  if (eku.indexOf('serverAuth') < 0 || !p.cn) {
    log.debug("Leaving defaultSubjectAltName(). None for this profile.");
    return '';
  }
  log.debug("Leaving defaultSubjectAltName(). dns:" + p.cn);
  return 'dns:' + p.cn;
}

// Whether a subjectAltName is one THIS table wrote, asked and answered for the
// same reason isDefaultSubjectCN() is: the page may replace its own default
// when the profile changes and must never touch a name somebody typed. Empty
// counts, so the first server profile chosen fills an untouched field.
function isDefaultSubjectAltName(value) {
  log.debug("Entering isDefaultSubjectAltName(). value=" + value);
  var wanted = String(value || '').trim();
  var found = !wanted || PROFILE_ORDER.some(function (id) {
    var mine = defaultSubjectAltName(id);
    return !!mine && mine === wanted;
  });
  log.debug("Leaving isDefaultSubjectAltName(). " + found);
  return found;
}

// The extension spec a profile starts from, which the page then edits. Kept
// here rather than in the page so that the node tests issue exactly what the
// browser issues.
function defaultExtensions(profileId) {
  log.debug("Entering defaultExtensions(). profile=" + profileId);
  var p = profile(profileId) || {};
  var out = {
    basicConstraints: { present: true, ca: !!p.ca, pathLen: p.pathLen,
                       critical: true },
    keyUsage: { present: true, usages: (p.keyUsage || []).slice(),
               critical: true },
    extKeyUsage: { present: !!(p.extKeyUsage || []).length,
                  usages: (p.extKeyUsage || []).slice(),
                  critical: !!p.ekuCritical },
    subjectKeyIdentifier: { present: true, critical: false },
    authorityKeyIdentifier: { present: true, critical: false,
                             includeIssuerAndSerial: false },
    subjectAltName: { present: false, names: [], critical: false },
    issuerAltName: { present: false, names: [], critical: false },
    cRLDistributionPoints: { present: false, urls: [], critical: false },
    freshestCRL: { present: false, urls: [], critical: false },
    authorityInfoAccess: { present: false, entries: [], critical: false },
    subjectInfoAccess: { present: false, entries: [], critical: false },
    certificatePolicies: { present: false, policies: [], critical: false },
    policyMappings: { present: false, mappings: [], critical: true },
    policyConstraints: { present: false, critical: true },
    nameConstraints: { present: false, permitted: [], excluded: [],
                      critical: true },
    inhibitAnyPolicy: { present: false, critical: true },
    privateKeyUsagePeriod: { present: false, critical: false },
    tlsFeature: { present: false, features: [], critical: false },
    ocspNoCheck: { present: !!p.ocspNoCheck, critical: false },
    netscapeCertType: { present: false, types: [], critical: false },
    netscapeComment: { present: false, text: '', critical: false },
    custom: []
  };
  // A CA that is not self-signed has no business claiming a path length it did
  // not ask for; a leaf has no basicConstraints pathLen at all.
  if (!p.ca) out.basicConstraints.pathLen = null;
  log.debug("Leaving defaultExtensions().");
  return out;
}

// ---------------------------------------------------------------------------
// Serial numbers
//
// A random 128-bit positive integer, which is what the CA/Browser Forum
// requires and what makes a hash collision on the TBS impractical to arrange.
// The top bit is cleared so the DER INTEGER stays positive without a leading
// zero byte that some parsers report as a 17-byte serial.
// ---------------------------------------------------------------------------
function randomSerialHex(bytes) {
  log.debug("Entering randomSerialHex().");
  var raw = new Uint8Array(bytes || 16);
  crypto.getRandomValues(raw);
  raw[0] = raw[0] & 0x7f;
  if (raw[0] === 0) raw[0] = 1;
  var hex = '';
  for (var i = 0; i < raw.length; i++) {
    hex += ('0' + raw[i].toString(16)).slice(-2);
  }
  log.debug("Leaving randomSerialHex().");
  return hex;
}

function serialFromHex(hex) {
  log.debug("Entering serialFromHex().");
  var clean = String(hex).replace(/[^0-9a-fA-F]/g, '');
  if (clean.length % 2) clean = '0' + clean;
  var bytes = new Uint8Array(clean.length / 2);
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  // A leading byte of 0x80 or more would be read as a negative integer.
  var value = bytes[0] >= 0x80
    ? new Uint8Array([0].concat(Array.prototype.slice.call(bytes)))
    : bytes;
  log.debug("Leaving serialFromHex().");
  return new asn1js.Integer({ valueHex: value.buffer.slice(value.byteOffset,
      value.byteOffset + value.byteLength) });
}

// ---------------------------------------------------------------------------
// Issuing a certificate
//
// spec:
//   subject          [{name,value}] or a DN string
//   subjectPublicKey SPKI PEM of the key being certified
//   issuer           null for self-signed, else
//                    {certificatePem, privateKeyPem, keyAlg}
//   issuerPrivateKey PKCS#8 PEM (self-signed: the subject's own private key)
//   signatureAlg     a SIG_ALGS id
//   serial           hex string; omitted means a random 128-bit one
//   notBefore/notAfter Date or ISO string
//   extensions       as defaultExtensions() returns
// ---------------------------------------------------------------------------
async function issueCertificate(spec) {
  log.debug("Entering issueCertificate().");
  var subjectAttrs = typeof spec.subject === 'string'
    ? parseDnString(spec.subject)
    : spec.subject;
  if (!subjectAttrs || !subjectAttrs.length) {
    log.debug("Leaving issueCertificate(). Empty subject.");
    throw new Error('A certificate needs a subject.');
  }
  var subjectSpki = pemToDer(spec.subjectPublicKey);
  var sig = sigAlg(spec.signatureAlg);
  if (!sig) {
    log.debug("Leaving issueCertificate(). Unknown signature algorithm.");
    throw new Error('Unknown signature algorithm: ' + spec.signatureAlg);
  }

  var issuerCert = spec.issuer && spec.issuer.certificatePem
    ? pkijs.Certificate.fromBER(pemToDer(spec.issuer.certificatePem))
    : null;
  var issuerPrivatePem = spec.issuer
    ? spec.issuer.privateKeyPem
    : spec.issuerPrivateKey;
  if (!issuerPrivatePem) {
    log.debug("Leaving issueCertificate(). No signing key.");
    throw new Error('No issuer private key: nothing can sign this ' +
                    'certificate.');
  }
  var issuerKeyDesc = spec.issuer && spec.issuer.keyAlg
    ? keys.keyAlg(spec.issuer.keyAlg)
    : await keys.describePublicPem(spec.subjectPublicKey);
  var signerDesc = signerDescriptor(sig, issuerKeyDesc || {});

  var cert = new pkijs.Certificate();
  cert.version = 2; // v3
  cert.serialNumber = serialFromHex(spec.serial || randomSerialHex(16));
  cert.subject = buildDn(subjectAttrs);
  cert.issuer = issuerCert ? issuerCert.subject : cert.subject;

  var notBefore = spec.notBefore ? new Date(spec.notBefore) : new Date();
  var notAfter = spec.notAfter ? new Date(spec.notAfter) : null;
  if (!notAfter) {
    var years = (profile(spec.profile) || {}).years || 1;
    notAfter = new Date(notBefore.getTime());
    notAfter.setUTCFullYear(notAfter.getUTCFullYear() + years);
  }
  cert.notBefore.value = notBefore;
  cert.notAfter.value = notAfter;
  // RFC 5280 section 4.1.2.5: a time at or after 2050 must be a
  // GeneralizedTime. pkijs picks UTCTime by default, and a 2050+ UTCTime is
  // read as 1950 — a certificate that expired seventy years ago, reported by
  // every validator as expired and by none as misencoded.
  if (notBefore.getUTCFullYear() >= 2050) cert.notBefore.type = 1;
  if (notAfter.getUTCFullYear() >= 2050) cert.notAfter.type = 1;

  // The subject public key: parsed in as DER rather than imported, because
  // pkijs's importKey cannot read an Ed25519 SPKI. See the header.
  cert.subjectPublicKeyInfo.fromSchema(asn1js.fromBER(subjectSpki).result);

  var extensions = await buildExtensions(spec, subjectSpki, issuerCert);
  if (extensions.length) cert.extensions = extensions;

  var privateKey = await keys.importPrivateKey(issuerPrivatePem, signerDesc);
  await signCertificate(cert, privateKey, sig);

  var der = cert.toSchema(true).toBER(false);
  log.debug("Leaving issueCertificate().");
  return {
    der: new Uint8Array(der),
    pem: derToPem(der, 'CERTIFICATE'),
    serialHex: bytesToHex(cert.serialNumber.valueBlock.valueHexView),
    subject: dnToString(cert.subject),
    issuer: dnToString(cert.issuer),
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    signatureAlg: sig.id
  };
}

// ---------------------------------------------------------------------------
// A DER INTEGER, minimally encoded — which is what an ECDSA signature in a
// certificate has to carry and what pkijs does not always produce.
//
// Web Crypto returns an ECDSA signature as FIXED-WIDTH r||s, and pkijs turns
// that into `SEQUENCE { INTEGER r, INTEGER s }` through asn1js's
// `Integer.toDER()`, which strips exactly ONE leading zero octet. A value small
// enough to have TWO — about one P-521 signature in 256, because that curve's r
// and s are 66 octets for a 521-bit order — therefore comes out as `00 1d f9 …`
// where DER requires `1d f9 …`.
//
// The certificate is otherwise perfect and verifies against this codebase's own
// verifyChain(), because pkijs's reader right-aligns whatever length it finds.
// OPENSSL refuses it, because ECDSA_verify re-encodes what it parsed and
// compares the bytes:
//
//     error 7 at 0 depth lookup: certificate signature failure
//     ...asn1 encoding routines:ASN1_item_verify_ctx:EVP lib
//
// — a message that names neither the encoding nor the curve, on one certificate
// in a few hundred. tests/pki_x509.js caught it as an intermittent failure of
// one cell of its algorithm matrix.
// ---------------------------------------------------------------------------
function minimalDerInteger(bytes) {
  log.debug("Entering minimalDerInteger().");
  var start = 0;
  while (start + 1 < bytes.length && bytes[start] === 0 &&
         (bytes[start + 1] & 0x80) === 0) {
    start = start + 1;
  }
  var trimmed = bytes.slice(start);
  // The other half of the same rule: a value whose top bit is set needs a
  // leading zero octet so the INTEGER stays positive. asn1js gets this one
  // right; it is here so that this function alone defines the encoding.
  if ((trimmed[0] & 0x80) !== 0) {
    var padded = new Uint8Array(trimmed.length + 1);
    padded.set(trimmed, 1);
    trimmed = padded;
  }
  log.debug("Leaving minimalDerInteger().");
  return trimmed;
}

// `SEQUENCE { INTEGER r, INTEGER s }` in, the same pair minimally encoded out.
// Anything that is not that pair is returned untouched: this runs on bytes
// another library produced, and a signature it cannot read is not one to
// rewrite.
function minimalEcdsaSignature(der) {
  log.debug("Entering minimalEcdsaSignature().");
  var bytes = new Uint8Array(der);
  var parsed = asn1js.fromBER(bytes.slice().buffer);
  var seq = parsed.result;
  var pair = (parsed.offset !== -1 && seq && seq.valueBlock &&
              seq.valueBlock.value) ? seq.valueBlock.value : [];
  if (pair.length !== 2) {
    log.debug("Leaving minimalEcdsaSignature(). Not an (r, s) pair.");
    return bytes;
  }
  var rebuilt = new asn1js.Sequence({
    value: pair.map(function (part) {
      var value = minimalDerInteger(
        new Uint8Array(part.valueBlock.valueHexView));
      return new asn1js.Integer({
        valueHex: value.buffer.slice(value.byteOffset,
                                     value.byteOffset + value.byteLength)
      });
    })
  });
  log.debug("Leaving minimalEcdsaSignature(). Re-encoded.");
  return new Uint8Array(rebuilt.toBER(false));
}

// Sign the TBS. Everything but Ed25519 goes through pkijs; Ed25519 is done by
// hand because pkijs's engine does not know the algorithm at all — see the
// header. Both paths set the SAME two AlgorithmIdentifiers, which is what
// makes the certificate self-consistent.
async function signCertificate(cert, privateKey, sig) {
  log.debug("Entering signCertificate(). alg=" + sig.id);
  if (sig.kind !== 'okp') {
    await cert.sign(privateKey, sig.hash);
    // ECDSA only, and only because pkijs's (r, s) encoding is not always
    // minimal — see minimalDerInteger() above. RSA signatures are a single
    // octet string and are left exactly as they were produced.
    if (sig.kind === 'ec') {
      var normalized = minimalEcdsaSignature(
        cert.signatureValue.valueBlock.valueHexView);
      cert.signatureValue = new asn1js.BitString({
        valueHex: normalized.buffer.slice(
          normalized.byteOffset,
          normalized.byteOffset + normalized.byteLength)
      });
    }
    log.debug("Leaving signCertificate(). Signed by pkijs.");
    return cert;
  }
  cert.signature = new pkijs.AlgorithmIdentifier({
      algorithmId: ED25519_OID });
  cert.signatureAlgorithm = new pkijs.AlgorithmIdentifier({
      algorithmId: ED25519_OID });
  var tbs = cert.encodeTBS().toBER(false);
  var signature = await crypto.subtle.sign({ name: 'Ed25519' }, privateKey,
      tbs);
  cert.signatureValue = new asn1js.BitString({ valueHex: signature });
  log.debug("Leaving signCertificate(). Signed as Ed25519.");
  return cert;
}

async function buildExtensions(spec, subjectSpki, issuerCert) {
  log.debug("Entering buildExtensions().");
  var ext = spec.extensions || defaultExtensions(spec.profile);
  var out = [];
  function add(built) {
    log.debug("Entering add().");
    if (built) out.push(built);
    log.debug("Leaving add().");
  }

  if (ext.basicConstraints && ext.basicConstraints.present) {
    add(buildBasicConstraints(ext.basicConstraints));
  }
  if (ext.keyUsage && ext.keyUsage.present) add(buildKeyUsage(ext.keyUsage));
  if (ext.extKeyUsage && ext.extKeyUsage.present) {
    add(buildExtKeyUsage(ext.extKeyUsage));
  }
  if (ext.subjectAltName && ext.subjectAltName.present) {
    add(buildAltName(EXT_OIDS.subjectAltName, ext.subjectAltName));
  }
  if (ext.issuerAltName && ext.issuerAltName.present) {
    add(buildAltName(EXT_OIDS.issuerAltName, ext.issuerAltName));
  }
  if (ext.subjectKeyIdentifier && ext.subjectKeyIdentifier.present) {
    var skid = await keyIdentifier(subjectSpki);
    add(extension(EXT_OIDS.subjectKeyIdentifier,
        !!ext.subjectKeyIdentifier.critical,
        new asn1js.OctetString({ valueHex: skid.buffer.slice(skid.byteOffset,
            skid.byteOffset + skid.byteLength) })));
  }
  if (ext.authorityKeyIdentifier && ext.authorityKeyIdentifier.present) {
    add(await buildAuthorityKeyIdentifier(ext.authorityKeyIdentifier,
        subjectSpki, issuerCert));
  }
  if (ext.cRLDistributionPoints && ext.cRLDistributionPoints.present) {
    add(buildCrlDistributionPoints(EXT_OIDS.cRLDistributionPoints,
        ext.cRLDistributionPoints));
  }
  if (ext.freshestCRL && ext.freshestCRL.present) {
    add(buildCrlDistributionPoints(EXT_OIDS.freshestCRL, ext.freshestCRL));
  }
  if (ext.authorityInfoAccess && ext.authorityInfoAccess.present) {
    add(buildInfoAccess(EXT_OIDS.authorityInfoAccess,
        ext.authorityInfoAccess));
  }
  if (ext.subjectInfoAccess && ext.subjectInfoAccess.present) {
    add(buildInfoAccess(EXT_OIDS.subjectInfoAccess, ext.subjectInfoAccess));
  }
  if (ext.certificatePolicies && ext.certificatePolicies.present) {
    add(buildCertificatePolicies(ext.certificatePolicies));
  }
  if (ext.policyMappings && ext.policyMappings.present) {
    add(buildPolicyMappings(ext.policyMappings));
  }
  if (ext.policyConstraints && ext.policyConstraints.present) {
    add(buildPolicyConstraints(ext.policyConstraints));
  }
  if (ext.nameConstraints && ext.nameConstraints.present) {
    add(buildNameConstraints(ext.nameConstraints));
  }
  if (ext.inhibitAnyPolicy && ext.inhibitAnyPolicy.present) {
    add(buildInhibitAnyPolicy(ext.inhibitAnyPolicy));
  }
  if (ext.privateKeyUsagePeriod && ext.privateKeyUsagePeriod.present) {
    add(buildPrivateKeyUsagePeriod(ext.privateKeyUsagePeriod));
  }
  if (ext.tlsFeature && ext.tlsFeature.present) {
    add(buildTlsFeature(ext.tlsFeature));
  }
  if (ext.ocspNoCheck && ext.ocspNoCheck.present) {
    add(buildOcspNoCheck(ext.ocspNoCheck));
  }
  if (ext.netscapeCertType && ext.netscapeCertType.present) {
    add(buildNetscapeCertType(ext.netscapeCertType));
  }
  if (ext.netscapeComment && ext.netscapeComment.present) {
    add(buildNetscapeComment(ext.netscapeComment));
  }
  (ext.custom || []).forEach(function (custom) {
    add(buildCustomExtension(custom));
  });
  log.debug("Leaving buildExtensions(). " + out.length + " extension(s).");
  return out;
}

// The AKI names the ISSUER's key, which for a self-signed certificate is the
// subject's own — the one case where reading it off the issuer certificate is
// impossible, because there is not one yet.
async function buildAuthorityKeyIdentifier(spec, subjectSpki, issuerCert) {
  log.debug("Entering buildAuthorityKeyIdentifier().");
  var spki;
  if (issuerCert) {
    spki = issuerCert.subjectPublicKeyInfo.toSchema().toBER(false);
  } else {
    spki = subjectSpki;
  }
  var kid = await keyIdentifier(spki);
  var aki = new pkijs.AuthorityKeyIdentifier({
    keyIdentifier: new asn1js.OctetString({
        valueHex: kid.buffer.slice(kid.byteOffset,
            kid.byteOffset + kid.byteLength) })
  });
  if (spec.includeIssuerAndSerial && issuerCert) {
    aki.authorityCertIssuer = [new pkijs.GeneralName({
        type: GN_TYPES.dirName, value: issuerCert.issuer })];
    aki.authorityCertSerialNumber = issuerCert.serialNumber;
  }
  log.debug("Leaving buildAuthorityKeyIdentifier().");
  return extension(EXT_OIDS.authorityKeyIdentifier, !!spec.critical,
      aki.toSchema());
}

function bytesToHex(bytes) {
  log.debug("Entering bytesToHex().");
  var view = new Uint8Array(bytes.buffer ? bytes.buffer.slice(bytes.byteOffset,
      bytes.byteOffset + bytes.byteLength) : bytes);
  var hex = '';
  for (var i = 0; i < view.length; i++) {
    hex += ('0' + view[i].toString(16)).slice(-2);
  }
  log.debug("Leaving bytesToHex().");
  return hex;
}

// ---------------------------------------------------------------------------
// Reading one back
//
// The describer covers exactly the extensions the builder writes, which is what
// makes the pair testable: issue with a setting, read it back, compare. An
// extension it does not know is reported by OID with its bytes rather than
// skipped — a certificate whose interesting extension is silently missing from
// the display is worse than no display.
// ---------------------------------------------------------------------------
var SIG_OID_NAMES = {
  '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.113549.1.1.10': 'rsassaPss',
  '1.2.840.10045.4.1': 'ecdsa-with-SHA1',
  '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
  '1.3.101.112': 'Ed25519'
};

var PUBKEY_OID_NAMES = {
  '1.2.840.113549.1.1.1': 'rsaEncryption',
  '1.2.840.10045.2.1': 'id-ecPublicKey',
  '1.3.101.112': 'Ed25519'
};

function describeGeneralName(gn) {
  log.debug("Entering describeGeneralName().");
  var out;
  if (gn.type === GN_TYPES.dns) out = 'DNS:' + gn.value;
  else if (gn.type === GN_TYPES.email) out = 'email:' + gn.value;
  else if (gn.type === GN_TYPES.uri) out = 'URI:' + gn.value;
  else if (gn.type === GN_TYPES.ip) {
    out = 'IP:' + describeIp(gn.value.valueBlock.valueHexView);
  } else if (gn.type === GN_TYPES.dirName) out = 'DirName:' + dnToString(
      gn.value);
  else if (gn.type === GN_TYPES.registeredID) out = 'RID:' + gn.value;
  else if (gn.type === GN_TYPES.otherName) out = describeOtherName(gn);
  else out = 'type ' + gn.type;
  log.debug("Leaving describeGeneralName().");
  return out;
}

function describeIp(bytes) {
  log.debug("Entering describeIp().");
  var view = new Uint8Array(bytes);
  var out;
  if (view.length === 4 || view.length === 8) {
    out = Array.prototype.slice.call(view.slice(0, 4)).join('.');
    if (view.length === 8) {
      out += '/' + Array.prototype.slice.call(view.slice(4)).join('.');
    }
  } else {
    var groups = [];
    for (var i = 0; i + 1 < Math.min(view.length, 16); i += 2) {
      groups.push(((view[i] << 8) | view[i + 1]).toString(16));
    }
    out = groups.join(':');
    if (view.length === 32) out += '/…';
  }
  log.debug("Leaving describeIp().");
  return out;
}

function describeOtherName(gn) {
  log.debug("Entering describeOtherName().");
  var out = 'otherName';
  try {
    var seq = gn.value.valueBlock.value;
    var oid = seq[0].valueBlock.toString();
    var inner = seq[1].valueBlock.value[0];
    var name = oid === OTHERNAME_UPN ? 'UPN'
      : oid === OTHERNAME_KRB5 ? 'Kerberos principal' : oid;
    var text = inner && inner.valueBlock && inner.valueBlock.value !== undefined
      ? inner.valueBlock.value
      : '(DER)';
    out = 'otherName:' + name + ':' + text;
  } catch (e) {
    log.debug("describeOtherName(): " + e.message);
  }
  log.debug("Leaving describeOtherName().");
  return out;
}

function bitsSet(bitString, table) {
  log.debug("Entering bitsSet().");
  var view = new Uint8Array(bitString.valueBlock.valueHexView);
  var out = table.filter(function (entry) {
    var byte = Math.floor(entry.bit / 8);
    if (byte >= view.length) return false;
    return (view[byte] & (0x80 >> (entry.bit % 8))) !== 0;
  }).map(function (entry) { return entry.name; });
  log.debug("Leaving bitsSet().");
  return out;
}

function describeExtension(ext) {
  log.debug("Entering describeExtension(). oid=" + ext.extnID);
  var name = EXT_BY_OID[ext.extnID] || ext.extnID;
  var out = { oid: ext.extnID, name: name, critical: !!ext.critical,
              value: null };
  var parsed = asn1js.fromBER(ext.extnValue.valueBlock.valueHexView);
  var asn1 = parsed.offset === -1 ? null : parsed.result;
  try {
    if (name === 'basicConstraints') {
      var bc = new pkijs.BasicConstraints({ schema: asn1 });
      out.value = { ca: !!bc.cA,
                    pathLen: bc.pathLenConstraint === undefined
                      ? null : bc.pathLenConstraint };
    } else if (name === 'keyUsage') {
      out.value = bitsSet(asn1, KEY_USAGE_BITS);
    } else if (name === 'netscapeCertType') {
      out.value = bitsSet(asn1, NS_CERT_TYPE_BITS);
    } else if (name === 'extKeyUsage') {
      out.value = new pkijs.ExtKeyUsage({ schema: asn1 }).keyPurposes
        .map(function (oid) { return EKU_BY_OID[oid] || oid; });
    } else if (name === 'subjectAltName' || name === 'issuerAltName') {
      out.value = new pkijs.GeneralNames({ schema: asn1 }).names
        .map(describeGeneralName);
    } else if (name === 'subjectKeyIdentifier') {
      out.value = bytesToHex(asn1.valueBlock.valueHexView);
    } else if (name === 'authorityKeyIdentifier') {
      var aki = new pkijs.AuthorityKeyIdentifier({ schema: asn1 });
      out.value = {
        keyIdentifier: aki.keyIdentifier
          ? bytesToHex(aki.keyIdentifier.valueBlock.valueHexView) : null,
        issuer: aki.authorityCertIssuer
          ? aki.authorityCertIssuer.map(describeGeneralName) : null,
        serial: aki.authorityCertSerialNumber
          ? bytesToHex(aki.authorityCertSerialNumber.valueBlock.valueHexView)
          : null
      };
    } else if (name === 'cRLDistributionPoints' || name === 'freshestCRL') {
      out.value = new pkijs.CRLDistributionPoints({ schema: asn1 })
        .distributionPoints.map(function (point) {
          return (point.distributionPoint || []).map(describeGeneralName)
              .join(', ');
        });
    } else if (name === 'authorityInfoAccess' || name === 'subjectInfoAccess') {
      out.value = new pkijs.InfoAccess({ schema: asn1 }).accessDescriptions
        .map(function (access) {
          return (AIA_BY_OID[access.accessMethod] || access.accessMethod) +
              ': ' + describeGeneralName(access.accessLocation);
        });
    } else if (name === 'certificatePolicies') {
      out.value = new pkijs.CertificatePolicies({ schema: asn1 })
        .certificatePolicies.map(function (info) {
          return { oid: info.policyIdentifier,
                   qualifiers: (info.policyQualifiers || []).length };
        });
    } else if (name === 'policyMappings') {
      out.value = new pkijs.PolicyMappings({ schema: asn1 }).mappings
        .map(function (m) {
          return m.issuerDomainPolicy + ' -> ' + m.subjectDomainPolicy;
        });
    } else if (name === 'policyConstraints') {
      var pc = new pkijs.PolicyConstraints({ schema: asn1 });
      out.value = { requireExplicitPolicy: pc.requireExplicitPolicy,
                    inhibitPolicyMapping: pc.inhibitPolicyMapping };
    } else if (name === 'nameConstraints') {
      var nc = new pkijs.NameConstraints({ schema: asn1 });
      out.value = {
        permitted: (nc.permittedSubtrees || []).map(function (t) {
          return describeGeneralName(t.base);
        }),
        excluded: (nc.excludedSubtrees || []).map(function (t) {
          return describeGeneralName(t.base);
        })
      };
    } else if (name === 'inhibitAnyPolicy') {
      out.value = asn1.valueBlock.valueDec;
    } else if (name === 'ocspNoCheck') {
      out.value = 'present';
    } else if (name === 'netscapeComment') {
      out.value = asn1.valueBlock.value;
    } else if (name === 'tlsFeature') {
      out.value = asn1.valueBlock.value.map(function (v) {
        return v.valueBlock.valueDec;
      });
    } else {
      out.value = bytesToHex(ext.extnValue.valueBlock.valueHexView);
    }
  } catch (e) {
    log.warn('describeExtension(' + ext.extnID + '): ' + e.message);
    out.value = bytesToHex(ext.extnValue.valueBlock.valueHexView);
    out.parseError = e.message;
  }
  log.debug("Leaving describeExtension().");
  return out;
}

async function describeCertificate(pemOrDer) {
  log.debug("Entering describeCertificate().");
  var der = typeof pemOrDer === 'string' ? pemToDer(pemOrDer) : pemOrDer;
  var cert = pkijs.Certificate.fromBER(der);
  var spkiDer = cert.subjectPublicKeyInfo.toSchema().toBER(false);
  var out = {
    version: (cert.version || 0) + 1,
    serialHex: bytesToHex(cert.serialNumber.valueBlock.valueHexView),
    subject: dnToString(cert.subject),
    issuer: dnToString(cert.issuer),
    notBefore: cert.notBefore.value.toISOString(),
    notAfter: cert.notAfter.value.toISOString(),
    signatureAlgorithm: SIG_OID_NAMES[cert.signatureAlgorithm.algorithmId] ||
        cert.signatureAlgorithm.algorithmId,
    signatureAlgorithmOid: cert.signatureAlgorithm.algorithmId,
    publicKeyAlgorithm:
        PUBKEY_OID_NAMES[cert.subjectPublicKeyInfo.algorithm.algorithmId] ||
        cert.subjectPublicKeyInfo.algorithm.algorithmId,
    selfSigned: dnToString(cert.subject) === dnToString(cert.issuer),
    extensions: (cert.extensions || []).map(describeExtension),
    fingerprints: {}
  };
  // The key description comes from importing the key, which is the only way to
  // learn an RSA modulus size or an EC curve — and the only part of this
  // function that can decline: describePublicPem() returns null rather than
  // throwing when no candidate imports, which is what a browser without
  // Ed25519 in Web Crypto does with an Ed25519 certificate. The ALGORITHM is
  // in the SubjectPublicKeyInfo either way, so that is the fallback rather
  // than "unrecognised" — the certificate says what it is, and a page that
  // cannot import the key can still say so.
  var keyDesc = await keys.describePublicPem(derToPem(spkiDer, 'PUBLIC KEY'));
  out.publicKey = keyDesc
    ? (keyDesc.kind === 'rsa' ? 'RSA ' + keyDesc.bits + '-bit'
      : keyDesc.kind === 'ec' ? 'ECDSA ' + keyDesc.curve : 'Ed25519')
    : out.publicKeyAlgorithm;
  out.fingerprints = await fingerprintsOf(der);
  log.debug("Leaving describeCertificate().");
  return out;
}

// SHA-1 and SHA-256 over the DER, or nulls.
//
// Both digests are Web Crypto, which is absent outside a secure context — and
// this describes a certificate, which is a public document that needs no
// secrecy to read. Everything else in describeCertificate() is ASN.1 parsing
// that works anywhere, so a missing crypto.subtle costs two rows of a table
// rather than the whole description: saml_cert.html is reachable from eight
// pages and reads certificates that arrived in somebody else's metadata.
async function fingerprintsOf(der) {
  log.debug("Entering fingerprintsOf().");
  var out = { sha1: null, sha256: null };
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    log.warn('fingerprintsOf(): no Web Crypto here, so no fingerprints.');
    log.debug("Leaving fingerprintsOf(). No Web Crypto.");
    return out;
  }
  try {
    var sha1 = await crypto.subtle.digest('SHA-1', der);
    var sha256 = await crypto.subtle.digest('SHA-256', der);
    out.sha1 = colonHex(new Uint8Array(sha1));
    out.sha256 = colonHex(new Uint8Array(sha256));
  } catch (e) {
    log.warn('fingerprintsOf(): ' + e.message);
  }
  log.debug("Leaving fingerprintsOf().");
  return out;
}

// One described extension's value as a line of text.
//
// It lives here rather than in the page that first needed it because the
// second page that needs it is saml_cert.html, which reads certificates this
// tree did not issue: `describeExtension()` returns a string for some
// extensions, a number for others, an array for the list-shaped ones and an
// object for basicConstraints, nameConstraints and the authority key
// identifier, and a caller that renders only the shapes it happens to have met
// prints "[object Object]" for the rest.
function extensionValueText(ext) {
  log.debug("Entering extensionValueText().");
  var value = ext ? ext.value : null;
  var text;
  if (value === null || value === undefined) {
    text = '(present)';
  } else if (typeof value === 'string' || typeof value === 'number') {
    text = String(value);
  } else if (Object.prototype.toString.call(value) === '[object Array]') {
    text = value.map(function (item) {
      return typeof item === 'object' ? JSON.stringify(item) : String(item);
    }).join(', ');
  } else {
    text = JSON.stringify(value);
  }
  log.debug("Leaving extensionValueText().");
  return text;
}

function colonHex(bytes) {
  log.debug("Entering colonHex().");
  var hex = bytesToHex(bytes).toUpperCase();
  log.debug("Leaving colonHex().");
  return (hex.match(/.{2}/g) || [hex]).join(':');
}

// Verify that each certificate in the list was signed by the next one, and
// that the last is self-signed. Reports EVERY link rather than one boolean:
// "the chain is broken" is not an answer anybody can act on.
async function verifyChain(pems) {
  log.debug("Entering verifyChain().");
  var certs = pems.map(function (pem) {
    return pkijs.Certificate.fromBER(pemToDer(pem));
  });
  var results = [];
  for (var i = 0; i < certs.length; i++) {
    var issuer = certs[i + 1] || certs[i];
    var link = {
      subject: dnToString(certs[i].subject),
      issuer: dnToString(certs[i].issuer),
      signedBy: dnToString(issuer.subject),
      namesMatch: dnToString(certs[i].issuer) === dnToString(issuer.subject),
      selfSigned: !certs[i + 1],
      signatureValid: false
    };
    try {
      link.signatureValid = await verifySignature(certs[i], issuer);
    } catch (e) {
      link.error = e.message;
    }
    var now = new Date();
    link.expired = certs[i].notAfter.value < now;
    link.notYetValid = certs[i].notBefore.value > now;
    results.push(link);
  }
  log.debug("Leaving verifyChain(). " + results.length + " link(s).");
  return results;
}

// pkijs's own verify() cannot check an Ed25519 signature (the same engine gap
// as signing), so that one is verified with Web Crypto against the issuer's
// SPKI directly.
async function verifySignature(cert, issuerCert) {
  log.debug("Entering verifySignature().");
  if (cert.signatureAlgorithm.algorithmId !== ED25519_OID) {
    var ok = await cert.verify(issuerCert);
    log.debug("Leaving verifySignature(). pkijs says " + ok);
    return ok;
  }
  var spkiPem = derToPem(issuerCert.subjectPublicKeyInfo.toSchema()
      .toBER(false), 'PUBLIC KEY');
  var key = await keys.importPublicKey(spkiPem, { kind: 'okp',
      name: 'Ed25519' });
  var verified = await crypto.subtle.verify({ name: 'Ed25519' }, key,
      cert.signatureValue.valueBlock.valueHexView, cert.tbsView);
  log.debug("Leaving verifySignature(). Ed25519 says " + verified);
  return verified;
}

// ---------------------------------------------------------------------------
// A SELF-SIGNED CERTIFICATE FOR A KEY PAIR THAT NEEDS ONE ONLY AS A WRAPPER.
//
// PKCS#12 cannot carry a bare private key: the format's whole shape is a key
// bag beside a certificate bag, so key_material.js's buildPkcs12() takes the
// certificates it is to wrap and deliberately does not mint one — that would
// make it depend on this module, and this module already depends on it.
//
// Which leaves each PAGE to mint the throwaway. jwt_tools.js had the only copy
// (buildSelfSignedCertPem), and the Encryption / Decryption page's RSA pane
// needs exactly the same thing for exactly the same reason — its Download Keys
// button offers PKCS#12, and without a certificate that download fails with
// "PKCS#12 needs at least one certificate to wrap the private key in".
//
// So it is here, once. `subject` is the caller's, because the CN is the only
// part of this that says which page produced the file, and the validity window
// is fixed rather than relative to now: a keystore's dates are not the point
// of the exercise on either page, and a fixed window makes the output
// reproducible.
async function selfSignedCertPem(options) {
  log.debug("Entering selfSignedCertPem().");
  var opts = options || {};
  var issued = await issueCertificate({
    subject: opts.subject || 'CN=generated key',
    subjectPublicKey: opts.publicPem,
    issuerPrivateKey: opts.privatePem,
    signatureAlg: opts.signatureAlg ||
        defaultSignatureAlgorithm(opts.desc),
    serial: opts.serial || '01',
    notBefore: new Date(Date.UTC(2020, 0, 1)),
    notAfter: new Date(Date.UTC(2035, 0, 1)),
    extensions: defaultExtensions(opts.profile || 'tls-server')
  });
  log.debug("Leaving selfSignedCertPem().");
  return issued.pem;
}

module.exports = {
  // algorithms
  SIG_ALGS: SIG_ALGS,
  sigAlg: sigAlg,
  signatureAlgorithmsFor: signatureAlgorithmsFor,
  defaultSignatureAlgorithm: defaultSignatureAlgorithm,
  selfSignedCertPem: selfSignedCertPem,
  signerDescriptor: signerDescriptor,
  // names
  DN_ATTRS: DN_ATTRS,
  buildDn: buildDn,
  dnToString: dnToString,
  parseDnString: parseDnString,
  GN_TYPES: GN_TYPES,
  buildGeneralName: buildGeneralName,
  ipBytes: ipBytes,
  ipConstraintBytes: ipConstraintBytes,
  // extensions
  EXT_OIDS: EXT_OIDS,
  KEY_USAGE_BITS: KEY_USAGE_BITS,
  EKU_OIDS: EKU_OIDS,
  AIA_METHODS: AIA_METHODS,
  NS_CERT_TYPE_BITS: NS_CERT_TYPE_BITS,
  keyIdentifier: keyIdentifier,
  // profiles
  PROFILES: PROFILES,
  profileIds: profileIds,
  profile: profile,
  defaultSubjectCN: defaultSubjectCN,
  isDefaultSubjectCN: isDefaultSubjectCN,
  DEFAULT_DN: DEFAULT_DN,
  defaultSubjectAltName: defaultSubjectAltName,
  isDefaultSubjectAltName: isDefaultSubjectAltName,
  defaultExtensions: defaultExtensions,
  // issuing and reading
  randomSerialHex: randomSerialHex,
  issueCertificate: issueCertificate,
  describeCertificate: describeCertificate,
  extensionValueText: extensionValueText,
  verifyChain: verifyChain,
  verifySignature: verifySignature,
  // Exported for tests/pki_x509.js: the case it guards against appears in
  // roughly one P-521 signature in 256, so a check that waits for a real one
  // is a check that reports green most of the time.
  minimalEcdsaSignature: minimalEcdsaSignature,
  bytesToHex: bytesToHex,
  colonHex: colonHex
};
