// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: mdoc_test_issuer.js
//
// ---------------------------------------------------------------------------
// An ISO/IEC 18013-5 mdoc ISSUER for the tests, written here and not in the
// wallet: its own CBOR encoder, node's own ECDSA, and an IACA and document
// signer certificate of its own. A shared module rather than a test, so
// nothing schedules it; tests/mdoc_engine.js and
// tests/vc_presentation_mdoc.js require it.
//
// It exists because no issuer in this stack mints an ISO mDL: iya-sts 1.1.0
// issues an `mso_mdoc` of its own type (urn:iya:sts:mdoc:identity, #1862)
// and VERIFIES others from issuers it trusts, through
// `oid4vp.mdocTrustAnchors`; 1.0.0 minted none. An issuer written beside
// the wallet that reads its output would share any misreading of the
// specification with it, so this one
// shares no code with client/src/mdoc.js: if the two agree, and iya-sts's
// verifier accepts what the wallet built from it, three readings agree.
//
// Also its own verifier of a DeviceResponse's device signature, for the
// engine test: the session transcript of OpenID4VP 1.0 Appendix B.2.6.1
// rebuilt from the specification's text.
// ---------------------------------------------------------------------------

const nodeCrypto = require("crypto");
const path = require("path");
const fs = require("fs");
const paths = require("./module_paths.js");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "mdoc_test_issuer",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});

const DOCTYPE = "org.iso.18013.5.1.mDL";
const NS = "org.iso.18013.5.1";
const DS_EKU = "1.0.18013.5.1.2";

function srcDir() {
  log.debug("Entering srcDir().");
  const candidates = [path.resolve(__dirname, ".."),
                      path.resolve(__dirname, "..", "source-tree")];
  for (const c of candidates) {
    if (fs.existsSync(path.join(c, "client", "package.json"))) {
      log.debug("Leaving srcDir(). " + c);
      return path.join(c, "client", "src");
    }
  }
  log.debug("Leaving srcDir(). Default.");
  return path.join(candidates[0], "client", "src");
}

// --- this file's own CBOR (RFC 8949), encoding only -------------------------
// Recursive and called per item, so no Entering/Leaving pair: the hot-path
// exception the code style allows, stated as it requires.
class Tag {
  constructor(tag, value) {
    this.tag = tag;
    this.value = value;
  }
}

function hd(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  if (n < 65536) {
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(n, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(n, 1);
  return b;
}

function cbor(v) {
  if (v === null) return Buffer.from([0xf6]);
  if (v === true) return Buffer.from([0xf5]);
  if (v === false) return Buffer.from([0xf4]);
  if (Buffer.isBuffer(v) || v instanceof Uint8Array) {
    return Buffer.concat([hd(2, v.length), Buffer.from(v)]);
  }
  if (v instanceof Tag) return Buffer.concat([hd(6, v.tag), cbor(v.value)]);
  if (typeof v === "number") return v >= 0 ? hd(0, v) : hd(1, -1 - v);
  if (typeof v === "string") {
    const s = Buffer.from(v, "utf8");
    return Buffer.concat([hd(3, s.length), s]);
  }
  if (Array.isArray(v)) {
    return Buffer.concat([hd(4, v.length)].concat(v.map(cbor)));
  }
  const entries = (v instanceof Map ? Array.from(v.entries()) :
    Object.keys(v).map(function (k) {
      return [k, v[k]];
    })).map(function (e) {
    return [cbor(e[0]), cbor(e[1])];
  }).sort(function (a, b) {
    return Buffer.compare(a[0], b[0]);
  });
  return Buffer.concat([hd(5, entries.length)].concat(
    [].concat.apply([], entries)));
}

function b64u(buf) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(buf).toString("base64url");
}

function coseKey(publicJwk) {
  log.debug("Entering coseKey().");
  log.debug("Leaving coseKey().");
  return new Map([[1, 2], [-1, 1],
                  [-2, Buffer.from(publicJwk.x, "base64url")],
                  [-3, Buffer.from(publicJwk.y, "base64url")]]);
}

function sign(privateKey, data) {
  log.debug("Entering sign().");
  log.debug("Leaving sign().");
  return nodeCrypto.sign("sha256", data,
      { key: privateKey, dsaEncoding: "ieee-p1363" });
}

function sigStructure(protectedBytes, payload) {
  log.debug("Entering sigStructure().");
  log.debug("Leaving sigStructure().");
  return cbor(["Signature1", protectedBytes, Buffer.alloc(0), payload]);
}

// An IACA (a root) and a document signer under it, P-256, from the
// debugger's own certificate encoder: the certificates are not what this
// file is checking, and iya-sts's verifier judges them independently.
async function authority(label) {
  log.debug("Entering authority(). " + label);
  const x509 = paths.requireSharedModule([path.join(srcDir(), "x509.js")],
                                         "client/src/x509.js");
  const pair = function () {
    const p = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    return { publicPem: p.publicKey.export({ type: "spki", format: "pem" }),
             privatePem: p.privateKey.export({ type: "pkcs8",
                                               format: "pem" }),
             privateKey: p.privateKey };
  };
  const iacaKey = pair();
  const dsKey = pair();
  const now = Date.now();
  const iaca = await x509.issueCertificate({
    profile: "root-ca", subject: "CN=" + label + " IACA,O=idptools,C=US",
    subjectPublicKey: iacaKey.publicPem, issuerPrivateKey: iacaKey.privatePem,
    signatureAlg: "sha256-ecdsa", notBefore: new Date(now - 86400000),
    notAfter: new Date(now + 5 * 365 * 86400000),
    extensions: x509.defaultExtensions("root-ca")
  });
  const ext = x509.defaultExtensions("tls-server");
  ext.keyUsage = { present: true, usages: ["digitalSignature"],
                   critical: true };
  ext.extKeyUsage = { present: true, usages: [DS_EKU], critical: true };
  const ds = await x509.issueCertificate({
    profile: "tls-server", subject: "CN=" + label + " DS,O=idptools,C=US",
    subjectPublicKey: dsKey.publicPem,
    issuer: { certificatePem: iaca.pem, privateKeyPem: iacaKey.privatePem,
              keyAlg: "es256" },
    signatureAlg: "sha256-ecdsa", notBefore: new Date(now - 3600000),
    notAfter: new Date(now + 365 * 86400000), extensions: ext
  });
  log.debug("Leaving authority().");
  return { iacaPem: iaca.pem, dsPem: ds.pem,
           dsDer: new nodeCrypto.X509Certificate(ds.pem).raw,
           dsKey: dsKey.privateKey };
}

// An IssuerSigned, as OpenID4VCI 1.0 Appendix A.2 delivers it (base64url),
// bound to `devicePublicJwk`, carrying `elements` in namespace NS.
function issue(auth, devicePublicJwk, elements, options) {
  log.debug("Entering issue().");
  const opts = options || {};
  const now = new Date();
  const until = new Date(now.getTime() + 30 * 86400000);
  const tdate = function (d) {
    return new Tag(0, d.toISOString().replace(/\.\d{3}Z$/, "Z"));
  };
  const items = Object.keys(elements).map(function (name, i) {
    const item = cbor({ digestID: i, random: nodeCrypto.randomBytes(16),
                        elementIdentifier: name,
                        elementValue: elements[name] });
    return { name: name, digestID: i, bytes: item };
  });
  const digests = new Map();
  items.forEach(function (it) {
    digests.set(it.digestID, nodeCrypto.createHash("sha256")
      .update(cbor(new Tag(24, it.bytes))).digest());
  });
  const mso = {
    version: "1.0", digestAlgorithm: "SHA-256",
    valueDigests: new Map([[NS, digests]]),
    deviceKeyInfo: { deviceKey: coseKey(devicePublicJwk) },
    docType: opts.docType || DOCTYPE,
    validityInfo: { signed: tdate(now), validFrom: tdate(now),
                    validUntil: tdate(until) }
  };
  const payload = cbor(new Tag(24, cbor(mso)));
  const protectedBytes = cbor(new Map([[1, -7]]));
  const signature = sign(auth.dsKey, sigStructure(protectedBytes, payload));
  const issuerAuth = [protectedBytes, new Map([[33, auth.dsDer]]), payload,
                      signature];
  const issuerSigned = {
    nameSpaces: new Map([[NS, items.map(function (it) {
      return new Tag(24, it.bytes);
    })]]),
    issuerAuth: issuerAuth
  };
  log.debug("Leaving issue(). " + items.length + " element(s).");
  return b64u(cbor(issuerSigned));
}

// OpenID4VP 1.0 Appendix B.2.6.1, written from the text: [null, null,
// ["OpenID4VPHandover", SHA-256(cbor([client_id, nonce, jwkThumbprint,
// response_uri]))]], the thumbprint the RFC 7638 one (bytes) of the
// Verifier's encryption key, or null.
function transcript(clientId, nonce, encryptionJwk, responseUri) {
  log.debug("Entering transcript().");
  let thumb = null;
  if (encryptionJwk) {
    thumb = nodeCrypto.createHash("sha256").update(JSON.stringify({
      crv: encryptionJwk.crv, kty: encryptionJwk.kty, x: encryptionJwk.x,
      y: encryptionJwk.y })).digest();
  }
  const info = cbor([clientId, nonce, thumb, responseUri]);
  log.debug("Leaving transcript().");
  return [null, null, ["OpenID4VPHandover",
    nodeCrypto.createHash("sha256").update(info).digest()]];
}

// The device signature of a DeviceResponse, checked with this file's own
// encoder: DeviceAuthenticationBytes rebuilt from the transcript, and the
// detached COSE_Sign1 verified with node's crypto against `devicePublicKey`.
function verifyDeviceSignature(document, devicePublicKey, sessionTranscript) {
  log.debug("Entering verifyDeviceSignature().");
  const deviceSigned = document.deviceSigned;
  const sig = deviceSigned.deviceAuth.deviceSignature;
  const auth = cbor(new Tag(24, cbor(["DeviceAuthentication",
    sessionTranscript, document.docType,
    new Tag(24, Buffer.from(deviceSigned.nameSpacesBytes))])));
  log.debug("Leaving verifyDeviceSignature().");
  return nodeCrypto.verify("sha256",
    sigStructure(Buffer.from(sig[0]), auth),
    { key: devicePublicKey, dsaEncoding: "ieee-p1363" }, Buffer.from(sig[3]));
}

module.exports = {
  DOCTYPE: DOCTYPE,
  NS: NS,
  Tag: Tag,
  cbor: cbor,
  authority: authority,
  issue: issue,
  transcript: transcript,
  verifyDeviceSignature: verifyDeviceSignature
};
