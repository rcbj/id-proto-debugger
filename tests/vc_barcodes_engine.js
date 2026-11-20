// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vc_barcodes_engine.js
//
// ---------------------------------------------------------------------------
// client/src/cborld.js and client/src/vc_barcodes.js in node (#480), held to
// the specification's own vectors and to Digital Bazaar's RELEASED
// @digitalbazaar/cborld 8.1.0 and @digitalbazaar/ecdsa-xi-2023-cryptosuite
// 1.2.0 — the implementation every published VC barcode was made with.
//
//   1. VC Barcodes v1.0's three printed CBOR-LD payloads (the Utopia
//      driver's licence, the employment authorization document, the birth
//      certificate): decoded, re-encoded to the SAME bytes, and verified;
//      the PDF417 text and the QR text as printed; both opticalDataBytes.
//   2. CBOR-LD byte for byte with the library over a corpus that exercises
//      every codec — the term ids, the URL table and the did:key, urn:uuid,
//      data: and http(s) forms, multibase, xsd:date and xsd:dateTime, the
//      cryptosuite table, plural values, scoped contexts — in both
//      directions, and the two legacy framings the library still writes.
//   3. ecdsa-xi-2023 both ways: barcodes issued here (P-256, P-384, MRZ and
//      AAMVA) verified by jsonld-signatures with the library's cryptosuite,
//      and the library's signed by it verified here.
//   4. What must fail: changed optical data, a protectedComponentIndex with
//      its padding bits set, a QR text without "VC1-R", a base45 length of
//      3n+1, a term id no context defines.
//   5. Base45 against RFC 9285's own examples.
//   6. IsoDrivingLicenceMachineReadableInformation (Appendix B,
//      informative), for which NO VECTOR EXISTS, so this file builds one:
//      fixed data groups, the 2-byte index, and the canonical text spelled
//      out independently with node's own base64url, then signed both ways
//      with the library's cryptosuite over the same opticalDataBytes. DG10
//      is protected on purpose: a code-point sort would put it before DG2.
//   7. Status: the BitstringStatusListCredential a terse entry expands to,
//      issued by Digital Bazaar's @digitalbazaar/vc-bitstring-status-list
//      2.0.1 and signed with its ecdsa-rdfc-2019 suite, read by
//      vp_verifier.js's checkBitstringStatus() (the page's reader); and one
//      packed and signed here, accepted by the library's checkStatus(). A
//      list changed after signing is not relied on.
//   8. PDF417 (client/src/pdf417.js: bwip-js to draw, @zxing/library to
//      read): the specification's driver's licence text drawn, rasterised
//      here from the symbol's modules at three scales, and read back to the
//      same text, which still verifies; a symbol too damaged to read is
//      reported as none rather than as wrong text.
//
// No browser and no services, so this never skips.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const nodeCrypto = require("crypto");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "vc_barcodes_engine",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});
log.info("Log initialized. logLevel=" + log.level());

// In a checkout the sources are beside tests/; in the tests image they are
// the complete copy at /usr/src/source-tree.
function repoRoot() {
  log.debug("Entering repoRoot().");
  var candidates = [path.resolve(__dirname, ".."),
                    path.resolve(__dirname, "..", "source-tree")];
  for (var i = 0; i < candidates.length; i++) {
    if (fs.existsSync(path.join(candidates[i], "client", "package.json"))) {
      log.debug("Leaving repoRoot(). " + candidates[i]);
      return candidates[i];
    }
  }
  log.debug("Leaving repoRoot(). None found.");
  return candidates[0];
}

const SRC = path.join(repoRoot(), "client", "src");
const paths = require("./module_paths.js");
function load(name) {
  log.debug("Entering load(). " + name);
  log.debug("Leaving load().");
  return paths.requireSharedModule([path.join(SRC, name)],
                                   "client/src/" + name);
}
load("data_integrity_rdfc.js");
const cborld = load("cborld.js");
const vcb = load("vc_barcodes.js");
const contexts = load("jsonld_contexts.js");
const di = load("data_integrity.js");
const didLib = load("did.js");
const vpVerifier = load("vp_verifier.js");
const pdf417 = load("pdf417.js");
const zlib = require("zlib");

const hex = function (s) {
  return new Uint8Array(Buffer.from(s.replace(/\s+/g, ""), "hex"));
};

// ---------------------------------------------------------------------------
// The specification's vectors (VC Barcodes v1.0, Appendix C and section
// 1.1.1), copied from the TR.
// ---------------------------------------------------------------------------
const DL_HEX = "D9CB1D821864A60183198000198001198002189D82187618A418B8A31" +
  "89C18A618CE18B218D01AE592208118BAA2189C18A018A8447582002018BE18AA18C0A51" +
  "89C186C18D60418E018E618E258417AB7C2E56B49E2CCE62184CE26818E15A8B17316440" +
  "1B5D3BB93FFD6D2B5EB8F6AC0971502AE3DD49D17EC66528164034C912685B8111BC04CD" +
  "C9EC13DBADD91CC18E418AC";
const EAD_HEX = "D9CB1D821864A50183198000198001198002189D82187618A418BAA11" +
  "89C18A218BE18AE18C0A5189C186C18D20418DC18E218DE58417A9EC7F688F60CAA8C757" +
  "592250B3F6D6E18419941F186E1ED4245770E687502D51D01CD2C2295E4338178A51A35C" +
  "2F044A85598E15DB9AEF00261BC5C95A744E718E018B0";
const BIRTH_HEX = "d9cb1d8201a60182782468747470733a2f2f7777772e77332e6f72" +
  "672f6e732f63726564656e7469616c732f7632782468747470733a2f2f773369642e6f72" +
  "672f766974616c2d7265636f7264732f7631726331189d82187618a4190130a3189c18a2" +
  "18cc74323032332d30392d33305431333a34343a35325a190104a618966754696d20446f" +
  "65189c18ae18bc74323032332d31302d30355431343a32393a30305a18c4a6189c18b219" +
  "01446655746f7069611901466b55746f70696120546f776e1901486855746f706f6c6973" +
  "19014a65313233343519014c6f31323320486f73706974616c20526418e2644d616c6519" +
  "010b82a31896684a616e6520446f65189c18ac1901026a4a616e6520536d697468a21896" +
  "684a6f686e20446f65189c18aa190134820277686f73706974616c2e6578616d706c652f" +
  "697373756572190136a6189c186c1901501a6a8a0c721901526f65636473612d72646663" +
  "2d3230313919015c19016219015e58417a82a8b0f62caf3aafa0ff69bac837d0ec2cfa62" +
  "0d47c4adcf60fc15ce0d5562acc7f69ff0ead1876427fc8b4f7910febb66154d372013c6" +
  "14e167af84de5623ea190160821904015823802403c7a5c2d0492eee1afa7735eca2336f" +
  "795a6c029ff0f0e882b6e8498ec42150e81901401a651806b8";
const DL_PDF417 = "@\n\x1e\rANSI 000000090002DL00410234ZZ02750202DLDAQF9876" +
  "54321\nDCSSMITH\nDDEN\nDACJOHN\nDDFN\nDADNONE\nDDGN\nDCAC\nDCBNONE\n" +
  "DCDNONE\nDBD01012024\nDBB04191988\nDBA04192030\nDBC1\nDAU069 IN\n" +
  "DAYBRO\nDAG123 MAIN ST\nDAIANYVILLE\nDAJUTO\nDAKF87P20000  \n" +
  "DCFUTODOCDISCRIM\nDCGUTO\nDAW158\nDCK1234567890\nDDAN\rZZZZA2csdghhkpgG" +
  "DGYAAGYABGYACGJ2CGHYYpBi4oxicGKYYzhiyGNAa5ZIggRi6ohicGKAYqER1ggAgGL4Yqhj" +
  "ApRicGGwY1gQY4BjmGOJYQXq3wuVrSeLM5iGEziaBjhWosXMWRAG107uT/9bSteuPasCXFQK" +
  "uPdSdF+xmUoFkA0yRJoW4ERvATNyewT263ZHMGOQYrA==\r";
const EAD_QR = "VC1-R0OR*W3Y33V%K PG88G3A3B60A8G1534KG$-ENXKWQN053653Y53I53" +
  " 539*K0XJ.TDYOQJ63P63L6337BPMFPCP7EH2R12YH%%EXU4$08E-D8D86F8E2HX:T8Z8/ " +
  "1TZEH.QBA03Q5W.I0N6FBF4E3:SOQU8. A3MSELNHFU0GCVVBP6LU9T%ES-3";
const EAD_MRZ = ["IAUTO0000007010SRC0000000701<<",
                 "8804192M2601058NOT<<<<<<<<<<<5",
                 "SMITH<<JOHN<<<<<<<<<<<<<<<<<<<"];
const DL_OPTICAL = "bc26c892e3d55afa32127efe2fb15b17408168df88517443887d" +
  "89a5753f98cf";
const EAD_OPTICAL = "08c67eb719a0a670feb8bd2fe1d37dd284892d56a91c39a52ef" +
  "d0989912ac071";

// ---------------------------------------------------------------------------
// The library, and what it loads.
// ---------------------------------------------------------------------------

// A context only this test uses, typing a term for every codec CBOR-LD
// has, with a property-scoped and a type-scoped context to move the term
// numbering about.
const CORPUS_CONTEXT_URL = "https://test.example/cborld-corpus/v1";
const CORPUS_CONTEXT = { "@context": {
  "@protected": true,
  "ex": "https://test.example/vocab#",
  "xsd": "http://www.w3.org/2001/XMLSchema#",
  "born": { "@id": "ex:born", "@type": "xsd:date" },
  "seen": { "@id": "ex:seen", "@type": "xsd:dateTime" },
  "link": { "@id": "ex:link", "@type": "@id" },
  "kind": { "@id": "ex:kind", "@type": "@vocab" },
  "digest": { "@id": "ex:digest",
              "@type": "https://w3id.org/security#multibase" },
  "count": "ex:count",
  "ratio": "ex:ratio",
  "flag": "ex:flag",
  "label": "ex:label",
  "Widget": { "@id": "ex:Widget", "@context": {
    "@protected": true,
    "part": { "@id": "ex:part", "@type": "@id" },
    "weight": "ex:weight" } },
  "holder": { "@id": "ex:holder", "@context": {
    "alias": "ex:alias",
    "since": { "@id": "ex:since", "@type": "xsd:dateTime" } } }
} };

function didKeyFor(jwk) {
  log.debug("Entering didKeyFor().");
  var curve = jwk.crv === "P-256" ? "prime256v1" : "secp384r1";
  var codec = jwk.crv === "P-256" ? [0x80, 0x24] : [0x81, 0x24];
  var point = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, "base64url"),
                             Buffer.from(jwk.y, "base64url")]);
  var comp = nodeCrypto.ECDH.convertKey(point, curve, undefined, undefined,
                                        "compressed");
  var mb = "z" + didLib.base58Encode(new Uint8Array(Buffer.concat([
    Buffer.from(codec), comp])));
  log.debug("Leaving didKeyFor().");
  return { did: "did:key:" + mb, vm: "did:key:" + mb + "#" + mb, mb: mb };
}

let EcdsaMultikey;
async function loader(url) {
  log.debug("Entering loader(). " + url);
  if (url === CORPUS_CONTEXT_URL) {
    log.debug("Leaving loader(). Corpus context.");
    return { contextUrl: null, documentUrl: url, document: CORPUS_CONTEXT };
  }
  if (url.indexOf("did:key:") === 0) {
    var did = url.split("#")[0];
    var mb = did.slice(8);
    var key = await EcdsaMultikey.from({ id: did + "#" + mb, controller: did,
                                         publicKeyMultibase: mb });
    var vm = await key.export({ publicKey: true, includeContext: true });
    log.debug("Leaving loader(). did:key.");
    if (url.indexOf("#") !== -1) return { documentUrl: url, document: vm };
    return { documentUrl: url, document: {
      "@context": ["https://www.w3.org/ns/did/v1",
                   "https://w3id.org/security/multikey/v1"],
      id: did, verificationMethod: [vm], assertionMethod: [vm.id] } };
  }
  if (url === "https://www.w3.org/ns/did/v1") {
    log.debug("Leaving loader(). Minimal DID context.");
    return { documentUrl: url, document: { "@context": {
      "@protected": true, id: "@id", type: "@type",
      verificationMethod: { "@id":
        "https://w3id.org/security#verificationMethod", "@type": "@id" },
      assertionMethod: { "@id": "https://w3id.org/security#assertionMethod",
                         "@type": "@id", "@container": "@set" } } } };
  }
  log.debug("Leaving loader(). Shipped.");
  return contexts.documentLoader(url);
}

const VCB_TABLE = new Map([
  ["context", new Map([["https://www.w3.org/ns/credentials/v2", 32768],
                       ["https://w3id.org/vc-barcodes/v1", 32769],
                       ["https://w3id.org/utopia/v2", 32770]])],
  ["https://w3id.org/security#cryptosuiteString", new Map([
    ["ecdsa-rdfc-2019", 1], ["ecdsa-sd-2023", 2], ["eddsa-rdfc-2022", 3],
    ["ecdsa-xi-2023", 4]])]
]);
// A table of this test's own for the corpus, so the url/none byte-string
// forms and the 255 → 00 FF quirk are exercised.
const CORPUS_TABLE = new Map([
  ["context", new Map([["https://www.w3.org/ns/credentials/v2", 40000],
                       [CORPUS_CONTEXT_URL, 40001]])],
  ["url", new Map([["https://test.example/tabled", 255],
                   ["https://test.example/small", 7]])],
  ["none", new Map([["tabled text", 65535]])],
  ["https://w3id.org/security#cryptosuiteString", new Map([
    ["ecdsa-rdfc-2019", 1], ["ecdsa-xi-2023", 4]])]
]);

function tableLoaderFor(id) {
  log.debug("Entering tableLoaderFor(). " + id);
  log.debug("Leaving tableLoaderFor().");
  return id === 100 ? VCB_TABLE : id === 300 ? CORPUS_TABLE : undefined;
}

// ---------------------------------------------------------------------------
// 1. The specification's vectors.
// ---------------------------------------------------------------------------

async function specVectors(theirs) {
  log.debug("Entering specVectors().");
  var cases = [["driver's licence", DL_HEX, 100, DL_OPTICAL],
               ["employment authorization", EAD_HEX, 100, EAD_OPTICAL],
               ["birth certificate", BIRTH_HEX, 1, null]];
  for (var i = 0; i < cases.length; i++) {
    var c = cases[i];
    var bytes = hex(c[1]);
    var ours = await cborld.decode(bytes);
    var lib = await theirs.decode({ cborldBytes: bytes,
      documentLoader: loader, typeTableLoader: function (o) {
        return tableLoaderFor(o.registryEntryId);
      } });
    assert.deepStrictEqual(ours, lib, c[0] + ": decoded as the library " +
                           "decodes it");
    var again = await cborld.encode(ours, { registryEntryId: c[2] });
    assert.strictEqual(Buffer.from(again).toString("hex"),
                       Buffer.from(bytes).toString("hex"),
                       c[0] + ": re-encoded to the printed bytes");
    var r = await di.verifyProof(ours, { extraInformation: c[3] ?
                                         hex(c[3]) : undefined });
    assert.ok(r.valid, c[0] + ": the printed proof verifies: " + r.reason);
    log.info("PASS spec vector, " + c[0] + " (" + bytes.length + " bytes): " +
             "decoded as the library does, re-encoded byte for byte, " +
             "verified.");
  }
  var dl = await vcb.verify(DL_PDF417);
  assert.ok(dl.valid, "the PDF417 text verifies: " + dl.reason);
  assert.deepStrictEqual(dl.protected, ["DAC", "DAQ", "DCS"]);
  assert.strictEqual(dl.canonical, "DACJOHN\nDAQF987654321\nDCSSMITH\n");
  assert.strictEqual(Buffer.from(dl.opticalDataBytes).toString("hex"),
                     DL_OPTICAL, "AAMVA opticalDataBytes are VC Barcodes " +
                     "Example 8's");
  var urlSafe = DL_PDF417.replace(/\//g, "_").replace(/\+/g, "-");
  assert.ok((await vcb.verify(urlSafe)).valid, "the base64url spelling of " +
            "the ZZA field (Example 21) reads too");
  var ead = await vcb.verify(EAD_QR, { printed: { mrz: EAD_MRZ } });
  assert.ok(ead.valid, "the QR text verifies against the MRZ: " + ead.reason);
  assert.strictEqual(Buffer.from(ead.opticalDataBytes).toString("hex"),
                     EAD_OPTICAL, "MRZ opticalDataBytes are Example 15's");
  assert.strictEqual(Buffer.from(ead.cborld).toString("hex").toUpperCase(),
                     EAD_HEX, "the QR text carries the printed CBOR-LD");
  assert.strictEqual(vcb.qrText(hex(EAD_HEX)), EAD_QR,
                     "and the CBOR-LD encodes to the printed QR text");
  var status = vcb.expandStatus(dl.credential.credentialStatus,
                                { listLength: 131072 });
  assert.strictEqual(status.statusListCredential, "https://sandbox.platform." +
    "veres.dev/statuses/z19rJ4oGrbFCqf3cNTVDHSbNd/status-lists/revocation/" +
    "29385", "the terse entry expands as Example 27 does (listLength 2^17)");
  assert.strictEqual(status.statusListIndex, "8321");
  log.info("PASS the PDF417 (both alphabets), the QR text, both " +
           "opticalDataBytes and the terse status expansion are the " +
           "specification's.");
  log.debug("Leaving specVectors().");
}

// ---------------------------------------------------------------------------
// 2. CBOR-LD against the library.
// ---------------------------------------------------------------------------

function corpus() {
  log.debug("Entering corpus().");
  var ctx = ["https://www.w3.org/ns/credentials/v2", CORPUS_CONTEXT_URL];
  var docs = [
    { "@context": ctx, id: "urn:uuid:188e8450-269e-11eb-b545-d3692cf35398",
      type: ["VerifiableCredential", "Widget"],
      issuer: "did:key:zDnaeWjKfs1ob9QcgasjYSPEMkwq31hmvSAWPVAgnrt1e9GKj",
      validFrom: "2024-01-02T03:04:05Z", validUntil: "2030-01-01T00:00:00.123Z",
      credentialSubject: { id: "https://test.example/tabled",
        born: "1988-04-19", seen: "2024-05-06T07:08:09Z",
        link: ["https://test.example/small", "http://test.example/plain",
               "data:text/plain;base64,SGVsbG8=", "data:,raw%20text",
               "did:key:zDnaeZSD9XcuULaS8qmgDUa6TMg2QjF9xABnZK42awDH3BEzj" +
               "#zDnaeZSD9XcuULaS8qmgDUa6TMg2QjF9xABnZK42awDH3BEzj",
               "urn:uuid:188E8450-269E-11EB-B545-D3692CF35398",
               "https://host.example:8443/port"],
        kind: "Widget", digest: ["zQmP", "uAQID", "MAQID"],
        count: 255, ratio: 0.5, flag: true, label: "tabled text",
        part: "https://test.example/part/1", weight: 1.25,
        holder: { alias: "w", since: "2020-02-29T12:00:00Z" } } },
    { "@context": ctx, type: "VerifiableCredential",
      credentialSubject: [{ count: -7, ratio: 3.14159, label: "a" },
                          { count: 0, label: null }],
      proof: { type: "DataIntegrityProof", cryptosuite: "ecdsa-rdfc-2019",
        created: "2025-12-31T23:59:59Z", proofPurpose: "assertionMethod",
        verificationMethod: "https://test.example/keys#1",
        proofValue: "z3FXQjecWufY46yg5abdVZsXqLhxhueuSoZgNSARiKBk9czhSePTF" +
          "ehP8c3PGfb6a22gkfUKKiBGDhbENGHGbAgr" } }
  ];
  log.debug("Leaving corpus().");
  return docs;
}

async function cborldBothWays(theirs) {
  log.debug("Entering cborldBothWays().");
  var docs = corpus();
  var opts = { documentLoader: loader, typeTableLoader: function (o) {
    return tableLoaderFor(o.registryEntryId);
  } };
  var entries = [300, 1, 0];
  for (var i = 0; i < docs.length; i++) {
    for (var j = 0; j < entries.length; j++) {
      var id = entries[j];
      var label = "corpus " + i + ", entry " + id;
      var lib = Buffer.from(await theirs.encode(Object.assign({
        jsonldDocument: docs[i], registryEntryId: id }, opts)));
      var ours = Buffer.from(await cborld.encode(docs[i], {
        registryEntryId: id, documentLoader: loader,
        typeTable: id === 300 ? CORPUS_TABLE : undefined }));
      assert.strictEqual(ours.toString("hex"), lib.toString("hex"),
                         label + ": the same bytes as the library");
      var back = await cborld.decode(new Uint8Array(lib), {
        documentLoader: loader,
        typeTable: id === 300 ? CORPUS_TABLE : undefined });
      var libBack = await theirs.decode(Object.assign({
        cborldBytes: new Uint8Array(lib) }, opts));
      assert.deepStrictEqual(back, libBack, label + ": decoded as the " +
                             "library decodes it");
    }
    for (const format of ["legacy-range", "legacy-singleton"]) {
      var legacyOpts = format === "legacy-singleton" ?
          { appContextMap: new Map([[CORPUS_CONTEXT_URL, 32769]]) } :
          { registryEntryId: 300, typeTableLoader: opts.typeTableLoader };
      var old = Buffer.from(await theirs.encode(Object.assign({
        jsonldDocument: docs[i], format: format,
        documentLoader: loader }, legacyOpts)));
      var mine = Buffer.from(await cborld.encode(docs[i], Object.assign({
        format: format, documentLoader: loader,
        typeTable: format === "legacy-range" ? CORPUS_TABLE : undefined },
        legacyOpts)));
      assert.strictEqual(mine.toString("hex"), old.toString("hex"),
                         "corpus " + i + ", " + format + ": the library's " +
                         "bytes");
      assert.deepStrictEqual(await cborld.decode(new Uint8Array(old),
        Object.assign({ documentLoader: loader,
          typeTable: format === "legacy-range" ? CORPUS_TABLE : undefined },
          legacyOpts)),
        await theirs.decode(Object.assign({ cborldBytes: new Uint8Array(old),
          documentLoader: loader }, legacyOpts)),
        "corpus " + i + ", " + format + ": decoded as the library does");
    }
  }
  log.info("PASS CBOR-LD: " + docs.length + " documents through every " +
           "codec, entries 300 (a test table), 1 and 0 and both legacy " +
           "framings — the library's bytes, and the library's reading.");
  log.debug("Leaving cborldBothWays().");
}

// ---------------------------------------------------------------------------
// 3. ecdsa-xi-2023 both ways.
// ---------------------------------------------------------------------------

async function xiBothWays(theirs) {
  log.debug("Entering xiBothWays().");
  var jsigs = await import("jsonld-signatures");
  jsigs = jsigs.default || jsigs;
  var Purpose = jsigs.purposes.AssertionProofPurpose;
  var { DataIntegrityProof } = await import("@digitalbazaar/data-integrity");
  var xi = await import("@digitalbazaar/ecdsa-xi-2023-cryptosuite");
  var printedSets = [
    [vcb.MRZ, { mrz: EAD_MRZ }, {}],
    [vcb.AAMVA, { aamva: DL_PDF417 }, { protect: ["DAC", "DBB", "DCS"] }]];
  for (const crv of ["P-256", "P-384"]) {
    var jwk = nodeCrypto.generateKeyPairSync("ec", { namedCurve: crv })
      .privateKey.export({ format: "jwk" });
    var k = didKeyFor(jwk);
    for (const set of printedSets) {
      var label = crv + " " + set[0];
      var unsigned = vcb.credentialTemplate(Object.assign({ issuer: k.did,
        subjectType: set[0], status: {
          terseStatusListBaseUrl: "https://status.example/lists",
          terseStatusListIndex: 3851559041 } }, set[2]));
      var issued = await vcb.issue(unsigned, { privateJwk: jwk,
        verificationMethod: k.vm, printed: set[1] });
      var decoded = await theirs.decode({ cborldBytes: issued.cborld,
        documentLoader: loader, typeTableLoader: function (o) {
          return tableLoaderFor(o.registryEntryId);
        } });
      assert.deepStrictEqual(decoded, issued.credential, label + ": the " +
                             "library decodes our barcode to our credential");
      var suite = new DataIntegrityProof({ cryptosuite: xi.createCryptosuite({
        extraInformation: issued.opticalDataBytes }) });
      var v = await jsigs.verify(decoded, { suite: suite,
        purpose: new Purpose(), documentLoader: loader });
      assert.ok(v.verified, label + ": the library verifies our " +
                "ecdsa-xi-2023 proof: " + JSON.stringify(v.error));
      var signer = await EcdsaMultikey.fromJwk({ jwk: jwk, secretKey: true,
        id: k.vm, controller: k.did });
      var theirSuite = new DataIntegrityProof({ signer: signer.signer(),
        date: null, cryptosuite: xi.createCryptosuite({
          extraInformation: issued.opticalDataBytes }) });
      var theirsSigned = await jsigs.sign(unsigned, { suite: theirSuite,
        purpose: new Purpose(), documentLoader: loader });
      var theirBytes = await theirs.encode({ jsonldDocument: theirsSigned,
        registryEntryId: 100, documentLoader: loader,
        typeTableLoader: function (o) {
          return tableLoaderFor(o.registryEntryId);
        } });
      var text = set[0] === vcb.MRZ ? vcb.qrText(theirBytes) :
          vcb.pdf417FieldText(theirBytes);
      var mine = await vcb.verify(text, { printed: set[1] });
      assert.ok(mine.valid, label + ": the library's barcode verifies " +
                "here: " + mine.reason);
      log.info("PASS ecdsa-xi-2023 " + label + ": ours verified by the " +
               "library (" + issued.cborld.length + " bytes), the library's " +
               "verified here.");
    }
  }
  log.debug("Leaving xiBothWays().");
}

// ---------------------------------------------------------------------------
// 4. What must fail, and 5. base45.
// ---------------------------------------------------------------------------

async function refusals() {
  log.debug("Entering refusals().");
  var changed = await vcb.verify(EAD_QR, { printed: { mrz: [EAD_MRZ[0],
    EAD_MRZ[1], EAD_MRZ[2].replace("JOHN", "JANE")] } });
  assert.ok(!changed.valid, "a different MRZ under the same barcode fails");
  var forged = DL_PDF417.replace("DACJOHN", "DACJANE");
  assert.ok(!(await vcb.verify(forged)).valid, "a protected AAMVA field " +
            "changed fails");
  var unprotected = DL_PDF417.replace("DAYBRO", "DAYBLU");
  assert.ok((await vcb.verify(unprotected)).valid, "an UNprotected field " +
            "(DAY) changed still verifies — which is what the index means");
  assert.throws(function () {
    vcb.protectedComponents("uggAh");
  }, /padding/, "padding bits set in the index are refused");
  assert.throws(function () {
    vcb.fromQrText("VC1-0OR*W3");
  }, /VC1-R/, "a QR text without the multibase R is refused");
  assert.throws(function () {
    vcb.base45Decode("ABCD");
  }, /multiple of three/, "a base45 length of 3k + 1 is refused");
  assert.throws(function () {
    vcb.base45Decode(":::");
  }, /65535/, "a base45 triple above 65535 is refused");
  await assert.rejects(cborld.decode(hex("D9CB1D821864A1190FA001")),
                       /term id 4000/, "a term id no context defines is " +
                       "refused by number");
  assert.throws(function () {
    cborld.parse(hex("D8FA00"));
  }, /not a CBOR-LD tag/, "another tag is not CBOR-LD");
  log.info("PASS refusals: changed MRZ, changed protected field (and an " +
           "unprotected change that must verify), index padding, missing " +
           "multibase prefix, both base45 malformations, an unknown term " +
           "id and a foreign tag.");
  // RFC 9285 section 4.
  [["AB", "BB8"], ["Hello!!", "%69 VD92EX0"], ["base-45", "UJCLQE7W581"],
   ["ietf!", "QED8WEX0"]].forEach(function (v) {
    assert.strictEqual(vcb.base45Encode(Buffer.from(v[0])), v[1],
                       "base45(" + v[0] + ")");
    assert.strictEqual(Buffer.from(vcb.base45Decode(v[1])).toString(), v[0],
                       "base45 decode of " + v[1]);
  });
  log.info("PASS base45: RFC 9285 section 4's four examples, both ways.");
  log.debug("Leaving refusals().");
}

// ---------------------------------------------------------------------------
// 6. IsoDrivingLicenceMachineReadableInformation (Appendix B).
// ---------------------------------------------------------------------------

// A licence's data groups. DG2 carries bytes above 0x7f so its base64url
// has the two characters base64 does not ("-" and "_"); DG3 is never
// protected, so it may change.
const ISO_GROUPS = {
  DG1: "UTO\x1dSMITH\x1dJOHN\x1d19880419\x1d20240101\x1d20300419\x1d" +
    "UTOPIA DMV\x1dF987654321",
  DG2: Buffer.from("fbff3ec0fe7f00ff", "hex"),
  DG3: "BRO\x1d069",
  DG10: "ENDORSEMENTS:NONE"
};
const ISO_PROTECT = ["DG1", "DG2", "DG10"];
// What Appendix B.2 makes of them, pinned (computed once by
// isoCanonicalByHand() below and checked against it every run).
const ISO_CANONICAL = "DG1VVRPHVNNSVRIHUpPSE4dMTk4ODA0MTkdMjAyNDAxMDEdMjAzMD" +
  "A0MTkdVVRPUElBIERNVh1GOTg3NjU0MzIx\nDG2-_8-wP5_AP8\n" +
  "DG10RU5ET1JTRU1FTlRTOk5PTkU\n";
// An ISO barcode made ENTIRELY by Digital Bazaar's libraries — signed with
// ecdsa-xi-2023-cryptosuite over ISO_OPTICAL and encoded with cborld, on a
// throwaway P-256 key — once, so a fixed ISO vector exists for this file and
// the page's example link to hold to. The private key was
// discarded; the did:key is in the credential.
const ISO_EXAMPLE_DG11 =
  "2csdghhkpQGDGYAAGYABoXgrSXNvRHJpdmluZ0xpY2VuY2VNYWNoaW5lUmVhZGFi" +
  "bGVJbmZvcm1hdGlvbnhIaHR0cHM6Ly93M2lkLm9yZy92Yy1iYXJjb2RlcyNJc29E" +
  "cml2aW5nTGljZW5jZU1hY2hpbmVSZWFkYWJsZUluZm9ybWF0aW9uGJ2CGHYYpBiy" +
  "ohicGKoYqEN1wEAYtoIZBAFYI4AkA7PTi9n4hQNhmVLLNdlG_QSgSyjM9MHACH_9" +
  "_bkzc0w3GLilGJwYbBjKBBjUGNoY1lhBeoKm-_CqGFQs0Qvw5p1jsrq1tCQEPcoo" +
  "f9GH3QtlwwSJaP19j3O0d3_psG2eHyuR5fUO4eyQ3_G8joaJ9FYfotMY2IMZBAFY" +
  "I4AkA7PTi9n4hQNhmVLLNdlG_QSgSyjM9MHACH_9_bkzc0w3WCOAJAOz04vZ-IUD" +
  "YZlSyzXZRv0EoEsozPTBwAh__f25M3NMNw";
const ISO_OPTICAL = "58af2a194288b9b0270607ad67d1cbb5b7fb79dc4396f93623a0" +
  "4d5e1c11facd";

function isoGroupBytes(groups) {
  log.debug("Entering isoGroupBytes().");
  var out = {};
  Object.keys(groups).forEach(function (k) {
    out[k] = new Uint8Array(Buffer.from(groups[k]));
  });
  log.debug("Leaving isoGroupBytes().");
  return out;
}

// Appendix B.2 spelled out independently: "DGn" + base64url(contents) +
// "\n" for each protected group, in data-group NUMBER order.
function isoCanonicalByHand(groups, names) {
  log.debug("Entering isoCanonicalByHand().");
  var order = names.slice().sort(function (a, b) {
    return Number(a.slice(2)) - Number(b.slice(2));
  });
  log.debug("Leaving isoCanonicalByHand().");
  return order.map(function (n) {
    return n + Buffer.from(groups[n]).toString("base64url") + "\n";
  }).join("");
}

async function isoLicence(theirs) {
  log.debug("Entering isoLicence().");
  var index = vcb.isoComponentIndex(ISO_PROTECT);
  // DG1 = bit 0, DG2 = bit 1, DG10 = bit 9: C0 40.
  assert.strictEqual(index, "u" + Buffer.from([0xc0, 0x40])
                     .toString("base64url"), "the 2-byte index");
  assert.strictEqual(index.length, 4, "\"a total of 4 characters\"");
  assert.deepStrictEqual(vcb.isoProtectedGroups(index), ISO_PROTECT);
  var groups = isoGroupBytes(ISO_GROUPS);
  var canonical = vcb.isoCanonical(groups, index);
  var byHand = isoCanonicalByHand(ISO_GROUPS, ISO_PROTECT);
  assert.strictEqual(canonical, byHand, "Appendix B.2's components");
  assert.strictEqual(canonical, ISO_CANONICAL, "the pinned vector");
  assert.ok(canonical.indexOf("DG2") < canonical.indexOf("DG10"),
            "numeric, not code-point, order");
  assert.ok(/[-_]/.test(canonical.split("\n")[1]), "base64url, not base64");
  var text = vcb.formatIsoDataGroups(groups);
  assert.deepStrictEqual(vcb.parseIsoDataGroups(text), groups,
                         "the text form reads back to the same bytes");
  var opticalHex = nodeCrypto.createHash("sha256").update(byHand)
    .digest("hex");
  assert.strictEqual(opticalHex, ISO_OPTICAL, "the pinned opticalDataBytes");
  var example = vcb.formatIsoDataGroups(groups) + "\nDG11: " +
      ISO_EXAMPLE_DG11;
  var ex = await vcb.verify(example);
  assert.ok(ex.valid, "the library-made ISO example verifies: " + ex.reason);
  assert.strictEqual(Buffer.from(ex.opticalDataBytes).toString("hex"),
                     ISO_OPTICAL);
  log.info("ISO vector: index " + index + ", canonical " +
           JSON.stringify(canonical) + ", opticalDataBytes " + opticalHex);

  var jsigs = await import("jsonld-signatures");
  jsigs = jsigs.default || jsigs;
  var Purpose = jsigs.purposes.AssertionProofPurpose;
  var { DataIntegrityProof } = await import("@digitalbazaar/data-integrity");
  var xi = await import("@digitalbazaar/ecdsa-xi-2023-cryptosuite");
  var tableLoader = function tableLoader(o) {
    log.debug("Entering tableLoader().");
    log.debug("Leaving tableLoader().");
    return tableLoaderFor(o.registryEntryId);
  };
  for (const crv of ["P-256", "P-384"]) {
    var jwk = nodeCrypto.generateKeyPairSync("ec", { namedCurve: crv })
      .privateKey.export({ format: "jwk" });
    var k = didKeyFor(jwk);
    var unsigned = vcb.credentialTemplate({ issuer: k.did,
      subjectType: vcb.ISO_IDL, protect: ISO_PROTECT });
    var issued = await vcb.issue(unsigned, { privateJwk: jwk,
      verificationMethod: k.vm, printed: { iso: groups } });
    assert.strictEqual(issued.carrier, "dg11");
    assert.strictEqual(issued.canonical, byHand);
    assert.strictEqual(Buffer.from(issued.opticalDataBytes).toString("hex"),
                       opticalHex, crv + ": opticalDataBytes");
    var libBytes = Buffer.from(await theirs.encode({
      jsonldDocument: issued.credential, registryEntryId: 100,
      documentLoader: loader, typeTableLoader: tableLoader }));
    assert.strictEqual(Buffer.from(issued.cborld).toString("hex"),
                       libBytes.toString("hex"), crv + ": the library " +
                       "writes the same CBOR-LD, inline context and all");
    var decoded = await theirs.decode({ cborldBytes: issued.cborld,
      documentLoader: loader, typeTableLoader: tableLoader });
    assert.deepStrictEqual(decoded, issued.credential);
    var v = await jsigs.verify(decoded, { suite: new DataIntegrityProof({
      cryptosuite: xi.createCryptosuite({ extraInformation: new Uint8Array(
        Buffer.from(opticalHex, "hex")) }) }),
      purpose: new Purpose(), documentLoader: loader });
    assert.ok(v.verified, crv + ": the library verifies our ISO barcode " +
              "over the same optical data: " + JSON.stringify(v.error));
    var licence = vcb.formatIsoDataGroups(vcb.withVcbInDg11(groups,
                                                            issued.text));
    var mine = await vcb.verify(licence);
    assert.ok(mine.valid, crv + ": ours, from DG11: " + mine.reason);
    assert.deepStrictEqual(mine.protected, ISO_PROTECT);
    var signer = await EcdsaMultikey.fromJwk({ jwk: jwk, secretKey: true,
      id: k.vm, controller: k.did });
    var theirsSigned = await jsigs.sign(unsigned, { suite:
      new DataIntegrityProof({ signer: signer.signer(), date: null,
        cryptosuite: xi.createCryptosuite({ extraInformation:
          new Uint8Array(Buffer.from(opticalHex, "hex")) }) }),
      purpose: new Purpose(), documentLoader: loader });
    var theirBytes = await theirs.encode({ jsonldDocument: theirsSigned,
      registryEntryId: 100, documentLoader: loader,
      typeTableLoader: tableLoader });
    var theirLicence = vcb.formatIsoDataGroups(vcb.withVcbInDg11(groups,
      vcb.pdf417FieldText(theirBytes)));
    var r = await vcb.verify(theirLicence);
    assert.ok(r.valid, crv + ": the library's ISO barcode verifies here: " +
              r.reason);
    // DG2 protected and changed: fails. DG3 unprotected and changed: not.
    var forged = Object.assign({}, groups, { DG2: new Uint8Array([1]) });
    assert.ok(!(await vcb.verify(vcb.formatIsoDataGroups(vcb.withVcbInDg11(
      forged, issued.text)))).valid, crv + ": a changed protected group");
    var moved = Object.assign({}, groups, { DG3: new Uint8Array([2]) });
    assert.ok((await vcb.verify(vcb.formatIsoDataGroups(vcb.withVcbInDg11(
      moved, issued.text)))).valid, crv + ": an unprotected group changed " +
      "still verifies");
    log.info("PASS ISO " + crv + ": ours verified by the library (" +
             issued.cborld.length + " bytes in DG11), the library's verified " +
             "here; a protected group changed fails, an unprotected one " +
             "does not.");
  }
  assert.throws(function () {
    vcb.credentialTemplate({ issuer: "did:example:x", subjectType: vcb.ISO_IDL,
                             protect: ["DG1", "DG11"] });
  }, /DG11 cannot be protected/, "DG11 carries the VCB, so it is not " +
  "protected");
  assert.throws(function () {
    vcb.isoProtectedGroups("u" + Buffer.from([0xc0, 0x41])
                           .toString("base64url"));
  }, /padding/, "the five padding bits must be 0");
  assert.throws(function () {
    vcb.isoProtectedGroups("uwAAA");
  }, /4 characters/, "a 3-byte (AAMVA) index is not an ISO one");
  assert.throws(function () {
    vcb.parseIsoDataGroups("DG12: x");
  }, /DG1\.\.DG11/, "DG12 is not a data group");
  log.info("PASS ISO refusals: DG11 protected, padding bits, a 3-byte " +
           "index, DG12.");
  log.debug("Leaving isoLicence().");
}

// ---------------------------------------------------------------------------
// 7. The status list a terse entry expands to.
// ---------------------------------------------------------------------------

// MSB-first packing (Bitstring Status List v1.0 section 3.2) and GZIP, done
// here rather than by either implementation under test.
function packList(length, set) {
  log.debug("Entering packList().");
  var bits = Buffer.alloc(length / 8);
  set.forEach(function (i) {
    bits[i >> 3] |= 0x80 >> (i & 7);
  });
  log.debug("Leaving packList().");
  return "u" + zlib.gzipSync(bits).toString("base64url");
}

async function statusLists() {
  log.debug("Entering statusLists().");
  var bsl = await import("@digitalbazaar/vc-bitstring-status-list");
  var { DataIntegrityProof } = await import("@digitalbazaar/data-integrity");
  var ecdsaRdfc = (await import(
    "@digitalbazaar/ecdsa-rdfc-2019-cryptosuite")).cryptosuite;
  var jsigs = await import("jsonld-signatures");
  jsigs = jsigs.default || jsigs;
  var dl = await vcb.verify(DL_PDF417);
  var entry = vcb.expandStatus(dl.credential.credentialStatus,
                               { listLength: 131072 });
  var url = entry.statusListCredential;
  var jwk = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" })
    .privateKey.export({ format: "jwk" });
  var k = didKeyFor(jwk);
  var signer = await EcdsaMultikey.fromJwk({ jwk: jwk, secretKey: true,
    id: k.vm, controller: k.did });
  var served = {};
  var fetchText = async function fetchText(u) {
    log.debug("Entering fetchText(). " + u);
    if (!served[u]) {
      log.debug("Leaving fetchText(). Not served.");
      throw new Error("404 " + u);
    }
    log.debug("Leaving fetchText().");
    return JSON.stringify(served[u]);
  };
  var docLoader = async function docLoader(u) {
    log.debug("Entering docLoader(). " + u);
    if (served[u]) {
      log.debug("Leaving docLoader(). Served.");
      return { documentUrl: u, document: served[u] };
    }
    log.debug("Leaving docLoader().");
    return loader(u);
  };

  // The library's list, signed with the library's suite, read here.
  var list = await bsl.createList({ length: 131072 });
  list.setStatus(Number(entry.statusListIndex), true);
  var unsignedList = await bsl.createCredential({ id: url, list: list,
    statusPurpose: "revocation" });
  unsignedList.issuer = k.did;
  served[url] = await jsigs.sign(unsignedList, { suite:
    new DataIntegrityProof({ signer: signer.signer(),
                             cryptosuite: ecdsaRdfc }),
    purpose: new jsigs.purposes.AssertionProofPurpose(),
    documentLoader: docLoader });
  var r = await vpVerifier.checkBitstringStatus(entry, { fetchText: fetchText,
    issuer: k.did });
  assert.strictEqual(r.value, 1, "entry 8321 is set: " +
                     JSON.stringify(r.checks));
  assert.ok(r.trusted, "the library's list verifies here");
  var verdict = r.checks.filter(function (c) {
    return c.id === "status";
  })[0];
  assert.strictEqual(verdict.status, "fail");
  assert.ok(/revoked/.test(verdict.detail), verdict.detail);
  var clear = Object.assign({}, entry, { statusListIndex: "8320" });
  r = await vpVerifier.checkBitstringStatus(clear, { fetchText: fetchText });
  assert.strictEqual(r.value, 0, "entry 8320 is clear");
  log.info("PASS status: the library's BitstringStatusListCredential (" +
           "ecdsa-rdfc-2019) at the expanded URL verifies here; entry 8321 " +
           "is revoked and 8320 is not.");

  // Ours: packed here, signed with data_integrity.js, read by the library.
  var ourUrl = url.replace(/\/29385$/, "/29386");
  served[ourUrl] = await di.createProof({ "@context":
    ["https://www.w3.org/ns/credentials/v2"], id: ourUrl,
    type: ["VerifiableCredential", "BitstringStatusListCredential"],
    issuer: k.did, credentialSubject: { id: ourUrl + "#list",
      type: "BitstringStatusList", statusPurpose: "revocation",
      encodedList: packList(131072, [5, 131071]) } }, {
    suite: "ecdsa-rdfc-2019", privateJwk: jwk, verificationMethod: k.vm,
    proofPurpose: "assertionMethod", documentLoader: docLoader });
  for (const idx of [5, 6, 131071]) {
    var holderVc = { "@context": ["https://www.w3.org/ns/credentials/v2"],
      type: ["VerifiableCredential"], issuer: k.did,
      credentialSubject: {
        id: "urn:uuid:4ab1e1c8-0000-4000-8000-000000000001" },
      credentialStatus: Object.assign({}, entry, {
        statusListCredential: ourUrl, statusListIndex: String(idx) }) };
    var theirs = await bsl.checkStatus({ credential: holderVc,
      documentLoader: docLoader, suite: new DataIntegrityProof({
        cryptosuite: ecdsaRdfc }), verifyMatchingIssuers: true });
    assert.ok(theirs.verified, "the library accepts our list: " +
              (theirs.error && theirs.error.message));
    assert.strictEqual(theirs.results[0].status, idx !== 6,
                       "the library reads bit " + idx);
    var ours = await vpVerifier.checkBitstringStatus(
      holderVc.credentialStatus, { fetchText: fetchText });
    assert.strictEqual(ours.value, idx !== 6 ? 1 : 0, "and so do we");
  }
  log.info("PASS status: a list packed and signed here is accepted by the " +
           "library's checkStatus(), which reads bits 5, 6 and 131071 as " +
           "this does.");

  // Changed after signing: the bit is read and not relied on.
  served[url] = JSON.parse(JSON.stringify(served[url]));
  served[url].credentialSubject.encodedList = packList(131072, []);
  r = await vpVerifier.checkBitstringStatus(entry, { fetchText: fetchText });
  assert.ok(!r.trusted, "a tampered list does not verify");
  assert.strictEqual(r.checks.filter(function (c) {
    return c.id === "status";
  })[0].status, "skip", "and its bit is not relied on");
  assert.ok(r.checks.some(function (c) {
    return c.id === "status.list" && c.status === "fail";
  }), "the list check fails");
  log.info("PASS status: a list changed after signing fails its proof and " +
           "its bit is not relied on.");
  log.debug("Leaving statusLists().");
}

// ---------------------------------------------------------------------------
// 8. PDF417.
// ---------------------------------------------------------------------------

// The symbol's modules as a picture: `scale` pixels a module, a quiet zone,
// one luminance byte a pixel.
function rasterise(m, scale, quiet) {
  log.debug("Entering rasterise(). " + scale);
  var w = m.width * scale + 2 * quiet;
  var h = m.height * scale + 2 * quiet;
  var lum = new Uint8ClampedArray(w * h).fill(255);
  for (var y = 0; y < m.height; y++) {
    for (var x = 0; x < m.width; x++) {
      if (!m.dark[y * m.width + x]) {
        continue;
      }
      for (var dy = 0; dy < scale; dy++) {
        var row = (quiet + y * scale + dy) * w + quiet + x * scale;
        lum.fill(0, row, row + scale);
      }
    }
  }
  log.debug("Leaving rasterise().");
  return { lum: lum, w: w, h: h };
}

async function pdf417RoundTrip() {
  log.debug("Entering pdf417RoundTrip().");
  var m = pdf417.symbolModules(DL_PDF417);
  for (const scale of [2, 3, 5]) {
    var px = rasterise(m, scale, 12);
    var text = pdf417.readSymbol(px.lum, px.w, px.h);
    assert.strictEqual(text, DL_PDF417, "scale " + scale + ": the symbol " +
                       "reads back to the specification's PDF417 text");
  }
  var back = await vcb.verify(pdf417.readSymbol(rasterise(m, 3, 12).lum,
    m.width * 3 + 24, m.height * 3 + 24));
  assert.ok(back.valid, "the text read from the symbol verifies: " +
            back.reason);
  var svg = pdf417.symbolSvg(DL_PDF417);
  var sized = new RegExp("^<svg width=\"\\d+\" height=\"\\d+\" " +
                         "viewBox=\"0 0 \\d+ \\d+\" xmlns=\"http://" +
                         "www.w3.org/2000/svg\"");
  assert.ok(sized.test(svg), "an SVG document with its own size: " +
            svg.slice(0, 90));
  assert.ok(svg.indexOf("ANSI") === -1 && svg.indexOf("DAQ") === -1,
            "the SVG carries modules, not the text");
  // Most of the symbol painted over: nothing is read, and nothing wrong.
  var damaged = rasterise(m, 3, 12);
  damaged.lum.fill(255, 0, Math.floor(damaged.lum.length * 0.8));
  assert.strictEqual(pdf417.readSymbol(damaged.lum, damaged.w, damaged.h),
                     null, "a symbol too damaged to read reads as none");
  assert.throws(function () {
    pdf417.symbolSvg("\u20ac");
  }, /not a byte/, "a character above U+00FF is refused");
  log.info("PASS PDF417: the specification's licence text drawn with " +
           pdf417.ENCODER + " (" + m.width + "x" + m.height + " modules, EC " +
           "level " + pdf417.EC_LEVEL + ") reads back with " + pdf417.DECODER +
           " at three scales and verifies; a damaged symbol reads as none.");
  log.debug("Leaving pdf417RoundTrip().");
}

async function main() {
  log.debug("Entering main().");
  EcdsaMultikey = await import("@digitalbazaar/ecdsa-multikey");
  var theirs = await import("@digitalbazaar/cborld");
  await specVectors(theirs);
  await cborldBothWays(theirs);
  await xiBothWays(theirs);
  await refusals();
  await isoLicence(theirs);
  await statusLists();
  await pdf417RoundTrip();
  log.info("vc_barcodes_engine: all checks passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("FAILED: " + (e && e.stack || e));
  process.exitCode = 1;
});
