// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vc_barcodes_qr.js
//
// ---------------------------------------------------------------------------
// The QR and PDF417 encode/decode machinery for the VC Barcodes page, in a
// bundle of its own so `vc_barcodes_page.js` does not carry it.
//
// qrcode-generator (QR ENCODE), jsqr (QR DECODE) and pdf417.js (PDF417 encode
// and decode, over bwip-js and @zxing/library) are heavy — jsqr alone is
// ~250 KB, and @zxing's PDF417 reader and bwip-js add more — and are needed
// only when the page actually renders a QR code or a PDF417 symbol or reads
// one out of a picture. Bundling them into the page bundle made it ~300 KB
// larger for every visit, QR or not. This bundle is loaded by the page on
// demand (vc_barcodes_page.js's ensureQrCodecs()), from the same origin, so a
// static deployment still works offline: the file ships beside the page and is
// fetched the first time a QR or PDF417 action runs.
//
// It is a leaf re-export with no DOM, no storage and no configuration;
// `--standalone vcbarcodesqr` makes `window.vcbarcodesqr` the object below.
// `pdf417` is the whole pdf417.js module, so the page reaches its functions
// (readSymbol, luminanceOf, symbolSvg) and its constants (ENCODER, DECODER,
// EC_LEVEL) through codecs.pdf417.
// ---------------------------------------------------------------------------
var qrcode = require("qrcode-generator");
var jsQR = require("jsqr");
var pdf417 = require("./pdf417");

module.exports = { qrcode: qrcode, jsQR: jsQR, pdf417: pdf417 };
