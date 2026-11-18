// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: vc_barcodes_qr.js
//
// ---------------------------------------------------------------------------
// The QR encode/decode machinery for the VC Barcodes page, in a bundle of its
// own so `vc_barcodes_page.js` does not carry it.
//
// qrcode-generator (QR ENCODE) and jsqr (QR DECODE) are heavy — jsqr alone is
// ~250 KB — and are needed only when the page actually renders a QR code or
// reads one out of a picture. Bundling them into the page bundle made it ~300
// KB larger for every visit, QR or not. This bundle is loaded by the page on
// demand (vc_barcodes_page.js's ensureQrCodecs()), from the same origin, so a
// static deployment still works offline: the file ships beside the page and is
// fetched the first time a QR action runs.
//
// It is a leaf re-export with no DOM, no storage and no configuration;
// `--standalone vcbarcodesqr` makes `window.vcbarcodesqr` the object below.
// ---------------------------------------------------------------------------
var qrcode = require("qrcode-generator");
var jsQR = require("jsqr");

module.exports = { qrcode: qrcode, jsQR: jsQR };
