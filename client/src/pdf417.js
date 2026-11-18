// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: pdf417.js
//
// ---------------------------------------------------------------------------
// PDF417 (ISO/IEC 15438) symbols for the VC Barcodes page (#480): drawing
// the AAMVA licence text — with the credential in subfile ZZ — as a symbol,
// and reading the text back out of a picture of one. Both halves are
// released pure-JavaScript libraries, used as they ship:
//   * bwip-js 4.11.4 (MIT), the encoder: Barcode Writer in Pure PostScript
//     translated to JavaScript;
//   * @zxing/library 0.23.0 (Apache-2.0), the decoder: ZXing's Java
//     PDF417Reader ported to TypeScript. Only the reader's own modules are
//     required, not the package index, so the bundle carries no QR, Aztec,
//     Data Matrix or 1-D readers it would never use.
//
// AAMVA DL/ID Card Design Standard (2020) Annex D asks for error correction
// level 3 at least and recommends 5; this draws at 5. The text is handed to
// the encoder as it is, so its control characters (LF, RS, CR) are symbol
// data like any other byte.
//
// NO DOM: the caller turns a picture into luminance (one byte per pixel)
// and puts the SVG somewhere. tests/vc_barcodes_engine.js runs the round
// trip in node; tests/vc_barcodes_browser.js through the page's file input.
// ---------------------------------------------------------------------------

var bwipjs = require("bwip-js");
var PDF417Reader = require("@zxing/library/cjs/core/pdf417/PDF417Reader")
  .default;
var BinaryBitmap = require("@zxing/library/cjs/core/BinaryBitmap").default;
var HybridBinarizer = require(
  "@zxing/library/cjs/core/common/HybridBinarizer").default;
var RGBLuminanceSource = require(
  "@zxing/library/cjs/core/RGBLuminanceSource").default;
var DecodeHintType = require("@zxing/library/cjs/core/DecodeHintType")
  .default;

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "pdf417",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var EC_LEVEL = 5;
var COLUMNS = 13;
var ENCODER = "bwip-js " + (bwipjs.BWIPJS_VERSION || "4.11.4");
var DECODER = "@zxing/library 0.23.0";

function encoderOptions(text, opts) {
  log.debug("Entering encoderOptions().");
  var o = opts || {};
  var s = String(text === undefined || text === null ? "" : text);
  if (!s.length) {
    log.debug("Leaving encoderOptions(). Empty.");
    throw new Error("there is no text to draw as a PDF417 symbol.");
  }
  for (var i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) > 0xff) {
      log.debug("Leaving encoderOptions(). Not one byte per character.");
      throw new Error("character " + i + " (U+" + s.charCodeAt(i)
        .toString(16).toUpperCase() + ") is not a byte; AAMVA PDF417 text " +
        "is ASCII.");
    }
  }
  log.debug("Leaving encoderOptions().");
  return { bcid: "pdf417", text: s, eclevel: o.eclevel || EC_LEVEL,
           columns: o.columns || COLUMNS, scale: o.scale || 3,
           paddingwidth: 10, paddingheight: 10, backgroundcolor: "FFFFFF" };
}

// The symbol as an SVG document: rectangles drawn from the modules alone,
// so nothing of the text reaches the markup. bwip-js writes only a viewBox;
// the width and height are added so that an image decoder (a browser's
// <img>, the page's own reader) draws it at its own size and aspect.
function symbolSvg(text, opts) {
  log.debug("Entering symbolSvg().");
  var svg = bwipjs.toSVG(encoderOptions(text, opts)).replace(
    /^<svg viewBox="0 0 (\d+) (\d+)"/, function (m, w, h) {
      return "<svg width=\"" + w + "\" height=\"" + h + "\" viewBox=\"0 0 " +
        w + " " + h + "\"";
    });
  log.debug("Leaving symbolSvg(). " + svg.length + " characters.");
  return svg;
}

// The symbol's modules: { width, height, dark (Uint8Array, 1 = bar) }.
function symbolModules(text, opts) {
  log.debug("Entering symbolModules().");
  var o = encoderOptions(text, opts);
  delete o.scale;
  delete o.paddingwidth;
  delete o.paddingheight;
  delete o.backgroundcolor;
  var raw = bwipjs.raw(o)[0];
  log.debug("Leaving symbolModules(). " + raw.pixx + "x" + raw.pixy);
  return { width: raw.pixx, height: raw.pixy,
           dark: Uint8Array.from(raw.pixs) };
}

// One luminance byte per pixel (0 black, 255 white) from RGBA pixels, as a
// canvas's getImageData() gives them; transparent pixels are white.
function luminanceOf(rgba, width, height) {
  log.debug("Entering luminanceOf(). " + width + "x" + height);
  var out = new Uint8ClampedArray(width * height);
  for (var i = 0, p = 0; i < out.length; i++, p += 4) {
    var a = rgba[p + 3] / 255;
    var y = 0.299 * rgba[p] + 0.587 * rgba[p + 1] + 0.114 * rgba[p + 2];
    out[i] = Math.round(y * a + 255 * (1 - a));
  }
  log.debug("Leaving luminanceOf().");
  return out;
}

// The text of the PDF417 symbol in a picture given as luminance, or null
// when none is found. Each character is one byte of the symbol's data.
function readSymbol(luminance, width, height) {
  log.debug("Entering readSymbol(). " + width + "x" + height);
  var hints = new Map();
  hints.set(DecodeHintType.TRY_HARDER, true);
  var source = new RGBLuminanceSource(luminance, width, height);
  var result;
  try {
    result = new PDF417Reader().decode(new BinaryBitmap(
      new HybridBinarizer(source)), hints);
  } catch (e) {
    log.debug("Leaving readSymbol(). None: " + (e && e.message));
    return null;
  }
  log.debug("Leaving readSymbol(). " + result.getText().length);
  return result.getText();
}

module.exports = {
  EC_LEVEL: EC_LEVEL,
  ENCODER: ENCODER,
  DECODER: DECODER,
  symbolSvg: symbolSvg,
  symbolModules: symbolModules,
  luminanceOf: luminanceOf,
  readSymbol: readSymbol
};
