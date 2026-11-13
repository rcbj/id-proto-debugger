// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: smartcard_reader.js
//
// The optional PC/SC transmit path. A browser cannot open CCID.
// This module does not require the native library at load, so an
// api that was not given one still starts. A missing library is a
// limit, reported by GET /smartcard/limits, not a crash.
//
// There is no host, no port and no caller-chosen filesystem path.
// The reader is the machine this api runs on. The APDU is not
// logged: a VERIFY carries a PIN.
//
// It is OFF unless smartcardReaderEnabled is true in the api's env:
// anything that reaches the api could otherwise send any APDU to a
// card on this machine, including the wrong-PIN VERIFYs that block a
// PIN, a PIV reset or an OpenPGP TERMINATE.
//
// A transmit is a SEQUENCE of up to MAX_SEQUENCE APDUs on ONE
// connection, so SELECT then GET DATA, or VERIFY then a signature,
// cannot be interleaved by another process. A sequence of more than
// one APDU connects SCARD_SHARE_EXCLUSIVE for that reason. 61xx is
// followed by GET RESPONSE and 6Cxx is resent with the Le the card
// asked for, the way ISO 7816-4 section 5.1.3 describes, unless the
// caller turns that off to see the raw exchange.

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "smartcard_reader",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var MAX_APDU_BYTES = 8192;
var MAX_SEQUENCE = 16;
var MAX_RESPONSE_BYTES = 65536;
var MAX_GET_RESPONSE = 64;
var MAX_READER_LENGTH = 256;
var LIST_WAIT_MS = 450;
// A whole sequence, touches included. A card that never answers would
// otherwise hold the request, and the reader, for ever.
var TRANSMIT_TIMEOUT_MS = 60000;
// GET RESPONSE is ISO 7816-4's C0. YKOATH does not implement it and
// asks for SEND REMAINING, A5, instead (yubikit's oath.py builds its
// SmartCardProtocol with INS_SEND_REMAINING = 0xA5).
var INS_GET_RESPONSE = 0xc0;
var INS_SEND_REMAINING = 0xa5;
var OATH_AID = "a0000005272101";

function failure(message) {
  log.debug("Entering failure().");
  log.debug("Leaving failure().");
  return { ok: false, error: message };
}

function loadFactory() {
  log.debug("Entering loadFactory().");
  var loaded = null;
  var reason = "PC/SC is not installed on this api. Install " +
      "libpcsclite and the native module the operator chooses. " +
      "Nothing in this image installs either.";
  try {
    var name = ["pcs", "clite"].join("");
    loaded = require(name);
  } catch (e) {
    loaded = null;
  }
  var factory = typeof loaded === "function" ? loaded : null;
  log.debug("Leaving loadFactory().");
  return { factory: factory, reason: factory ? null : reason };
}

function enabled(appconfig) {
  log.debug("Entering enabled().");
  var on = !!(appconfig && appconfig.smartcardReaderEnabled === true);
  log.debug("Leaving enabled().");
  return on;
}

var DISABLED_MESSAGE = "The smart-card reader relay is off on this " +
    "api. Set smartcardReaderEnabled: true in its env file to send " +
    "APDUs to a reader on the machine it runs on.";

function limits(appconfig) {
  log.debug("Entering limits().");
  var loaded = loadFactory();
  var on = enabled(appconfig);
  var out = {
    enabled: on,
    available: on && !!loaded.factory,
    reason: on ? loaded.reason : DISABLED_MESSAGE,
    maxApduBytes: MAX_APDU_BYTES,
    maxSequence: MAX_SEQUENCE,
    reader: "the machine this api runs on"
  };
  log.debug("Leaving limits().");
  return out;
}

function checkReaderName(name) {
  log.debug("Entering checkReaderName().");
  if (typeof name !== "string" || !name.trim()) {
    log.debug("Leaving checkReaderName(). Empty.");
    return failure("The reader name is empty.");
  }
  if (name.length > MAX_READER_LENGTH) {
    log.debug("Leaving checkReaderName(). Long.");
    return failure("The reader name is longer than " +
        MAX_READER_LENGTH + " characters.");
  }
  if (/[\u0000-\u001f\u007f]/.test(name)) {
    log.debug("Leaving checkReaderName(). Control.");
    return failure("The reader name has a control character.");
  }
  if (name.indexOf("://") >= 0) {
    log.debug("Leaving checkReaderName(). Scheme.");
    return failure("The reader is a name, not a URL.");
  }
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(name)) {
    log.debug("Leaving checkReaderName(). URI.");
    return failure("The reader is a name, not a URI.");
  }
  if (/:\d{1,5}$/.test(name)) {
    log.debug("Leaving checkReaderName(). Port.");
    return failure("The reader is a name, not a host and port.");
  }
  if (name.charAt(0) === "/" || name.indexOf("..") >= 0) {
    log.debug("Leaving checkReaderName(). Path.");
    return failure("The reader is a name, not a filesystem path.");
  }
  log.debug("Leaving checkReaderName().");
  return { ok: true, reader: name };
}

function parseApdu(text) {
  log.debug("Entering parseApdu().");
  var hex = String(text == null ? "" : text).replace(/\s+/g, "");
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) {
    log.debug("Leaving parseApdu(). Hex.");
    return failure("The APDU is an even number of hex characters.");
  }
  var bytes = Buffer.from(hex, "hex");
  if (bytes.length < 4) {
    log.debug("Leaving parseApdu(). Short.");
    return failure("An APDU is at least 4 bytes.");
  }
  if (bytes.length > MAX_APDU_BYTES) {
    log.debug("Leaving parseApdu(). Long.");
    return failure("An APDU is at most " + MAX_APDU_BYTES + " bytes.");
  }
  log.debug("Leaving parseApdu().");
  return { ok: true, apdu: bytes };
}

// { reader, apdu } or { reader, apdus: [...] }, and getResponse,
// which is true unless the caller sends false.
function describeTransmit(given) {
  log.debug("Entering describeTransmit().");
  var body = given || {};
  var reader = checkReaderName(body.reader);
  if (!reader.ok) {
    log.debug("Leaving describeTransmit(). Reader.");
    return reader;
  }
  var texts = Array.isArray(body.apdus) ? body.apdus : [body.apdu];
  if (texts.length === 0 || texts.length > MAX_SEQUENCE) {
    log.debug("Leaving describeTransmit(). Count.");
    return failure("A sequence is 1 to " + MAX_SEQUENCE + " APDUs.");
  }
  var apdus = [];
  var i;
  for (i = 0; i < texts.length; i++) {
    var apdu = parseApdu(texts[i]);
    if (!apdu.ok) {
      log.debug("Leaving describeTransmit(). APDU.");
      return texts.length > 1 ?
          failure("APDU " + (i + 1) + ": " + apdu.error) : apdu;
    }
    apdus.push(apdu.apdu);
  }
  var getResponse = !(body.getResponse === false ||
      body.getResponse === "false");
  // The applet may have been selected by an earlier transmit, which
  // remainingInsAfter() cannot see. "a5" says it is YKOATH.
  var remaining = String(body.remainingIns == null ? "c0" :
      body.remainingIns).toLowerCase();
  if (remaining !== "c0" && remaining !== "a5") {
    log.debug("Leaving describeTransmit(). Remaining.");
    return failure("remainingIns is c0 (GET RESPONSE) or a5 " +
        "(YKOATH SEND REMAINING).");
  }
  log.debug("Leaving describeTransmit().");
  return { ok: true, reader: reader.reader, apdu: apdus[0],
      apdus: apdus, getResponse: getResponse,
      remainingIns: parseInt(remaining, 16) };
}

// The same APDU with its Le replaced by le, for a 6Cxx answer. Only a
// short APDU has a one-byte Le to replace; null means "do not retry".
function withLe(apdu, le) {
  log.debug("Entering withLe().");
  var out = null;
  if (apdu.length === 4) {
    out = Buffer.concat([apdu, Buffer.from([le])]);
  } else if (apdu.length === 5) {
    out = Buffer.from(apdu);
    out[4] = le;
  } else if (apdu[4] !== 0) {
    var lc = apdu[4];
    if (apdu.length === 5 + lc) {
      out = Buffer.concat([apdu, Buffer.from([le])]);
    } else if (apdu.length === 6 + lc) {
      out = Buffer.from(apdu);
      out[out.length - 1] = le;
    }
  }
  log.debug("Leaving withLe().");
  return out;
}

function splitStatus(buf) {
  log.debug("Entering splitStatus().");
  if (!buf || buf.length < 2) {
    log.debug("Leaving splitStatus(). No status word.");
    throw new Error("The card returned no status word.");
  }
  log.debug("Leaving splitStatus().");
  return { data: buf.slice(0, buf.length - 2),
      sw1: buf[buf.length - 2], sw2: buf[buf.length - 1] };
}

// The CLA of a GET RESPONSE: the command's logical channel, and
// nothing else. First interindustry CLA (00-3F) keeps the channel in
// b2-b1; further interindustry (40-7F) keeps b7 and the channel in
// b4-b1. Chaining and secure messaging bits are dropped either way.
function responseCla(cla) {
  log.debug("Entering responseCla().");
  var out = (cla & 0xc0) === 0x40 ? (cla & 0x4f) : (cla & 0x03);
  log.debug("Leaving responseCla().");
  return out;
}

// The INS that fetches the rest of a 61xx answer after this APDU,
// given the one in force before it. A SELECT changes it: SELECT of
// the OATH applet means A5 from then on, any other SELECT means C0.
function remainingInsAfter(apdu, current) {
  log.debug("Entering remainingInsAfter().");
  var out = current;
  if (apdu.length >= 5 && apdu[1] === 0xa4 && apdu[2] === 0x04) {
    var lc = apdu[4];
    var aid = apdu.slice(5, 5 + lc).toString("hex");
    out = aid.indexOf(OATH_AID) === 0 ? INS_SEND_REMAINING :
        INS_GET_RESPONSE;
  }
  log.debug("Leaving remainingInsAfter().");
  return out;
}

// One APDU through send(apdu) -> Promise<Buffer>, completed with GET
// RESPONSE and the 6Cxx retry when getResponse is on. Every exchange
// on the wire is in steps, so the page can show what was sent.
function exchange(send, apdu, getResponse, remainingIns) {
  log.debug("Entering exchange().");
  var fetchIns = remainingIns === undefined ? INS_GET_RESPONSE :
      remainingIns;
  var steps = [];
  var data = Buffer.alloc(0);
  var retried = false;
  var fetches = 0;
  function record(sent, answer) {
    steps.push({
      apdu: sent.toString("hex").toUpperCase(),
      data: answer.data.toString("hex"),
      status: Buffer.from([answer.sw1, answer.sw2]).toString("hex")
          .toUpperCase()
    });
  }
  function step(sent) {
    return send(sent).then(function (buf) {
      var answer = splitStatus(Buffer.from(buf));
      record(sent, answer);
      data = Buffer.concat([data, answer.data]);
      if (data.length > MAX_RESPONSE_BYTES) {
        throw new Error("The response is longer than " +
            MAX_RESPONSE_BYTES + " bytes.");
      }
      if (getResponse && answer.sw1 === 0x6c && !retried) {
        var again = withLe(sent, answer.sw2);
        if (again) {
          retried = true;
          data = Buffer.alloc(0);
          return step(again);
        }
      }
      if (getResponse && answer.sw1 === 0x61) {
        fetches += 1;
        if (fetches > MAX_GET_RESPONSE) {
          throw new Error("The card asked for more than " +
              MAX_GET_RESPONSE + " GET RESPONSEs.");
        }
        return step(Buffer.from([responseCla(apdu[0]), fetchIns, 0x00,
            0x00, answer.sw2]));
      }
      return {
        data: data.toString("hex"),
        status: Buffer.from([answer.sw1, answer.sw2]).toString("hex")
            .toUpperCase(),
        steps: steps
      };
    });
  }
  log.debug("Leaving exchange().");
  return step(apdu);
}

// Every APDU in order, stopping at the first one whose final status is
// not 90xx or 61xx, because the next one usually depends on it.
function runSequence(send, apdus, getResponse, remainingIns) {
  log.debug("Entering runSequence().");
  var results = [];
  var chain = Promise.resolve(true);
  var fetchIns = remainingIns === undefined ? INS_GET_RESPONSE :
      remainingIns;
  apdus.forEach(function (apdu) {
    chain = chain.then(function (going) {
      if (!going) {
        return false;
      }
      fetchIns = remainingInsAfter(apdu, fetchIns);
      return exchange(send, apdu, getResponse, fetchIns)
          .then(function (answer) {
        results.push(answer);
        return answer.status.slice(0, 2) === "90" ||
            answer.status.slice(0, 2) === "61";
      });
    });
  });
  log.debug("Leaving runSequence().");
  return chain.then(function () {
    return results;
  });
}

function closePcsc(pcsc) {
  log.debug("Entering closePcsc().");
  try {
    if (pcsc) {
      pcsc.close();
    }
  } catch (e) {
    log.debug("closePcsc() ignored a close error.");
  }
  log.debug("Leaving closePcsc().");
}

function listReaders() {
  log.debug("Entering listReaders().");
  var loaded = loadFactory();
  if (!loaded.factory) {
    log.debug("Leaving listReaders(). Unavailable.");
    return Promise.reject(new Error(loaded.reason));
  }
  var pending = new Promise(function (resolve, reject) {
    var pcsc = null;
    var settled = false;
    var names = [];
    function finish(err, value) {
      if (settled) {
        return;
      }
      settled = true;
      closePcsc(pcsc);
      if (err) {
        reject(err);
      } else {
        resolve(value);
      }
    }
    try {
      pcsc = loaded.factory();
    } catch (e) {
      finish(e);
      return;
    }
    pcsc.on("reader", function (reader) {
      if (reader && reader.name && names.indexOf(reader.name) < 0) {
        names.push(reader.name);
      }
    });
    pcsc.on("error", function (err) {
      finish(err || new Error("The reader subsystem reported an error."));
    });
    setTimeout(function () {
      finish(null, names);
    }, LIST_WAIT_MS);
  });
  log.debug("Leaving listReaders().");
  return pending;
}

// opts: { getResponse, remainingIns, factory, timeoutMs }. factory
// replaces the native module,
// which is how tests/smartcard_engine.js drives this without a reader.
function transmit(readerName, apdus, opts) {
  log.debug("Entering transmit().");
  var options = opts || {};
  var list = Buffer.isBuffer(apdus) ? [apdus] : apdus;
  var getResponse = options.getResponse !== false;
  var timeoutMs = options.timeoutMs || TRANSMIT_TIMEOUT_MS;
  var loaded = options.factory ? { factory: options.factory } :
      loadFactory();
  if (!loaded.factory) {
    log.debug("Leaving transmit(). Unavailable.");
    return Promise.reject(new Error(loaded.reason));
  }
  var pending = new Promise(function (resolve, reject) {
    var pcsc = null;
    var settled = false;
    var found = false;
    function finish(err, value) {
      if (settled) {
        return;
      }
      settled = true;
      closePcsc(pcsc);
      if (err) {
        reject(err);
      } else {
        resolve(value);
      }
    }
    try {
      pcsc = loaded.factory();
    } catch (e) {
      finish(e);
      return;
    }
    pcsc.on("error", function (err) {
      finish(err || new Error("The reader subsystem reported an error."));
    });
    pcsc.on("reader", function (reader) {
      if (!reader || reader.name !== readerName || found) {
        return;
      }
      found = true;
      var share = list.length > 1 ? reader.SCARD_SHARE_EXCLUSIVE :
          reader.SCARD_SHARE_SHARED;
      reader.connect({ share_mode: share },
          function (connectErr, protocol) {
        if (connectErr) {
          finish(new Error(list.length > 1 ?
              "Could not open " + readerName + " exclusively. Is a " +
              "card in it, and is another process (scdaemon, pcscd " +
              "clients) holding it? " + connectErr.message :
              "No card in " + readerName + "."));
          return;
        }
        function send(apdu) {
          return new Promise(function (ok, bad) {
            reader.transmit(apdu, MAX_APDU_BYTES, protocol,
                function (txErr, data) {
              if (txErr) {
                bad(txErr);
                return;
              }
              ok(Buffer.from(data || []));
            });
          });
        }
        runSequence(send, list, getResponse, options.remainingIns)
            .then(function (results) {
          reader.disconnect(reader.SCARD_LEAVE_CARD, function () {
            var last = results[results.length - 1];
            finish(null, {
              data: last.data,
              status: last.status,
              steps: last.steps,
              results: results
            });
          });
        }, function (err) {
          reader.disconnect(reader.SCARD_LEAVE_CARD, function () {
            finish(err);
          });
        });
      });
    });
    setTimeout(function () {
      if (!found) {
        finish(new Error("No reader named \"" + readerName + "\"."));
      }
    }, LIST_WAIT_MS);
    setTimeout(function () {
      finish(new Error("The card did not finish the sequence in " +
          (timeoutMs / 1000) + " seconds."));
    }, timeoutMs).unref();
  });
  log.debug("Leaving transmit().");
  return pending;
}

module.exports = {
  MAX_APDU_BYTES: MAX_APDU_BYTES,
  MAX_SEQUENCE: MAX_SEQUENCE,
  DISABLED_MESSAGE: DISABLED_MESSAGE,
  enabled: enabled,
  limits: limits,
  withLe: withLe,
  responseCla: responseCla,
  remainingInsAfter: remainingInsAfter,
  exchange: exchange,
  runSequence: runSequence,
  checkReaderName: checkReaderName,
  describeTransmit: describeTransmit,
  listReaders: listReaders,
  transmit: transmit
};
