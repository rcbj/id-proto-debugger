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
  // record(), step() and send() run once per APDU on the wire, at
  // most MAX_SEQUENCE x (MAX_GET_RESPONSE + 2) times a request, which
  // is not a hot path, so they log like everything else.
  function record(sent, answer) {
    log.debug("Entering record().");
    steps.push({
      apdu: sent.toString("hex").toUpperCase(),
      data: answer.data.toString("hex"),
      status: Buffer.from([answer.sw1, answer.sw2]).toString("hex")
          .toUpperCase()
    });
    log.debug("Leaving record().");
  }
  function step(sent) {
    log.debug("Entering step().");
    log.debug("Leaving step(). The answer is a promise.");
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

// CLOSE THE READERS, THEN THE CONTEXT. Every reader object pcsclite hands
// out runs its own status-monitoring thread, and closing the context does
// not stop them: until 2026-11-13 this closed only the context, and each
// listing left a thread behind and each transmit one or two — 52 threads
// after forty calls, measured against a YubiKey, and a long-running api
// grows without bound.
function closePcsc(pcsc, readers) {
  log.debug("Entering closePcsc().");
  (readers || []).forEach(function (reader) {
    try {
      reader.close();
    } catch (e) {
      log.debug("closePcsc() ignored a reader close error.");
    }
  });
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
    var seen = [];
    var names = [];
    function finish(err, value) {
      log.debug("Entering finish().");
      if (settled) {
        log.debug("Leaving finish(). Already settled.");
        return;
      }
      settled = true;
      closePcsc(pcsc, seen);
      if (err) {
        reject(err);
      } else {
        resolve(value);
      }
      log.debug("Leaving finish().");
    }
    try {
      pcsc = loaded.factory();
    } catch (e) {
      finish(e);
      return;
    }
    pcsc.on("reader", function (reader) {
      seen.push(reader);
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
    var seen = [];
    var found = false;
    function finish(err, value) {
      log.debug("Entering finish().");
      if (settled) {
        log.debug("Leaving finish(). Already settled.");
        return;
      }
      settled = true;
      closePcsc(pcsc, seen);
      if (err) {
        reject(err);
      } else {
        resolve(value);
      }
      log.debug("Leaving finish().");
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
      if (reader) {
        seen.push(reader);
      }
      if (!reader || reader.name !== readerName || found) {
        return;
      }
      found = true;
      var share = list.length > 1 ? reader.SCARD_SHARE_EXCLUSIVE :
          reader.SCARD_SHARE_SHARED;
      reader.connect({ share_mode: share },
          function (connectErr, protocol) {
        if (connectErr) {
          // pcsclite's own text names the PC/SC code (no card, card
          // unpowered, sharing violation, ...), which is the diagnosis.
          // A guess of ours in its place would hide it.
          var said = (connectErr && connectErr.message) ?
              connectErr.message : String(connectErr);
          finish(new Error(list.length > 1 ?
              "Could not open " + readerName + " exclusively. Is a " +
              "card in it, and is another process (scdaemon, pcscd " +
              "clients) holding it? PC/SC said: " + said :
              "Could not connect to " + readerName + ". PC/SC said: " +
              said));
          return;
        }
        function send(apdu) {
          log.debug("Entering send().");
          log.debug("Leaving send(). The answer is a promise.");
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
        // A sequence that VERIFYs a PIN or authenticates with a key leaves
        // the card in that security state on a LEAVE_CARD disconnect, for
        // whatever connects next to inherit. Such a sequence ends with a
        // card reset instead, which clears it.
        var authed = list.some(function (apdu) {
          return apdu.length > 1 && (apdu[1] === 0x20 || apdu[1] === 0x87);
        });
        var ending = authed && reader.SCARD_RESET_CARD !== undefined ?
            reader.SCARD_RESET_CARD : reader.SCARD_LEAVE_CARD;
        runSequence(send, list, getResponse, options.remainingIns)
            .then(function (results) {
          reader.disconnect(ending, function () {
            var last = results[results.length - 1];
            finish(null, {
              data: last.data,
              status: last.status,
              steps: last.steps,
              results: results
            });
          });
        }, function (err) {
          reader.disconnect(ending, function () {
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

// ---------------------------------------------------------------------------
// SESSIONS: one exclusive connection kept open across several requests.
//
// PIV's management-key authentication is a challenge-response the page
// computes from the card's own answer (SP 800-73-4 part 2, 3.2.4), so the
// command after it cannot be in a sequence written in advance; and the
// card forgets the authentication when the connection closes. A session
// holds the connection, exclusively, until it is closed or sits idle for
// SESSION_IDLE_MS, and is closed with a card RESET, which clears every PIN
// and key the card accepted on it. At most MAX_SESSIONS at once, one
// request at a time in each. The key material never comes here: the page
// does the arithmetic and sends APDUs.
// ---------------------------------------------------------------------------
var SESSION_IDLE_MS = 60000;
var MAX_SESSIONS = 4;
var sessions = {};

function endSession(id, why) {
  log.debug("Entering endSession(). " + why);
  var session = sessions[id];
  if (!session) {
    log.debug("Leaving endSession(). Unknown.");
    return Promise.resolve(false);
  }
  delete sessions[id];
  clearTimeout(session.timer);
  var ended = new Promise(function (resolve) {
    var mode = session.reader.SCARD_RESET_CARD !== undefined ?
        session.reader.SCARD_RESET_CARD : session.reader.SCARD_LEAVE_CARD;
    try {
      session.reader.disconnect(mode, function () {
        closePcsc(session.pcsc, session.seen);
        resolve(true);
      });
    } catch (e) {
      closePcsc(session.pcsc, session.seen);
      resolve(true);
    }
  });
  log.debug("Leaving endSession().");
  return ended;
}

function touchSession(id) {
  log.debug("Entering touchSession().");
  var session = sessions[id];
  if (session) {
    clearTimeout(session.timer);
    session.timer = setTimeout(function () {
      endSession(id, "idle");
    }, SESSION_IDLE_MS);
    if (session.timer.unref) {
      session.timer.unref();
    }
  }
  log.debug("Leaving touchSession().");
}

// Open a session on a reader. Resolves to { id, idleMs }.
function openSession(readerName, opts) {
  log.debug("Entering openSession().");
  var options = opts || {};
  if (Object.keys(sessions).length >= MAX_SESSIONS) {
    log.debug("Leaving openSession(). Too many.");
    return Promise.reject(new Error("Too many open sessions (" +
        MAX_SESSIONS + "); close one or wait " + (SESSION_IDLE_MS / 1000) +
        " seconds."));
  }
  var loaded = options.factory ? { factory: options.factory } :
      loadFactory();
  if (!loaded.factory) {
    log.debug("Leaving openSession(). No PC/SC.");
    return Promise.reject(new Error(loaded.reason));
  }
  var opened = new Promise(function (resolve, reject) {
    var pcsc = null;
    var seen = [];
    var settled = false;
    function fail(err) {
      if (settled) {
        return;
      }
      settled = true;
      closePcsc(pcsc, seen);
      reject(err);
    }
    try {
      pcsc = loaded.factory();
    } catch (e) {
      fail(e);
      return;
    }
    pcsc.on("error", function (err) {
      fail(err || new Error("The reader subsystem reported an error."));
    });
    pcsc.on("reader", function (reader) {
      if (reader) {
        seen.push(reader);
      }
      if (!reader || reader.name !== readerName || settled) {
        return;
      }
      reader.connect({ share_mode: reader.SCARD_SHARE_EXCLUSIVE },
          function (err, protocol) {
        if (err) {
          fail(new Error("Could not open " + readerName + " exclusively. " +
              "PC/SC said: " + (err.message || String(err))));
          return;
        }
        if (settled) {
          return;
        }
        settled = true;
        var id = require("crypto").randomBytes(16).toString("hex");
        sessions[id] = { pcsc: pcsc, reader: reader, protocol: protocol,
                         seen: seen, busy: false, timer: null };
        touchSession(id);
        resolve({ id: id, idleMs: SESSION_IDLE_MS });
      });
    });
    setTimeout(function () {
      fail(new Error("No reader named \"" + readerName + "\"."));
    }, LIST_WAIT_MS);
  });
  log.debug("Leaving openSession().");
  return opened;
}

// Run a sequence in an open session. Same answer as transmit().
function sessionTransmit(id, apdus, opts) {
  log.debug("Entering sessionTransmit().");
  var options = opts || {};
  var session = sessions[id];
  if (!session) {
    log.debug("Leaving sessionTransmit(). Unknown.");
    return Promise.reject(new Error("No such session: it was closed, or " +
        "it was idle for " + (SESSION_IDLE_MS / 1000) + " seconds."));
  }
  if (session.busy) {
    log.debug("Leaving sessionTransmit(). Busy.");
    return Promise.reject(new Error("The session is still answering the " +
        "previous request."));
  }
  session.busy = true;
  touchSession(id);
  function send(apdu) {
    return new Promise(function (ok, bad) {
      session.reader.transmit(apdu, MAX_APDU_BYTES, session.protocol,
          function (err, data) {
        if (err) {
          bad(err);
          return;
        }
        ok(Buffer.from(data || []));
      });
    });
  }
  var list = Buffer.isBuffer(apdus) ? [apdus] : apdus;
  var ran = runSequence(send, list, options.getResponse !== false,
      options.remainingIns).then(function (results) {
    session.busy = false;
    touchSession(id);
    var last = results[results.length - 1];
    return { data: last.data, status: last.status, steps: last.steps,
             results: results };
  }, function (err) {
    session.busy = false;
    throw err;
  });
  log.debug("Leaving sessionTransmit().");
  return ran;
}

function closeSession(id) {
  log.debug("Entering closeSession().");
  log.debug("Leaving closeSession().");
  return endSession(id, "closed");
}

function checkSessionId(id) {
  log.debug("Entering checkSessionId().");
  var ok = typeof id === "string" && /^[0-9a-f]{32}$/.test(id);
  log.debug("Leaving checkSessionId(). " + ok);
  return ok;
}

module.exports = {
  openSession: openSession,
  sessionTransmit: sessionTransmit,
  closeSession: closeSession,
  checkSessionId: checkSessionId,
  SESSION_IDLE_MS: SESSION_IDLE_MS,
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
