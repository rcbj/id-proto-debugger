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
var MAX_READER_LENGTH = 256;
var LIST_WAIT_MS = 450;

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

function limits() {
  log.debug("Entering limits().");
  var loaded = loadFactory();
  var out = {
    available: !!loaded.factory,
    reason: loaded.reason,
    maxApduBytes: MAX_APDU_BYTES,
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

function describeTransmit(given) {
  log.debug("Entering describeTransmit().");
  var body = given || {};
  var reader = checkReaderName(body.reader);
  if (!reader.ok) {
    log.debug("Leaving describeTransmit(). Reader.");
    return reader;
  }
  var apdu = parseApdu(body.apdu);
  if (!apdu.ok) {
    log.debug("Leaving describeTransmit(). APDU.");
    return apdu;
  }
  log.debug("Leaving describeTransmit().");
  return { ok: true, reader: reader.reader, apdu: apdu.apdu };
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

function transmit(readerName, apdu) {
  log.debug("Entering transmit().");
  var loaded = loadFactory();
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
      reader.connect({ share_mode: reader.SCARD_SHARE_SHARED },
          function (connectErr, protocol) {
        if (connectErr) {
          finish(new Error("No card in " + readerName + "."));
          return;
        }
        reader.transmit(apdu, MAX_APDU_BYTES, protocol,
            function (txErr, data) {
          reader.disconnect(reader.SCARD_LEAVE_CARD, function () {
            if (txErr) {
              finish(txErr);
              return;
            }
            var buf = Buffer.from(data || []);
            if (buf.length < 2) {
              finish(new Error("The card returned no status word."));
              return;
            }
            finish(null, {
              data: buf.slice(0, buf.length - 2).toString("hex"),
              status: buf.slice(buf.length - 2).toString("hex")
                  .toUpperCase()
            });
          });
        });
      });
    });
    setTimeout(function () {
      if (!found) {
        finish(new Error("No reader named \"" + readerName + "\"."));
      }
    }, LIST_WAIT_MS);
  });
  log.debug("Leaving transmit().");
  return pending;
}

module.exports = {
  MAX_APDU_BYTES: MAX_APDU_BYTES,
  limits: limits,
  checkReaderName: checkReaderName,
  describeTransmit: describeTransmit,
  listReaders: listReaders,
  transmit: transmit
};
