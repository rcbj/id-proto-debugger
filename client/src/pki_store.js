// File: pki_store.js
//
// ---------------------------------------------------------------------------
// The PKI page's store of keys and certificates — the thing that makes a CA
// hierarchy usable rather than a one-shot generator.
//
// A certificate authority is only worth having if it is still there tomorrow:
// the whole point of a root is that it signs an intermediate next week and an
// issuing CA the week after, and a client certificate is only interesting if
// the truststore that trusts it can still be assembled when the TLS test runs.
// So every object this page makes goes in here, keyed by an id, remembering who
// issued it — and `chainFor()` walks that back to the root, which is what the
// PKCS#12 export, the trust anchor list and the mutual-auth test all need.
//
// ---------------------------------------------------------------------------
// PRIVATE KEYS, AND THE OPT-OUT
//
// This is the repository's standing exception, applied the way the SD-JWT VC
// workflow applies it rather than the way the SAML page does — because here
// there is not one key pair but a collection, and the certificates in it are
// public documents that there is no reason to throw away.
//
// So the preference (`pki_save_keys`, on by default) governs the PRIVATE HALF
// ONLY: with it cleared, `privateKeyPem` is stripped from every entry on the
// way in AND from every entry already stored, while subjects, certificates and
// public keys stay. The enforcement is central — one write path, `writeRaw()`,
// which every mutation below ends at — because a guard per call site is a
// guard somebody forgets, and the failure
// here is silent in the reassuring direction: the box unticks, the note
// appears, and the key goes on being written.
//
// An entry without its private key is not useless, and the page says which it
// is: the certificate can still be inspected, exported and put in a truststore.
// What it cannot do is sign anything or be presented as a client certificate,
// and `canSign()` is what every caller asks rather than testing for the field.
//
// No DOM in here beyond localStorage itself, which is why the opt-out is
// checked where it actually lives: tests/pki_page.js drives the page and then
// READS storage, exactly as tests/keypair_storage_optout.js does for the other
// four protocols — this failure is silent in the reassuring direction, and
// nothing on screen distinguishes a working guard from a broken one. See
// docs/pki.md.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");

var log = bunyan.createLogger({
  name: "pki_store",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var STORE_PREFIX = 'pkitools_';
// Everything the page makes, as one JSON array. One key rather than one per
// object because the order is the hierarchy's order and a store spread over
// n keys has no order at all — and because clearing it has to be one act.
var OBJECTS_KEY = STORE_PREFIX + 'objects';
// The preference, stored under the id of the checkbox that sets it so it
// behaves like every other `.stored` field on the page.
var SAVE_KEYS_KEY = STORE_PREFIX + 'pki_save_keys';

// The kinds of object this store holds. A 'ca' can issue; a 'leaf' cannot.
var KIND_CA = 'ca';
var KIND_LEAF = 'leaf';

function storage() {
  log.debug("Entering storage().");
  try {
    if (typeof localStorage !== 'undefined' && localStorage) {
      log.debug("Leaving storage().");
      return localStorage;
    }
  } catch (e) {
    log.debug("storage(): unavailable: " + e.message);
  }
  log.debug("Leaving storage(). None.");
  return null;
}

// Only an explicit "0" turns saving off, so an unreadable or absent preference
// fails toward the workflow — the same rule the SD-JWT VC holder key uses.
function saveKeysAllowed() {
  log.debug("Entering saveKeysAllowed().");
  var store = storage();
  if (!store) {
    log.debug("Leaving saveKeysAllowed(). No storage at all.");
    return false;
  }
  var value = store.getItem(SAVE_KEYS_KEY);
  log.debug("Leaving saveKeysAllowed(). value=" + value);
  return value !== '0';
}

function setSaveKeys(allowed) {
  log.debug("Entering setSaveKeys(). allowed=" + allowed);
  var store = storage();
  if (!store) {
    log.debug("Leaving setSaveKeys(). No storage.");
    return false;
  }
  store.setItem(SAVE_KEYS_KEY, allowed ? '1' : '0');
  // Not merely "stop writing them": strip what is already there. An opt-out
  // that leaves yesterday's CA key in storage is not an opt-out.
  if (!allowed) purgePrivateKeys();
  log.debug("Leaving setSaveKeys().");
  return true;
}

function readRaw() {
  log.debug("Entering readRaw().");
  var store = storage();
  if (!store) {
    log.debug("Leaving readRaw(). No storage.");
    return [];
  }
  var text = store.getItem(OBJECTS_KEY);
  if (!text) {
    log.debug("Leaving readRaw(). Empty.");
    return [];
  }
  try {
    var parsed = JSON.parse(text);
    log.debug("Leaving readRaw(). " + (parsed.length || 0) + " entries.");
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    log.error('readRaw: the store is not JSON: ' + e.message);
    log.debug("Leaving readRaw(). Unreadable.");
    return [];
  }
}

// THE ONE WRITE PATH. Every mutation below ends here, which is what makes the
// private-key rule enforceable in a single place.
function writeRaw(entries) {
  log.debug("Entering writeRaw(). " + entries.length + " entries.");
  var store = storage();
  if (!store) {
    log.debug("Leaving writeRaw(). No storage.");
    return false;
  }
  var allowed = saveKeysAllowed();
  var toWrite = entries.map(function (entry) {
    if (allowed) return entry;
    var copy = Object.assign({}, entry);
    delete copy.privateKeyPem;
    return copy;
  });
  store.setItem(OBJECTS_KEY, JSON.stringify(toWrite));
  log.debug("Leaving writeRaw(). keys kept=" + allowed);
  return true;
}

function list() {
  log.debug("Entering list().");
  var entries = readRaw();
  log.debug("Leaving list(). " + entries.length + " entries.");
  return entries;
}

function get(id) {
  log.debug("Entering get(). id=" + id);
  var found = readRaw().filter(function (entry) {
    return entry.id === id;
  })[0] || null;
  log.debug("Leaving get(). " + (found ? 'found' : 'not found'));
  return found;
}

// Certificate authorities, newest last, for the "sign with" dropdown. An entry
// whose private key is gone cannot sign, so `signingOnly` drops it — offering
// a CA that cannot sign produces a Web Crypto error two clicks later that
// names neither the CA nor the missing key.
function certificateAuthorities(signingOnly) {
  log.debug("Entering certificateAuthorities().");
  var out = readRaw().filter(function (entry) {
    if (entry.kind !== KIND_CA) return false;
    if (signingOnly && !canSign(entry)) return false;
    return true;
  });
  log.debug("Leaving certificateAuthorities(). " + out.length + " of them.");
  return out;
}

function canSign(entry) {
  log.debug("Entering canSign().");
  var able = !!(entry && entry.privateKeyPem);
  log.debug("Leaving canSign(). " + able);
  return able;
}

// A stable-enough id: the time plus a random tail. Not a serial number — the
// certificate has one of those and it is not this.
function newId(kind) {
  log.debug("Entering newId().");
  var random = new Uint8Array(6);
  crypto.getRandomValues(random);
  var tail = '';
  for (var i = 0; i < random.length; i++) {
    tail += ('0' + random[i].toString(16)).slice(-2);
  }
  log.debug("Leaving newId().");
  return (kind || 'obj') + '-' + tail;
}

// Add or replace. Returns the entry as stored, which is NOT necessarily the
// entry passed in: with saving off it comes back without its private key, and a
// caller that assumed otherwise would show a "ready to sign" object that is
// not.
function put(entry) {
  log.debug("Entering put(). id=" + (entry || {}).id);
  if (!entry || !entry.id) {
    log.debug("Leaving put(). No id.");
    throw new Error('A store entry needs an id.');
  }
  var entries = readRaw();
  var index = -1;
  for (var i = 0; i < entries.length; i++) {
    if (entries[i].id === entry.id) index = i;
  }
  if (index >= 0) entries[index] = entry;
  else entries.push(entry);
  writeRaw(entries);
  log.debug("Leaving put().");
  return get(entry.id);
}

// Remove one object. Its children keep their `issuerId` and become orphans
// rather than being deleted with it: the certificates they hold are still
// valid documents, and deleting somebody's leaf because they tidied up a CA is
// not a thing a debugging tool should do on its own. `orphans()` finds them.
function remove(id) {
  log.debug("Entering remove(). id=" + id);
  var entries = readRaw().filter(function (entry) {
    return entry.id !== id;
  });
  writeRaw(entries);
  log.debug("Leaving remove().");
  return true;
}

function clear() {
  log.debug("Entering clear().");
  var store = storage();
  if (!store) {
    log.debug("Leaving clear(). No storage.");
    return false;
  }
  store.removeItem(OBJECTS_KEY);
  log.debug("Leaving clear().");
  return true;
}

function purgePrivateKeys() {
  log.debug("Entering purgePrivateKeys().");
  var store = storage();
  if (!store) {
    log.debug("Leaving purgePrivateKeys(). No storage.");
    return false;
  }
  var entries = readRaw().map(function (entry) {
    var copy = Object.assign({}, entry);
    delete copy.privateKeyPem;
    return copy;
  });
  store.setItem(OBJECTS_KEY, JSON.stringify(entries));
  log.debug("Leaving purgePrivateKeys(). " + entries.length + " entries.");
  return true;
}

function orphans() {
  log.debug("Entering orphans().");
  var entries = readRaw();
  var ids = {};
  entries.forEach(function (entry) { ids[entry.id] = true; });
  var out = entries.filter(function (entry) {
    return entry.issuerId && !ids[entry.issuerId];
  });
  log.debug("Leaving orphans(). " + out.length + " of them.");
  return out;
}

// The chain from this object up to its root, leaf first — the order a TLS
// server sends and a PKCS#12 stores. A cycle (which only a hand-edited store
// can produce) stops the walk rather than hanging it.
function chainFor(id) {
  log.debug("Entering chainFor(). id=" + id);
  var entries = readRaw();
  var byId = {};
  entries.forEach(function (entry) { byId[entry.id] = entry; });
  var out = [];
  var seen = {};
  var current = byId[id];
  while (current && !seen[current.id]) {
    seen[current.id] = true;
    out.push(current);
    current = current.issuerId ? byId[current.issuerId] : null;
  }
  log.debug("Leaving chainFor(). " + out.length + " link(s).");
  return out;
}

function chainPems(id) {
  log.debug("Entering chainPems(). id=" + id);
  var out = chainFor(id).map(function (entry) {
    return entry.certificatePem;
  }).filter(Boolean);
  log.debug("Leaving chainPems(). " + out.length + " certificate(s).");
  return out;
}

// The trust anchor an object chains to — what a truststore needs, as opposed
// to what a chain sends.
function rootFor(id) {
  log.debug("Entering rootFor(). id=" + id);
  var chain = chainFor(id);
  var root = chain.length ? chain[chain.length - 1] : null;
  log.debug("Leaving rootFor().");
  return root;
}

// A one-line label for a dropdown or a table row.
function labelFor(entry) {
  log.debug("Entering labelFor().");
  if (!entry) {
    log.debug("Leaving labelFor(). No entry.");
    return '';
  }
  var text = (entry.subject || entry.id) +
      ' — ' + (entry.profileLabel || entry.profile || entry.kind);
  if (!canSign(entry)) text += ' (no private key)';
  log.debug("Leaving labelFor().");
  return text;
}

module.exports = {
  STORE_PREFIX: STORE_PREFIX,
  OBJECTS_KEY: OBJECTS_KEY,
  SAVE_KEYS_KEY: SAVE_KEYS_KEY,
  KIND_CA: KIND_CA,
  KIND_LEAF: KIND_LEAF,
  saveKeysAllowed: saveKeysAllowed,
  setSaveKeys: setSaveKeys,
  list: list,
  get: get,
  put: put,
  remove: remove,
  clear: clear,
  purgePrivateKeys: purgePrivateKeys,
  newId: newId,
  canSign: canSign,
  certificateAuthorities: certificateAuthorities,
  orphans: orphans,
  chainFor: chainFor,
  chainPems: chainPems,
  rootFor: rootFor,
  labelFor: labelFor
};
