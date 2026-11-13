// File: xacml_own_members.js
//
// Own-member reads and writes for names a policy, a request or an ALFA
// document chose. The engine looks names up in plain-object tables
// (functions, combining algorithms, datatypes, variables, references,
// ALFA categories and attributes). A plain lookup reads through the
// prototype chain, so `constructor`, `toString` and `__proto__` answer a
// function or Object.prototype where an unknown name answers nothing, and
// an assignment to `__proto__` replaces the prototype instead of storing
// a member. Every such read goes through has() or read(), and every write
// into a map read that way goes through put().

'use strict';

var log = require("../xacml_runtime").log;

var DIGITS = /^[0-9]+$/;

/**
 * Whether `key` names a member `node` holds itself: an array's index
 * (digits, below its length), or an object's own member, never one it
 * inherits.
 *
 * A hot path (every function, variable and datatype a policy names, at
 * every evaluation): no Entering/Leaving pair, which would drown the log.
 *
 * @param {*} node - the object or array
 * @param {*} key - the name
 * @returns {boolean} true where the member is the node's own
 */
function has(node, key) {
  if (node === null || typeof node !== "object") {
    return false;
  }
  var name = String(key);
  if (Array.isArray(node)) {
    return DIGITS.test(name) && Number(name) < node.length;
  }
  return Object.prototype.hasOwnProperty.call(node, name);
}

/**
 * The member `key` names when `node` holds it itself, otherwise
 * undefined, the answer a missing name gives.
 *
 * A hot path, as has(): no Entering/Leaving pair.
 *
 * @param {*} node - the object or array
 * @param {*} key - the name
 * @returns {*} the own member, or undefined
 */
function read(node, key) {
  if (!has(node, key)) {
    return undefined;
  }
  return node[String(key)];
}

/**
 * Sets an own member of a plain object, `__proto__` included: an
 * ordinary data member, enumerable, writable and configurable, as an
 * assignment makes one, but never the prototype.
 *
 * @param {object} node - the object
 * @param {*} key - the name
 * @param {*} value - the value
 */
function put(node, key, value) {
  log.debug("Entering put().");
  Object.defineProperty(node, String(key), {
    value: value,
    writable: true,
    enumerable: true,
    configurable: true
  });
  log.debug("Leaving put().");
}

module.exports = {
  has: has,
  read: read,
  put: put
};
