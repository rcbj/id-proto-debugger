// File: stale_socket_retry.js
//
// ---------------------------------------------------------------------------
// One retry for an idempotent outbound call that a POOLED socket lost.
//
// The api's outbound agents keep connections alive (appconfig.keepAlive, on by
// default — see agentFor() in server.js). That carries one race Node does not
// handle for you: the far end closes an idle connection after ITS keep-alive
// timeout (Node's http server default is five seconds, and the mock STS is a
// Node http server), and a request written onto that socket in the moment the
// close is in flight dies with ECONNRESET — before a single byte of response,
// and through no fault of either end. Node's agent retires a free socket a
// second before the server's advertised `Keep-Alive: timeout=` hint, which
// makes the race rare rather than impossible: a busy event loop on either side
// reopens it, and ./run-coverage.sh, with both processes instrumented and a
// pool of jobs on a four-core runner, is exactly that. On 2026-09-27 it took
// one job of 303 red: GET /samlmetadata answered 500 with `read ECONNRESET`
// fetching the mock's metadata, and the test reported a browser that could not
// reach the STS.
//
// The remedy is the one Node's own documentation gives (http, "reusedSocket"):
// retry. It is limited here to what is SAFE to send twice without knowing
// whether the first copy arrived — GET, HEAD and OPTIONS, which RFC 9110
// section 9.2.1 defines as safe — and to a failure that produced NO response
// at all. Anything with a status code is the far end's answer and is passed
// through untouched; a POST is never repeated, because a token endpoint that
// did receive the first copy has already spent the authorization code.
//
// One retry, not a loop. The second attempt either gets a fresh connection or
// another pooled one that is not about to close; a host that resets that too
// is genuinely refusing, and the caller should see it.
// ---------------------------------------------------------------------------
'use strict';

// The log level comes from the same configuration everything else here
// reads. A caller without one still has to be able to load this module,
// so an unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "stale_socket_retry",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// The error codes a connection the peer has already closed produces: a reset
// when the request is read against the close, a broken pipe when it is written.
var STALE_SOCKET_CODES = ['ECONNRESET', 'EPIPE'];

// RFC 9110 section 9.2.1's safe methods. axios lower-cases config.method.
var SAFE_METHODS = ['get', 'head', 'options'];

// Marks a config that has already been retried once, so the second failure
// is reported rather than retried again.
var RETRIED = '__staleSocketRetried';

/**
 * Whether a failed axios call is a stale pooled socket worth one more try.
 *
 * @param {Error} error - the axios error.
 * @returns {boolean}
 */
function shouldRetry(error) {
  log.debug("Entering shouldRetry().");
  if (!error || error.response || !error.config) {
    log.debug("Leaving shouldRetry(). A response, or no config to repeat.");
    return false;
  }
  if (error.config[RETRIED]) {
    log.debug("Leaving shouldRetry(). Already retried once.");
    return false;
  }
  if (STALE_SOCKET_CODES.indexOf(error.code) === -1) {
    log.debug("Leaving shouldRetry(). Not a stale-socket code: " +
              error.code + ".");
    return false;
  }
  var method = String(error.config.method || 'get').toLowerCase();
  var safe = SAFE_METHODS.indexOf(method) !== -1;
  log.debug("Leaving shouldRetry(). method=" + method + ", safe=" + safe +
            ".");
  return safe;
}

/**
 * Install the retry on an axios instance's response interceptors.
 *
 * @param {object} axiosInstance - axios, or anything with
 *   interceptors.response.use() and request(config).
 * @param {object} [logger] - bunyan-style logger for the one warn line a
 *   retry writes; defaults to this module's own.
 * @returns {number} the interceptor id, for eject().
 */
function install(axiosInstance, logger) {
  log.debug("Entering install().");
  var out = logger || log;
  var id = axiosInstance.interceptors.response.use(undefined,
    function (error) {
      if (!shouldRetry(error)) {
        return Promise.reject(error);
      }
      error.config[RETRIED] = true;
      out.warn('stale_socket_retry: ' +
               String(error.config.method || 'get').toUpperCase() + ' ' +
               error.config.url + ' failed with ' + error.code +
               ' and no response (a pooled connection the far end had ' +
               'closed); retrying once.');
      return axiosInstance.request(error.config);
    });
  log.debug("Leaving install().");
  return id;
}

module.exports = {
  install: install,
  shouldRetry: shouldRetry,
  STALE_SOCKET_CODES: STALE_SOCKET_CODES,
  SAFE_METHODS: SAFE_METHODS
};
