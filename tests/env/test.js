// ---------------------------------------------------------------------------
// HOW LONG A BROWSER WAIT MAY TAKE, AND WHY IT IS A VARIABLE NOW.
//
// `waitTime` is the timeout every `driver.wait()` in this suite is given —
// several tests multiply it (`waitTime * 6` for a token exchange), none of
// them SLEEP for it, so raising it costs nothing on a run that passes and
// only makes a genuinely broken test take longer to say so.
//
// Two seconds is the right number for the plain containerized suite and it is
// NOT the right number for `./run-coverage.sh`. That run serves Istanbul-
// INSTRUMENTED bundles — slower to parse, slower to execute — to a pool of
// jobs sharing a four-core GitHub runner, and on 2026-09-01 it took [08]
// OAuth2 Authorization Code (public, PKCE=false) red on a two-second wait for
// `#token_client_id` after the Keycloak redirect: 288 of 289 jobs passed and
// the one that did not was reporting the page's LOAD TIME as an assertion
// about the page. `run-coverage.sh` therefore exports TEST_WAIT_TIME_MS, the
// same way it already exports a longer TEST_JOB_TIMEOUT_MS, for the same
// reason and with the same shape.
//
// IT HAS TO CROSS TWO BOUNDARIES to be read here: `sudo`, which keeps only
// what COMPOSE_FORWARDED_VARS (common/common.sh) names, and compose, which
// substitutes it into the tests service (docker-compose-run-tests.yml).
// tests/compose_env_forwarding.js fails when either half is missing — an
// unforwarded variable arrives EMPTY and looks exactly like one nobody set.
//
// Unset, empty, or not a positive number means the file's own value, so a run
// that asks for nothing behaves exactly as it did before this existed.
// ---------------------------------------------------------------------------
var config = {
  // Milliseconds Selenium waits for elements/conditions in the test scripts.
  //
  // A CONFIG IIFE rather than a named helper, deliberately: the root
  // CLAUDE.md's style notes exempt exactly this shape from the
  // Entering/Leaving convention, and a config file has no bunyan logger to
  // call anyway — it is `require`d before every one of them exists.
  waitTime: (function () {
    var raw = Number(process.env.TEST_WAIT_TIME_MS);
    if (Number.isFinite(raw) && raw > 0) {
      return raw;
    }
    return 2000;
  })(),
  // Bunyan log level for the test scripts (trace|debug|info|warn|error|fatal).
  LOG_LEVEL: 'info'
};

module.exports = config;
