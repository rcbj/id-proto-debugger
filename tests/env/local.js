// TEST_WAIT_TIME_MS overrides `waitTime` here, and env/test.js carries the
// whole reasoning — the short version is that ./run-coverage.sh serves
// instrumented bundles and two seconds is not the right timeout for them.
// Unset, empty or not a positive number means the value below.
var config = {
  // Milliseconds Selenium waits for elements/conditions in the test scripts.
  // A config IIFE, which the style notes exempt from Entering/Leaving.
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
