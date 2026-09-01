// TEST_WAIT_TIME_MS overrides `waitTime` here too, so the knob means the
// same thing on every configuration rather than on three of five; the
// whole reasoning is in env/test.js. Unset, empty or not a positive
// number means the value below.
var config = {
  // Milliseconds Selenium waits for elements/conditions in the test scripts.
  // Raised to 10s (from the local default of 2s) to tolerate real-network
  // latency when testing the deployed test.idptools.com site.
  waitTime: (function () {
    var raw = Number(process.env.TEST_WAIT_TIME_MS);
    if (Number.isFinite(raw) && raw > 0) {
      return raw;
    }
    return 10000;
  })(),
  // Bunyan log level for the test scripts (trace|debug|info|warn|error|fatal).
  LOG_LEVEL: 'info'
};

module.exports = config;
