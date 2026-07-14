var config = {
  // Milliseconds Selenium waits for elements/conditions in the test scripts.
  // Raised to 10s (from the local default of 2s) to tolerate real-network
  // latency when testing the deployed idptools.com site.
  waitTime: 10000,
  // Bunyan log level for the test scripts (trace|debug|info|warn|error|fatal).
  LOG_LEVEL: 'info'
};

module.exports = config;
