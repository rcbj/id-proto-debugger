// Configuration for the containerized test stack (docker-compose-run-tests.yml).
var config = {
  // Kept at debug: the STS log is the record of what the mock issued when a test
  // fails, and it is the only place the signed artifacts are written down.
  logLevel: "debug"
};

module.exports = config;
