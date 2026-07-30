// Local (docker-compose / bare `node server.js`) configuration for the STS mock.
//
// Selected with CONFIG_FILE, the same way the api and client services choose
// theirs — e.g. CONFIG_FILE=./env/local.js node server.js.
var config = {
  // Bunyan log level (trace|debug|info|warn|error|fatal). debug is the useful
  // level for a mock whose job is to show what it did: every endpoint call, and
  // every token/assertion before and after it was signed.
  logLevel: "debug"
};

module.exports = config;
