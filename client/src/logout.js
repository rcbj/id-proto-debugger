var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var $ = require("jquery");
var log = bunyan.createLogger({ name: 'logout',
                                level: appconfig.logLevel });
log.info("Log initialized. logLevel=" + log.level());
window.onload = function() {
  log.debug("Entering onload().");
  log.debug("Entering onload function.");
  log.debug("Leaving onload().");
}

function loadValuesFromLocalStorage()
{
  log.debug("Entering loadValuesFromLocalStorage().");
  log.debug("Leaving loadValuesFromLocalStorage().");
}

function clickLink() {
  log.debug("Entering clickLink().");
  log.debug("Leaving clickLink().");
  return true;
}

module.exports = {
  loadValuesFromLocalStorage,
  clickLink
};
