// File: session_reset.js
//
// ---------------------------------------------------------------------------
// CLEARING A SIGN-IN SESSION THAT IS NOT ON THE PAGE'S OWN ORIGIN.
//
// `driver.manage().deleteAllCookies()` looks like "empty the cookie jar" and is
// not. WebDriver defines Delete All Cookies as acting on the cookies
// ASSOCIATED WITH THE CURRENT BROWSING CONTEXT'S ACTIVE DOCUMENT — so it clears
// the origin the browser happens to be sitting on and nothing else. Every test
// here that calls it is at one of the debugger's own pages when it does, and
// the session it is trying to throw away belongs to the IDENTITY PROVIDER.
//
// ON A HOST RUN THE TWO ARE THE SAME HOST AND THE BUG IS INVISIBLE. The client
// is http://localhost:3000 and the mock STS is https://localhost:8081; cookies
// ignore the port, so both are the `localhost` jar and one call empties both.
// On the containerized stack they are `client` and `sts` — two different hosts,
// two different jars — and the identity provider's session SURVIVES the call.
//
// WHAT THAT LOOKS LIKE, because it names nothing about cookies. Every one of
// these tests signs somebody in, then clears the cookies and sends the SAME
// authorization request again to prove that some attribute it just removed was
// what did the work. With the session still there the mock answers that second
// request from it — correctly — and no sign-in screen is drawn at all, so what
// the run reports is
//
//   "With the tie removed no sign-in screen appeared at all"
//   "Something answered the authorization request without asking anybody
//    who they are"
//   "Neither the chooser nor a sign-in screen drew anything to pick from"
//
// — twenty-two jobs of the containerized run of 2026-08-27, each accusing the
// feature it was written to defend.
//
// So the clear is done ON the identity provider's origin as well: the browser
// is parked there for one navigation, the cookies are deleted with that
// document active, and it goes back to whatever it was showing. Two extra page
// loads, and they are the difference between an assertion and a decoration.
//
// `log` is this module's own bunyan logger, as everywhere else here.
// ---------------------------------------------------------------------------
const bunyan = require("bunyan");
const log = bunyan.createLogger({
  name: "session_reset",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// The scheme+host+port of a URL, or "" when there is nothing usable. A bare
// origin passed in comes back unchanged.
function originOf(url) {
  log.debug("Entering originOf().");
  const text = String(url || "").trim();
  if (!text) {
    log.debug("Leaving originOf(). Nothing given.");
    return "";
  }
  try {
    const origin = new URL(text).origin;
    log.debug("Leaving originOf(). " + origin);
    return origin;
  } catch (e) {
    // Not parseable — a caller that passed something else gets it back rather
    // than an exception, and the navigation below is what will complain.
    log.debug("Leaving originOf(). Unparseable; returned as given.");
    return text.replace(/\/+$/, "");
  }
}

// Delete the cookies of the current document AND of every origin named, each on
// its own document. `urls` may be one URL or a list, and any path on them is
// ignored: the origin's root is what gets loaded, because a 404 body from the
// right origin is as good a place to delete a cookie from as a home page.
async function clearSessionsAt(driver, urls) {
  log.debug("Entering clearSessionsAt().");
  // The current origin first, which is what the callers used to do on its own.
  await driver.manage().deleteAllCookies();

  const origins = [].concat(urls || [])
    .map(originOf)
    .filter(function (one) {
      return one;
    })
    .filter(function (one, at, all) {
      return all.indexOf(one) === at;
    });

  for (const origin of origins) {
    await driver.get(origin + "/");
    await driver.manage().deleteAllCookies();
    log.info("Cleared the cookies held for " + origin + ".");
  }
  log.debug("Leaving clearSessionsAt(). " + origins.length + " extra " +
      "origin(s).");
}

module.exports = {
  clearSessionsAt: clearSessionsAt,
  originOf: originOf
};
