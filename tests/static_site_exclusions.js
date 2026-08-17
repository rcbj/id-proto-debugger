// File: static_site_exclusions.js
//
// client/static_site.js — what the STATIC deployments leave out, and what the
// landing page says about it.
//
// ---------------------------------------------------------------------------
// Why this needs a test of its own, and why that test is not a browser.
//
// Kerberos is DER over port 88. A browser cannot open that socket, so every
// page of the workflow but the decoder goes through api/krb5_relay.js, and
// idptools.com has no api. Shipping those pages there gives a workflow whose
// every button fails at the network — a failure that names a fetch rather than
// the absent backend. So the static build drops the pages and greys their
// landing card.
//
// Every part of that arrangement fails SILENTLY when it drifts, and each one
// fails somewhere other than where it broke:
//
//  * **An exclusion that matches nothing.** fs.rmSync on an absent path
//    succeeds. Rename kerberos_tgs.html and the build still reports "excluded
//    from the static build: kerberos_tgs.html" while shipping the page under
//    its new name. (The build throws on this too — this test is the same check
//    one commit earlier, before anybody has run a deploy.)
//  * **A card that stops matching its marker.** The rewrite is keyed off
//    data-not-on-static in client/public/index.html. Drop the attribute and the
//    card stays a live link to a page the build has just deleted: a 404 on the
//    landing page, which is the first thing a visitor touches.
//  * **A surviving page that links to a dropped one.** Nothing 404s until
//    somebody clicks it, and no test drives a link that only exists on the
//    hosted site.
//  * **The two halves of the card swap.** The greyed card explains itself with
//    a second description that is display:none everywhere else. Lose the CSS
//    and the card shows BOTH texts (taller — and this page's one hard
//    requirement is that every card fits without scrolling); lose the span and
//    it explains nothing.
//  * **The exclusion escaping into the CONTAINER build.** This is static-only.
//    client/Dockerfile must still browserify every one of these pages, because
//    the containerized app is where the workflow works.
//
// No browser and no services: node only, so it never skips as a whole. The two
// directory-wide checks need client/public, which the tests image does not
// carry, and say so in the log when it is absent — the four files they can be
// run against ARE copied there (tests/Dockerfile), so the image runs the rest.
// ---------------------------------------------------------------------------
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const bunyan = require("bunyan");
const { Command, Option } = require("commander");

var log = bunyan.createLogger({
  name: "static_site_exclusions",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      // No CONFIG_FILE, or it does not resolve from here. Falling back to info
      // loses only the configured verbosity.
      return "info";
    }
  })()
});

// Flat in the tests container, in their own trees in a checkout — the same
// arrangement tests/edge_landing_contract.js reads two files under.
function locate(candidates) {
  log.debug("Entering locate().");
  log.debug("Leaving locate().");
  return candidates.filter(function (p) {
    return fs.existsSync(p);
  })[0];
}

const MODULE_PATH = locate([
  path.join(__dirname, "static_site.js"),
  path.join(__dirname, "..", "client", "static_site.js")]);
const INDEX_PATH = locate([
  path.join(__dirname, "index.html"),
  path.join(__dirname, "..", "client", "public", "index.html")]);
const LANDING_CSS_PATH = locate([
  path.join(__dirname, "landing.css"),
  path.join(__dirname, "..", "client", "public", "css", "landing.css")]);
const CLIENT_DOCKERFILE_PATH = locate([
  path.join(__dirname, "client_Dockerfile"),
  path.join(__dirname, "..", "client", "Dockerfile")]);
const PUBLIC_DIR = locate([
  path.join(__dirname, "..", "client", "public")]);

// ---------------------------------------------------------------------------
// What is excluded still exists. An exclusion naming a file nobody has is not
// an exclusion, it is a line of configuration that reads like one.
// ---------------------------------------------------------------------------
function everyExclusionNamesSomethingThatExists(staticSite) {
  log.debug("Entering everyExclusionNamesSomethingThatExists().");
  if (!PUBLIC_DIR) {
    log.info("[exclusions] skipped the existence check: client/public is not " +
      "here, so this is the tests image rather than a checkout. The build " +
      "throws on the same condition (client/build.js step 2a).");
    log.debug("Leaving everyExclusionNamesSomethingThatExists().");
    return;
  }
  const missing = staticSite.excludedFiles().filter(function (rel) {
    return !fs.existsSync(path.join(PUBLIC_DIR, rel));
  });
  assert.deepStrictEqual(missing, [],
    "client/static_site.js excludes these from the static deployments and " +
    "client/public has no such file: " + missing.join(", ") + ". A removal " +
    "of a path that is not there SUCCEEDS, so a rename turns the whole " +
    "exclusion into a no-op and the page ships to a site that cannot " +
    "serve it.");
  log.info("[exclusions] OK — all " + staticSite.excludedFiles().length +
    " excluded file(s) exist in client/public: " +
    staticSite.excludedFiles().join(", "));
  log.debug("Leaving everyExclusionNamesSomethingThatExists().");
}

// ---------------------------------------------------------------------------
// The landing page marks exactly the cards whose pages are dropped — both
// directions. A marker on a card that still ships greys a working protocol; a
// missing marker leaves a live link to a deleted page.
// ---------------------------------------------------------------------------
function theLandingPageMarksExactlyTheDroppedCards(staticSite, index) {
  log.debug("Entering theLandingPageMarksExactlyTheDroppedCards().");
  const cards = index.match(/<a\b[^>]*class="[^"]*landing-card[^"]*"[^>]*>/g)
      || [];
  assert.ok(cards.length >= 8,
    "expected the landing page to offer every protocol; found " +
    cards.length + " card(s). Has the markup changed shape?");

  const excludedPages = staticSite.EXCLUDED_PAGES;
  const marked = [];
  const wronglyLive = [];
  cards.forEach(function (tag) {
    const href = (tag.match(/href="([^"]*)"/) || [])[1] || "";
    const page = href.split("#")[0].replace(/^\//, "");
    const isExcluded = page !== "" &&
        excludedPages.indexOf(page.replace(/\.html$/, "")) >= 0;
    const isMarked = tag.indexOf(staticSite.CARD_MARKER) >= 0;
    if (isMarked) marked.push(href);
    if (isExcluded && !isMarked) wronglyLive.push(href);
    if (isMarked && !isExcluded) {
      assert.fail("the landing card for " + (href || "(no href)") +
        " carries " +
        staticSite.CARD_MARKER + ", but its page is not in " +
        "client/static_site.js's EXCLUDED_PAGES — so the static build greys " +
        "out a protocol it then ships perfectly working pages for.");
    }
  });

  assert.deepStrictEqual(wronglyLive, [],
    "these landing cards link to a page the static build DELETES and do not " +
    "carry " + staticSite.CARD_MARKER + ": " + wronglyLive.join(", ") +
    ". On the hosted site that card is a live link to a 404, and the build " +
    "cannot know: it only rewrites what is marked.");
  assert.ok(marked.length > 0,
    "no landing card carries " + staticSite.CARD_MARKER + " at all, so the " +
    "static build has nothing to grey out — and it throws rather than ship " +
    "the page list and the landing page disagreeing.");
  log.info("[exclusions] OK — " + cards.length + " card(s), " + marked.length +
    " marked not-on-static (" + marked.join(", ") + "), and every card that " +
    "links to a dropped page is one of them.");
  log.debug("Leaving theLandingPageMarksExactlyTheDroppedCards().");
}

// ---------------------------------------------------------------------------
// The rewrite itself, against the real index.html: the marked card loses its
// href and gains the disabled class, and EVERY OTHER card is untouched. The
// second half is the one worth having — a regex that ate one href too many
// would leave a landing page where nothing is clickable, and the page would
// still look right in a screenshot.
// ---------------------------------------------------------------------------
function theRewriteKillsOnlyTheMarkedCards(staticSite, index) {
  log.debug("Entering theRewriteKillsOnlyTheMarkedCards().");
  const before = (index.match(/class="[^"]*landing-card[^"]*"[^>]*href=/g) ||
      []).length +
      (index.match(/<a[^>]*href="[^"]*"[^>]*class="[^"]*landing-card/g) ||
      []).length;
  const result = staticSite.disableUnavailableCards(index);

  assert.ok(result.count > 0,
    "disableUnavailableCards() changed nothing on the real index.html — the " +
    "marker and the regex that looks for it have drifted apart.");

  staticSite.EXCLUDED_PAGES.forEach(function (page) {
    assert.ok(result.html.indexOf('href="/' + page + '.html"') === -1,
      "after the rewrite the landing page still links to /" + page +
      ".html, which the static build deletes.");
  });

  const marked = result.html.match(
      new RegExp('<a\\b[^>]*' + staticSite.CARD_MARKER + '[^>]*>', 'g')) || [];
  assert.strictEqual(marked.length, result.count,
    "every marked card should survive the rewrite as an <a> — " +
    marked.length + " found, " + result.count + " rewritten.");
  marked.forEach(function (tag) {
    assert.ok(tag.indexOf(staticSite.DISABLED_CLASS) >= 0,
      "a rewritten card did not get the " + staticSite.DISABLED_CLASS +
      " class, so nothing in landing.css greys it: " + tag);
    assert.ok(tag.indexOf('aria-disabled="true"') >= 0,
      "a rewritten card is greyed for a sighted visitor and unannounced for " +
      "anybody else: " + tag);
    assert.ok(!/\shref=/.test(tag),
      "a rewritten card kept its href, so it is still a live link to a page " +
      "this build deleted: " + tag);
  });

  const after = (result.html.match(
      /class="[^"]*landing-card[^"]*"[^>]*href=/g) || []).length +
      (result.html.match(
      /<a[^>]*href="[^"]*"[^>]*class="[^"]*landing-card/g) || []).length;
  assert.strictEqual(after, before - result.count,
    "the rewrite removed " + (before - after) + " landing-card href(s) while " +
    "disabling " + result.count + " card(s). It must take exactly the ones " +
    "it disables: a regex reaching past its own tag leaves a landing page on " +
    "which nothing is clickable, and that looks perfectly normal.");
  log.info("[exclusions] OK — the rewrite disabled " + result.count +
    " card(s) and left the other " + after + " href(s) alone.");
  log.debug("Leaving theRewriteKillsOnlyTheMarkedCards().");
}

// ---------------------------------------------------------------------------
// The greyed card explains itself: a second description in the markup, and the
// CSS that swaps one for the other. Both halves, because either alone is worse
// than neither — the span without the CSS shows two descriptions on every
// deployment, the CSS without the span greys a card that says nothing about
// why.
// ---------------------------------------------------------------------------
function theGreyedCardSaysWhy(staticSite, index, css) {
  log.debug("Entering theGreyedCardSaysWhy().");
  const card = (index.match(
      new RegExp('<a\\b[^>]*' + staticSite.CARD_MARKER +
                 '[^>]*>[\\s\\S]*?</a>')) || [])[0];
  assert.ok(card,
    "could not find a card carrying " + staticSite.CARD_MARKER +
    " in index.html.");
  assert.ok(card.indexOf("landing-card-unavailable") >= 0,
    "the card the static build greys out carries no " +
    ".landing-card-unavailable description, so on the hosted site it is a " +
    "dead card that does not say why.");

  assert.ok(/\.landing-card-unavailable\s*\{[^}]*display:\s*none/.test(css),
    "landing.css must hide the .landing-card-unavailable text by default, or " +
    "every api-backed deployment shows both descriptions on that card.");
  assert.ok(css.indexOf("." + staticSite.DISABLED_CLASS) >= 0,
    "landing.css defines nothing for ." + staticSite.DISABLED_CLASS +
    ", so the static build's rewritten card looks exactly like a live one.");
  assert.ok(new RegExp("\\." + staticSite.DISABLED_CLASS +
      "[^{]*\\.landing-card-unavailable\\s*\\{[^}]*display:\\s*block")
      .test(css),
    "landing.css never shows .landing-card-unavailable on a disabled card, " +
    "so the greyed card loses its description entirely.");
  log.info("[exclusions] OK — the greyed card carries its own description " +
    "and landing.css swaps the two.");
  log.debug("Leaving theGreyedCardSaysWhy().");
}

// ---------------------------------------------------------------------------
// Nothing that still ships links to something that does not. The build checks
// dist/ for this too; here it is checked at the SOURCE, where the fix is.
// ---------------------------------------------------------------------------
function nothingThatShipsLinksToADroppedPage(staticSite) {
  log.debug("Entering nothingThatShipsLinksToADroppedPage().");
  if (!PUBLIC_DIR) {
    log.info("[exclusions] skipped the dead-link sweep: client/public is not " +
      "here, so this is the tests image rather than a checkout. " +
      "client/build.js runs the same sweep over dist/ on every deploy.");
    log.debug("Leaving nothingThatShipsLinksToADroppedPage().");
    return;
  }
  const dropped = staticSite.EXCLUDED_PAGES.map(function (p) {
    return p + ".html";
  });
  const offenders = [];
  function sweep(dir) {
    log.debug("Entering sweep().");
    fs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        sweep(full);
        return;
      }
      if (!entry.name.endsWith(".html")) return;
      // A dropped page linking to another dropped page is fine: neither ships.
      if (dropped.indexOf(entry.name) >= 0) return;
      // Nor does a dropped ASSET, and that is a separate list. This sweep only
      // consulted EXCLUDED_PAGES, which is right for pages and wrong for a
      // PARTIAL: partials/krb_steps.html is html, is not a page, links to all
      // five Kerberos pages, and is itself excluded — so before this line it
      // was reported as an offender for linking to things it correctly links
      // to. The paths in EXCLUDED_ASSETS are site-root-relative, which is the
      // same shape path.relative(PUBLIC_DIR, ...) produces.
      const siteRelative = path.relative(PUBLIC_DIR, full).split(path.sep)
          .join("/");
      if ((staticSite.EXCLUDED_ASSETS || []).indexOf(siteRelative) >= 0) {
        return;
      }
      // Against what the build SHIPS, not what the source says: the landing
      // card's href to /kerberos.html is in index.html and is exactly what the
      // rewrite takes out. Sweeping the raw source would fail on the one link
      // this whole mechanism exists to remove.
      const dead = staticSite.linksToExcludedFiles(
          staticSite.disableUnavailableCards(
              fs.readFileSync(full, "utf8")).html);
      if (dead.length) {
        offenders.push(path.relative(PUBLIC_DIR, full) + " -> " +
            dead.join(", "));
      }
    });
    log.debug("Leaving sweep().");
  }
  sweep(PUBLIC_DIR);
  assert.deepStrictEqual(offenders, [],
    "these pages DO ship to the static deployments and link to something " +
    "that does not: " + offenders.join(" | ") + ". Either that target ships " +
    "too (client/static_site.js) or the link goes — on the hosted site it is " +
    "a 404 nobody sees until a visitor clicks it. Note this is checked " +
    "AFTER the landing-card rewrite, so a marked card's own href is not it.");
  log.info("[exclusions] OK — no page that ships links to one that does not.");
  log.debug("Leaving nothingThatShipsLinksToADroppedPage().");
}

// ---------------------------------------------------------------------------
// The exclusion is STATIC-ONLY. The containerized app is where Kerberos works,
// so client/Dockerfile must still build every one of these bundles.
// ---------------------------------------------------------------------------
function theContainerBuildStillCarriesThem(staticSite) {
  log.debug("Entering theContainerBuildStillCarriesThem().");
  if (!CLIENT_DOCKERFILE_PATH) {
    log.info("[exclusions] skipped the container check: client/Dockerfile is " +
      "not present in this layout.");
    log.debug("Leaving theContainerBuildStillCarriesThem().");
    return;
  }
  const dockerfile = fs.readFileSync(CLIENT_DOCKERFILE_PATH, "utf8");
  const absent = staticSite.EXCLUDED_PAGES.filter(function (page) {
    return dockerfile.indexOf("browserify src/" + page + ".js") === -1;
  });
  assert.deepStrictEqual(absent, [],
    "client/Dockerfile no longer browserifies " + absent.join(", ") +
    ". These pages are left out of the STATIC deployments only — the " +
    "containerized app has the api's relay and is where the workflow runs. " +
    "Dropping them from the image too removes the workflow from the product.");
  log.info("[exclusions] OK — client/Dockerfile still builds all " +
    staticSite.EXCLUDED_PAGES.length + " of them for the container.");
  log.debug("Leaving theContainerBuildStillCarriesThem().");
}

// ---------------------------------------------------------------------------
// The rewrite is a no-op on markup that carries no marker. Cheap, and it is the
// half a real index.html cannot demonstrate: everything above proves the regex
// fires, nothing proves it stops.
// ---------------------------------------------------------------------------
function anUnmarkedPageIsLeftAlone(staticSite) {
  log.debug("Entering anUnmarkedPageIsLeftAlone().");
  const plain = '<a class="landing-card" href="/debugger.html">' +
      '<span class="landing-card-title">OAuth2</span></a>';
  const result = staticSite.disableUnavailableCards(plain);
  assert.strictEqual(result.count, 0,
    "disableUnavailableCards() disabled a card that carries no marker.");
  assert.strictEqual(result.html, plain,
    "disableUnavailableCards() rewrote markup it should not have touched.");
  log.info("[exclusions] OK — unmarked cards pass through untouched.");
  log.debug("Leaving anUnmarkedPageIsLeftAlone().");
}

function test() {
  log.debug("Entering test().");
  assert.ok(MODULE_PATH,
    "client/static_site.js was not found next to this test or in the " +
    "checkout — it is the list this whole check is about.");
  assert.ok(INDEX_PATH, "client/public/index.html was not found.");
  assert.ok(LANDING_CSS_PATH, "client/public/css/landing.css was not found.");
  const staticSite = require(MODULE_PATH);
  const index = fs.readFileSync(INDEX_PATH, "utf8");
  const css = fs.readFileSync(LANDING_CSS_PATH, "utf8");

  everyExclusionNamesSomethingThatExists(staticSite);
  theLandingPageMarksExactlyTheDroppedCards(staticSite, index);
  theRewriteKillsOnlyTheMarkedCards(staticSite, index);
  theGreyedCardSaysWhy(staticSite, index, css);
  nothingThatShipsLinksToADroppedPage(staticSite);
  theContainerBuildStillCarriesThem(staticSite);
  anUnmarkedPageIsLeftAlone(staticSite);
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("static_site_exclusions")
  .description("Verify what the static deployments leave out: the exclusion " +
               "list, the greyed landing card, and that nothing links to a " +
               "page that does not ship.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

try {
  test();
} catch (e) {
  log.error(e.stack || e.message);
  process.exit(1);
}
