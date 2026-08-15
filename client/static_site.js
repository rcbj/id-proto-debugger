'use strict';

// What the STATIC deployments (idptools.com, test.idptools.com) leave out, and
// what the landing page says about it.
//
// Kerberos is the one workflow here that cannot run without a backend, and the
// reason is not policy: it speaks DER over TCP and UDP port 88, so a browser
// cannot open a socket to a KDC and every page but the decoder goes through
// api/krb5_relay.js. The Lambda@Edge trick that rescued WS-Federation and SAML
// (infra/CLAUDE.md) cannot rescue this one — there is no HTTP request to catch.
// Shipping those pages to a site with no api gives a page whose every button
// fails at the network, which is worse than not offering it: the failure names
// a fetch rather than the absent backend.
//
// So the static build drops the pages entirely and marks their landing card
// unavailable. The DECODER is dropped with them although it needs no network:
// it is not a workflow of its own, it has no card, and the only route to it is
// a link on kerberos.html — which is not there either.
//
// This is a module rather than a few lines in build.js because two things read
// it and they must not disagree: client/build.js leaves these files out of
// dist/, and tests/static_site_exclusions.js checks that what is excluded still
// exists in client/public (a rename would otherwise turn every exclusion into a
// silent no-op) and that no page that DOES ship links to one of them.
//
// The Entering/Leaving logging convention (see the repo-root CLAUDE.md) wants a
// `log` here, and bunyan is not reachable from this file: it is read by a build
// that runs from a checkout, before and outside the image build, and by a test
// that must not need client/node_modules. So this is the same call shape backed
// by console, exactly as client/build.js and client/version.js carry. Debug
// output is off by default. The methods below are the one place the convention
// cannot apply — a log line inside log.debug() is infinite recursion.
var DEBUG = false;
var LOG_TAG = "[static_site]";
var log = {
  debug: function () {
    if (!DEBUG) return;
    console.log.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  },
  info: function () {
    console.log.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  },
  warn: function () {
    console.warn.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  },
  error: function () {
    console.error.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  }
};

// Pages that do not ship to a static deployment, by basename. The basename is
// also the bundle name in client/build.js's BUNDLES and the page's file name
// under client/public, which is what lets one list drive all three.
var EXCLUDED_PAGES = [
  'kerberos',
  'kerberos_tgs',
  'kerberos_ap',
  'kerberos_delegation',
  'kerberos_decoder'
];

// Everything else those pages own, as paths relative to the site root. Only
// assets used by NOTHING that still ships belong here — the check in
// tests/static_site_exclusions.js enforces that, since dropping a stylesheet a
// surviving page links leaves the survivor unstyled with nothing 404ing that
// anybody looks at.
var EXCLUDED_ASSETS = [
  'css/kerberos.css'
];

// The marker an <a class="landing-card"> carries in client/public/index.html to
// say "this protocol is not on the static site". The container-served page uses
// it for nothing; the static build turns the card it is on into a dead one.
var CARD_MARKER = 'data-not-on-static';

// Added to that card's class list by the static build. client/public/css/
// landing.css greys the card, drops the hover lift, and swaps the description
// for the .landing-card-unavailable one that is display:none everywhere else.
var DISABLED_CLASS = 'landing-card-disabled';

// The page files the static build must not copy into dist/.
function excludedFiles() {
  log.debug("Entering excludedFiles().");
  var files = EXCLUDED_PAGES.map(function (name) {
    return name + '.html';
  }).concat(EXCLUDED_ASSETS);
  log.debug("Leaving excludedFiles().");
  return files;
}

// True when client/build.js should skip this BUNDLES entry.
function bundleIsExcluded(name) {
  log.debug("Entering bundleIsExcluded().");
  var excluded = EXCLUDED_PAGES.indexOf(name) >= 0;
  log.debug("Leaving bundleIsExcluded().");
  return excluded;
}

// One tag's attributes with href removed and DISABLED_CLASS added. Split out of
// disableUnavailableCards() so the replace callback stays readable; `attrs` is
// everything between `<a` and `>`, so it starts with whitespace.
function deadCardAttributes(attrs) {
  log.debug("Entering deadCardAttributes().");
  var rest = attrs.replace(/\s*href\s*=\s*"[^"]*"/i, '');
  if (/class\s*=\s*"[^"]*"/i.test(rest)) {
    rest = rest.replace(/class\s*=\s*"([^"]*)"/i,
        'class="$1 ' + DISABLED_CLASS + '"');
  } else {
    rest = ' class="' + DISABLED_CLASS + '"' + rest;
  }
  log.debug("Leaving deadCardAttributes().");
  return rest + ' aria-disabled="true"';
}

// Turn every marked landing card into a dead one: no href, greyed, announced as
// disabled. It stays an <a> rather than becoming a <span> deliberately — an <a>
// with no href is not a link (not focusable, not clickable), and every selector
// that reads this page, in landing.css and in tests/navigation.js, is written
// against `a.landing-card`. Swapping the element would make the card invisible
// to the geometry and accent-colour checks there, which is precisely when a
// card silently stops fitting on one screen.
//
// Returns the rewritten html and the number of cards changed, so the caller can
// fail on zero: a marker that stopped matching is a card that quietly stays
// live and links to a page the build just deleted.
function disableUnavailableCards(html) {
  log.debug("Entering disableUnavailableCards().");
  var count = 0;
  var re = new RegExp('<a\\b([^>]*\\b' + CARD_MARKER + '\\b[^>]*)>', 'gi');
  var out = html.replace(re, function (match, attrs) {
    count++;
    return '<a' + deadCardAttributes(attrs) + '>';
  });
  log.debug("Leaving disableUnavailableCards().");
  return { html: out, count: count };
}

// Every href in `html` that points at a file this build is not shipping. Used
// by both the build and the test: a link to a deleted page is a 404 nobody sees
// until a user clicks it, and it is exactly what adding a page to the lists
// above without touching its callers produces.
function linksToExcludedFiles(html) {
  log.debug("Entering linksToExcludedFiles().");
  var found = [];
  excludedFiles().forEach(function (file) {
    var re = new RegExp('(?:href|src)\\s*=\\s*"/?' +
        file.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '"', 'i');
    if (re.test(html)) found.push(file);
  });
  log.debug("Leaving linksToExcludedFiles().");
  return found;
}

module.exports = {
  EXCLUDED_PAGES: EXCLUDED_PAGES,
  EXCLUDED_ASSETS: EXCLUDED_ASSETS,
  CARD_MARKER: CARD_MARKER,
  DISABLED_CLASS: DISABLED_CLASS,
  excludedFiles: excludedFiles,
  bundleIsExcluded: bundleIsExcluded,
  disableUnavailableCards: disableUnavailableCards,
  linksToExcludedFiles: linksToExcludedFiles
};
