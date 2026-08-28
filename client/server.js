// File: server.js
// Author: Robert C. Broeckelmann Jr.
// Date: 05/31/2020
// Notes:
//
'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');
var appconfig = require(process.env.CONFIG_FILE);
const expressLogging = require('express-logging');
const logger = require('logops');
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: 'server', 
                                logLevel: appconfig.logLevel });

log.info('appconfig: ' + JSON.stringify(appconfig));
// Constants
const PORT = appconfig.port || 3000;
const HOST = appconfig.hostname || '0.0.0.0';

// App
const app = express();
const PUBLIC_ROOT = path.resolve(__dirname, 'public');

// Code-coverage collection endpoint (opt-in via COVERAGE=true). The
// Istanbul-instrumented browser bundles POST their window.__coverage__ here on
// page unload; each payload is written as an Istanbul coverage file that nyc
// can later report on. Disabled (and absent) unless COVERAGE=true.
if (process.env.COVERAGE === 'true') {
  const COVERAGE_DIR = process.env.COVERAGE_DIR ||
      '/coverage/frontend/.nyc_output';
  app.post('/coverage', express.text({ type: function() { return true; },
           limit: '256mb' }), function(req, res) {
    try {
      fs.mkdirSync(COVERAGE_DIR, { recursive: true });
      var fileName = 'frontend-' + Date.now() + '-' +
          Math.random().toString(36).slice(2) + '.json';
      fs.writeFileSync(path.join(COVERAGE_DIR, fileName), req.body || '{}');
      log.info('Wrote browser coverage to ' + path.join(COVERAGE_DIR,
               fileName));
    } catch (e) {
      log.error('Failed to write browser coverage: ' + e);
    }
    res.status(204).end();
  });
  log.info('Coverage collection enabled: POST /coverage -> ' + COVERAGE_DIR);
}

// Application version (M.N.O). Read once: the build number identifies the
// build this server is serving, so it must not change between requests.
const appversion = require('./version');
const APP_VERSION = appversion.load(path.join(__dirname, 'public'));
const APP_BUILD_INFO = appversion.buildInfo(APP_VERSION);
log.info('Serving version ' + APP_VERSION.version + ' (' + APP_BUILD_INFO +
         ')');

// ---------------------------------------------------------------------------
// RFC 9700 sections 4.11 (Referer) and 4.14 (clickjacking), and they are NOT
// behind the compliance checkbox. Everything that switch governs is about this
// client's conversation with an identity PROVIDER, and turning any of it on
// can break a flow against a provider that does not implement RFC 9700 — which
// is most of why anybody uses this tool. These three headers are about this
// deployment's own posture, are invisible to any provider, and cannot break
// anything: nothing in client/public or client/src frames a page of this site,
// and no page of it needs to send a Referer anywhere.
//
// Note what the CSP deliberately does NOT contain. frame-ancestors and nothing
// else: this site's pages carry inline event handlers on nearly every control,
// so a default-src or a script-src here would take the whole application out at
// once. RFC 9700 asks for CSP Level 2 restricting frame-ancestors, and that is
// exactly what this is. X-Frame-Options is beside it for anything that does not
// implement frame-ancestors, which is the case that header still exists for.
//
// It is FIRST in the middleware chain because express applies middleware only
// to routes added after it, so anything registered later — the SSI handler, the
// static server, /callback — is covered and nothing has to remember to be.
app.use(function(req, res, next) {
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "frame-ancestors 'none'");
  next();
});

app.use(function(req, res, next) {
  // Treat the site root as index.html so the landing page's SSI includes
  // (header/footer) are resolved; otherwise express.static would serve it raw.
  var reqPath = (req.path === '/') ? '/index.html' : req.path;
  if (!reqPath.endsWith('.html')) { return next(); }
  const filePath = path.resolve(PUBLIC_ROOT, '.' + reqPath);
  if (!(filePath === PUBLIC_ROOT || filePath.startsWith(PUBLIC_ROOT +
      path.sep))) { return next(); }
  fs.readFile(filePath, 'utf8', function(err, content) {
    if (err) { return next(); }
    var processed = content.replace(/<!--#include file="([^"]+)"-->/g,
        function(match, file) {
      try {
        // The include is written site-absolute in the markup
        // ("/partials/footer.html"), and path.resolve IGNORES its base when the
        // next segment starts with a slash — path.resolve(PUBLIC_ROOT,
        // '/partials/x') is '/partials/x', outside PUBLIC_ROOT. The traversal
        // guard below then refused EVERY include and the catch replaced each
        // one with '', so the header, footer and step links silently vanished
        // from every page. Anchor it under PUBLIC_ROOT the way the page path
        // above already does, with a leading '.', which keeps the guard
        // meaningful: a '../' inside `file` still escapes and is still refused.
        const relative = file.startsWith('/') ? file : '/' + file;
        const includePath = path.resolve(PUBLIC_ROOT, '.' + relative);
        if (!(includePath === PUBLIC_ROOT ||
            includePath.startsWith(PUBLIC_ROOT + path.sep))) {
          throw new Error('Path traversal attempt');
        }
        return fs.readFileSync(includePath, 'utf8');
      } catch(e) {
        log.error('SSI include failed: ' + file + ' - ' + e);
        return '';
      }
    });
    // Stamp the copyright year ({{YEAR}} in the footer partial / error pages).
    // The static build (build.js) does this at build time; do it here at
    // request time for the local (non-built) server so the year is always
    // current.
    processed =
        processed.split('{{YEAR}}').join(String(new Date().getFullYear()));
    // ... and the M.N.O version. APP_VERSION is read once at startup from the
    // record stamped into public/ during the image build, so every page of a
    // deployment reports the same build number.
    processed = processed.split('{{VERSION}}').join(APP_VERSION.version);
    processed = processed.split('{{BUILD_INFO}}').join(APP_BUILD_INFO);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(processed);
  });
});

app.use( function(req, res, next) {
    console.log(req.originalUrl);
    next();
}, express.static('public'));
app.use(expressLogging(logger));

// ---------------------------------------------------------------------------
// The authorization response lands here.
//
// **This is the endpoint RFC 9700 sections 4.1.1 and 4.10 are about, and the
// property both of them ask for is one line long: the destination is built
// from appconfig.uiUrl and NOTHING is ever read out of the request to
// construct it.** A redirect endpoint that will forward a browser to a URL of
// the caller's choosing is an open redirector, and an open redirector on a
// registered redirect_uri is how an authorization code is stolen from a client
// that did everything else right. tests/rfc9700_client.js asserts it over this
// source rather than leaving it to inspection, because the failure is one
// well-meaning edit away and produces no symptom at all in normal use.
//
// 303 rather than 302, and rather than 307 (section 4.12). For the GET below
// the three are equivalent in practice; for the POST they are not, and a 307
// would replay the method AND THE BODY — which on a form_post response is the
// authorization response itself — onto the next hop. Both use 303 so that the
// rule is a property of this endpoint rather than of one of its two methods.
// ---------------------------------------------------------------------------

// Where a response is forwarded to. Built here, once, from configuration, so
// there is one expression to read and no path through this file that can
// produce a different answer.
function debuggerLandingUrl() {
  return appconfig.uiUrl + '/oauth2_oidc_2.html';
}

app.get('/callback', (req, res) => {
  var qp = req.query;
  var queryString='';
  Object.keys(qp).forEach( (key) => {
    queryString= queryString +
                 key +
                 '=' +
                 qp[key] +
                 '&';
  });
  queryString = queryString.substring(0, queryString.length - 1);
  log.info('host: ' + req.headers.host);
  log.info('queryString: ' + queryString);
  res.writeHead(303, {
    'Location': debuggerLandingUrl() + '?' + queryString
  });
  res.end();
});

// OAuth 2.0 Form Post Response Mode — response_mode=form_post.
//
// RFC 9700 section 4.12.2 names it as the remedy for an authorization response
// in the browser's history: the parameters arrive in a POST BODY, so the code
// never appears in a query string on the wire, never in this server's access
// log, never in a Referer, and never in any intermediary's log.
//
// What happens to them next is worth reading rather than assuming. They are
// handed to the page in the URL FRAGMENT, for three reasons: a fragment is
// never sent to any server by any browser, so this same-origin hop leaks
// nothing further; oauth2_oidc_2.js already parses fragments synchronously
// (that is how an implicit response reaches it), so this needs no new
// machinery on the page; and RFC 9700 mode removes it from the address bar and
// from the history entry as soon as the page has read it — see
// rfc9700ScrubAuthorizationResponse() there. The alternative, holding the
// parameters in a map on this server and handing the page a claim ticket,
// would put state into a process that has none and buy nothing the scrub does
// not already provide.
//
// The body cap is deliberate and small: an authorization response is a few
// hundred bytes, and this endpoint is reachable by anybody.
app.post('/callback',
         express.urlencoded({ extended: false, limit: '64kb' }),
         (req, res) => {
  var body = req.body || {};
  var fragment = '';
  Object.keys(body).forEach( (key) => {
    // encodeURIComponent on both halves: a form_post body is not
    // percent-encoded once express has parsed it, and an unencoded '&' or '#'
    // in a value would split the fragment into parameters the page never
    // received. The GET branch above does not need this — those values are
    // still encoded when req.query hands them over.
    fragment = fragment +
               encodeURIComponent(key) +
               '=' +
               encodeURIComponent(body[key]) +
               '&';
  });
  fragment = fragment.substring(0, fragment.length - 1);
  log.info('host: ' + req.headers.host);
  log.info('form_post authorization response received: ' +
           Object.keys(body).join(', '));
  res.writeHead(303, {
    'Location': debuggerLandingUrl() + (fragment ? '#' + fragment : '')
  });
  res.end();
});

app.listen(PORT, HOST);
log.info(`Running on http://${HOST}:${PORT}`);
