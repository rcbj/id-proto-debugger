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
  res.writeHead(302, {
    'Location': appconfig.uiUrl + '/debugger2.html' + '?' + queryString
  });
  res.end();
});

app.listen(PORT, HOST);
log.info(`Running on http://${HOST}:${PORT}`);
