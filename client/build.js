#!/usr/bin/env node
'use strict';

// Static-site build for the OAuth2/OIDC Debugger client.
//
// Produces client/dist/ containing everything needed to serve the client as
// static content (no Express backend):
//   1. copies client/public/ into dist/
//   2. browserifies each feature bundle into dist/js/ (envify inlines the
//      CONFIG_FILE at build time, exactly like the Docker image build)
//   3. resolves the server-side <!--#include file="..."--> directives that
//      server.js normally handles at request time
//   4. writes a small dist/callback/ shim so the OAuth2 redirect_uri
//      (/callback) still forwards to debugger2.html without a server
//
// CONFIG_FILE selects which env config is baked in (default ./env/prod.js).

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const CLIENT_DIR = __dirname;
const DIST = path.join(CLIENT_DIR, 'dist');
const PUBLIC = path.join(CLIENT_DIR, 'public');
const SRC = path.join(CLIENT_DIR, 'src');
const COMMON_DATA = path.join(CLIENT_DIR, '..', 'common', 'data.js');
const CONFIG_FILE = process.env.CONFIG_FILE || './env/prod.js';
const BROWSERIFY = path.join(CLIENT_DIR, 'node_modules', '.bin', 'browserify');
const TERSER = path.join(CLIENT_DIR, 'node_modules', '.bin', 'terser');
const CLEANCSS = path.join(CLIENT_DIR, 'node_modules', '.bin', 'cleancss');
const HTMLMIN = path.join(CLIENT_DIR, 'node_modules', '.bin', 'html-minifier-terser');

// Minify JS/CSS/HTML so the hosted static site loads faster. On by default for
// this build; set MINIFY=false to skip (useful when debugging a bundle). The
// local Docker container never runs this script, so its assets stay unminified.
const MINIFY = process.env.MINIFY !== 'false';

// Google Analytics is injected into the static (hosted) build ONLY. It is
// keyed off GA_MEASUREMENT_ID: when the var is unset (e.g. a bare `npm run
// build`, or the local Docker container which never runs this script) no
// analytics snippet is emitted. deploy/entrypoint.sh sets this per environment.
const GA_MEASUREMENT_ID = process.env.GA_MEASUREMENT_ID || '';

// [ source basename, browserify --standalone name ] — matches client/Dockerfile
const BUNDLES = [
  ['jwks', 'jwks'],
  ['debugger', 'debug'],
  ['token_detail', 'token_detail'],
  ['debugger2', 'debugger2'],
  ['userinfo', 'userinfo'],
  ['introspection', 'introspection'],
  ['logout', 'logout'],
  ['jwt_tools', 'jwt_tools'],
  ['encoding_tools', 'encoding_tools'],
  ['digital_signature', 'digital_signature'],
  ['saml_tools', 'saml_tools'],
  ['saml_cert', 'saml_cert'],
  ['saml_response', 'saml_response'],
  ['wstrust_tools', 'wstrust_tools'],
  ['wstrust_response', 'wstrust_response'],
];

const CALLBACK_HTML = `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Redirecting…</title>
    <script>
      // Static replacement for the Express /callback route: forward the OAuth2
      // response (query and/or fragment) on to the debugger results page.
      (function () {
        var target = '/debugger2.html' + window.location.search + window.location.hash;
        window.location.replace(target);
      })();
    </script>
  </head>
  <body>Redirecting to the debugger…</body>
</html>
`;

// Google Analytics (GA4 / gtag.js) snippet, placed as high in <head> as
// possible per Google's guidance. Only emitted when GA_MEASUREMENT_ID is set.
function gaSnippet(id) {
  return '\n    <!-- Google tag (gtag.js) -->\n' +
    '    <script async src="https://www.googletagmanager.com/gtag/js?id=' + id + '"></script>\n' +
    '    <script>\n' +
    '      window.dataLayer = window.dataLayer || [];\n' +
    '      function gtag(){dataLayer.push(arguments);}\n' +
    '      gtag(\'js\', new Date());\n' +
    '      gtag(\'config\', \'' + id + '\');\n' +
    '    </script>\n';
}

function log(msg) { console.log('[build] ' + msg); }

// 1. Clean output
log('cleaning ' + path.relative(CLIENT_DIR, DIST));
fs.rmSync(DIST, { recursive: true, force: true });
fs.mkdirSync(path.join(DIST, 'js'), { recursive: true });

// 2. Copy static assets
log('copying public/ -> dist/');
fs.cpSync(PUBLIC, DIST, { recursive: true });

// 2b. Ship the IANA JWT claim registry as a static object at /claimdescription.
//     On api-backed deployments Express serves GET /claimdescription from
//     api/jwt.xml; the static site has no backend, so the client's fetch of
//     appconfig.apiUrl + "/claimdescription" (apiUrl == the site's own origin
//     here) 404s. Emit the same bytes at that exact path so claim descriptions
//     resolve. The client reads it via response.text() + DOMParser, so the
//     object's content-type does not matter for parsing.
const CLAIM_XML_SRC = path.join(CLIENT_DIR, '..', 'api', 'jwt.xml');
log('copying api/jwt.xml -> dist/claimdescription');
fs.copyFileSync(CLAIM_XML_SRC, path.join(DIST, 'claimdescription'));

// 3. Bundle. debugger2 requires('./data.js'), so stage common/data.js into src/
//    (the Docker build does the same COPY). Removed again afterward.
const stagedData = path.join(SRC, 'data.js');
fs.copyFileSync(COMMON_DATA, stagedData);
try {
  for (const [name, standalone] of BUNDLES) {
    const out = path.join(DIST, 'js', name + '.js');
    log('browserify src/' + name + '.js -> dist/js/' + name + '.js (CONFIG_FILE=' + CONFIG_FILE + ')');
    // Omit inline source maps (--debug) when minifying — they would bloat the
    // shipped bundle and defeat the point.
    const bArgs = [
      path.join('src', name + '.js'),
      '-o', out,
      '--standalone', standalone,
      '-t', '[', 'envify', 'purge', '--CONFIG_FILE', CONFIG_FILE, ']',
    ];
    if (!MINIFY) bArgs.splice(3, 0, '--debug');
    execFileSync(BROWSERIFY, bArgs, { cwd: CLIENT_DIR, stdio: 'inherit' });
    if (MINIFY) {
      log('terser dist/js/' + name + '.js (minify)');
      execFileSync(TERSER, [out, '-o', out, '--compress', '--mangle'],
        { cwd: CLIENT_DIR, stdio: 'inherit' });
    }
  }
} finally {
  fs.rmSync(stagedData, { force: true });
}

// 4. Resolve <!--#include file="/partials/x.html"--> directives in-place
const INCLUDE_RE = /<!--#include file="([^"]+)"-->/g;
function resolveIncludes(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) { resolveIncludes(full); continue; }
    if (!entry.name.endsWith('.html')) continue;
    const html = fs.readFileSync(full, 'utf8');
    const resolved = html.replace(INCLUDE_RE, function (match, inc) {
      const incPath = path.join(DIST, inc.replace(/^\/+/, ''));
      try {
        return fs.readFileSync(incPath, 'utf8');
      } catch (e) {
        console.error('[build] include failed: ' + inc + ' (' + e.message + ')');
        return '';
      }
    });
    if (resolved !== html) {
      fs.writeFileSync(full, resolved);
      log('resolved includes in ' + path.relative(DIST, full));
    }
  }
}
resolveIncludes(DIST);

// 4b. Stamp the current year into the copyright notice. The {{YEAR}} placeholder
//     ships in the footer partial (now inlined into every page above) and in the
//     error pages. Done at build time so each build/deploy refreshes the year.
//     server.js does the same substitution at request time for the local build.
const YEAR = String(new Date().getFullYear());
function stampYear(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) { stampYear(full); continue; }
    if (!entry.name.endsWith('.html')) continue;
    const html = fs.readFileSync(full, 'utf8');
    if (!html.includes('{{YEAR}}')) continue;
    fs.writeFileSync(full, html.split('{{YEAR}}').join(YEAR));
    log('stamped year in ' + path.relative(DIST, full));
  }
}
log('stamping copyright year ' + YEAR);
stampYear(DIST);

// 5. Inject Google Analytics into each page's <head> (hosted build only)
if (GA_MEASUREMENT_ID) {
  const snippet = gaSnippet(GA_MEASUREMENT_ID);
  const HEAD_RE = /<head\b[^>]*>/i;
  function injectGA(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) { injectGA(full); continue; }
      if (!entry.name.endsWith('.html')) continue;
      const html = fs.readFileSync(full, 'utf8');
      if (!HEAD_RE.test(html)) continue;
      const injected = html.replace(HEAD_RE, function (m) { return m + snippet; });
      fs.writeFileSync(full, injected);
      log('injected GA into ' + path.relative(DIST, full));
    }
  }
  log('injecting Google Analytics (GA_MEASUREMENT_ID=' + GA_MEASUREMENT_ID + ')');
  injectGA(DIST);
} else {
  log('GA_MEASUREMENT_ID not set — skipping Google Analytics injection');
}

// 6. Minify CSS and HTML (JS was minified per-bundle above). Each tool reads
//    an input and writes an output, so minify to a temp file then swap it in.
if (MINIFY) {
  function minifyInPlace(bin, buildArgs, file) {
    const tmp = file + '.min.tmp';
    execFileSync(bin, buildArgs(file, tmp), { cwd: CLIENT_DIR, stdio: 'inherit' });
    fs.renameSync(tmp, file);
  }
  function walk(dir, ext, fn) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) { walk(full, ext, fn); continue; }
      if (entry.name.endsWith(ext)) fn(full);
    }
  }

  log('minifying CSS');
  walk(DIST, '.css', function (file) {
    minifyInPlace(CLEANCSS, (i, o) => ['-o', o, i], file);
    log('cleancss ' + path.relative(DIST, file));
  });

  log('minifying HTML');
  walk(DIST, '.html', function (file) {
    minifyInPlace(HTMLMIN, (i, o) => [
      i, '-o', o,
      '--collapse-whitespace',
      '--remove-comments',
      '--minify-css', 'true',
      '--minify-js', 'true',
      // Some source pages contain minor markup quirks (e.g. a stray quote in a
      // tag). Don't fail the deploy build over them — skip and pass through.
      '--continue-on-parse-error',
    ], file);
    log('html-minifier-terser ' + path.relative(DIST, file));
  });
}

// 7. Callback shim
fs.mkdirSync(path.join(DIST, 'callback'), { recursive: true });
fs.writeFileSync(path.join(DIST, 'callback', 'index.html'), CALLBACK_HTML);
log('wrote callback/index.html shim');

log('done — dist/ is ready.');
