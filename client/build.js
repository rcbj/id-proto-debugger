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

// [ source basename, browserify --standalone name ] — matches client/Dockerfile
const BUNDLES = [
  ['jwks', 'jwks'],
  ['debugger', 'debug'],
  ['token_detail', 'token_detail'],
  ['debugger2', 'debugger2'],
  ['userinfo', 'userinfo'],
  ['introspection', 'introspection'],
  ['logout', 'logout'],
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

function log(msg) { console.log('[build] ' + msg); }

// 1. Clean output
log('cleaning ' + path.relative(CLIENT_DIR, DIST));
fs.rmSync(DIST, { recursive: true, force: true });
fs.mkdirSync(path.join(DIST, 'js'), { recursive: true });

// 2. Copy static assets
log('copying public/ -> dist/');
fs.cpSync(PUBLIC, DIST, { recursive: true });

// 3. Bundle. debugger2 requires('./data.js'), so stage common/data.js into src/
//    (the Docker build does the same COPY). Removed again afterward.
const stagedData = path.join(SRC, 'data.js');
fs.copyFileSync(COMMON_DATA, stagedData);
try {
  for (const [name, standalone] of BUNDLES) {
    const out = path.join(DIST, 'js', name + '.js');
    log('browserify src/' + name + '.js -> dist/js/' + name + '.js (CONFIG_FILE=' + CONFIG_FILE + ')');
    execFileSync(BROWSERIFY, [
      path.join('src', name + '.js'),
      '-o', out,
      '--debug',
      '--standalone', standalone,
      '-t', '[', 'envify', 'purge', '--CONFIG_FILE', CONFIG_FILE, ']',
    ], { cwd: CLIENT_DIR, stdio: 'inherit' });
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

// 5. Callback shim
fs.mkdirSync(path.join(DIST, 'callback'), { recursive: true });
fs.writeFileSync(path.join(DIST, 'callback', 'index.html'), CALLBACK_HTML);
log('wrote callback/index.html shim');

log('done — dist/ is ready.');
