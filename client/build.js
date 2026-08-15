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
//   5. leaves out the pages a backendless deployment cannot serve, and greys
//      out their landing card (client/static_site.js — Kerberos, today)
//
// CONFIG_FILE selects which env config is baked in (default ./env/prod.js).

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
// Which pages this build does NOT carry, and what the landing page says about
// them. Kerberos needs the api's port-88 relay, which a static site has not
// got — see client/static_site.js for the whole of the reasoning.
const staticSite = require('./static_site.js');

// The Entering/Leaving logging convention (see the repo-root CLAUDE.md)
// wants a `log` here, and bunyan is not reachable from this file:
// it runs from a checkout, before and outside the image build.
// So this is the same call shape backed by console. Debug output is off by
// default, so an ordinary run stays quiet; flip DEBUG to follow a call
// through. Note the methods below are the one place the convention cannot
// apply — a log line inside log.debug() is infinite recursion.
var DEBUG = false;
var LOG_TAG = "[build]";
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

const CLIENT_DIR = __dirname;
const DIST = path.join(CLIENT_DIR, 'dist');
const PUBLIC = path.join(CLIENT_DIR, 'public');
const SRC = path.join(CLIENT_DIR, 'src');
const COMMON_DATA = path.join(CLIENT_DIR, '..', 'common', 'data.js');
const CONFIG_FILE = process.env.CONFIG_FILE || './env/prod.js';
const BROWSERIFY = path.join(CLIENT_DIR, 'node_modules', '.bin', 'browserify');
const TERSER = path.join(CLIENT_DIR, 'node_modules', '.bin', 'terser');
const CLEANCSS = path.join(CLIENT_DIR, 'node_modules', '.bin', 'cleancss');
const HTMLMIN = path.join(CLIENT_DIR, 'node_modules', '.bin',
    'html-minifier-terser');

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
//
// The Kerberos entries stay in this list although this build does not produce
// them: client/static_site.js filters them out below, and a list that still
// names them is what makes the exclusion visible to somebody reading either
// file. Deleting them here instead would make a static-only omission look like
// a page nobody ever registered — the failure client/CLAUDE.md warns about.
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
  ['saml_request', 'saml_request'],
  ['saml_cert', 'saml_cert'],
  ['saml_tools', 'saml_tools'],
  ['saml_response', 'saml_response'],
  ['wstrust_tools', 'wstrust_tools'],
  ['wstrust_response', 'wstrust_response'],
  ['vc_issuance_0', 'vcissuance0'],
  ['vc_issuance_1', 'vcissuance1'],
  ['vc_issuance_2', 'vcissuance2'],
  ['vc_issuance_3', 'vcissuance3'],
  ['vc_issuance_4', 'vcissuance4'],
  ['vc_presentation_0', 'vcpresentation0'],
  ['vc_presentation_1', 'vcpresentation1'],
  ['vc_presentation_2', 'vcpresentation2'],
  ['vc_presentation_3', 'vcpresentation3'],
  ['did_tools', 'didtools'],
  ['webauthn_lab', 'webauthnlab'],
  ['webauthn_analyzer', 'webauthnanalyzer'],
  ['wsfed_request', 'wsfed_request'],
  ['wsfed_response', 'wsfed_response'],
  ['kerberos_decoder', 'kerberos_decoder'],
  ['kerberos', 'kerberos'],
  ['kerberos_tgs', 'kerberos_tgs'],
  ['kerberos_ap', 'kerberos_ap'],
  ['kerberos_delegation', 'kerberos_delegation'],
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
  log.debug("Entering gaSnippet().");
  log.debug("Leaving gaSnippet().");
  return '\n    <!-- Google tag (gtag.js) -->\n' +
    '    <script async src="https://www.googletagmanager.com/gtag/js?id=' + id +
        '"></script>\n' +
    '    <script>\n' +
    '      window.dataLayer = window.dataLayer || [];\n' +
    '      function gtag(){dataLayer.push(arguments);}\n' +
    '      gtag(\'js\', new Date());\n' +
    '      gtag(\'config\', \'' + id + '\');\n' +
    '    </script>\n';
}

// The build's own progress lines went through a `log(msg)` function that wrote
// '[build] ' + msg. That is exactly what the console-backed `log.info` above
// does, so the function is gone rather than renamed — and it had to go: a
// function declaration and a `var` of the same name are ONE binding, so the
// object assignment won and every call below was "log is not a function". This
// script runs outside the suite (deploy/Dockerfile, `npm run build`), so no
// test would have reported it.

// 1. Clean output
log.info('cleaning ' + path.relative(CLIENT_DIR, DIST));
fs.rmSync(DIST, { recursive: true, force: true });
fs.mkdirSync(path.join(DIST, 'js'), { recursive: true });

// 1b. Fix this build's identity (M.N.O) and ship it as dist/version.json.
const appversion = require('./version');
const VERSION = appversion.stamp(DIST);
const BUILD_INFO = appversion.buildInfo(VERSION);
log.info('version ' + VERSION.version + ' (' + BUILD_INFO + ')');
// Warn (don't fail) if a project's package.json version drifted from VERSION.
appversion.checkManifests().filter(function (m) { return !m.ok; })
                          .forEach(function (m) {
  log.warn('WARNING: ' + m.path + ' says ' + m.actual + ', expected ' +
      m.expected + ' — run `node client/version.js --sync-manifests`');
});

// 2. Copy static assets
log.info('copying public/ -> dist/');
fs.cpSync(PUBLIC, DIST, { recursive: true });

// 2a. Drop the pages this deployment cannot serve, and kill their landing card.
//
//     Each removal is asserted rather than attempted: an rmSync on a path that
//     is not there succeeds, so a renamed page would turn the whole exclusion
//     into a no-op and ship a Kerberos workflow whose every button fails at the
//     network. Same for the card — a marker that stopped matching leaves a live
//     link to a page this build just deleted.
staticSite.excludedFiles().forEach(function (rel) {
  const full = path.join(DIST, rel);
  if (!fs.existsSync(full)) {
    throw new Error('client/static_site.js excludes ' + rel + ', which is ' +
        'not in client/public — renamed or already gone? An exclusion that ' +
        'matches nothing silently ships the thing it names.');
  }
  fs.rmSync(full);
  log.info('excluded from the static build: ' + rel);
});

const landingPage = path.join(DIST, 'index.html');
const disabled = staticSite.disableUnavailableCards(
    fs.readFileSync(landingPage, 'utf8'));
if (disabled.count === 0) {
  throw new Error('no landing card carries ' + staticSite.CARD_MARKER +
      ' — client/public/index.html must mark the cards whose pages this ' +
      'build drops, or they stay live and link to a 404.');
}
fs.writeFileSync(landingPage, disabled.html);
log.info('disabled ' + disabled.count + ' landing card(s) not on this ' +
    'deployment');

// 2b. Ship the IANA JWT claim registry as a static object at /claimdescription.
//     On api-backed deployments Express serves GET /claimdescription from
//     api/jwt.xml; the static site has no backend, so the client's fetch of
//     appconfig.apiUrl + "/claimdescription" (apiUrl == the site's own origin
//     here) 404s. Emit the same bytes at that exact path so claim descriptions
//     resolve. The client reads it via response.text() + DOMParser, so the
//     object's content-type does not matter for parsing.
const CLAIM_XML_SRC = path.join(CLIENT_DIR, '..', 'api', 'jwt.xml');
log.info('copying api/jwt.xml -> dist/claimdescription');
fs.copyFileSync(CLAIM_XML_SRC, path.join(DIST, 'claimdescription'));

// 3. Bundle. debugger2 requires('./data.js'), so stage common/data.js into src/
//    (the Docker build does the same COPY). Removed again afterward.
//
//    The Kerberos codec is staged the same way and for the same reason:
//    kerberos_decoder.js requires('./krb5_describe.js') and that module requires
//    its siblings, so browserify has to find them beside the bundle entry point.
//    They live in common/krb5/ rather than client/src because the api's relay and
//    the mock KDC read the same code — a second copy of a wire codec is a codec
//    that drifts.
//
//    Two consequences worth knowing. These files are BUNDLE SOURCE even though
//    they are not under client/src, so the no-bare-require('crypto') rule applies
//    to them (tests/jwk_pem_encoding.js scans common/krb5 for exactly that — a
//    `require("crypto")` there would put `elliptic` into this bundle). And the
//    staging is removed in the `finally` below, so a failed build does not leave
//    copies behind for the next one to bundle silently.
//
//    The staging is conditional on a bundle that needs it actually being built:
//    with every Kerberos page excluded from this deployment, nothing here reads
//    common/krb5, and copying ten modules into client/src for no bundle to
//    require is how a stale copy gets left in a working tree.
const BUILT_BUNDLES = BUNDLES.filter(function (entry) {
  return !staticSite.bundleIsExcluded(entry[0]);
});
BUNDLES.filter(function (entry) {
  return staticSite.bundleIsExcluded(entry[0]);
}).forEach(function (entry) {
  log.info('not bundling ' + entry[0] + ' — its page is not on this ' +
      'deployment');
});
const stagedData = path.join(SRC, 'data.js');
fs.copyFileSync(COMMON_DATA, stagedData);
const KRB5_DIR = path.join(CLIENT_DIR, '..', 'common', 'krb5');
const needsKrb5 = BUILT_BUNDLES.some(function (entry) {
  return entry[0].indexOf('kerberos') === 0;
});
const stagedKrb5 = (needsKrb5 && fs.existsSync(KRB5_DIR))
  ? fs.readdirSync(KRB5_DIR).filter((f) => f.endsWith('.js')).map((f) => {
      const dest = path.join(SRC, f);
      log.info('staging common/krb5/' + f + ' -> src/' + f);
      fs.copyFileSync(path.join(KRB5_DIR, f), dest);
      return dest;
    })
  : [];
try {
  for (const [name, standalone] of BUILT_BUNDLES) {
    const out = path.join(DIST, 'js', name + '.js');
    log.info('browserify src/' + name + '.js -> dist/js/' + name +
        '.js (CONFIG_FILE=' + CONFIG_FILE + ')');
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
      log.info('terser dist/js/' + name + '.js (minify)');
      execFileSync(TERSER, [out, '-o', out, '--compress', '--mangle'],
        { cwd: CLIENT_DIR, stdio: 'inherit' });
    }
  }
} finally {
  fs.rmSync(stagedData, { force: true });
  stagedKrb5.forEach((f) => fs.rmSync(f, { force: true }));
}

// 4. Resolve <!--#include file="/partials/x.html"--> directives in-place
const INCLUDE_RE = /<!--#include file="([^"]+)"-->/g;
function resolveIncludes(dir) {
  log.debug("Entering resolveIncludes().");
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
        console.error('[build] include failed: ' + inc + ' (' + e.message +
                      ')');
        return '';
      }
    });
    if (resolved !== html) {
      fs.writeFileSync(full, resolved);
      log.info('resolved includes in ' + path.relative(DIST, full));
    }
  }
  log.debug("Leaving resolveIncludes().");
}
resolveIncludes(DIST);

// 4a. Nothing that ships may link to something that did not. Run AFTER the
//     includes are resolved, since a header or footer partial is where a link
//     to every page tends to live, and before the minifier rewrites quoting.
//     A dead link on a deployed site is a 404 no test sees until a user clicks
//     it, so this fails the build and names both ends.
function assertNoLinksToExcluded(dir) {
  log.debug("Entering assertNoLinksToExcluded().");
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      assertNoLinksToExcluded(full);
      continue;
    }
    if (!entry.name.endsWith('.html')) continue;
    const dead = staticSite.linksToExcludedFiles(
        fs.readFileSync(full, 'utf8'));
    if (dead.length) {
      log.debug("Leaving assertNoLinksToExcluded().");
      throw new Error(path.relative(DIST, full) + ' links to ' +
          dead.join(', ') + ', which this deployment does not carry. Either ' +
          'that page ships too (client/static_site.js) or the link goes.');
    }
  }
  log.debug("Leaving assertNoLinksToExcluded().");
}
log.info('checking for links to pages this deployment does not carry');
assertNoLinksToExcluded(DIST);

// 4b. Stamp the current year and the M.N.O version into every page. The
//     {{YEAR}} / {{VERSION}} / {{BUILD_INFO}} placeholders ship in the footer
//     partial (now inlined into every page above) and in the error pages. The
//     version record was written to dist/version.json at the top of this build,
//     so the pages and that file agree.
const YEAR = String(new Date().getFullYear());
function stampYear(dir) {
  log.debug("Entering stampYear().");
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) { stampYear(full); continue; }
    if (!entry.name.endsWith('.html')) continue;
    const html = fs.readFileSync(full, 'utf8');
    if (!html.includes('{{YEAR}}') && !html.includes('{{VERSION}}')) continue;
    fs.writeFileSync(full, html
      .split('{{YEAR}}').join(YEAR)
      .split('{{VERSION}}').join(VERSION.version)
      .split('{{BUILD_INFO}}').join(BUILD_INFO));
    log.info('stamped year in ' + path.relative(DIST, full));
  }
  log.debug("Leaving stampYear().");
}
log.info('stamping copyright year ' + YEAR + ' and version ' + VERSION.version);
stampYear(DIST);

// 5. Inject Google Analytics into each page's <head> (hosted build only)
if (GA_MEASUREMENT_ID) {
  const snippet = gaSnippet(GA_MEASUREMENT_ID);
  const HEAD_RE = /<head\b[^>]*>/i;
  function injectGA(dir) {
    log.debug("Entering injectGA().");
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) { injectGA(full); continue; }
      if (!entry.name.endsWith('.html')) continue;
      const html = fs.readFileSync(full, 'utf8');
      if (!HEAD_RE.test(html)) continue;
      const injected = html.replace(HEAD_RE, function (m) { return m +
          snippet; });
      fs.writeFileSync(full, injected);
      log.info('injected GA into ' + path.relative(DIST, full));
    }
    log.debug("Leaving injectGA().");
  }
  log.info('injecting Google Analytics (GA_MEASUREMENT_ID=' +
      GA_MEASUREMENT_ID +
      ')');
  injectGA(DIST);
} else {
  log.info('GA_MEASUREMENT_ID not set — skipping Google Analytics injection');
}

// 6. Minify CSS and HTML (JS was minified per-bundle above). Each tool reads
//    an input and writes an output, so minify to a temp file then swap it in.
if (MINIFY) {
  function minifyInPlace(bin, buildArgs, file) {
    log.debug("Entering minifyInPlace().");
    const tmp = file + '.min.tmp';
    execFileSync(bin, buildArgs(file, tmp), { cwd: CLIENT_DIR,
                 stdio: 'inherit' });
    fs.renameSync(tmp, file);
    log.debug("Leaving minifyInPlace().");
  }
  function walk(dir, ext, fn) {
    log.debug("Entering walk().");
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) { walk(full, ext, fn); continue; }
      if (entry.name.endsWith(ext)) fn(full);
    }
    log.debug("Leaving walk().");
  }

  log.info('minifying CSS');
  walk(DIST, '.css', function (file) {
    minifyInPlace(CLEANCSS, (i, o) => ['-o', o, i], file);
    log.info('cleancss ' + path.relative(DIST, file));
  });

  log.info('minifying HTML');
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
    log.info('html-minifier-terser ' + path.relative(DIST, file));
  });
}

// 7. Callback shim
fs.mkdirSync(path.join(DIST, 'callback'), { recursive: true });
fs.writeFileSync(path.join(DIST, 'callback', 'index.html'), CALLBACK_HTML);
log.info('wrote callback/index.html shim');

log.info('done — dist/ is ready.');
