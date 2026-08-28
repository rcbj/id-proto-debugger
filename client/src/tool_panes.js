// File: tool_panes.js
//
// ---------------------------------------------------------------------------
// The pane grid the standalone tool pages are built out of.
//
// The Digital Signature page established a shape — a grid of collapsible
// fieldsets, each with a Value box, a Copy button on every label, a Key Pair
// sub-section with a keystore format / password / Download row, a pair of
// action buttons and a one-line status readout at the foot — and the
// Encryption / Decryption page is the same page with different cryptography
// in it. This is the half of that shape which is not cryptography: the DOM
// accessors, the collapse/expand behaviour, the clipboard, the download, and
// the "Return to" link that has to point back at whichever page sent you here.
//
// It is a MODULE rather than a copied block because the two pages must not
// drift apart in the small ways nobody reviews — whether a legend toggles on
// click, whether panes start collapsed, whether Copy falls back to
// execCommand on a page served over plain http (where navigator.clipboard is
// undefined, which is every containerized test run). The CSS half of the same
// shape is css/tool_panes.css, linked by both pages.
//
// The DOM is here ON PURPOSE, and it is the only place on these two pages that
// has any: the cryptography lives in crypto_bytes.js, symmetric_crypto.js,
// pk_encryption.js, key_material.js and jose_jwe.js, all of which are
// DOM-free so that tests/crypto_engines.js can drive them in node.
// ---------------------------------------------------------------------------

var bunyan = require("bunyan");
var jose = require("./jose_jwe");

// A node consumer (a test that only wants the pure helpers) may have no
// CONFIG_FILE, so fall back to info rather than failing to load.
var log = bunyan.createLogger({
  name: "tool_panes",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// The grid both pages wrap their panes in. Passed explicitly by anything that
// wants a different one; defaulted so no caller has to say it twice.
var DEFAULT_GRID = '.ds-grid';

// ---------------------------------------------------------------------------
// Field accessors
// ---------------------------------------------------------------------------
function val(id) {
  log.debug("Entering val().");
  var el = document.getElementById(id);
  log.debug("Leaving val().");
  return el ? el.value : '';
}

function setVal(id, value) {
  log.debug("Entering setVal().");
  var el = document.getElementById(id);
  if (el) {
    el.value = value;
  }
  log.debug("Leaving setVal().");
}

function isChecked(id) {
  log.debug("Entering isChecked().");
  var el = document.getElementById(id);
  log.debug("Leaving isChecked().");
  return !!(el && el.checked);
}

// ---------------------------------------------------------------------------
// Collapse / expand.
//
// Panes start COLLAPSED on both pages: nine panes expanded is a page you have
// to scroll past to find the one you came for, and the titles are the index.
// ---------------------------------------------------------------------------
function setAllCollapsed(collapsed, gridSelector) {
  log.debug("Entering setAllCollapsed().");
  var panes = document.querySelectorAll((gridSelector || DEFAULT_GRID) +
                                        ' > fieldset');
  for (var i = 0; i < panes.length; i++) {
    if (collapsed) {
      panes[i].classList.add('ds-collapsed');
    } else {
      panes[i].classList.remove('ds-collapsed');
    }
  }
  log.debug("Leaving setAllCollapsed().");
  return false;
}

function expandAll(gridSelector) {
  log.debug("Entering expandAll().");
  log.debug("Leaving expandAll().");
  return setAllCollapsed(false, gridSelector);
}

function collapseAll(gridSelector) {
  log.debug("Entering collapseAll().");
  log.debug("Leaving collapseAll().");
  return setAllCollapsed(true, gridSelector);
}

// Make each pane's legend the control that opens it. The listener is added
// once per legend at load; a pane added to the DOM later would need this
// called again, and neither page does that.
function wireCollapsibleLegends(gridSelector) {
  log.debug("Entering wireCollapsibleLegends().");
  var legends = document.querySelectorAll((gridSelector || DEFAULT_GRID) +
                                          ' > fieldset > legend');
  for (var i = 0; i < legends.length; i++) {
    // An anonymous handler: it has no name to log and the house style leaves
    // those alone.
    legends[i].addEventListener('click', function () {
      this.parentNode.classList.toggle('ds-collapsed');
    });
  }
  log.debug("Leaving wireCollapsibleLegends(). n=" + legends.length);
  return legends.length;
}

// ---------------------------------------------------------------------------
// Clipboard
//
// navigator.clipboard is undefined outside a secure context, and the
// containerized suite serves these pages over plain http on a hostname that is
// not localhost — so the execCommand fallback is not legacy politeness, it is
// the path every test run takes.
// ---------------------------------------------------------------------------
function copyField(elementId) {
  log.debug("Entering copyField().");
  var el = document.getElementById(elementId);
  if (!el) {
    log.error('copyField: element not found: ' + elementId);
    log.debug("Leaving copyField(). No such element.");
    return false;
  }
  var text = el.value || '';
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(function (err) {
      log.error('copyField: ' + err);
    });
    log.debug("Leaving copyField(). Async clipboard.");
    return false;
  }
  try {
    el.focus();
    el.select();
    document.execCommand('copy');
  } catch (e) {
    log.error('copyField fallback: ' + e.message);
  }
  log.debug("Leaving copyField(). execCommand fallback.");
  return false;
}

// ---------------------------------------------------------------------------
// Downloads
// ---------------------------------------------------------------------------
function triggerDownload(filename, data, mime) {
  log.debug("Entering triggerDownload(). filename=" + filename);
  var blob = new Blob([data], { type: mime || 'application/octet-stream' });
  var url = URL.createObjectURL(blob);
  var anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  log.debug("Leaving triggerDownload().");
}

// Emit a JWK set (public + private), optionally PBES2-encrypted, as a
// download, and report which of the two it was. The encryption is
// jose_jwe.js's, so the .jwe this writes is the same artifact jwt_tools and
// the PKI page write.
async function downloadJwkSet(jwks, password, baseName, statusId) {
  log.debug("Entering downloadJwkSet(). baseName=" + baseName);
  var text = JSON.stringify({ keys: jwks }, null, 2);
  if (password) {
    triggerDownload(baseName + '.jwe',
                    await jose.pbes2JweEncrypt(text, password),
                    'application/jose');
    setVal(statusId, 'Downloaded PBES2-encrypted JWK set (' + baseName +
           '.jwe).');
    log.debug("Leaving downloadJwkSet(). Encrypted.");
    return;
  }
  triggerDownload(baseName + '.jwk.json', text, 'application/jwk+json');
  setVal(statusId, 'Downloaded JWK set (' + baseName + '.jwk.json).');
  log.debug("Leaving downloadJwkSet(). Plain.");
}

// ---------------------------------------------------------------------------
// The "Return to" link.
//
// `allowed` is a map of the `?from=` values this page will honour to the paths
// they mean. It is a WHITELIST rather than a redirect: putting
// window.location.search into an href is an open redirector, which is the
// thing requirement 11 of the RFC 9700 client checklist is about and which
// tests/url_safety_schemes.js reads client/src for.
// ---------------------------------------------------------------------------
function setReturnLink(allowed, fallback, linkId) {
  log.debug("Entering setReturnLink().");
  var from = new URLSearchParams(window.location.search).get('from');
  var entry = allowed[from];
  var link = document.getElementById(linkId || 'return_link');
  if (!link) {
    log.debug("Leaving setReturnLink(). No link on this page.");
    return;
  }
  if (entry) {
    link.setAttribute('href', entry.href);
    if (entry.label) {
      link.textContent = '← Return to ' + entry.label;
    }
    log.debug("Leaving setReturnLink(). from=" + from);
    return;
  }
  link.setAttribute('href', fallback || '/oauth2_oidc_1.html');
  log.debug("Leaving setReturnLink(). Fallback.");
}

// ---------------------------------------------------------------------------
// Key generation in these panes can block for a moment — a 4096-bit RSA key
// pair is seconds of pure JS. Defer so that the "…" status paints before the
// main thread is taken.
// ---------------------------------------------------------------------------
function defer(fn) {
  log.debug("Entering defer().");
  setTimeout(fn, 15);
  log.debug("Leaving defer().");
}

module.exports = {
  DEFAULT_GRID: DEFAULT_GRID,
  val: val,
  setVal: setVal,
  isChecked: isChecked,
  setAllCollapsed: setAllCollapsed,
  expandAll: expandAll,
  collapseAll: collapseAll,
  wireCollapsibleLegends: wireCollapsibleLegends,
  copyField: copyField,
  triggerDownload: triggerDownload,
  downloadJwkSet: downloadJwkSet,
  setReturnLink: setReturnLink,
  defer: defer
};
