// File: xacml.js
//
// The XACML page: a guided policy editor and a decision test.
// The grammar, the writer and the PDP live in client/src/xacml/ and
// have no DOM. This file is the only one that touches the page.
// Policies are stored in localStorage under xacml_repository.

'use strict';

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "xacml",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var workbench = require("./xacml_workbench");
var draw = require("./xacml_draw");
// The collapsible panes and the collapse / expand all switch.
var panes = require("./panes");

var STORAGE_KEY = "xacml_repository";

var bench = null;
var selected = "";

/**
 * Reads the repository out of localStorage.
 *
 * @returns {Array<object>} the rows, or [] when nothing is stored
 */
function readStored() {
  log.debug("Entering readStored().");
  var raw = null;
  try {
    raw = window.localStorage.getItem(STORAGE_KEY);
  } catch (error) {
    log.debug("Leaving readStored(). Storage is unavailable.");
    return [];
  }
  if (!raw) {
    log.debug("Leaving readStored(). Empty.");
    return [];
  }
  try {
    var parsed = JSON.parse(raw);
    log.debug("Leaving readStored().");
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    log.debug("Leaving readStored(). Not JSON.");
    return [];
  }
}

/**
 * Writes the repository back to localStorage.
 *
 * @param {object} repository - the memory repository
 */
function writeStored(repository) {
  log.debug("Entering writeStored().");
  try {
    window.localStorage.setItem(STORAGE_KEY,
                                JSON.stringify(repository.all()));
  } catch (error) {
    log.debug("Caught in writeStored(): " + error.message);
  }
  log.debug("Leaving writeStored().");
}

/**
 * A repository that keeps itself in localStorage.
 *
 * @returns {object} the repository
 */
function storedRepository() {
  log.debug("Entering storedRepository().");
  var inner = workbench.memoryRepository(readStored());
  var save = inner.save;
  var remove = inner.remove;
  inner.save = function (row) {
    log.debug("Entering save().");
    var stored = save(row);
    writeStored(inner);
    log.debug("Leaving save().");
    return stored;
  };
  inner.remove = function (name) {
    log.debug("Entering remove().");
    var removed = remove(name);
    writeStored(inner);
    log.debug("Leaving remove().");
    return removed;
  };
  log.debug("Leaving storedRepository().");
  return inner;
}

/**
 * Shows a status line.
 *
 * @param {string} text - the message
 * @param {boolean} warn - whether it is a refusal
 */
function status(text, warn) {
  log.debug("Entering status().");
  var node = document.getElementById("xacml_status");
  if (node) {
    node.textContent = text || "";
    node.className = warn ? "xacml-warn" : "xacml-note";
  }
  log.debug("Leaving status().");
}

/**
 * Fills a select with the repository names.
 *
 * @param {string} id - the select's id
 * @param {string} current - the selected name
 * @param {boolean} blank - whether the first option is empty
 */
function fillNames(id, current, blank) {
  log.debug("Entering fillNames().");
  var node = document.getElementById(id);
  if (!node) {
    log.debug("Leaving fillNames(). No select.");
    return;
  }
  var html = blank ? '<option value="">(the root)</option>' : "";
  bench.names().forEach(function (name) {
    html += '<option value="' + draw.esc(name) + '"' +
      (name === current ? " selected" : "") + ">" +
      draw.esc(name) + "</option>";
  });
  node.innerHTML = html;
  log.debug("Leaving fillNames().");
}

/**
 * Redraws the editor from the repository.
 */
function render() {
  log.debug("Entering render().");
  var view = bench.editorView(selected);
  selected = view.policy ? view.policy.name : "";
  fillNames("xacml_open", selected, false);
  fillNames("xacml_decide_policy", "", true);
  var enabled = document.getElementById("xacml_enabled");
  var rootBox = document.getElementById("xacml_is_root");
  if (enabled) {
    enabled.checked = !!(view.policy && view.policy.enabled);
    enabled.disabled = !view.policy;
  }
  if (rootBox) {
    rootBox.textContent = view.policy && view.policy.isRoot
      ? "This is the decision root."
      : (view.policy ? "This is not the decision root." : "");
  }
  var body = document.getElementById("xacml_editor");
  if (body) {
    body.innerHTML = draw.editorBody(view);
  }
  log.debug("Leaving render().");
}

/**
 * Reads an edit form into the object applyEdit expects.
 *
 * @param {HTMLFormElement} form - the submitted form
 * @returns {object} the fields
 */
function fieldsOf(form) {
  log.debug("Entering fieldsOf().");
  var out = {};
  Array.prototype.forEach.call(form.elements, function (el) {
    if (el.name) {
      out[el.name] = el.value;
    }
  });
  log.debug("Leaving fieldsOf().");
  return out;
}

/**
 * Applies the edit form that was submitted.
 *
 * @param {Event} event - the submit event
 * @returns {boolean} false, so the browser does not navigate
 */
function onEditSubmit(event) {
  log.debug("Entering onEditSubmit().");
  event.preventDefault();
  var result = bench.edit(fieldsOf(event.target));
  if (!result.ok) {
    status(result.why, true);
  } else {
    status(result.what || "Saved.", false);
  }
  render();
  log.debug("Leaving onEditSubmit().");
  return false;
}

/**
 * Creates a blank policy from the name and kind fields.
 *
 * @returns {boolean} false
 */
function createBlank() {
  log.debug("Entering createBlank().");
  var name = document.getElementById("xacml_name").value;
  var kind = document.getElementById("xacml_kind").value;
  var result = bench.createBlank(name, kind);
  if (!result.ok) {
    status(result.why, true);
    log.debug("Leaving createBlank(). Refused.");
    return false;
  }
  selected = result.name;
  status("Created " + result.name + ".", false);
  render();
  // Straight to the policy: every other pane folds and the Editor opens.
  panes.focusPane("xacml_pane_editor");
  log.debug("Leaving createBlank().");
  return false;
}

/**
 * Imports the XML or ALFA in the import box.
 *
 * @returns {boolean} false
 */
function importPolicy() {
  log.debug("Entering importPolicy().");
  var result = bench.importText(
    document.getElementById("xacml_import_name").value,
    document.getElementById("xacml_import").value);
  if (!result.ok) {
    status(result.why, true);
    log.debug("Leaving importPolicy(). Refused.");
    return false;
  }
  selected = result.name;
  status("Imported " + result.name + ".", false);
  render();
  log.debug("Leaving importPolicy().");
  return false;
}

/**
 * Loads the one-rule sample, permitting alice.
 *
 * @returns {boolean} false
 */
function loadSample() {
  log.debug("Entering loadSample().");
  var result = bench.loadSample();
  if (!result.ok) {
    status(result.why, true);
    log.debug("Leaving loadSample(). Refused.");
    return false;
  }
  selected = result.name;
  status("Loaded the sample. alice is permitted; anyone else is denied.",
         false);
  render();
  panes.focusPane("xacml_pane_editor");
  log.debug("Leaving loadSample().");
  return false;
}

/**
 * The open policy's XML in the chosen layout. Formatted is the document
 * as the editor writes it, indented. Unformatted removes the whitespace
 * between elements, which carries no meaning in an XACML document.
 *
 * @param {string} xmlText - the stored document
 * @param {string} layout - "formatted" or "unformatted"
 * @returns {string} the text
 */
function laidOut(xmlText, layout) {
  log.debug("Entering laidOut(). " + layout);
  var text = String(xmlText || "");
  if (layout === "unformatted") {
    text = text.replace(/>\s+</g, "><").trim();
  }
  log.debug("Leaving laidOut().");
  return text;
}

function exportLayout() {
  log.debug("Entering exportLayout().");
  var box = document.getElementById("xacml_export_layout");
  log.debug("Leaving exportLayout().");
  return box && box.value === "unformatted" ? "unformatted" : "formatted";
}

/**
 * Reads a policy file chosen in the upload field and adds it to the
 * repository, as Import does with pasted text. XACML XML or ALFA.
 *
 * @returns {boolean} false
 */
function uploadPolicy() {
  log.debug("Entering uploadPolicy().");
  var input = document.getElementById("xacml_upload");
  var file = input && input.files && input.files[0];
  if (!file) {
    status("Choose a file to upload first.", true);
    log.debug("Leaving uploadPolicy(). No file.");
    return false;
  }
  var reader = new FileReader();
  reader.onload = function () {
    var asName = document.getElementById("xacml_import_name").value ||
        file.name.replace(/\.(xml|alfa|txt)$/i, "");
    var result = bench.importText(asName, String(reader.result || ""));
    if (!result.ok) {
      status(file.name + ": " + result.why, true);
      return;
    }
    selected = result.name;
    status("Uploaded " + file.name + " as " + result.name + ".", false);
    render();
    panes.focusPane("xacml_pane_editor");
  };
  reader.onerror = function () {
    status("Could not read " + file.name + ".", true);
  };
  reader.readAsText(file);
  log.debug("Leaving uploadPolicy().");
  return false;
}

/**
 * Saves the open policy's XML as a file.
 *
 * @returns {boolean} false
 */
function downloadPolicy() {
  log.debug("Entering downloadPolicy().");
  var doc = bench.documentOf(selected);
  if (!doc.ok) {
    status(doc.why, true);
    log.debug("Leaving downloadPolicy(). Nothing open.");
    return false;
  }
  var blob = new Blob([laidOut(doc.xml, exportLayout())],
                      { type: "application/xml" });
  var link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = doc.name + ".xml";
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  setTimeout(function () {
    URL.revokeObjectURL(link.href);
  }, 1000);
  status("Downloaded " + doc.name + ".xml (" + exportLayout() + ").", false);
  log.debug("Leaving downloadPolicy().");
  return false;
}

/**
 * Copies the open policy's XML to the clipboard.
 *
 * @returns {boolean} false
 */
function copyPolicy() {
  log.debug("Entering copyPolicy().");
  var doc = bench.documentOf(selected);
  if (!doc.ok) {
    status(doc.why, true);
    log.debug("Leaving copyPolicy(). Nothing open.");
    return false;
  }
  var text = laidOut(doc.xml, exportLayout());
  var done = function () {
    status("Copied " + doc.name + " (" + exportLayout() + ").", false);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done, function () {
      copyByHand(text) ? done() :
        status("The browser refused the clipboard.", true);
    });
  } else if (copyByHand(text)) {
    done();
  } else {
    status("The browser refused the clipboard.", true);
  }
  log.debug("Leaving copyPolicy().");
  return false;
}

// The clipboard where navigator.clipboard is not offered (plain HTTP).
function copyByHand(text) {
  log.debug("Entering copyByHand().");
  var area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "absolute";
  area.style.left = "-9999px";
  document.body.appendChild(area);
  area.select();
  var ok = false;
  try {
    ok = document.execCommand("copy");
  } catch (e) {
    ok = false;
  }
  document.body.removeChild(area);
  log.debug("Leaving copyByHand(). " + ok);
  return ok;
}

/**
 * Opens the policy chosen in the list.
 *
 * @returns {boolean} false
 */
function openPolicy() {
  log.debug("Entering openPolicy().");
  selected = document.getElementById("xacml_open").value;
  status("", false);
  render();
  log.debug("Leaving openPolicy().");
  return false;
}

/**
 * Makes the open policy the decision root.
 *
 * @returns {boolean} false
 */
function makeRoot() {
  log.debug("Entering makeRoot().");
  if (!selected) {
    status("Open a policy first.", true);
    log.debug("Leaving makeRoot(). None open.");
    return false;
  }
  var result = bench.setRoot(selected);
  status(result.ok ? selected + " is the decision root." : result.why,
         !result.ok);
  render();
  log.debug("Leaving makeRoot().");
  return false;
}

/**
 * Enables or disables the open policy from the checkbox.
 *
 * @returns {boolean} false
 */
function toggleEnabled() {
  log.debug("Entering toggleEnabled().");
  if (!selected) {
    log.debug("Leaving toggleEnabled(). None open.");
    return false;
  }
  var on = document.getElementById("xacml_enabled").checked;
  bench.setEnabled(selected, on);
  status(selected + (on ? " is enabled." : " is disabled."), false);
  render();
  log.debug("Leaving toggleEnabled().");
  return false;
}

/**
 * Removes the open policy.
 *
 * @returns {boolean} false
 */
function removePolicy() {
  log.debug("Entering removePolicy().");
  if (!selected) {
    status("Open a policy first.", true);
    log.debug("Leaving removePolicy(). None open.");
    return false;
  }
  var name = selected;
  var result = bench.removePolicy(name);
  if (!result.ok) {
    status(result.why, true);
    log.debug("Leaving removePolicy(). Refused.");
    return false;
  }
  selected = "";
  status("Removed " + name + ".", false);
  render();
  log.debug("Leaving removePolicy().");
  return false;
}

/**
 * Reads the extra attribute rows under the decision form.
 *
 * @returns {Array<object>} category, attributeId, value, type
 */
function extraAttributes() {
  log.debug("Entering extraAttributes().");
  var rows = [];
  var box = document.getElementById("xacml_attributes");
  if (!box) {
    log.debug("Leaving extraAttributes(). No box.");
    return rows;
  }
  Array.prototype.forEach.call(box.querySelectorAll(".xacml-attr"),
    function (row) {
      var id = row.querySelector('[name="attributeId"]');
      if (!id || !id.value.trim()) {
        return;
      }
      rows.push({
        category: row.querySelector('[name="category"]').value,
        attributeId: id.value.trim(),
        value: row.querySelector('[name="value"]').value,
        type: row.querySelector('[name="type"]').value
      });
    });
  log.debug("Leaving extraAttributes().");
  return rows;
}

/**
 * Adds one empty attribute row to the decision form.
 *
 * @returns {boolean} false
 */
function addAttribute() {
  log.debug("Entering addAttribute().");
  var box = document.getElementById("xacml_attributes");
  var row = document.createElement("div");
  row.className = "xacml-attr";
  row.innerHTML =
    '<input name="category" size="28" ' +
    'value="urn:oasis:names:tc:xacml:1.0:subject-category:' +
    'access-subject" title="The category URI this attribute is in: ' +
    'access-subject, action, resource, environment or another.">' +
    '<input name="attributeId" size="28" placeholder="AttributeId" ' +
    'title="The AttributeId URI a policy reads this value under.">' +
    '<input name="value" size="16" placeholder="value" ' +
    'title="The attribute value, in the lexical form of its DataType.">' +
    '<input name="type" size="18" ' +
    'value="http://www.w3.org/2001/XMLSchema#string" title="The ' +
    'DataType URI of the value, such as XMLSchema#string or #integer.">';
  box.appendChild(row);
  log.debug("Leaving addAttribute().");
  return false;
}

/**
 * Asks the PDP with the decision form.
 *
 * @returns {boolean} false
 */
function decide() {
  log.debug("Entering decide().");
  var policy = document.getElementById("xacml_decide_policy").value;
  var answer = bench.decide({
    policy: policy,
    subject: document.getElementById("xacml_subject").value,
    action: document.getElementById("xacml_action").value,
    resource: document.getElementById("xacml_resource").value,
    requestText: document.getElementById("xacml_request").value,
    attributes: extraAttributes()
  });
  document.getElementById("xacml_decision").innerHTML =
    draw.decisionBody(answer);
  log.debug("Leaving decide().");
  return false;
}

/**
 * Binds the page and draws whatever the repository holds.
 */
function init() {
  log.debug("Entering init().");
  bench = workbench.createWorkbench(storedRepository());
  var editor = document.getElementById("xacml_editor");
  if (editor) {
    editor.addEventListener("submit", onEditSubmit);
  }
  // The SAML Tools pane is a list of links, closed until wanted.
  panes.collapse(["xacml_pane_saml_tools"]);
  render();
  log.debug("Leaving init().");
}

window.onload = init;

module.exports = {
  togglePane: panes.togglePane,
  setAllPanes: panes.setAllPanes,
  uploadPolicy: uploadPolicy,
  downloadPolicy: downloadPolicy,
  copyPolicy: copyPolicy,
  createBlank: createBlank,
  importPolicy: importPolicy,
  loadSample: loadSample,
  openPolicy: openPolicy,
  makeRoot: makeRoot,
  toggleEnabled: toggleEnabled,
  removePolicy: removePolicy,
  addAttribute: addAttribute,
  decide: decide
};
