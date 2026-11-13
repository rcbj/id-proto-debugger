// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: xacml_draw.js
//
// HTML for the policy editor and the decision result. No DOM of its
// own: the page inserts the strings. Every value is escaped.

'use strict';

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "xacml-draw",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

/**
 * Escapes text for HTML.
 *
 * A hot path, so it has no Entering/Leaving pair: every label, value and
 * option the editor draws passes through it, which is thousands of calls
 * per redraw of a large policy, and render() redraws the whole tree after
 * every edit. At logLevel "debug" a pair here would be most of the log.
 * Its callers (editorBody(), decisionBody()) log their own entry and exit.
 *
 * @param {*} value - the text
 * @returns {string} the escaped text
 */
function esc(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * A hidden input.
 *
 * @param {string} name - the field name
 * @param {*} value - the value
 * @returns {string} the input
 */
function hidden(name, value) {
  log.debug("Entering hidden().");
  log.debug("Leaving hidden().");
  return '<input type="hidden" name="' + esc(name) + '" value="' +
    esc(value) + '">';
}

/**
 * A text input.
 *
 * @param {string} name - the field name
 * @param {*} value - the value
 * @param {number} size - the size attribute
 * @returns {string} the input
 */
function textField(name, value, size) {
  log.debug("Entering textField().");
  log.debug("Leaving textField().");
  return '<input type="text" name="' + esc(name) + '" value="' +
    esc(value == null ? "" : value) + '" size="' + Number(size) + '"' +
    titleFor(name) + '>';
}

// THE TOOLTIP OF EVERY EDITOR FIELD, by its form field name. Every field
// the editor draws comes through textField() or select(), so one table
// covers all of them; a name not listed gets no title.
var FIELD_TIPS = {
  action: "What to add or remove at this element.",
  attributeId: "The AttributeId: the URI naming the attribute to read " +
    "from the request.",
  category: "The attribute category: access-subject, action, " +
    "resource, environment, or another category URI.",
  combiningAlgId: "How the decisions of the children are combined " +
    "into one: deny-overrides, permit-overrides, first-applicable, " +
    "deny-unless-permit and the rest.",
  contextSelectorId: "The AttributeId of an XPath attribute in the " +
    "request whose value is the context node of the Path.",
  dataType: "The XML Schema or XACML data type of the value, such " +
    "as string, anyURI, integer or dateTime.",
  description: "Free text describing this element. It does not affect " +
    "the decision.",
  effect: "Permit or Deny: what this Rule returns when its target and " +
    "condition both match.",
  functionId: "The XACML function applied to the arguments.",
  id: "The identifier of this element: its PolicyId, PolicySetId or " +
    "RuleId.",
  issuer: "The Issuer an attribute must carry to match. Empty matches " +
    "any issuer.",
  lexical: "The value, written as the data type's lexical form.",
  matchId: "The function comparing the literal with each attribute " +
    "value, such as string-equal.",
  maxDelegationDepth: "The longest delegation chain an administrative " +
    "request may follow. Empty means unlimited.",
  mustBePresent: "Yes makes a missing attribute an Indeterminate " +
    "result; no treats it as an empty bag.",
  namespacePrefix: "The XML namespace prefix used in the XPath " +
    "expressions.",
  namespaceUri: "The namespace URI that prefix stands for.",
  on: "Which obligation or advice list this expression belongs to.",
  path: "The XPath expression selecting values from the request's " +
    "Content.",
  ref: "The id of the Policy or PolicySet this reference points to.",
  referenceKind: "Whether the reference names a Policy or a PolicySet.",
  type: "The kind of element to add.",
  value: "The literal value.",
  variableId: "The VariableDefinition this refers to, or defines.",
  version: "The version of this Policy or PolicySet, such as 1.0.",
  xpathCategory: "The category whose Content an XPath expression " +
    "reads.",
  xpathVersion: "The XPath version the document's XPath expressions " +
    "are written in."
};

// Explanatory text, folded: a <details> closed until asked for, styled by
// saml_common.css's `saml-explain`. `inner` is already HTML.
function explain(summary, inner) {
  log.debug("Entering explain().");
  log.debug("Leaving explain().");
  return '<details class="saml-explain"><summary>' + esc(summary) +
    "</summary><div>" + inner + "</div></details>";
}

function titleFor(name) {
  log.debug("Entering titleFor().");
  var tip = Object.prototype.hasOwnProperty.call(FIELD_TIPS, name) ?
      FIELD_TIPS[name] : "";
  log.debug("Leaving titleFor().");
  return tip ? ' title="' + esc(tip) + '"' : "";
}

/**
 * A select.
 *
 * @param {string} name - the field name
 * @param {Array<object>} options - value and label
 * @param {*} selected - the selected value
 * @returns {string} the select
 */
function select(name, options, selected) {
  log.debug("Entering select().");
  var html = '<select name="' + esc(name) + '"' + titleFor(name) + '>';
  (options || []).forEach(function (one) {
    var on = String(one.value) === String(selected == null ? "" : selected);
    html += '<option value="' + esc(one.value) + '"' +
      (on ? " selected" : "") + '>' + esc(one.label) + '</option>';
  });
  html += "</select>";
  log.debug("Leaving select().");
  return html;
}

/**
 * Yes or no. A checkbox would omit the field when clear, and a form
 * that does not edit this field must not be read as "no".
 *
 * @param {string} name - the field name
 * @param {*} value - whether it is yes
 * @returns {string} the select
 */
function yesNo(name, value) {
  log.debug("Entering yesNo().");
  log.debug("Leaving yesNo().");
  return select(name, [
    { value: "false", label: "no" },
    { value: "true", label: "yes" }
  ], value ? "true" : "false");
}

/**
 * The start of one edit form.
 *
 * @param {object} view - the editor view
 * @param {object} row - the tree row
 * @param {string} action - the editor action
 * @returns {string} the opening form and the hidden fields
 */
function formHead(view, row, action) {
  log.debug("Entering formHead().");
  log.debug("Leaving formHead().");
  return '<form class="xacml-edit">' +
    hidden("policy", view.policy.name) +
    hidden("path", row.path) +
    hidden("action", action);
}

/**
 * The expression fields under a value, designator, selector, function
 * or apply. A variable definition uses the same forms.
 *
 * @param {object} view - the editor view
 * @param {object} row - the tree row
 * @param {object} node - the expression
 * @returns {string} the form, or ''
 */
function expressionForm(view, row, node) {
  log.debug("Entering expressionForm().");
  var menus = view.menus || {};
  if (node.kind === "value") {
    var xpath = node.type === menus.xpathType;
    var html = formHead(view, row, "edit-value") +
      textField("lexical", node.lexical, 24) + " as " +
      select("type", menus.types, node.type) +
      (xpath ? " over " + select("xpathCategory", menus.categories,
                                 node.xpathCategory || menus.resourceCategory)
             : "") +
      ' <button type="submit">Update</button></form>';
    log.debug("Leaving expressionForm(). A value.");
    return html;
  }
  if (node.kind === "designator") {
    log.debug("Leaving expressionForm(). A designator.");
    return formHead(view, row, "edit-designator") +
      textField("attributeId", node.attributeId, 24) + " in " +
      select("category", menus.categories, node.category) + " as " +
      select("dataType", menus.types, node.dataType) +
      " Issuer " + textField("issuer", node.issuer, 16) +
      " must be present " + yesNo("mustBePresent", node.mustBePresent) +
      ' <button type="submit">Update</button></form>' +
      explain("Notes", "Issuer is optional. must be present " +
      "turns a missing attribute into Indeterminate.");
  }
  if (node.kind === "selector") {
    var bindings = Object.keys(node.namespaces || {}).filter(function (p) {
      return p !== "";
    }).sort().map(function (prefix) {
      return "<code>" + esc(prefix) + "</code> → <code>" +
        esc(node.namespaces[prefix]) + "</code>";
    }).join(", ");
    log.debug("Leaving expressionForm(). A selector.");
    return formHead(view, row, "edit-selector") +
      "Path " + textField("path", node.path, 30) + " over " +
      select("category", menus.categories, node.category) + " as " +
      select("dataType", menus.types, node.dataType) +
      "<br>ContextSelectorId " +
      textField("contextSelectorId", node.contextSelectorId, 24) +
      " must be present " + yesNo("mustBePresent", node.mustBePresent) +
      " namespace " + textField("namespacePrefix", "", 6) + " = " +
      textField("namespaceUri", "", 30) +
      ' <button type="submit">Update</button></form>' +
      '<div class="xacml-sub">Bindings: ' +
      (bindings || "<em>none</em>") + ".</div>" +
      explain("Notes", "A prefix and a URI on Update adds one binding. " +
      "This PDP does not evaluate XPath.");
  }
  if (node.kind === "function") {
    log.debug("Leaving expressionForm(). A function.");
    return formHead(view, row, "edit-function") +
      select("functionId", menus.functions, node.functionId) +
      ' <button type="submit">Update</button></form>' +
      explain("Notes", "A function used as a value, not applied " +
      "here. any-of and map take one of these.");
  }
  if (node.kind === "apply") {
    log.debug("Leaving expressionForm(). An apply.");
    return formHead(view, row, "edit-apply") +
      select("functionId", menus.functions, node.functionId) +
      " Description " + textField("description", node.description, 30) +
      ' <button type="submit">Update</button></form>';
  }
  if (node.kind === "variableRef") {
    var scope = row.edit.scope || [];
    if (!scope.length) {
      log.debug("Leaving expressionForm(). No variables in scope.");
      return '<div class="xacml-sub">$' + esc(node.variableId) +
        " is not defined on this policy.</div>";
    }
    log.debug("Leaving expressionForm(). A variable reference.");
    return formHead(view, row, "set-expression-variable") +
      select("variableId", scope.map(function (one) {
        return { value: one.id, label: "$" + one.id + " — " + one.detail };
      }), node.variableId) +
      ' <button type="submit">Update</button></form>';
  }
  log.debug("Leaving expressionForm(). No fields.");
  return "";
}

/**
 * The edit form for one tree row.
 *
 * @param {object} view - the editor view
 * @param {object} row - the tree row
 * @returns {string} the form, or ''
 */
function editForm(view, row) {
  log.debug("Entering editForm().");
  if (!row.edit) {
    log.debug("Leaving editForm(). Nothing to edit.");
    return "";
  }
  var node = row.edit.node;
  if (row.kind === "policy" || row.kind === "policySet") {
    var menu = row.edit.algorithms || [];
    var chosen = menu.filter(function (one) {
      return one.uri === node.combiningAlgId;
    })[0] || {};
    log.debug("Leaving editForm(). A policy.");
    return formHead(view, row, "edit-policy") +
      (row.kind === "policySet" ? "PolicySetId " : "PolicyId ") +
      textField("id", node.id, 40) + " " +
      select("combiningAlgId", menu.map(function (one) {
        return { value: one.uri, label: one.label };
      }), node.combiningAlgId) +
      " Version " + textField("version", node.version || "1.0", 6) +
      "<br>Description " + textField("description", node.description, 60) +
      "<br>MaxDelegationDepth " +
      textField("maxDelegationDepth", node.maxDelegationDepth, 4) +
      " XPathVersion " + textField("xpathVersion", node.xpathVersion, 44) +
      ' <button type="submit">Update</button></form>' +
      explain("Notes", esc(chosen.what || "") + "<br>" +
      "MaxDelegationDepth is stored and not " +
      "read by this PDP. XPathVersion is reported when a selector " +
      "needs it, and it is not enforced.");
  }
  if (row.kind === "reference") {
    log.debug("Leaving editForm(). A reference.");
    return formHead(view, row, "edit-reference") +
      esc(node.kind) + " " + textField("ref", node.ref, 44) +
      " Version " + textField("version", node.version, 8) +
      ' <button type="submit">Update</button></form>' +
      explain("Notes", "Resolved from the other enabled " +
      "policies when a decision is asked, by PolicyId.");
  }
  if (row.kind === "rule") {
    log.debug("Leaving editForm(). A rule.");
    return formHead(view, row, "edit-rule") +
      select("effect", [
        { value: "Permit", label: "Permit" },
        { value: "Deny", label: "Deny" }
      ], node.effect) +
      " RuleId " + textField("id", node.id, 36) +
      " Description " + textField("description", node.description, 40) +
      ' <button type="submit">Update</button></form>';
  }
  if (row.kind === "variable") {
    var id = String(row.path).split(".").pop();
    log.debug("Leaving editForm(). A variable.");
    return formHead(view, row, "edit-variable") +
      "VariableId $" + textField("variableId", id, 12) +
      ' <button type="submit">Rename</button></form>' +
      explain("Notes", "Renaming rewrites every reference. " +
      "A dot in the name is refused, because a path uses dots.") +
      expressionForm(view, row, node);
  }
  if (row.kind === "match") {
    var reference = node.reference || {};
    var selector = reference.kind === "selector";
    var test = formHead(view, row, "edit-match") +
      select("matchId", view.menus.matchFunctions, node.matchId) + " " +
      textField("value", node.value.lexical, 18) +
      ' <button type="submit">Update</button></form>' +
      '<div class="xacml-sub">Value type: ' +
      esc(row.edit.valueShortType) +
      ". Changing the function changes the type of both sides.</div>";
    var against = formHead(view, row, "edit-match") +
      "against " +
      select("referenceKind", [
        { value: "designator", label: "an attribute" },
        { value: "selector", label: "a selector" }
      ], selector ? "selector" : "designator") + " " +
      (selector
        ? "Path " + textField("path", reference.path, 24)
        : "AttributeId " +
          textField("attributeId", reference.attributeId, 24)) +
      " in " + select("category", view.menus.categories, reference.category) +
      (selector
        ? " ContextSelectorId " +
          textField("contextSelectorId", reference.contextSelectorId, 20)
        : " Issuer " + textField("issuer", reference.issuer, 16)) +
      " must be present " +
      yesNo("mustBePresent", reference.mustBePresent) +
      ' <button type="submit">Update</button></form>';
    log.debug("Leaving editForm(). A match.");
    return test + against;
  }
  if (row.kind === "assignment") {
    log.debug("Leaving editForm(). An assignment.");
    return formHead(view, row, "edit-assignment") +
      "AttributeId " + textField("attributeId", node.attributeId, 30) +
      " Category " + select("category",
        [{ value: "", label: "(none)" }].concat(view.menus.categories),
        node.category || "") +
      " Issuer " + textField("issuer", node.issuer, 16) +
      ' <button type="submit">Update</button></form>';
  }
  if (row.kind === "obligation") {
    log.debug("Leaving editForm(). An obligation.");
    return formHead(view, row, "edit-obligation") +
      textField("id", node.id, 40) + " fires on " +
      select("on", [
        { value: "Permit", label: "Permit" },
        { value: "Deny", label: "Deny" }
      ], node.on) +
      ' <button type="submit">Update</button></form>';
  }
  if (row.kind === "expression") {
    log.debug("Leaving editForm(). An expression.");
    return expressionForm(view, row, node);
  }
  log.debug("Leaving editForm(). No form for this kind.");
  return "";
}

/**
 * The editor body: warnings, the tree, ALFA and the stored XML.
 *
 * @param {object} view - editorView()
 * @returns {string} the HTML
 */
function editorBody(view) {
  log.debug("Entering editorBody().");
  if (!view.policy) {
    log.debug("Leaving editorBody(). Empty.");
    return '<p class="xacml-warn">There is nothing to edit yet. ' +
      "Create a blank policy, load the sample, or import XML or ALFA. " +
      "An empty deny-unless-permit policy denies every request.</p>";
  }
  var parsed = !view.problem;
  var html = "";
  if (view.policy.enabled && view.policy.isRoot) {
    html += '<p class="xacml-warn">This policy is the decision root ' +
      "and it is enabled. Try a decision uses it. Disable it, or " +
      "choose another root, before experimenting on a live copy.</p>";
  }
  if (view.problems && view.problems.length) {
    html += '<div class="xacml-warn"><ul>';
    view.problems.forEach(function (one) {
      html += "<li>" + esc(one) + "</li>";
    });
    html += "</ul><p>An edit that does not typecheck is not saved.</p></div>";
  }
  if (view.xpathVersionGaps && view.xpathVersionGaps.length) {
    html += '<p class="xacml-warn">';
    if (view.xpathVersionGaps.length === 1) {
      html += "<code>" + esc(view.xpathVersionGaps[0]) + "</code> holds " +
        "an AttributeSelector or an xpathExpression and has no " +
        "XPathVersion.";
    } else {
      html += "These policies need an XPathVersion: " +
        view.xpathVersionGaps.map(function (one) {
          return "<code>" + esc(one) + "</code>";
        }).join(", ") + ".";
    }
    html += " This PDP does not evaluate XPath, so the gap is reported " +
      "and the document is still saved.</p>";
  }
  if (!parsed) {
    html += '<p class="xacml-warn">' + esc(view.problem) + "</p>";
    log.debug("Leaving editorBody(). Unparsed.");
    return html;
  }
  html += explain("How Add and edits work", "Each Add offers only the " +
    "elements that are legal at that point, from the same grammar that " +
    "checks the result. An edit updates the copy stored in this " +
    "browser. ALFA is a view of that document, not a second copy.");
  html += "<table class=\"xacml-tree\"><tr><th>Element</th><th>Kind</th>" +
    "<th>Add / remove</th></tr>";
  view.tree.forEach(function (row) {
    var adds = (row.options && row.options.additions) || [];
    var depth = Math.min(Math.max(0, Number(row.depth) || 0), 9);
    var menu = adds.length
      ? '<form class="xacml-edit">' +
        hidden("policy", view.policy.name) +
        hidden("path", row.path) +
        select("action", adds.map(function (one) {
          return { value: one.action, label: one.label };
        }), "") +
        ' <button type="submit">Add</button></form>'
      : "";
    var remove = row.options && row.options.removable
      ? '<form class="xacml-edit">' +
        hidden("policy", view.policy.name) +
        hidden("path", row.path) +
        hidden("action", "remove") +
        '<button type="submit">Remove</button></form>'
      : "";
    var helps = adds.filter(function (one) {
      return one.help;
    }).map(function (one) {
      return "<strong>" + esc(one.label) + "</strong> — " + esc(one.help);
    }).join("<br>");
    html += '<tr><td class="xacml-indent-' + depth + '"><code>' +
      esc(row.label) + "</code>" +
      (row.detail ? '<div class="xacml-sub">' + esc(row.detail) + "</div>"
                  : "") +
      editForm(view, row) +
      (helps ? explain("What can be added here", helps) : "") +
      "</td><td class=\"xacml-sub\">" + esc(row.kind) + "</td><td>" +
      menu + " " + remove + "</td></tr>";
  });
  html += "</table>";
  html += "<details><summary>As ALFA</summary><pre>" +
    esc(view.alfa || "") + "</pre></details>";
  html += "<details><summary>As stored XML</summary><pre>" +
    esc(view.document || "") + "</pre></details>";
  log.debug("Leaving editorBody().");
  return html;
}

/**
 * The decision result.
 *
 * @param {object} answer - decide()
 * @returns {string} the HTML
 */
function decisionBody(answer) {
  log.debug("Entering decisionBody().");
  if (!answer || !answer.asked) {
    log.debug("Leaving decisionBody(). Not asked.");
    return "";
  }
  if (answer.problem) {
    log.debug("Leaving decisionBody(). A problem.");
    return '<p class="xacml-warn">' + esc(answer.problem) + "</p>";
  }
  var policies = answer.applicablePolicies.length
    ? answer.applicablePolicies.map(function (one) {
        var id = one && one.id ? one.id : one;
        return "<code>" + esc(id) + "</code>";
      }).join(", ")
    : "<em>none</em>";
  var deny = answer.enforcement;
  var permit = (answer.enforcements || [])[1] || deny;
  var html = "<h3>" + esc(answer.decision) + "</h3>" +
    "<p>Policy <code>" + esc(answer.policy) + "</code>.</p>" +
    "<table><tr><th>PDP</th><td>" + esc(answer.decision) + "</td></tr>" +
    "<tr><th>Deny-biased PEP</th><td>" +
    (deny.allowed ? "Allowed" : "Refused") +
    '<div class="xacml-sub">' + esc(deny.why) + "</div></td></tr>" +
    "<tr><th>Permit-biased PEP</th><td>" +
    (permit.allowed ? "Allowed" : "Refused") +
    '<div class="xacml-sub">' + esc(permit.why) + "</div></td></tr>" +
    "<tr><th>Applicable policies</th><td>" + policies + "</td></tr>" +
    "<tr><th>Obligations</th><td>" +
    (answer.obligations.length ? esc(answer.obligations.join(", "))
                               : "<em>none</em>") + "</td></tr>" +
    "<tr><th>Advice</th><td>" +
    (answer.advice.length ? esc(answer.advice.join(", "))
                          : "<em>none</em>") + "</td></tr>" +
    "<tr><th>Status</th><td><code>" +
    esc((answer.status || {}).code || "") + "</code>" +
    ((answer.status || {}).message
      ? '<div class="xacml-sub">' + esc(answer.status.message) + "</div>"
      : "") +
    "</td></tr></table>";
  log.debug("Leaving decisionBody().");
  return html;
}

module.exports = {
  esc: esc,
  editorBody: editorBody,
  decisionBody: decisionBody
};
