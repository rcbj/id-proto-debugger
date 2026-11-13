// File: xacml_workbench.js
//
// The policy editor and the decision test, with no DOM. A repository
// is a list of named documents held by the caller (the page uses
// localStorage; the node test uses an array). Evaluation uses the
// copied XACML engine. Nothing here talks to a directory or to iya-sts.

'use strict';

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "xacml-workbench",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var model = require("./xacml/xacml_model");
var xml = require("./xacml/xacml_xml");
var jsonProfile = require("./xacml/xacml_json");
var editor = require("./xacml/xacml_editor");
var alfa = require("./xacml/xacml_alfa");
var validate = require("./xacml/xacml_validate");
var pdp = require("./xacml/xacml_pdp");
var requestBuilder = require("./xacml/xacml_request");

var AuthorizationRequest = requestBuilder.AuthorizationRequest;

// The one obligation the iya-sts embedded PEP knows how to discharge.
// Any other obligation turns an otherwise allowed decision into a
// refusal, which is XACML section 7.2.
var DISCHARGEABLE = ['urn:sts:xacml:obligation:log'];

var ALFA_NAMESPACE = "example";

/**
 * Copies a repository row so a caller cannot mutate the stored one.
 *
 * @param {object} row - a stored policy
 * @returns {object} the copy
 */
function copyRow(row) {
  log.debug("Entering copyRow().");
  log.debug("Leaving copyRow().");
  return {
    name: row.name,
    document: row.document,
    enabled: row.enabled !== false,
    isRoot: !!row.isRoot
  };
}

/**
 * An in-memory policy repository.
 *
 * @param {Array<object>} [initial] - rows to start from
 * @returns {object} the repository
 */
function memoryRepository(initial) {
  log.debug("Entering memoryRepository().");
  var rows = (initial || []).map(copyRow);
  log.debug("Leaving memoryRepository().");
  return {
    all: function () {
      log.debug("Entering all().");
      log.debug("Leaving all().");
      return rows.map(copyRow);
    },
    read: function (name) {
      log.debug("Entering read().");
      var found = null;
      rows.forEach(function (row) {
        if (row.name === name) {
          found = copyRow(row);
        }
      });
      log.debug("Leaving read().");
      return found;
    },
    save: function (row) {
      log.debug("Entering save().");
      var next = copyRow(row);
      var replaced = false;
      rows = rows.map(function (one) {
        if (one.name !== next.name) {
          return one;
        }
        replaced = true;
        return next;
      });
      if (!replaced) {
        rows.push(next);
      }
      log.debug("Leaving save().");
      return copyRow(next);
    },
    remove: function (name) {
      log.debug("Entering remove().");
      var before = rows.length;
      rows = rows.filter(function (one) {
        return one.name !== name;
      });
      log.debug("Leaving remove().");
      return rows.length !== before;
    }
  };
}

/**
 * Builds an empty Policy or PolicySet. An empty deny-unless-permit
 * document denies every request until a rule permits one.
 *
 * @param {string} id - the PolicyId or PolicySetId
 * @param {string} kind - 'policy' or 'policyset'
 * @returns {object} the model
 */
function blankModel(id, kind) {
  log.debug("Entering blankModel().");
  var set = String(kind || "").toLowerCase() === "policyset";
  var policy = {
    kind: set ? "PolicySet" : "Policy",
    id: id,
    version: "1.0",
    description: "An empty " + (set ? "PolicySet" : "Policy") +
      ". deny-unless-permit over nothing at all is a Deny, so this " +
      "document refuses every request until a rule permits one.",
    combiningAlgId: set ? model.POLICY_ALG.DENY_UNLESS_PERMIT
                        : model.RULE_ALG.DENY_UNLESS_PERMIT,
    target: null,
    obligations: [],
    advice: []
  };
  if (set) {
    policy.children = [];
  } else {
    policy.variables = {};
    policy.rules = [];
  }
  log.debug("Leaving blankModel().");
  return policy;
}

/**
 * Parses a stored document. A failure is the message, not a throw.
 *
 * @param {string} document - the XACML XML
 * @returns {{policy: object|null, problem: string|null}}
 */
function tryParse(document) {
  log.debug("Entering tryParse().");
  try {
    var parsed = xml.parsePolicy(document);
    log.debug("Leaving tryParse().");
    return { policy: parsed, problem: null };
  } catch (error) {
    log.debug("Leaving tryParse(). It did not parse.");
    return { policy: null, problem: error.message };
  }
}

/**
 * The menus every edit form chooses from.
 *
 * @returns {object} the menus
 */
function editorMenus() {
  log.debug("Entering editorMenus().");
  log.debug("Leaving editorMenus().");
  return {
    types: editor.typeMenu().map(function (one) {
      return { value: one.uri, label: one.label };
    }),
    categories: editor.CATEGORY_MENU.map(function (one) {
      return { value: one.uri, label: one.label };
    }),
    functions: editor.applyFunctions().map(function (one) {
      return {
        value: one.uri,
        label: one.label + "  (" + one.arity + " → " +
          one.returns + ")"
      };
    }),
    matchFunctions: editor.matchFunctions().map(function (one) {
      return { value: one.uri, label: one.label };
    }),
    xpathType: model.TYPE.XPATH_EXPRESSION,
    resourceCategory: model.CATEGORY.RESOURCE
  };
}

/**
 * The fields one tree row's edit form is drawn from.
 *
 * @param {object} parsed - the policy model
 * @param {object} row - a tree row
 * @returns {object|null} the edit data
 */
function editDataFor(parsed, row) {
  log.debug("Entering editDataFor(). path=" + row.path);
  var located = editor.nodeAt(parsed, row.path);
  if (!located) {
    log.debug("Leaving editDataFor(). No node.");
    return null;
  }
  var node = located.node;
  var own = {};
  Object.keys(node).forEach(function (name) {
    var value = node[name];
    if (value === null || typeof value !== "object") {
      own[name] = value;
    }
  });
  ["value", "reference", "namespaces"].forEach(function (name) {
    if (node[name] && typeof node[name] === "object" &&
        !Array.isArray(node[name])) {
      own[name] = Object.assign({}, node[name]);
    }
  });
  var out = { node: own };
  if (row.kind === "policy" || row.kind === "policySet") {
    out.algorithms = editor.algorithmMenuFor(node).map(function (one) {
      return { uri: one.uri, label: one.label, what: one.what || "" };
    });
  }
  if (row.kind === "match" && node.value) {
    out.valueShortType = editor.shortType(node.value.type);
  }
  if (node.kind === "variableRef") {
    out.scope = editor.variablesInScope(parsed, row.path)
      .map(function (one) {
        return { id: one.id, detail: one.detail };
      });
  }
  log.debug("Leaving editDataFor().");
  return out;
}

/**
 * Renders a policy model as ALFA in this page's namespace.
 *
 * @param {object} parsed - the policy model
 * @returns {string} the ALFA text, or a comment when it cannot
 */
function alfaOf(parsed) {
  log.debug("Entering alfaOf().");
  try {
    var text = alfa.write(parsed, { namespace: ALFA_NAMESPACE });
    log.debug("Leaving alfaOf().");
    return text;
  } catch (error) {
    log.debug("Leaving alfaOf(). Could not be rendered.");
    return "// This policy cannot be rendered as ALFA: " + error.message;
  }
}

/**
 * A repository plus the editor and the decision test.
 *
 * @param {object} repository - all/read/save/remove
 * @returns {object} the workbench
 */
function createWorkbench(repository) {
  log.debug("Entering createWorkbench().");

  function names() {
    log.debug("Entering names().");
    log.debug("Leaving names().");
    return repository.all().map(function (row) {
      return row.name;
    });
  }

  function rootRow() {
    log.debug("Entering rootRow().");
    var found = null;
    repository.all().forEach(function (row) {
      if (row.isRoot) {
        found = row;
      }
    });
    log.debug("Leaving rootRow().");
    return found;
  }

  /**
   * Stores a document, making it the root when the repository has none.
   *
   * @param {string} name - the repository name
   * @param {string} document - XACML XML
   * @returns {object} the saved row
   */
  function storeDocument(name, document) {
    log.debug("Entering storeDocument().");
    var anyRoot = !!rootRow();
    var saved = repository.save({
      name: name,
      document: document,
      enabled: true,
      isRoot: anyRoot ? false : true
    });
    log.debug("Leaving storeDocument().");
    return saved;
  }

  /**
   * Creates an empty policy.
   *
   * @param {string} name - the repository name, also the initial id
   * @param {string} kind - 'policy' or 'policyset'
   * @returns {{ok: boolean, why?: string, name?: string}}
   */
  function createBlank(name, kind) {
    log.debug("Entering createBlank().");
    var called = String(name || "").trim();
    if (!called) {
      log.debug("Leaving createBlank(). No name.");
      return { ok: false, why: "A policy needs a name." };
    }
    if (repository.read(called)) {
      log.debug("Leaving createBlank(). The name is taken.");
      return { ok: false,
               why: "There is already a policy called \"" + called + "\"." };
    }
    var document = xml.writePolicy(blankModel(called, kind));
    storeDocument(called, document);
    log.debug("Leaving createBlank().");
    return { ok: true, name: called };
  }

  /**
   * Imports XACML XML or ALFA. The stored form is always XML.
   *
   * @param {string} name - the repository name; the policy id when empty
   * @param {string} text - the document
   * @returns {{ok: boolean, why?: string, name?: string}}
   */
  function importText(name, text) {
    log.debug("Entering importText().");
    var source = String(text || "").trim();
    if (!source) {
      log.debug("Leaving importText(). Empty.");
      return { ok: false, why: "Paste a policy first." };
    }
    var parsed;
    try {
      if (source.charAt(0) === "<") {
        parsed = xml.parsePolicy(source);
      } else {
        parsed = alfa.parse(source);
        xml.parsePolicy(xml.writePolicy(parsed));
      }
    } catch (error) {
      log.debug("Leaving importText(). It did not parse.");
      return { ok: false, why: error.message };
    }
    var called = String(name || "").trim() || parsed.id;
    if (!called) {
      log.debug("Leaving importText(). No name.");
      return { ok: false, why: "The document has no id, so it needs a name." };
    }
    if (repository.read(called)) {
      log.debug("Leaving importText(). The name is taken.");
      return { ok: false,
               why: "There is already a policy called \"" + called + "\"." };
    }
    storeDocument(called, xml.writePolicy(parsed));
    log.debug("Leaving importText().");
    return { ok: true, name: called };
  }

  /**
   * The editor view of one policy.
   *
   * @param {string} name - the repository name; the root when omitted
   * @returns {object} the view
   */
  function editorView(name) {
    log.debug("Entering editorView().");
    var rows = repository.all();
    var chosen = name ? repository.read(name)
                      : (rootRow() || rows[0] || null);
    if (!chosen) {
      log.debug("Leaving editorView(). Nothing to edit.");
      return {
        policies: rows.map(function (one) { return one.name; }),
        policy: null
      };
    }
    var loaded = tryParse(chosen.document);
    var parsed = loaded.policy;
    var json = {
      policies: rows.map(function (one) { return one.name; }),
      policy: {
        name: chosen.name,
        enabled: chosen.enabled,
        isRoot: chosen.isRoot,
        policyId: parsed ? parsed.id : null,
        kind: parsed ? (parsed.kind || "Policy") : null,
        version: parsed ? (parsed.version || "1.0") : null,
        combiningAlgId: parsed ? parsed.combiningAlgId : null,
        description: parsed ? parsed.description : ""
      },
      problem: loaded.problem,
      tree: parsed ? editor.tree(parsed).map(function (row) {
        return {
          path: row.path,
          depth: row.depth,
          kind: row.kind,
          label: row.label,
          detail: row.detail,
          options: editor.optionsAt(parsed, row.path),
          edit: editDataFor(parsed, row)
        };
      }) : [],
      menus: parsed ? editorMenus() : null,
      problems: parsed ? validate.problemsIn(parsed)
                       : [loaded.problem],
      xpathVersionGaps: parsed ? editor.xpathVersionGaps(parsed) : [],
      document: chosen.document,
      alfa: parsed ? alfaOf(parsed) : null
    };
    log.debug("Leaving editorView(). " + json.tree.length + " node(s).");
    return json;
  }

  /**
   * Applies one editor action and stores the document when it still
   * typechecks. A refused edit leaves the stored document as it was.
   *
   * @param {object} body - policy, path, action, and the action's fields
   * @returns {{ok: boolean, why?: string, what?: string}}
   */
  function edit(body) {
    log.debug("Entering edit(). action=" + (body || {}).action);
    var given = body || {};
    var name = String(given.policy || "");
    var existing = repository.read(name);
    if (!existing) {
      log.debug("Leaving edit(). No such policy.");
      return { ok: false,
               why: "There is no policy called \"" + name + "\"." };
    }
    var loaded = tryParse(existing.document);
    if (!loaded.policy) {
      log.debug("Leaving edit(). It will not load.");
      return { ok: false,
               why: "That policy does not load, so it cannot be edited " +
                    "here: " + loaded.problem };
    }
    var policy = xml.parsePolicy(xml.writePolicy(loaded.policy));
    var applied = editor.applyEdit(policy, String(given.path || ""),
                                   String(given.action || ""), given);
    if (!applied.ok) {
      log.debug("Leaving edit(). The edit was refused.");
      return applied;
    }
    var document;
    try {
      document = xml.writePolicy(policy);
      xml.parsePolicy(document);
    } catch (error) {
      log.debug("Leaving edit(). The result does not typecheck.");
      return { ok: false,
               why: "That edit would leave the policy invalid, so it was " +
                    "not saved. " + error.message };
    }
    repository.save({
      name: existing.name,
      document: document,
      enabled: existing.enabled,
      isRoot: existing.isRoot
    });
    log.debug("Leaving edit(). " + applied.what);
    return { ok: true, what: applied.what };
  }

  /**
   * Makes one policy the decision root. The previous root stays in
   * the repository and stops being the root.
   *
   * @param {string} name - the repository name
   * @returns {{ok: boolean, why?: string}}
   */
  function setRoot(name) {
    log.debug("Entering setRoot().");
    var chosen = repository.read(name);
    if (!chosen) {
      log.debug("Leaving setRoot(). No such policy.");
      return { ok: false,
               why: "There is no policy called \"" + name + "\"." };
    }
    repository.all().forEach(function (row) {
      repository.save({
        name: row.name,
        document: row.document,
        enabled: row.enabled,
        isRoot: row.name === name
      });
    });
    log.debug("Leaving setRoot().");
    return { ok: true };
  }

  /**
   * Enables or disables a policy. A disabled policy is left out of
   * reference resolution.
   *
   * @param {string} name - the repository name
   * @param {boolean} enabled - whether the PDP may use it
   * @returns {{ok: boolean, why?: string}}
   */
  function setEnabled(name, enabled) {
    log.debug("Entering setEnabled().");
    var row = repository.read(name);
    if (!row) {
      log.debug("Leaving setEnabled(). No such policy.");
      return { ok: false,
               why: "There is no policy called \"" + name + "\"." };
    }
    row.enabled = !!enabled;
    repository.save(row);
    log.debug("Leaving setEnabled().");
    return { ok: true };
  }

  /**
   * Removes a policy. When it was the root, the first remaining
   * policy becomes the root.
   *
   * @param {string} name - the repository name
   * @returns {{ok: boolean, why?: string}}
   */
  function removePolicy(name) {
    log.debug("Entering removePolicy().");
    var row = repository.read(name);
    if (!row) {
      log.debug("Leaving removePolicy(). No such policy.");
      return { ok: false,
               why: "There is no policy called \"" + name + "\"." };
    }
    var wasRoot = row.isRoot;
    repository.remove(name);
    if (wasRoot) {
      var rest = repository.all();
      if (rest.length) {
        setRoot(rest[0].name);
      }
    }
    log.debug("Leaving removePolicy().");
    return { ok: true };
  }

  /**
   * The policies a reference may resolve to, keyed by PolicyId.
   * The document under test is not included; it is the root of the
   * evaluation itself.
   *
   * @param {string} exceptName - the repository name being decided
   * @returns {object} PolicyId to model
   */
  function repositoryMap(exceptName) {
    log.debug("Entering repositoryMap().");
    var map = {};
    repository.all().forEach(function (row) {
      if (!row.enabled || row.name === exceptName) {
        return;
      }
      var loaded = tryParse(row.document);
      if (loaded.policy && loaded.policy.id) {
        map[loaded.policy.id] = loaded.policy;
      }
    });
    log.debug("Leaving repositoryMap().");
    return map;
  }

  /**
   * Builds the subject / action / resource request the decision form
   * asks, plus any extra attribute rows.
   *
   * @param {object} query - the form
   * @returns {object} the request model
   */
  function requestFromForm(query) {
    log.debug("Entering requestFromForm().");
    var subject = String(query.subject || "");
    var action = String(query.action || "GET");
    var resource = String(query.resource || "");
    var built = new AuthorizationRequest({ includeInResult: true });
    [model.CATEGORY.ACCESS_SUBJECT, model.CATEGORY.ACTION,
     model.CATEGORY.ENVIRONMENT].forEach(function (id) {
      built.category(id);
    });
    if (subject) {
      built.subject(model.ATTRIBUTE.SUBJECT_ID, [subject]);
    }
    built.requestedAction(action);
    if (resource) {
      built.target(resource, model.TYPE.ANYURI);
    }
    (query.attributes || []).forEach(function (row) {
      if (!row || !row.attributeId) {
        return;
      }
      built.attribute(row.category || model.CATEGORY.ACCESS_SUBJECT,
                      row.attributeId, [row.value == null ? "" : row.value],
                      row.type || model.TYPE.STRING);
    });
    var request = built.build();
    log.debug("Leaving requestFromForm().");
    return request;
  }

  /**
   * Reads a pasted request. A leading "{" is the JSON Profile;
   * anything else is XACML XML.
   *
   * @param {string} text - the request document
   * @returns {object} the request model
   */
  function requestFromText(text) {
    log.debug("Entering requestFromText().");
    var source = String(text || "").trim();
    var request = source.charAt(0) === "{"
      ? jsonProfile.parseRequest(source)
      : xml.parseRequest(source);
    log.debug("Leaving requestFromText().");
    return request;
  }

  /**
   * What a PEP would do with a decision, under one bias.
   *
   * @param {object} answer - the PDP response
   * @param {string} asked - 'permit-biased', or deny-biased otherwise
   * @returns {object} allowed, bias, why
   */
  function enforce(answer, asked) {
    log.debug("Entering enforce(). decision=" + answer.decision);
    var bias = asked === "permit-biased" ? "permit-biased" : "deny-biased";
    var undischargeable = [];
    (answer.obligations || []).forEach(function (obligation) {
      var id = obligation.id || obligation;
      if (DISCHARGEABLE.indexOf(id) < 0) {
        undischargeable.push(id);
      }
    });
    var permitted = answer.decision === model.DECISION.PERMIT;
    var denied = answer.decision === model.DECISION.DENY;
    var allowed = bias === "deny-biased" ? permitted : !denied;
    var why;
    if (bias === "deny-biased") {
      why = permitted ? "The PDP said Permit."
        : "The PDP said " + answer.decision + ", and this PEP is " +
          "deny-biased, so anything that is not Permit is a refusal.";
    } else {
      why = denied ? "The PDP said Deny."
        : "The PDP said " + answer.decision + ", and this PEP is " +
          "permit-biased, so anything that is not Deny is allowed.";
    }
    if (allowed && undischargeable.length) {
      allowed = false;
      why = "The PDP said " + answer.decision +
        ", but the decision carries " +
        (undischargeable.length === 1 ? "an obligation" : "obligations") +
        " this PEP cannot discharge (" + undischargeable.join(", ") +
        "). A PEP that cannot fulfil an obligation must not grant " +
        "the access.";
    }
    log.debug("Leaving enforce(). " + (allowed ? "Allowed." : "Refused."));
    return { allowed: allowed, bias: bias, why: why };
  }

  /**
   * Asks the PDP. A pasted request is used when one is present.
   * Otherwise the subject, action, resource and extra attributes
   * are built into a request. The policy is the named one, or the
   * root when the name is omitted.
   *
   * @param {object} query - the form
   * @returns {object} the answer, with asked false when nothing was asked
   */
  function decide(query) {
    log.debug("Entering decide().");
    var given = query || {};
    var pasted = String(given.requestText || "").trim();
    var subject = String(given.subject || "");
    var resource = String(given.resource || "");
    if (!pasted && !subject && !resource &&
        !(given.attributes && given.attributes.length)) {
      log.debug("Leaving decide(). Nothing asked.");
      return { asked: false };
    }
    var chosen = given.policy ? repository.read(given.policy) : rootRow();
    if (!chosen) {
      var rows = repository.all();
      chosen = rows[0] || null;
    }
    if (!chosen) {
      log.debug("Leaving decide(). No policy.");
      return { asked: true, problem: "There is no policy to decide with." };
    }
    var loaded = tryParse(chosen.document);
    if (!loaded.policy) {
      log.debug("Leaving decide(). The policy does not load.");
      return { asked: true, policy: chosen.name,
               problem: loaded.problem };
    }
    var request;
    try {
      request = pasted ? requestFromText(pasted) : requestFromForm(given);
    } catch (error) {
      log.debug("Leaving decide(). The request did not parse.");
      return { asked: true, policy: chosen.name, problem: error.message };
    }
    var answer = pdp.evaluate(loaded.policy, request, {
      repository: repositoryMap(chosen.name)
    });
    var enforcements = ["deny-biased", "permit-biased"].map(function (bias) {
      return enforce(answer, bias);
    });
    log.debug("Leaving decide(). " + answer.decision);
    return {
      asked: true,
      policy: chosen.name,
      subject: pasted ? null : subject,
      action: pasted ? null : String(given.action || "GET"),
      resource: pasted ? null : (resource || null),
      decision: answer.decision,
      status: answer.status,
      obligations: (answer.obligations || []).map(function (one) {
        return one.id || String(one);
      }),
      advice: (answer.advice || []).map(function (one) {
        return one.id || String(one);
      }),
      applicablePolicies: answer.policyIdentifiers || [],
      enforcement: enforcements[0],
      enforcements: enforcements
    };
  }

  /**
   * A one-rule sample: alice is permitted, and deny-unless-permit
   * refuses everyone else.
   *
   * @returns {{ok: boolean, why?: string, name?: string}}
   */
  function loadSample() {
    log.debug("Entering loadSample().");
    var created = createBlank("sample", "policy");
    if (!created.ok) {
      log.debug("Leaving loadSample(). " + created.why);
      return created;
    }
    var ruled = edit({
      policy: "sample",
      path: "",
      action: "add-rule",
      effect: model.EFFECT.PERMIT
    });
    if (!ruled.ok) {
      log.debug("Leaving loadSample(). The rule was refused.");
      return ruled;
    }
    var matched = edit({
      policy: "sample",
      path: "rules.0",
      action: "add-target-anyof",
      value: "alice",
      attributeId: model.ATTRIBUTE.SUBJECT_ID,
      category: model.CATEGORY.ACCESS_SUBJECT
    });
    if (!matched.ok) {
      log.debug("Leaving loadSample(). The match was refused.");
      return matched;
    }
    log.debug("Leaving loadSample().");
    return { ok: true, name: "sample" };
  }

  log.debug("Leaving createWorkbench().");
  /**
   * The stored XACML document of one policy, for download or copy.
   *
   * @param {string} name - the policy's repository name
   * @returns {object} { ok, name, xml } or { ok: false, why }
   */
  function documentOf(name) {
    log.debug("Entering documentOf().");
    var row = name ? repository.read(name) : null;
    if (!row) {
      log.debug("Leaving documentOf(). No such policy.");
      return { ok: false, why: "There is no policy open to export." };
    }
    log.debug("Leaving documentOf().");
    return { ok: true, name: row.name, xml: String(row.document || "") };
  }

  return {
    names: names,
    documentOf: documentOf,
    createBlank: createBlank,
    importText: importText,
    editorView: editorView,
    edit: edit,
    setRoot: setRoot,
    setEnabled: setEnabled,
    removePolicy: removePolicy,
    decide: decide,
    enforce: enforce,
    loadSample: loadSample
  };
}

module.exports = {
  memoryRepository: memoryRepository,
  createWorkbench: createWorkbench,
  blankModel: blankModel,
  ALFA_NAMESPACE: ALFA_NAMESPACE
};
