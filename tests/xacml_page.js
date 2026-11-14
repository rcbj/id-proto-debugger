// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: xacml_page.js
//
// The XACML editor page in a browser: load the sample, ask for decisions,
// edit a Match through the tree, have an ill-typed edit refused, add and
// remove a rule, round-trip the policy through the ALFA view and Import,
// make a decision root, survive a reload, and remove a policy. Named _page
// so it does not collide with client/src/xacml.js when the tests image
// copies modules flat.
//
// ---------------------------------------------------------------------------
// WHY IT IS WRITTEN THE WAY IT IS. The same editor in iya-sts has a Selenium
// job that fails intermittently, and every one of its recorded failures is a
// race between the test and the page re-rendering under it: an element
// handle held across a submit goes stale, or a probe lands while the old
// document is being torn down. This page re-renders #xacml_editor with
// innerHTML on EVERY edit, so the same races are available here. The rules
// this file follows so that none of them is:
//
//  * NO ELEMENT HANDLE OUTLIVES ONE executeScript CALL. Every action — find
//    the form for (path, action), fill it, submit it — happens inside one
//    script in the page. A render cannot happen between finding a control
//    and using it, so nothing can go stale.
//  * WAIT ON STATE, NEVER ON ELEMENTS. Each action first clears the status
//    line (or the decision box), then acts, and the test waits until that
//    output is non-empty again. The page's handlers are synchronous, but the
//    wait costs nothing when they are and is right if they ever are not.
//  * THE REPOSITORY IN localStorage IS THE SOURCE OF TRUTH. Assertions about
//    what was saved read xacml_repository, not the drawn tree, so a change to
//    the markup or to the pane layout cannot change what is asserted.
//  * VISIBILITY DOES NOT MATTER. Panes may be collapsed (the layout is being
//    reworked into collapsible panes); a click from a script and
//    requestSubmit() work on a control that is not displayed, and nothing
//    here asks WebDriver to click.
//  * A FAILURE SAYS WHAT THE PAGE SHOWED. Every wait that times out reports
//    the last snapshot: the status line, the repository and the decision.
// ---------------------------------------------------------------------------

const { Builder } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const assert = require("assert");
const { Command, Option } = require("commander");
const browserFlags = require("./browser_flags.js");
const { loadUrl } = require("./page_load.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "xacml_page",
  level: appconfig.LOG_LEVEL || "info"
});
log.info("Log initialized. logLevel=" + log.level());

var baseUrl = "https://localhost:3000";
var headless = true;
var waitTime = appconfig.waitTime;

const MATCH = ".rules.0.target.anyOf.0.allOf.0.matches.0";
const STRING_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:string-equal";
const INTEGER_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:integer-equal";

// ---------------------------------------------------------------------------
// In-page scripts. These run in the BROWSER (Selenium serialises them), so
// they carry no log lines: there is no bunyan there. See CLAUDE.md.
// ---------------------------------------------------------------------------

// Everything a step asserts on, read in one call.
const SNAPSHOT = `
  var out = { ready: false };
  out.ready = document.readyState === "complete" &&
    typeof window.xacml === "object" && window.xacml !== null &&
    !!document.getElementById("xacml_editor") &&
    document.getElementById("xacml_editor").innerHTML.length > 0;
  var st = document.getElementById("xacml_status");
  out.status = st ? st.textContent : "";
  out.statusWarn = st ? st.className.indexOf("xacml-warn") >= 0 : false;
  var raw = null;
  try { raw = window.localStorage.getItem("xacml_repository"); }
  catch (e) { raw = null; }
  var rows = [];
  try { rows = raw ? JSON.parse(raw) : []; } catch (e) { rows = []; }
  out.repo = rows.map(function (r) {
    return { name: r.name, enabled: r.enabled, isRoot: r.isRoot,
             document: r.document };
  });
  var ed = document.getElementById("xacml_editor");
  out.editorText = ed ? ed.textContent : "";
  var pres = ed ? ed.querySelectorAll("details pre") : [];
  out.alfa = pres.length > 0 ? pres[0].textContent : "";
  out.xml = pres.length > 1 ? pres[1].textContent : "";
  var dec = document.getElementById("xacml_decision");
  var h = dec ? dec.querySelector("h3") : null;
  out.decision = h ? h.textContent.trim() : "";
  out.decisionText = dec ? dec.textContent : "";
  function opts(id) {
    var s = document.getElementById(id);
    return s ? Array.prototype.map.call(s.options, function (o) {
      return o.value; }) : [];
  }
  out.openOptions = opts("xacml_open");
  out.decideOptions = opts("xacml_decide_policy");
  return out;`;

// Clear the status line, then press the page's own button whose text is
// `label`. Only buttons with an onclick count: the editor tree draws a
// submit button labelled "Remove" on every removable node, and the first of
// those must never be mistaken for the repository's Remove. Returns an
// error string, or "".
const PRESS = `
  var label = arguments[0];
  var st = document.getElementById("xacml_status");
  if (st) { st.textContent = ""; }
  var buttons = document.querySelectorAll("button[onclick]");
  var hit = null;
  for (var i = 0; i < buttons.length; i++) {
    if (buttons[i].textContent.trim() === label) { hit = buttons[i]; break; }
  }
  if (!hit) {
    return "no button labelled " + JSON.stringify(label) + "; the page has " +
      JSON.stringify(Array.prototype.map.call(buttons, function (b) {
        return b.textContent.trim(); }));
  }
  hit.click();
  return "";`;

// Set fields by id and fire input and change, as typing would.
const SET_FIELDS = `
  var values = arguments[0];
  var missing = [];
  Object.keys(values).forEach(function (id) {
    var el = document.getElementById(id);
    if (!el) { missing.push(id); return; }
    if (el.type === "checkbox") { el.checked = !!values[id]; }
    else { el.value = values[id]; }
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  });
  return missing.length ? "no field " + missing.join(", ") : "";`;

// Find the editor form for (path, action) — a hidden action, or an Add menu
// offering it — optionally the one carrying a control named `carrying`,
// fill it and submit it, all in this one call. Returns an error string
// naming what the editor does offer, or "".
const SUBMIT_EDIT = `
  var path = arguments[0], action = arguments[1], values = arguments[2],
      carrying = arguments[3];
  var st = document.getElementById("xacml_status");
  if (st) { st.textContent = ""; }
  var forms = document.querySelectorAll("#xacml_editor form.xacml-edit");
  var offered = [];
  var chosen = null;
  for (var i = 0; i < forms.length && !chosen; i++) {
    var f = forms[i];
    var p = f.querySelector('input[type="hidden"][name="path"]');
    var a = f.querySelector('input[type="hidden"][name="action"]');
    var menu = f.querySelector('select[name="action"]');
    var acts = a ? [a.value] : (menu ? Array.prototype.map.call(
      menu.options, function (o) { return o.value; }) : []);
    var fp = p ? p.value : null;
    offered.push(fp + " " + acts.join("|"));
    if (fp !== path || acts.indexOf(action) < 0) { continue; }
    if (carrying && !f.querySelector('[name="' + carrying + '"]')) {
      continue;
    }
    chosen = f;
    if (menu) { menu.value = action; }
  }
  if (!chosen) {
    return "no editor form for " + path + " " + action +
      (carrying ? " carrying " + carrying : "") + "; offered: " +
      offered.join("; ");
  }
  var bad = [];
  Object.keys(values || {}).forEach(function (name) {
    var el = chosen.querySelector('[name="' + name + '"]:not([type="hidden"])');
    if (!el) { bad.push(name); return; }
    if (el.tagName === "SELECT") {
      var has = Array.prototype.some.call(el.options, function (o) {
        return o.value === values[name]; });
      if (!has) { bad.push(name + "=" + values[name] + " (not offered)"); }
    }
    el.value = values[name];
  });
  if (bad.length) { return "form " + path + " " + action + ": " +
    bad.join(", "); }
  chosen.requestSubmit();
  return "";`;

// What the editor offers right now, as [path, action] pairs: "add" is
// every option of every Add menu, "edit" every edit form as drawn, and
// "remove" every Remove button.
const OFFERS = `
  var kind = arguments[0];
  var ed = document.getElementById("xacml_editor");
  var out = [];
  Array.prototype.forEach.call(ed.querySelectorAll("form.xacml-edit"),
    function (f) {
      var p = f.querySelector('input[type="hidden"][name="path"]');
      var a = f.querySelector('input[type="hidden"][name="action"]');
      var m = f.querySelector('select[name="action"]');
      if (kind === "add" && m) {
        Array.prototype.forEach.call(m.options, function (o) {
          out.push([p.value, o.value]);
        });
      } else if (kind === "edit" && a && a.value !== "remove") {
        out.push([p.value, a.value]);
      } else if (kind === "remove" && a && a.value === "remove") {
        out.push([p.value, a.value]);
      }
    });
  return out;`;

// Submit the one form at that path offering that action, as drawn.
// Returns null when there is none any more, else the status it left.
const SUBMIT_OFFER = `
  var path = arguments[0], action = arguments[1];
  var ed = document.getElementById("xacml_editor");
  var st = document.getElementById("xacml_status");
  var forms = ed.querySelectorAll("form.xacml-edit");
  for (var i = 0; i < forms.length; i++) {
    var f = forms[i];
    var p = f.querySelector('input[type="hidden"][name="path"]');
    var a = f.querySelector('input[type="hidden"][name="action"]');
    var m = f.querySelector('select[name="action"]');
    if (!p || p.value !== path) { continue; }
    var offers = a ? a.value === action : (m && Array.prototype.some.call(
      m.options, function (o) { return o.value === action; }));
    if (!offers) { continue; }
    if (m) { m.value = action; }
    st.textContent = "";
    st.className = "";
    f.requestSubmit();
    return { warn: st.className.indexOf("xacml-warn") >= 0,
             text: st.textContent };
  }
  return null;`;

// ---------------------------------------------------------------------------
// Node-side helpers.
// ---------------------------------------------------------------------------

async function snapshot(driver) {
  log.debug("Entering snapshot().");
  const shot = await driver.executeScript(SNAPSHOT);
  log.debug("Leaving snapshot().");
  return shot;
}

function describe(shot) {
  log.debug("Entering describe().");
  const text = JSON.stringify({
    status: shot.status,
    statusWarn: shot.statusWarn,
    repo: (shot.repo || []).map(function (r) {
      return r.name + (r.isRoot ? " (root)" : "") +
        (r.enabled === false ? " (disabled)" : "");
    }),
    decision: shot.decision,
    decisionText: (shot.decisionText || "").slice(0, 200)
  });
  log.debug("Leaving describe().");
  return text;
}

async function waitFor(driver, predicate, what) {
  log.debug("Entering waitFor(). " + what);
  let last = {};
  try {
    await driver.wait(async function () {
      last = await snapshot(driver);
      return predicate(last);
    }, waitTime * 5);
  } catch (e) {
    log.debug("Caught in waitFor(): " + ((e && e.message) || e));
    throw new Error(what + ". The page showed: " + describe(last));
  }
  log.debug("Leaving waitFor().");
  return last;
}

async function press(driver, label) {
  log.debug("Entering press(). " + label);
  const error = await driver.executeScript(PRESS, label);
  assert.strictEqual(error, "", error);
  const shot = await waitFor(driver, function (s) {
    return s.status.length > 0;
  }, "pressing " + label + " set no status");
  log.debug("Leaving press().");
  return shot;
}

async function setFields(driver, values) {
  log.debug("Entering setFields().");
  const error = await driver.executeScript(SET_FIELDS, values);
  assert.strictEqual(error, "", error);
  log.debug("Leaving setFields().");
}

async function edit(driver, path, action, values, carrying) {
  log.debug("Entering edit(). " + path + " " + action);
  const error = await driver.executeScript(SUBMIT_EDIT, path, action,
      values || {}, carrying || null);
  assert.strictEqual(error, "", error);
  const shot = await waitFor(driver, function (s) {
    return s.status.length > 0;
  }, "the " + action + " edit at " + JSON.stringify(path) +
     " set no status");
  log.debug("Leaving edit().");
  return shot;
}

async function decide(driver, subject, policy) {
  log.debug("Entering decide(). " + subject + " " + policy);
  await setFields(driver, {
    xacml_subject: subject,
    xacml_action: "GET",
    xacml_resource: "https://example.com/a",
    xacml_request: "",
    xacml_decide_policy: policy
  });
  await driver.executeScript(
      "document.getElementById('xacml_decision').innerHTML = '';");
  const error = await driver.executeScript(PRESS, "Ask");
  assert.strictEqual(error, "", error);
  const shot = await waitFor(driver, function (s) {
    return s.decision.length > 0 || s.decisionText.trim().length > 0;
  }, "asking for " + subject + " drew no decision");
  assert.ok(shot.decision.length > 0,
      "the decision for " + subject + " is a problem, not a decision: " +
      shot.decisionText.slice(0, 300));
  log.debug("Leaving decide(). " + shot.decision);
  return shot.decision;
}

function ruleCount(xml) {
  log.debug("Entering ruleCount().");
  const n = (String(xml).match(/<Rule\b/g) || []).length;
  log.debug("Leaving ruleCount().");
  return n;
}

function documentOf(shot, name) {
  log.debug("Entering documentOf().");
  const row = (shot.repo || []).filter(function (r) {
    return r.name === name;
  })[0];
  log.debug("Leaving documentOf().");
  return row ? row.document : null;
}

async function openFresh(driver) {
  log.debug("Entering openFresh().");
  await loadUrl(driver, baseUrl + "/xacml.html");
  await driver.executeScript(
      "try { localStorage.removeItem('xacml_repository'); } catch (e) {}");
  await loadUrl(driver, baseUrl + "/xacml.html");
  const shot = await waitFor(driver, function (s) {
    return s.ready;
  }, "the XACML page never finished drawing");
  log.debug("Leaving openFresh().");
  return shot;
}

// ---------------------------------------------------------------------------
// The steps.
// ---------------------------------------------------------------------------

async function sampleDecides(driver) {
  log.debug("Entering sampleDecides().");
  let shot = await snapshot(driver);
  assert.ok(/nothing to edit yet/i.test(shot.editorText),
      "a fresh repository should say there is nothing to edit: " +
      shot.editorText.slice(0, 200));
  shot = await press(driver, "Load sample");
  assert.ok(/Loaded the sample/.test(shot.status), shot.status);
  assert.deepStrictEqual(shot.repo.map(function (r) {
    return r.name;
  }), ["sample"]);
  assert.strictEqual(await decide(driver, "alice", "sample"), "Permit");
  assert.strictEqual(await decide(driver, "bob", "sample"), "Deny");
  log.info("PASS  the sample permits alice and denies bob");
  log.debug("Leaving sampleDecides().");
}

async function illTypedEditIsRefused(driver) {
  log.debug("Entering illTypedEditIsRefused().");
  const before = documentOf(await snapshot(driver), "sample");
  const shot = await edit(driver, MATCH, "edit-match",
      { matchId: INTEGER_EQUAL, value: "notanint" }, "value");
  assert.ok(shot.statusWarn, "an ill-typed edit was not shown as a " +
      "refusal: " + shot.status);
  assert.ok(/not a valid integer/.test(shot.status), shot.status);
  assert.strictEqual(documentOf(shot, "sample"), before,
      "a refused edit changed the stored document");
  log.info("PASS  an ill-typed Match is refused and nothing is stored");
  log.debug("Leaving illTypedEditIsRefused().");
}

async function matchEditChangesTheDecision(driver) {
  log.debug("Entering matchEditChangesTheDecision().");
  const shot = await edit(driver, MATCH, "edit-match",
      { matchId: STRING_EQUAL, value: "bob" }, "value");
  assert.ok(!shot.statusWarn, shot.status);
  assert.ok(/>bob</.test(documentOf(shot, "sample")),
      "the stored document does not compare against bob");
  assert.strictEqual(await decide(driver, "bob", "sample"), "Permit");
  assert.strictEqual(await decide(driver, "alice", "sample"), "Deny");
  log.info("PASS  editing the Match to bob moves the Permit to bob");
  log.debug("Leaving matchEditChangesTheDecision().");
}

async function ruleAddedAndRemoved(driver) {
  log.debug("Entering ruleAddedAndRemoved().");
  let shot = await edit(driver, "", "add-rule", {});
  assert.ok(!shot.statusWarn, shot.status);
  assert.strictEqual(ruleCount(documentOf(shot, "sample")), 2);
  shot = await edit(driver, ".rules.1", "remove", {});
  assert.ok(!shot.statusWarn, shot.status);
  assert.strictEqual(ruleCount(documentOf(shot, "sample")), 1);
  log.info("PASS  a rule is added through the Add menu and removed again");
  log.debug("Leaving ruleAddedAndRemoved().");
}

async function alfaRoundTrips(driver) {
  log.debug("Entering alfaRoundTrips().");
  let shot = await snapshot(driver);
  assert.ok(/subjectId == "bob"/.test(shot.alfa),
      "the ALFA view does not show the edited Match: " +
      shot.alfa.slice(0, 400));
  await setFields(driver, {
    xacml_import_name: "fromalfa",
    xacml_import: shot.alfa
  });
  shot = await press(driver, "Import");
  assert.ok(!shot.statusWarn, shot.status);
  assert.ok(/Imported fromalfa/.test(shot.status), shot.status);
  assert.ok(documentOf(shot, "fromalfa"), "fromalfa was not stored");
  assert.strictEqual(await decide(driver, "bob", "fromalfa"), "Permit");
  assert.strictEqual(await decide(driver, "alice", "fromalfa"), "Deny");
  log.info("PASS  the ALFA view imports back and decides the same");
  log.debug("Leaving alfaRoundTrips().");
}

async function decisionRootAnswers(driver) {
  log.debug("Entering decisionRootAnswers().");
  await setFields(driver, { xacml_open: "sample" });
  let shot = await press(driver, "Make decision root");
  assert.ok(!shot.statusWarn, shot.status);
  shot = await waitFor(driver, function (s) {
    return (s.repo || []).some(function (r) {
      return r.name === "sample" && r.isRoot;
    });
  }, "sample was never stored as the decision root");
  assert.strictEqual(await decide(driver, "bob", ""), "Permit");
  log.info("PASS  the decision root answers when no policy is named");
  log.debug("Leaving decisionRootAnswers().");
}

async function survivesAReload(driver) {
  log.debug("Entering survivesAReload().");
  await loadUrl(driver, baseUrl + "/xacml.html");
  const shot = await waitFor(driver, function (s) {
    return s.ready && s.openOptions.length === 2;
  }, "the repository did not come back after a reload");
  assert.deepStrictEqual(shot.openOptions.slice().sort(),
      ["fromalfa", "sample"]);
  assert.ok(/>bob</.test(documentOf(shot, "sample")));
  log.info("PASS  the repository survives a reload");
  log.debug("Leaving survivesAReload().");
}

async function policyRemoved(driver) {
  log.debug("Entering policyRemoved().");
  await setFields(driver, { xacml_open: "fromalfa" });
  const shot = await press(driver, "Remove");
  assert.ok(/Removed fromalfa/.test(shot.status), shot.status);
  assert.deepStrictEqual(shot.repo.map(function (r) {
    return r.name;
  }), ["sample"]);
  log.info("PASS  Remove deletes the open policy");
  log.debug("Leaving policyRemoved().");
}

// EVERY ELEMENT THE PAGE OFFERS TO ADD IS ONE IT CAN ADD, every edit form
// it draws submits, and every Remove removes — through the page's own
// forms, so the editor and the drawing are exercised together in a browser.
// One submission per executeScript call: the page redraws the whole editor
// on each, and a hundred of them in one call outlasts the script timeout.
async function submitOffers(driver, kind, plan, tally) {
  log.debug("Entering submitOffers().");
  for (const step of plan) {
    const got = await driver.executeScript(SUBMIT_OFFER, step[0], step[1]);
    if (got === null) {
      continue;
    }
    tally[kind] += 1;
    if (got.warn) {
      tally[kind + "Refused"] += 1;
      if (tally.refusals.length < 20) {
        tally.refusals.push(step[1] + " at '" + step[0] + "': " + got.text);
      }
    }
  }
  log.debug("Leaving submitOffers().");
}

async function everyOfferWorks(driver) {
  log.debug("Entering everyOfferWorks().");
  await setFields(driver, { xacml_open: "sample" });
  const tally = { add: 0, addRefused: 0, edit: 0, editRefused: 0,
                  remove: 0, removeRefused: 0, refusals: [] };
  for (let pass = 0; pass < 2; pass++) {
    const adds = await driver.executeScript(OFFERS, "add");
    await submitOffers(driver, "add", adds, tally);
  }
  await submitOffers(driver, "edit",
    await driver.executeScript(OFFERS, "edit"), tally);
  // Deepest first, so a removal never shifts an index a later one names.
  const removes = (await driver.executeScript(OFFERS, "remove")).reverse();
  await submitOffers(driver, "remove", removes, tally);
  log.info("every offer: " + JSON.stringify(tally));
  assert.ok(tally.add > 30, "only " + tally.add + " additions were offered");
  assert.ok(tally.addRefused < tally.add / 4,
    "too many offered additions refused: " + tally.refusals.join("; "));
  assert.ok(tally.edit > 10, "only " + tally.edit + " edit forms drawn");
  assert.ok(tally.remove > 10, "only " + tally.remove + " removals drawn");
  const answer = await decide(driver, "alice", "sample");
  assert.ok(["Permit", "Deny", "NotApplicable", "Indeterminate"]
    .indexOf(answer) >= 0, "decision after the walk: " + answer);
  log.info("PASS  every Add, edit and Remove the page draws applies");
  log.debug("Leaving everyOfferWorks().");
}

// ---------------------------------------------------------------------------
// EVERY POLICY-COMBINING ALGORITHM, DECIDED BY THE PAGE.
//
// One PolicySet per algorithm, imported as XML: a policy for alice that
// permits, one for bob that denies, and one for carol whose only rule needs
// an attribute nobody sends (MustBePresent), so it is Indeterminate. dave
// matches none. The expected answers are XACML 3.0 Appendix C's — including
// the two legacy rows, where an error is Deny under deny-overrides and
// Indeterminate (never Permit) under permit-overrides.
// ---------------------------------------------------------------------------
const XNS = "urn:oasis:names:tc:xacml:3.0:core:schema:wd-17";
const SUBJ = "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject";
const COMBINER_ROWS = [
  // [ identifier, alice, bob, carol, dave ]
  ["urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:deny-overrides",
   "Permit", "Deny", "Indeterminate", "NotApplicable"],
  ["urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:" +
   "ordered-permit-overrides",
   "Permit", "Deny", "Indeterminate", "NotApplicable"],
  ["urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:" +
   "deny-unless-permit", "Permit", "Deny", "Deny", "Deny"],
  ["urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:" +
   "permit-unless-deny", "Permit", "Deny", "Permit", "Permit"],
  ["urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:" +
   "first-applicable", "Permit", "Deny", "Indeterminate", "NotApplicable"],
  ["urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:" +
   "only-one-applicable", "Permit", "Deny", "Indeterminate", "NotApplicable"],
  ["urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:deny-overrides",
   "Permit", "Deny", "Deny", "NotApplicable"],
  ["urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:permit-overrides",
   "Permit", "Deny", "Indeterminate", "NotApplicable"]
];

function combinerSetXml(id, alg) {
  log.debug("Entering combinerSetXml().");
  const sv = function (text) {
    return '<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#' +
      'string">' + text + "</AttributeValue>";
  };
  const des = function (attr, must) {
    return '<AttributeDesignator Category="' + SUBJ + '" AttributeId="' +
      attr + '" DataType="http://www.w3.org/2001/XMLSchema#string" ' +
      'MustBePresent="' + must + '"/>';
  };
  const forWho = function (who) {
    return "<Target><AnyOf><AllOf><Match MatchId=\"" + STRING_EQUAL +
      "\">" + sv(who) +
      des("urn:oasis:names:tc:xacml:1.0:subject:subject-id", "false") +
      "</Match></AllOf></AnyOf></Target>";
  };
  const pol = function (pid, who, effect, condition) {
    return '<Policy PolicyId="' + id + "-" + pid + '" Version="1.0" ' +
      'RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-' +
      'algorithm:deny-overrides">' + forWho(who) + '<Rule RuleId="r" ' +
      'Effect="' + effect + '"><Target/>' +
      (condition ? "<Condition>" + condition + "</Condition>" : "") +
      "</Rule></Policy>";
  };
  const needsClearance = '<Apply FunctionId="urn:oasis:names:tc:xacml:1.0:' +
    'function:string-is-in">' + sv("secret") +
    des("urn:example:clearance", "true") + "</Apply>";
  log.debug("Leaving combinerSetXml().");
  return '<PolicySet xmlns="' + XNS + '" PolicySetId="' + id +
    '" Version="1.0" PolicyCombiningAlgId="' + alg + '"><Target/>' +
    pol("alice", "alice", "Permit") + pol("bob", "bob", "Deny") +
    pol("carol", "carol", "Permit", needsClearance) + "</PolicySet>";
}

async function everyCombinerDecides(driver) {
  log.debug("Entering everyCombinerDecides().");
  let asked = 0;
  for (let i = 0; i < COMBINER_ROWS.length; i++) {
    const row = COMBINER_ROWS[i];
    const name = "combine" + i;
    await setFields(driver, {
      xacml_import_name: name,
      xacml_import: combinerSetXml(name, row[0])
    });
    const shot = await press(driver, "Import");
    assert.ok(!shot.statusWarn, row[0] + ": " + shot.status);
    const who = ["alice", "bob", "carol", "dave"];
    for (let j = 0; j < who.length; j++) {
      const got = await decide(driver, who[j], name);
      assert.strictEqual(got, row[j + 1], row[0] + " for " + who[j]);
      asked += 1;
    }
  }
  log.info("PASS  " + COMBINER_ROWS.length + " policy-combining algorithms " +
           "decide as Appendix C says (" + asked + " decisions)");
  log.debug("Leaving everyCombinerDecides().");
}

async function test() {
  log.debug("Entering test().");
  const options = new chrome.Options();
  if (headless) {
    options.addArguments("--headless=new");
  }
  options.addArguments("--no-sandbox", "--disable-dev-shm-usage");
  browserFlags.addBrowserAccessFlags(options, baseUrl);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  try {
    await openFresh(driver);
    await sampleDecides(driver);
    await illTypedEditIsRefused(driver);
    await matchEditChangesTheDecision(driver);
    await ruleAddedAndRemoved(driver);
    await alfaRoundTrips(driver);
    await decisionRootAnswers(driver);
    await survivesAReload(driver);
    await policyRemoved(driver);
    await everyOfferWorks(driver);
    await everyCombinerDecides(driver);
    log.info("Test completed successfully.");
  } catch (error) {
    log.error(error.stack || error.message);
    process.exitCode = 1;
  } finally {
    await driver.quit();
  }
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("xacml_page")
  .description("Drive the XACML editor page.")
  .addOption(new Option("-u, --url <url>", "Set base URL.")
      .makeOptionMandatory())
  .addOption(new Option("-b, --browser", "Display browser."))
  .action((options) => {
    if (options.url) {
      log.info("Setting url to " + options.url);
      baseUrl = options.url;
    }
    if (options.browser) {
      headless = false;
    }
  });
program.parse(process.argv);

test();
