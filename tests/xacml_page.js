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
