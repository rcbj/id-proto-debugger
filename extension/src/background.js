// File: background.js  —  the service worker.
//
// Owns three things: the capture buffer, the ARM state, and the disarm ladder.
//
// The extension ships INERT. At install it holds no host permission for anything
// but the debugger's own origins (which it needs in order to hand captures to
// the debugger's pages), and it injects nothing anywhere. Observing an origin is
// a deliberate act with a clock on it:
//
//   TTL expiry / browser restart  -> disarmed, needs nobody
//   the debugger says "done"      -> disarmed, needs nobody
//   the popup's Uninstall button  -> management.uninstallSelf(), native dialog
//
// Only the last can be declined, and declining it leaves an extension with no
// permissions and no injected scripts.
"use strict";

const BUFFER_KEY = "captures";
const ARMED_KEY = "armed";
const MAX_CAPTURES = 50;
const TTL_MS = 30 * 60 * 1000;

function log(...args) {
  console.log("[idptools-webauthn]", ...args);
}

async function getArmed() {
  const stored = await chrome.storage.local.get(ARMED_KEY);
  const armed = stored[ARMED_KEY] || null;
  if (armed && armed.expires < Date.now()) {
    await disarm("the observation window expired");
    return null;
  }
  return armed;
}

async function setBadge(armed) {
  try {
    await chrome.action.setBadgeText({ text: armed ? "ARM" : "" });
    await chrome.action.setBadgeBackgroundColor({ color: "#b00020" });
    await chrome.action.setTitle({
      title: armed
        ? "Observing WebAuthn on " + armed.origin + " until " + new Date(armed.expires).toLocaleTimeString()
        : "WebAuthn observer — inactive",
    });
  } catch (e) {
    // Badge decoration is not worth failing an arm over.
  }
}

// The shim goes in the page's world; the relay beside it in the isolated one.
// Registered dynamically rather than declared in the manifest, because a
// declared content script would need its host permission at INSTALL time and the
// whole posture here is that a fresh install can see nothing.
async function registerFor(origin) {
  const pattern = origin.replace(/\/+$/, "") + "/*";
  await unregisterAll();
  await chrome.scripting.registerContentScripts([
    {
      id: "shim", matches: [pattern], js: ["shim.js"],
      runAt: "document_start", world: "MAIN", allFrames: true,
    },
    {
      id: "relay", matches: [pattern], js: ["relay.js"],
      runAt: "document_start", world: "ISOLATED", allFrames: true,
    },
  ]);
}

async function unregisterAll() {
  try {
    const existing = await chrome.scripting.getRegisteredContentScripts();
    const ids = existing.filter((s) => s.id === "shim" || s.id === "relay").map((s) => s.id);
    if (ids.length) {
      await chrome.scripting.unregisterContentScripts({ ids });
    }
  } catch (e) {
    // Nothing registered, which is the state we wanted anyway.
  }
}

async function arm(origin) {
  log("arming for", origin);
  await registerFor(origin);
  const armed = { origin: origin, since: Date.now(), expires: Date.now() + TTL_MS };
  await chrome.storage.local.set({ [ARMED_KEY]: armed });
  await chrome.alarms.clear("disarm");
  await chrome.alarms.create("disarm", { when: armed.expires });
  await setBadge(armed);
  return armed;
}

async function disarm(reason) {
  log("disarming:", reason);
  await unregisterAll();
  await chrome.storage.local.remove(ARMED_KEY);
  // The buffer goes with it. A capture is somebody's authentication ceremony;
  // keeping it past the window it was collected in is not this extension's
  // business.
  await chrome.storage.local.remove(BUFFER_KEY);
  await chrome.alarms.clear("disarm");
  await setBadge(null);
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "disarm") {
    disarm("the observation window expired");
  }
});

// Nothing survives a restart: the arm state is cleared on startup rather than
// restored, so a browser relaunch is a disarm even on Chrome, where the
// extension itself persists.
chrome.runtime.onStartup.addListener(() => disarm("the browser restarted"));

chrome.runtime.onInstalled.addListener(async () => {
  await disarm("freshly installed");
  // A build that ships autoarm.json arms itself for the origins listed there.
  // That file exists ONLY in the CI build: a permission prompt cannot be clicked
  // by a WebDriver session, and the alternative — a test-only bypass inside the
  // arm path — would mean testing something users never run.
  try {
    const res = await fetch(chrome.runtime.getURL("autoarm.json"));
    if (res.ok) {
      const cfg = await res.json();
      if (Array.isArray(cfg.origins) && cfg.origins.length) {
        log("autoarm.json present (CI build); arming for", cfg.origins[0]);
        await arm(cfg.origins[0]);
      }
    }
  } catch (e) {
    // Absent, which is the normal case for a real install.
  }
});

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  (async () => {
    if (msg && msg.type === "capture") {
      const armed = await getArmed();
      if (!armed) {
        // Arrived after the window closed. Dropping it is the point of the window.
        reply({ stored: false, reason: "not armed" });
        return;
      }
      const stored = await chrome.storage.local.get(BUFFER_KEY);
      const buffer = stored[BUFFER_KEY] || [];
      buffer.unshift(msg.capture);
      await chrome.storage.local.set({ [BUFFER_KEY]: buffer.slice(0, MAX_CAPTURES) });
      log("captured a", msg.capture.ceremony, "ceremony on", msg.capture.origin);
      reply({ stored: true });
      return;
    }
    if (msg && msg.type === "getCaptures") {
      const stored = await chrome.storage.local.get(BUFFER_KEY);
      // version_name, not version: the manifest's `version` must be up to four
      // integers under 65536, so build.js mangles the M.N.O stamp to fit it.
      // The debugger's pages compare against their own M.N.O build, and
      // reporting the mangled form here made that comparison always disagree —
      // a drift warning on every page in a matched build, which is worse than no
      // warning at all.
      const manifest = chrome.runtime.getManifest();
      reply({ captures: stored[BUFFER_KEY] || [], armed: await getArmed(),
               version: manifest.version_name || manifest.version });
      return;
    }
    if (msg && msg.type === "arm") {
      reply({ armed: await arm(msg.origin) });
      return;
    }
    if (msg && msg.type === "disarm") {
      await disarm(msg.reason || "asked to");
      reply({ armed: null });
      return;
    }
    if (msg && msg.type === "clear") {
      await chrome.storage.local.remove(BUFFER_KEY);
      reply({ cleared: true });
      return;
    }
    reply({ error: "unknown message" });
  })();
  // Keep the message channel open for the async work above.
  return true;
});
