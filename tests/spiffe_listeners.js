// File: spiffe_listeners.js
//
// ---------------------------------------------------------------------------
// IS THE gRPC ADDRESS THIS JOB IS ABOUT TO DIAL SERVED BY THE MOCK IT JUST
// CONFIGURED?
//
// Every other SPIFFE surface in this suite is reached through the mock's HTTP
// port: the trust bundle, the applications registry, and — the one that
// matters here — `POST /admin-api/config/set`, which is how
// `spiffe_protocol.js` makes its own SVID an administrator. The two gRPC
// surfaces are reached on PORTS OF THEIR OWN (8092 and 8181), and a port is
// not an identity: whoever bound it first is what answers there.
//
// WHY THIS EXISTS. On 2026-09-01 the mock STS started with 0.0.0.0:8092 and
// 0.0.0.0:8181 already held by another process. Its own log says so at level
// 50 — `spiffe: could not bind 0.0.0.0:8181 ... EADDRINUSE` — and, unlike the
// HTTP port, it CARRIES ON: the SPIFFE gRPC listeners are optional to this
// service in a way the port everything else uses is not. So the stack came up
// healthy, `requireStsReachable()` was satisfied on 8081, and three jobs then
// spoke to a stranger of the same species for the rest of the run:
//
//   * `spiffe_protocol.js` wrote `spiffe.adminIds` to THIS mock over 8081 and
//     then made an authorized call to SOMEBODY ELSE'S SPIRE server on 8181,
//     which had never heard of that setting. It failed with the far end's own
//     refusal — "Entry.CountEntries is allowed to: local, admin ... (no
//     entity)" — which reads exactly like an authorization bug in the mock.
//   * `spiffe_page.js` fetched the trust bundle from THIS mock and presented
//     the SVID it issued to the stranger's mutual-TLS port, whose certificate
//     was signed by the stranger's own authority. That is a chain that does
//     not verify, and the api reported it as `self-signed certificate in
//     certificate chain` — a message about TLS, three services from the cause.
//   * `api_spiffe.js` PASSED, which is the worst of the three: the stranger
//     was another instance of the same mock, so every status-code assertion
//     was true of it.
//
// Not one of those three named a port, and none of them could: the fact that
// settles it is held by the mock and nowhere else. `GET /spiffe?format=json`
// publishes each listener with `listening` and, when that is false, the bind
// error — so this module ASKS, and turns the answer into one line naming the
// port before a single gRPC call is made.
//
// WHAT IT REFUSES AND WHAT IT DOES NOT. Three verdicts, because they are three
// different facts about a deployment:
//
//   ok        — the mock says it bound that port, or nothing here could be
//               decided (the document did not parse, the surface is served on
//               a port this job is not dialing — a published container port,
//               say). Silence is the right answer to a question that was not
//               answered; inventing a failure from a mapped port would break
//               every stack that maps one.
//   stranger  — the mock says that port DID NOT BIND. Whatever answers there
//               is a different process, and the caller must FAIL rather than
//               skip: a skip would leave a green run in which the workflow was
//               never exercised and somebody else's service was driven.
//   absent    — SPIFFE is enabled but this surface is not served over TCP at
//               all (`spiffe.workloadPort` is 0, say). That is a capability
//               this deployment does not have, so the caller SKIPS with a
//               reason, which is what this suite does everywhere else.
// ---------------------------------------------------------------------------

// The log level comes from the same configuration everything else here reads.
// A caller without one still has to be able to load this module, so an
// unresolvable CONFIG_FILE falls back to info rather than throwing — the same
// arrangement tests/sts_applications.js has, and for the same reason.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "spiffe_listeners",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});

// The port a `host:port`, `tcp://host:port` or `[::1]:port` address names, or
// null when there is none to read. Deliberately not the full parser
// `api/spiffe_client.js` has: the only thing compared here is the port, and a
// unix path — which that parser also accepts — has none and is not a port
// anybody can squat.
function portOf(address) {
  log.debug("Entering portOf(). address=" + address);
  var text = String(address || "").trim().replace(/^tcp:\/\//, "");
  var match = text.match(/:(\d+)$/);
  if (!match) {
    log.debug("Leaving portOf(). No port.");
    return null;
  }
  log.debug("Leaving portOf(). " + match[1]);
  return Number(match[1]);
}

// The mock's own description of its SPIFFE service, or null when it cannot be
// read. Null is not an error here: the callers all have a gate of their own
// that has already decided this deployment has a SPIFFE service at all, and
// this module's whole job is to add a fact when there is one to add.
async function describe(stsUrl) {
  log.debug("Entering describe(). stsUrl=" + stsUrl);
  var base = String(stsUrl || "").replace(/\/+$/, "");
  var response = null;
  try {
    response = await fetch(base + "/spiffe?format=json");
  } catch (e) {
    log.debug("Leaving describe(). Unreachable: " + e.message);
    return null;
  }
  if (!response.ok) {
    log.debug("Leaving describe(). HTTP " + response.status);
    return null;
  }
  var document = null;
  try {
    document = await response.json();
  } catch (e) {
    log.debug("Leaving describe(). Not JSON: " + e.message);
    return null;
  }
  log.debug("Leaving describe(). Described.");
  return document;
}

// The verdict for ONE address on one surface, given the mock's document.
function verdictFor(document, want) {
  log.debug("Entering verdictFor(). surface=" + want.surface +
    " address=" + want.address);
  var wanted = portOf(want.address);
  var surface = (document && document[want.surface]) || {};
  var listeners = Array.isArray(surface.listeners) ? surface.listeners : [];
  // TCP only. The Workload API's unix socket is a listener of the same shape
  // and is never what a `host:port` address names.
  var tcp = listeners.filter(function (one) {
    return one && one.socket !== true;
  });
  if (wanted === null || tcp.length === 0) {
    // No TCP listener described at all means this surface is not served that
    // way here — the capability is absent rather than stolen. An address with
    // no port is not one this module can say anything about.
    var absent = wanted !== null && tcp.length === 0;
    log.debug("Leaving verdictFor(). " + (absent ? "Absent." : "Undecided."));
    return absent
      ? { ok: false, absent: true, why: "the mock STS describes no TCP " +
          "listener for " + want.what + ", so this deployment does not serve " +
          "that surface on a port at all. " + want.address + " cannot be it." }
      : { ok: true };
  }
  var match = tcp.filter(function (one) {
    return portOf(one.address) === wanted;
  });
  if (match.length === 0) {
    // The mock serves the surface on a different port from the one this job
    // dials, which is the ordinary state of a stack that PUBLISHES a container
    // port under another number. Nothing to conclude.
    log.debug("Leaving verdictFor(). Not the same port.");
    return { ok: true };
  }
  var bound = match.filter(function (one) {
    return one.listening === true;
  });
  if (bound.length > 0) {
    log.debug("Leaving verdictFor(). Bound.");
    return { ok: true };
  }
  log.debug("Leaving verdictFor(). Not bound.");
  return { ok: false, stranger: true, why: "the mock STS serving " +
    (document.trustDomainId || "this trust domain") + " reports that it " +
    "could NOT bind " + match[0].address + " for " + want.what + ": " +
    (match[0].error || "no reason given") + ". Whatever is answering on " +
    want.address + " is therefore ANOTHER PROCESS, and the two are not " +
    "interchangeable: an SVID this trust domain issues is signed by an " +
    "authority the stranger does not hold, and a setting written to this one " +
    "over HTTP means nothing there. Find it BY PID and stop it: " +
    "`ss -ltnp | grep :" + wanted + "`." };
}

// Every address this job is about to dial, against what the mock says it
// bound. `wanted` is an array of { surface, address, what }, where `surface`
// is "workloadApi" or "serverApi" — the two keys GET /spiffe?format=json
// publishes listeners under.
//
// The first refusal wins and the rest are not reported, deliberately: two
// ports held by the same stranger is one fact, and a caller that printed both
// would say it twice.
async function verify(stsUrl, wanted) {
  log.debug("Entering verify(). stsUrl=" + stsUrl);
  var document = await describe(stsUrl);
  if (!document) {
    log.debug("Leaving verify(). Nothing to compare against.");
    return { ok: true };
  }
  for (var i = 0; i < (wanted || []).length; i++) {
    var verdict = verdictFor(document, wanted[i]);
    if (!verdict.ok) {
      log.debug("Leaving verify(). Refused.");
      return verdict;
    }
  }
  log.debug("Leaving verify(). Every address is one this mock bound.");
  return { ok: true };
}

module.exports = {
  verify: verify,
  describe: describe,
  portOf: portOf
};
