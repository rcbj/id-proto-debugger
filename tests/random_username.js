// File: random_username.js
//
// ---------------------------------------------------------------------------
// ONE PLACE THAT MINTS THE USERNAME A TEST AUTHENTICATES AS.
//
// WHY THIS EXISTS
//
// Several tests used to sign in as `alice`. Every one of them, against every
// mock, was therefore the same person — and the mocks remember people. The mock
// STS keeps a users page, an authentication log and a statistics pane keyed by
// the name presented; its KDC keeps a principal table that an account is added
// to on first sight and never removed from. So a run left a pile of events on
// one identity, two tests running against one stack could not be told apart in
// it, and "did MY test do that?" had no answer at all.
//
// The name a test presents is therefore generated, and it carries a PREFIX THAT
// NAMES THE TEST THAT OWNS IT. `rfc9700-flows-mf2k9x3q1a` in the mock's audit
// log or in `/krb5/principals` says which file to open; `alice` says nothing.
//
// THE STAMP IS PER PROCESS, NOT PER CALL. One test file runs in one process, so
// every name it mints shares a suffix: the whole of one run's litter greps as a
// unit, and a test that needs two identities (a user and somebody to
// impersonate) gets two names that visibly belong together.
//
// It is derived from the clock AND from randomness rather than from the clock
// alone: a CI matrix starts several jobs in the same second, and two of them
// choosing the same name against one shared mock is precisely the collision
// this module exists to remove.
//
// WHAT A GENERATED NAME IS SAFE FOR — and what it is NOT
//
// Safe, because the thing being authenticated against accepts any name:
//
//   * the mock STS's sign-in screen and its password grant, which check no
//     password and take the name typed in as the identity (see oauth2.js);
//   * the mock KDC, whose findOrCreateUser() registers an account for any
//     username on first sight with AD's user-shaped salt, the one password
//     every user account there shares, and a PAC identity of its own. Its
//     /krb5/principals endpoint publishes that policy as
//     `accountPolicy.anyUsernameAuthenticates`, and the names it still refuses
//     as `accountPolicy.neverCreated` — see requireKnownOrCreatable() below,
//     which asks rather than assumes;
//   * an LDAP entry the test creates and deletes itself.
//
// NOT safe, and left alone deliberately:
//
//   * a FIXTURE account, whose value to a test is the properties the mock
//     configured it with. `alice` in the KDC's principal table is RID 1104, a
//     member of Domain Admins, with the full name `Alice Example`, and
//     tests/krb5_tgs_ap.js asserts every one of those against the PAC it gets
//     back. An account created on demand carries Domain Users and nothing else,
//     so a generated name there would not randomise the test — it would delete
//     it. There is no admin API for the principal table, so a randomised
//     Domain Admin is not available to ask for either.
//   * `alice` as ENCODED TEST DATA — a cname inside a message handed to the
//     codec, a salt in a decoder fixture, a `given_name` claim. Nothing stores
//     it, nothing can collide with it, and some of those assertions are about
//     byte offsets that a name of a different length would move.
//
// THE PRECEDENT THIS GENERALISES. tests/webauthn_oidc_mfa.js got here first and
// for a sharper reason than tidiness: the STS remembers an enrolled key per
// username for the life of its process, while a virtual authenticator lives
// only as long as the browser session, so a second run against a still-running
// STS was told to assert with a key that browser had never held. It rolled its
// own name; it now calls this, because a suite with two of these grows a third.
//
// USAGE
//
//   const { usernameFor } = require("./random_username.js");
//   var principal = process.env.KRB5_PRINCIPAL || usernameFor("kerberos-as");
//
// Keep the env override in front of it. Pinning the name is how a failed run is
// re-driven by hand against the artifacts it left behind.
// ---------------------------------------------------------------------------

// The log level comes from the same configuration everything else here reads. A
// caller without one still has to be able to load this module, so an
// unresolvable CONFIG_FILE falls back to info rather than throwing.
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "random_username",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      return "info";
    }
  })()
});

var crypto = require("crypto");

// ---------------------------------------------------------------------------
// The per-process suffix. Computed once, on first use.
//
// RANDOM_USERNAME_STAMP pins it, which is what makes a run reproducible: set it
// to the stamp printed by a failed run and every name that run used comes back.
// ---------------------------------------------------------------------------
var stamp = null;

function runStamp() {
  log.debug("Entering runStamp().");
  if (stamp) {
    log.debug("Leaving runStamp(). Already minted.");
    return stamp;
  }
  var pinned = String(process.env.RANDOM_USERNAME_STAMP || "").trim();
  if (pinned) {
    stamp = sanitize(pinned);
    log.info("[username] stamp pinned by RANDOM_USERNAME_STAMP: " + stamp);
    log.debug("Leaving runStamp(). Pinned.");
    return stamp;
  }
  // base36 of the millisecond clock, then five characters of randomness. The
  // clock alone is not enough — see the header — and randomness alone loses the
  // ordering that makes a directory listing of leftovers readable.
  stamp = Date.now().toString(36) +
      crypto.randomBytes(4).readUInt32BE(0).toString(36).slice(0, 5);
  log.info("[username] this run's usernames end in -" + stamp +
      ". Re-drive it with RANDOM_USERNAME_STAMP=" + stamp + ".");
  log.debug("Leaving runStamp(). Minted.");
  return stamp;
}

// A username has to be legal in three places at once: a Kerberos principal
// component, an LDAP RDN value, and a form field posted to the mock's sign-in
// screen. Lowercase alphanumerics and the hyphen are legal in all three and
// need escaping in none of them, so everything else is folded away rather than
// quoted.
function sanitize(text) {
  log.debug("Entering sanitize().");
  var cleaned = String(text).toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  log.debug("Leaving sanitize().");
  return cleaned;
}

// ---------------------------------------------------------------------------
// The name itself: <prefix>-<stamp>.
//
// The prefix is the test's own name — `rfc9700-flows`, `kerberos-as` — and it
// is the whole point of the exercise. A run leaves accounts behind in a table
// nothing prunes, and the only question anybody asks of that table afterwards
// is which test put a given row in it.
//
// An EMPTY prefix is refused rather than defaulted. A defaulted one would give
// back exactly the anonymous name this module exists to stop, and it would do
// it silently, at the one call site that forgot.
// ---------------------------------------------------------------------------
function usernameFor(prefix) {
  log.debug("Entering usernameFor().");
  var clean = sanitize(prefix || "");
  if (!clean) {
    log.debug("Leaving usernameFor(). No prefix.");
    throw new Error("usernameFor() needs a prefix naming the test that owns " +
      "the account — it is what makes a leftover row in the mock's user " +
      "table, audit log or principal table traceable to a file. Pass the " +
      "test's own name, e.g. usernameFor(\"kerberos-as\").");
  }
  var name = clean + "-" + runStamp();
  log.debug("Leaving usernameFor(). " + name);
  return name;
}

// ---------------------------------------------------------------------------
// The guard that has to change when a test stops naming a fixture account.
//
// A test that asks a mock KDC for a ticket first checks the KDC is the one it
// expects. The obvious check — "is this name in /krb5/principals?" — was right
// while the name was `alice` and is WRONG for a generated one: a name that is
// created on first sight is by definition not in the table yet, so the check
// would skip every such test, for a stated reason, on a perfectly good stack.
// That is the failure mode that reports OK while testing nothing.
//
// So this asks the question that is actually being asked: can this KDC produce
// an account under this name — either because it already has one, or because
// it creates them on demand and has not reserved this one? Both facts are
// published on /krb5/principals; neither is assumed here.
//
// `body` is the parsed /krb5/principals document. Returns null when the name is
// usable, or a sentence saying why it is not.
// ---------------------------------------------------------------------------
function requireKnownOrCreatable(body, name) {
  log.debug("Entering requireKnownOrCreatable().");
  var policy = (body && body.accountPolicy) || {};
  var names = ((body && body.principals) || []).map(function (p) {
    return String(p.principal || "").split("@")[0];
  });
  if (names.indexOf(name) !== -1) {
    log.debug("Leaving requireKnownOrCreatable(). Already registered.");
    return null;
  }
  if (!policy.anyUsernameAuthenticates) {
    log.debug("Leaving requireKnownOrCreatable(). No account, no auto-create.");
    return "the mock KDC has no principal named " + name + " and does not " +
      "create accounts on demand (accountPolicy.anyUsernameAuthenticates is " +
      "not set), so this generated name can never authenticate. It has " +
      names.join(", ");
  }
  var reserved = (policy.neverCreated || []).map(function (n) {
    return String(n).toLowerCase();
  });
  if (reserved.indexOf(name.toLowerCase()) !== -1) {
    log.debug("Leaving requireKnownOrCreatable(). Reserved.");
    return name + " is on the KDC's neverCreated list, so it stays unknown " +
      "on purpose: " + reserved.join(", ");
  }
  log.debug("Leaving requireKnownOrCreatable(). Creatable on demand.");
  return null;
}

module.exports = {
  usernameFor: usernameFor,
  requireKnownOrCreatable: requireKnownOrCreatable,
  runStamp: runStamp
};
