// File: krb5_client.js
//
// ---------------------------------------------------------------------------
// The client's half of the TGS and AP exchanges.
//
// The AS exchange lives in the page (client/src/kerberos.js) because it is a
// two-step conversation with a human in the middle — the salt has to be seen before
// the second request can be built. The TGS and AP exchanges are not like that: they
// are mechanical, and every hard part of them is arithmetic that has to be exactly
// right. So they live here, with no DOM, and tests/krb5_tgs_ap.js drives them with
// no browser.
//
// ---------------------------------------------------------------------------
// THE THREE THINGS THAT GO WRONG IN A TGS-REQ.
//
// A TGS-REQ is not an AS-REQ with a different tag. It carries the TGT as
// pre-authentication, in a **PA-TGS-REQ whose value is an entire AP-REQ**, and that
// AP-REQ's Authenticator carries a checksum **over the encoded KDC-REQ-BODY**. So:
//
//  1. **The body's bytes must be the ones the checksum covered.** Re-encoding the
//     body after checksumming it — even correctly, even to the same fields — risks
//     different DER, and the KDC then sees a checksum over something else. This is
//     why krb5_messages.js keeps `raw` on a parsed body and why the builder here
//     encodes the body ONCE and passes the same bytes to both places.
//  2. **The checksum is at key usage 6 and the Authenticator at key usage 7**, both
//     under the TGT's SESSION key rather than the client's long-term key. Any other
//     number produces a well-formed request the KDC rejects as a bad checksum.
//  3. **The reply's enc-part is at usage 8 — or 9 if the Authenticator carried a
//     subkey.** The KDC chooses based on what was sent, so a client that always
//     tries 8 fails whenever it sent a subkey, and a client that always tries 9
//     fails whenever it did not.
//
// ---------------------------------------------------------------------------
// AND THE ONE THING THAT GOES WRONG IN AN AP-REQ.
//
// A service does not receive a bare AP-REQ; it receives a GSS InitialContextToken
// wrapping one, and the Authenticator inside carries a checksum of type 0x8003 that
// is not a checksum at all — see krb5_gss.js. Everything else about the AP exchange
// is straightforward, and that one field is where it fails.
// ---------------------------------------------------------------------------

var prim = require("./krb5_primitives.js");
var asn1 = require("./krb5_asn1.js");
var msgs = require("./krb5_messages.js");
var kcrypto = require("./krb5_crypto.js");
var gss = require("./krb5_gss.js");
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "krb5_client",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      // No CONFIG_FILE resolvable here — a node caller rather than a bundle.
      return "info";
    }
  })()
});

function randomNonce() {
  var b = kcrypto.randomBytes(4);
  return ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
}

// A sequence number for the AP exchange. RFC 4120 wants it unpredictable, and
// it is a UInt32 on the wire — the top bit is left clear because some
// implementations treat the field as signed and a negative value then reads as
// out of order.
function randomSequenceNumber() {
  var b = kcrypto.randomBytes(4);
  return (((b[0] & 0x7f) << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
}

// ---------------------------------------------------------------------------
// The TGS exchange.
// ---------------------------------------------------------------------------

// Build a TGS-REQ asking `service` for a ticket, presenting `tgt`.
//
// `tgt` is what the AS exchange produced: { ticket, sessionKey, etype, client,
// realm }.
async function buildTgsReq(options) {
  log.debug("Entering buildTgsReq().");
  var opts = options || {};
  var tgt = opts.tgt;
  if (!tgt || !tgt.ticket || !tgt.sessionKey) {
    throw new Error("krb5: a TGS-REQ needs a TGT with its session key — that " +
        "key is what signs the " +
      "request, and without it the KDC has nothing to verify");
  }
  var profile = kcrypto.etypeById(tgt.etype);
  var realm = opts.realm || tgt.realm;
  var nonce = opts.nonce === undefined ? randomNonce() : opts.nonce;
  var subkey = opts.subkey || null;

  // The body, encoded ONCE. These exact bytes are what the checksum covers and
  // what goes on the wire; re-encoding between the two is how a checksum stops
  // matching for no visible reason.
  var body = msgs.encKdcReqBody({
    kdcOptions: opts.kdcOptions || [msgs.KDC_OPTION.FORWARDABLE,
        msgs.KDC_OPTION.RENEWABLE],
    realm: realm,
    sname: opts.sname,
    till: opts.till || new Date(Date.now() + 10 * 3600 * 1000),
    nonce: nonce,
    etypes: opts.etypes || [tgt.etype],
    // A ticket bound to the addresses it may be used from. AD issues
    // addressless tickets and so does this by default — but the field has to be
    // PASSED THROUGH, or an option the caller sets is silently dropped and the
    // ticket comes back unbound with no error anywhere to say so.
    addresses: opts.addresses || null,
    additionalTickets: opts.additionalTickets || null,
    encAuthorizationData: opts.encAuthorizationData || null
  });

  // Key usage 6 for the checksum over that body, under the TGT's SESSION key.
  var checksum = await profile.checksum(tgt.sessionKey,
      kcrypto.KEY_USAGE.TGS_REQ_AUTH_CKSUM, body);
  var now = opts.now || new Date();
  var authenticator = msgs.encAuthenticator({
    crealm: tgt.realm,
    cname: tgt.client,
    cksum: { type: profile.checksumType, checksum: checksum },
    cusec: (now.getMilliseconds() * 1000) % 1000000,
    ctime: now,
    subkey: subkey ? { etype: subkey.etype, key: subkey.key } : null,
    seqNumber: opts.sequenceNumber === undefined ? randomSequenceNumber() :
        opts.sequenceNumber
  });

  // Key usage 7 for the Authenticator itself.
  var apReq = msgs.encApReq({
    apOptions: [],
    ticket: tgt.ticket,
    authenticator: {
      etype: tgt.etype,
      cipher: await profile.encrypt(tgt.sessionKey,
          kcrypto.KEY_USAGE.TGS_REQ_AUTH, authenticator)
    }
  });

  var request = msgs.encKdcReq({
    msgType: msgs.MSG_TYPE.TGS_REQ,
    padata: [{
      type: msgs.PA_TYPE.TGS_REQ,
      value: apReq
    }].concat(opts.extraPadata || []),
    // The SAME bytes. encKdcReq takes `raw` and uses it verbatim.
    reqBody: { raw: body }
  });
  log.debug("Leaving buildTgsReq(). bytes=" + request.length + ", nonce=" +
      nonce);
  // `sname` is returned so the caller can hand it back to readTgsRep as
  // `requestedSname`: a referral is only detectable by comparing the reply's
  // sname with what was ASKED FOR, and a caller that has to remember that
  // separately is a caller that will forget.
  return {
    request: request,
    nonce: nonce,
    subkey: subkey,
    body: body,
    sname: opts.sname
  };
}

// Read a TGS-REP and produce the service ticket.
//
// The enc-part is at key usage 8 under the TGT session key, or 9 under the
// Authenticator's subkey when one was sent. Both are tried in the right order
// and which one worked is reported, because a client that guesses wrong sees
// only an integrity failure.
async function readTgsRep(options) {
  log.debug("Entering readTgsRep().");
  var opts = options || {};
  var tgt = opts.tgt;
  var response = msgs.readKdcResponse(opts.reply);
  if (response.kind === "KRB-ERROR") {
    log.debug("Leaving readTgsRep(). error=" + response.error.error.name);
    return { ok: false, error: response.error };
  }
  if (response.kind !== "TGS-REP") {
    throw new Error("krb5: expected a TGS-REP, the KDC answered " +
        response.kind);
  }
  var rep = response.rep;
  var profile = kcrypto.etypeById(rep.encPart.etype);

  var attempts = [];
  if (opts.subkey) {
    attempts.push({
      key: opts.subkey.key,
      usage: kcrypto.KEY_USAGE.TGS_REP_ENCPART_SUBKEY,
      label: "the Authenticator's subkey (key usage 9)"
    });
  }
  attempts.push({
    key: tgt.sessionKey,
    usage: kcrypto.KEY_USAGE.TGS_REP_ENCPART_SESSKEY,
    label: "the TGT's session key (key usage 8)"
  });

  var part = null;
  var plain = null;
  var used = null;
  var failures = [];
  for (var i = 0; i < attempts.length && !part; i++) {
    try {
      // The plaintext is kept, not only what it parses into. It is the one view
      // of a reply that cannot be reconstructed later — the caller holds the
      // key, but decrypting a second time to look at the bytes would be a
      // second implementation of the usage-8-or-9 question above. Assigned
      // AFTER the read so that a plaintext which does not parse is not returned
      // as though it had: `part` is what the loop tests.
      var candidate = await profile.decrypt(attempts[i].key, attempts[i].usage,
          rep.encPart.cipher);
      part = msgs.readEncKdcRepPart(candidate);
      plain = candidate;
      used = attempts[i];
    } catch (e) {
      failures.push(attempts[i].label + ": " + e.message);
    }
  }
  if (!part) {
    throw new Error("krb5: the TGS-REP's enc-part would not decrypt. Tried " +
        failures.join("; ") +
      ". The KDC uses key usage 9 when the request carried a subkey and 8 " +
          "when it did not, so a " +
      "client that always tries one of them fails half the time.");
  }

  if (opts.nonce !== undefined && part.nonce !== opts.nonce) {
    throw new Error("krb5: the TGS-REP's nonce is " + part.nonce +
        " but the request sent " +
      opts.nonce + ". This is not an answer to that request and may be a " +
          "replay.");
  }

  // ---------------------------------------------------------------------------
  // Was this a REFERRAL rather than the ticket that was asked for?
  //
  // A cross-realm referral is not an error and not a distinct message type: it is an
  // ordinary successful TGS-REP whose `sname` is **krbtgt/OTHER-REALM** instead of the
  // service the client named. That difference is the only signal there is.
  //
  // A client that does not look will take the reply as its service ticket and present a
  // ticket-granting ticket to a web server, which reports that the ticket does not
  // decrypt — a message about a ticket, for a problem about a realm. So it is detected
  // and reported here, with the realm to go and ask next, rather than left for the
  // caller to notice.
  //
  // The comparison is against what the CALLER asked for, which is why `requestedSname`
  // is worth passing in. Without it the only available test is "does the reply name a
  // krbtgt principal", and that is true of a legitimate renewal too.
  var referral = null;
  var asked = opts.requestedSname || opts.sname ||
    (opts.built && (opts.built.sname || (opts.built.body || {}).sname)) || null;
  var got = part.sname;
  if (asked && got && (asked.name || []).join("/") !== (got.name ||
      []).join("/")) {
    var toRealm = (got.name || []).length > 1 && got.name[0] === "krbtgt" ?
        got.name[1] : null;
    referral = {
      requested: msgs.principalToString(asked),
      issued: msgs.principalToString(got, part.srealm),
      toRealm: toRealm,
      note: toRealm
        ? "This is a REFERRAL, not the ticket that was asked for. " +
            part.srealm + " has no " +
          msgs.principalToString(asked) + " and has issued a ticket-granting " +
              "ticket for " +
          toRealm + " instead, sealed with the trust key those two realms " +
              "share. Present THIS " +
          "ticket to " + toRealm + "'s KDC and ask it for the service again."
        : "The reply names " + msgs.principalToString(got, part.srealm) +
            ", which is not the " +
          msgs.principalToString(asked) + " that was requested, and is not a " +
              "krbtgt principal " +
          "either. The KDC has answered a different question from the one " +
              "asked."
    };
    log.info("krb5: the TGS-REP is a referral to " + (toRealm ||
        "an unexpected principal") + ".");
  }

  log.debug("Leaving readTgsRep(). opened with " + used.label +
    (referral ? ", and it is a referral to " + referral.toRealm : ""));
  return {
    ok: true,
    openedWith: used.label,
    referral: referral,
    ticket: rep.ticket,
    sessionKey: part.key.key,
    etype: part.key.etype,
    client: rep.cname,
    realm: rep.crealm,
    service: part.sname,
    serviceRealm: part.srealm,
    flags: part.flags,
    flagNames: msgs.ticketFlagNames(part.flags),
    authtime: part.authtime,
    starttime: part.starttime,
    endtime: part.endtime,
    renewTill: part.renewTill,
    encPart: part,
    bytes: replyBytes(rep, plain)
  };
}

// ---------------------------------------------------------------------------
// The three byte strings inside a reply that are worth looking at on their own,
// which is what the delegation page's per-part hex tabs render.
//
// WHY THEY COME FROM HERE rather than from the page: two of the three are only
// available while the reply is open. The plaintext is the obvious one — nothing
// but this function has it. The Ticket is the subtle one: `msgs.readTicket()`
// keeps the ORIGINAL bytes as `raw` and `encTicket()` hands them straight back,
// so what comes out here is the ticket exactly as the KDC sent it. A page that
// re-encoded a parsed ticket instead would usually get the same DER and
// occasionally not, and a hex view that is usually the wire is worse than one
// that never claims to be.
//
// `encPart` IS a re-encode, and that is the one caveat worth stating. An
// EncryptedData is etype, an optional kvno and an OCTET STRING, and Kerberos
// mandates DER — so the encoding is determined by those three values and this
// reproduces it. The ciphertext inside it is the wire's own either way.
//
// THE PLAINTEXT IS TRIMMED TO ITS DER, because RFC 3961 allows a decrypt to
// return trailing padding for a block-cipher etype (DES does; the AES CTS
// profiles and RC4 do not, which is why this is invisible against any KDC worth
// testing against). Those bytes are not part of the EncTGSRepPart, and left on
// the end they read as ASN.1: the range walker sees them as two `universal 0`
// elements and an unparsed tail, which in a hex view looks like two extra
// fields on a malformed message rather than like padding.
// ---------------------------------------------------------------------------
function replyBytes(rep, plain) {
  log.debug("Entering replyBytes().");
  var trimmed = plain;
  if (plain) {
    try {
      // `raw` is the element's own bytes, header included — exactly the trim
      // wanted here, and it comes from the reader rather than from arithmetic.
      trimmed = asn1.readTlv(prim.toBytes(plain), 0, 0).raw;
    } catch (e) {
      // It parsed a moment ago, so this cannot normally happen — and if it
      // does, the untrimmed bytes are still the right thing to show.
      log.warn("the enc-part plaintext will not re-read as one element, so " +
          "its hex view keeps whatever padding is on the end: " + e.message);
    }
  }
  log.debug("Leaving replyBytes().");
  return {
    ticket: msgs.encTicket(rep.ticket),
    encPart: msgs.encEncryptedData(rep.encPart),
    encPartPlain: trimmed
  };
}

// ---------------------------------------------------------------------------
// The AP exchange.
// ---------------------------------------------------------------------------

// Build an AP-REQ for a service ticket, wrapped as a GSS InitialContextToken —
// which is what a service actually expects to receive.
async function buildApReq(options) {
  log.debug("Entering buildApReq().");
  var opts = options || {};
  var ticket = opts.ticket;
  if (!ticket || !ticket.ticket || !ticket.sessionKey) {
    throw new Error("krb5: an AP-REQ needs a service ticket and its session " +
        "key");
  }
  var profile = kcrypto.etypeById(ticket.etype);
  var mutual = opts.mutual !== false;
  var flags = (opts.gssFlags || [gss.GSS_FLAG.INTEG,
      gss.GSS_FLAG.CONF]).slice();
  if (mutual &&
      flags.indexOf(gss.GSS_FLAG.MUTUAL) === -1) flags.push(gss.GSS_FLAG.MUTUAL);
  if (opts.delegation &&
      flags.indexOf(gss.GSS_FLAG.DELEG) === -1) flags.push(gss.GSS_FLAG.DELEG);

  // The 0x8003 structure: channel bindings and flags, NOT a checksum of the
  // message. See krb5_gss.js on why this is the field that fails.
  var gssChecksum = gss.buildGssChecksum({
    flags: flags,
    channelBindings: opts.channelBindings || null,
    delegation: opts.delegation || null
  });

  // KerberosTime has NO FRACTIONAL SECONDS — the wire format is YYYYMMDDHHMMSSZ
  // — so the ctime that actually goes out is truncated to the second, and the
  // sub-second part travels separately in cusec. A caller that later compares
  // the AP-REP's echo against a millisecond-precision Date will NEVER match:
  // the echo is correct and the comparison is wrong. So the truncated value is
  // what this function reports as `ctime`, and `cusec` is reported beside it.
  var requested = opts.now || new Date();
  var now = new Date(Math.floor(requested.getTime() / 1000) * 1000);
  var cusec = (requested.getMilliseconds() * 1000) % 1000000;
  var sequenceNumber = opts.sequenceNumber === undefined ?
      randomSequenceNumber() : opts.sequenceNumber;
  var subkey = opts.subkey === undefined
    ? { etype: ticket.etype, key: kcrypto.randomBytes(profile.keyBytes) }
    : opts.subkey;

  var authenticator = msgs.encAuthenticator({
    crealm: ticket.realm,
    cname: ticket.client,
    cksum: { type: gss.CHECKSUM_TYPE_GSS, checksum: gssChecksum },
    cusec: cusec,
    ctime: now,
    subkey: subkey,
    seqNumber: sequenceNumber
  });

  var apReq = msgs.encApReq({
    apOptions: mutual ? [msgs.AP_OPTION.MUTUAL_REQUIRED] : [],
    ticket: ticket.ticket,
    authenticator: {
      etype: ticket.etype,
      // Key usage 11 for an AP-REQ Authenticator, under the ticket's session
      // key.
      cipher: await profile.encrypt(ticket.sessionKey,
          kcrypto.KEY_USAGE.AP_REQ_AUTH, authenticator)
    }
  });

  log.debug("Leaving buildApReq(). mutual=" + mutual + ", seq=" +
      sequenceNumber);
  return {
    apReq: apReq,
    // What a service is actually handed.
    token: gss.encodeInitialContextToken(gss.TOK_ID.AP_REQ, apReq),
    sequenceNumber: sequenceNumber,
    subkey: subkey,
    // Second precision, because that is what went on the wire.
    ctime: now,
    cusec: cusec,
    gssFlags: flags
  };
}

// Read the AP-REP and confirm the service proved itself.
//
// The proof is narrow and worth stating: the AP-REP echoes the Authenticator's
// ctime and cusec, encrypted under the ticket's session key. Only something
// holding the service's long-term key could have decrypted the ticket to learn
// that session key, so a correct echo is the service's identity. A client that
// does not CHECK the echo has asked for mutual authentication and not performed
// it.
async function readApRep(options) {
  log.debug("Entering readApRep().");
  var opts = options || {};
  var bytes = opts.reply;

  // A service may answer with a GSS-wrapped AP-REP, or with a KRB-ERROR inside
  // the same wrapper. Unwrap when wrapped, and be explicit about which arrived.
  var wrapped = null;
  if (bytes.length && bytes[0] === 0x60) {
    wrapped = gss.decodeInitialContextToken(bytes);
    bytes = wrapped.inner;
  }
  var identified = msgs.identify(bytes);
  if (identified &&
      identified.applicationNumber === msgs.APPLICATION.KRB_ERROR) {
    var error = msgs.readKrbError(bytes);
    log.debug("Leaving readApRep(). the service answered " + error.error.name);
    return { ok: false, error: error, wrapped: !!wrapped };
  }
  var apRep = msgs.readApRep(bytes);
  var profile = kcrypto.etypeById(apRep.encPart.etype);
  var part = msgs.readEncApRepPart(
    await profile.decrypt(opts.ticket.sessionKey,
        kcrypto.KEY_USAGE.AP_REP_ENCPART,
      apRep.encPart.cipher));

  // The echo, compared at the precision it was actually sent at.
  //
  // KerberosTime carries no fractional seconds, so ctime on the wire is
  // truncated to the second and the sub-second part is in cusec — RFC 4120 has
  // the AP-REP echo BOTH. Comparing a millisecond-precision Date here fails
  // against a perfectly correct service, which is a false accusation of the
  // worst kind: it tells the user their service is not who it says it is.
  var sentSecond = opts.sentCtime
    ? new Date(Math.floor(opts.sentCtime.getTime() / 1000) * 1000)
    : null;
  var timeEchoed = sentSecond && part.ctime.getTime() === sentSecond.getTime();
  var usecEchoed = opts.sentCusec === undefined || opts.sentCusec === null
    ? true
    : part.cusec === opts.sentCusec;
  if (!timeEchoed || !usecEchoed) {
    return {
      ok: false,
      mutualOk: false,
      reason: "the AP-REP echoes ctime " + part.ctime.toISOString() + "/" +
          part.cusec +
        " but the Authenticator sent " +
        (sentSecond ? sentSecond.toISOString() : "(unknown)") + "/" +
        (opts.sentCusec === undefined ? "(not checked)" : opts.sentCusec) +
        ". That echo is the whole of the service's proof of identity, so " +
            "this context is NOT " +
        "mutually authenticated.",
      encPart: part,
      wrapped: !!wrapped
    };
  }
  log.debug("Leaving readApRep(). mutual authentication confirmed.");
  return {
    ok: true,
    mutualOk: true,
    // The acceptor's subkey, when it sent one, is what per-message tokens are
    // then keyed from — not the ticket's session key.
    acceptorSubkey: part.subkey || null,
    sequenceNumber: part.seqNumber,
    encPart: part,
    wrapped: !!wrapped
  };
}

// Which key a per-message token should use once the context is established: the
// acceptor's subkey if it offered one, else the initiator's, else the session
// key. Getting this wrong is a token the far end cannot verify.
function perMessageKey(context) {
  log.debug("Entering perMessageKey().");
  if (context.acceptorSubkey) {
    log.debug("Leaving perMessageKey().");
    return {
      key: context.acceptorSubkey.key,
      etype: context.acceptorSubkey.etype,
      which: "the acceptor's subkey",
      acceptorSubkey: true
    };
  }
  if (context.subkey) {
    log.debug("Leaving perMessageKey().");
    return {
      key: context.subkey.key,
      etype: context.subkey.etype,
      which: "the initiator's subkey",
      acceptorSubkey: false
    };
  }
  log.debug("Leaving perMessageKey().");
  return {
    key: context.sessionKey,
    etype: context.etype,
    which: "the ticket's session key",
    acceptorSubkey: false
  };
}


// ---------------------------------------------------------------------------
// Delegation: S4U2Self, S4U2Proxy, and renewals.
//
// All three are ordinary TGS exchanges with one thing added, which is why they reuse
// buildTgsReq() rather than reimplementing it — the body must be encoded ONCE and the
// checksum must cover those exact bytes, and that rule is easy to break in a second
// copy.
//
// What the two S4U halves actually do, because the names are unhelpful:
//
//   S4U2Self  — a service asks for a ticket TO ITSELF, on behalf of a user, WITHOUT the
//               user being involved at all. That is the surprising part: no password, no
//               ticket from the user, nothing the user consented to. It is how a service
//               that authenticated somebody by other means (a form, a certificate, NTLM)
//               obtains a Kerberos identity for them. The ticket it gets back is the
//               EVIDENCE for the next step.
//   S4U2Proxy — the service then asks for a ticket to ANOTHER service on the user's
//               behalf, presenting that evidence ticket in `additional-tickets` with the
//               cname-in-addl-tkt option set. The KDC decides whether to allow it, and
//               THAT decision is the whole of constrained delegation.
//
// Which is why S4U2Self is not itself a privilege escalation and S4U2Proxy is: the first
// gets you a ticket to yourself, and the second gets you a ticket to somebody else as
// anybody. What stands between them is one attribute on an account.
// ---------------------------------------------------------------------------

// The S4UByteArray of [MS-SFU] section 2.2.1, whose exact composition is not
// guessable: the name TYPE as four little-endian bytes, then each name
// component, then the realm, then the auth-package — concatenated with no
// separators and no terminators.
function s4uByteArray(userName, userRealm, authPackage) {
  log.debug("Entering s4uByteArray().");
  var parts = [new Uint8Array([
    userName.type & 0xff, (userName.type >>> 8) & 0xff,
    (userName.type >>> 16) & 0xff, (userName.type >>> 24) & 0xff
  ])];
  (userName.name ||
      []).forEach(function (component) { parts.push(prim.utf8(component)); });
  parts.push(prim.utf8(userRealm));
  parts.push(prim.utf8(authPackage || "Kerberos"));
  log.debug("Leaving s4uByteArray().");
  return prim.concat(parts);
}

// PA-FOR-USER's keyed checksum. Note what it is NOT: the checksum type is
// **KERB_CHECKSUM_HMAC_MD5 always**, whatever the session key's own etype, so
// an AES session key is fed to an HMAC-MD5 here. Using the session key's own
// checksum type instead produces a well-formed request the KDC rejects, and
// [MS-SFU] section 2.2.1 is explicit about it.
async function forUserChecksum(sessionKey, userName, userRealm, authPackage) {
  var arcfour = kcrypto.etypeById(23);
  return {
    type: arcfour.checksumType,                   // -138
    checksum: await arcfour.checksum(sessionKey,
        kcrypto.KEY_USAGE.PA_FOR_USER_CKSUM,
      s4uByteArray(userName, userRealm, authPackage))
  };
}

// S4U2Self. `tgt` is the SERVICE's own TGT; `user` is who to impersonate.
async function buildS4u2SelfReq(options) {
  log.debug("Entering buildS4u2SelfReq().");
  var opts = options || {};
  var user = opts.user;
  if (!user || !user.name) {
    throw new Error("krb5: S4U2Self needs the user to impersonate (a " +
        "PrincipalName)");
  }
  var userRealm = opts.userRealm || opts.tgt.realm;
  var authPackage = opts.authPackage || "Kerberos";
  var forUser = msgs.encPaForUser({
    userName: user,
    userRealm: userRealm,
    cksum: await forUserChecksum(opts.tgt.sessionKey, user, userRealm,
        authPackage),
    authPackage: authPackage
  });

  // sname is the service ITSELF — that is what makes it S4U2*Self*.
  var built = await buildTgsReq(Object.assign({}, opts, {
    sname: opts.sname || opts.tgt.client,
    // Ask for a forwardable ticket: without that flag the result cannot be used
    // as evidence for classic S4U2Proxy, and the KDC only grants it to an
    // account with TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION. A client that does
    // not ask gets a ticket that works perfectly and then fails at the next
    // step for an unrelated-looking reason.
    kdcOptions: opts.kdcOptions || [msgs.KDC_OPTION.FORWARDABLE,
        msgs.KDC_OPTION.RENEWABLE],
    extraPadata: [{
      type: msgs.PA_TYPE.FOR_USER,
      value: forUser
    }].concat(opts.extraPadata || [])
  }));
  log.debug("Leaving buildS4u2SelfReq(). impersonating " +
      msgs.principalToString(user, userRealm));
  return Object.assign({ impersonating: msgs.principalToString(user,
      userRealm) }, built);
}

// S4U2Proxy. `evidence` is the ticket S4U2Self produced (or one the user
// forwarded); `sname` is the BACK-END service to reach on their behalf.
async function buildS4u2ProxyReq(options) {
  log.debug("Entering buildS4u2ProxyReq().");
  var opts = options || {};
  if (!opts.evidenceTicket) {
    throw new Error("krb5: S4U2Proxy needs the evidence ticket — the service " +
        "ticket for the user, " +
      "which goes in additional-tickets and is what the KDC reads the " +
          "client's identity out of");
  }
  var options4 = [msgs.KDC_OPTION.FORWARDABLE, msgs.KDC_OPTION.RENEWABLE,
                  msgs.KDC_OPTION.CNAME_IN_ADDL_TKT];
  var padata = [];
  // Resource-based constrained delegation additionally requires PA-PAC-OPTIONS
  // with the RBCD bit. [MS-SFU] makes a KDC answer KDC_ERR_BADOPTION without
  // it, and that error says nothing about padata — so it is offered explicitly
  // rather than always sent.
  if (opts.resourceBased) {
    padata.push({
      type: msgs.PA_TYPE.PAC_OPTIONS,
      value: msgs.encPaPacOptions([msgs.PAC_OPTION.RESOURCE_BASED_CONSTRAINED_DELEGATION])
    });
  }
  var built = await buildTgsReq(Object.assign({}, opts, {
    kdcOptions: opts.kdcOptions || options4,
    additionalTickets: [opts.evidenceTicket],
    extraPadata: padata.concat(opts.extraPadata || [])
  }));
  log.debug("Leaving buildS4u2ProxyReq(). resourceBased=" +
      !!opts.resourceBased);
  return built;
}

// A renewal. The same TGT is presented with the RENEW option and the same sname
// it was issued for; the KDC returns a new one with the ORIGINAL authtime
// preserved, which is the point — a renewed ticket does not become a freshly
// authenticated one, and a service relying on authtime would be deceived if it
// did.
async function buildRenewReq(options) {
  log.debug("Entering buildRenewReq().");
  var opts = options || {};
  log.debug("Leaving buildRenewReq().");
  return buildTgsReq(Object.assign({}, opts, {
    sname: opts.sname || {
      type: msgs.NAME_TYPE.SRV_INST,
      name: ["krbtgt", opts.tgt.realm]
    },
    kdcOptions: opts.kdcOptions || [msgs.KDC_OPTION.RENEW,
        msgs.KDC_OPTION.RENEWABLE]
  }));
}

// ---------------------------------------------------------------------------
// UNCONSTRAINED delegation: a forwarded TGT inside a KRB-CRED.
//
// This is the oldest and by far the most dangerous form. The client asks its KDC for a
// ticket-granting ticket flagged `forwarded`, wraps it in a KRB-CRED with its session key,
// and puts that in the AP-REQ Authenticator's 0x8003 checksum. The service can then get a
// ticket to ANYTHING as that client, for as long as the TGT lives, and the KDC is never
// consulted about it again — there is no list of permitted targets, because there is no
// constraint. Compare S4U2Proxy, where every hop goes back to the KDC and is checked
// against an attribute.
//
// Two defences exist and both live on the CLIENT's account rather than the service's:
// the `NOT_DELEGATED` flag ([MS-SAMR]'s USER_ACCOUNT code 0x4000, "Account is sensitive
// and cannot be delegated"), which makes the KDC refuse to issue a forwardable ticket at
// all; and Protected Users. The service's `ok-as-delegate` flag is only ADVICE to the
// client about whether to do this — nothing enforces it, which is exactly why the client
// side is where the decision has to be made carefully.
// ---------------------------------------------------------------------------

// Ask the KDC for a forwarded TGT. `sname` stays krbtgt: the result is another
// ticket-granting ticket, which is the whole point — a service ticket would
// only reach one service, and this is meant to reach all of them.
async function buildForwardedTgtReq(options) {
  log.debug("Entering buildForwardedTgtReq().");
  var opts = options || {};
  log.debug("Leaving buildForwardedTgtReq().");
  return buildTgsReq(Object.assign({}, opts, {
    sname: opts.sname || {
      type: msgs.NAME_TYPE.SRV_INST,
      name: ["krbtgt", opts.tgt.realm]
    },
    // FORWARDED asks for the flag. FORWARDABLE is sent alongside it so the
    // forwarded ticket can itself be forwarded onward — though note this is
    // belt and braces against a STRICT KDC: RFC 4120 has the TGS set
    // FORWARDABLE when it is requested *and* the presented ticket carries it,
    // while this project's mock KDC inherits the presented ticket's flags
    // unconditionally. So dropping the option changes nothing against the mock
    // and would matter against Active Directory — which is why it is stated
    // here rather than left to be discovered, and why no test asserts a
    // difference it cannot produce.
    kdcOptions: opts.kdcOptions || [msgs.KDC_OPTION.FORWARDED,
        msgs.KDC_OPTION.FORWARDABLE],
    // The address the ticket is being forwarded TO, when the client cares to
    // bind it. AD issues addressless tickets and so does this by default; a
    // bound one is stricter and breaks behind NAT, which is why almost nobody
    // uses it.
    addresses: opts.addresses || null
  }));
}

// Wrap a ticket and its session key as a KRB-CRED, encrypted for one service.
//
// `key` is the AP exchange's subkey when there is one and the ticket's session
// key otherwise — NOT the forwarded ticket's own key. Key usage 14.
async function wrapDelegatedCredential(options) {
  log.debug("Entering wrapDelegatedCredential().");
  var opts = options || {};
  var forwarded = opts.forwarded;
  if (!forwarded || !forwarded.ticket || !forwarded.sessionKey) {
    throw new Error("krb5: a KRB-CRED needs the forwarded ticket AND its " +
        "session key — the ticket " +
      "alone is opaque to whoever receives it, so forwarding one without its " +
          "key delegates nothing");
  }
  var profile = kcrypto.etypeById(opts.key.etype);
  var now = opts.now || new Date();
  var part = msgs.encEncKrbCredPart({
    ticketInfo: [{
      key: { etype: forwarded.etype, key: forwarded.sessionKey },
      prealm: forwarded.realm,
      pname: forwarded.client,
      flags: forwarded.flags || null,
      authtime: forwarded.authtime || null,
      starttime: forwarded.starttime || null,
      endtime: forwarded.endtime || null,
      renewTill: forwarded.renewTill || null,
      srealm: forwarded.serviceRealm || forwarded.realm,
      sname: forwarded.service || null
    }],
    nonce: opts.nonce === undefined ? randomNonce() : opts.nonce,
    timestamp: now,
    usec: (now.getMilliseconds() * 1000) % 1000000
  });
  var cred = msgs.encKrbCred({
    tickets: [forwarded.ticket],
    encPart: {
      etype: opts.key.etype,
      cipher: await profile.encrypt(opts.key.key,
          kcrypto.KEY_USAGE.KRB_CRED_ENCPART, part)
    }
  });
  log.debug("Leaving wrapDelegatedCredential(). bytes=" + cred.length);
  return cred;
}

// The acceptor's half: open a KRB-CRED and produce something usable as a TGT.
//
// The result is deliberately shaped like the return of readTgsRep(), so a
// service can hand it straight to buildTgsReq() and start acting as the client.
// That IS the capability, and the shape makes it obvious rather than clever.
async function readDelegatedCredential(options) {
  log.debug("Entering readDelegatedCredential().");
  var opts = options || {};
  var cred = msgs.readKrbCred(opts.bytes);
  var profile = kcrypto.etypeById(cred.encPart.etype);
  if (opts.key.etype !== cred.encPart.etype) {
    throw new Error("krb5: this KRB-CRED is encrypted with " +
        cred.encPart.etypeName +
      " (etype " + cred.encPart.etype + ") and the key supplied is etype " +
          opts.key.etype +
      ". The key is the AP exchange's subkey if one was sent and the " +
          "ticket's session key " +
      "otherwise — not the forwarded ticket's own key.");
  }
  var part = msgs.readEncKrbCredPart(await profile.decrypt(opts.key.key,
    kcrypto.KEY_USAGE.KRB_CRED_ENCPART, cred.encPart.cipher));
  if (part.ticketInfo.length !== cred.tickets.length) {
    throw new Error("krb5: this KRB-CRED carries " + cred.tickets.length +
        " ticket(s) and " +
      part.ticketInfo.length + " set(s) of ticket information. They are " +
          "positional, so a " +
      "mismatch means no ticket can be paired with its key.");
  }
  var info = part.ticketInfo[0];
  log.debug("Leaving readDelegatedCredential(). " +
      msgs.principalToString(info.pname, info.prealm));
  return {
    ok: true,
    ticket: cred.tickets[0],
    sessionKey: info.key.key,
    etype: info.key.etype,
    client: info.pname,
    realm: info.prealm,
    service: info.sname,
    serviceRealm: info.srealm,
    flags: info.flags || [],
    flagNames: msgs.ticketFlagNames(info.flags || []),
    authtime: info.authtime,
    starttime: info.starttime,
    endtime: info.endtime,
    renewTill: info.renewTill,
    timestamp: part.timestamp,
    credential: part
  };
}

module.exports = {
  buildTgsReq: buildTgsReq,
  buildS4u2SelfReq: buildS4u2SelfReq,
  buildS4u2ProxyReq: buildS4u2ProxyReq,
  buildRenewReq: buildRenewReq,
  buildForwardedTgtReq: buildForwardedTgtReq,
  wrapDelegatedCredential: wrapDelegatedCredential,
  readDelegatedCredential: readDelegatedCredential,
  s4uByteArray: s4uByteArray,
  forUserChecksum: forUserChecksum,
  readTgsRep: readTgsRep,
  // Exported for tests/krb5_tgs_ap.js, which cannot otherwise check the one
  // thing this does that no KDC worth testing against exercises: the trim. The
  // etypes in use (the AES CTS profiles, RC4) return no padding at all, so a
  // reply from either KDC in this suite trims to itself and an assertion made
  // through readTgsRep() would pass with the trim deleted.
  replyBytes: replyBytes,
  buildApReq: buildApReq,
  readApRep: readApRep,
  perMessageKey: perMessageKey,
  randomNonce: randomNonce,
  randomSequenceNumber: randomSequenceNumber
};
