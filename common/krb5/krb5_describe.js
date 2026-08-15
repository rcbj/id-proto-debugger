// File: krb5_describe.js
//
// ---------------------------------------------------------------------------
// "Here are these bytes, explained" — the decoder page's whole content, with no
// DOM in it.
//
// The split follows webauthn.js / webauthn_panes.js: every fact about Kerberos
// lives here and is checkable by a node test with no browser, and the page is a
// renderer that knows nothing about the protocol. A pane that disagreed with the
// protocol would then be a rendering bug rather than a protocol bug, which is a
// much cheaper thing to find.
//
// Output is a plain document:
//
//   { kind, summary, sections: [ { title, note, rows: [ {name, value, note} ],
//                                 sections: [...] } ], problems: [...] }
//
// Three design points worth stating, because each is a decision the obvious
// implementation gets wrong:
//
//  * **Every value is a STRING here, already formatted.** The renderer never
//    formats and never interprets. That is what stops a hex dump becoming a
//    number somewhere, and it is why the page can put everything through
//    textContent — this page renders bytes a stranger pasted in, and every value
//    in it is hostile by default.
//  * **A failure to decrypt is CONTENT, not an error.** Most of the interesting
//    parts of a Kerberos message are encrypted under keys the person reading it
//    does not have. "Encrypted under the service's key, which you have not
//    supplied" is the most useful sentence on the screen, so it is a row rather
//    than an exception.
//  * **`problems` is for things that are WRONG, not things that are absent.**
//    A missing optional field is normal. A pvno of 4, an etype the KDC should not
//    still be offering, a KerberosTime far from now — those are findings, and
//    they are what somebody opened this page to be told.
// ---------------------------------------------------------------------------

var prim = require("./krb5_primitives.js");
var asn1 = require("./krb5_asn1.js");
var msgs = require("./krb5_messages.js");
var kcrypto = require("./krb5_crypto.js");
var kpac = require("./krb5_pac.js");
var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "krb5_describe",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || "info";
    } catch (e) {
      // No CONFIG_FILE resolvable here — a node caller rather than a bundle.
      return "info";
    }
  })()
});

// ---------------------------------------------------------------------------
// Getting the bytes out of whatever was pasted.
//
// A capture arrives in more shapes than people expect, and guessing wrong gives
// a parse error that names ASN.1 rather than the paste. Each accepted form is
// reported, so the page can say what it decided.
// ---------------------------------------------------------------------------
function parseInput(text) {
  log.debug("Entering parseInput().");
  var raw = String(text === null || text === undefined ? "" : text).trim();
  if (!raw) {
    throw new Error("Nothing to decode — paste a Kerberos message first.");
  }

  // Wireshark's "Copy as a hex stream", a C array, or a colon-separated dump:
  // strip the punctuation that is obviously not data.
  var cleaned = raw.replace(/0x/gi, "").replace(/[\s,:;]+/g, "");
  var how;
  var bytes;

  if (/^[0-9a-f]+$/i.test(cleaned) && cleaned.length % 2 === 0 && 
      cleaned.length >= 4) {
    bytes = prim.fromHex(cleaned);
    how = "hex";
  } else {
    // base64 or base64url. Padding is optional in the wild.
    var b64 = raw.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
    var pad = b64.length % 4;
    if (pad === 1) {
      throw new Error("This is not valid base64 (its length cannot be right) " +
          "and not hex either.");
    }
    if (pad) b64 += "====".slice(pad);
    var decoded;
    try {
      decoded = base64ToBytes(b64);
    } catch (e) {
      throw new Error("Could not read this as hex or as base64: " + e.message);
    }
    bytes = decoded;
    how = /[-_]/.test(raw) ? "base64url" : "base64";
  }

  // The TCP framing. Kerberos over TCP puts a four-byte big-endian length in
  // front of every message, and a capture very often includes it. Left in place
  // the ASN.1 parse fails on the first byte, which names the wrong thing
  // entirely — so it is detected and stripped, and SAID.
  var framing = null;
  if (bytes.length > 4 && (bytes[0] & 0x80) === 0) {
    var declared = ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
    if (declared === bytes.length - 4 && 
        asn1.peekApplicationNumber(bytes.subarray(4)) !== null) {
      framing = "TCP length prefix (" + declared + " bytes) stripped";
      bytes = bytes.subarray(4);
    }
  }

  log.debug("Leaving parseInput(). " + how + ", " + bytes.length + " bytes");
  return { bytes: bytes, encoding: how, framing: framing };
}

function base64ToBytes(b64) {
  if (typeof atob === "function") {
    var s = atob(b64);
    var out = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }
  // node
  return new Uint8Array(Buffer.from(b64, "base64"));
}

// ---------------------------------------------------------------------------
// Formatting helpers. Everything the renderer receives is already a string.
// ---------------------------------------------------------------------------
function hexOf(bytes, limit) {
  var h = prim.toHex(bytes);
  var cap = limit || 96;
  return h.length > cap * 2 ? h.slice(0, cap * 2) + "… (" + 
      prim.toBytes(bytes).length + " bytes)" : h;
}

function timeOf(date) {
  if (!date) {
    return "(absent)";
  }
  return asn1.formatKerberosTime(date) + "  (" + date.toISOString() + ")";
}

function principalOf(p, realm) {
  log.debug("Entering principalOf().");
  if (!p) {
    log.debug("Leaving principalOf().");
    return "(absent)";
  }
  var nameTypeName = null;
  Object.keys(msgs.NAME_TYPE).forEach(function (k) {
    if (msgs.NAME_TYPE[k] === p.type) nameTypeName = k;
  });
  log.debug("Leaving principalOf().");
  return msgs.principalToString(p, realm) +
    "   [name-type " + p.type + (nameTypeName ? " NT-" + 
        nameTypeName.replace(/_/g, "-") : "") + "]";
}

function row(name, value, note) {
  return {
    name: name,
    value: value === undefined || value === null ? "(absent)" : String(value),
    note: note || null
  };
}

function etypeListOf(ids) {
  return (ids || []).map(function (id) {
    return id + " " + kcrypto.etypeName(id) + (kcrypto.isSupportedEtype(id) ? 
        "" : " (not performed here)");
  }).join("\n");
}

// ---------------------------------------------------------------------------
// Decryption, when the reader has a key.
//
// The caller supplies candidate keys; each encrypted part is tried with the keys
// whose etype matches, at the key usage that part is defined to use. Trying every
// usage would be worse than useless: it would sometimes succeed with the wrong
// one and present a confident wrong answer.
// ---------------------------------------------------------------------------
async function tryDecrypt(encPart, usage, keys, what) {
  log.debug("Entering tryDecrypt().");
  var candidates = (keys || 
      []).filter(function (k) { return k.etype === encPart.etype; });
  if (!candidates.length) {
    var haveOther = (keys || []).length > 0;
    log.debug("Leaving tryDecrypt().");
    return {
      ok: false,
      note: haveOther
        ? "Encrypted with " + encPart.etypeName + " (etype " + encPart.etype + 
            "), and none of the keys " +
          "supplied is of that type. " + what
        : "Encrypted with " + encPart.etypeName + ". " + what
    };
  }
  var e;
  try {
    e = kcrypto.etypeById(encPart.etype);
  } catch (err) {
    log.debug("Leaving tryDecrypt().");
    return {
      ok: false,
      note: "This build cannot decrypt " + encPart.etypeName + ": " + 
          err.message
    };
  }
  for (var i = 0; i < candidates.length; i++) {
    try {
      var plain = await e.decrypt(candidates[i].key, usage, encPart.cipher);
      log.debug("Leaving tryDecrypt().");
      return { ok: true, plain: plain, usedKey: candidates[i], usage: usage };
    } catch (err) {
      // Wrong key of the right type: keep trying the others. Reported below if
      // none works, because "the key you gave is not this key" is a real
      // answer.
      log.debug("key " + (candidates[i].label || i) + " did not decrypt: " + 
          err.message);
    }
  }
  log.debug("Leaving tryDecrypt().");
  return {
    ok: false,
    note: candidates.length + " key(s) of the right type were tried at key " +
        "usage " + usage +
      " and none decrypted this. Either the key is not this principal's, or " +
          "its kvno is stale."
  };
}

// ---------------------------------------------------------------------------
// The per-message describers.
// ---------------------------------------------------------------------------

function describeEncryptedData(d, label) {
  log.debug("Leaving describeEncryptedData().");
  log.debug("Entering describeEncryptedData().");
  return {
    title: label,
    rows: [
      row("etype", d.etype + " " + d.etypeName),
      row("kvno", d.kvno === null ? "(absent)" : d.kvno,
          d.kvno === null ? null : "the key version — a stale one is " +
              "KRB_AP_ERR_BADKEYVER"),
      row("cipher", hexOf(d.cipher), prim.toBytes(d.cipher).length + " bytes")
    ]
  };
}

async function describeTicket(ticket, keys, problems) {
  log.debug("Entering describeTicket().");
  var section = {
    title: "Ticket",
    note: "Opaque to its holder: encrypted under the SERVICE's long-term " +
        "key. Supply that key " +
          "(or its keytab) to see inside.",
    rows: [
      row("tkt-vno", ticket.tktVno),
      row("realm", ticket.realm),
      row("sname", principalOf(ticket.sname, ticket.realm))
    ],
    sections: [describeEncryptedData(ticket.encPart, "Ticket enc-part " +
        "(EncTicketPart)")]
  };
  if (ticket.tktVno !== 5) {
    problems.push("The ticket's tkt-vno is " + ticket.tktVno + ", not 5.");
  }
  var attempt = await tryDecrypt(ticket.encPart, 
      kcrypto.KEY_USAGE.KDC_REP_TICKET, keys,
    "Supply the service's key to read the session key, the client name and " +
        "the PAC.");
  if (attempt.ok) {
    try {
      var part = msgs.readEncTicketPart(attempt.plain);
      section.sections.push(await describeEncTicketPart(part, attempt.usedKey, 
          problems, keys));
    } catch (e) {
      section.sections.push({
        title: "EncTicketPart",
        rows: [row("decrypted, but", e.message)]
      });
    }
  } else {
    section.sections[0].rows.push(row("decryption", "not attempted or not " +
        "possible", attempt.note));
  }
  log.debug("Leaving describeTicket().");
  return section;
}

async function describeEncTicketPart(p, usedKey, problems, keys) {
  log.debug("Entering describeEncTicketPart().");
  var rows = [
    row("flags", msgs.ticketFlagNames(p.flags).join(", ") || "(none)",
        "bits " + p.flags.join(", ")),
    row("key", p.key.etypeName + ", " + hexOf(p.key.key), "the SESSION key — " +
        "a credential in itself"),
    row("crealm", p.crealm),
    row("cname", principalOf(p.cname, p.crealm)),
    row("authtime", timeOf(p.authtime)),
    row("starttime", timeOf(p.starttime)),
    row("endtime", timeOf(p.endtime)),
    row("renew-till", timeOf(p.renewTill))
  ];
  if (p.caddr) {
    rows.push(row("caddr", p.caddr.map(function (a) {
      return "type " + a.type + " " + prim.toHex(a.address);
    }).join(", "), "an address-restricted ticket; AD issues addressless ones"));
  }
  var pacSections = [];
  if (p.authorizationData) {
    rows.push(row("authorization-data", p.authorizationData.map(function (ad) {
      return kpac.adTypeName(ad.type) + " (" + prim.toBytes(ad.data).length + 
          " bytes)";
    }).join(", "), "the top-level elements only; the PAC is nested inside " +
        "AD-IF-RELEVANT"));

    var found = kpac.findPacs(p.authorizationData);
    if (!found.length) {
      rows.push(row("PAC", "none",
        "no AD-WIN2K-PAC in here. A ticket from Active Directory carries one " +
            "unless the account " +
        "has USER_NO_AUTH_DATA_REQUIRED set or the client asked for none — " +
            "and a service that " +
        "authorizes on groups has nothing to read without it"));
    } else if (found.length > 1) {
      problems.push("This ticket carries " + found.length + " PACs. A ticket " +
          "has one; the extra " +
        "ones are a place to hide a different set of groups.");
    }
    // The key that opened this ticket IS the service's long-term key by
    // definition, so it is exactly the key the server signature is made with —
    // which is why the PAC's signatures can be checked at all here without
    // asking for anything more.
    var pool = (keys || []).slice();
    if (usedKey && pool.indexOf(usedKey) === -1) pool.push(usedKey);
    for (var i = 0; i < found.length; i++) {
      // usedKey is passed as the ASSERTED service key, not merely thrown into
      // the pool: a server signature that fails against the key which just
      // decrypted this ticket is a real finding, while the KDC signature
      // failing against a pool of unlabelled keys is only ever "you do not have
      // the krbtgt key".
      pacSections.push(await describePac(found[i], pool, problems, usedKey));
    }
  }
  if (p.flags.indexOf(msgs.TICKET_FLAG.OK_AS_DELEGATE) !== -1) {
    rows.push(row("note", "ok-as-delegate is set",
      "the KDC is telling the client this service may be trusted with " +
          "delegated credentials"));
  }
  log.debug("Leaving describeEncTicketPart().");
  return {
    title: "EncTicketPart (decrypted)",
    note: usedKey ? "Decrypted with " + (usedKey.label || "a supplied key") + 
        "." : null,
    rows: rows,
    sections: pacSections
  };
}

// ---------------------------------------------------------------------------
// The PAC.
//
// Presented as its own nest of sections rather than a row of hex, because this is the
// structure that decides what the ticket's holder can DO — a service authorizes on the
// groups in here, not on the ticket's cname. See krb5_pac.js's header for the wire
// format and for why the four signatures are not interchangeable.
//
// The rule from this file's header applies throughout: `problems` is for what is
// WRONG. An undecoded buffer is not a problem, an absent one usually is not either,
// and a group list a real service would ignore very much is.
// ---------------------------------------------------------------------------
async function describePac(found, keys, problems, serviceKey) {
  log.debug("Entering describePac(). bytes=" + found.bytes.length);
  var parsed;
  try {
    parsed = kpac.parsePac(found.bytes);
  } catch (e) {
    // A PAC that will not parse at all is content, not an exception: the reader
    // wants to know that, and to see how big the thing was.
    return {
      title: "PAC (does not parse)",
      note: "Found at " + found.path + ", " + found.bytes.length + " bytes.",
      rows: [row("error", e.message)]
    };
  }

  parsed.problems.forEach(function (p) { problems.push("PAC: " + p); });

  var section = {
    title: "PAC (Privilege Attribute Certificate)",
    note: "Found at " + found.path + ". " + found.bytes.length + " bytes in " + 
        parsed.cBuffers +
      " buffer(s). This is what a Windows service reads to decide what the " +
          "holder may do — " +
      "everything from here down is little-endian C structures and NDR, not " +
          "DER.",
    rows: [
      row("buffers", parsed.buffers.map(function (b) {
        return b.type + " " + b.typeName + " — " + b.size + 
            " bytes at offset " + b.offset;
      }).join("\n")),
      row("PACTYPE Version", parsed.version, parsed.version === 0 ? null : 
          "[MS-PAC] requires 0")
    ],
    sections: []
  };

  var logon = kpac.bufferOfType(parsed, kpac.TYPE.LOGON_INFO);
  if (logon && 
      logon.parsed) section.sections.push(describeLogonInfo(logon.parsed, 
      problems));
  else if (logon) {
    section.sections.push({
      title: "Logon information (KERB_VALIDATION_INFO)",
      rows: [row("does not parse", logon.error || "(no reason recorded)")]
    });
  }

  var client = kpac.bufferOfType(parsed, kpac.TYPE.CLIENT_INFO);
  if (client && client.parsed) {
    section.sections.push({
      title: "Client name and ticket information",
      note: "Used to check the PAC belongs to this ticket's client rather " +
          "than to another one.",
      rows: [
        row("name", client.parsed.name),
        row("ClientId", client.parsed.clientId.text,
          "the INITIAL TGT's authentication time, which is the same across " +
              "every service " +
          "ticket derived from it — not this ticket's authtime")
      ]
    });
  }

  var upn = kpac.bufferOfType(parsed, kpac.TYPE.UPN_DNS_INFO);
  if (upn && upn.parsed) {
    var u = upn.parsed;
    section.sections.push({
      title: "UPN and DNS information",
      rows: [
        row("UPN", u.upn),
        row("DNS domain name", u.dnsDomainName),
        row("SAM name", u.samName, u.extended ? null : "only present when " +
            "the S flag is set"),
        row("SID", u.sid ? u.sid.text : null),
        row("flags", u.flagNames.join("\n") || "(none set)")
      ]
    });
  }

  var attrs = kpac.bufferOfType(parsed, kpac.TYPE.ATTRIBUTES_INFO);
  if (attrs && attrs.parsed) {
    section.sections.push({
      title: "PAC attributes",
      rows: [
        row("flags", attrs.parsed.flagNames.join(", ") || "(none set)",
          attrs.parsed.flagNames.indexOf("PAC_WAS_GIVEN_IMPLICITLY") !== -1
            ? "the client neither asked for nor declined a PAC" : null),
        row("FlagsLength", attrs.parsed.flagsLength + " bits")
      ]
    });
  }

  var requestor = kpac.bufferOfType(parsed, kpac.TYPE.REQUESTOR_SID);
  if (requestor && requestor.parsed) {
    section.sections.push({
      title: "PAC requestor",
      note: "The SID of the account that ASKED for this ticket. In a " +
          "delegation flow that is " +
        "not the account the ticket is for, which is the whole point of the " +
            "buffer.",
      rows: [row("SID", requestor.parsed.sid.text +
        (requestor.parsed.name ? "  (" + requestor.parsed.name + ")" : ""))]
    });
  }

  // Anything present that this codec does not decode, listed rather than
  // dropped.
  var undecoded = parsed.buffers.filter(function (b) {
    return b.parsed === null && !b.error && !kpac.isSignatureBuffer(b.type);
  });
  if (undecoded.length) {
    section.sections.push({
      title: "Buffers not decoded here",
      note: "Present in the PAC and not read by this codec. Listed rather " +
          "than dropped, because " +
        "'present but not decoded' is a different fact from 'absent'.",
      rows: undecoded.map(function (b) {
        return row(b.typeName, b.size + " bytes", hexOf(b.bytes, 32));
      })
    });
  }

  section.sections.push(await describePacSignatures(parsed, keys, problems, 
      serviceKey));
  log.debug("Leaving describePac().");
  return section;
}

function describeLogonInfo(info, problems) {
  log.debug("Entering describeLogonInfo().");
  var rows = [
    row("account", info.effectiveName, info.fullName ? "full name: " + 
        info.fullName : null),
    row("account SID", info.userSid,
      "assembled from LogonDomainId + UserId (" + info.userId + ") — a PAC " +
          "never carries it whole"),
    row("primary group SID", info.primaryGroupSid, "RID " + 
        info.primaryGroupId +
      (kpac.ridName(info.primaryGroupId) ? ", " + 
          kpac.ridName(info.primaryGroupId) : "")),
    row("logon domain", info.logonDomainName +
      (info.logonDomainId ? "  (" + info.logonDomainId.text + ")" : "")),
    row("logon server", info.logonServer, "the DC that issued the initial TGT"),
    row("UserAccountControl", info.userAccountControlNames.join("\n") || 
        "(none set)",
      "[MS-SAMR]'s USER_ACCOUNT codes, not the LDAP userAccountControl bits"),
    row("UserFlags", info.userFlagNames.join("\n") || "(none set)"),
    row("logon count", info.logonCount),
    row("bad password count", info.badPasswordCount),
    row("logon time", info.logonTime.text),
    row("logoff time", info.logoffTime.text),
    row("kickoff time", info.kickOffTime.text),
    row("password last set", info.passwordLastSet.text),
    row("password must change", info.passwordMustChange.text),
    row("groups (" + info.groups.length + ")", info.groups.length
      ? info.groups.map(function (g) {
        return (info.logonDomainId ? info.logonDomainId.text + "-" : "RID ") + 
            g.relativeId +
          (g.name ? "  (" + g.name + ")" : "") + "   [" + 
              g.attributeNames.join(", ") + "]";
      }).join("\n")
      : "(none)",
      "groups in the ACCOUNT's domain, given as RIDs — the SID is the domain " +
          "SID plus the RID")
  ];

  if (info.extraSids.length) {
    rows.push(row("extra SIDs (" + info.extraSids.length + ")",
      info.extraSids.map(function (e) {
        return e.text + (e.name ? "  (" + e.name + ")" : "") + "   [" +
          e.attributeNames.join(", ") + "]";
      }).join("\n"),
      "SIDs from outside the account's domain, and the well-known ones that " +
          "record HOW the " +
      "identity was established"));
  }
  if (info.resourceGroups.length) {
    rows.push(row("resource groups (" + info.resourceGroups.length + ")",
      info.resourceGroups.map(function (g) {
        return (info.resourceGroupDomainSid ? 
            info.resourceGroupDomainSid.text + "-" : "RID ") +
          g.relativeId + (g.name ? "  (" + g.name + ")" : "") + "   [" +
          g.attributeNames.join(", ") + "]";
      }).join("\n"),
      "domain-local groups in the RESOURCE's domain, which is a different " +
          "domain SID from the " +
      "account's"));
  }
  if (info.userSessionKey && 
      
          
              
                  
                      
                          !prim.toBytes(info.userSessionKey).every(function (b) { return b === 0; })) {
    rows.push(row("UserSessionKey", hexOf(info.userSessionKey),
      "[MS-PAC] requires this to be zero for Kerberos — it is an NTLM field"));
    problems.push("The PAC's UserSessionKey is not zero. [MS-PAC] section " +
        "2.5 requires zero for " +
      "anything other than NTLM.");
  }

  // Each of these parses fine and changes how a real service behaves, which is
  // the definition of a finding here rather than a note.
  info.notes.forEach(function (n) { problems.push("PAC logon information: " + 
      n); });

  log.debug("Leaving describeLogonInfo().");
  return {
    title: "Logon information (KERB_VALIDATION_INFO)",
    note: "NDR-encoded ([MS-RPCE] section 2.2.6), which is why this one " +
        "buffer starts with " +
      "01 10 08 00 cc cc cc cc. These groups are what a Windows service " +
          "authorizes on.",
    rows: rows
  };
}

async function describePacSignatures(parsed, keys, problems, serviceKey) {
  log.debug("Entering describePacSignatures().");
  var results = await kpac.verifySignaturesWithAnyKey(parsed, keys || [],
    { serverKey: serviceKey || null });
  var rows = results.map(function (r) {
    var state = r.verified === true ? "verified" : r.verified === false ? 
        "DOES NOT VERIFY"
      : "not checked";
    return row(r.name, state + " — " + r.signatureTypeName, r.note);
  });
  if (!results.length) {
    rows.push(row("signatures", "none present",
      "a PAC inside a ticket always carries at least the server and KDC " +
          "signatures"));
  }
  // A signature that failed against a key we KNOW is the right one is a
  // finding. One that no unlabelled key in the pool happened to verify is not —
  // the reader has simply not supplied the krbtgt key, which on a service
  // ticket they cannot have, and reporting that as tampering would cry wolf on
  // every paste.
  //
  // Keyed off `roleAsserted` rather than off the wording of the note: matching
  // prose is how this check silently stopped firing once the note was reworded.
  results.forEach(function (r) {
    if (r.verified === false && r.roleAsserted) {
      problems.push("The PAC's " + r.name + " does not verify against the " + 
          r.role +
        " — the very key that decrypted this ticket. Either the PAC has been " +
            "altered since it " +
        "was signed, or it was not signed for this service.");
    }
  });
  log.debug("Leaving describePacSignatures().");
  return {
    title: "PAC signatures",
    note: "Four signatures over four DIFFERENT things, with two different " +
        "keys. A service holds " +
      "only its own key, so it can check the server signature and nothing " +
          "else — and altering " +
      "the PAC's contents leaves the KDC signature intact, because that one " +
          "covers only the " +
      "server signature's bytes. That is why the extended KDC signature " +
          "exists.",
    rows: rows
  };
}

async function describeKdcReq(req, input, keys, problems) {
  log.debug("Entering describeKdcReq().");
  var isTgs = req.msgType === msgs.MSG_TYPE.TGS_REQ;
  var body = req.reqBody;
  var doc = {
    kind: isTgs ? "TGS-REQ" : "AS-REQ",
    summary: (isTgs ? "A ticket-granting request" : "An " +
        "authentication-service request") +
      " for " + msgs.principalToString(body.sname || { name: ["(no sname)"] }, 
          body.realm) +
      (body.cname ? " by " + msgs.principalToString(body.cname) : ""),
    sections: []
  };
  doc.sections.push({
    title: "Message",
    rows: [
      row("pvno", req.pvno),
      row("msg-type", req.msgType + " (" + doc.kind + ")")
    ]
  });

  var padataRows = [];
  req.padata.forEach(function (pa) {
    padataRows.push(row(pa.typeName + " (" + pa.type + ")", 
        prim.toBytes(pa.value).length + " bytes"));
  });
  doc.sections.push({
    title: "Pre-authentication (padata)",
    note: req.padata.length ? null
      : (isTgs
          ? "A TGS-REQ with no PA-TGS-REQ cannot be answered — the TGT " +
              "travels in the padata."
          : "None. An AS-REQ without PA-ENC-TIMESTAMP is what a KDC answers " +
              "with " +
            "KDC_ERR_PREAUTH_REQUIRED, and that answer is where the salt " +
                "comes from."),
    rows: padataRows.length ? padataRows : [row("padata", "(none)")]
  });
  if (isTgs && 
      
          
              
                  
                      
                          !req.padata.some(function (p) { return p.type === msgs.PA_TYPE.TGS_REQ; })) {
    problems.push("This TGS-REQ carries no PA-TGS-REQ, so it has no TGT and " +
        "no KDC can answer it.");
  }

  // The padata worth expanding.
  req.padata.forEach(function (pa) {
    if (pa.type === msgs.PA_TYPE.ENC_TIMESTAMP) {
      try {
        var enc = msgs.readEncryptedData(asn1.readTlv(pa.value, 0));
        doc.sections.push(describeEncryptedData(enc, "PA-ENC-TIMESTAMP " +
            "(encrypted with the client's key)"));
      } catch (e) {
        problems.push("PA-ENC-TIMESTAMP does not decode as EncryptedData: " + 
            e.message);
      }
    }
    if (pa.type === msgs.PA_TYPE.PAC_REQUEST) {
      try {
        doc.sections.push({
          title: "PA-PAC-REQUEST",
          rows: [row("include-pac", 
              String(msgs.readPaPacRequest(pa.value).includePac),
            "asking a Windows KDC to omit the PAC is a legitimate diagnostic")]
        });
      } catch (e) {
        problems.push("PA-PAC-REQUEST does not decode: " + e.message);
      }
    }
    if (pa.type === msgs.PA_TYPE.FOR_USER) {
      try {
        var fu = msgs.readPaForUser(pa.value);
        doc.sections.push({
          title: "PA-FOR-USER (S4U2Self)",
          note: "This request asks the KDC for a ticket to ITSELF on behalf " +
              "of another user — " +
                "protocol transition.",
          rows: [
            row("userName", principalOf(fu.userName, fu.userRealm)),
            row("userRealm", fu.userRealm),
            row("cksum", "type " + fu.cksum.type + ", " + 
                hexOf(fu.cksum.checksum),
              fu.cksum.type === -138 ? "KERB_CHECKSUM_HMAC_MD5, as MS-SFU " +
                  "requires" : null),
            row("auth-package", fu.authPackage)
          ]
        });
      } catch (e) {
        problems.push("PA-FOR-USER does not decode: " + e.message);
      }
    }
  });

  var optionNames = msgs.kdcOptionNames(body.kdcOptions);
  var bodyRows = [
    row("kdc-options", optionNames.join(", ") || "(none)", "bits " + 
        body.kdcOptions.join(", ")),
    row("cname", principalOf(body.cname, null)),
    row("realm", body.realm, "case-sensitive, and conventionally UPPER CASE"),
    row("sname", principalOf(body.sname, body.realm)),
    row("from", timeOf(body.from)),
    row("till", timeOf(body.till)),
    row("rtime", timeOf(body.rtime)),
    row("nonce", body.nonce, "must come back unchanged in the reply"),
    row("etype", etypeListOf(body.etypes), "in preference order — the KDC " +
        "picks from this list")
  ];
  if (body.addresses) {
    bodyRows.push(row("addresses", body.addresses.map(function (a) {
      return "type " + a.type + " " + prim.toHex(a.address);
    }).join(", ")));
  }
  if (body.additionalTickets) {
    bodyRows.push(row("additional-tickets", body.additionalTickets.length + 
        " ticket(s)",
      optionNames.indexOf("cname-in-addl-tkt") !== -1
        ? "with cname-in-addl-tkt set this is S4U2Proxy: the evidence ticket " +
            "being presented"
        : "used by user-to-user and by constrained delegation"));
  }
  doc.sections.push({ title: "KDC-REQ-BODY", rows: bodyRows });

  if (body.realm && body.realm !== body.realm.toUpperCase()) {
    problems.push("The realm \"" + body.realm + "\" is not upper case. " +
        "Realms are case-sensitive on the " +
      "wire and almost every deployment uses upper case; this is the " +
          "commonest configuration error there is.");
  }
  if (body.etypes && body.etypes.length && 
      body.etypes.every(function (id) { return id === 23; })) {
    problems.push("The only encryption type offered is arcfour-hmac-md5 " +
        "(RC4). The Windows Server 2025 " +
      "security baseline disables it, so this request will be refused with " +
          "KDC_ERR_ETYPE_NOSUPP on a " +
      "current domain controller.");
  }
  (body.etypes || []).forEach(function (id) {
    if (id >= 1 && id <= 7) {
      problems.push("Encryption type " + id + " (" + kcrypto.etypeName(id) + 
          ") is a DES type. DES was " +
        "removed from Windows Server 2025 entirely.");
    }
  });
  if (body.till && body.from && body.till <= body.from) {
    problems.push("till is not after from, so the requested validity window " +
        "is empty " +
      "(KDC_ERR_NEVER_VALID).");
  }
  log.debug("Leaving describeKdcReq().");
  return doc;
}

async function describeKdcRep(rep, keys, problems) {
  log.debug("Entering describeKdcRep().");
  var isTgs = rep.msgType === msgs.MSG_TYPE.TGS_REP;
  // `kind` is computed before the document literal rather than inside it. The
  // first version read `doc.kind` from within the literal that was defining
  // `doc`, which is undefined at that point — and because describe() catches
  // reader exceptions and falls back to a structural view, the symptom was an
  // AS-REP reported as "does not parse". A parse failure blamed on the message
  // when the fault is in the describer is the worst outcome this page can have.
  var kind = isTgs ? "TGS-REP" : "AS-REP";
  var doc = {
    kind: kind,
    summary: "A ticket for " + msgs.principalToString(rep.ticket.sname, 
        rep.ticket.realm) +
             " issued to " + msgs.principalToString(rep.cname, rep.crealm),
    sections: [{
      title: "Message",
      rows: [
        row("pvno", rep.pvno),
        row("msg-type", rep.msgType + " (" + kind + ")"),
        row("crealm", rep.crealm),
        row("cname", principalOf(rep.cname, rep.crealm))
      ]
    }]
  };
  if (rep.padata.length) {
    doc.sections.push({
      title: "padata",
      rows: rep.padata.map(function (pa) {
        return row(pa.typeName + " (" + pa.type + ")", 
            prim.toBytes(pa.value).length + " bytes");
      })
    });
  }
  doc.sections.push(await describeTicket(rep.ticket, keys, problems));

  // The enc-part is under the CLIENT's key for an AS-REP and under the TGT
  // session key (or the Authenticator's subkey) for a TGS-REP. Both usages are
  // tried for a TGS-REP because which one applies depends on whether the
  // request carried a subkey, and the reader of a capture does not necessarily
  // know.
  var encSection = describeEncryptedData(rep.encPart,
    isTgs ? "enc-part (EncTGSRepPart, under the TGT session key or the subkey)"
          : "enc-part (EncASRepPart, under the client's long-term key)");
  doc.sections.push(encSection);

  var usages = isTgs
    ? [kcrypto.KEY_USAGE.TGS_REP_ENCPART_SESSKEY, 
        kcrypto.KEY_USAGE.TGS_REP_ENCPART_SUBKEY]
    : [kcrypto.KEY_USAGE.AS_REP_ENCPART];
  var got = null;
  for (var i = 0; i < usages.length && !got; i++) {
    var attempt = await tryDecrypt(rep.encPart, usages[i], keys,
      isTgs ? "Supply the TGT's session key." : "Supply the client's key, or " +
          "its password and salt.");
    if (attempt.ok) got = attempt;
    else encSection.rows.push(row("decryption at key usage " + usages[i], "no", 
        attempt.note));
  }
  if (got) {
    try {
      var part = msgs.readEncKdcRepPart(got.plain);
      var rows = [
        row("tagged as", part.taggedAs,
          part.taggedAs === "EncTGSRepPart" && !isTgs
            ? "An AS-REP whose enc-part is tagged EncTGSRepPart. RFC 4120 " +
                "section 5.4.2 records this and " +
              "requires a client to accept it — this one does."
            : null),
        row("key", part.key.etypeName + ", " + hexOf(part.key.key), 
            "the session key"),
        row("nonce", part.nonce, "must equal the request's"),
        row("flags", msgs.ticketFlagNames(part.flags).join(", ") || "(none)"),
        row("authtime", timeOf(part.authtime)),
        row("starttime", timeOf(part.starttime)),
        row("endtime", timeOf(part.endtime)),
        row("renew-till", timeOf(part.renewTill)),
        row("key-expiration", timeOf(part.keyExpiration),
          part.keyExpiration ? "the password expiry the KDC is reporting" : 
              null),
        row("srealm", part.srealm),
        row("sname", principalOf(part.sname, part.srealm))
      ];
      doc.sections.push({
        title: "Enc" + (isTgs ? "TGS" : "AS") + "RepPart (decrypted)",
        note: "Decrypted with " + (got.usedKey.label || "a supplied key") + 
            " at key usage " + got.usage + ".",
        rows: rows
      });
      if (part.sname && rep.ticket.sname &&
          part.sname.name.join("/") !== rep.ticket.sname.name.join("/")) {
        problems.push("The sname in the enc-part (" + 
            part.sname.name.join("/") + ") does not match the " +
          "ticket's (" + rep.ticket.sname.name.join("/") + "). With " +
              "canonicalize set this can be a " +
          "referral; otherwise it is wrong.");
      }
    } catch (e) {
      doc.sections.push({
        title: "enc-part",
        rows: [row("decrypted, but does not parse", e.message)]
      });
    }
  }
  log.debug("Leaving describeKdcRep().");
  return doc;
}

async function describeApReq(r, keys, problems) {
  log.debug("Entering describeApReq().");
  var doc = {
    kind: "AP-REQ",
    summary: "A client presenting a ticket for " + 
        msgs.principalToString(r.ticket.sname, r.ticket.realm),
    sections: [{
      title: "Message",
      rows: [
        row("pvno", r.pvno),
        row("msg-type", r.msgType + " (AP-REQ)"),
        row("ap-options", msgs.apOptionNames(r.apOptions).join(", ") || 
            "(none)",
          r.apOptions.indexOf(msgs.AP_OPTION.MUTUAL_REQUIRED) !== -1
            ? "mutual-required: the client expects an AP-REP back"
            : "without mutual-required the service never proves its own " +
                "identity")
      ]
    }]
  };
  doc.sections.push(await describeTicket(r.ticket, keys, problems));
  var encSection = describeEncryptedData(r.authenticator,
    "Authenticator (encrypted under the ticket's SESSION key)");
  doc.sections.push(encSection);
  var attempt = await tryDecrypt(r.authenticator, 
      kcrypto.KEY_USAGE.AP_REQ_AUTH, keys,
    "Supply the session key from the ticket, which the service gets by " +
        "decrypting the ticket itself.");
  if (attempt.ok) {
    try {
      var a = msgs.readAuthenticator(attempt.plain);
      var rows = [
        row("crealm", a.crealm),
        row("cname", principalOf(a.cname, a.crealm),
          "must match the ticket's cname or the service answers " +
              "KRB_AP_ERR_BADMATCH"),
        row("ctime", timeOf(a.ctime), "checked against the service's clock — " +
            "five minutes on AD"),
        row("cusec", a.cusec),
        row("seq-number", a.seqNumber),
        row("subkey", a.subkey ? a.subkey.etypeName + ", " + 
            hexOf(a.subkey.key) : "(absent)",
          a.subkey ? "the client proposing a per-context key" : null)
      ];
      if (a.cksum) {
        rows.push(row("cksum", "type " + a.cksum.type + ", " + 
            hexOf(a.cksum.checksum),
          a.cksum.type === 0x8003
            ? "checksum type 0x8003 — the GSS-API channel-binding-and-flags " +
                "structure of RFC 4121, " +
              "not a checksum over the message at all"
            : null));
      }
      doc.sections.push({
        title: "Authenticator (decrypted)",
        note: "Decrypted with " + (attempt.usedKey.label || "a supplied key") + 
            ".",
        rows: rows
      });
    } catch (e) {
      doc.sections.push({
        title: "Authenticator",
        rows: [row("decrypted, but does not parse", e.message)]
      });
    }
  } else {
    encSection.rows.push(row("decryption", "no", attempt.note));
  }
  log.debug("Leaving describeApReq().");
  return doc;
}

async function describeApRep(r, keys) {
  log.debug("Entering describeApRep().");
  var doc = {
    kind: "AP-REP",
    summary: "A service proving its identity back to the client (mutual " +
        "authentication)",
    sections: [
      {
        title: "Message",
        rows: [row("pvno", r.pvno), row("msg-type", r.msgType + " (AP-REP)")]
      },
      describeEncryptedData(r.encPart, "enc-part (under the ticket's session " +
          "key)")
    ]
  };
  var attempt = await tryDecrypt(r.encPart, kcrypto.KEY_USAGE.AP_REP_ENCPART, 
      keys,
    "Supply the session key.");
  if (attempt.ok) {
    var p = msgs.readEncApRepPart(attempt.plain);
    doc.sections.push({
      title: "EncAPRepPart (decrypted)",
      rows: [
        row("ctime", timeOf(p.ctime), "echoes the Authenticator's ctime — " +
            "that echo IS the proof"),
        row("cusec", p.cusec),
        row("subkey", p.subkey ? p.subkey.etypeName + ", " + 
            hexOf(p.subkey.key) : "(absent)",
          p.subkey ? "the acceptor's subkey, which per-message tokens are " +
              "then keyed from" : null),
        row("seq-number", p.seqNumber)
      ]
    });
  } else {
    doc.sections[1].rows.push(row("decryption", "no", attempt.note));
  }
  log.debug("Leaving describeApRep().");
  return doc;
}

function describeKrbError(e, problems) {
  log.debug("Entering describeKrbError().");
  var doc = {
    kind: "KRB-ERROR",
    summary: e.error.name + " (" + e.errorCode + ") from " +
             msgs.principalToString(e.sname, e.realm),
    sections: [{
      title: "Error",
      rows: [
        row("error-code", e.errorCode + " " + e.error.name),
        row("meaning", e.error.meaning),
        row("e-text", e.eText),
        row("realm", e.realm),
        row("sname", principalOf(e.sname, e.realm)),
        row("crealm", e.crealm),
        row("cname", principalOf(e.cname, e.crealm)),
        row("stime", timeOf(e.stime), "the KDC's own clock, which is how " +
            "skew is measured"),
        row("susec", e.susec),
        row("ctime", timeOf(e.ctime))
      ]
    }]
  };

  // Clock skew is measurable rather than guessable, and this is the one message
  // that carries the other side's clock.
  if (e.stime) {
    var skewSeconds = Math.round((Date.now() - e.stime.getTime()) / 1000);
    var absSkew = Math.abs(skewSeconds);
    doc.sections[0].rows.push(row("skew against this browser",
      (skewSeconds >= 0 ? "+" : "") + skewSeconds + " s",
      absSkew > 300
        ? "MORE THAN FIVE MINUTES. That alone will produce KRB_AP_ERR_SKEW " +
            "on a default AD configuration."
        : "within AD's default five-minute tolerance"));
    if (e.errorCode === 37 || absSkew > 300) {
      problems.push("The clock difference between this browser and the KDC " +
          "is " + skewSeconds +
        " seconds. AD's default tolerance is 300.");
    }
  }

  if (e.eDataPaData) {
    var rows = [];
    e.eDataPaData.forEach(function (pa) {
      rows.push(row(pa.typeName + " (" + pa.type + ")", 
          prim.toBytes(pa.value).length + " bytes"));
      if (pa.type === msgs.PA_TYPE.ETYPE_INFO2) {
        try {
          msgs.readEtypeInfo2(pa.value).forEach(function (info) {
            var iterations = null;
            if (info.s2kparams && prim.toBytes(info.s2kparams).length === 4) {
              var p = prim.toBytes(info.s2kparams);
              iterations = ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
            }
            rows.push(row("  etype " + info.etype + " " + info.etypeName,
              "salt: " + (info.salt === null ? "(none — arcfour is unsalted)" : 
                  JSON.stringify(info.salt)) +
              (iterations !== null ? ", iterations: " + iterations : ""),
              "THIS is the salt to use for string-to-key. It is not " +
                  "guessable: AD uses the realm plus " +
              "the sAMAccountName for a user, but a host-shaped string for a " +
                  "computer account."));
          });
        } catch (err) {
          rows.push(row("  ETYPE-INFO2", "does not decode: " + err.message));
        }
      }
    });
    doc.sections.push({
      title: "e-data",
      note: e.errorCode === 25
        ? "On KDC_ERR_PREAUTH_REQUIRED this is not an error report — it is " +
            "the information needed to " +
          "build the real request."
        : null,
      rows: rows
    });
  } else if (e.eData) {
    doc.sections.push({
      title: "e-data",
      rows: [row("bytes", hexOf(e.eData), e.eDataNote || null)]
    });
  }

  if (e.errorCode !== 25) {
    problems.push(e.error.name + ": " + e.error.meaning);
  }
  log.debug("Leaving describeKrbError().");
  return doc;
}

// ---------------------------------------------------------------------------
// The entry point.
// ---------------------------------------------------------------------------
async function describe(input, options) {
  log.debug("Entering describe().");
  var opts = options || {};
  var parsed = (input instanceof Uint8Array) ? {
    bytes: input,
    encoding: "bytes",
    framing: null
  }
                                             : parseInput(input);
  var bytes = parsed.bytes;
  var problems = [];
  var keys = opts.keys || [];

  var id = msgs.identify(bytes);
  var doc;
  if (!id) {
    // Not a Kerberos message. Show the ASN.1 structure rather than refusing: a
    // structural tree is far more useful than "could not parse", and it is how
    // a codec bug in THIS tool becomes visible.
    doc = {
      kind: "unrecognised",
      summary: "These bytes do not begin with a Kerberos [APPLICATION n] " +
          "tag. Showing their ASN.1 " +
               "structure instead.",
      sections: [],
      tree: null
    };
    try {
      doc.tree = asn1.tree(bytes);
    } catch (e) {
      doc.summary = "These bytes are neither a Kerberos message nor " +
          "parseable as ASN.1: " + e.message;
      problems.push(e.message);
    }
  } else {
    var n = id.applicationNumber;
    var A = msgs.APPLICATION;
    try {
      if (n === A.AS_REQ || n === A.TGS_REQ) {
        doc = await describeKdcReq(msgs.readKdcReq(bytes), parsed, keys, 
            problems);
      } else if (n === A.AS_REP || n === A.TGS_REP) {
        doc = await describeKdcRep(msgs.readKdcRep(bytes), keys, problems);
      } else if (n === A.AP_REQ) {
        doc = await describeApReq(msgs.readApReq(bytes), keys, problems);
      } else if (n === A.AP_REP) {
        doc = await describeApRep(msgs.readApRep(bytes), keys);
      } else if (n === A.KRB_ERROR) {
        doc = describeKrbError(msgs.readKrbError(bytes), problems);
      } else if (n === A.TICKET) {
        doc = {
          kind: "Ticket",
          summary: "A bare Ticket, outside any message",
          sections: [await describeTicket(msgs.readTicket(bytes), keys, 
              problems)]
        };
      } else if (n === A.KRB_CRED) {
        // Somebody has pasted a DELEGATED CREDENTIAL. Worth saying plainly what
        // that is, because it is the one structure here that is a capability
        // rather than a claim: a ticket-granting ticket someone handed to a
        // service so it could act as them.
        var cred = msgs.readKrbCred(bytes);
        doc = {
          kind: "KRB-CRED",
          summary: "A delegated credential carrying " + cred.tickets.length + 
              " forwarded " +
            "ticket(s) — unconstrained delegation",
          sections: [{
            title: "KRB-CRED",
            note: "This is how a client hands its own ticket-granting ticket " +
                "to a service so " +
                  "that the service can obtain tickets to ANYTHING as that " +
                      "client, for as long " +
                  "as the ticket lives, without the KDC being asked again. " +
                      "It normally travels " +
                  "inside an AP-REQ Authenticator's 0x8003 checksum rather " +
                      "than on its own.",
            rows: [
              row("pvno", cred.pvno),
              row("msg-type", cred.msgType + " (KRB-CRED)"),
              row("tickets", cred.tickets.map(function (t) {
                return principalOf(t.sname, t.realm);
              }).join("\n"), "each one's SESSION KEY is in the encrypted " +
                  "part below — a ticket " +
                "without its key is opaque, and that separation is what " +
                    "makes this safe to put " +
                "in a checksum field")
            ],
            sections: [describeEncryptedData(cred.encPart, "KRB-CRED " +
                "enc-part (EncKrbCredPart)")]
          }]
        };
        // The enc-part is at key usage 14 under the AP exchange's subkey, or
        // the ticket's session key when no subkey was sent — not under any
        // long-term key, so a reader usually cannot open it and saying which
        // key is needed is the useful part.
        var credAttempt = await tryDecrypt(cred.encPart, 
            kcrypto.KEY_USAGE.KRB_CRED_ENCPART, keys,
          "Encrypted at key usage 14 under the AP exchange's SUBKEY, or the " +
              "presented ticket's " +
          "session key when none was sent. Supply that to see the forwarded " +
              "ticket's own key.");
        if (credAttempt.ok) {
          try {
            var credPart = msgs.readEncKrbCredPart(credAttempt.plain);
            doc.sections[0].sections.push({
              title: "EncKrbCredPart (decrypted)",
              rows: [
                row("timestamp", timeOf(credPart.timestamp)),
                row("nonce", credPart.nonce),
                row("s-address", credPart.sAddress
                  ? "type " + credPart.sAddress.type + " " + 
                      prim.toHex(credPart.sAddress.address)
                  : null),
                row("r-address", credPart.rAddress
                  ? "type " + credPart.rAddress.type + " " + 
                      prim.toHex(credPart.rAddress.address)
                  : null)
              ],
              sections: credPart.ticketInfo.map(function (info, i) {
                return {
                  title: "Forwarded credential " + (i + 1),
                  rows: [
                    row("client", principalOf(info.pname, info.prealm)),
                    row("service", principalOf(info.sname, info.srealm)),
                    row("key", info.key.etypeName + ", " + hexOf(info.key.key),
                        "the forwarded ticket's session key — holding this " +
                            "and the ticket IS " +
                        "being that client"),
                    row("flags", info.flags ? 
                        msgs.ticketFlagNames(info.flags).join(", ") : null,
                        info.flags && 
                            
                                
                                    
                                        
                                            
                                                info.flags.indexOf(msgs.TICKET_FLAG.FORWARDED) !== -1
                          ? "flagged `forwarded`, which is the record a " +
                              "receiving service has " +
                            "that these credentials were handed over rather " +
                                "than presented by " +
                            "their owner"
                          : null),
                    row("authtime", timeOf(info.authtime)),
                    row("starttime", timeOf(info.starttime)),
                    row("endtime", timeOf(info.endtime)),
                    row("renew-till", timeOf(info.renewTill))
                  ]
                };
              })
            });
          } catch (e) {
            doc.sections[0].sections.push({
              title: "EncKrbCredPart",
              rows: [row("decrypted, but", e.message)]
            });
          }
        } else {
          doc.sections[0].sections[0].rows.push(
            row("decryption", "not attempted or not possible", 
                credAttempt.note));
        }
      } else if (n === A.AUTHENTICATOR) {
        var a = msgs.readAuthenticator(bytes);
        doc = {
          kind: "Authenticator",
          summary: "A decrypted Authenticator for " + 
              msgs.principalToString(a.cname, a.crealm),
          sections: [{
            title: "Authenticator",
            rows: [
              row("crealm", a.crealm), row("cname", principalOf(a.cname, 
                  a.crealm)),
              row("ctime", timeOf(a.ctime)), row("cusec", a.cusec),
              row("seq-number", a.seqNumber),
              row("cksum", a.cksum ? "type " + a.cksum.type + ", " + 
                  hexOf(a.cksum.checksum) : "(absent)")
            ]
          }]
        };
      } else if (n === A.ENC_TICKET_PART) {
        doc = {
          kind: "EncTicketPart",
          summary: "A decrypted EncTicketPart",
          sections: [await describeEncTicketPart(msgs.readEncTicketPart(bytes), 
              null,
            problems, keys)]
        };
      } else if (n === A.ENC_AS_REP_PART || n === A.ENC_TGS_REP_PART) {
        var p = msgs.readEncKdcRepPart(bytes);
        doc = {
          kind: p.taggedAs,
          summary: "A decrypted " + p.taggedAs + " for " + 
              msgs.principalToString(p.sname, p.srealm),
          sections: [{
            title: p.taggedAs,
            rows: [
              row("tagged as", p.taggedAs),
              row("key", p.key.etypeName + ", " + hexOf(p.key.key)),
              row("nonce", p.nonce),
              row("flags", msgs.ticketFlagNames(p.flags).join(", ") || 
                  "(none)"),
              row("authtime", timeOf(p.authtime)), row("endtime", 
                  timeOf(p.endtime)),
              row("srealm", p.srealm), row("sname", principalOf(p.sname, 
                  p.srealm))
            ]
          }]
        };
      } else {
        doc = {
          kind: id.name,
          summary: "A " + id.name + ". This build does not decode that " +
              "message yet; its ASN.1 " +
                   "structure is below.",
          sections: [],
          tree: asn1.tree(bytes)
        };
      }
    } catch (e) {
      // A message that identifies itself and then fails to parse is the most
      // interesting case there is: it is either malformed or this codec is
      // wrong. Both deserve the structure alongside the error.
      doc = {
        kind: id.name + " (does not parse)",
        summary: "These bytes announce themselves as a " + id.name + 
            " but do not parse: " + e.message,
        sections: [],
        tree: null
      };
      problems.push(e.message);
      try {
        doc.tree = asn1.tree(bytes);
      } catch (e2) {
        problems.push("The ASN.1 structure could not be shown either: " + 
            e2.message);
      }
    }
  }

  doc.input = {
    encoding: parsed.encoding,
    framing: parsed.framing,
    byteLength: bytes.length,
    hex: hexOf(bytes, 64)
  };
  doc.problems = (doc.problems || []).concat(problems);
  log.debug("Leaving describe(). kind=" + doc.kind + ", problems=" + 
      doc.problems.length);
  return doc;
}

// A key list from a password, for the AS-REP case where that is all a reader
// has. Every supported etype is derived, because the reader usually does not
// know which one the KDC chose — and the salt is the part they will get wrong,
// so it is a required argument rather than something guessed here.
async function keysFromPassword(password, salt, etypes) {
  log.debug("Entering keysFromPassword().");
  var out = [];
  var ids = etypes && etypes.length ? etypes : kcrypto.DEFAULT_ETYPE_PREFERENCE;
  for (var i = 0; i < ids.length; i++) {
    var e = kcrypto.etypeById(ids[i]);
    out.push({
      etype: e.id,
      key: await e.stringToKey(password, prim.utf8(salt || ""), null),
      label: "the password with salt " + JSON.stringify(salt || "") + " as " + 
          e.name
    });
  }
  log.debug("Leaving keysFromPassword().");
  return out;
}

module.exports = {
  describe: describe,
  parseInput: parseInput,
  keysFromPassword: keysFromPassword,
  // exposed for the tests, which check the formatting rules directly
  hexOf: hexOf,
  timeOf: timeOf,
  principalOf: principalOf
};
