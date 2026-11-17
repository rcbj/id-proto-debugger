#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# File: tests/tools/smartcard_capture.py
#
# ---------------------------------------------------------------------------
# Writes tests/smartcard_card_vectors.json: what a REAL YubiKey answers to
# the smart-card page's own read plans for PIV, the OpenPGP card and
# YubiHSM Auth, beside what Yubico's yubikit reads from the same
# key. tests/smartcard_engine.js decodes the bytes with this tree's
# decoders and holds them to those readings, so neither side of a check is
# this code (#410, item 6).
#
# The OpenPGP fingerprints on the card are left unwritten (yubikit, like
# the card, leaves that to the caller), so they read as zeros. GnuPG's own
# fingerprints are held by smartcard_engine.js's GPG_KEYS instead.
#
# IT IS DESTRUCTIVE. It resets the three applets, writes keys, a
# certificate and credentials, records, and resets the three applets
# again, leaving them at factory defaults. It refuses any key whose serial
# is not --serial.
#
# Not run by the suite and not needed by it: the JSON is committed. Run by
# hand with a key attached, under a yubikey-manager >= 5.8 (the system
# 4.x has no YubiHSM Auth):
#
#   python3 tests/tools/smartcard_capture.py --serial <serial> \
#       --out tests/smartcard_card_vectors.json
#
# The key's serial is replaced by 12345678 wherever it appears (GET
# SERIAL, the OpenPGP AID), as tests/smartcard_recorded.json
# does. PIV attestation is not captured: the serial is signed inside the
# attestation certificate, and a real attestation chain is already held
# by tests/smartcard_engine.js (piv-go's vector).
# ---------------------------------------------------------------------------
import argparse
import datetime
import json
import re
import subprocess
import sys

from cryptography.hazmat.primitives import serialization
from ykman.device import list_all_devices
from ykman.piv import generate_self_signed_certificate
import yubikit.core
import yubikit.hsmauth
import yubikit.openpgp
import yubikit.piv
from yubikit.core.smartcard import SmartCardConnection
from yubikit.hsmauth import HsmAuthSession
from yubikit.openpgp import KEY_REF, OID, OpenPgpSession
from yubikit.piv import (DEFAULT_MANAGEMENT_KEY, KEY_TYPE,
                         MANAGEMENT_KEY_TYPE, SLOT, PivSession)

SCRUBBED_SERIAL = 12345678
PIV_PIN = "123456"
PGP_ADMIN = "12345678"
HSM_MGMT = bytes(16)
# Fixed so a re-capture of the same setup names the same keys.
PGP_TIME = 1767225600  # 2026-01-01T00:00:00Z
CERT_FROM = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
CERT_TO = datetime.datetime(2036, 1, 1, tzinfo=datetime.timezone.utc)
CERT_SUBJECT = "CN=id-proto-debugger capture 9A"

PIV_AID = "a000000308"
PGP_AID = "d27600012401"
HSM_AID = "a000000527210701"


def log(msg):
    print("[capture] " + msg, file=sys.stderr)


def apdu(cla, ins, p1, p2, data=b"", le=None):
    out = bytes([cla, ins, p1, p2])
    if data:
        out += bytes([len(data)]) + data
    if le is not None:
        out += bytes([le & 0xff])
    return out


def transmit(conn, cmd):
    """What the api relay does: GET RESPONSE on 61xx, Le retry on 6Cxx."""
    data, sw = conn.send_and_receive(cmd)
    if (sw >> 8) == 0x6C:
        data, sw = conn.send_and_receive(cmd[:-1] + bytes([sw & 0xff]))
    body = bytes(data)
    while (sw >> 8) == 0x61:
        more, sw = conn.send_and_receive(apdu(0x00, 0xC0, 0, 0,
                                              le=sw & 0xff))
        body += bytes(more)
    return body, sw


def steps(conn, aid_hex, commands):
    out = []
    sel = apdu(0x00, 0xA4, 0x04, 0x00, bytes.fromhex(aid_hex))
    for label, cmd in commands:
        transmit(conn, sel)
        body, sw = transmit(conn, cmd)
        out.append({"label": label, "command": cmd.hex(),
                    "data": body.hex(), "status": "%04x" % sw})
    return out


def piv_get_data(tag_hex):
    tag = bytes.fromhex(tag_hex)
    return apdu(0x00, 0xCB, 0x3F, 0xFF, bytes([0x5C, len(tag)]) + tag,
                le=0)


def pgp_get_data(tag):
    return apdu(0x00, 0xCA, 0x00, tag, le=0)


def pgp_read_key(crt):
    return apdu(0x00, 0x47, 0x81, 0x00, bytes([crt, 0x00]), le=0)


def open_key(serial):
    for dev, info in list_all_devices():
        if info.serial == serial:
            return dev, info
    raise SystemExit("no YubiKey with serial %d attached" % serial)


def allow_development_firmware():
    """A preview key reports firmware 0.0.x, which yubikit's version gates
    read as older than every feature. Lift the gates for such a key only."""
    def ungated(*_args, **_kwargs):
        return None
    for mod in (yubikit.core, yubikit.piv, yubikit.openpgp,
                yubikit.hsmauth):
        if hasattr(mod, "require_version"):
            mod.require_version = ungated


def setup_piv(conn):
    s = PivSession(conn)
    s.reset()
    try:
        kind = s.get_management_key_metadata().key_type
    except Exception:
        kind = MANAGEMENT_KEY_TYPE.TDES
    s.authenticate(kind, DEFAULT_MANAGEMENT_KEY)
    s.verify_pin(PIV_PIN)
    pub = s.generate_key(SLOT.AUTHENTICATION, KEY_TYPE.ECCP256)
    cert = generate_self_signed_certificate(
        s, SLOT.AUTHENTICATION, pub, CERT_SUBJECT, CERT_FROM, CERT_TO)
    s.put_certificate(SLOT.AUTHENTICATION, cert)


def oracle_piv(conn):
    s = PivSession(conn)
    cert = s.get_certificate(SLOT.AUTHENTICATION)
    pub = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return {
        "version": "%d.%d.%d" % tuple(s.version),
        "certificate9a": {
            "der": cert.public_bytes(serialization.Encoding.DER).hex(),
            "subject": cert.subject.rfc4514_string(),
            "serialNumber": "%x" % cert.serial_number,
            "notBefore": cert.not_valid_before_utc.isoformat(),
            "notAfter": cert.not_valid_after_utc.isoformat(),
            "spki": pub.hex(),
        },
    }


def capture_piv(conn):
    plan = [
        ("Version (GET VERSION)", apdu(0x00, 0xFD, 0, 0, le=0)),
        ("Serial (GET SERIAL)", apdu(0x00, 0xF8, 0, 0, le=0)),
        ("CHUID", piv_get_data("5fc102")),
        ("Certificate, slot 9A (authentication)", piv_get_data("5fc105")),
        ("Certificate, slot 9C (signature)", piv_get_data("5fc10a")),
    ]
    return steps(conn, PIV_AID, plan)


def setup_pgp(conn):
    s = OpenPgpSession(conn)
    s.reset()
    s.verify_admin(PGP_ADMIN)
    for ref, curve in ((KEY_REF.SIG, OID.SECP256R1),
                       (KEY_REF.DEC, OID.X25519),
                       (KEY_REF.AUT, OID.Ed25519)):
        s.generate_ec_key(ref, curve)
        s.set_generation_time(ref, PGP_TIME)


def oracle_pgp_yubikit(conn):
    s = OpenPgpSession(conn)
    fps = s.get_fingerprints()
    times = s.get_generation_times()
    out = {"version": "%d.%d.%d" % tuple(s.version), "keys": {}}
    for name, ref in (("sig", KEY_REF.SIG), ("dec", KEY_REF.DEC),
                      ("aut", KEY_REF.AUT)):
        attrs = s.get_algorithm_attributes(ref)
        spki = s.get_public_key(ref).public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        out["keys"][name] = {
            "fingerprint": fps[ref].hex(),
            "generated": times[ref],
            "algorithm": str(getattr(attrs, "oid", attrs)),
            "spki": spki.hex(),
        }
    return out


def capture_pgp(conn):
    plan = [
        ("Application related data", pgp_get_data(0x6E)),
        ("Cardholder related data", pgp_get_data(0x65)),
        ("Security support template", pgp_get_data(0x7A)),
        ("Signature key", pgp_read_key(0xB6)),
        ("Decryption key", pgp_read_key(0xB8)),
        ("Authentication key", pgp_read_key(0xA4)),
    ]
    return steps(conn, PGP_AID, plan)


HSM_LABELS = ("debugger-derived", "debugger-ec-touch")


def setup_hsm(conn):
    s = HsmAuthSession(conn)
    s.reset()
    s.put_credential_derived(HSM_MGMT, HSM_LABELS[0], "derivation-pass",
                             "cred-pass")
    s.generate_credential_asymmetric(HSM_MGMT, HSM_LABELS[1], "cred-pass",
                                     touch_required=True)


def oracle_hsm(conn):
    s = HsmAuthSession(conn)
    creds = []
    for c in s.list_credentials():
        creds.append({"label": c.label, "algorithm": c.algorithm.name,
                      "touchRequired": bool(c.touch_required),
                      "counter": c.counter})
    return {"version": "%d.%d.%d" % tuple(s.version),
            "credentials": sorted(creds, key=lambda c: c["label"])}


def capture_hsm(conn):
    plan = [
        ("Version", apdu(0x00, 0x07, 0, 0, le=0)),
        ("Credentials (LIST)", apdu(0x00, 0x05, 0, 0, le=0)),
    ]
    return steps(conn, HSM_AID, plan)


def reset_all(conn):
    PivSession(conn).reset()
    OpenPgpSession(conn).reset()
    HsmAuthSession(conn).reset()


def scrub(obj, serial):
    """Replace the serial in every encoding it is seen in here."""
    text = json.dumps(obj)
    dec = str(serial)
    hex4 = "%08x" % serial
    bcd = "%08d" % serial
    for old, new in ((hex4, "%08x" % SCRUBBED_SERIAL),
                     (bcd, "%08d" % SCRUBBED_SERIAL),
                     (dec, str(SCRUBBED_SERIAL))):
        text = text.replace(old, new)
    return json.loads(text)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--serial", type=int, required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    dev, info = open_key(args.serial)
    if tuple(info.version)[:2] == (0, 0):
        log("development firmware %s: lifting yubikit's version gates" %
            (info.version,))
        allow_development_firmware()
    subprocess.run(["gpgconf", "--kill", "scdaemon"], check=False)
    out = {"captured": datetime.date.today().isoformat(),
           "note": "Real YubiKey answers to smartcard.js's read plans; "
                   "written by tests/tools/smartcard_capture.py. "
                   "Serial replaced by %d." % SCRUBBED_SERIAL}
    try:
        with dev.open_connection(SmartCardConnection) as conn:
            log("setting up PIV, OpenPGP, YubiHSM Auth")
            setup_piv(conn)
            setup_pgp(conn)
            setup_hsm(conn)
            out["piv"] = {"steps": capture_piv(conn),
                          "yubikit": oracle_piv(conn)}
            out["pgp"] = {"steps": capture_pgp(conn),
                          "yubikit": oracle_pgp_yubikit(conn)}
            out["hsm"] = {"steps": capture_hsm(conn),
                          "yubikit": oracle_hsm(conn)}
    finally:
        with dev.open_connection(SmartCardConnection) as conn:
            log("resetting PIV, OpenPGP, YubiHSM Auth to factory defaults")
            reset_all(conn)
    out = scrub(out, args.serial)
    if re.search(str(args.serial), json.dumps(out)):
        raise SystemExit("serial survived the scrub; not writing")
    with open(args.out, "w") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    log("wrote " + args.out)


if __name__ == "__main__":
    main()
