# Smart cards — ISO 7816, and what a browser can already read

Issue #217 asks for the applications a security key exposes besides
WebAuthn. FIDO2 and FIDO U2F are the WebAuthn workflow:
`webauthn.html` (the Lab), `webauthn_analyzer.html` (the Analyzer) and
the read-only extension. `docs/webauthn.md` records why that workflow
sees a ceremony's artifacts and never the authenticator. There is no
CTAP, no USB frame and no PIN protocol there, and this tree does not
grow a second one. A CTAP debugger needs native HID access.

The rest of #217 is Yubico OTP, OATH, PIV, the OpenPGP card and
YubiHSM Auth. USB and NFC are transports. A keyboard-typed OTP and an
NFC tap that types the same OTP are one token. A CCID reader, on
either transport, presents the same APDUs. One payload, read once.

## The boundary

PIV, the OpenPGP card, the on-key OATH applet and YubiHSM Auth speak
ISO 7816 APDUs over CCID. A browser cannot open CCID: WebUSB refuses
the smart-card class, and Firefox has no WebHID. `client/src/iso7816.js`
reads and writes bytes somebody already has — a paste, or a trace a
reader captured somewhere else. It performs no card operation. It is
the only TLV reader those four applications call, so a length means
one thing in all of them.

Two further applications need no reader at all, and neither lives in
this module. Yubico OTP arrives as keystrokes. HOTP and TOTP can be
computed from a pasted secret. The secret on a key's OATH applet does
not come back out, and neither does an OTP AES key, a PIN, a private
key or a biometric. A signature or a decrypted blob is the result of
an operation the key performed.

YubiHSM Auth is the YubiKey applet that authenticates to a YubiHSM 2.
This work decodes that applet. A session to an HSM is a different
project, and so is OpenPGP message format, PKCS#11 and GPG-agent.

The page is `client/public/smartcard.html`. The hosted sites keep
the decode half the way the PKI page keeps its offline half:
verifying an OTP, and talking to a reader, need the api.
`client/static_site.js` does not drop the page. The api image
installs `libpcsclite1` and builds the `pcsclite` module (an optional
dependency, so a host `npm install` without PC/SC headers skips it).
`POST /smartcard/transmit` loads the module only when a request asks,
and a missing module is a limit the page shows. The reader relay is
**off** unless the api's env sets `smartcardReaderEnabled: true` (see
[Reader](#reader)).

## Browser or API

The page asks once, at the top, how to reach a key: **this browser** or
**the API**. It is remembered in the browser, and defaults to the browser
where WebHID exists and to the API where it does not (Firefox).

* **This browser** reaches what a page can: the typed OTP in any
  browser, and OTP-slot challenge-response over WebHID in Chrome or
  Edge. No browser opens CCID — WebUSB refuses the smart-card class,
  and Chrome's Web Smart Card API is offered only to installed isolated
  web apps — so PIV, OATH, the OpenPGP card and YubiHSM Auth say so and
  point at the API rather than doing nothing.
* **The API** sends everything through the reader relay, which uses the
  OS's own PC/SC: pcsc-lite on Linux, the PCSC framework on macOS,
  WinSCard on Windows (the `pcsclite` module binds to each). Every
  application, any browser.

**Read from the key**, on each of the OATH, PIV, OpenPGP and YubiHSM
Auth panes, sends a fixed read plan through the relay and decodes every
answer with the pane's own decoder: OATH's LIST and CALCULATE ALL;
PIV's version, serial, CHUID, discovery object, the four certificates,
the F9 attestation certificate and ATTEST of 9A; OpenPGP's application,
cardholder and security data and its three public keys (GENERATE
ASYMMETRIC KEY PAIR with P1=81, which reads); YubiHSM Auth's version
and credential list. Each read is its own short sequence beginning with
SELECT, because the relay stops a sequence at a status that is not
`90xx`/`61xx` and an empty PIV slot answers 6A82. **Every command only
reads** — no VERIFY, no PIN, no password, nothing written — and
`tests/smartcard_engine.js` holds every plan to a list of read
instructions. Against a YubiKey (the 2026 PIV ML preview) on
2026-11-13 every plan ran; its F9 attestation certificate is 7,448
bytes, signed with ML-DSA-87 by "Yubico 2026 PIV ML Preview CA", and the
PKI code describes it.

## Running the API natively

A container on Linux reaches the host's pcscd through its socket
(`docker-compose-smartcard.yml`). On macOS and Windows a container
cannot reach the host's smart-card service at all, so the api runs as an
ordinary process:

```
cd api && npm install && cd ..
node api/native.js --smartcard
```

`api/native.js` uses only node's own modules and does what the image
does at build time: it makes `CONFIG_FILE` absolute and sets `NODE_PATH`
to `api/node_modules` (so `common/data.js` and `common/xmldsig.js`, which
`server.js` loads from `../common` in a checkout, find their packages),
makes the stack's TLS pair with `common/generate_tls_cert.js` when
`generated-tls/` has none (it needs `npm ci --prefix client`), and with
`--smartcard` turns the relay on and checks `pcsclite` loads, naming
what this OS needs when it does not:

| OS | PC/SC | To build the binding |
|---|---|---|
| Linux | `pcscd` running | `libpcsclite-dev`, python3, make, g++ |
| macOS | built in (CryptoTokenKit) | Xcode command line tools |
| Windows | built in (Smart Card service) | Visual Studio Build Tools (C++), Python 3 |

Run the client and the rest from compose without the api, which would
hold port 4000: `docker-compose up client sts`. Verified on Linux
(Ubuntu 26.04, a YubiKey, the host's pcscd); macOS and Windows are the
same code against their own PC/SC and have not been run here.

Each relay call opens a PC/SC context and closes it, readers first:
pcsclite gives every reader object its own monitoring thread, and
closing only the context left one behind per listing and one or two per
transmit (52 threads after forty calls) until 2026-11-13.

## Which browser does what

| Feature | Chrome / Edge | Firefox |
|---|---|---|
| Keyboard OTP: decode, verify with YubiCloud (api) | yes | yes |
| HOTP / TOTP calculator, every decoder | yes | yes |
| OTP-slot challenge-response | WebHID, or through the API | through the API: HID (native api), or CCID for a key on NFC |
| Read from the key (OATH, PIV, OpenPGP, YubiHSM Auth) | through the relay | through the relay |
| Reader: list readers, transmit APDUs | through the relay | through the relay |

Firefox has no WebHID and no browser opens CCID, so everything that
touches a key and is not a keystroke goes through the api's relay, in
every browser. On a local stack that is one extra compose file:

```
CONFIG_FILE=./env/local.js docker-compose -f docker-compose.yml \
  -f docker-compose-smartcard.yml up
```

which mounts the host's `/run/pcscd` into the api (the container runs
no pcscd and needs no USB device) and sets
`SMARTCARD_READER_ENABLED=true`, which `api/env/local.js` turns into
`smartcardReaderEnabled`. The host needs pcscd running, and GnuPG's
`scdaemon`, if it holds the key, has to let go: `gpgconf --kill
scdaemon`. A plain `docker-compose up` keeps the relay off.

## The codec

`parseCommand` and `encodeCommand` cover the cases ISO 7816-4
defines.

| Case | Wire | What the fifth byte is |
|---|---|---|
| 1 | 4 bytes | absent. There is no extended case 1 |
| 2S | 5 bytes | Le. `00` means 256 |
| 3S | 5 + Lc | Lc, then that many data bytes |
| 4S | 6 + Lc | Lc and data, then one Le byte |
| 2E | 7 bytes | `00`, then a two-byte Le. `0000` means 65536 |
| 3E | 7 + Lc | `00`, a two-byte Lc, then data |
| 4E | 9 + Lc | the case 3E body, then a two-byte Le |

Le comes back as a count of bytes. An absent Le is `null`. A body
longer than 255 bytes, or an Le above 256, is written in the extended
form even when the caller did not ask. An extended Lc of zero is
refused: that shape is case 2E, which is seven bytes and carries no
Lc.

`parseResponse` splits the body from the last two bytes and names the
words these cards return:

| Word | Name |
|---|---|
| `9000` | success |
| `61xx` | more data available. `remaining` is the byte `xx` |
| `6982` | security status not satisfied |
| `6985` | conditions of use not satisfied |
| `6A80` | incorrect parameters in the data field |
| `6A82` | file or application not found |
| `6A86` | incorrect parameters P1-P2 |
| `6A88` | referenced data not found |
| `6300` | verification failed |
| `63Cx` | verification failed, and the low nibble is the tries left |

Any other word is shown as four hex digits. `6983` is the usual next
word after `63Cx` reaches zero, and it is left as `6983` so a later
name is a decision rather than a guess that landed in a label.
`61xx` keeps `xx` as the card sent it. A short Le uses `00` to mean
256; that rule belongs to Le, and applying it here would hide a zero.

`parseTlv` and `encodeTlv` are BER-TLV. Bit 6 of the first tag byte
marks a constructed value, which is parsed one level down, to eight
levels. A one-byte tag whose low five bits are `1f` is refused on
write: that byte announces a long-form tag and the continuation is
missing. Multi-byte tags are passed as their bytes. A number above
255 is refused, because encoding it back would have to guess how many
continuation bytes the card used.

Indefinite length (a length byte of `80`) is refused by name. These
cards use definite lengths, and absorbing an indefinite one would
hide a truncated object. A length that runs past the buffer is an
error that names the tag. The value is not sliced short and returned
as a success. A long form of a short value is accepted on read —
cards do write that — and written back in the short form.

The input is untrusted. The buffer is capped at 256 KiB, and a
declared length is checked against the bytes still remaining before
it is believed. `walk()`, the recursive reader, does not log: one
certificate is dozens of tags, and a line on each of them is the
whole log. `parseTlv()` is the entry point. `readElements()`, which
`walk()` calls, does not log either.

`parseElements()` stops after one level. PIV's certificate tag is
`70`, the OATH and YubiHSM Auth tags are `71` through `7D`, and an
OpenPGP URL is `5F50`. Bit 6 is set on those tags and the value is
not child TLV, so `parseTlv()` would descend into it and refuse the
buffer. The applet codecs call `parseElements()`. OpenPGP then
descends only into the tags whose value is itself TLV: `6E`, `65`,
`73`, `7F49`, `7F48`, `B6`, `B8` and `A4`.

`tests/smartcard_engine.js` drives the module in node. No browser, no
reader, no service.

## Yubico OTP

A current token is 44 modhex characters: twelve of public identity
and 32 of ciphertext. An older token is 32 to 48 characters, even,
and 32 characters is the ciphertext alone, which is the shape of
Yubico's published vectors. The alphabet is `cbdefghijklnrtuv`.
AES-128-ECB with no padding recovers a 16-byte block. The CRC-16
residual of a genuine block is `0xf0b8`. A wrong key fails that
check and is reported as a wrong key.

The validation request is protocol 2.0. The page signs it. The
signature is HMAC-SHA1 over the parameters sorted by name, joined
with `&`, excluding `h`. The query string is the same fields
percent-encoded, including `h`. The API key stays in the browser.
`POST /otp/verify` checks the shape and sends it to the verifier as
an HTTP GET with those fields as the query string, which is what
Validation Protocol 2.0 specifies. A `status=BAD_OTP` answer is a
200, because that answer is the point.

The page checks the answer the way the protocol tells a client to:
the response `nonce` and `otp` must be the ones the request sent, and
with an API key the response `h` must verify. A signed answer for a
different OTP is refused. An error status that omits `otp` is shown
as "not echoed"; an `OK` without the request's `otp` is refused.
The five default hosts are `api.yubico.com` through `api5.yubico.com`,
path `/wsapi/2.0/verify`; server 1, `api.yubico.com`, is the default.
All five answered an unsigned verify with HTTP 200 on 2026-11-13, and
each still resolves to its own `apiN.yubicloud-r53.yubico.com` name. A caller-supplied verifier is https, with
no userinfo, no query string and no `..` in the URL. The address
policy is the one already installed on axios.

The AES key and the API key are saved only when that field's box is
checked. Clearing the box removes the stored value. A missing box
does not save.

Challenge-response over WebHID uses the frame in `yubico_otp.js`: 64
bytes of payload, the slot, the CRC of the payload, three zero bytes.
Reports are eight bytes, seven of payload and a sequence byte. An
all-zero report is skipped except the first and the last. Slots
`0x20` and `0x28` are Yubico OTP challenge-response (6-byte challenge,
16-byte answer) and `0x30` and `0x38` are HMAC-SHA1 (up to 64 bytes,
20-byte answer).

An HMAC slot is programmed **variable** or **fixed**, and the page
asks which (*HMAC challenge length*; variable is the default because
it is what `ykman otp chalresp` programs). A variable slot
(`HMAC_LT64`) drops every trailing byte equal to the payload's last
byte before it computes, so the page pads the way yubikit's
`calculate_hmac_sha1` does: with `01` after a challenge ending in
`00`, and with `00` otherwise, and the key strips exactly that
padding. A variable slot therefore cannot take a 64-byte challenge
whose last bytes repeat. A fixed slot HMACs all 64 bytes, so a
shorter challenge is zero filled and the answer is the HMAC of that
64-byte block. Pick the wrong mode and the key answers with a valid
CRC and an HMAC of a different message. `hmacChallengeBytes()` gives
the message a slot actually signs, for checking an answer against a
known key.

The exchange is the one yubikit's `otp.py` runs, and a single read
straight after the write does not work. The last byte of every
feature report is a status: before each write the page polls until
`SLOT_WRITE` (`0x80`) is clear; after the frame it polls while the
key is busy (20 ms) or waiting for a touch (`0x20`, 100 ms, and the
status line says "Touch the key"), collects each report flagged
`RESP_PENDING` (`0x40`) in sequence-number order, stops at the
report whose sequence is back to 0, and writes the reset report
(`ff…8f`). The answer is the response bytes plus a CRC whose
residual is `0xf0b8`; a bad CRC is refused. A plain status report
with no data means the slot is not configured for challenge-response.
The page gives up after 15 seconds.

The device the page asks for is the key's OTP interface, which is a HID
KEYBOARD (usage page `0x01`, usage `0x06`): WebHID blocks a keyboard's
input and output reports and allows its feature reports, which are all
this exchange uses. Until 2026-11-13 the filter named usage page
`0xF1D0`, the FIDO interface, which Chrome blocks from WebHID outright,
so no key was ever offered and the button did nothing.

**Through the API** — the default in a browser with no `navigator.hid` —
the api asks the key over **HID** itself (`api/otp_hid.js`,
`POST /smartcard/otp/challenge`), because **a YubiKey on USB answers
challenge-response only on HID**: over USB CCID the CALCULATE below is
refused with 6985, by yubikit's own `calculate_hmac_sha1` as much as by
this tree (checked against a YubiKey 5 on 2026-11-13, with slot 2 a
valid HMAC-SHA1 slot that answered correctly over HID). The api uses the
optional `node-hid` module (hidapi: hidraw on Linux, IOKit on macOS, HID
on Windows), finds the key's OTP interface by usage page 1 / usage 6
(interface 0 where hidapi reports no usages), and runs
`yubico_otp.hidChallenge()` — the same exchange the page runs over
WebHID, moved into that DOM-free module so the two cannot drift. It needs
a **native** api (`node api/native.js --smartcard`): in a container the
hidraw node is neither present nor permitted to the container's user,
and `yubico_otp.js` needs the client's packages. Through the API on a key
answered `2a26efef…` for slot 2 and challenge `0102030405`, which is
HMAC-SHA1 of it.

When HID is not there (a container, or a key on an NFC reader) the page
falls back to **CCID**: SELECT of the OTP application (`A0 00 00 05 27 20
01 01`), then CALCULATE (`00 01 <slot> 00 40` and the same 64-byte
payload the HID frame carries, padded the same way). That is how the
slots answer over **NFC**; over USB it is the 6985 above. The answer is
bare, with no CRC: 20 bytes for an HMAC-SHA1 slot, 16 for an OTP slot.

`tests/smartcard_engine.js` drives `hidChallenge()` against a scripted
key — through the page's wrapper and through `otp_hid.js` behind a fake
`node-hid` whose reads carry hidapi's report-ID byte — so the exchange
itself is tested without hardware; a real key is still the check of the
transport.

## OATH

HOTP is RFC 4226 and TOTP is RFC 6238, six, seven or eight digits,
SHA-1, SHA-256 or SHA-512. The calculator's default on the page is
six digits. The engine's TOTP default is eight, which is the RFC
appendix. The secret is saved only when the box is checked.

YKOATH's AID is `A0000005272101`. PUT builds an APDU and does not
send it. The secret in that APDU is described as a length, not
shown, and a secret shorter than 14 bytes is padded with zeros to
14, as yubikit does (the applet refuses a shorter key, and HMAC pads
with zeros anyway, so the codes do not change). The property element
is the one exception to TLV in YKOATH: tag `78` and ONE value byte
with no length (`01` only-increasing, `02` touch). LIST, CALCULATE,
CALCULATE ALL and RESET are decoded from a paste. A truncated
CALCULATE answer (`76`) is the digit count and four bytes, and the
code is those bytes with the top bit masked. A full one (`75`) is the
digit count and the whole HMAC (20, 32 or 64 bytes), and the code is
its RFC 4226 dynamic truncation; the engine test checks it against
the RFC 4226 Appendix D HMACs and RFC 6238 Appendix B. CALCULATE ALL
is name (`71`) and answer pairs, where the answer is `75` or `76` as
above, `77` for an HOTP credential and `7C` for one that needs a
touch. Neither of those last two is calculated; they carry the digit
count alone. YKOATH continues a long answer
with SEND REMAINING (`A5`), not GET RESPONSE; see [Reader](#reader).

## PIV

NIST SP 800-73-4, plus the Yubico instructions GET METADATA, GET
SERIAL, GET VERSION and ATTEST. The AID is `A00000030800001000`, and
a SELECT of the shorter `A000000308` prefix is still the PIV
application. A certificate is tag `70` inside tag `53`, with tag `71`
as CertInfo. The low bit of CertInfo means gzip. A gzip header with
no CertInfo is still gzip. The page inflates with
`DecompressionStream` and hands the DER to
`x509.describeCertificate`. This module does not parse a certificate
itself. GENERAL AUTHENTICATE is decoded and not performed, including
the `85` exponentiation element of an ECDH. VERIFY is described as a
PIN of N bytes, not shown, and its P2 is named as a PIN reference
(`80` application PIN, `81` PUK, `00` global PIN) rather than as a
key slot. The page's *Build VERIFY* writes the application PIN the
way SP 800-73-4 Part 2 section 3.2.1 requires: 6 to 8 characters,
padded with `FF` to 8 bytes. An unpadded PIN is a different value and
the card counts it as a wrong one. The PIN is not stored. GET
METADATA's origin is `01` generated and `02` imported (yubikit's
`ORIGIN_GENERATED`/`ORIGIN_IMPORTED`), and its retries element is
the total then the remaining count.

Object `5FFF01` is Yubico's: the attestation certificate for the key
in slot `F9`, factory-loaded and signed by a Yubico PIV CA. ATTEST
(`F9`) returns a certificate for one slot's key, signed by that F9
key. Both are read like any other certificate, and the Yubico
extensions under `1.3.6.1.4.1.41482.3` are named, as
developers.yubico.com/PIV/Introduction/PIV_attestation.html defines
them: `3.3` firmware (three bytes), `3.7` serial (a DER INTEGER),
`3.8` PIN then touch policy, `3.9` form factor (high bit set for a
FIPS device), and `3.10`/`3.11` FIPS and CSPN certified. The device
certificate in `5FFF01` usually carries only `3.3`. The engine test
uses a real pair from go-piv's `TestVerify` (firmware 5.4.3, serial
15732500, PIN once, touch never, USB-C nano) rather than a
certificate this code made.

## OpenPGP card

Application related data and the public keys, from the OpenPGP card
3.4 data objects. Algorithm attributes for an EC key (`C1`-`C3`) are
the algorithm ID followed by the curve OID's content octets with no
tag and no length byte (section 4.4.3.9), and an optional trailing
`FF` import-format byte. The signature counter `93` is found inside
the security support template `7A`.
RSA, NIST curves, Ed25519 and X25519 public keys
become a SubjectPublicKeyInfo, and the page asks
`key_material.describePublicPem` what it imported. There is no
OpenPGP message, no PKCS#11 and no GPG-agent. PSO:CDS, PSO:DECIPHER
and INTERNAL AUTHENTICATE are decoded and not performed.

## YubiHSM Auth

The applet that authenticates to a YubiHSM 2. The AID is
`A000000527210701`. Algorithms 38 and 39 are AES-128 and EC P-256
Yubico authentication, the numbers yubikit 5.8.0 uses. A LIST entry
is the algorithm, the touch byte, the label and a one-byte counter.
CALCULATE's response is 48 bytes: `key_senc`, `key_smac`,
`key_srmac`. The page says those are what a host would hand to a
YubiHSM 2. It does not open an HSM session. A password derives the
two AES keys with PBKDF2-HMAC-SHA256, salt `Yubico`, 10000 rounds.
The management key and the credential password are not saved and are
not logged.

Most of the PIV, OATH, OpenPGP and YubiHSM traces in
`tests/smartcard_engine.js` are containers this code built. The
exceptions are the attestation certificates (go-piv's real pair),
the OpenPGP algorithm attributes (the bytes gpg writes), and the
OATH CALCULATE answers (RFC 4226 and RFC 6238 values in the YKOATH
grammar). The OTP
vectors are Yubico's published ones. The OATH codes are the RFC
appendices. A capture from a key is the manual list below, which CI
does not run.

## Reader

The reader is the machine the api runs on. A name that is a URL, a
host and port, a filesystem path, empty, longer than 256 characters
or full of control characters is refused. The usual
`Yubico YubiKey OTP+FIDO+CCID 00 00` is a name and is accepted.

**The relay is off by default.** `GET /smartcard/readers` and
`POST /smartcard/transmit` answer 403 unless the api's env file sets
`smartcardReaderEnabled: true` (the boolean; `"true"` does not
count). Anything that reaches the api can otherwise send any APDU to
a card on that machine: a few wrong-PIN VERIFYs block a PIN, and PIV
and OpenPGP both have reset and terminate commands.
`GET /smartcard/limits` reports `enabled`, and the page hides the
reader buttons and says why when it is false.

One call lists readers. A transmit is a **sequence** of up to 16
APDUs (`apdus`, one per line on the page; a single `apdu` still
works), run in order on ONE PC/SC connection, so SELECT then GET
DATA or VERIFY then a signature keeps its selected applet and
security state. A sequence of more than one APDU connects
`SCARD_SHARE_EXCLUSIVE`, so another process (`scdaemon`, say) cannot
interleave; if one holds the reader the connect fails and says so. A
sequence stops at the first APDU whose final status is not `90xx` or
`61xx`, because the next command usually depends on it.

With `getResponse` on (the default, a checkbox on the page) a `61xx`
answer is followed by GET RESPONSE (`CLA C0 00 00 xx`, keeping the
command's logical channel in either CLA range) until the card stops
asking. YKOATH does not implement `C0` and asks for SEND REMAINING
(`A5`) instead, so after a SELECT of the OATH AID in the same
sequence the relay sends `A5`; a transmit that relies on an OATH
SELECT made earlier passes `remainingIns: "a5"`. A `6Cxx`
is resent once with the Le the card named, as ISO 7816-4 section
5.1.3 describes; the data is the concatenation. Every APDU actually
on the wire is in `steps`, and the page shows them. Off, the answer
is the raw exchange.

A failed connect reports pcsclite's own text (`SCardConnect error:
Card is unpowered.(0x80100067)`, a sharing violation, no card)
after the reader's name, because that text is the diagnosis.

A card status word is a 200. A missing library, a missing reader,
no card, or a sequence that has not finished in 60 seconds (a touch
nobody gave, a wedged reader) is a 502. A bad request is a 400. The APDU is not logged.
A container sees a host key through the host's pcscd socket, which
`docker-compose-smartcard.yml` mounts; pcsc-lite 2.4 in the api image
was checked against a host pcscd 1.9.5 with a YubiKey 5 on 2026-11-13.
No test launcher starts a reader: the containerized test stack keeps
the relay off, and `tests/api_otp_smartcard.js` asserts it.

## What to check with a key

CI does not run this.

1. Touch the key so it types an OTP. The public identity matches
   `ykman`. With the AES key, a second touch advances the counter.
2. Verify that OTP against YubiCloud through the api, from a local
   stack.
3. Paste a PIV authentication certificate from
   `ykman piv certificates export`. The description matches
   `openssl x509`.
4. Paste an OATH LIST trace. The names match
   `ykman oath accounts list`.
5. Paste OpenPGP algorithm attributes and fingerprints. The
   fingerprints match `gpg --card-status`.
