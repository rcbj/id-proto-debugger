# PKI — a certificate authority, X.509v3, and a real TLS handshake

Scope: `client/public/pki.html` and its bundle, `client/src/x509.js`,
`client/src/key_material.js`, `client/src/pki_store.js`,
`client/src/pki_history.js`, `api/tls_probe.js` and the two endpoints it sits
behind. Cross-cutting matters — the logging convention, the 80-column rule, the
key-material opt-out rule, how the suite is run — stay in the repo-root
`CLAUDE.md`.

Read this before touching any of those files. Almost everything in it is a
defect that produced bytes which parse perfectly and are then refused by
something else, with an error message naming the wrong thing.

## What it is

One page that builds a certificate authority — **Root**, **Intermediate**,
**Issuing** — and issues the leaf certificates any of them can sign, with every
X.509v3 extension editable including its critical flag. Then it makes a real
TLS or mutual-TLS connection with what it issued, which is the only way to find
out whether any of it works.

The split across files is not arbitrary, and it is what makes the claim "every
combination" testable:

| File | Holds | Has a DOM? |
|---|---|---|
| `client/src/key_material.js` | key pairs, PEM↔JWK, PEM/DER/JWK/PKCS#12 export | no |
| `client/src/x509.js` | profiles, extensions, issuing, describing, chain checks | no |
| `client/src/pki_store.js` | the keys and certificates kept for reuse | no (localStorage only) |
| `client/src/pki_history.js` | the Operations History, over `op_history.js` | no |
| `client/src/pki.js` | the page: the form, the tables, the buttons | all of it |
| `api/tls_probe.js` | the TLS / mutual-TLS connection | n/a |

So `tests/pki_x509.js` drives ~240 certificates through the real encoder in node
and hands every one of them to **OpenSSL**, and `tests/pki_page.js` is left with
only the page.

## The key-pair pane is jwt_tools' pane

`client/src/key_material.js` is not new code. It is the bottom third of
`client/src/jwt_tools.js`, extracted: the algorithm table, generation, the
PEM/JWK conversion behind the format toggle, PBES2-encrypted PKCS#8, PKCS#12,
and the PBES2 JWE that password-protects a JWK set. `jwt_tools.js` is now a
**caller** of it — the page lost 340 lines and gained nothing — and the two
panes are identical rather than similar.

Two things came out of that extraction that are worth knowing:

* **`exportKeyPair()` returns the files rather than downloading them.** A
  keystore is a wire format that somebody else's tool has to read, so "the
  button said Downloaded" is a check on nothing. Returning `{name, data, mime}`
  is what lets `tests/pki_key_formats.js` produce all 49 cells of the matrix and
  read them back with `openssl pkcs12 -in`, `openssl pkey -in` and friends.
* **PKCS#12 for Ed25519 works, and the refusal that used to be there was
  misattributed.** PKCS#12 carries an Ed25519 key perfectly well — OpenSSL reads
  both bags. What failed was building the self-signed certificate the keystore
  has to wrap it in, because **pkijs cannot import an Ed25519 public key**. The
  certificate is `x509.js`'s job now, so the format works and the refusal is
  gone.

## Four things about certificates that are wrong and self-consistent

Each of these produces a certificate that parses, that `openssl x509 -text`
displays plausibly, and that something else then refuses. Each was real. All
four are why `tests/pki_x509.js` asserts by asking **OpenSSL** what it reads
rather than by reading back what this codebase just wrote.

**1. pkijs builds a Name as one multi-valued RDN.** A `Name` is an
`RDNSequence` — a SEQUENCE of SETs, one per attribute. `pkijs`'s
`RelativeDistinguishedNames.toSchema()` emits a single SET holding all of them,
which OpenSSL renders as `CN = host + O = Example + C = US`; the `+` is the tell.
It parses. It is simply a different name, so nothing chains to it. `buildDn()`
therefore builds the DER itself and hands it to pkijs as a parsed schema, which
`toSchema()` then returns verbatim.

**2. pkijs wraps an otherName in a second `[0]`.** GeneralName's otherName is
`[0] IMPLICIT OtherName`, so the tag *replaces* the SEQUENCE tag and the OID and
the `[0] EXPLICIT` value sit directly inside it. `pkijs.GeneralName`'s `toSchema()`
for type 0 wraps whatever it is given in a further `[0]`. `openssl x509 -text`
prints the name quite happily; `openssl verify` refuses the whole certificate
with:

```
error:0580009E:x509 certificate routines:ossl_x509v3_cache_extensions:reason(158)
```

which names no extension, no name and no field. `otherNameGeneralName()` builds
that DER by hand and returns a duck-typed object with the `toSchema()` its
callers use, and `buildAltName()` emits the `GeneralNames` SEQUENCE itself so
the hand-built name is accepted alongside the pkijs ones.

**3. The hash a signing key is IMPORTED with is the hash that lands in the
certificate.** pkijs reads `privateKey.algorithm` to build the
`signatureAlgorithm` field, so importing an RSA key as SHA-256 and then asking
`sign()` for SHA-512 produces a certificate whose declared algorithm and actual
signature disagree. `signerDescriptor()` derives the import parameters from the
**signature algorithm chosen**, never from the key. `openssl verify` is what
catches getting this wrong, and it reports it as a bad signature — naming no
hash.

**4. A date at or after 2050 must be a GeneralizedTime.** RFC 5280 §4.1.2.5.
pkijs picks UTCTime by default, and a 2050+ UTCTime is read as **1950** — a
certificate that expired seventy years ago, reported by every validator as
expired and by none as misencoded. `issueCertificate()` switches the type at the
boundary. A twenty-year root issued in 2031 crosses it.

And a fifth, which is not pkijs's fault: **an IP name constraint is the address
followed by its mask** — eight bytes for IPv4, not four. It is the one place a
general name's `iPAddress` is not just an address, and encoding it as one
produces a constraint that constrains nothing while looking correct in every
dump. `ipConstraintBytes()` does it; `nameConstraintsAreEnforcedByOpenssl()`
proves it by having OpenSSL **refuse** a name outside the permitted subtree.

## Ed25519 is signed by hand

`pkijs` cannot import an Ed25519 public key (`subjectPublicKeyInfo.importKey()`
throws *"Error during exporting public key: Incorrect key data"*) and cannot
sign with one. Both are avoidable:

* an SPKI **is** the exact DER that field holds, so it is parsed in with
  `fromSchema()` for **every** algorithm rather than only for the one that needs
  it. One path, so the odd one out is not the untested one.
* signing sets both AlgorithmIdentifiers to `1.3.101.112`, encodes the TBS,
  signs it with Web Crypto and drops the result in as the BIT STRING.
  `verifySignature()` has the mirror image, because `cert.verify()` has the same
  gap.

OpenSSL verifies the result, and `tests/pki_x509.js` issues a whole chain
through it.

## The store, and the private-key opt-out

`pki_store.js` keeps every object under one localStorage key as a JSON array —
one key rather than one per object, because the order is the hierarchy's order
and a store spread over *n* keys has no order at all.

The repository's standing rule is that key material stays out of localStorage,
with an opt-out on every protocol that generates a key pair. Here it is applied
**the way the SD-JWT VC workflow applies it rather than the way the SAML page
does**, because there is not one key pair but a collection, and the certificates
in it are public documents:

* the preference (`pki_save_keys`, on by default) governs the **private half
  only**. Clearing it strips `privateKeyPem` from every entry already stored and
  from every entry written afterwards; subjects, certificates and public keys
  stay.
* the enforcement is **central** — one write path, `writeRaw()` — because a
  guard per call site is a guard somebody forgets, and this failure is silent in
  the reassuring direction: the box unticks, the note appears, and the key goes
  on being written.
* an entry without its private key is **not useless**, and the page says which
  it is: the certificate can still be inspected, exported and used as a trust
  anchor. What it cannot do is sign or be presented as a client certificate, so
  `canSign()` is what every caller asks and such a CA is not offered in the
  "Signed by" dropdown at all — offering one produces a Web Crypto error two
  clicks later that names neither the CA nor the missing key.

`tests/pki_page.js` reads localStorage directly for all of this, for the same
reason `tests/keypair_storage_optout.js` does on the other four protocols.

## The list fields are text, and that is deliberate

`subjectAltName`, the CRL distribution points, the AIA entries, the policies,
the name constraints and the custom extensions are textareas with a small
documented syntax rather than rows of widgets. Three reasons: an editor built
out of widgets can only express what its widgets anticipated, and the point of
this page is issuing the certificate that is wrong in **exactly one way**; a
line of text is something an operator can paste from a ticket; and it is input a
test can drive exhaustively. The syntax is documented on the page beside each
field, parsed by the `parse*()` functions in `pki.js`, and checked directly by
`tests/pki_page.js`.

```
dns:example.com            ip:10.0.0.1        ip:2001:db8::1
email:user@example.com     uri:https://x/y    rid:1.2.3.4
upn:user@EXAMPLE.COM       krb5:host/h@REALM  dirname:CN=alt,O=Example
othername:<oid>:<base64 DER>

permit dns:example.com     exclude ip:10.0.0.0/8      (name constraints)
ocsp:http://ocsp/          caissuers:http://ca/       (AIA / SIA)
1.3.6.1.4.1.99999.1|cps=https://c/|notice=text        (policies)
<oid>|critical|<base64 DER>                           (any extension at all)
```

A malformed line is **refused by name** rather than dropped. A certificate
quietly missing a name somebody typed is the failure this whole page exists to
avoid.

## The TLS test, and why the page has no option to make it itself

Every other page here offers the choice: call from the browser, or proxy through
the api. **This one does not, and the omission is the design.** A browser cannot
answer any of the questions the pane exists to ask:

* the **client certificate** is chosen by the browser's own UI from the
  browser's own store, so the certificate issued thirty seconds ago on this page
  is not offered — and "present none" is not offerable either;
* the **truststore** is the platform's, so *"does this chain verify against my
  root, and only mine"* is unaskable;
* the negotiated **version, cipher, ALPN protocol and the server's chain** are
  not exposed to script at all;
* and a failed handshake reaches script as a generic network error with **the
  alert discarded** — the one genuinely informative thing.

So `POST /tls/connect` opens the socket and reports both sides. A browser-side
option would be a button that answers a different question badly, and every
answer it gave would be about the browser. `tests/pki_page.js` asserts that the
pane contains no radio button, so this cannot be "fixed" by mistake.

### A completed handshake is not an accepted client certificate

This is the sharpest thing in `api/tls_probe.js` and the assertion that earns
its keep.

Under **TLS 1.2** a server that refuses a client certificate refuses it during
the handshake, and `secureConnect` never fires. Under **TLS 1.3** the client
sends its Certificate and Finished **last** — the handshake is complete from the
client's point of view the instant it has written them — and the server's
verdict arrives afterwards. It arrives in one of two ways, and neither is
visible in the handshake:

* a **post-handshake alert** (`certificate required`, `bad certificate`,
  `unknown ca`), or
* the server simply **hangs up**. Node's own TLS server does exactly this when
  `rejectUnauthorized` refuses a client certificate: the socket closes with no
  alert at all.

An implementation that resolves on `secureConnect` therefore reports a happy
mutual-authentication connection to a server that rejected the certificate a
millisecond later, and its mutual-auth probe answers *"not required"* for every
TLS 1.3 server on earth. So the socket is **read for a moment** after the
handshake (`POST_HANDSHAKE_GRACE_MS`, 750 ms): an alert, a close or the server's
first bytes all end the wait, and only silence spends the whole grace period.
`handshakeUsable()` is what every verdict is computed from, and it is not
`connected`.

### A client certificate is sent with its chain

The page sends `chainPems()` — the leaf and its intermediates, leaf first — and
not the leaf alone. A server verifying a client certificate has to build a path
from what the client **sent** to an anchor it holds, so a leaf issued by an
Issuing CA and presented by itself is unverifiable to a server holding only the
root.

This one is worth knowing because of how it fails. Node's TLS server answers an
unverifiable client certificate by **resetting the connection with no alert at
all**, so the far end reads as *"the server refused my certificate"* when what
it could not do was find the issuer — and the mutual-auth probe duly reports
`required-and-rejected` against a server that would have been perfectly happy.
It was found by driving the page end to end against a real server, and it is
now asserted from both sides in `tests/api_tls_probe.js`: the leaf alone must
fail, the chain must work. Asserting only the second would pass against a
server that verifies nothing.

The **root** is deliberately not sent: a server that does not already hold it
will not trust it because we offered it.

### `usable`, not `connected`

Because of the TLS 1.3 ordering above, *"did this connection actually work"* has
one answer and it is not `connected`. The api computes it once, as `usable` on
every report, and every caller reads that field — the page included. The page
briefly re-derived it, and duly announced *"Handshake completed"* for a server
that had already hung up.

### Mutual authentication is measured, not read

Node exposes no `CertificateRequest`: there is no event and no property, and it
is consumed inside OpenSSL. The only way to find out whether a server *requires*
a client certificate is to try both ways, which is what `mutualAuthProbe` does —
one handshake with the certificate and one without, reported side by side, with
five possible verdicts:

| verdict | means |
|---|---|
| `required` | worked with the certificate, failed without it |
| `not-required` | worked both ways (it may still have asked optionally) |
| `certificate-rejected` | worked **without** the certificate, failed with it |
| `required-and-rejected` | neither worked, both reached TLS — the server wants one and refused this one, usually an untrusted issuing CA |
| `unknown` | neither reached a handshake; the errors are about reaching the server |

That fourth row is the case an operator hits most, and it is exactly the one a
single connection cannot tell from `required`.

### What bounds the endpoint

Same accounting as the Kerberos relay, plus one setting of its own:

* **the address policy**, reused from `api/ssrf_guard.js` rather than
  reimplemented — `tls.connect` is a raw socket, so the guard's axios
  interceptor and agent hooks never see it. It asks `guard.blockedRangeFor()`
  for the decision, because two implementations of an address policy is one
  implementation and one hole.
* **`tlsAllowedPorts`**, the ninth setting in `api/env/*.js`. This endpoint is
  broader than the Kerberos relay in one specific way: **there is no payload
  shape to bound it with**, because a ClientHello sent to port 22 is a perfectly
  well-formed ClientHello. So the ports do all of that work. `"any"` is spelled
  as a word so enabling it cannot be a plausible typo; `local.js` and
  `docker-tests.js` set it, and say why.
* **three deadlines**, and the name lookup gets one of its own for the reason
  `api/krb5_relay.js` records: until a name is an address, neither of the other
  budgets has started. A call is bounded by `connectionTimeout` (resolve) +
  `connectionTimeout` (connect) + `callTimeout` (handshake), and
  `everyDeadlineIsSeparateAndArmed()` fails against an implementation that
  expresses the last two with one timer.
* **`maxContentLength`**, applied to the certificate chain that comes back.

**The handshake is always made with `rejectUnauthorized: false`, and the verdict
is reported rather than enforced.** That looks like the wrong default and is the
only useful one: the question is *"what does this server present, and does it
verify against the truststore I chose"*, and aborting on a verification failure
throws away the chain that would explain it. Node computes `socket.authorized`
and `socket.authorizationError` either way, so nothing is lost — the caller gets
the certificate, the alert **and** the verdict, and the response says
`authorized: false` in as many words.

Note also that supplying trust anchors **does not** quietly add the platform
roots. A chain that verifies for a reason the caller did not ask about is not an
answer.

## Tests

| Test | Covers | Skips? |
|---|---|---|
| `tests/pki_x509.js` | ~240 certificates over every (issuer key, signature algorithm) pair × every subject key algorithm; every extension read back by OpenSSL; the whole set at once; all 14 profiles; a four-deep chain; name constraints, pathLen and an unknown critical extension actually **refusing** something; serials; the 2050 boundary; key identifiers | never |
| `tests/pki_key_formats.js` | 7 algorithms × 4 formats × password on/off, read back by OpenSSL; a PKCS#12 carrying a whole chain; the refusals by name; PEM↔JWK round trips | never |
| `tests/api_tls_probe.js` | the address policy on a raw socket, the port allowlist, truststore selection, the mutual-auth measurement (all five verdicts), the three deadlines, and that **every path settles** | never |
| `tests/pki_page.js` | the hierarchy built through the form, the store surviving a reload, the private-key opt-out in both states, the list-field syntax, the TLS test end to end, and no browser-side TLS option | needs the client; the TLS section skips without an api |

The first three are node-only and need **`openssl` on the PATH** (the tests image
installs it); they say so rather than skipping if it is absent, because a test
that quietly stops asserting is worse than one that fails.

## Adding to this page

* A new **key algorithm** is one entry in `KEY_ALGS`. The dropdown is filled
  from it, so nothing in the markup changes — but add an expectation to
  `everyAlgorithmGeneratesAKeyOpensslRecognises()`, which asserts the two lists
  match so a new algorithm cannot arrive untested.
* A new **signature algorithm** is one entry in `SIG_ALGS` plus its `kind`, which
  is what filters it to the keys that can produce it.
* A new **profile** is one entry in `PROFILES` and `PROFILE_ORDER`.
  `everyProfileIssuesWhatItPromises()` will issue it and check what it claims.
* A new **extension** needs a builder, a branch in `buildExtensions()`, a branch
  in `describeExtension()`, a control in `pki.html`, a case in
  `everyExtensionIsWrittenAndReadBack()` with **OpenSSL's own words** as the
  expectation, and an entry in the id list `thePageOffersWhatTheModulesDefine()`
  checks. Miss the last and the extension is one nobody can set, with nothing to
  say so.
