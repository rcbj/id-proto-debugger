# Credential status: Token Status List and Bitstring Status List

A credential can say where to look up whether it has since been revoked or
suspended. Two mechanisms are checked, one per family of formats:

| Mechanism | Specification | Formats |
|---|---|---|
| **Token Status List** | draft-ietf-oauth-status-list-**21** (IETF OAuth WG, **a draft**) | `dc+sd-jwt`, `mso_mdoc` |
| **Bitstring Status List** | W3C Bitstring Status List v1.0 | `jwt_vc_json`, `ldp_vc` |

AnonCreds revocation is a different, zero-knowledge mechanism; see
[format-anoncreds.md](format-anoncreds.md). A VC Barcode's
`TerseBitstringStatusListEntry` is expanded on its page but not fetched; see
[format-vc-barcodes.md](format-vc-barcodes.md).

## Where status is checked

**Only on the Verifier page** (`vc-verifier.html`), for each credential in
each answer. The wallet pages do not look a credential's status up. Issuance
step 4 shows a refreshed credential's status entry (`index N on <uri>`, or `—`
when the issuer sets none) beside the old one, as one row of what changed.

A status list is something the **Verifier** fetches; the wallet did not send
it. From the page that is a cross-origin GET, which works only when the server
sends CORS headers, and the Token Status List draft makes CORS only a SHOULD.
So pane 2 of the Verifier page has **Fetch issuer metadata, DID documents and
status lists through the api** (`vpv_fetch_via_api`): on by default where
there is an api, off and disabled on the static sites, which have none. Ticked,
the GET goes through the api's `POST /oid4vp/call` and arrives as bytes, so a
binary CWT status list is not mangled. A fetch that fails names its URL.

Every credential's result is in the row `status` (`vc.status` for a W3C
credential in a VP), and its sub-rows. **A credential with no status is a
SKIP, not a PASS.**

## Token Status List (draft-21)

The credential carries `status.status_list` with an index `idx` and a `uri`.
The Verifier:

1. **Fetches** the Status List Token with `Accept:
   application/statuslist+jwt, application/statuslist+cwt` (section 8.1). A
   Content-Type other than the form's media type is reported.
2. **Reads either form.**
   * JWT (section 5.1): `typ` is compared as a media type, so
     `application/statuslist+jwt` and `statuslist+jwt` in any letter case pass.
   * CWT (section 5.2): a COSE_Sign1, verified over RFC 9052's Sig_structure.
     It FAILS when it is not tagged COSE_Sign1 (18), when it is tagged as a CWT
     (61, which the section forbids), or when the protected header's type is
     missing or wrong. An integer type is reported, not judged (its
     Content-Format number is still TBD). A COSE_Mac0 is a SKIP: it needs a key
     shared with the status issuer.
   * Anything else (an HTML page, other binary, other text) is a FAIL that
     says what it was.
3. **Checks the signature** with the first key that verifies: the credential
   issuer's own key when the token references it, then the token's own key
   (`x5c`, a DID, or an `https` `iss`'s metadata), then the credential
   issuer's key as a fallback. A token with its own `x5c` is held to that key
   alone.
4. **Checks who signed it** (`.signer` row): PASS when it is the credential's
   issuer, or a key from the issuer's own key resolution. A certificate from
   the same CA with the `id-kp-oauthStatusSigning` EKU would also count, but
   that EKU has no OID yet (the draft says `1.3.6.1.5.5.7.3.TBD`), so on the
   page such a signer is a SKIP. Anything else is **SKIP, "NOT linked"**,
   never a PASS.
5. **Reads the entry**: `lst` is zlib-decompressed, entry 0 in the least
   significant bits of byte 0. VALID (0x00) is PASS; INVALID (0x01) and
   SUSPENDED (0x02) are FAIL. Application-specific values (0x03, 0x0C–0x0F)
   and reserved ones are SKIP and shown.

A status mechanism other than `status_list`, such as an mdoc's
`identifier_list`, is a SKIP by name.

## Bitstring Status List (W3C v1.0)

The credential carries one or more `credentialStatus` entries
(`BitstringStatusListEntry`), each with a `statusPurpose`, a
`statusListIndex` and a `statusListCredential`. One row per purpose:

* The list credential is asked for as `application/vc`,
  `application/vc+jwt` and the JSON types (section 4), and its own proof or
  signature is checked under the same "the issuer controls the key" rule as
  the credential's. A VC-JWT list's `validFrom` / `validUntil` are checked as
  well as its `nbf` / `exp`.
* The list is GZIP, read most significant bit first.
* `revocation` and `suspension` **FAIL when the bit is set**. `refresh` is a
  PASS either way and says when an updated credential is available.
  `message` reports the message, matching `statusMessage` by number.
* A `statusSize` above 1 with no `statusMessage`, or a `statusMessage` that
  is not 2^`statusSize` long, is a FAIL (`.entry` row, section 2.1).
* A list credential whose issuer differs from the credential's is reported,
  not failed (section 2.2 says it MAY differ).
* A list shorter than 131072 entries is reported, not refused: it gives its
  subjects no herd privacy (section 6.1).

## Related

* [Verifier developer notes, status lists](../vc-verifier.md#what-is-checked)
* [format-sd-jwt-vc.md](format-sd-jwt-vc.md), [format-mdoc.md](format-mdoc.md),
  [format-jwt-vc-json.md](format-jwt-vc-json.md),
  [format-ldp-vc.md](format-ldp-vc.md)
