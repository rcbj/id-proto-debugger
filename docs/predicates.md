# Predicate queries (`vp_query.js`, `vc-predicates.html`)

Issue #474. A **predicate** asks the holder to prove something *about* a
claim — `age >= 18`, `birthdate_dateint <= 20081118` — instead of
disclosing the claim. This note covers the query language that carries
one, how each credential format answers it, the separate page, and what
the wallet and the Verifier do with it.

## What is standard and what is not

| Piece | Status |
|---|---|
| DIF Presentation Exchange 2.1.1 and its **Predicate Feature** | Standard (DIF). |
| PE carried as `presentation_definition` / `presentation_submission` in OpenID4VP | **The OpenID4VP drafts. Removed in 1.0.** Every label says "OpenID4VP drafts — presentation_definition, removed in 1.0" (`vpQuery.LABEL_PE`). |
| DCQL `values` matching | Standard: OpenID4VP 1.0 section 6.4.1, implemented exactly. |
| `x_debugger_predicates` / `x_debugger_crit` in a DCQL credential query | **This debugger's extension. Non-standard.** (`vpQuery.LABEL_EXT`) |
| `x_debugger_predicates_supported` in `wallet_metadata` / `client_metadata` | **This debugger's extension.** No specification defines predicate capability metadata. |
| AnonCreds `requested_predicates` | Standard: AnonCreds v1.0. |
| Mapping a query onto an AnonCreds request | **This debugger's.** Neither OpenID4VP nor PE defines AnonCreds. |
| Answering an mdoc age bound with `age_over_NN` | **This debugger's mapping** of an ISO/IEC 18013-5 issuer-computed claim. |

## Why DCQL needs care

OpenID4VP 1.0's DCQL has **no predicates**. A claims query's `values` is an
exact type-and-value match, a SHOULD, best effort (section 6.4.1), and a
wallet **MUST ignore** a property it does not understand (section 6.1). So
an ad-hoc `predicate` member on a claims query is dangerous: a 1.0 wallet
ignores it and discloses the raw value the predicate was meant to protect.

The extension is built so that cannot happen:

- **The predicates live in their own member**, `x_debugger_predicates`, on
  the credential query. The claim a predicate is about **must not** also be
  in `claims`. A query that names it in both places is refused outright, by
  the wallet (`readExtension()`) and by the Verifier's builder.
- **It is honoured only when the query marks it critical**, JOSE `crit`
  style: `x_debugger_crit: ["x_debugger_predicates"]`.
  - Unlisted: ignored, exactly as section 6.1 says. Nothing extra is
    disclosed, because nothing it names is in `claims`.
  - Listed and understood: a wallet that cannot prove a predicate **does
    not return that credential**. It never falls back to the value.
  - Listed but not understood (any other name in `x_debugger_crit`): the
    credential query is refused.
- **The Verifier fails closed**: a predicate it asked for and the answer
  does not prove is a FAIL, so a 1.0 wallet that ignored the extension
  gets nowhere.

```json
{ "credentials": [{
    "id": "pid", "format": "anoncreds", "meta": {},
    "claims": [{ "path": ["name"] }],
    "x_debugger_predicates": [
      { "id": "age", "path": ["age"],
        "filter": { "type": "integer", "minimum": 18 } } ],
    "x_debugger_crit": ["x_debugger_predicates"] }] }
```

The filter is PE's JSON Schema, restricted the same way, so the two
languages share one predicate semantics.

## Presentation Exchange 2.1.1

`readDefinition()` reads and validates a `presentation_definition`: ids,
JSONPath `path` arrays (`$`, `.name`, `['name']`, `[n]`, `[*]`; anything
else is refused by name), `filter`, `optional`, `limit_disclosure`,
`group`, and `submission_requirements` (`all`, `pick` with `count`/`min`/
`max`, `from` / `from_nested`).

The **Predicate Feature**: a field with `predicate: "required" |
"preferred"` MUST have a `filter` restricted to the predicate operation:

| Filter | Operation | AnonCreds `p_type` |
|---|---|---|
| `minimum` | greater than or equal | `>=` |
| `exclusiveMinimum` | greater than | `>` |
| `maximum` | less than or equal | `<=` |
| `exclusiveMaximum` | less than | `<` |
| `const`, `not const` | equal / not equal | none |
| `enum`, `not enum` | in set / not in set | none |

A range filter is `type: "number"` or `"integer"` and those four keywords
only. Draft-04's boolean `exclusiveMinimum` is refused. A filter keyword
this module does not implement is a **non-match** (fail closed).

`required` means the answer MUST be the boolean result. `preferred` means
it SHOULD be, so PE lets a holder answer with the value. **This wallet does
not**: an unprovable preferred predicate is refused too, unless a caller
passes `allowPreferredDisclosure` to `planFor()`. That path exists in the
engine and is tested, and the wallet never takes it.

**`presentation_submission`**: `buildSubmission()` and `checkSubmission()`.
The check holds the submission to the definition (`definition_id`, known
descriptor ids, the submission requirements) and to the vp_token (every
`path` and `path_nested` must select something).

**The answer**, as the drafts defined it: the `vp_token` IS the
presentation (no query-id keys), and `presentation_submission` goes beside
it. An AnonCreds presentation is `format: "anoncreds"`, path `$`. In the W3C
form it is `di_vp` with `path_nested` `{ format: "di_vc", path:
"$.verifiableCredential[0]" }` (the DIF Claim Format Registry's names).

## How each format answers

`FORMAT_PREDICATES` in `vp_query.js`:

| Format | Predicates |
|---|---|
| `anoncreds` (and its W3C form) | Range, in **zero knowledge** (CL range proofs). Integer attributes only (an `i32` the issuer encoded as an integer). A date is `YYYYMMDD`, the AnonCreds specification's convention; `ageThresholdDateInt(18, today)` gives "born on or before". |
| `mso_mdoc` | None in zero knowledge. A single lower bound on `age_in_years` / `age` (`>= NN`, or `> NN-1`) is answered by disclosing the issuer-computed `age_over_NN` when it is `true`. When it is `false` the credential is refused. |
| `dc+sd-jwt`, `vc+sd-jwt`, `jwt_vc_json`, `ldp_vc`, `jpt`, `sd-cwt` | None. A required predicate is **refused**, never answered with the value. |

AnonCreds cannot reveal an attribute and prove a predicate over it in one
presentation, and asking for both defeats the predicate anyway. A plan that
does both is refused.

## The AnonCreds mapping

`anoncredsRequestFor(plan, { nonce, revocationTimestamp })`:

- one requested attribute per disclosed claim, its referent the attribute's
  name (as `anoncreds_wallet.js` always has);
- one requested predicate per bound, its referent
  `<id>_<ge|gt|le|lt>_<value>` (`m` for a minus sign), deterministic so a
  Verifier rebuilding the request reaches the same referents;
- the nonce from the OpenID4VP one by `anoncreds_wallet.js nonceFor()`;
- `non_revoked` at the held status list's timestamp for a revocable
  credential.

A Verifier holds no credential, so it uses `nominalPlan(item, names)`:
every range predicate the query asks for, and the claims the presentation
revealed (a `claim_sets` choice is the wallet's). Fed to
`anoncredsRequestFor()`, that reaches the request the wallet proved.
`anoncreds_wallet.js verifyForQuery()` does exactly that, then holds the
presentation's credential to the query's restrictions (a PE field on
`$.cred_def_id`, `$.schema_id`, ...), which the AnonCreds request does not
carry.

**A raw AnonCreds request** (the specification's own object, where its
predicates are standardized) is an input too: `readAnoncredsRequest()`
validates it, `specFromAnoncredsRequest()` turns it into either query
language, and `anoncreds_wallet.js presentRequest()` proves it with the held
credential, refusing by name what the credential cannot answer.

## OpenID4VP 1.0 section 6.4.1 in the wallet

`selectClaims()` is the section exactly:

- no `claims`: only what is mandatory to present;
- `claims` without `claim_sets`: every claim;
- with `claim_sets`: the first option the credential satisfies, and **none**
  when none can be;
- a claim with `values` matches only by exact type and value (`"true"` is
  not `true`, `"18"` is not `18`); a mismatching claim is treated as absent.

If the credential cannot deliver what is selected, it is **not returned**:
step 1 says why and keeps Continue off, and step 2 builds nothing. One
exception keeps the old behaviour: a plain DCQL query (no `values`, no
`claim_sets`, no predicates) whose claim this wallet's presence check
cannot find stays the advisory it always was, because that check is
approximate for nested paths.

## The wallet

- **Step 1** reads `dcql_query` or, when there is none,
  `presentation_definition` (a new entry in `REQUEST_PARAMS`). It labels the
  query language, marks each claim available / absent / value-mismatch,
  and has a **Predicates** table: each predicate, how this credential
  proves it (or why it cannot), and what is not revealed. A refusal is a
  blocking problem. Under HAIP 1.0 a `presentation_definition` is refused
  (HAIP profiles 1.0, which has only DCQL); otherwise it is a WARNING row
  saying where it comes from.
- **Step 2** selects exactly what the plan discloses. A predicated
  attribute's row cannot be ticked. The AnonCreds proof carries the
  predicates, and a summary above the table says which are proven and what
  is not revealed. A `presentation_definition` is answered with the
  presentation as the vp_token and a `presentation_submission`.
- **Step 3** re-checks an AnonCreds proof against the request step 2
  recorded (`anoncredsRequest`), with one row per predicate.
- **`wallet_metadata`** carries `x_debugger_predicates_supported`: the query
  languages it reads, the crit entries it understands, and per format how it
  proves a predicate.

## The page

`vc-predicates.html`, bundle `vc_predicates_page.js` (global
`vcpredicatespage`). It is offered from presentation step 0 (a third role
button) and step 1, and it ships to the static sites, since it needs no api.
It has five collapsible panes, each field with a tooltip:

1. **Compose**: language, format, the claims to reveal, the predicates
   (`name op integer`, plus an "older than N years" helper over a
   `YYYYMMDD` attribute), required or preferred (PE), a `cred_def_id`
   restriction. The query lands in an editable box.
2. **The equivalent AnonCreds request**, for each query item. A raw
   AnonCreds request can be read into the query, or proven with the held
   credential directly (no OpenID4VP around it).
3. **Send to the wallet**: an Authorization Request from a `redirect_uri:`
   Client Identifier that is the page itself, `response_mode=fragment`. The
   page keeps `vcpred_request` (the query, nonce and state; no key or
   secret), and the wallet's answer comes back in the fragment.
4. **Inspect**: the vp_token and presentation_submission, checked with
   `verifyForQuery()` against the held bundle's (or a pasted bundle's)
   schema and credential definition. One row per predicate.
5. **Capability advertisement**: the wallet and Verifier metadata.

## The Verifier

`vp_verifier.js`:

- `buildDcql()` takes `predicates` on a query and writes the extension,
  marked critical. It refuses a predicate whose claim is also in `claims`.
  `anoncreds` is a format a query may name (`QUERY_FORMATS`), with an empty
  `meta`. `FORMATS` is unchanged, because AnonCreds is no OpenID4VP format.
- `buildPresentationDefinition()` builds a PE 2.1.1 definition.
  `requestObjectClaims()` sends it as `presentation_definition` instead of
  `dcql_query` when asked, and `advertisePredicates` adds
  `x_debugger_predicates_supported` to `client_metadata`.
- `verifyResponse()`:
  - **AnonCreds** (`verifyAnoncreds()`): the CL proof against the request
    the query maps onto, one row per predicate, and the requested claims.
    The issuer's schema and credential definition come in
    `session.anoncreds`. Without them, or without a status list for a
    revocable credential, the proof row is an essential SKIP, so the
    verdict is **incomplete**.
  - **The extension's predicates on any other format**
    (`checkQueryPredicates()`): an mdoc's `age_over_NN` must be `true`. Any
    other format FAILs the predicate. A disclosed value is not accepted in
    a predicate's place.
  - **A presentation_definition answer** (`session.presentationDefinition`,
    no `dcql`; `verifyPeAnswer()`): the `presentation_submission` is checked,
    then each mapped presentation. Only AnonCreds (`anoncreds`, `di_vp`) is
    verified there. Any other format's row is an essential SKIP, so the
    verdict is incomplete, never a pass.
- `vc_verifier.js` / `vc-verifier.html` gain a Predicates box, a
  query-language choice and an AnonCreds issuer-material box. None is
  stored. A `presentation_definition` is refused under HAIP and over the
  Digital Credentials API.

## Tests

| Test | What it checks |
|---|---|
| `tests/vp_query_engine.js` | PE: the Predicate Feature's own filter examples, malformed definitions, submission requirements, and `presentation_submission` (refused for another definition, a path that selects nothing, an unknown descriptor). Section 6.4.1: `age_over_18` with `values [true]` against `true` and `false`, `"18"` against `18`, the `claim_sets` fallback. The extension's crit rules. The fail-closed plans. Then against anoncreds-rs: our wallet proves both languages' predicates and anoncreds-rs verifies; anoncreds-rs proves the mapped request and we verify; a weaker predicate, another nonce, a minor and a wrong restriction are refused; a raw AnonCreds request with a `YYYYMMDD` predicate is proven both ways; the W3C form. Finally the Verifier engine: requests in both languages, our wallet's and anoncreds-rs's answers (legacy and W3C, with `presentation_submission`) pass; a weaker predicate, an ignored extension and another `definition_id` fail; with no issuer material the verdict is incomplete. |
| `tests/vc_predicates_browser.js` | In Chrome, for both languages: the page composes `age >= 18`, the wallet proves it without revealing age, anoncreds-rs verifies what step 2 built, and the answer comes back to the page and verifies there. Then the wallet's `values` matching against an SD-JWT VC holding `true` and one holding `false`. Then the Verifier page building both forms. |
| `tests/anoncreds_engine.js` | The W3C form **with revocation**, both ways (`docs/anoncreds.md`). |

## Not done

- The Verifier checks a `presentation_definition` answer in AnonCreds only.
  Any other format is reported as incomplete.
- The Verifier's `age_over_NN` check for an mdoc is engine code, with no
  test of its own. No mdoc issuer in this stack writes `age_over_NN`.
- `presentation_definition_uri` (a draft parameter) is not read.
- PE's other features (Relational Constraint, Credential Status, Holder
  Binding, JSON-LD framing) are not implemented. `frame` is reported as not
  applied.
