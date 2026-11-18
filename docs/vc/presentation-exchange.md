# Predicates: Presentation Exchange 2.1.1, the DCQL extension, and `values`

A **predicate** proves something *about* a claim — `age >= 18` — without
disclosing it. OpenID4VP 1.0 has no way to ask for one: its query language,
DCQL, can only ask for claims, and a claim's `values` is an exact match. The
debugger therefore carries predicates in two ways, which are labelled
differently on every page because they are different kinds of thing:

| Piece | Status |
|---|---|
| DIF Presentation Exchange 2.1.1 and its **Predicate Feature** | **Standard** (DIF) |
| PE carried as `presentation_definition` / `presentation_submission` in OpenID4VP | **OpenID4VP drafts — removed in 1.0.** OpenID4VP 1.0 replaced PE with DCQL. |
| `x_debugger_predicates` / `x_debugger_crit` in a DCQL credential query | **NON-STANDARD.** This debugger's extension, critical and fail-closed |
| `x_debugger_predicates_supported` in `wallet_metadata` / `client_metadata` | **Non-standard.** No specification defines predicate capability metadata. |
| DCQL `values` matching | **Standard**: OpenID4VP 1.0 §6.4.1, implemented exactly |
| AnonCreds `requested_predicates` | **Standard**: AnonCreds 1.0 |
| Mapping a query onto an AnonCreds request; answering an mdoc age bound with `age_over_NN` | The debugger's mappings |

The page that composes predicate queries is `vc-predicates.html`
([reference-predicates.md](reference-predicates.md)); the walk through it is
[tutorial-predicates.md](tutorial-predicates.md); the developer note is
[../predicates.md](../predicates.md).

## Presentation Exchange 2.1.1 (OpenID4VP drafts — removed in 1.0)

[DIF Presentation Exchange 2.1.1](https://identity.foundation/presentation-exchange/spec/v2.1.1/)
describes what a Verifier wants as a `presentation_definition`: Input
Descriptors, each with `constraints.fields` that select data with JSONPath
`path` arrays and test it with a JSON Schema `filter`, plus optional
`submission_requirements`. The holder answers with the presentation and a
`presentation_submission` saying which descriptor each part answers, in
which format, at which path. The OpenID4VP **drafts** carried it as the
`presentation_definition` request parameter; **OpenID4VP 1.0 removed it** in
favour of DCQL, and HAIP 1.0, which profiles 1.0, has no
`presentation_definition` at all.

What the debugger reads: ids, JSONPath `path` arrays (`$`, `.name`,
`['name']`, `[n]`, `[*]` — anything else is refused by name), `filter`,
`optional`, `limit_disclosure`, `group`, and `submission_requirements`
(`all`, `pick` with `count`/`min`/`max`, `from` / `from_nested`). It does not
read `presentation_definition_uri`, and PE's Relational Constraint,
Credential Status, Holder Binding and JSON-LD framing features are not
implemented (`frame` is reported as not applied).

### The Predicate Feature

A field with `predicate: "required"` or `"preferred"` must have a `filter`
restricted to the predicate operation:

| Filter | Operation | AnonCreds `p_type` |
|---|---|---|
| `minimum` | greater than or equal | `>=` |
| `exclusiveMinimum` | greater than | `>` |
| `maximum` | less than or equal | `<=` |
| `exclusiveMaximum` | less than | `<` |
| `const`, `not const` | equal / not equal | none |
| `enum`, `not enum` | in set / not in set | none |

A range filter is `type: "number"` or `"integer"` with those four keywords
only; draft-04's boolean `exclusiveMinimum` is refused, and a filter keyword
the debugger does not implement is a **non-match** (fail closed).

`required` means the answer MUST be the boolean result; `preferred` means it
SHOULD be, so PE lets a holder answer with the value. **The debugger's wallet
never does**: it refuses an unprovable `preferred` predicate exactly as a
`required` one.

The answer, as the drafts defined it: the `vp_token` IS the presentation (no
query-id keys) and `presentation_submission` goes beside it. An AnonCreds
presentation is `format: "anoncreds"`, path `$`; in the W3C form it is
`di_vp`, with `path_nested` `{ format: "di_vc", path:
"$.verifiableCredential[0]" }` (the DIF Claim Format Registry's names). The
submission is held to the definition (`definition_id`, known descriptor ids,
the submission requirements) and to the `vp_token` (every `path` and
`path_nested` must select something).

## The DCQL predicate extension (NON-STANDARD, critical, fail-closed)

An ad-hoc `predicate` member on a DCQL claims query would be dangerous:
OpenID4VP 1.0 §6.1 has a wallet **ignore** a property it does not
understand, so a 1.0 wallet would ignore the predicate and disclose the very
value it was meant to protect. The extension is built so that cannot happen:

```json
{ "credentials": [{
    "id": "pid", "format": "anoncreds", "meta": {},
    "claims": [{ "path": ["name"] }],
    "x_debugger_predicates": [
      { "id": "age", "path": ["age"],
        "filter": { "type": "integer", "minimum": 18 } } ],
    "x_debugger_crit": ["x_debugger_predicates"] }] }
```

- **Its own member.** The predicates go in `x_debugger_predicates` on the
  credential query, never in `claims`, and the claim a predicate is about
  **must not** also be in `claims`. A query that names it in both places is
  refused outright, by the wallet and by the Verifier page's builder. So a
  wallet that ignores the extension discloses nothing it was not asked for
  plainly. The `filter` is PE's restricted JSON Schema, so the two languages
  share one predicate semantics.
- **Critical.** It is honoured only when the query lists it in
  `x_debugger_crit`, JOSE-`crit` style:
  - not listed: ignored, exactly as §6.1 says, with a note — nothing it
    names is disclosed, because nothing it names is in `claims`;
  - listed: the wallet must prove each predicate;
  - `x_debugger_crit` naming anything the wallet does not understand, or
    listing the extension when the query carries none: the credential query
    is **refused**.
- **Fail-closed, on both ends.** A wallet that cannot prove a listed
  predicate **does not return that credential**; it never falls back to the
  value. The Verifier treats a predicate it asked for and the answer does not
  prove as a **FAIL**, so a 1.0 wallet that ignored the extension gets
  nowhere.

## How each format proves a predicate

| Format | Predicates |
|---|---|
| `anoncreds`, and its W3C form | A range, in **zero knowledge** (CL range proofs), over integer attributes. A date is `YYYYMMDD`, the AnonCreds convention: "older than 18" is `birthdate_dateint <= <today minus 18 years>`. |
| `mso_mdoc` | A single lower bound on `age_in_years` / `age` (`>= NN` or `> NN-1`), answered by disclosing the issuer-computed `age_over_NN` when it is `true`. When it is `false`, the credential is refused. |
| `dc+sd-jwt`, `vc+sd-jwt`, `jwt_vc_json`, `ldp_vc`, `jpt`, `sd-cwt` | None. A required predicate is **refused**, never answered with the value. |

AnonCreds cannot reveal an attribute and prove a predicate over it in one
presentation (and asking for both defeats the predicate), so a query that
does both is refused.

## OpenID4VP 1.0 §6.4.1 — `values` matching in the wallet

DCQL's `values` is not a predicate: it lists the exact values a claim may
have. The wallet implements §6.4.1 exactly:

- no `claims`: only what is mandatory to present;
- `claims` without `claim_sets`: every claim;
- with `claim_sets`: the first option the credential satisfies, and **none**
  when none can be;
- a claim with `values` matches only by exact type and value — `"true"` is
  not `true`, `"18"` is not `18` — and a mismatching claim is treated as
  absent.

If the credential cannot deliver what is selected, it is **not returned**:
step 1 says why and keeps Continue off, and step 2 builds nothing. So
`age_over_18` with `values: [true]` against a credential holding `false` is
refused on step 1, naming the claim (see
[tutorial-predicates.md](tutorial-predicates.md#when-the-value-does-not-match)).

## Capability metadata (non-standard)

The wallet advertises `x_debugger_predicates_supported` in its
`wallet_metadata` (sent under `request_uri_method=post`, OpenID4VP 1.0 §10):
the query languages it reads, the `crit` entries it understands, and per
format how it proves a predicate. A Verifier using the debugger's pages
advertises what it verifies in `client_metadata`. Pane 5 of
`vc-predicates.html` shows both.
