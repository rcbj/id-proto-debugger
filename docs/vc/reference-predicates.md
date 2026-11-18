# Configuration reference: Predicate Queries (`vc-predicates.html`)

A **predicate** asks the holder to prove something *about* a claim —
`age >= 18`, `birthdate_dateint <= 20081118` — instead of disclosing the
claim. `vc-predicates.html` composes such a query, shows the AnonCreds
presentation request it maps onto, sends it to the debugger's own wallet,
and verifies what comes back. It is offered from presentation step 0 (a
third role button) and step 1, needs **no api**, and ships to the static
sites.

What is standard and what is not, and the protocol detail, are on
[presentation-exchange.md](presentation-exchange.md). The walk through it is
[tutorial-predicates.md](tutorial-predicates.md). The developer note is
[../predicates.md](../predicates.md).

**Stored.** The page stores one thing: `vcpred_request` (`localStorage`,
ordinary), written by **Send to the wallet** — the query, its language, the
nonce, the `state`, the `client_id` and the time, so the answer can be
checked against them. No key and no secret. Every field below is **not
stored**; the page reads the held credential and the holder's link secret
from the issuance workflow's storage (`sdjwtvc_credential`,
`sdjwtvc_holder_private_jwk`) and never writes them.

- [Pane 1 — Compose a Predicate Query](#pane-1--compose-a-predicate-query)
- [Pane 2 — The Equivalent AnonCreds Presentation Request](#pane-2--the-equivalent-anoncreds-presentation-request)
- [Pane 3 — Send It to the Wallet](#pane-3--send-it-to-the-wallet)
- [Pane 4 — Inspect a Returned Presentation](#pane-4--inspect-a-returned-presentation)
- [Pane 5 — Capability Advertisement](#pane-5--capability-advertisement)
- [What the wallet pages do with a predicate query](#what-the-wallet-pages-do-with-a-predicate-query)
- [What the Verifier page does](#what-the-verifier-page-does)

## Pane 1 — Compose a Predicate Query

`pane_vcp_compose`. **Load the example** (`vcp_example`) fills in an
AnonCreds credential, reveal `name`, prove `age >= 18`, and builds it; the
page does this on its own when it opens with an empty query.

| Field | id | What it is | Spec | Default |
|---|---|---|---|---|
| Query language | `vcp_language` | **Presentation Exchange 2.1.1** carried as `presentation_definition` (labelled *OpenID4VP drafts — presentation_definition, removed in 1.0*), or **DCQL + debugger predicate extension (non-standard)**. `vcp_language_note` restates what the choice means. | DIF PE 2.1.1; OpenID4VP 1.0 §6 | Presentation Exchange |
| Credential format | `vcp_format` | `anoncreds` (CL, zero-knowledge range proofs), `di_vc` (AnonCreds in the W3C form, `anoncreds-2023`), `mso_mdoc` (issuer-computed `age_over_NN`), `dc+sd-jwt`, `jwt_vc_json`, `ldp_vc` (no predicates: a wallet refuses a required one) | — | `anoncreds` |
| Query id | `vcp_query_id` | The Input Descriptor id (PE) or credential query id (DCQL): letters, digits, `_`, `-` | PE §5; OpenID4VP §6.1 | `credential` |
| Claims to reveal | `vcp_reveal` | Attribute names to disclose, comma separated. A claim a predicate is about must not also be revealed. | — | empty |
| Predicates | `vcp_predicates` | One per line, `attribute op integer`, `op` one of `>=`, `>`, `<=`, `<` (AnonCreds `p_type`). In PE each becomes a field with `predicate` and an integer `filter` (`minimum`, `exclusiveMinimum`, `maximum`, `exclusiveMaximum`). AnonCreds proves over integer attributes; a date is `YYYYMMDD`. | PE Predicate Feature; AnonCreds 1.0 | empty |
| Older than … years, over … / Add | `vcp_age_years`, `vcp_age_attr`, `vcp_age_button` | Appends `<attr> <= <today minus N years as YYYYMMDD>` — "born on or before" — the AnonCreds specification's date convention | AnonCreds 1.0 | `18`, `birthdate_dateint` |
| Predicate | `vcp_mode` (PE only; row hidden for DCQL) | `required` (the answer MUST be the boolean result) or `preferred` (it SHOULD be). This wallet refuses an unprovable predicate either way; it never answers with the value. | PE Predicate Feature | `required` |
| cred_def_id | `vcp_cred_def_id` | Optional AnonCreds restriction: only a credential under this credential definition answers. In PE a field on `$.cred_def_id` with a `const` filter. | AnonCreds 1.0 | empty |
| Purpose | `vcp_purpose` | Optional Input Descriptor `purpose` (PE only) | PE | empty |
| Build | `vcp_build_button` | Writes the query into **Query**; `vcp_compose_status` says what was built or why not | — | — |
| Query | `vcp_query` | The `presentation_definition` or `dcql_query` as JSON. Editable: the panes below read it from here, so a hand-edited or malformed query can be tried. | — | built from the example |

## Pane 2 — The Equivalent AnonCreds Presentation Request

`pane_vcp_mapping`. Every query maps onto an AnonCreds presentation request —
one requested attribute per claim, one requested predicate per bound
(`minimum` → `>=`, `exclusiveMinimum` → `>`, `maximum` → `<=`,
`exclusiveMaximum` → `<`), shown per query item in `vcp_mapping`. The mapping
is the debugger's: neither OpenID4VP nor PE defines AnonCreds.

| Field | id | What it does |
|---|---|---|
| AnonCreds request | `vcp_anoncreds_request` | An AnonCreds presentation request as that specification defines it (`name`, `version`, `nonce` in decimal digits, `requested_attributes`, `requested_predicates` with `name`, `p_type`, `p_value`) |
| Read into the query | `vcp_read_request_button` | Converts it into the query in pane 1, in the language chosen there |
| Prove with the held credential | `vcp_prove_request_button` | Answers it with the AnonCreds credential this browser holds, with no OpenID4VP around it — the AnonCreds specification's own exchange — then verifies the result in pane 4. Says so by name when the credential cannot answer. |

`vcp_anoncreds_status` reports the result.

## Pane 3 — Send It to the Wallet

`pane_vcp_send`. An OpenID4VP Authorization Request carrying the query — as
`dcql_query`, or as the drafts' `presentation_definition` — from a
`redirect_uri:` Client Identifier that is this page, with
`response_mode=fragment`, so the wallet's answer comes back here in the URL
fragment. Its `client_metadata` carries the debugger's
`x_debugger_predicates_supported` (pane 5).

| Field | id | What it is | Default |
|---|---|---|---|
| Nonce | `vcp_nonce` | The OpenID4VP nonce. The AnonCreds nonce (decimal digits) is derived from it: the nonce itself when it is digits, else the first 80 bits of its SHA-256. | 16 random bytes, base64url, made on load |
| Request | `vcp_request_uri` | The request as a link to `/vc-presentation-1.html`. Read-only. | — |
| Show the request | `vcp_show_request_button` | Fills **Request** without sending | — |
| Send to the wallet | `vcp_send_button` | Stores `vcpred_request` and opens the wallet's step 1 | — |

## Pane 4 — Inspect a Returned Presentation

`pane_vcp_inspect`. Filled in on its own when the wallet's answer arrives in
the fragment (an answer whose `state` is not the stored request's is
reported; a wallet's `error` is shown as a refusal). The AnonCreds request is
rebuilt from the query, the nonce and what the presentation reveals, and the
CL proof is verified against it with the debugger's `anoncreds.js`: **every
predicate the query asks for must be proven, at exactly its bound.**

| Field | id | What it is |
|---|---|---|
| vp_token | `vcp_vp_token` | What the wallet answered: for DCQL, an object keyed by credential query id (OpenID4VP 1.0 §8.1); for a `presentation_definition`, the presentation itself. Legacy AnonCreds JSON or the W3C form. |
| presentation_submission | `vcp_submission` | PE 2.1.1: which Input Descriptor the `vp_token` answers, in which format, at which JSONPath. Checked against the definition and the `vp_token`. Empty for DCQL. |
| Issuer material | `vcp_bundle` | The schema and credential definition (and, for a revocable credential, the registry definition, status list and tails) as an AnonCreds bundle. Empty: the held credential's bundle is used. A Verifier with no ledger needs these out of band. |
| Verify | `vcp_verify_button` | Verifies; `vcp_inspect_status` gives the verdict ("Every check passed: N predicate(s) proven, …") and `vcp_inspect_result` one row per check and per predicate |

## Pane 5 — Capability Advertisement

`pane_vcp_capability` (**debugger extension**). No specification defines how
a wallet or a Verifier says it can prove or verify predicates. The debugger
uses `x_debugger_predicates_supported`, in the wallet's `wallet_metadata`
(sent under `request_uri_method=post`, OpenID4VP 1.0 §10) and in a
Verifier's `client_metadata`. `vcp_wallet_metadata` shows the wallet's — the
query languages it reads, the `crit` entries it understands, and per format
how it proves a predicate — and `vcp_verifier_metadata` the Verifier's.

## What the wallet pages do with a predicate query

- **Step 1** reads `dcql_query` or, when there is none,
  `presentation_definition`, and labels the query language
  (`vp_query_language`). **What Is Being Asked For** marks each claim
  available, absent or value-mismatch, and a **Predicates** table
  (`vp_predicates_table`) gives each predicate, how this credential proves it
  (or why it cannot) and what is not revealed. A predicate the credential
  cannot prove is a blocking problem. Under HAIP 1.0 a
  `presentation_definition` is refused; otherwise it is a WARNING row saying
  where it comes from.
- **Step 2** selects exactly what the plan discloses; a predicated
  attribute's row **cannot be ticked**. A summary
  (`vp_predicates_summary`) says which predicates are proven and what is not
  revealed. A `presentation_definition` is answered with the presentation as
  the `vp_token` and a `presentation_submission`
  (`vp_presentation_submission`).
- **Step 3** re-checks an AnonCreds proof against the request step 2
  recorded, one row per predicate.

| Format | How a predicate is answered |
|---|---|
| `anoncreds` and its W3C form | A range, in zero knowledge (CL range proofs), over integer attributes |
| `mso_mdoc` | A single lower bound on `age_in_years` / `age` by disclosing the issuer-computed `age_over_NN` when it is `true`; refused when it is `false` |
| `dc+sd-jwt`, `vc+sd-jwt`, `jwt_vc_json`, `ldp_vc`, `jpt`, `sd-cwt` | None: a required predicate is **refused**, never answered with the value |

## What the Verifier page does

`vc-verifier.html` pane 1 has **Predicates (optional)** (`vpv_predicates`,
`age >= 18` lines), **Query language** (`vpv_query_language`: DCQL with the
extension, marked critical, or a PE `presentation_definition`), and
**AnonCreds issuer material** (`vpv_anoncreds_material`); `anoncreds` is a
format a query may name. None of these is stored. A
`presentation_definition` is refused under HAIP and over the Digital
Credentials API. The answer is checked fail-closed: an AnonCreds proof
against the request the query maps onto, one row per predicate; an mdoc's
`age_over_NN` must be `true`; any other format **FAILs** the predicate, and a
disclosed value is not accepted in its place. Without the issuer material
(or a status list for a revocable credential), the proof row is an essential
SKIP and the verdict is *incomplete*. A `presentation_definition` answer is
verified for AnonCreds only; any other format is reported as incomplete.
