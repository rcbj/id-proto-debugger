// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/saml_tools.tsp
//
// The browser storage keys client/src/saml_tools.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/saml_tools.js")
model SamlToolsKeys {
  @storageKey(#{ area: "local", class: "ordinary", prefix: true })
  samlassert_: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_advice_ref: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_audience: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_authn_context: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_authn_method: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_authz_action: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_authz_action_ns: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_authz_decision: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_authz_resource: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_confirm_address: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_confirm_inresponseto: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_confirm_method: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_confirm_recipient: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_enc_c14n: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_enc_cert: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_enc_data_alg: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_enc_digest: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_enc_key_alg: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_enc_key_bits: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_enc_mgf: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_enc_private_key: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_enc_type: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_enc_wrap: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_issuer: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_key_bits: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_locality_address: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_locality_dns: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_nameid_format: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_nameid_qualifier: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_nameid_spqualifier: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_nameid_value: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_opt_advice: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_opt_attrs: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_opt_audience: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_opt_authn: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_opt_authz: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_opt_conditions: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_opt_locality: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_opt_onetimeuse: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_opt_proxy: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_opt_subjconf: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_opt_subject: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_private_key: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_proxy_count: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_public_key: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_session_index: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_sig_alg: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_sig_c14n: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_skew_seconds: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_validity_minutes: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samlassert_sa_version: unknown;
}
