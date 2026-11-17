// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/wstrust_tools.tsp
//
// The browser storage keys client/src/wstrust_tools.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/wstrust_tools.js")
model WstrustToolsKeys {
  @storageKey(#{ area: "local", class: "ordinary", prefix: true })
  wstrust_: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_actas: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_add_timestamp: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_applies_to: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_claims: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_cred_mode: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_enc_c14n: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_enc_cert: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_enc_data_alg: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_enc_digest: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_enc_key_alg: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_enc_mgf: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_enc_type: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_encrypt_request: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_key_bits: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_key_size: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_key_type: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_lifetime_minutes: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_onbehalfof: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_operation: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_password_type: unknown;

  @storageKey(#{ area: "local", class: "output" })
  wstrust_wst_saml_token: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_save_keypair: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_sig_alg: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_sign_request: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_sign_timestamp: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_soap_version: unknown;

  @storageKey(#{
    area: "local",
    class: "keypair",
    optOut: "wstrust_wst_save_keypair"
  })
  wstrust_wst_sp_cert: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_ssl_validate: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_sts_url: unknown;

  @storageKey(#{ area: "local", class: "output" })
  wstrust_wst_target_token: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_token_type: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_trust_version: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_use_actas: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_use_onbehalfof: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_username: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_wsa_action: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_wsa_from: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_wsa_messageid: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_wsa_replyto: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_wsa_support: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_wst_wsa_to: unknown;
}
