// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/saml_request.tsp
//
// The browser storage keys client/src/saml_request.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/saml_request.js")
model SamlRequestKeys {
  @storageKey(#{ area: "local", class: "ordinary", prefix: true })
  samltools_: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml11_artifact_acs_url: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_acs_url: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_ars: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_binding: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_enc_c14n: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_enc_cert: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_enc_data_alg: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_enc_digest: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_enc_key_alg: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_enc_mgf: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_enc_type: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_encrypt_request: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_idp_entity_id: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_key_bits: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_metadata_doc: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_metadata_url: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_nameid_format: unknown;

  @storageKey(#{ area: "local", class: "output" })
  samltools_saml_response_binding: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_save_keypair: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_sig_alg: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_sign_request: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_slo_artifact: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_slo_post: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_slo_redirect: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_sp_entity_id: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_sso_artifact: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_sso_post: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_sso_redirect: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_username_hint: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_version: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_wsa_action: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_wsa_from: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_wsa_messageid: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_wsa_replyto: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_wsa_support: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_wsa_to: unknown;
}
