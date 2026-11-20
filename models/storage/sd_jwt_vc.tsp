// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/sd_jwt_vc.tsp
//
// The browser storage keys client/src/sd_jwt_vc.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/sd_jwt_vc.js")
model SdJwtVcKeys {
  @storageKey(#{ class: "ordinary" })
  sdjwtvc_credential: unknown;

  @storageKey(#{ class: "output" })
  sdjwtvc_credential_history: unknown;

  @storageKey(#{ class: "output" })
  sdjwtvc_credential_history_dropped: unknown;

  @storageKey(#{ class: "output" })
  sdjwtvc_credential_history_index: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_credential_meta: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_credential_offer: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_credentials: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_dpop_alg: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_dpop_binding: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_dpop_enabled: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_dpop_jkt: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_dpop_nonce: unknown;

  @storageKey(#{ class: "keypair", optOut: "sdjwtvc_save_holder_key" })
  sdjwtvc_dpop_private_jwk: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_dpop_public_jwk: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_dpop_token_jkt: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_dpop_token_type: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_flow: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_holder_jwk: unknown;

  @storageKey(#{ class: "keypair", optOut: "sdjwtvc_save_holder_key" })
  sdjwtvc_holder_private_jwk: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_issuer_site_url: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_previous_credential: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_previous_credential_meta: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_previous_holder_jwk: unknown;

  @storageKey(#{ class: "keypair", optOut: "sdjwtvc_save_holder_key" })
  sdjwtvc_previous_holder_private_jwk: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_refreshed_credential: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_refreshed_credential_meta: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_refreshed_credentials: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_refreshed_holder_jwk: unknown;

  @storageKey(#{ class: "keypair", optOut: "sdjwtvc_save_holder_key" })
  sdjwtvc_refreshed_holder_private_jwk: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_return: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_save_holder_key: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_use_case: unknown;
}
