// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/op_metadata.tsp
//
// The browser storage keys client/src/op_metadata.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/op_metadata.js")
model OpMetadataKeys {
  @storageKey(#{ area: "local", class: "ordinary" })
  discovery_info: unknown;

  @storageKey(#{ class: "ordinary" })
  acr_values_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  claim_types_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  claims_locales_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  claims_parameter_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  claims_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  code_challenge_methods_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  display_values_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  dpop_signing_alg_values_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  grant_types_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  id_token_encryption_alg_values_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  id_token_encryption_enc_values_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  id_token_signing_alg_values_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  introspection_endpoint_auth_methods_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  introspection_endpoint_auth_signing_alg_values_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  op_policy_uri: unknown;

  @storageKey(#{ class: "ordinary" })
  op_tos_uri: unknown;

  @storageKey(#{ class: "ordinary" })
  request_object_encryption_alg_values_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  request_object_encryption_enc_values_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  request_object_signing_alg_values_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  request_parameter_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  request_uri_parameter_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  require_request_uri_registration: unknown;

  @storageKey(#{ class: "ordinary" })
  response_modes_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  response_types_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  revocation_endpoint_auth_methods_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  revocation_endpoint_auth_signing_alg_values_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  scopes_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  service_documentation: unknown;

  @storageKey(#{ class: "ordinary" })
  signed_metadata: unknown;

  @storageKey(#{ class: "ordinary" })
  subject_types_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  token_endpoint_auth_methods_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  token_endpoint_auth_signing_alg_values_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  ui_locales_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  userinfo_encryption_alg_values_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  userinfo_encryption_enc_values_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  userinfo_signing_alg_values_supported: unknown;
}
