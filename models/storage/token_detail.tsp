// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/token_detail.tsp
//
// The browser storage keys client/src/token_detail.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/token_detail.js")
model TokenDetailKeys {
  @storageKey(#{ area: "local", class: "ordinary" })
  jwt_claims_client_id: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  jwt_clock_skew: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  jwt_expected_aud: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  jwt_expected_iss: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  jwt_expected_scope: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  jwt_purpose: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  jwt_verification_key: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  jwt_verification_type: unknown;

  @storageKey(#{ area: "local", class: "output" })
  tokenexchange_id_token: unknown;

  @storageKey(#{ class: "ordinary" })
  rfc9068_auth_context: unknown;

  @storageKey(#{ class: "ordinary" })
  rfc9068_authz_claims: unknown;

  @storageKey(#{ class: "ordinary" })
  rfc9068_decrypt: unknown;

  @storageKey(#{ class: "ordinary" })
  rfc9068_select_on_access: unknown;

  @storageKey(#{ class: "ordinary" })
  rfc9068_verify: unknown;

  @storageKey(#{ class: "ordinary" })
  rfc9068_workflow: unknown;
}
