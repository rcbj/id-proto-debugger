// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/jwt_tools.tsp
//
// The browser storage keys client/src/jwt_tools.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/jwt_tools.js")
model JwtToolsKeys {
  @storageKey(#{ area: "local", class: "ordinary" })
  client_id: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  issuer: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  resource: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  token_resource: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  yesResourceCheck: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  yesResourceCheckToken: unknown;

  @storageKey(#{ class: "ordinary" })
  jwt_rfc9068_auth_context: unknown;

  @storageKey(#{ class: "ordinary" })
  jwt_rfc9068_authz_claims: unknown;

  @storageKey(#{ class: "ordinary" })
  jwt_rfc9068_decrypt: unknown;

  @storageKey(#{ class: "ordinary" })
  jwt_rfc9068_verify: unknown;

  @storageKey(#{ class: "ordinary" })
  jwt_rfc9068_workflow: unknown;
}
