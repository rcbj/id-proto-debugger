// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/jwks.tsp
//
// The browser storage keys client/src/jwks.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/jwks.js")
model JwksKeys {
  @storageKey(#{ area: "local", class: "ordinary" })
  authorization_endpoint: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  authorization_grant_type: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  jwks_endpoint: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  scope: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  token_endpoint: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  token_scope: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  token_scope_edited: unknown;
}
