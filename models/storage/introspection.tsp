// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/introspection.tsp
//
// The browser storage keys client/src/introspection.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/introspection.js")
model IntrospectionKeys {
  @storageKey(#{ area: "local", class: "ordinary" })
  introspection_client_id: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  introspection_endpoint: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  introspection_initiateFromBackEnd: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  introspection_initiateFromFrontEnd: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  nonce_field: unknown;

  @storageKey(#{ area: "local", class: "output" })
  operation_history: unknown;

  @storageKey(#{ area: "local", class: "output" })
  refresh_access_token: unknown;

  @storageKey(#{ area: "local", class: "output" })
  refresh_id_token: unknown;

  @storageKey(#{ area: "local", class: "output" })
  refresh_refresh_token: unknown;

  @storageKey(#{ area: "local", class: "output" })
  token_access_token: unknown;

  @storageKey(#{ area: "local", class: "output" })
  token_history: unknown;

  @storageKey(#{ area: "local", class: "output" })
  token_id_token: unknown;

  @storageKey(#{ area: "local", class: "output" })
  token_refresh_token: unknown;

  @storageKey(#{ area: "local", class: "output" })
  tokenexchange_access_token: unknown;

  @storageKey(#{ area: "local", class: "output" })
  tokenexchange_refresh_token: unknown;
}
