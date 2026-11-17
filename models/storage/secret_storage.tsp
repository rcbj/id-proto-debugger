// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/secret_storage.tsp
//
// The browser storage keys client/src/secret_storage.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/secret_storage.js")
model SecretStorageKeys {
  @storageKey(#{ area: "none", class: "secret" })
  client_secret: unknown;

  @storageKey(#{ area: "session", class: "bearer" })
  dcr_initial_access_token: unknown;

  @storageKey(#{ area: "session", class: "bearer" })
  introspection_bearer_token: unknown;

  @storageKey(#{ area: "none", class: "secret" })
  introspection_client_secret: unknown;

  @storageKey(#{ area: "none", class: "secret" })
  password: unknown;

  @storageKey(#{ area: "none", class: "secret" })
  refresh_client_secret: unknown;

  @storageKey(#{ area: "session", class: "bearer" })
  registration_access_token: unknown;

  @storageKey(#{ area: "none", class: "secret" })
  revocation_client_secret: unknown;

  @storageKey(#{ area: "none", class: "secret" })
  token_client_secret: unknown;

  @storageKey(#{ area: "none", class: "secret" })
  token_password: unknown;

  @storageKey(#{ area: "none", class: "secret" })
  tokenexchange_client_secret: unknown;

  @storageKey(#{ area: "none", class: "secret" })
  userinfo_client_secret: unknown;
}

/**
 * Members of a stored JSON document that are secrets (a dynamic client
 * registration's answer), stripped before it is stored. Not keys.
 */
@storageGroup("client/src/secret_storage.js")
model SecretMembers {
  @storageKey(#{ area: "none", class: "secret", member: true })
  client_secret: unknown;

  @storageKey(#{ area: "none", class: "secret", member: true })
  registration_access_token: unknown;
}
