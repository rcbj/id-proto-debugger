// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/spiffe.tsp
//
// The browser storage keys client/src/spiffe.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/spiffe.js")
model SpiffeKeys {
  @storageKey(#{ area: "local", class: "ordinary" })
  spiffe_identity_bundle: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  spiffe_identity_cert: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  spiffe_identity_id: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  spiffe_identity_key: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  spiffe_save_identity: unknown;
}
