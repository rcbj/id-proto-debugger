// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/gnap.tsp
//
// The browser storage keys client/src/gnap.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/gnap.js")
model GnapKeys {
  @storageKey(#{ area: "local", class: "output" })
  gnap_access_token: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  gnap_mtls_key: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  gnap_private_jwk: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  gnap_state: unknown;
}
