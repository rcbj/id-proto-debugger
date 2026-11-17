// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/scim.tsp
//
// The browser storage keys client/src/scim.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/scim.js")
model ScimKeys {
  @storageKey(#{ area: "local", class: "output" })
  scim_auth_token: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  scim_config: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  scim_config_groups: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  scim_discovered: unknown;

  @storageKey(#{ area: "local", class: "output" })
  scim_save_token: unknown;
}
