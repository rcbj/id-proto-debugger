// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/wstrust_response.tsp
//
// The browser storage keys client/src/wstrust_response.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/wstrust_response.js")
model WstrustResponseKeys {
  @storageKey(#{ area: "local", class: "ordinary" })
  wstrust_last_exchange: unknown;

  @storageKey(#{
    area: "local",
    class: "keypair",
    optOut: "wstrust_wst_save_keypair"
  })
  wstrust_wst_sp_private_key: unknown;
}
