// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/spiffe_history.tsp
//
// The browser storage keys client/src/spiffe_history.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/spiffe_history.js")
model SpiffeHistoryKeys {
  @storageKey(#{ class: "output" })
  spiffe_operation_history: unknown;
}
