// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/wsfed_history.tsp
//
// The browser storage keys client/src/wsfed_history.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/wsfed_history.js")
model WsfedHistoryKeys {
  @storageKey(#{ class: "output" })
  wsfed_operation_history: unknown;
}
