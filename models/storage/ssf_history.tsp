// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/ssf_history.tsp
//
// The browser storage keys client/src/ssf_history.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/ssf_history.js")
model SsfHistoryKeys {
  @storageKey(#{ class: "output" })
  ssf_message_history: unknown;

  @storageKey(#{ class: "output" })
  ssf_token_history: unknown;
}
