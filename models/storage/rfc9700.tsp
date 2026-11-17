// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/rfc9700.tsp
//
// The browser storage keys client/src/rfc9700.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/rfc9700.js")
model Rfc9700Keys {
  @storageKey(#{ class: "ordinary" })
  rfc9700_mode: unknown;

  @storageKey(#{ class: "ordinary" })
  rfc9700_spent: unknown;

  @storageKey(#{ class: "ordinary" })
  rfc9700_transaction: unknown;
}
