// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/token_handoff.tsp
//
// The browser storage keys client/src/token_handoff.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/token_handoff.js")
model TokenHandoffKeys {
  @storageKey(#{ class: "ordinary" })
  token_handoff_active: unknown;

  @storageKey(#{ class: "ordinary" })
  token_handoff_label: unknown;

  @storageKey(#{ class: "ordinary" })
  token_handoff_meta: unknown;

  @storageKey(#{ class: "ordinary" })
  token_handoff_return: unknown;

  @storageKey(#{ class: "ordinary" })
  token_handoff_scope: unknown;

  @storageKey(#{ class: "ordinary" })
  token_handoff_set: unknown;

  @storageKey(#{ class: "output" })
  token_handoff_token: unknown;
}
