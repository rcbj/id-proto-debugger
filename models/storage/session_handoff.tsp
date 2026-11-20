// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/session_handoff.tsp
//
// The browser storage keys client/src/session_handoff.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/session_handoff.js")
model SessionHandoffKeys {
  @storageKey(#{ class: "ordinary" })
  session_handoff_active: unknown;

  @storageKey(#{ class: "ordinary" })
  session_handoff_label: unknown;

  @storageKey(#{ class: "ordinary" })
  session_handoff_meta: unknown;

  @storageKey(#{ class: "ordinary" })
  session_handoff_return: unknown;

  @storageKey(#{ class: "ordinary" })
  session_handoff_session: unknown;

  @storageKey(#{ class: "ordinary" })
  session_handoff_wanted: unknown;
}
