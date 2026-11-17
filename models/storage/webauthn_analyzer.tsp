// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/webauthn_analyzer.tsp
//
// The browser storage keys client/src/webauthn_analyzer.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/webauthn_analyzer.js")
model WebauthnAnalyzerKeys {
  @storageKey(#{ area: "local", class: "ordinary" })
  webauthn_analyzer_input: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  webauthn_analyzer_keys: unknown;
}
