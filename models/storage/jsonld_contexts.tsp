// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/jsonld_contexts.tsp
//
// The browser storage keys client/src/jsonld_contexts.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/jsonld_contexts.js")
model JsonldContextsKeys {
  @storageKey(#{ class: "ordinary" })
  vc_jsonld_contexts: unknown;
}
