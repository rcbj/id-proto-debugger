// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/bbs2023.tsp
//
// The browser storage keys client/src/bbs2023.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/bbs2023.js")
model Bbs2023Keys {
  @storageKey(#{ class: "ordinary" })
  vc_jsonld_contexts: unknown;
}
