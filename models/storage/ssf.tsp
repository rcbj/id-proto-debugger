// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/ssf.tsp
//
// The browser storage keys client/src/ssf.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/ssf.js")
model SsfKeys {
  @storageKey(#{ area: "local", class: "ordinary" })
  ssf_call_path: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  ssf_profile: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  ssf_ssl_validate: unknown;
}
