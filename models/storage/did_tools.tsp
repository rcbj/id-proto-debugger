// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/did_tools.tsp
//
// The browser storage keys client/src/did_tools.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/did_tools.js")
model DidToolsKeys {
  @storageKey(#{ class: "ordinary" })
  didtools_did_identifier: unknown;

  @storageKey(#{ class: "ordinary" })
  didtools_did_resolution_url: unknown;

  @storageKey(#{ class: "ordinary" })
  didtools_origin: unknown;

  @storageKey(#{ class: "ordinary" })
  vci_credential_issuer: unknown;

  // DID document members on the DID tools page: storeKey(didLib.idFor(member)).
  @storageKey(#{ class: "ordinary", prefix: true })
  didtools_did_: unknown;
}
