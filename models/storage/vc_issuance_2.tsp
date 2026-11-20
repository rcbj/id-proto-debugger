// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/vc_issuance_2.tsp
//
// The browser storage keys client/src/vc_issuance_2.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/vc_issuance_2.js")
model VcIssuance2Keys {
  @storageKey(#{ class: "ordinary" })
  vci_batch_credential_issuance: unknown;

  @storageKey(#{ class: "ordinary" })
  vci_credential_request_encryption: unknown;

  @storageKey(#{ class: "ordinary" })
  vci_credential_response_encryption: unknown;

  @storageKey(#{ class: "ordinary" })
  vci_deferred_credential_endpoint: unknown;

  @storageKey(#{ class: "output" })
  vci_info: unknown;
}
