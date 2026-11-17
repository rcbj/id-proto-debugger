// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/vc_issuance_1.tsp
//
// The browser storage keys client/src/vc_issuance_1.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/vc_issuance_1.js")
model VcIssuance1Keys {
  @storageKey(#{ class: "ordinary" })
  did_identifier: unknown;

  @storageKey(#{ class: "ordinary" })
  didcfg_url: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_request_mechanism: unknown;

  @storageKey(#{ class: "ordinary" })
  vci_metadata_endpoint: unknown;

  @storageKey(#{ class: "ordinary" })
  did_enabled: unknown;

  @storageKey(#{ class: "ordinary" })
  did_resolution_url: unknown;

  @storageKey(#{ class: "ordinary" })
  vci_credential_configuration_id: unknown;

  @storageKey(#{ class: "ordinary" })
  vci_format: unknown;

  // DID document members, under did.js's idFor() ("did_" + member).
  @storageKey(#{ class: "ordinary", prefix: true })
  did_: unknown;

  @storageKey(#{ class: "output" })
  didcfg_info: unknown;

  @storageKey(#{ class: "output" })
  didcfg_source: unknown;

  @storageKey(#{ class: "output" })
  vci_info_source: unknown;
}
