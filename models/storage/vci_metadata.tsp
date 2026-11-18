// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/vci_metadata.tsp
//
// The browser storage keys client/src/vci_metadata.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/vci_metadata.js")
model VciMetadataKeys {
  @storageKey(#{ class: "ordinary" })
  vci_authorization_servers: unknown;

  @storageKey(#{ class: "ordinary" })
  vci_credential_definition: unknown;

  @storageKey(#{ class: "ordinary" })
  vci_credential_endpoint: unknown;

  @storageKey(#{ class: "ordinary" })
  vci_credential_signing_alg_values_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  vci_cryptographic_binding_methods_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  vci_display: unknown;

  @storageKey(#{ class: "ordinary" })
  vci_nonce_endpoint: unknown;

  @storageKey(#{ class: "ordinary" })
  vci_notification_endpoint: unknown;

  @storageKey(#{ class: "ordinary" })
  vci_proof_signing_alg_values_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  vci_proof_types_supported: unknown;

  @storageKey(#{ class: "ordinary" })
  vci_scope: unknown;

  @storageKey(#{ class: "ordinary" })
  vci_signed_metadata: unknown;

  @storageKey(#{ class: "ordinary" })
  vci_vct: unknown;
}
