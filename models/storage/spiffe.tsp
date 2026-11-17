// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/spiffe.tsp
//
// The browser storage keys client/src/spiffe.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/spiffe.js")
model SpiffeKeys {
  @storageKey(#{ area: "local", class: "ordinary" })
  spiffe_identity_bundle: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  spiffe_identity_cert: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  spiffe_identity_id: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  spiffe_identity_key: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  spiffe_save_identity: unknown;

  @storageKey(#{ class: "ordinary" })
  spiffe_bundle_url: unknown;

  @storageKey(#{ class: "ordinary" })
  spiffe_csr_key_alg: unknown;

  @storageKey(#{ class: "ordinary" })
  spiffe_csr_subject: unknown;

  @storageKey(#{ class: "ordinary" })
  spiffe_csr_uri: unknown;

  @storageKey(#{ class: "ordinary" })
  spiffe_id_input: unknown;

  @storageKey(#{ class: "ordinary" })
  spiffe_server_address: unknown;

  @storageKey(#{ class: "ordinary" })
  spiffe_server_id: unknown;

  @storageKey(#{ class: "ordinary" })
  spiffe_server_identity_mode: unknown;

  @storageKey(#{ class: "ordinary" })
  spiffe_server_messages: unknown;

  @storageKey(#{ class: "ordinary" })
  spiffe_server_metadata: unknown;

  @storageKey(#{ class: "ordinary" })
  spiffe_server_method: unknown;

  @storageKey(#{ class: "ordinary" })
  spiffe_server_request: unknown;

  @storageKey(#{ class: "ordinary" })
  spiffe_server_service: unknown;

  @storageKey(#{ class: "ordinary" })
  spiffe_trust_domain: unknown;

  @storageKey(#{ class: "ordinary" })
  spiffe_workload_address: unknown;

  @storageKey(#{ class: "ordinary" })
  spiffe_workload_messages: unknown;

  @storageKey(#{ class: "ordinary" })
  spiffe_workload_metadata: unknown;

  @storageKey(#{ class: "ordinary" })
  spiffe_workload_method: unknown;

  @storageKey(#{ class: "ordinary" })
  spiffe_workload_request: unknown;
}
