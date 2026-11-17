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

  @storageKey(#{ class: "ordinary" })
  caep_acr: unknown;

  @storageKey(#{ class: "ordinary" })
  caep_amr: unknown;

  @storageKey(#{ class: "ordinary" })
  caep_device: unknown;

  @storageKey(#{ class: "ordinary" })
  caep_initiating: unknown;

  @storageKey(#{ class: "ordinary" })
  caep_iss: unknown;

  @storageKey(#{ class: "ordinary" })
  caep_language: unknown;

  @storageKey(#{ class: "ordinary" })
  caep_reason_admin: unknown;

  @storageKey(#{ class: "ordinary" })
  caep_reason_user: unknown;

  @storageKey(#{ class: "ordinary" })
  caep_sid: unknown;

  @storageKey(#{ class: "ordinary" })
  caep_sub: unknown;

  @storageKey(#{ class: "ordinary" })
  caep_tenant: unknown;

  @storageKey(#{ class: "ordinary" })
  caep_timestamp: unknown;

  @storageKey(#{ class: "ordinary" })
  risc_credential_type: unknown;

  @storageKey(#{ class: "ordinary" })
  risc_email: unknown;

  @storageKey(#{ class: "ordinary" })
  risc_iss: unknown;

  @storageKey(#{ class: "ordinary" })
  risc_language: unknown;

  @storageKey(#{ class: "ordinary" })
  risc_new_value: unknown;

  @storageKey(#{ class: "ordinary" })
  risc_phone: unknown;

  @storageKey(#{ class: "ordinary" })
  risc_reason_admin: unknown;

  @storageKey(#{ class: "ordinary" })
  risc_reason_user: unknown;

  @storageKey(#{ class: "ordinary" })
  risc_sub: unknown;

  @storageKey(#{ class: "ordinary" })
  risc_subject_format: unknown;

  @storageKey(#{ class: "ordinary" })
  risc_timestamp: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_auth_scheme: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_base_url: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_basic_user: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_inbox_idle_minutes: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_inbox_max_kib: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_inbox_ttl_minutes: unknown;

  @storageKey(#{ class: "output" })
  ssf_operation_history: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_poll_max: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_status_reason: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_status_value: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_stream_aud: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_stream_delivery: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_stream_description: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_stream_endpoint: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_stream_format: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_stream_id: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_subject_format: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_subject_json: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_tx_alg: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_tx_aud: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_tx_endpoint: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_tx_iss: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_tx_media: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_tx_payload: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_tx_subject: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_tx_txn: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_tx_type: unknown;

  @storageKey(#{ class: "ordinary" })
  ssf_verify_state: unknown;
}
