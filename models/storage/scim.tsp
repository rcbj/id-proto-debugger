// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/scim.tsp
//
// The browser storage keys client/src/scim.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/scim.js")
model ScimKeys {
  @storageKey(#{ area: "local", class: "output" })
  scim_auth_token: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  scim_config: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  scim_config_groups: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  scim_discovered: unknown;

  @storageKey(#{ area: "local", class: "output" })
  scim_save_token: unknown;

  @storageKey(#{ class: "ordinary" })
  scim_auth_realm: unknown;

  @storageKey(#{ class: "ordinary" })
  scim_auth_scheme: unknown;

  @storageKey(#{ class: "ordinary" })
  scim_auth_username: unknown;

  @storageKey(#{ class: "ordinary" })
  scim_base_url: unknown;

  @storageKey(#{ class: "ordinary" })
  scim_gen_count: unknown;

  @storageKey(#{ class: "ordinary" })
  scim_gen_domain: unknown;

  @storageKey(#{ class: "ordinary" })
  scim_gen_prefix: unknown;

  @storageKey(#{ class: "ordinary" })
  scim_gen_seed: unknown;

  @storageKey(#{ class: "ordinary" })
  scim_hoba_username: unknown;

  @storageKey(#{ class: "ordinary" })
  scim_last_group_id: unknown;

  @storageKey(#{ class: "ordinary" })
  scim_last_user_id: unknown;

  @storageKey(#{ class: "ordinary" })
  scim_op: unknown;

  @storageKey(#{ class: "ordinary" })
  scim_op_body: unknown;

  @storageKey(#{ class: "ordinary" })
  scim_op_id: unknown;

  @storageKey(#{ class: "ordinary" })
  scim_query_attributes: unknown;

  @storageKey(#{ class: "ordinary" })
  scim_query_count: unknown;

  @storageKey(#{ class: "ordinary" })
  scim_query_excluded_attributes: unknown;

  @storageKey(#{ class: "ordinary" })
  scim_query_filter: unknown;

  @storageKey(#{ class: "ordinary" })
  scim_query_sort_by: unknown;

  @storageKey(#{ class: "ordinary" })
  scim_query_sort_order: unknown;

  @storageKey(#{ class: "ordinary" })
  scim_query_start_index: unknown;

  @storageKey(#{ class: "ordinary" })
  scim_scenario: unknown;

  @storageKey(#{ class: "ordinary" })
  scim_scenario_count: unknown;

  @storageKey(#{ class: "ordinary" })
  scim_scenario_prefix: unknown;

  @storageKey(#{ class: "ordinary" })
  scim_scenario_seed: unknown;

  @storageKey(#{ class: "ordinary" })
  scim_ssl_validate: unknown;
}
