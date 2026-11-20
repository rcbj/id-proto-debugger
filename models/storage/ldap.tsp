// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/ldap.tsp
//
// The browser storage keys client/src/ldap.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/ldap.js")
model LdapKeys {
  @storageKey(#{ class: "ordinary" })
  ldap_base_dn: unknown;

  @storageKey(#{ class: "ordinary" })
  ldap_bind_dn: unknown;

  @storageKey(#{ class: "ordinary" })
  ldap_entry_attribute: unknown;

  @storageKey(#{ class: "ordinary" })
  ldap_entry_attributes: unknown;

  @storageKey(#{ class: "ordinary" })
  ldap_entry_changes: unknown;

  @storageKey(#{ class: "ordinary" })
  ldap_entry_dn: unknown;

  @storageKey(#{ class: "ordinary" })
  ldap_entry_new_rdn: unknown;

  @storageKey(#{ class: "ordinary" })
  ldap_entry_value: unknown;

  @storageKey(#{ class: "ordinary" })
  ldap_group_cn: unknown;

  @storageKey(#{ class: "ordinary" })
  ldap_group_description: unknown;

  @storageKey(#{ class: "ordinary" })
  ldap_search_attributes: unknown;

  @storageKey(#{ class: "ordinary" })
  ldap_search_base: unknown;

  @storageKey(#{ class: "ordinary" })
  ldap_search_filter: unknown;

  @storageKey(#{ class: "ordinary" })
  ldap_search_page_size: unknown;

  @storageKey(#{ class: "ordinary" })
  ldap_search_scope: unknown;

  @storageKey(#{ class: "ordinary" })
  ldap_search_size_limit: unknown;

  @storageKey(#{ class: "ordinary" })
  ldap_url: unknown;

  @storageKey(#{ class: "ordinary" })
  ldap_user_cn: unknown;

  @storageKey(#{ class: "ordinary" })
  ldap_user_given_name: unknown;

  @storageKey(#{ class: "ordinary" })
  ldap_user_mail: unknown;

  @storageKey(#{ class: "ordinary" })
  ldap_user_sn: unknown;

  @storageKey(#{ class: "ordinary" })
  ldap_user_title: unknown;

  @storageKey(#{ class: "ordinary" })
  ldap_user_uid: unknown;
}
