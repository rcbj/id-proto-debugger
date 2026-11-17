// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/kerberos_panes.tsp
//
// The browser storage keys client/src/kerberos_panes.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/kerberos_panes.js")
model KerberosPanesKeys {
  @storageKey(#{ area: "local", class: "output" })
  krb_ccache: unknown;

  @storageKey(#{ class: "ordinary" })
  krb_deleg_target: unknown;

  @storageKey(#{ class: "ordinary" })
  krb_deleg_user: unknown;

  @storageKey(#{ class: "ordinary" })
  krb_etypes: unknown;

  @storageKey(#{ class: "ordinary" })
  krb_kdc_host: unknown;

  @storageKey(#{ class: "ordinary" })
  krb_kdc_port: unknown;

  @storageKey(#{ class: "ordinary" })
  krb_principal: unknown;

  @storageKey(#{ class: "ordinary" })
  krb_realm: unknown;

  @storageKey(#{ area: "session", class: "ordinary" })
  krb_return_to: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  krb_s4u_evidence: unknown;

  @storageKey(#{ area: "local", class: "output" })
  krb_save_ccache: unknown;

  @storageKey(#{ class: "ordinary" })
  krb_service_host: unknown;

  @storageKey(#{ class: "ordinary" })
  krb_service_port: unknown;

  @storageKey(#{ class: "ordinary" })
  krb_service_spn: unknown;

  @storageKey(#{ area: "local", class: "output" })
  krb_service_tickets: unknown;

  @storageKey(#{ class: "ordinary" })
  krb_spnego_spn: unknown;

  @storageKey(#{ class: "ordinary" })
  krb_spnego_url: unknown;

  @storageKey(#{ area: "local", class: "output" })
  krb_ticket_history: unknown;

  @storageKey(#{ class: "ordinary" })
  krb_transport: unknown;
}
