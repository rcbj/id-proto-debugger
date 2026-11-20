// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/vp_protocols.tsp
//
// The browser storage keys client/src/vp_protocols.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/vp_protocols.js")
model VpProtocolsKeys {
  @storageKey(#{ class: "ordinary" })
  sdjwtvp_protocol: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvp_siop_subject_syntax: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvp_x509_trust_anchor: unknown;
}
