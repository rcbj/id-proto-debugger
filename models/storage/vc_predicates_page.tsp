// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/vc_predicates_page.tsp
//
// The browser storage keys client/src/vc_predicates_page.js is the first
// module (alphabetically) to name. Which other modules name each one is read
// from the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/vc_predicates_page.js")
model VcPredicatesPageKeys {
  // The predicate query the page last sent to the wallet, with its nonce,
  // state and Client Identifier, so the answer coming back by fragment can be
  // checked against them. A query, not a secret.
  @storageKey(#{ class: "ordinary" })
  vcpred_request: unknown;
}
