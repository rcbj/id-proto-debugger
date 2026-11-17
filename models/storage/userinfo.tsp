// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/userinfo.tsp
//
// The browser storage keys client/src/userinfo.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/userinfo.js")
model UserinfoKeys {
  @storageKey(#{ area: "local", class: "ordinary" })
  userinfo_claims: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  userinfo_endpoint: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  userinfo_method: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  userinfo_scope: unknown;

  @storageKey(#{ class: "ordinary" })
  userinfo_expected_audience: unknown;

  @storageKey(#{ class: "ordinary" })
  userinfo_expected_issuer: unknown;

  @storageKey(#{ class: "ordinary" })
  userinfo_jwks: unknown;

  @storageKey(#{ class: "ordinary" })
  userinfo_jwks_source: unknown;
}
