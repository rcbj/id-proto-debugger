// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/oauth_dpop.tsp
//
// The browser storage keys client/src/oauth_dpop.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/oauth_dpop.js")
model OauthDpopKeys {
  @storageKey(#{ class: "ordinary" })
  oauth_dpop_alg: unknown;

  @storageKey(#{ class: "ordinary" })
  oauth_dpop_enabled: unknown;

  @storageKey(#{ class: "ordinary" })
  oauth_dpop_jkt: unknown;

  @storageKey(#{ class: "ordinary" })
  oauth_dpop_jkt_sent: unknown;

  @storageKey(#{ class: "ordinary" })
  oauth_dpop_nonce: unknown;

  @storageKey(#{ class: "ordinary" })
  oauth_dpop_private_jwk: unknown;

  @storageKey(#{ class: "ordinary" })
  oauth_dpop_public_jwk: unknown;

  @storageKey(#{ class: "ordinary" })
  oauth_dpop_token_jkt: unknown;

  @storageKey(#{ class: "ordinary" })
  oauth_dpop_token_type: unknown;
}
