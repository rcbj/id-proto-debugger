// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/oauth2_oidc_2.tsp
//
// The browser storage keys client/src/oauth2_oidc_2.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/oauth2_oidc_2.js")
model Oauth2Oidc2Keys {
  @storageKey(#{ area: "local", class: "ordinary", prefix: true })
  `customTokenParameterName-`: unknown;

  @storageKey(#{ area: "local", class: "ordinary", prefix: true })
  `customTokenParameterValue-`: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  `customTokenParametersCheck-no`: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  `customTokenParametersCheck-yes`: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  last_authz_signature: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  logout_client_id: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  noResourceCheckToken: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  refresh_client_id: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  refresh_initiateFromBackEnd: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  refresh_initiateFromFrontEnd: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  refresh_iteration: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  refresh_post_auth_style: unknown;

  @storageKey(#{ area: "local", class: "output" })
  refresh_token_used: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  revocation_initiateFromBackEnd: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  revocation_initiateFromFrontEnd: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  revocation_post_auth_style: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  tokenNumberCustomParameters: unknown;

  @storageKey(#{ area: "local", class: "output" })
  token_access_token_type: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  token_authorization_details: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  token_client_id: unknown;

  @storageKey(#{ area: "local", class: "output" })
  token_history_active_index: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  token_initialize: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  token_initiateFromBackEnd: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  token_initiateFromFrontEnd: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  token_post_auth_style: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  token_redirect_uri: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  token_username: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  tokenexchange_initiateFromBackEnd: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  tokenexchange_initiateFromFrontEnd: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  tokenexchange_post_auth_style: unknown;
}
