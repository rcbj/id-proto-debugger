// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/oauth2_oidc_1.tsp
//
// The browser storage keys client/src/oauth2_oidc_1.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/oauth2_oidc_1.js")
model Oauth2Oidc1Keys {
  @storageKey(#{ area: "local", class: "ordinary" })
  PKCE_code_challenge: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  PKCE_code_challenge_method: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  PKCE_code_verifier: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  authzNumberCustomParameters: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  `authzcustomParametersCheck-no`: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  `authzcustomParametersCheck-yes`: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  client_has_secret: unknown;

  @storageKey(#{ area: "local", class: "ordinary", prefix: true })
  `customParameterName-`: unknown;

  @storageKey(#{ area: "local", class: "ordinary", prefix: true })
  `customParameterValue-`: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  dcr_client_metadata: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  debugger_initialized: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  device_authorization_endpoint: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  device_code: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  device_expires_in: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  device_interval: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  discovery_info_source: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  end_session_endpoint: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  initialized: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  metadata_source: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  noCheck: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  noCheckOIDCArtifacts: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  noResourceCheck: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  oidc_discovery_endpoint: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  oidc_userinfo_endpoint: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  redirect_uri: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  refresh_scope: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  refresh_scope_edited: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  registration_client_uri: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  registration_endpoint: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  revocation_endpoint: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  state: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  `usePKCE-no`: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  `usePKCE-yes`: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  usePKCE_no: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  usePKCE_yes: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  useRefreshToken_no: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  useRefreshToken_yes: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  user_code: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  verification_uri: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  verification_uri_complete: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  yesCheck: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  yesCheckOIDCArtifacts: unknown;

  @storageKey(#{ class: "ordinary" })
  dpop_jkt_sent: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_authorization_details: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_issuer_state: unknown;
}
