// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/vc_client_auth_pane.tsp
//
// The browser storage keys client/src/vc_client_auth_pane.js is the first
// module (alphabetically) to name: the VC issuance workflow's client
// authentication at the token endpoint. The settings are ordinary; the
// private keys and the Client Attestation are key material, kept only while
// sdjwtvc_save_client_key allows; the secret field is never stored. Which
// other modules name each one is read from the source by
// tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/vc_client_auth_pane.js")
model VcClientAuthPaneKeys {
  @storageKey(#{ class: "ordinary" })
  sdjwtvc_client_attestation_challenge: unknown;

  @storageKey(#{ class: "keypair", optOut: "sdjwtvc_save_client_key" })
  sdjwtvc_client_attestation: unknown;

  @storageKey(#{ class: "keypair", optOut: "sdjwtvc_save_client_key" })
  sdjwtvc_client_attester_private_jwk: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_client_auth_alg: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_client_auth_audience: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_client_auth_kid: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_client_auth_method: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_client_auth_typed: unknown;

  @storageKey(#{ class: "keypair", optOut: "sdjwtvc_save_client_key" })
  sdjwtvc_client_instance_private_jwk: unknown;

  @storageKey(#{ class: "keypair", optOut: "sdjwtvc_save_client_key" })
  sdjwtvc_client_private_jwk: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvc_save_client_key: unknown;

  @storageKey(#{ area: "none", class: "secret" })
  vc_client_secret: unknown;
}
