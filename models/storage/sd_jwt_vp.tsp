// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/sd_jwt_vp.tsp
//
// The browser storage keys client/src/sd_jwt_vp.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/sd_jwt_vp.js")
model SdJwtVpKeys {
  @storageKey(#{ class: "ordinary" })
  sdjwtvp_api_ssl_validate: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvp_presentation: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvp_request: unknown;

  @storageKey(#{ class: "output" })
  sdjwtvp_result: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvp_selected_disclosures: unknown;

  // SIOPv2 pairwise subject key pairs, one per Verifier. Kept only while
  // sdjwtvp_siop_save_pairwise is not "0"; clearing it removes them
  // (client/src/vc_presentation_2.js).
  @storageKey(#{ class: "keypair", optOut: "sdjwtvp_siop_save_pairwise" })
  sdjwtvp_siop_pairwise_keys: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvp_siop_save_pairwise: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvp_use_case: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvp_verifier_base_url: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvp_verifier_jwks_url: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvp_verifier_site_url: unknown;

  @storageKey(#{ class: "ordinary" })
  sdjwtvp_via_api: unknown;
}
