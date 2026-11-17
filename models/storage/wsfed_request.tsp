// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/wsfed_request.tsp
//
// The browser storage keys client/src/wsfed_request.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/wsfed_request.js")
model WsfedRequestKeys {
  @storageKey(#{ area: "local", class: "ordinary", prefix: true })
  wsfedtools_: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wsfedtools_wsfed_auth_type: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wsfedtools_wsfed_context: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wsfedtools_wsfed_freshness: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wsfedtools_wsfed_home_realm: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wsfedtools_wsfed_idp_entity_id: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wsfedtools_wsfed_include_wct: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wsfedtools_wsfed_include_wreq: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wsfedtools_wsfed_key_bits: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wsfedtools_wsfed_metadata_doc: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wsfedtools_wsfed_metadata_url: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wsfedtools_wsfed_policy: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wsfedtools_wsfed_realm: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wsfedtools_wsfed_reply: unknown;

  @storageKey(#{
    area: "local",
    class: "keypair",
    optOut: "wsfedtools_wsfed_save_keypair"
  })
  wsfedtools_wsfed_rp_cert: unknown;

  @storageKey(#{
    area: "local",
    class: "keypair",
    optOut: "wsfedtools_wsfed_save_keypair"
  })
  wsfedtools_wsfed_rp_private_key: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wsfedtools_wsfed_save_keypair: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wsfedtools_wsfed_sig_alg: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wsfedtools_wsfed_sig_binding: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wsfedtools_wsfed_sign_request: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wsfedtools_wsfed_signer_cert: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wsfedtools_wsfed_signin_endpoint: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wsfedtools_wsfed_signout_endpoint: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wsfedtools_wsfed_sts_endpoint: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  wsfedtools_wsfed_wreq: unknown;
}
