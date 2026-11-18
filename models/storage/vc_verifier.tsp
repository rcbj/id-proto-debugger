// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/vc_verifier.tsp
//
// The browser storage keys client/src/vc_verifier.js is the first module
// (alphabetically) to name: the Verifier page's configuration (#364), and
// its identity (#470, B4). The response decryption key, each request's leaf
// key and the api session's secret are held for one page load and never
// stored. The identity — the root CA, the attester and the request key a
// wallet is given to trust this Verifier — is key material, kept only while
// vpv_save_identity is not "0". See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/vc_verifier.js")
model VcVerifierKeys {
  @storageKey(#{ area: "local", class: "ordinary" })
  vpv_binding: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  vpv_claims: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  vpv_client_prefix: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  vpv_dcql: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  vpv_delivery: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  vpv_format: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  vpv_query_id: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  vpv_redirect_uri: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  vpv_response_mode: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  vpv_scheme: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  vpv_type: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  vpv_client_id_typed: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  vpv_dc_signed: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  vpv_trust_anchors: unknown;

  // "1" or "0": issuer metadata, DID documents and status lists fetched
  // through the api's POST /oid4vp/call (#470, B3). Absent is the default,
  // on wherever there is an api.
  @storageKey(#{ area: "local", class: "ordinary" })
  vpv_fetch_via_api: unknown;

  // The base a wallet reaches the api at, sent as publicBaseUrl on
  // POST /oid4vp/verifier (#470, B5). Empty is the api's own choice.
  @storageKey(#{ area: "local", class: "ordinary" })
  vpv_public_base_url: unknown;

  // "1" or "0": keep the Verifier's identity across runs. Absent or "1"
  // keeps it; only "0" stops it, and removes vpv_identity on the spot.
  @storageKey(#{ area: "local", class: "ordinary" })
  vpv_save_identity: unknown;

  // The Verifier's identity as one JSON document
  // (vp_verifier.js verifierIdentityFile()): the root CA's certificate and
  // private JWK, the attester's iss and private JWK, the request key's
  // private JWK. Removed whenever vpv_save_identity is "0"
  // (client/src/vc_verifier.js).
  @storageKey(#{ area: "local", class: "keypair",
                 optOut: "vpv_save_identity" })
  vpv_identity: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  vpv_issuer_bindings: unknown;
}
