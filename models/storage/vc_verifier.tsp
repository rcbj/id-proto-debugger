// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/vc_verifier.tsp
//
// The browser storage keys client/src/vc_verifier.js is the first module
// (alphabetically) to name: the Verifier page's configuration (#364). None is
// a secret — the request's signing key, the response decryption key and the
// api session's secret are held for one page load and never stored. See
// models/storage/main.tsp.

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
}
