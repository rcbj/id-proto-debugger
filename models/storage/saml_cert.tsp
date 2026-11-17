// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/saml_cert.tsp
//
// The browser storage keys client/src/saml_cert.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/saml_cert.js")
model SamlCertKeys {
  @storageKey(#{ area: "local", class: "ordinary" })
  samltools_saml_signer_cert: unknown;
}
