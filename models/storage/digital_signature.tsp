// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/digital_signature.tsp
//
// The browser storage keys client/src/digital_signature.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/digital_signature.js")
model DigitalSignatureKeys {
  @storageKey(#{ area: "local", class: "ordinary" })
  saml_cert_view: unknown;
}
