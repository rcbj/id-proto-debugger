// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/saml_authnrequest.tsp
//
// The browser storage keys client/src/saml_authnrequest.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/saml_authnrequest.js")
model SamlAuthnrequestKeys {
  @storageKey(#{
    area: "local",
    class: "keypair",
    optOut: "samltools_saml_save_keypair"
  })
  samltools_saml_sp_private_key: unknown;

  @storageKey(#{
    area: "local",
    class: "keypair",
    optOut: "samltools_saml_save_keypair"
  })
  samltools_saml_sp_public_key: unknown;
}
