// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/smartcard.tsp
//
// The browser storage keys client/src/smartcard.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/smartcard.js")
model SmartcardKeys {
  @storageKey(#{ class: "ordinary" })
  smartcard_transport: unknown;

  @storageKey(#{ class: "keypair", optOut: "sc_save_oath_secret" })
  sc_oath_secret: unknown;

  @storageKey(#{ class: "keypair", optOut: "sc_save_otp_key" })
  sc_otp_aes_key: unknown;

  @storageKey(#{ class: "keypair", optOut: "sc_save_api_key" })
  sc_otp_api_key: unknown;

  @storageKey(#{ class: "ordinary" })
  sc_save_api_key: unknown;

  @storageKey(#{ class: "ordinary" })
  sc_save_oath_secret: unknown;

  @storageKey(#{ class: "ordinary" })
  sc_save_otp_key: unknown;
}
