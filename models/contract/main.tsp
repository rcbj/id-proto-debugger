// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/contract/main.tsp
//
// THE EMBEDDED DEPLOYMENT'S CONTRACT (embedded/CLAUDE.md). iya-sts serves
// this debugger's UI and forks its api from one tree that embedded/build.sh
// writes, and sets the api child's environment. "The mock STS is the
// consumer and the file is the contract": a renamed variable or path here is
// a change to the other repository too, and @contractVariable's `consumer`
// says so on each.
//
// Generated from it: common/model/embedded_contract.json, which
// embedded/build.sh ships in the tree it writes (<OUT>/common/model/), so a
// consumer can read what the tree it was handed promises; and the
// variables table in embedded/CLAUDE.md, between its model markers.
// tests/data_model.js holds every declared variable to a read of it in the
// file named, and every process.env.DEBUGGER_* read in the tree to a
// declaration.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Contract;

/** The environment iya-sts gives the api child it forks. */
model EmbeddedEnvironment {
  /** Absolute path of `<OUT>/api/env/embedded.js`. */
  @contractVariable(#{ readBy: #["api/server.js"], consumer: "iya-sts" })
  CONFIG_FILE: string;

  /**
   * Bind plain HTTP on this unix socket, whatever the configuration says
   * about https. The socket is chmod 0600 and is the access control.
   */
  @contractVariable(#{
    readBy: #["common/tls_listener.js", "api/env/embedded.js"],
    consumer: "iya-sts"
  })
  DEBUGGER_LISTEN_SOCKET: string;

  /**
   * The debugger origin, no trailing slash. uiUrl is it; apiUrl is it +
   * /api; spEntityId is it + /saml/sp; acsUrl, sloUrl and wsfedAcsUrl are
   * apiUrl + /samlacs, /samlslo and /wsfed.
   */
  @contractVariable(#{
    readBy: #["api/env/embedded.js"],
    consumer: "iya-sts"
  })
  DEBUGGER_UI_URL: string;

  /**
   * A JSON array of address ranges. Non-empty is allow-list mode, which
   * replaces the block-list; a list with no usable entry fails closed.
   */
  @contractVariable(#{
    readBy: #["api/env/embedded.js"],
    consumer: "iya-sts"
  })
  DEBUGGER_ALLOWED_ADDRESS_RANGES?: string;

  /** "true" or "false", only without an allow-list. */
  @contractVariable(#{
    readBy: #["api/env/embedded.js"],
    consumer: "iya-sts",
    defaultValue: "true"
  })
  DEBUGGER_BLOCK_PRIVATE_NETWORK_CALLS?: string;

  /** A bunyan level. */
  @contractVariable(#{
    readBy: #["api/env/embedded.js"],
    consumer: "iya-sts",
    defaultValue: "info"
  })
  DEBUGGER_LOG_LEVEL?: string;

  /** The anchor for iya-sts's own certificate. Read by node itself. */
  @contractVariable(#{ readBy: #["node"], consumer: "iya-sts" })
  NODE_EXTRA_CA_CERTS?: string;
}

/** What embedded/build.sh writes under its output directory. */
model EmbeddedTree {
  /** client/build.js, DEPLOYMENT=embedded, CONFIG_FILE=./env/embedded.js. */
  @contractPath(#{ path: "ui/", kind: "directory" })
  ui: unknown;

  /** A runnable api: `cd <OUT>/api && node server.js`. */
  @contractPath(#{ path: "api/", kind: "directory" })
  api: unknown;

  /** What the api requires as ../common/... and nothing more. */
  @contractPath(#{ path: "common/", kind: "directory" })
  common: unknown;

  /** The generated API document, configuration schema and this contract. */
  @contractPath(#{ path: "common/model/", kind: "directory" })
  generatedModel: unknown;

  /** The build's M.N.P.B, the same record as api/version.json. */
  @contractPath(#{ path: "version.json", kind: "file" })
  version: unknown;
}
