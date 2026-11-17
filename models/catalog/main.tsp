// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/catalog/main.tsp
//
// THE PROTOCOL CATALOGUES: the rows of data a client module reads, such as
// an event vocabulary or a schema's attributes, each written once here as a
// typed `const`. models/tools/generate.mjs writes every const declared under
// this directory to client/src/catalog/<const name, lower case>.json, and the
// module requires it as "./catalog/<name>.json".
//
// EACH IS THIS PROJECT'S READING OF ITS SPECIFICATION, written from the
// specification. Nothing here reads or copies iya-sts's models: a grammar
// two ends share is a misunderstanding neither can see.
//
// A catalogue moved here only after the generated rows were shown to equal
// the literal they replaced (models/CLAUDE.md, "Catalogues").

import "./oauth.tsp";
import "./scim.tsp";
import "./ssf_events.tsp";

namespace IdProtoDebugger.Catalog;

