// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/config/main.tsp
//
// THE TWO SERVICES' CONFIGURATION FILES. Emitted as JSON Schema into
// common/model/config.schema.json, with additionalProperties false on both:
// a misspelt key in an env file is an error, not a setting that silently
// keeps its default. api/server.js refuses to bind on a file that fails
// ApiConfig; client/build.js refuses to bundle one that fails ClientConfig,
// before envify inlines it, so a bad file breaks the build and not a page.

import "./api_config.tsp";
import "./client_config.tsp";
