// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/main.tsp
//
// What the compiler is pointed at. Every namespace of the abstract data model
// is imported here, and they stay apart: an api request body is not a setting,
// and neither is a storage key. models/CLAUDE.md says what each one is and
// what reads what it generates.

import "./api/main.tsp";
import "./config/main.tsp";
import "./storage/main.tsp";
import "./contract/main.tsp";
import "./catalog/main.tsp";
