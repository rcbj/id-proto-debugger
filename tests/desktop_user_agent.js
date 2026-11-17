// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: desktop_user_agent.js
//
// ---------------------------------------------------------------------------
// THE USER-AGENT A DESKTOP BROWSER SENDS, written down once (#356).
//
// A product-mode iya-sts scores every interactive sign-in for risk (its #62).
// One evaluator flags an AUTOMATED CLIENT by its User-Agent — headless
// Chrome's `HeadlessChrome/…` and node's `node` alike — and a person's first
// sign-in from one scores HIGH, which the issuance policy refuses
// (STS-RISK-0016; the screen says only "Authentication failed"). Its owner
// kept that policy and decided that a suite driving a browser flow should
// look like the browser it stands for; iya-sts's own suite preloads
// tools/browser-user-agent.js for the same reason.
//
// Two callers, and the reason this is a module of its own: browser_flags.js
// hands it to Chrome, and sts_applications.js sends it on the HTTP walk that
// `authorizationCode()` makes in place of a browser. browser_flags.js loads
// selenium, which a job with no browser must not need. The string is a
// desktop Chrome on Linux, as iya-sts's preload sends.
//
// A constant and nothing else, so there is no function to enter or leave.
// ---------------------------------------------------------------------------
'use strict';

const DESKTOP_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) " +
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";

module.exports = { DESKTOP_USER_AGENT: DESKTOP_USER_AGENT };
