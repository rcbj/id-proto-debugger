#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: client/check_config.js
//
// ---------------------------------------------------------------------------
// THE CLIENT'S CONFIGURATION, HELD TO ITS MODEL BEFORE IT IS BAKED IN.
//
// envify inlines CONFIG_FILE into every bundle, so a misspelt key in
// client/src/env/*.js is not a startup error anywhere: it is a page that
// silently reads `undefined` for a setting somebody believes they set. This
// holds the file to common/model/config.schema.json's ClientConfig
// (models/config/client_config.tsp) and refuses the build when it does not
// match. client/build.js calls check(); client/Dockerfile runs this file.
//
//   CONFIG_FILE=./env/docker-tests.js node check_config.js
//
// CONFIG_FILE is resolved the way the bundles resolve it: against this
// directory, then against src/ (client/build.js is run with ./env/..., which
// is src/env/ in a checkout and env/ in the image).
// ---------------------------------------------------------------------------

'use strict';

const fs = require('fs');
const path = require('path');

// A build script, run before anything is bundled: console-backed, of the
// usual shape (CLAUDE.md, "Five places cannot reach bunyan").
var DEBUG = process.env.MODEL_DEBUG === '1';
var log = {
  debug: function (message) {
    if (DEBUG) {
      console.error('[check_config] ' + message);
    }
  },
  info: function (message) {
    console.error('[check_config] ' + message);
  },
  error: function (message) {
    console.error('[check_config] ERROR ' + message);
  }
};

function resolveConfigFile(configFile) {
  log.debug('Entering resolveConfigFile(). ' + configFile);
  const candidates = [path.resolve(__dirname, configFile),
                      path.resolve(__dirname, 'src', configFile)];
  const found = candidates.find(function (file) {
    return fs.existsSync(file);
  });
  if (!found) {
    log.debug('Leaving resolveConfigFile(). Not found.');
    throw new Error('CONFIG_FILE ' + configFile + ' is not ' +
                    candidates.join(' or '));
  }
  log.debug('Leaving resolveConfigFile(). ' + found);
  return found;
}

/**
 * Throws, naming every problem, when CONFIG_FILE does not match
 * ClientConfig. Returns the resolved path when it does.
 */
function check(configFile) {
  log.debug('Entering check(). ' + configFile);
  const file = resolveConfigFile(configFile);
  const modelConfig = require(path.join(__dirname, '..', 'common',
                                        'model_config.js'));
  const Ajv2020 = require('ajv/dist/2020').default;
  const problems = modelConfig.configProblems(Ajv2020, require(file),
                                              'ClientConfig');
  if (problems.length) {
    log.debug('Leaving check(). ' + problems.length + ' problems.');
    throw new Error(file + ' does not match ClientConfig ' +
      '(models/config/client_config.tsp):\n  ' + problems.join('\n  '));
  }
  log.debug('Leaving check().');
  return file;
}

if (require.main === module) {
  try {
    const file = check(process.env.CONFIG_FILE || './env/prod.js');
    log.info(file + ' matches ClientConfig.');
  } catch (e) {
    log.error(e.message);
    process.exitCode = 1;
  }
}

module.exports = { check: check };
