// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

// File: model_config.js
//
// ---------------------------------------------------------------------------
// A CONFIGURATION, HELD TO ITS MODEL. common/model/config.schema.json is
// generated from models/config/*.tsp and holds `ApiConfig` (api/env/*.js) and
// `ClientConfig` (client/src/env/*.js), each closed, so a misspelt key is a
// problem rather than a setting that silently keeps its default.
//
// ONE IMPLEMENTATION FOR BOTH SERVICES, which is why it is in common/: the api
// checks its file at startup (api/model_validate.js) and the client checks its
// file before envify inlines it into the bundles (client/check_config.js), and
// two readings of the same schema would be two chances to disagree.
//
// THE VALIDATOR IS THE CALLER'S. common/ is outside every node_modules in the
// tree (see common/tests.js), so this file requires no package: each caller
// passes its own ajv's 2020-12 class, which both services already depend on.
// ---------------------------------------------------------------------------

'use strict';

const fs = require('fs');
const path = require('path');

// The Entering/Leaving logging convention (see the repo-root CLAUDE.md)
// wants a `log` here, and bunyan is not reachable from this file: common/
// is outside the reach of every node_modules — see common/tests.js. So this
// is the same call shape backed by console, quiet unless MODEL_DEBUG=1. The
// methods below are the one place the convention cannot apply — a log line
// inside log.debug() is infinite recursion.
var DEBUG = process.env.MODEL_DEBUG === '1';
var LOG_TAG = '[model_config]';
var log = {
  debug: function () {
    if (!DEBUG) return;
    console.error.apply(console,
      [LOG_TAG].concat(Array.prototype.slice.call(arguments)));
  }
};

// The `x-` keyword this schema carries (models/lib/debugger_lib.mjs). An
// annotation: it changes nothing about what validates.
const ANNOTATIONS = ['x-outbound-policy'];

function schemaFile() {
  log.debug('Entering schemaFile().');
  log.debug('Leaving schemaFile().');
  return path.join(__dirname, 'model', 'config.schema.json');
}

/**
 * The problems with `config` as `which` ("ApiConfig" or "ClientConfig"),
 * one sentence each naming the key. An empty list is a configuration that
 * passes. `Ajv2020` is the caller's `require('ajv/dist/2020').default`.
 */
function configProblems(Ajv2020, config, which) {
  log.debug('Entering configProblems(). ' + which);
  const schema = JSON.parse(fs.readFileSync(schemaFile(), 'utf8'));
  const ajv = new Ajv2020({ allErrors: true, strict: true,
                            strictTypes: false });
  ANNOTATIONS.forEach(function (keyword) {
    ajv.addKeyword(keyword);
  });
  ajv.addSchema(schema);
  const validate = ajv.getSchema(which + '.json');
  if (!validate) {
    log.debug('Leaving configProblems(). No such schema.');
    throw new Error(schemaFile() + ' has no ' + which);
  }
  if (validate(config)) {
    log.debug('Leaving configProblems(). It passes.');
    return [];
  }
  const problems = validate.errors.map(function (e) {
    if (e.keyword === 'additionalProperties') {
      return '`' + e.params.additionalProperty + '` is not a setting ' +
        'this service has (a misspelling?)';
    }
    if (e.keyword === 'required') {
      return '`' + e.params.missingProperty + '` is required';
    }
    return '`' + e.instancePath.slice(1).replace(/\//g, '.') + '` ' +
      e.message;
  });
  log.debug('Leaving configProblems(). ' + problems.length + ' problems.');
  return problems.filter(function (p, i) {
    return problems.indexOf(p) === i;
  });
}

module.exports = {
  configProblems: configProblems,
  schemaFile: schemaFile
};
