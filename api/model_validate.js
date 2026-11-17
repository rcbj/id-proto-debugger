// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: api/model_validate.js
//
// ---------------------------------------------------------------------------
// THE API DOCUMENT, ENFORCED. common/model/openapi.json is generated from
// models/api/*.tsp; this builds a request validator for every operation in
// it and, where `validateResponses` is on, holds every answer to it.
//
// A route opts in by naming its operation:
//
//   app.post('/ldap/bind', model.route('ldapBind'), handler);
//
// and from then on what that route accepts is what the document says, which
// is the point: the document a caller reads and the check a request meets
// are one declaration (models/CLAUDE.md).
//
// WHAT A REFUSAL READS. A member that fails its schema is answered
// `400 { error, code }`. A member with `x-refusal` is answered with exactly
// that message (and code, if it has one) — that is how a route keeps the
// sentence it has always answered with. Any other member is answered with
// `code: "EMODELREQUEST"` and a sentence naming the member. When several
// members fail, the FIRST in the document's order wins, because that is the
// order the handlers checked them in.
//
// IT REFUSES A KEYWORD IT DOES NOT UNDERSTAND. Ajv runs in strict mode, so a
// schema keyword nobody registered stops the api at startup rather than
// being ignored — a validator that skipped one would accept what the
// document forbids.
//
// A LEAF: ajv and the two generated files, nothing of the api's.
// ---------------------------------------------------------------------------

'use strict';

const fs = require('fs');
const path = require('path');
const Ajv2020 = require('ajv/dist/2020').default;

var bunyan = require('bunyan');
var log = bunyan.createLogger({
  name: 'model_validate',
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || 'info';
    } catch (e) {
      return 'info';
    }
  })()
});

// The `x-` keywords this tree's decorators write (models/lib). Annotations
// only: none of them changes what validates.
const ANNOTATIONS = ['x-refusal', 'x-passthrough', 'x-checked-in-code',
                     'x-outbound-policy'];

const COMPONENTS_ID = 'components.json';

// Hot path: a format check runs once per numeric member of every request,
// so these one-line predicates carry no log lines (CLAUDE.md, the hot-path
// exception).
const NUMBER_FORMATS = {
  int8: function (n) {
    return Number.isInteger(n) && n >= -128 && n <= 127;
  },
  int16: function (n) {
    return Number.isInteger(n) && n >= -32768 && n <= 32767;
  },
  int32: function (n) {
    return Number.isInteger(n) && n >= -2147483648 && n <= 2147483647;
  },
  int64: function (n) {
    return Number.isSafeInteger(n);
  },
  uint8: function (n) {
    return Number.isInteger(n) && n >= 0 && n <= 255;
  },
  uint16: function (n) {
    return Number.isInteger(n) && n >= 0 && n <= 65535;
  },
  uint32: function (n) {
    return Number.isInteger(n) && n >= 0 && n <= 4294967295;
  },
  float: function (n) {
    return Number.isFinite(n);
  },
  double: function (n) {
    return Number.isFinite(n);
  }
};

/**
 * Where common/model/ is: beside the api in a checkout (../common/model) and
 * in the api image (/usr/src/common/model, which is ../common from
 * /usr/src/app). One rule for both layouts, like tls_listener.js's.
 */
function modelDir() {
  log.debug('Entering modelDir().');
  log.debug('Leaving modelDir().');
  return path.join(__dirname, '..', 'common', 'model');
}

function readModelFile(name) {
  log.debug('Entering readModelFile(). ' + name);
  const file = path.join(modelDir(), name);
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (e) {
    log.debug('Leaving readModelFile(). Unreadable.');
    throw new Error('Cannot read ' + file + ' (' + e.code + '). It is ' +
      'generated from models/ and committed; a tree without it is ' +
      'incomplete. See models/CLAUDE.md.');
  }
  log.debug('Leaving readModelFile().');
  return JSON.parse(text);
}

function newAjv() {
  log.debug('Entering newAjv().');
  const ajv = new Ajv2020({
    allErrors: true,
    strict: true,
    // anyOf over primitive types is how the emitter writes `string | null`,
    // which strictTypes would warn about on every compile.
    strictTypes: false,
    strictTuples: false
  });
  ANNOTATIONS.forEach(function (keyword) {
    ajv.addKeyword(keyword);
  });
  // OpenAPI's numeric formats, which the emitter writes for int32, int64,
  // float32 and float64. Each is held to what its name says; a format no
  // one registered stops the compile, like an unknown keyword.
  Object.keys(NUMBER_FORMATS).forEach(function (name) {
    ajv.addFormat(name, { type: 'number', validate: NUMBER_FORMATS[name] });
  });
  log.debug('Leaving newAjv().');
  return ajv;
}

// "#/components/schemas/X" means the document's root, which a schema
// compiled on its own does not have. Every component goes into one schema of
// its own instead, and each reference is pointed at it.
function retarget(node) {
  log.debug('Entering retarget().');
  if (Array.isArray(node)) {
    log.debug('Leaving retarget(). An array.');
    return node.map(retarget);
  }
  if (!node || typeof node !== 'object') {
    log.debug('Leaving retarget(). A leaf.');
    return node;
  }
  const out = {};
  Object.keys(node).forEach(function (key) {
    const value = node[key];
    if (key === '$ref' && typeof value === 'string' &&
        value.indexOf('#/components/schemas/') === 0) {
      out[key] = COMPONENTS_ID + '#/$defs/' +
        value.slice('#/components/schemas/'.length);
    } else {
      out[key] = retarget(value);
    }
  });
  log.debug('Leaving retarget().');
  return out;
}

function resolveComponent(doc, schema) {
  log.debug('Entering resolveComponent().');
  if (schema && typeof schema.$ref === 'string' &&
      schema.$ref.indexOf('#/components/schemas/') === 0) {
    const name = schema.$ref.slice('#/components/schemas/'.length);
    log.debug('Leaving resolveComponent(). ' + name);
    return doc.components.schemas[name];
  }
  log.debug('Leaving resolveComponent(). Inline.');
  return schema;
}

function jsonSchemaOf(content) {
  log.debug('Entering jsonSchemaOf().');
  const json = content && content['application/json'];
  log.debug('Leaving jsonSchemaOf().');
  return json ? json.schema : null;
}

/**
 * Every operation in the document, by operationId: its request validator,
 * the order and refusals of its top-level members, and its response schemas
 * (compiled on first use).
 */
function indexOperations(doc, ajv) {
  log.debug('Entering indexOperations().');
  const operations = {};
  Object.keys(doc.paths || {}).forEach(function (route) {
    const item = doc.paths[route];
    Object.keys(item).forEach(function (method) {
      const op = item[method];
      if (!op || !op.operationId) {
        return;
      }
      const entry = {
        operationId: op.operationId,
        method: method.toUpperCase(),
        path: route,
        request: null,
        order: [],
        refusals: {},
        responses: {},
        compiled: {}
      };
      const body = op.requestBody && jsonSchemaOf(op.requestBody.content);
      if (body) {
        entry.request = ajv.compile(retarget(body));
        const resolved = resolveComponent(doc, body) || {};
        const properties = resolved.properties || {};
        entry.order = Object.keys(properties);
        entry.required = resolved.required || [];
        entry.order.forEach(function (name) {
          if (properties[name]['x-refusal']) {
            entry.refusals[name] = properties[name]['x-refusal'];
          }
        });
      }
      Object.keys(op.responses || {}).forEach(function (status) {
        entry.responses[status] = jsonSchemaOf(op.responses[status].content);
      });
      operations[op.operationId] = entry;
    });
  });
  log.debug('Leaving indexOperations(). ' + Object.keys(operations).length);
  return operations;
}

// The member an ajv error is about, and the path to the value that failed.
function memberOf(error) {
  log.debug('Entering memberOf().');
  const segments = error.instancePath.split('/').slice(1);
  if (error.keyword === 'required') {
    segments.push(error.params.missingProperty);
  }
  log.debug('Leaving memberOf().');
  return { member: segments[0] || '', path: segments.join('.') };
}

function describe(errors) {
  log.debug('Entering describe().');
  const required = errors.find(function (e) {
    return e.keyword === 'required';
  });
  if (required) {
    log.debug('Leaving describe(). required');
    return 'is required';
  }
  const types = [];
  errors.forEach(function (e) {
    if (e.keyword === 'type') {
      [].concat(e.params.type).forEach(function (t) {
        if (types.indexOf(t) === -1) {
          types.push(t);
        }
      });
    }
  });
  const other = errors.find(function (e) {
    return e.keyword !== 'type' && e.keyword !== 'anyOf';
  });
  if (other) {
    log.debug('Leaving describe(). ' + other.keyword);
    return other.message;
  }
  if (types.length) {
    log.debug('Leaving describe(). type');
    return 'must be ' + types.map(function (t) {
      return t === 'null' ? 'null' : 'a JSON ' + t;
    }).join(' or ');
  }
  log.debug('Leaving describe(). Fallback.');
  return 'does not match the document';
}

/**
 * The one answer for a body that failed its schema: the first failing
 * member in the document's order, with its own refusal if it declares one.
 */
function chooseRefusal(op, errors) {
  log.debug('Entering chooseRefusal(). ' + op.operationId);
  const byMember = {};
  errors.forEach(function (error) {
    const where = memberOf(error);
    (byMember[where.member] = byMember[where.member] || []).push(
      Object.assign({ path: where.path }, error));
  });
  const members = Object.keys(byMember).sort(function (a, b) {
    const ia = op.order.indexOf(a);
    const ib = op.order.indexOf(b);
    return (ia === -1 ? Infinity : ia) - (ib === -1 ? Infinity : ib);
  });
  let member = members[0];
  if (member === '') {
    // The body itself is the wrong shape (an array, a string). That is the
    // first required member missing, in every sense a handler could tell.
    member = (op.required && op.required[0]) || '';
  }
  const own = op.refusals[member];
  if (own) {
    const answer = { error: own.message };
    if (own.code) {
      answer.code = own.code;
    }
    log.debug('Leaving chooseRefusal(). The member\'s own refusal.');
    return answer;
  }
  const found = byMember[member] || byMember[''] || [];
  const deepest = found.reduce(function (a, e) {
    return e.path.length > a.length ? e.path : a;
  }, member);
  log.debug('Leaving chooseRefusal(). The model\'s refusal.');
  return {
    error: 'Refusing the request: `' + (deepest || 'the body') + '` ' +
      describe(found) + '. GET /api-docs describes what ' + op.operationId +
      ' takes.',
    code: 'EMODELREQUEST'
  };
}

/**
 * The model, loaded. `options.validateResponses` turns on the record of
 * answers the document does not describe.
 */
function createModel(options) {
  log.debug('Entering createModel().');
  const settings = options || {};
  // `document` is for tests/data_model.js, which hands in a document with a
  // keyword nobody registered and requires this to refuse it.
  const doc = settings.document || readModelFile('openapi.json');
  const ajv = newAjv();
  ajv.addSchema({ $id: COMPONENTS_ID,
                  $defs: retarget((doc.components || {}).schemas || {}) });
  const operations = indexOperations(doc, ajv);
  const validateResponses = settings.validateResponses === true;
  const gaps = new Map();

  function recordGap(op, status, instancePath, keyword, message) {
    log.debug('Entering recordGap(). ' + op.operationId);
    // Array positions are folded, so a hundred entries with the same
    // missing member are one gap counted a hundred times.
    const where = instancePath.replace(/\/\d+(?=\/|$)/g, '/*');
    const key = [op.operationId, status, where, keyword].join('|');
    const gap = gaps.get(key);
    if (gap) {
      gap.count = gap.count + 1;
    } else {
      gaps.set(key, { operationId: op.operationId, status: status,
                      instancePath: where, keyword: keyword,
                      message: message, count: 1 });
      log.warn('MODEL GAP ' + op.operationId + ' ' + status + ': ' +
               (where || '/') + ' ' + keyword + ' (' + message + ')');
    }
    log.debug('Leaving recordGap().');
  }

  /**
   * Where an answer and its operation's documented response disagree, as
   * `{ instancePath, keyword, message }` each. Empty is an answer the
   * document describes.
   */
  function answerProblems(op, status, payload) {
    log.debug('Entering answerProblems(). ' + op.operationId + ' ' + status);
    const code = String(status);
    if (!Object.prototype.hasOwnProperty.call(op.responses, code)) {
      log.debug('Leaving answerProblems(). Undocumented status.');
      return [{ instancePath: '', keyword: 'status',
                message: 'the document has no ' + code +
                  ' answer for this operation' }];
    }
    const schema = op.responses[code];
    if (!schema) {
      log.debug('Leaving answerProblems(). No body documented.');
      return [];
    }
    if (!op.compiled[code]) {
      op.compiled[code] = ajv.compile(retarget(schema));
    }
    const validate = op.compiled[code];
    if (validate(payload)) {
      log.debug('Leaving answerProblems(). It matches.');
      return [];
    }
    log.debug('Leaving answerProblems(). ' + validate.errors.length);
    return validate.errors.map(function (e) {
      return { instancePath: e.instancePath, keyword: e.keyword,
               message: e.message };
    });
  }

  function checkAnswer(op, status, payload) {
    log.debug('Entering checkAnswer(). ' + op.operationId + ' ' + status);
    answerProblems(op, status, payload).forEach(function (p) {
      recordGap(op, status, p.instancePath, p.keyword, p.message);
    });
    log.debug('Leaving checkAnswer().');
  }

  /**
   * The operation a method and a concrete path are, by the document's path
   * templates (`/ssf/receiver/{id}`), or null.
   */
  function operationFor(method, concretePath) {
    log.debug('Entering operationFor(). ' + method + ' ' + concretePath);
    const wanted = String(method).toUpperCase();
    const found = Object.keys(operations).map(function (id) {
      return operations[id];
    }).find(function (op) {
      if (op.method !== wanted) {
        return false;
      }
      const pattern = new RegExp('^' + op.path.replace(/[.*+?^$()|[\]\\]/g,
        '\\$&').replace(/\{[^}]+\}/g, '[^/]+') + '$');
      return pattern.test(concretePath);
    });
    log.debug('Leaving operationFor().');
    return found || null;
  }

  function operation(operationId) {
    log.debug('Entering operation(). ' + operationId);
    const op = operations[operationId];
    if (!op) {
      log.debug('Leaving operation(). Unknown.');
      throw new Error('The API document has no operation ' + operationId +
        '. Add it to models/api/ and run models/tools/generate.mjs.');
    }
    log.debug('Leaving operation().');
    return op;
  }

  /**
   * Express middleware for one operation: the request is held to the
   * document before the handler runs, and the answer after it, when
   * validateResponses is on. Throws at startup for an unknown operation,
   * so a typo is a process that will not start rather than a route that is
   * never checked.
   */
  function route(operationId) {
    log.debug('Entering route(). ' + operationId);
    const op = operation(operationId);
    log.debug('Leaving route().');
    return function modelRoute(req, res, next) {
      log.debug('Entering modelRoute(). ' + operationId);
      if (validateResponses) {
        const send = res.json.bind(res);
        res.json = function modelJson(payload) {
          log.debug('Entering modelJson(). ' + operationId);
          try {
            checkAnswer(op, res.statusCode, payload);
          } catch (e) {
            log.error('The answer to ' + operationId + ' could not be ' +
                      'checked: ' + e.message);
          }
          log.debug('Leaving modelJson().');
          return send(payload);
        };
      }
      if (op.request) {
        const body = req.body === undefined ? {} : req.body;
        if (!op.request(body)) {
          const answer = chooseRefusal(op, op.request.errors);
          log.info(op.method + ' ' + op.path + ' refused by the model: ' +
                   answer.error);
          log.debug('Leaving modelRoute(). Refused.');
          return res.status(400).json(answer);
        }
      }
      log.debug('Leaving modelRoute().');
      return next();
    };
  }

  function gapsHandler(req, res) {
    log.debug('Entering gapsHandler().');
    if (!validateResponses) {
      log.debug('Leaving gapsHandler(). Off.');
      return res.status(404).json({
        error: 'validateResponses is off in this api\'s configuration, so ' +
          'no record of answers is kept.' });
    }
    log.debug('Leaving gapsHandler().');
    return res.status(200).json({
      validateResponses: true,
      gaps: Array.from(gaps.values())
    });
  }

  /**
   * The document as this process serves it: its version is the build's,
   * and its server is wherever the api is reached, which the model cannot
   * know.
   */
  function document(version, serverUrl) {
    log.debug('Entering document().');
    const copy = JSON.parse(JSON.stringify(doc));
    copy.info.version = version || copy.info.version;
    if (serverUrl) {
      copy.servers = [{ url: serverUrl,
                        description: 'This api, as it is reached here.' }];
    }
    log.debug('Leaving document().');
    return copy;
  }

  log.debug('Leaving createModel(). ' + Object.keys(operations).length +
            ' operations.');
  return {
    route: route,
    gapsHandler: gapsHandler,
    document: document,
    operations: operations,
    operationFor: operationFor,
    answerProblems: function answerProblemsFor(operationId, status,
                                               payload) {
      log.debug('Entering answerProblemsFor(). ' + operationId);
      const problems = answerProblems(operation(operationId), status,
                                      payload);
      log.debug('Leaving answerProblemsFor().');
      return problems;
    },
    validateResponses: validateResponses,
    chooseRefusal: chooseRefusal
  };
}

/**
 * Hold a configuration object to config.schema.json's `ApiConfig` or
 * `ClientConfig`. Returns the problems, one sentence each, naming the key;
 * an empty list is a configuration that passes. The one implementation is
 * common/model_config.js, which the client's build uses too.
 */
function checkConfig(config, which) {
  log.debug('Entering checkConfig(). ' + which);
  const modelConfig = require(path.join(__dirname, '..', 'common',
                                        'model_config.js'));
  const problems = modelConfig.configProblems(Ajv2020, config, which);
  log.debug('Leaving checkConfig(). ' + problems.length + ' problems.');
  return problems;
}

module.exports = {
  createModel: createModel,
  checkConfig: checkConfig,
  modelDir: modelDir
};
