// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/lib/debugger_lib.mjs
//
// The implementations of debugger_lib.tsp's decorators, and the one reader
// of what they recorded. A decorator here does one of two things: it puts
// an `x-` extension on the type, where the stock emitter writes it into the
// document unchanged, or it records a fact in a state map that
// models/tools/generate.mjs reads after the compile and writes as JSON.
//
// Nothing in this file decides anything about a value. The checks on the
// facts as a whole — a secret that claims an area, a keypair with no
// opt-out — are checkFacts() in generate.mjs, after every decorator ran.

import { setExtension as setOpenApiExtension } from "@typespec/openapi";
import { setExtension as setJsonSchemaExtension } from
  "@typespec/json-schema";

// This file is loaded by the TypeSpec compiler, which is not this tree's
// code and has no bunyan; it runs at build time only. A console-backed
// logger of the usual shape, quiet unless MODEL_DEBUG=1.
const DEBUG = process.env.MODEL_DEBUG === "1";
const log = {
  debug: function (message) {
    if (DEBUG) {
      console.error("[debugger_lib] " + message);
    }
  }
};

const KEYS = {
  storageKey: Symbol.for("IdProtoDebugger.Lib.storageKey"),
  storageGroup: Symbol.for("IdProtoDebugger.Lib.storageGroup"),
  contractVariable: Symbol.for("IdProtoDebugger.Lib.contractVariable"),
  contractPath: Symbol.for("IdProtoDebugger.Lib.contractPath"),
  outboundPolicy: Symbol.for("IdProtoDebugger.Lib.outboundPolicy")
};

function refusal(context, target, facts) {
  log.debug("Entering refusal(). " + target.name);
  setOpenApiExtension(context.program, target, "x-refusal", facts);
  log.debug("Leaving refusal().");
}

function passthrough(context, target) {
  log.debug("Entering passthrough(). " + target.name);
  setOpenApiExtension(context.program, target, "x-passthrough", true);
  log.debug("Leaving passthrough().");
}

function checkedInCode(context, target, what) {
  log.debug("Entering checkedInCode(). " + target.name);
  setOpenApiExtension(context.program, target, "x-checked-in-code", what);
  log.debug("Leaving checkedInCode().");
}

function outboundPolicy(context, target) {
  log.debug("Entering outboundPolicy(). " + target.name);
  setJsonSchemaExtension(context.program, target, "x-outbound-policy", true);
  context.program.stateSet(KEYS.outboundPolicy).add(target);
  log.debug("Leaving outboundPolicy().");
}

function storageKey(context, target, facts) {
  log.debug("Entering storageKey(). " + target.name);
  context.program.stateMap(KEYS.storageKey).set(target, facts);
  log.debug("Leaving storageKey().");
}

function storageGroup(context, target, module) {
  log.debug("Entering storageGroup(). " + target.name);
  context.program.stateMap(KEYS.storageGroup).set(target, module);
  log.debug("Leaving storageGroup().");
}

function contractVariable(context, target, facts) {
  log.debug("Entering contractVariable(). " + target.name);
  context.program.stateMap(KEYS.contractVariable).set(target, facts);
  log.debug("Leaving contractVariable().");
}

function contractPath(context, target, facts) {
  log.debug("Entering contractPath(). " + target.name);
  context.program.stateMap(KEYS.contractPath).set(target, facts);
  log.debug("Leaving contractPath().");
}

export const $decorators = {
  "IdProtoDebugger.Lib": {
    refusal: refusal,
    passthrough: passthrough,
    checkedInCode: checkedInCode,
    outboundPolicy: outboundPolicy,
    storageKey: storageKey,
    storageGroup: storageGroup,
    contractVariable: contractVariable,
    contractPath: contractPath
  }
};

/**
 * Everything the decorators recorded, as plain maps keyed by the TypeSpec
 * type they decorated. Read by generate.mjs once the compile has finished.
 */
export function readFacts(program) {
  log.debug("Entering readFacts().");
  const facts = {
    storageKeys: program.stateMap(KEYS.storageKey),
    storageGroups: program.stateMap(KEYS.storageGroup),
    contractVariables: program.stateMap(KEYS.contractVariable),
    contractPaths: program.stateMap(KEYS.contractPath),
    outboundPolicy: program.stateSet(KEYS.outboundPolicy)
  };
  log.debug("Leaving readFacts().");
  return facts;
}
