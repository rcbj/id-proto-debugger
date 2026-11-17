// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/lib/debugger_lib.tsp
//
// THIS PROJECT'S OWN DECORATORS, and the closed value types they take. The
// stock emitters (@typespec/openapi3, @typespec/json-schema) already say
// everything a type says; these say the facts about this tree they cannot:
// which member the api forwards untouched, what a refusal reads, which
// setting governs an outbound call, which storage key holds what, and which
// variable another repository reads.
//
// EVERY ARGUMENT IS A CLOSED MODEL. An object value given a key its model
// does not declare is a compile error, so a misspelt fact stops the build
// rather than becoming a note nobody reads. A new fact is added HERE first.
//
// The implementations are debugger_lib.mjs, beside this file.

import "./debugger_lib.mjs";

using TypeSpec.Reflection;

namespace IdProtoDebugger.Lib;

// ---------------------------------------------------------------------------
// The api's HTTP surface.
// ---------------------------------------------------------------------------

/**
 * What the api answers, as `400 { error, code }`, when this member fails its
 * schema — missing, empty, the wrong type or outside its values. `code` is
 * left out of the answer when it is left out here, because several
 * endpoints have always answered `{ error }` alone and a client reads that.
 */
model RefusalFacts {
  message: string;
  code?: string;
}

/** The refusal this member is answered with. See RefusalFacts. */
extern dec refusal(target: ModelProperty, facts: valueof RefusalFacts);

/**
 * The api forwards this member as the user typed it. Its schema states the
 * JSON type and nothing about its content, and the validator must never be
 * tightened past that: a debugger has to be able to send a malformed
 * protocol message and show what the far end says about it.
 */
extern dec passthrough(target: ModelProperty);

/**
 * A check on this member, or on this operation, that the code makes and the
 * schema does not: it reads configuration, resolves a name, or parses a
 * value the way a protocol library does. Named here so the document says
 * the check exists, and so nobody adds a second one to the schema.
 */
extern dec checkedInCode(target: ModelProperty | Operation,
  what: valueof string);

// ---------------------------------------------------------------------------
// Configuration.
// ---------------------------------------------------------------------------

/**
 * An api setting every outbound call site must honour: a timeout, a cap, a
 * redirect limit or the address policy. api/CLAUDE.md's rule that none of
 * them may be dropped from a new call site reads this list.
 */
extern dec outboundPolicy(target: ModelProperty);

// ---------------------------------------------------------------------------
// Persisted browser state.
// ---------------------------------------------------------------------------

/**
 * What a storage key is.
 *
 * * `secret`   — a client secret or a password. NEVER stored, anywhere:
 *                declared so the purge on every page load knows its name.
 *                `area` must be "none".
 * * `bearer`   — a bearer token the user typed as an INPUT. sessionStorage
 *                only. `area` must be "session".
 * * `keypair`  — key material kept so a later page can use it, behind a
 *                save checkbox. `optOut` names that checkbox's key.
 * * `output`   — something the workflow obtained: a token, a response, a
 *                history.
 * * `ordinary` — configuration the user typed or chose.
 *
 * `area` is required for `secret` and `bearer`, where it is the rule. For
 * every other class it is stated only where the code fixes it: several
 * modules choose the area at run time (the Kerberos ticket cache follows a
 * preference; a history helper takes one), and a declaration that guessed
 * would be worse than none. tests/data_model.js holds every area the source
 * shows to the declared one.
 */
model StorageFacts {
  area?: "local" | "session" | "either" | "none";
  class: "secret" | "bearer" | "keypair" | "output" | "ordinary";
  optOut?: string;

  /**
   * The property name is a prefix and the key is built at run time: a
   * custom parameter row, a `.stored` field under its page's STORE_PREFIX.
   */
  prefix?: boolean;

  /**
   * The member of a stored JSON document that is a secret, where the
   * document itself is ordinary (secret_storage.js's SECRET_MEMBERS). Not a
   * storage key of its own.
   */
  member?: boolean;
}

/** Declares the storage key named by this property. */
extern dec storageKey(target: ModelProperty, facts: valueof StorageFacts);

/**
 * The client module these keys are filed under: the first, alphabetically,
 * that names them. Which modules name a key is read from the source by
 * tests/storage_inventory.js, not declared, so it cannot go stale.
 */
extern dec storageGroup(target: Model, module: valueof string);

// ---------------------------------------------------------------------------
// The embedded deployment's contract.
// ---------------------------------------------------------------------------

/**
 * One environment variable the embedded tree reads. `readBy` is the file
 * that reads it, relative to the repository root; `consumer` is set when
 * another repository sets it, which makes a rename a cross-repo change.
 */
model ContractFacts {
  readBy: string[];
  consumer?: string;
  defaultValue?: string;
}

/** Declares an environment variable of the embedded deployment. */
extern dec contractVariable(target: ModelProperty,
  facts: valueof ContractFacts);

/** One path the embedded build writes, relative to its output directory. */
model ContractPathFacts {
  path: string;
  kind: "file" | "directory";
}

/** Declares a path of the embedded tree. */
extern dec contractPath(target: ModelProperty,
  facts: valueof ContractPathFacts);
