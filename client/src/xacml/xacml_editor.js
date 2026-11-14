// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
'use strict';
//
// File: xacml_editor.js
//
// ---------------------------------------------------------------------------
// THE GUIDED EDITOR'S GRAMMAR: WHAT MAY BE ADDED WHERE, AND HOW ONE EDIT IS
// APPLIED.
//
// This file has NO DOM and emits no HTML. It answers three questions about a
// policy model, `xacml_workbench.js` calls it, and `xacml_draw.js` draws the
// answers on the XACML page:
//
//   tree(policy)              what nodes are there, and where
//   optionsAt(policy, path)   what may legally be added AT this node
//   applyEdit(policy, ...)    do one of those things, and hand back the model
//
// Keeping it DOM-free is the same rule the rest of this directory follows, and
// here it buys something specific: the grammar is testable in node without a
// browser, a page or a form, which is how `tests/xacml_engine.js` drives the
// workbench.
//
// ---------------------------------------------------------------------------
// THE OPTIONS ARE COMPUTED BY THE CODE THAT VALIDATES THE POLICY.
//
// Every dropdown on the page is a plain `<select>` whose `<option>`s were
// computed by this file, and choosing one is a form submit that the page hands
// to `applyEdit()` and then redraws. The list of legal next elements comes
// from THE SAME CODE THAT VALIDATES THE POLICY, against the real function
// library, so the editor cannot offer something the validator will then
// refuse.
//
// ---------------------------------------------------------------------------
// A PATH IS A STRING OF SEGMENTS AND IT IS NOT AN OBJECT REFERENCE.
//
// `rules.0.target.anyOf.1.allOf.0.matches.2` names a node. It survives being
// written into an `<input type="hidden">`, which is the only state an edit
// form carries.
//
// THE CONSEQUENCE, and it is the one thing that will surprise somebody: a path
// is only valid against the document it was computed from. Remove rule 0 and
// every path naming rule 1 now means rule 0. That is why every edit redraws
// the whole tree rather than patching part of it, and why `nodeAt()` returns
// null for a path that no longer resolves instead of guessing.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// A CLASS WITH ITS DEPENDENCIES PASSED IN. `XacmlEditor` takes the logger and
// the three engine modules it reads (`xacml_model.js`, `xacml_datatypes.js`,
// `xacml_functions.js`) through its constructor. The menus and the grammar
// table are module-level constants, built at load, and are also static members
// of the class. The module exports each method as a function forwarding to
// the one instance `xacml_slot.js` holds, which is built when this module
// loads.
// ---------------------------------------------------------------------------
const helpers = require("../xacml_runtime");
const InstanceSlot = require("./xacml_slot");
const ownMembers = require("./xacml_own_members");
const model = require("./xacml_model");
const datatypes = require("./xacml_datatypes");
const functions = require("./xacml_functions");
const F1 = 'urn:oasis:names:tc:xacml:1.0:function:';
const TYPE = model.TYPE;
// The datatypes a dropdown offers, in a stable order with the common ones
// first — because an alphabetical list puts `anyURI` and `base64Binary` above
// `string`, and `string` is what nine values out of ten are.
const COMMON_TYPES = [TYPE.STRING, TYPE.BOOLEAN, TYPE.INTEGER, TYPE.DOUBLE,
    TYPE.ANYURI, TYPE.DATE, TYPE.DATETIME, TYPE.TIME];
/**
 * The attribute categories the editor offers, each with its short label,
 * the four common ones first.
 */
const CATEGORY_MENU = [
    { uri: model.CATEGORY.ACCESS_SUBJECT, label: 'access-subject' },
    { uri: model.CATEGORY.RESOURCE, label: 'resource' },
    { uri: model.CATEGORY.ACTION, label: 'action' },
    { uri: model.CATEGORY.ENVIRONMENT, label: 'environment' },
    { uri: model.CATEGORY.RECIPIENT_SUBJECT, label: 'recipient-subject' },
    { uri: model.CATEGORY.INTERMEDIARY_SUBJECT, label: 'intermediary-subject' },
    { uri: model.CATEGORY.CODEBASE, label: 'codebase' },
    { uri: model.CATEGORY.REQUESTING_MACHINE, label: 'requesting-machine' }
];
/**
 * The rule-combining algorithms the editor offers, each with a label and a
 * sentence on what it does.
 */
const RULE_ALG_MENU = [
    { uri: model.RULE_ALG.DENY_UNLESS_PERMIT, label: 'deny-unless-permit',
        what: 'Anything not permitted is denied. Cannot return ' +
          'NotApplicable or ' +
            'Indeterminate, so the answer never depends on the PEP\'s bias.' },
    { uri: model.RULE_ALG.PERMIT_UNLESS_DENY, label: 'permit-unless-deny',
        what: 'Anything not denied is permitted. The mirror, and the one to ' +
            'think twice about.' },
    { uri: model.RULE_ALG.DENY_OVERRIDES, label: 'deny-overrides',
        what: 'One Deny outranks any number of Permits. Stops at the ' +
          'first Deny, ' +
            'so a later rule\'s obligations are never collected.' },
    { uri: model.RULE_ALG.PERMIT_OVERRIDES, label: 'permit-overrides',
        what: 'One Permit outranks any number of Denies.' },
    { uri: model.RULE_ALG.FIRST_APPLICABLE, label: 'first-applicable',
        what: 'The first rule that decides anything wins. Order matters.' },
    { uri: model.RULE_ALG.ORDERED_DENY_OVERRIDES,
        label: 'ordered-deny-overrides',
        what: 'deny-overrides with the evaluation order fixed. Identical ' +
            'here, ' +
            'because this PDP always evaluates in document order.' },
    { uri: model.RULE_ALG.ORDERED_PERMIT_OVERRIDES,
        label: 'ordered-permit-overrides',
        what: 'permit-overrides with the evaluation order fixed.' }
];
// THE POLICY-COMBINING ALGORITHMS, WHICH ARE NOT THE RULE-COMBINING ONES AND
// ARE ALMOST SPELT THE SAME.
//
// `...:3.0:rule-combining-algorithm:deny-overrides` against
// `...:3.0:policy-combining-algorithm:deny-overrides` — one segment apart, and
// a PolicySet carrying the rule-combining spelling is a document that names an
// algorithm no combiner can find. That is why this is a second table rather
// than one table used in both places: the editor picks the menu from the kind
// of the node, so the wrong spelling is never on offer.
//
// `only-one-applicable` is the one that exists here and has no rule-combining
// counterpart at all, because it is about POLICIES being applicable — it is
// Indeterminate when two of them are, which is how a deployment says "these
// are meant to be disjoint and I want to hear about it when they are not".
/**
 * The policy-combining algorithms the editor offers, each with a label and
 * a sentence on what it does.
 */
const POLICY_ALG_MENU = [
    { uri: model.POLICY_ALG.DENY_UNLESS_PERMIT, label: 'deny-unless-permit',
        what: 'Anything not permitted is denied. Cannot return ' +
          'NotApplicable or ' +
            'Indeterminate, so the answer never depends on the PEP\'s bias.' },
    { uri: model.POLICY_ALG.PERMIT_UNLESS_DENY, label: 'permit-unless-deny',
        what: 'Anything not denied is permitted. The mirror, and the one to ' +
            'think twice about.' },
    { uri: model.POLICY_ALG.DENY_OVERRIDES, label: 'deny-overrides',
        what: 'One Deny outranks any number of Permits.' },
    { uri: model.POLICY_ALG.PERMIT_OVERRIDES, label: 'permit-overrides',
        what: 'One Permit outranks any number of Denies.' },
    { uri: model.POLICY_ALG.FIRST_APPLICABLE, label: 'first-applicable',
        what: 'The first child that decides anything wins. Order matters.' },
    { uri: model.POLICY_ALG.ONLY_ONE_APPLICABLE, label: 'only-one-applicable',
        what: 'Exactly one child may apply. Two applicable children is ' +
            'Indeterminate rather than a decision — the way to say that a ' +
                'set ' +
            'is meant to be disjoint and to hear about it when it is not. ' +
            'There is no rule-combining algorithm of this name.' },
    { uri: model.POLICY_ALG.ORDERED_DENY_OVERRIDES,
        label: 'ordered-deny-overrides',
        what: 'deny-overrides with the evaluation order fixed. Identical ' +
            'here, ' +
            'because this PDP always evaluates in document order.' },
    { uri: model.POLICY_ALG.ORDERED_PERMIT_OVERRIDES,
        label: 'ordered-permit-overrides',
        what: 'permit-overrides with the evaluation order fixed.' }
];
// ---------------------------------------------------------------------------
// WHAT MAY BE ADDED AT A NODE.
//
// THE TABLE IS THE GRAMMAR. Each entry is one `<option>` in that node's
// `Add ▾`, and `applyEdit()` below is the only thing that acts on them — so a
// legal move that is not in this table cannot be made, and a move in this
// table that `applyEdit()` does not handle is reported rather than silently
// doing nothing.
// ---------------------------------------------------------------------------
/**
 * The guided editor's grammar: for each kind of node, the `Add` options
 * that may be taken there. `applyEdit()` is the only thing that acts on
 * them.
 */
const ADDITIONS = {
    policy: [
        { action: 'add-rule', label: 'Rule',
            help: 'A Permit or Deny with its own Target and Condition.' },
        { action: 'add-variable', label: 'Variable definition',
            help: 'Names an expression so that several rules can share it ' +
              '— and ' +
                'so it is evaluated once per request rather than once per ' +
                    'use. ' +
                'Its scope is THIS policy: a sibling policy in the same set ' +
                'cannot see it.' },
        { action: 'add-policy-obligation', label: 'Obligation',
            help: 'Something the PEP must do when this policy decides. It ' +
                'MUST ' +
                'honour it or refuse the request.' },
        { action: 'add-policy-advice', label: 'Advice',
            help: 'Something the PEP may do. It is allowed to ignore ' +
              'this, which ' +
                'is the whole difference from an obligation.' },
        { action: 'add-target-anyof', label: 'Target clause',
            help: 'Narrows what this whole policy applies to. Every ' +
              'clause must ' +
                'match — they are ANDed.' }
    ],
    // A POLICY SET HOLDS POLICIES AND NOT RULES, which is the whole reason this
    // is a separate row rather than the list above with one thing added. Until
    // it existed the editor offered `Rule` on a policy set, accepted it, said
    // "Rule added." and wrote a document with no rule in it — because the
    // writer
    // serializes a PolicySet's `children` and never looks at `rules`. An edit
    // that is accepted and then silently discarded is the worst failure this
    // editor can have, and it is what a menu keyed only by path produced.
    policySet: [
        { action: 'add-policy', label: 'Policy',
            help: 'A policy of its own, inside this set. It gets its own ' +
                'rule-combining algorithm — the set combines the POLICIES ' +
                    'and ' +
                'each policy combines its own rules.' },
        { action: 'add-policyset', label: 'Policy set',
            help: 'A nested set. There is no depth limit.' },
        { action: 'add-policy-reference', label: 'PolicyIdReference',
            help: 'Names a policy stored SEPARATELY in the repository by its ' +
                'PolicyId. This is how a PDP reaches more than one document: ' +
                'the root is evaluated and references are resolved from the ' +
                'repository at decision time.' },
        { action: 'add-policyset-reference', label: 'PolicySetIdReference',
            help: 'The same, naming a policy set.' },
        { action: 'add-target-anyof', label: 'Target clause',
            help: 'Narrows what this whole set applies to. Every clause must ' +
                'match — they are ANDed.' },
        { action: 'add-policy-obligation', label: 'Obligation',
            help: 'Something the PEP must do when this SET decides. It MUST ' +
                'honour it or refuse the request.' },
        { action: 'add-policy-advice', label: 'Advice',
            help: 'Something the PEP may do. It is allowed to ignore this.' }
    ],
    rule: [
        { action: 'add-target-anyof', label: 'Target clause',
            help: 'Narrows what this rule applies to. Clauses are ANDed.' },
        { action: 'add-condition', label: 'Condition',
            help: 'A boolean expression evaluated after the Target ' +
              'matches. Only ' +
                'one per rule.' },
        { action: 'add-rule-obligation', label: 'Obligation',
            help: 'Fires when this rule\'s Effect is the decision.' },
        { action: 'add-rule-advice', label: 'Advice' }
    ],
    target: [
        { action: 'add-target-anyof', label: 'Target clause',
            help: 'Another clause. All of them must match.' }
    ],
    anyOf: [
        { action: 'add-allof', label: 'Alternative',
            help: 'Another alternative within this clause. ANY of them ' +
              'matching ' +
                'satisfies it — they are ORed.' }
    ],
    allOf: [
        { action: 'add-match', label: 'Match',
            help: 'A test of one attribute against one value. Every Match ' +
              'in an ' +
                'alternative must hold.' }
    ],
    expression: [
        { action: 'set-expression-apply', label: 'Function call',
            help: 'Apply a function to arguments.' },
        { action: 'set-expression-value', label: 'Literal value' },
        { action: 'set-expression-designator', label: 'Attribute',
            help: 'Reads an attribute out of the request, or out of the ' +
              'directory ' +
                'through the PIP. Returns a BAG — most functions need ' +
                'one-and-only around it.' },
        { action: 'set-expression-selector', label: 'Attribute selector',
            help: 'Reads an XPath over the CONTENT of a request category, ' +
              'rather ' +
                'than a named attribute. Also a bag. The bindings for any ' +
                'prefixes in the path travel with it.' },
        { action: 'set-expression-function', label: 'Function reference',
            help: 'Names a function WITHOUT applying it — the first ' +
              'argument of a ' +
                'higher-order function such as any-of or map. It is a value ' +
                'here, not a call.' },
        { action: 'set-expression-variable', label: 'Variable reference',
            help: 'Uses a VariableDefinition declared on this policy. ' +
                'Offered ' +
                'only where there is one to name.' }
    ],
    match: [],
    obligation: [
        { action: 'add-assignment', label: 'Attribute assignment',
            help: 'A value handed to the PEP along with the obligation.' }
    ],
    // Four kinds with nothing legal underneath them. They are here as EMPTY
    // LISTS rather than absent, because `ADDITIONS[kind] || []` would give the
    // same answer for "nothing may be added here" and "nobody has thought about
    // this kind yet", and those became different answers the moment a policy
    // set
    // was editable.
    assignment: [],
    variable: [],
    reference: [],
    combinerParameter: [],
    combinerParameterGroup: []
};
// A VariableDefinition HOLDS an expression, so what may be "added" at one is
// exactly what may be added at any expression: the definition is replaced.
// Assigned here rather than written twice in the table above, because two
// copies of that list would drift the moment a seventh expression kind
// arrived — which is how the fifth and sixth arrived to find the table saying
// four.
ADDITIONS.variable = ADDITIONS.expression.slice();
/**
 * The guided policy editor's grammar: what nodes a policy model holds, what
 * may legally be added at each, and how one edit is applied.
 *
 * It has no DOM and emits no HTML; `xacml_draw.js` draws its answers. A
 * node is named by a dotted path, valid only against the document it was
 * computed from.
 */
class XacmlEditor {
    /**
     * Builds the editor over the given dependencies.
     * @param deps - the logger and the model, datatype and function modules
     */
    constructor(deps) {
        this.deps = deps;
        deps.log.debug("Entering XacmlEditor.constructor().");
        deps.log.debug("Leaving XacmlEditor.constructor().");
    }
    /**
     * Returns the dependencies built from the real modules, for the default
     * instance.
     * @returns the editor's dependencies
     */
    static defaultDeps() {
        helpers.log.debug("Entering XacmlEditor.defaultDeps().");
        helpers.log.debug("Leaving XacmlEditor.defaultDeps().");
        return {
            log: helpers.log,
            model: model,
            datatypes: datatypes,
            functions: functions
        };
    }
    // -------------------------------------------------------------------------
    // PATHS.
    // -------------------------------------------------------------------------
    segmentsOf(path) {
        const { log } = this.deps;
        log.debug("Entering XacmlEditor.segmentsOf().");
        log.debug("Leaving XacmlEditor.segmentsOf().");
        return String(path || '').split('.').filter(function (one) {
            return one.length > 0;
        });
    }
    /**
     * Whether one step of a path names a member the node itself holds: an
     * array's index (digits, below its length) or an object's own member, never
     * one it inherits. See `nodeAt()`.
     *
     * @param node - the node the step leaves
     * @param key - the step
     * @returns true where the step may be taken
     */
    static ownStep(node, key) {
        helpers.log.debug("Entering XacmlEditor.ownStep().");
        // The rule is xacml_own_members.js's: one place, which every read
        // of a name a caller chose goes through.
        const own = ownMembers.has(node, key);
        helpers.log.debug("Leaving XacmlEditor.ownStep(). " + own);
        return own;
    }
    // Resolve a path to `{ node, parent, key }`, or null. `parent` and `key`
    // are what a REMOVE needs — you cannot delete a node from itself.
    //
    // **EVERY STEP IS AN OWN MEMBER OF THE NODE IT LEAVES, OR THE PATH DOES NOT
    // RESOLVE.** The path arrives from an edit form's hidden field, and a walk
    // written as `node[key]` follows the prototype chain: a path through
    // `__proto__` or `constructor.prototype` reaches `Object.prototype`, and
    // `node.rules = node.rules || []` there gives EVERY object on the page an
    // inherited `rules`. An index into an array is digits below its length;
    // anything else must be the node's own member.
    /**
     * Resolves a path in a policy model.
     * @param policy - the policy model
     * @param path - the dotted path, '' for the root
     * @returns `{ node, parent, key, path }`, or null when the path does not
     * resolve
     */
    nodeAt(policy, path) {
        const self = this;
        const { log } = this.deps;
        log.debug('Entering XacmlEditor.nodeAt(). path=' + path);
        const segments = self.segmentsOf(path);
        let node = policy;
        let parent = null;
        let key = null;
        for (let i = 0; i < segments.length; i += 1) {
            if (node === null || node === undefined) {
                log.debug('Leaving XacmlEditor.nodeAt(). The path does ' +
                  'not resolve.');
                return null;
            }
            parent = node;
            key = segments[i];
            if (!XacmlEditor.ownStep(node, key)) {
                log.debug('Leaving XacmlEditor.nodeAt(). Not an own member: ' +
                  key);
                return null;
            }
            node = Array.isArray(node) ? node[Number(key)] : node[key];
        }
        if (node === null || node === undefined) {
            log.debug('Leaving XacmlEditor.nodeAt(). Nothing there.');
            return null;
        }
        log.debug('Leaving XacmlEditor.nodeAt(). Resolved.');
        return { node: node, parent: parent, key: key, path: path };
    }
    // -------------------------------------------------------------------------
    // WHAT KIND OF THING SITS AT A PATH.
    //
    // Derived from the PATH rather than from the object, because the model's
    // nodes are plain objects with no type tag — an `AllOf` is
    // `{ matches: [...] }` and nothing about it says so. Reading the path is
    // unambiguous and needs no tag on every node, which would be a second thing
    // to keep in step with the reader, the writer and the ALFA parser.
    // -------------------------------------------------------------------------
    // THE NODE IS A SECOND ARGUMENT AND IT IS OPTIONAL, which is the one
    // wrinkle
    // in "derived from the path". Three kinds cannot be told apart from a path:
    // the ROOT of a document is a `Policy` or a `PolicySet` and the two accept
    // completely different children, and a `PolicySet`'s child is a Policy, a
    // nested PolicySet or a reference — all three at `children.0`. So where the
    // caller has the node it is passed and the answer is exact; where it does
    // not, the path-derived answer is returned and it is the Policy one, which
    // is
    // what every caller of the one-argument form meant before policy sets were
    // editable.
    /**
     * Names the kind of node at a path, such as 'rule', 'target', 'match' or
     * 'expression', derived from the path.
     *
     * Without the node, a document root or a policy set's child is answered as
     * 'policy'; passing the node makes 'policySet' and 'reference' exact.
     * @param path - the dotted path
     * @param node - the node at the path, where the caller has it
     * @returns the kind, 'unknown' when the path names nothing the editor knows
     */
    kindAt(path, node) {
        const self = this;
        const { log } = this.deps;
        log.debug("Entering XacmlEditor.kindAt().");
        const segments = self.segmentsOf(path);
        if (node && node.kind === 'PolicySet') {
            log.debug("Leaving XacmlEditor.kindAt().");
            return 'policySet';
        }
        if (node && (node.kind === 'PolicyIdReference' ||
            node.kind === 'PolicySetIdReference')) {
            log.debug("Leaving XacmlEditor.kindAt().");
            return 'reference';
        }
        if (!segments.length) {
            log.debug("Leaving XacmlEditor.kindAt().");
            return 'policy';
        }
        const last = segments[segments.length - 1];
        const previous = segments.length > 1 ?
            segments[segments.length - 2] : '';
        if (last === 'target') {
            log.debug("Leaving XacmlEditor.kindAt().");
            return 'target';
        }
        if (last === 'condition' || last === 'expression') {
            log.debug("Leaving XacmlEditor.kindAt().");
            return 'expression';
        }
        if (previous === 'rules') {
            log.debug("Leaving XacmlEditor.kindAt().");
            return 'rule';
        }
        if (previous === 'anyOf') {
            log.debug("Leaving XacmlEditor.kindAt().");
            return 'anyOf';
        }
        if (previous === 'allOf') {
            log.debug("Leaving XacmlEditor.kindAt().");
            return 'allOf';
        }
        if (previous === 'matches') {
            log.debug("Leaving XacmlEditor.kindAt().");
            return 'match';
        }
        if (previous === 'args') {
            log.debug("Leaving XacmlEditor.kindAt().");
            return 'expression';
        }
        if (previous === 'obligations' || previous === 'advice') {
            log.debug("Leaving XacmlEditor.kindAt().");
            return 'obligation';
        }
        if (previous === 'assignments') {
            log.debug("Leaving XacmlEditor.kindAt().");
            return 'assignment';
        }
        if (previous === 'variables') {
            log.debug("Leaving XacmlEditor.kindAt().");
            return 'variable';
        }
        if (previous === 'children') {
            log.debug("Leaving XacmlEditor.kindAt().");
            // A PolicySet's child, and the node above already answered the two
            // cases
            // that are not a Policy. Without the node this is the safe answer:
            // a
            // Policy offers rules, which is what a child of a set usually is.
            return 'policy';
        }
        if (previous === 'combinerParameters' || previous === 'parameters') {
            log.debug("Leaving XacmlEditor.kindAt().");
            return 'combinerParameter';
        }
        if (previous === 'ruleCombinerParameters' ||
            previous === 'policyCombinerParameters' ||
            previous === 'policySetCombinerParameters') {
            log.debug("Leaving XacmlEditor.kindAt().");
            return 'combinerParameterGroup';
        }
        log.debug("Leaving XacmlEditor.kindAt().");
        return 'unknown';
    }
    // The nearest enclosing Policy or PolicySet, which is the SCOPE a
    // VariableReference resolves in. A variable defined on one policy is
    // invisible from a sibling policy in the same set — section 5.24 — so an
    // editor that offered every variable in the document would offer references
    // the validator then refuses, which is the one thing this file exists not
    // to
    // do.
    /**
     * Returns the nearest Policy or PolicySet enclosing a path: the scope a
     * VariableReference there resolves in.
     * @param policy - the policy model
     * @param path - the dotted path
     * @returns the enclosing Policy or PolicySet, the root when there is none
     */
    enclosingPolicy(policy, path) {
        const self = this;
        const { log } = this.deps;
        log.debug('Entering XacmlEditor.enclosingPolicy(). path=' + path);
        const segments = self.segmentsOf(path);
        let node = policy;
        let holder = policy;
        for (let i = 0; i < segments.length; i += 1) {
            if (node === null || node === undefined) {
                break;
            }
            const key = segments[i];
            node = Array.isArray(node) ? node[Number(key)] : node[key];
            if (node && (node.kind === 'Policy' || node.kind === 'PolicySet')) {
                holder = node;
            }
        }
        log.debug('Leaving XacmlEditor.enclosingPolicy(). id=' +
            (holder ? holder.id : 'none'));
        return holder;
    }
    /**
     * Tells whether a node is a PolicySet.
     * @param node - a model node
     * @returns true for a PolicySet
     */
    isPolicySet(node) {
        const { log } = this.deps;
        log.debug("Entering XacmlEditor.isPolicySet().");
        log.debug("Leaving XacmlEditor.isPolicySet().");
        return !!(node && node.kind === 'PolicySet');
    }
    // -------------------------------------------------------------------------
    // THE FUNCTION MENUS.
    //
    // Computed from the real library rather than written down, which is what
    // stops the editor offering something `xacml_validate.js` will refuse. Two
    // menus, because a Match and an Apply want different things:
    //
    // matchFunctions() the two-argument predicates a <Match> may use — exactly
    //                     the functions taking two primitives and returning a
    //                     boolean. `string-equal` is in; `string-bag` is not;
    //                     `and` is not, because its parameters are variadic.
    // applyFunctions() everything, grouped, for the general expression editor.
    // -------------------------------------------------------------------------
    /**
     * Lists the functions a `<Match>` may use: those taking two primitives and
     * returning a boolean, computed from the function library.
     * @returns `{ uri, label, type }` per function, `type` the datatype both
     * arguments must have
     */
    matchFunctions() {
        const self = this;
        const { log, model, functions } = this.deps;
        const TYPE = model.TYPE;
        log.debug('Entering XacmlEditor.matchFunctions().');
        const out = functions.names().filter(function (uri) {
            const definition = functions.FUNCTIONS[uri];
            if (!definition.returns || definition.variadic) {
                return false;
            }
            if (model.canonicalType(definition.returns.type) !== TYPE.BOOLEAN) {
                return false;
            }
            const args = definition.args || [];
            return args.length === 2 && args[0].kind === 'primitive' &&
                args[1].kind === 'primitive';
        }).map(function (uri) {
            return { uri: uri, label: self.shortName(uri),
                // The datatype the Match's AttributeValue and its designator
                // both have to be. Offered so that the editor can pre-select
                // the
                // right one instead of letting somebody pick a mismatch the
                // validator then rejects a screen later.
                type: functions.FUNCTIONS[uri].args[0].type };
        });
        log.debug('Leaving XacmlEditor.matchFunctions(). ' + out.length +
            ' function(s).');
        return out;
    }
    /**
     * Lists every function in the library, for the general expression editor.
     * @returns `{ uri, label, arity, returns }` per function, `arity` 'any' for
     * a variadic one
     */
    applyFunctions() {
        const self = this;
        const { log, functions } = this.deps;
        log.debug('Entering XacmlEditor.applyFunctions().');
        const out = functions.names().map(function (uri) {
            const definition = functions.FUNCTIONS[uri];
            return { uri: uri, label: self.shortName(uri),
                arity: definition.variadic ? 'any'
                    : (definition.args || []).length,
                returns: definition.returns
                    ? self.shortType(definition.returns.type) : '?' };
        });
        log.debug('Leaving XacmlEditor.applyFunctions(). ' + out.length +
            ' function(s).');
        return out;
    }
    /**
     * Strips the XACML function prefix from a function URI.
     * @param uri - a function URI
     * @returns the bare function name
     */
    shortName(uri) {
        const { log } = this.deps;
        log.debug("Entering XacmlEditor.shortName().");
        log.debug("Leaving XacmlEditor.shortName().");
        return String(uri)
            .replace(/^urn:oasis:names:tc:xacml:[0-9.]+:function:/, '');
    }
    /**
     * Returns a datatype's short name.
     * @param uri - a datatype URI
     * @returns the short name, the URI when unknown, 'any' when absent
     */
    shortType(uri) {
        const { log, datatypes } = this.deps;
        log.debug("Entering XacmlEditor.shortType().");
        const row = uri ? datatypes.typeOf(uri) : null;
        log.debug("Leaving XacmlEditor.shortType().");
        return row ? row.name : (uri || 'any');
    }
    // A one-line reading of an expression, for a menu or a detail line. It
    // never
    // throws and never returns '': a node the reader produced that this
    // function
    // has no case for is named by its kind, because a blank row in a tree is a
    // node somebody cannot select.
    /**
     * Reads an expression as one line for a menu or a detail line; never ''
     * and never throws.
     * @param expression - a model expression node
     * @returns the one-line reading, 'nothing' for no expression
     */
    describeExpression(expression) {
        const self = this;
        const { log } = this.deps;
        log.debug("Entering XacmlEditor.describeExpression().");
        if (!expression) {
            log.debug("Leaving XacmlEditor.describeExpression().");
            return 'nothing';
        }
        if (expression.kind === 'value') {
            log.debug("Leaving XacmlEditor.describeExpression().");
            return '"' + expression.lexical + '" (' +
                self.shortType(expression.type) + ')';
        }
        if (expression.kind === 'designator') {
            log.debug("Leaving XacmlEditor.describeExpression().");
            return expression.attributeId + ' from ' +
                self.categoryLabel(expression.category);
        }
        if (expression.kind === 'selector') {
            log.debug("Leaving XacmlEditor.describeExpression().");
            return expression.path + ' in ' +
              self.categoryLabel(expression.category);
        }
        if (expression.kind === 'variableRef') {
            log.debug("Leaving XacmlEditor.describeExpression().");
            return '$' + expression.variableId;
        }
        if (expression.kind === 'function') {
            log.debug("Leaving XacmlEditor.describeExpression().");
            return self.shortName(expression.functionId) + ' (as a value)';
        }
        if (expression.kind === 'apply') {
            log.debug("Leaving XacmlEditor.describeExpression().");
            return self.shortName(expression.functionId) + '(' +
                (expression.args || []).length + ')';
        }
        log.debug("Leaving XacmlEditor.describeExpression().");
        return String(expression.kind);
    }
    /**
     * Lists the datatypes a dropdown offers, the common ones first and the rest
     * sorted.
     * @returns `{ uri, label }` per datatype
     */
    typeMenu() {
        const self = this;
        const { log, datatypes } = this.deps;
        log.debug("Entering XacmlEditor.typeMenu().");
        const rest = Object.keys(datatypes.TYPES).filter(function (uri) {
            return COMMON_TYPES.indexOf(uri) < 0;
        }).sort();
        log.debug("Leaving XacmlEditor.typeMenu().");
        return COMMON_TYPES.concat(rest).map(function (uri) {
            return { uri: uri, label: self.shortType(uri) };
        });
    }
    // Which menu a node's combining algorithm comes from. One function, so that
    // the page, the edit and the refusal cannot disagree about it.
    /**
     * Returns the combining-algorithm menu for a node: the policy-combining one
     * for a PolicySet, the rule-combining one otherwise.
     * @param node - a Policy or PolicySet
     * @returns the menu rows
     */
    algorithmMenuFor(node) {
        const self = this;
        const { log } = this.deps;
        log.debug("Entering XacmlEditor.algorithmMenuFor().");
        log.debug("Leaving XacmlEditor.algorithmMenuFor().");
        return self.isPolicySet(node) ? POLICY_ALG_MENU : RULE_ALG_MENU;
    }
    // The variables a VariableReference at this path may legally name: the ones
    // declared on the nearest enclosing Policy, sorted, as `{ id, detail }` so
    // the menu can say what each one IS rather than offering five bare names.
    /**
     * Lists the variables a VariableReference at a path may name: those the
     * nearest enclosing policy defines.
     * @param policy - the policy model
     * @param path - the dotted path
     * @returns `{ id, detail }` per variable, sorted by id
     */
    variablesInScope(policy, path) {
        const self = this;
        const { log } = this.deps;
        log.debug('Entering XacmlEditor.variablesInScope(). path=' + path);
        const holder = self.enclosingPolicy(policy, path);
        const variables = (holder && holder.variables) || {};
        const out = Object.keys(variables).sort().map(function (id) {
            return { id: id, detail: self.describeExpression(variables[id]) };
        });
        log.debug('Leaving XacmlEditor.variablesInScope(). ' + out.length +
            ' variable(s).');
        return out;
    }
    /**
     * Says what may be done at a path: the node's kind, the `Add` options legal
     * there and whether the node may be removed.
     * @param policy - the policy model
     * @param path - the dotted path
     * @returns `{ kind, additions, removable }`; kind 'unknown' with nothing
     * offered when the path does not resolve
     */
    optionsAt(policy, path) {
        const self = this;
        const { log } = this.deps;
        log.debug('Entering XacmlEditor.optionsAt(). path=' + path);
        const located = self.nodeAt(policy, path);
        if (!located) {
            log.debug('Leaving XacmlEditor.optionsAt(). The path does not ' +
              'resolve.');
            return { kind: 'unknown', additions: [], removable: false };
        }
        const kind = self.kindAt(path, located.node);
        let additions = (ADDITIONS[kind] || []).slice();
        // A rule already carrying a Condition may not have a second one — the
        // schema allows exactly one. Filtered here rather than refused in
        // `applyEdit()`, because an option that is offered and then refused
        // teaches
        // a person that the menu is not to be trusted.
        if (kind === 'rule' && located.node.condition) {
            additions = additions.filter(function (one) {
                return one.action !== 'add-condition';
            });
        }
        // A VariableReference may only name a variable THIS POLICY DEFINES
        // (section
        // 5.24), so the option is withdrawn where there is none — an editor
        // that
        // offered it would build `$v1`, the validator would refuse the
        // document,
        // and the store would decline the write with a message about a variable
        // the
        // person never asked for. It was exactly that until variables could be
        // defined here at all.
        if ((kind === 'expression' || kind === 'variable') &&
            !self.variablesInScope(policy, path).length) {
            additions = additions.filter(function (one) {
                return one.action !== 'set-expression-variable';
            });
        }
        // An `Apply` may take more arguments; every other expression is a leaf
        // and
        // may only be REPLACED, which the `set-expression-*` options already
        // do.
        if ((kind === 'expression' || kind === 'variable') &&
            located.node.kind === 'apply') {
            additions = additions.concat([
                { action: 'add-argument', label: 'Argument',
                    help: 'Another argument to this function.' }
            ]);
        }
        const result = {
            kind: kind,
            additions: additions,
            // THE ROOT IS NOT REMOVABLE. Everything else is, and a Target is
            // removable by removing its last clause rather than as a node of
            // its own
            // — which is why `target` is absent here. `path` rather than `kind`
            // decides the root, because a policy set INSIDE a set is a
            // `policySet`
            // that may certainly go.
            removable: path !== '' && kind !== 'target'
        };
        log.debug('Leaving XacmlEditor.optionsAt(). ' + additions.length +
            ' addition(s).');
        return result;
    }
    // -------------------------------------------------------------------------
    // APPLYING ONE EDIT.
    //
    // Mutates the model in place and returns `{ ok, why }`. In place rather
    // than
    // returning a copy, because the caller has just parsed the document and is
    // about to serialize it — a deep clone in between would buy immutability
    // nothing else here relies on.
    //
    // EVERY NEW NODE IS COMPLETE AND VALID ON ITS OWN. A rule arrives with a
    // Target, an Effect and an id; a Match arrives with a function, a literal
    // and
    // a designator. That is deliberate and it is the difference between an
    // editor
    // that always holds a loadable policy and one that holds a half-built
    // document which cannot be saved until several more edits are made — the
    // second kind cannot show you what you have, because it cannot evaluate it.
    // -------------------------------------------------------------------------
    /**
     * Applies one edit to a policy model, in place.
     *
     * Every node it adds is complete and valid on its own. An Effect that is
     * neither Permit nor Deny is refused.
     * @param policy - the policy model, mutated
     * @param path - the dotted path the edit applies at
     * @param action - the edit, one of the grammar's actions
     * @param params - the edit's form fields
     * @returns `{ ok: true, what }`, or `{ ok: false, why }` when the path no
     * longer resolves or the edit is refused
     */
    applyEdit(policy, path, action, params) {
        const self = this;
        const { log, model, functions } = this.deps;
        const TYPE = model.TYPE;
        log.debug('Entering XacmlEditor.applyEdit(). action=' + action +
            ' path=' + path);
        const given = params || {};
        const located = self.nodeAt(policy, path);
        if (!located) {
            log.debug('Leaving XacmlEditor.applyEdit(). The path does not ' +
              'resolve.');
            return { ok: false,
                why: 'That part of the policy is not there any more. The ' +
                    'document changed since the page was drawn — reload and ' +
                    'try again.' };
        }
        const node = located.node;
        // ---------------------------------------------------------------------
        // AN EDIT NAMES THE KIND OF NODE IT EDITS, AND ANY OTHER IS REFUSED.
        //
        // These six wrote their fields onto whatever the path named, so an
        // `edit-rule` sent to a Match gave the Match an `effect` and said
        // "Rule updated." — a document that typechecks, serializes the extra
        // field nowhere, and has changed nothing the user meant. `edit-match`,
        // `edit-selector` and the rest already checked; these now do too.
        // ---------------------------------------------------------------------
        const editsKind = {
            'edit-policy': ['policy', 'policySet'],
            'edit-rule': ['rule'],
            'edit-obligation': ['obligation'],
            'edit-assignment': ['assignment'],
            'edit-variable': ['variable']
        };
        if (editsKind[action] &&
            editsKind[action].indexOf(self.kindAt(path, node)) < 0) {
            log.debug('Leaving XacmlEditor.applyEdit(). ' + action +
                ' on a ' + self.kindAt(path, node) + '.');
            return { ok: false,
                why: action + ' edits a ' + editsKind[action].join(' or ') +
                    ', and that node is a ' + self.kindAt(path, node) + '.' };
        }
        if (action === 'edit-designator' &&
            (!node || node.kind !== 'designator')) {
            log.debug('Leaving XacmlEditor.applyEdit(). Not a designator.');
            return { ok: false,
                why: 'That node is not an AttributeDesignator.' };
        }
        // ---------------------------------------------------------------------
        // AN EFFECT IS ONE OF TWO WORDS, AND A THIRD IS REFUSED.
        //
        // Reading anything but exactly `Deny` as a PERMIT would make `deny`,
        // `DENY` or a typo write a rule that PERMITS and say "Rule added." So
        // absent or empty keeps the default, and a value that is neither word
        // is refused by name. XACML 3.0 section 5.9 (EffectType) defines
        // exactly these two.
        // ---------------------------------------------------------------------
        const effects = [model.EFFECT.PERMIT, model.EFFECT.DENY];
        const effectFields = ['effect', 'on'];
        for (let i = 0; i < effectFields.length; i++) {
            const asked = given[effectFields[i]];
            if (asked !== undefined && asked !== null && asked !== '' &&
                effects.indexOf(asked) < 0) {
                log.debug('Leaving XacmlEditor.applyEdit(). "' +
                  effectFields[i] +
                    '" is not an Effect.');
                return { ok: false,
                    why: '"' + effectFields[i] + '" is "' + String(asked) +
                        '", which is not an XACML Effect. It is Permit or ' +
                        'Deny, spelt exactly so.' };
            }
        }
        if (action === 'remove') {
            if (!located.parent || located.key === null) {
                log.debug('Leaving XacmlEditor.applyEdit(). Nothing to ' +
                  'remove from.');
                return { ok: false,
                  why: 'The policy itself cannot be removed.' };
            }
            if (Array.isArray(located.parent)) {
                located.parent.splice(Number(located.key), 1);
            }
            else {
                located.parent[located.key] = null;
            }
            log.debug('Leaving XacmlEditor.applyEdit(). Removed.');
            return { ok: true, what: 'Removed.' };
        }
        if (action === 'add-rule') {
            if (self.isPolicySet(node)) {
                // The menu does not offer this here, and the management API is
                // not the
                // menu. Without this the rule lands on `rules`, the writer
                // serializes
                // `children` and never looks at it, and the reply says "Rule
                // added."
                log.debug('Leaving XacmlEditor.applyEdit(). A policy set ' +
                    'holds ' +
                    'policies.');
                return { ok: false,
                    why: 'A PolicySet holds policies, not rules. Add a ' +
                        'Policy ' +
                        'to it and add the rule to that — the set combines ' +
                        'the policies and each policy combines its own ' +
                            'rules.' };
            }
            const index = (node.rules || []).length;
            node.rules = node.rules || [];
            node.rules.push({
                id: (node.id || 'urn:policy') + ':rule:' + (index + 1),
                effect: given.effect === model.EFFECT.DENY ? model.EFFECT.DENY
                    : model.EFFECT.PERMIT,
                description: '',
                target: null, condition: null, obligations: [], advice: []
            });
            log.debug('Leaving XacmlEditor.applyEdit(). Rule added.');
            return { ok: true, what: 'Rule added.' };
        }
        if (action === 'add-policy' || action === 'add-policyset') {
            if (!self.isPolicySet(node)) {
                log.debug('Leaving XacmlEditor.applyEdit(). Not a policy set.');
                return { ok: false,
                    why: 'Only a PolicySet holds policies. This is a Policy ' +
                        '— ' +
                        'it holds rules.' };
            }
            const set = action === 'add-policyset';
            node.children = node.children || [];
            const child = {
                kind: set ? 'PolicySet' : 'Policy',
                id: (node.id || 'urn:policyset') +
                  (set ? ':set:' : ':policy:') +
                    (node.children.length + 1),
                description: '',
                version: '1.0',
                // COMPLETE AND VALID, and deny-unless-permit rather than
                // something
                // permissive, because this editor is LIVE: a child added to the
                // running
                // root takes effect on the next request, and one that started
                // life
                // permitting whatever its parent's target let through would be
                // a hole
                // opened by clicking Add. An empty deny-unless-permit policy
                // denies,
                // which is the direction a half-built element should fail in.
                combiningAlgId: set ? model.POLICY_ALG.DENY_UNLESS_PERMIT
                    : model.RULE_ALG.DENY_UNLESS_PERMIT,
                target: null, obligations: [], advice: []
            };
            if (set) {
                child.children = [];
            }
            else {
                child.variables = {};
                child.rules = [];
            }
            node.children.push(child);
            log.debug('Leaving XacmlEditor.applyEdit(). ' + child.kind +
              ' added.');
            return { ok: true, what: (set ? 'Policy set' : 'Policy') +
              ' added.' };
        }
        if (action === 'add-policy-reference' ||
            action === 'add-policyset-reference') {
            if (!self.isPolicySet(node)) {
                log.debug('Leaving XacmlEditor.applyEdit(). Not a policy set.');
                return { ok: false,
                    why: 'Only a PolicySet may reference another policy.' };
            }
            node.children = node.children || [];
            node.children.push({
                kind: action === 'add-policyset-reference' ?
                    'PolicySetIdReference'
                    : 'PolicyIdReference',
                // A REFERENCE TO SOMETHING THAT IS NOT THERE YET IS LEGAL AND
                // IS NOT AN
                // ERROR HERE. It is resolved from the repository at DECISION
                // time, not
                // at load time, so a policy may reference one that has not been
                // written
                // yet — and `xacml_pdp.js` reports an unresolved reference on
                // the
                // decision rather than the store refusing the document.
                // Refusing it
                // here would make the order in which two policies are authored
                // matter.
                ref: given.ref ?
                    String(given.ref) : 'urn:example:policy:referenced',
                version: given.version ? String(given.version) : null
            });
            log.debug('Leaving XacmlEditor.applyEdit(). Reference added.');
            return { ok: true, what: 'Reference added.' };
        }
        if (action === 'edit-reference') {
            if (node.kind !== 'PolicyIdReference' &&
                node.kind !== 'PolicySetIdReference') {
                log.debug('Leaving XacmlEditor.applyEdit(). Not a reference.');
                return { ok: false,
                  why: 'That node is not a policy reference.' };
            }
            if (given.ref) {
                node.ref = String(given.ref);
            }
            if (given.version !== undefined) {
                // An empty box means NO version constraint, which is a
                // different
                // document from one naming a version — so '' is written as
                // absent
                // rather than as the string ''.
                node.version = String(given.version) || null;
            }
            log.debug('Leaving XacmlEditor.applyEdit(). Reference edited.');
            return { ok: true, what: 'Reference updated.' };
        }
        if (action === 'add-variable') {
            if (self.isPolicySet(node)) {
                log.debug('Leaving XacmlEditor.applyEdit(). A policy set ' +
                  'has no ' +
                    'variables.');
                return { ok: false,
                    why: 'A VariableDefinition belongs to a Policy. A ' +
                      'PolicySet ' +
                        'has no variable scope of its own — section 5.24.' };
            }
            node.variables = node.variables || {};
            let id = String(given.variableId || '').trim();
            const badId = self.checkVariableId(id);
            if (badId) {
                log.debug('Leaving XacmlEditor.applyEdit(). ' + badId);
                return { ok: false, why: badId };
            }
            if (!id) {
                let n = Object.keys(node.variables).length + 1;
                while (ownMembers.has(node.variables, 'v' + n)) {
                    n += 1;
                }
                id = 'v' + n;
            }
            // An own member only: `toString` is not already defined.
            if (ownMembers.read(node.variables, id)) {
                // The reader refuses a document with two definitions of one
                // id, so producing one here would write a policy this page
                // cannot load back.
                log.debug('Leaving XacmlEditor.applyEdit(). Duplicate ' +
                  'variable id.');
                return { ok: false,
                    why: 'This policy already defines $' + id + ', and a ' +
                        'VariableId must be unique within a policy.' };
            }
            // COMPLETE AND VALID: a bag of the subject's employeeType, which is
            // the
            // same starting expression `add-condition` uses and for the same
            // reason —
            // a VariableDefinition with no expression is a document that will
            // not
            // load.
            ownMembers.put(node.variables, id, {
                kind: 'designator', category: model.CATEGORY.ACCESS_SUBJECT,
                attributeId: 'employeeType', dataType: TYPE.STRING,
                issuer: null, mustBePresent: false
            });
            log.debug('Leaving XacmlEditor.applyEdit(). Variable added.');
            return { ok: true, what: 'Variable $' + id + ' added.' };
        }
        if (action === 'edit-variable') {
            const holder = self.enclosingPolicy(policy, path);
            const wasCalled =
                self.segmentsOf(path)[self.segmentsOf(path).length - 1];
            const renamed = String(given.variableId || '').trim();
            const badRename = self.checkVariableId(renamed);
            if (badRename) {
                log.debug('Leaving XacmlEditor.applyEdit(). ' + badRename);
                return { ok: false, why: badRename };
            }
            if (!renamed || renamed === wasCalled) {
                log.debug('Leaving XacmlEditor.applyEdit(). Nothing to ' +
                    'rename.');
                return { ok: true, what: 'Unchanged.' };
            }
            const variables = holder && holder.variables;
            if (variables && ownMembers.read(variables, renamed)) {
                log.debug('Leaving XacmlEditor.applyEdit(). Duplicate ' +
                  'variable id.');
                return { ok: false,
                    why: 'This policy already defines $' + renamed + '.' };
            }
            // A PATH THAT RESOLVES IS NOT A VARIABLE. The last segment is read
            // as
            // the id, and a path that names a rule, or a field of a variable,
            // still
            // resolves. Copying that miss stored `undefined`, and writePolicy
            // then
            // threw reading `.kind`. A policy set has no
            // variables map, and reading it threw the same way.
            const defined = variables && ownMembers.read(variables, wasCalled);
            if (!defined || !defined.kind) {
                log.debug('Leaving XacmlEditor.applyEdit(). No such variable.');
                return { ok: false,
                    why: 'There is no variable $' + (wasCalled || '') +
                        ' to rename.' };
            }
            // EVERY REFERENCE IS REWRITTEN WITH IT. The alternative — refusing
            // to
            // rename a variable that is used — is safe and useless, because a
            // variable nobody references is the only one nobody wants to
            // rename. A
            // rename that left the references behind would produce a document
            // that
            // does not load, and the store would refuse the write with a
            // message
            // about a variable that no longer exists.
            ownMembers.put(holder.variables, renamed, defined);
            delete holder.variables[wasCalled];
            const rewritten = self.renameVariableReferences(holder, wasCalled,
              renamed);
            log.debug('Leaving XacmlEditor.applyEdit(). Variable renamed.');
            return { ok: true,
                what: 'Renamed to $' + renamed + ', and ' + rewritten +
                    ' reference(s) with it.' };
        }
        if (action === 'edit-assignment') {
            if (given.attributeId) {
                node.attributeId = String(given.attributeId);
            }
            if (given.category !== undefined) {
                node.category = String(given.category) || null;
            }
            if (given.issuer !== undefined) {
                node.issuer = String(given.issuer) || null;
            }
            log.debug('Leaving XacmlEditor.applyEdit(). Assignment edited.');
            return { ok: true, what: 'Assignment updated.' };
        }
        if (action === 'add-target-anyof') {
            // The Target is created if it is not there — an absent Target and
            // an
            // empty one mean the same thing (match everything), so
            // materialising it
            // on the first clause is not a change of meaning.
            node.target = node.target || { anyOf: [] };
            node.target.anyOf.push({ allOf: [{ matches: [self
                .newMatch(given)] }] });
            log.debug('Leaving XacmlEditor.applyEdit(). Target clause added.');
            return { ok: true, what: 'Target clause added.' };
        }
        if (action === 'add-allof') {
            node.allOf = node.allOf || [];
            node.allOf.push({ matches: [self.newMatch(given)] });
            log.debug('Leaving XacmlEditor.applyEdit(). Alternative added.');
            return { ok: true, what: 'Alternative added.' };
        }
        if (action === 'add-match') {
            node.matches = node.matches || [];
            node.matches.push(self.newMatch(given));
            log.debug('Leaving XacmlEditor.applyEdit(). Match added.');
            return { ok: true, what: 'Match added.' };
        }
        if (action === 'edit-match') {
            // A MATCH IS THE ONLY NODE THIS ACTION MAY READ A VALUE FROM. The
            // path may name an AllOf (`.rules.0.target.anyOf.0.allOf.0`) and
            // omit `value`. An AllOf has `matches`, not `value`, so
            // `node.value.lexical` would throw. An expression edit of the
            // wrong kind is already a refusal; this is the same rule for the
            // action that owns a Match.
            if (self.kindAt(path, node) !== 'match') {
                log.debug('Leaving XacmlEditor.applyEdit(). Not a Match.');
                return { ok: false,
                    why: 'That path is not a Match. This action edits a ' +
                        'Match, and an AllOf, a rule or a target is edited ' +
                        'by its own action.' };
            }
            const matchId = given.matchId || node.matchId;
            const definition = functions.lookup(matchId);
            if (!definition) {
                log.debug('Leaving XacmlEditor.applyEdit(). Unknown match ' +
                  'function.');
                return { ok: false, why: 'There is no function "' + matchId +
                  '".' };
            }
            // A MATCH FUNCTION COMPARES A VALUE. `string-bag` and the other
            // constructors take no positional argument, so `args[0].type`
            // throws the same way the missing value does. Refused before the
            // node is written.
            const first = definition.args && definition.args[0];
            if (!first || !first.type) {
                log.debug('Leaving XacmlEditor.applyEdit(). Not a Match ' +
                  'function.');
                return { ok: false,
                    why: 'That function cannot be a Match. A Match compares ' +
                        'a value, and this function takes none.' };
            }
            const type = first.type;
            const was = node.reference || {};
            // WHICH KIND OF REFERENCE. A <Match> may hold an
            // <AttributeDesignator> or
            // an <AttributeSelector> and the schema allows exactly one of the
            // two, so
            // this is a switch rather than two fields — and it keeps whichever
            // it
            // already was when the form does not say, so the half of the form
            // that
            // edits the function cannot silently turn a selector into a
            // designator.
            const wantsSelector = given.referenceKind
                ? given.referenceKind === 'selector'
                : was.kind === 'selector';
            let lexical;
            if (given.value === undefined) {
                if (!node.value || node.value.lexical === undefined) {
                    log.debug('Leaving XacmlEditor.applyEdit(). Match has ' +
                      'no value.');
                    return { ok: false,
                        why: 'A Match needs a value, and this one has none.' };
                }
                lexical = node.value.lexical;
            }
            else {
                lexical = String(given.value);
            }
            const badMatchValue = self.lexicalRefusal(type, lexical);
            if (badMatchValue) {
                log.debug('Leaving XacmlEditor.applyEdit(). Match value ' +
                  'is not of its type.');
                return badMatchValue;
            }
            node.matchId = matchId;
            node.value = { kind: 'value', type: type, lexical: lexical };
            // THE DATATYPE FOLLOWS THE FUNCTION, always. A Match whose literal
            // is a
            // string and whose designator is an integer does not typecheck, and
            // letting the two be chosen independently is how somebody spends
            // ten
            // minutes on a form to be told at the end that it is wrong.
            node.reference = wantsSelector
                ? { kind: 'selector',
                    category: given.category || was.category ||
                        model.CATEGORY.ACCESS_SUBJECT,
                    path: given.path || was.path || '//*',
                    dataType: type,
                    contextSelectorId: given.contextSelectorId === undefined
                        ? (was.contextSelectorId || null)
                        : (String(given.contextSelectorId) || null),
                    issuer: null,
                    namespaces: was.namespaces || null,
                    mustBePresent: self.flagOf(given.mustBePresent,
                      was.mustBePresent) }
                : { kind: 'designator',
                    category: given.category || was.category ||
                        model.CATEGORY.ACCESS_SUBJECT,
                    attributeId: given.attributeId || was.attributeId ||
                        model.ATTRIBUTE.SUBJECT_ID,
                    dataType: type,
                    issuer: given.issuer === undefined
                        ? (was.issuer || null) : (String(given.issuer) || null),
                    mustBePresent: self.flagOf(given.mustBePresent,
                      was.mustBePresent) };
            log.debug('Leaving XacmlEditor.applyEdit(). Match edited.');
            return { ok: true, what: 'Match updated.' };
        }
        if (action === 'edit-rule') {
            if (given.id) {
                node.id = String(given.id);
            }
            if (given.effect === model.EFFECT.PERMIT ||
                given.effect === model.EFFECT.DENY) {
                node.effect = given.effect;
            }
            if (given.description !== undefined) {
                node.description = String(given.description);
            }
            log.debug('Leaving XacmlEditor.applyEdit(). Rule edited.');
            return { ok: true, what: 'Rule updated.' };
        }
        if (action === 'edit-policy') {
            if (given.id) {
                node.id = String(given.id);
            }
            if (given.description !== undefined) {
                node.description = String(given.description);
            }
            if (given.version !== undefined && String(given.version)) {
                // The schema's VersionType: dot-separated numbers. Checked
                // here because a Version of "draft 2" is refused by somebody
                // else's schema validator and by nothing in this engine, so it
                // would travel a long way before anybody found out.
                if (!/^\d+(\.\d+)*$/.test(String(given.version))) {
                    log.debug('Leaving XacmlEditor.applyEdit(). Bad version.');
                    return { ok: false,
                        why: 'A Version is dot-separated numbers — "1", ' +
                            '"1.0", ' +
                            '"2.13.7". "' + given.version + '" is not, and a ' +
                            'schema validator elsewhere would refuse the ' +
                            'document.' };
                }
                node.version = String(given.version);
            }
            if (given.maxDelegationDepth !== undefined) {
                const depth = String(given.maxDelegationDepth).trim();
                if (depth && !/^\d+$/.test(depth)) {
                    log.debug('Leaving XacmlEditor.applyEdit(). Bad ' +
                      'delegation depth.');
                    return { ok: false,
                        why: 'MaxDelegationDepth is a non-negative integer, ' +
                            'or ' +
                            'empty for none.' };
                }
                node.maxDelegationDepth = depth || null;
            }
            if (given.xpathVersion !== undefined) {
                node.xpathVersion = String(given.xpathVersion).trim() || null;
            }
            if (given.combiningAlgId) {
                // THE MENU IS CHOSEN BY THE NODE. A PolicySet takes a
                // POLICY-combining
                // algorithm and a Policy takes a RULE-combining one, and the
                // two
                // vocabularies differ by one URI segment — so validating a
                // policy set's
                // choice against the rule table would refuse every legal
                // answer, and
                // accepting either would write a document naming an algorithm
                // no
                // combiner can find.
                const menu = self.algorithmMenuFor(node);
                const known = menu.filter(function (one) {
                    return one.uri === given.combiningAlgId;
                })[0];
                if (!known) {
                    log.debug('Leaving XacmlEditor.applyEdit(). Unknown ' +
                      'combining ' +
                        'algorithm.');
                    return { ok: false,
                        why: 'That is not one of the ' +
                            (self.isPolicySet(node) ? 'policy' : 'rule') +
                            '-combining algorithms this editor offers.' };
                }
                node.combiningAlgId = given.combiningAlgId;
            }
            log.debug('Leaving XacmlEditor.applyEdit(). Policy edited.');
            return { ok: true,
                what: (self.isPolicySet(node) ? 'Policy set' : 'Policy') +
                    ' updated.' };
        }
        if (action === 'add-condition') {
            if (node.condition) {
                log.debug('Leaving XacmlEditor.applyEdit(). It already has ' +
                    'one.');
                return { ok: false,
                  why: 'A rule may have only one Condition.' };
            }
            // A NEW CONDITION IS A COMPLETE, TRUE ONE rather than an empty
            // shell:
            // `string-is-in("", <a subject attribute>)`. A rule whose Condition
            // is
            // half-built cannot be saved, and an editor that cannot save is an
            // editor
            // that has lost your work.
            node.condition = {
                kind: 'apply', functionId: F1 + 'string-is-in',
                args: [
                    { kind: 'value', type: TYPE.STRING, lexical: '' },
                    { kind: 'designator',
                      category: model.CATEGORY.ACCESS_SUBJECT,
                        attributeId: 'employeeType', dataType: TYPE.STRING,
                        issuer: null, mustBePresent: false }
                ]
            };
            log.debug('Leaving XacmlEditor.applyEdit(). Condition added.');
            return { ok: true, what: 'Condition added.' };
        }
        if (action === 'set-expression-apply' ||
            action === 'set-expression-value' ||
            action === 'set-expression-designator' ||
            action === 'set-expression-selector' ||
            action === 'set-expression-function' ||
            action === 'set-expression-variable') {
            // An empty or root-level path resolves to the document itself,
            // which has
            // no parent to write the expression into —
            // `located.parent[located.key]`
            // would throw (reading a property of null). The `remove` action
            // above guards the same way; an expression replaces a node that HAS
            // a
            // parent, so the root is a refusal, not a crash.
            if (!located.parent || located.key === null) {
                log.debug('Leaving XacmlEditor.applyEdit(). No node to ' +
                    'replace.');
                return { ok: false,
                    why: 'That path is the policy itself, which is not an ' +
                        'expression — point the edit at an expression inside ' +
                        'the document.' };
            }
            // A MATCH IS NOT AN EXPRESSION. These six actions replace the node
            // at the path. A path that names a Match still resolves, and
            // writing an Apply into that slot makes writeTarget() call
            // writeExpression() on match.value, which is now absent, so it
            // throws reading `.kind`. A rule, a target,
            // an AnyOf and an AllOf are the same kind of miss. A Match is
            // edited by edit-match.
            const slot = self.kindAt(path, node);
            if (slot !== 'expression' && slot !== 'variable') {
                log.debug('Leaving XacmlEditor.applyEdit(). Not an ' +
                    'expression.');
                return { ok: false,
                    why: 'That path is not an expression. These actions ' +
                        'replace an expression, and a Match, a rule or a ' +
                        'target is edited by its own action.' };
            }
            const replacement = self.newExpression(action, given,
              self.variablesInScope(policy, path));
            if (!replacement.ok) {
                log.debug('Leaving XacmlEditor.applyEdit(). ' +
                  replacement.why);
                return replacement;
            }
            if (Array.isArray(located.parent)) {
                located.parent[Number(located.key)] = replacement.expression;
            }
            else {
                located.parent[located.key] = replacement.expression;
            }
            log.debug('Leaving XacmlEditor.applyEdit(). Expression replaced.');
            return { ok: true, what: 'Expression replaced.' };
        }
        if (action === 'add-argument') {
            if (node.kind !== 'apply') {
                log.debug('Leaving XacmlEditor.applyEdit(). Not a ' +
                  'function call.');
                return { ok: false,
                  why: 'Only a function call takes arguments.' };
            }
            node.args = node.args || [];
            node.args.push({ kind: 'value', type: TYPE.STRING, lexical: '' });
            log.debug('Leaving XacmlEditor.applyEdit(). Argument added.');
            return { ok: true, what: 'Argument added.' };
        }
        if (action === 'edit-apply') {
            if (!functions.lookup(given.functionId)) {
                log.debug('Leaving XacmlEditor.applyEdit(). Unknown function.');
                return { ok: false, why: 'There is no function "' +
                  given.functionId +
                        '".' };
            }
            node.functionId = given.functionId;
            if (given.description !== undefined) {
                node.description = String(given.description);
            }
            log.debug('Leaving XacmlEditor.applyEdit(). Function changed.');
            return { ok: true, what: 'Function changed.' };
        }
        if (action === 'edit-value') {
            const nextType = given.type || node.type;
            const nextLexical = given.lexical === undefined ? node.lexical
                : String(given.lexical);
            const badValue = self.lexicalRefusal(nextType, nextLexical);
            if (badValue) {
                log.debug('Leaving XacmlEditor.applyEdit(). Value is not ' +
                  'of its type.');
                return badValue;
            }
            node.type = nextType;
            node.lexical = nextLexical;
            if (given.xpathCategory !== undefined) {
                node.xpathCategory = String(given.xpathCategory) || null;
            }
            // An `xpathExpression` literal is an XPath and needs the category
            // it runs
            // against; a value that is no longer one carries neither, so that a
            // datatype changed back to string does not leave an XPathCategory
            // on it
            // for somebody to puzzle over.
            if (model.canonicalType(node.type) !== TYPE.XPATH_EXPRESSION) {
                node.xpathCategory = null;
            }
            else if (!node.xpathCategory) {
                node.xpathCategory = model.CATEGORY.RESOURCE;
            }
            log.debug('Leaving XacmlEditor.applyEdit(). Value edited.');
            return { ok: true, what: 'Value updated.' };
        }
        if (action === 'edit-designator') {
            node.category = given.category || node.category;
            node.attributeId = given.attributeId || node.attributeId;
            node.dataType = given.dataType || node.dataType;
            if (given.issuer !== undefined) {
                // OPTIONAL, AND ABSENT IS NOT THE SAME AS EMPTY. A designator
                // with no
                // Issuer matches an attribute whatever its issuer; one with
                // Issuer=""
                // matches only an attribute issued by the empty string, which
                // is
                // nothing. So a cleared box is written as absent.
                node.issuer = String(given.issuer) || null;
            }
            node.mustBePresent = self.flagOf(given.mustBePresent,
              node.mustBePresent);
            log.debug('Leaving XacmlEditor.applyEdit(). Designator edited.');
            return { ok: true, what: 'Attribute updated.' };
        }
        if (action === 'edit-selector') {
            if (node.kind !== 'selector') {
                log.debug('Leaving XacmlEditor.applyEdit(). Not a selector.');
                return { ok: false,
                  why: 'That node is not an AttributeSelector.' };
            }
            node.category = given.category || node.category;
            node.dataType = given.dataType || node.dataType;
            if (given.path) {
                node.path = String(given.path);
            }
            if (given.contextSelectorId !== undefined) {
                node.contextSelectorId = String(given.contextSelectorId) ||
                  null;
            }
            if (given.namespacePrefix !== undefined ||
                given.namespaceUri !== undefined) {
                // ONE BINDING AT A TIME, because the edit form has one prefix
                // field and one URI field. A prefix with no URI REMOVES that
                // binding, which is the only way to take one away without a
                // second control.
                const prefix = String(given.namespacePrefix || '').trim();
                const uri = String(given.namespaceUri || '').trim();
                if (prefix) {
                    node.namespaces = node.namespaces || {};
                    if (uri) {
                        node.namespaces[prefix] = uri;
                    }
                    else {
                        delete node.namespaces[prefix];
                    }
                }
            }
            node.mustBePresent = self.flagOf(given.mustBePresent,
              node.mustBePresent);
            log.debug('Leaving XacmlEditor.applyEdit(). Selector edited.');
            return { ok: true, what: 'Selector updated.' };
        }
        if (action === 'edit-function') {
            if (node.kind !== 'function') {
                log.debug('Leaving XacmlEditor.applyEdit(). Not a ' +
                  'function reference.');
                return { ok: false,
                  why: 'That node is not a function reference.' };
            }
            if (!functions.lookup(given.functionId)) {
                log.debug('Leaving XacmlEditor.applyEdit(). Unknown function.');
                return { ok: false, why: 'There is no function "' +
                  given.functionId +
                        '".' };
            }
            node.functionId = given.functionId;
            log.debug('Leaving XacmlEditor.applyEdit(). Function ' +
              'reference changed.');
            return { ok: true, what: 'Function reference changed.' };
        }
        if (action === 'add-rule-obligation' ||
            action === 'add-policy-obligation' ||
            action === 'add-rule-advice' || action === 'add-policy-advice') {
            const advice = action.indexOf('advice') >= 0;
            const list = advice ? 'advice' : 'obligations';
            node[list] = node[list] || [];
            node[list].push({
                id: 'urn:sts:xacml:' + (advice ? 'advice' : 'obligation') +
                  ':' +
                    ((node[list].length) + 1),
                on: given.on === model.EFFECT.DENY ? model.EFFECT.DENY
                    : model.EFFECT.PERMIT,
                assignments: []
            });
            log.debug('Leaving XacmlEditor.applyEdit(). ' +
                (advice ? 'Advice' : 'Obligation') + ' added.');
            return { ok: true, what: (advice ? 'Advice' : 'Obligation') +
              ' added.' };
        }
        if (action === 'edit-obligation') {
            if (given.id) {
                node.id = String(given.id);
            }
            if (given.on === model.EFFECT.PERMIT ||
              given.on === model.EFFECT.DENY) {
                node.on = given.on;
            }
            log.debug('Leaving XacmlEditor.applyEdit(). Obligation edited.');
            return { ok: true, what: 'Updated.' };
        }
        if (action === 'add-assignment') {
            node.assignments = node.assignments || [];
            node.assignments.push({
                attributeId: 'urn:sts:xacml:assignment:' +
                    (node.assignments.length + 1),
                category: null, issuer: null,
                expression: { kind: 'value', type: TYPE.STRING, lexical: '' }
            });
            log.debug('Leaving XacmlEditor.applyEdit(). Assignment added.');
            return { ok: true, what: 'Assignment added.' };
        }
        // A move that is in ADDITIONS and not handled here would silently do
        // nothing, which is the failure this branch exists to make impossible.
        log.debug('Leaving XacmlEditor.applyEdit(). Unknown action.');
        return { ok: false,
            why: 'The editor does not know how to "' + action + '". This ' +
                'is a gap between the menu and the code that acts on it, ' +
                'not something you did.' };
    }
    // THE LITERAL MUST BE A VALUE OF ITS DATATYPE. An integer-equal Match
    // whose literal is "notanint" used to be stored, and only the decision
    // said so, as a syntax-error status that a deny-unless-permit policy
    // turns into a plain Deny. Refused here instead, before anything is
    // written. An xpathExpression is checked by the PDP against its
    // category, so it is not parsed here.
    lexicalRefusal(type, lexical) {
        const { log } = this.deps;
        log.debug("Entering XacmlEditor.lexicalRefusal().");
        if (model.canonicalType(type) === TYPE.XPATH_EXPRESSION) {
            log.debug("Leaving XacmlEditor.lexicalRefusal(). XPath.");
            return null;
        }
        try {
            datatypes.parseValue(type, lexical);
        }
        catch (error) {
            const why = (error && error.message) || String(error);
            log.debug("Leaving XacmlEditor.lexicalRefusal(). " + why);
            return { ok: false, why: why };
        }
        log.debug("Leaving XacmlEditor.lexicalRefusal(). Valid.");
        return null;
    }
    // A TRISTATE READ OF A FORM FIELD: true, false, or "the form did not say".
    //
    // It exists because of one specific way a form can lose information. An
    // unchecked checkbox SENDS NOTHING, so a form that edits a Match's function
    // and happens not to carry the MustBePresent box would clear MustBePresent
    // on
    // every save — silently turning "an absent attribute makes this
    // Indeterminate" into "an absent attribute is an empty bag", which is the
    // difference between a policy that fails closed and one that quietly does
    // not
    // apply. So the controls for it are <select>s with an explicit false, and a
    // field that is genuinely absent keeps what was there.
    flagOf(given, current) {
        const { log } = this.deps;
        log.debug("Entering XacmlEditor.flagOf().");
        if (given === undefined || given === null || given === '') {
            log.debug("Leaving XacmlEditor.flagOf().");
            return !!current;
        }
        log.debug("Leaving XacmlEditor.flagOf().");
        return given === true || given === 'true' || given === 'on' ||
            given === '1';
    }
    // Rewrite every <VariableReference> naming `from` to name `to`, within one
    // policy, and say how many. Walks the same places `xacml_pdp.js` evaluates
    // expressions in — the definitions themselves (a variable may be defined in
    // terms of another), every rule's condition, and every attribute assignment
    // on an obligation or advice at either level. A Target holds no expressions
    // a
    // reference can appear in: a <Match> takes an AttributeValue and a
    // designator
    // or selector, and none of those is a VariableReference.
    renameVariableReferences(holder, from, to) {
        const { log } = this.deps;
        log.debug('Entering XacmlEditor.renameVariableReferences(). from=' +
          from);
        let count = 0;
        function walk(expression) {
            log.debug("Entering walk().");
            if (!expression) {
                log.debug("Leaving walk().");
                return;
            }
            if (expression.kind === 'variableRef' &&
              expression.variableId === from) {
                expression.variableId = to;
                count += 1;
                log.debug("Leaving walk().");
                return;
            }
            if (expression.kind === 'apply') {
                (expression.args || []).forEach(walk);
            }
            log.debug("Leaving walk().");
        }
        function walkHolders(list) {
            log.debug("Entering walkHolders().");
            (list || []).forEach(function (one) {
                (one.assignments || []).forEach(function (assignment) {
                    walk(assignment.expression);
                });
            });
            log.debug("Leaving walkHolders().");
        }
        Object.keys(holder.variables || {}).forEach(function (id) {
            walk(holder.variables[id]);
        });
        (holder.rules || []).forEach(function (rule) {
            walk(rule.condition);
            walkHolders(rule.obligations);
            walkHolders(rule.advice);
        });
        walkHolders(holder.obligations);
        walkHolders(holder.advice);
        log.debug('Leaving XacmlEditor.renameVariableReferences(). ' + count +
            ' rewritten.');
        return count;
    }
    // A VariableId IS A PATH SEGMENT HERE, and that is this editor's limitation
    // rather than XACML's. A variable is addressed as `variables.<id>`, and
    // `segmentsOf()` splits an address on the dot — so a variable called `a.b`
    // would produce a row nothing could edit or remove, while the document
    // itself
    // stayed perfectly valid. Refused at the point of naming, where it can
    // still
    // be explained, rather than discovered later as a row whose buttons do
    // nothing.
    checkVariableId(id) {
        const { log } = this.deps;
        log.debug("Entering XacmlEditor.checkVariableId().");
        if (!id) {
            log.debug("Leaving XacmlEditor.checkVariableId().");
            return null;
        }
        if (id.indexOf('.') >= 0) {
            log.debug("Leaving XacmlEditor.checkVariableId().");
            return 'A variable name may not contain a dot in this editor. ' +
              'XACML ' +
                'allows one; this page addresses a node by a dotted path, so ' +
                    '"' +
                id + '" would produce a row that cannot be edited or ' +
                    'removed. ' +
                'The document itself would be valid — which is why this is ' +
                'refused here rather than by the validator.';
        }
        log.debug("Leaving XacmlEditor.checkVariableId().");
        return null;
    }
    newMatch(given) {
        const { log, model, functions } = this.deps;
        const TYPE = model.TYPE;
        log.debug("Entering XacmlEditor.newMatch().");
        const matchId = given.matchId || (F1 + 'string-equal');
        const definition = functions.lookup(matchId);
        const type = definition && definition.args &&
          definition.args.length === 2
            ? definition.args[0].type : TYPE.STRING;
        log.debug("Leaving XacmlEditor.newMatch().");
        return {
            matchId: matchId,
            value: { kind: 'value', type: type,
                lexical: given.value === undefined ? '' : String(given.value) },
            reference: { kind: 'designator',
                category: given.category || model.CATEGORY.ACCESS_SUBJECT,
                attributeId: given.attributeId ||
                    model.ATTRIBUTE.SUBJECT_ID,
                dataType: type, issuer: null, mustBePresent: false }
        };
    }
    newExpression(action, given, inScope) {
        const { log, model, functions } = this.deps;
        const TYPE = model.TYPE;
        log.debug("Entering XacmlEditor.newExpression().");
        if (action === 'set-expression-value') {
            log.debug("Leaving XacmlEditor.newExpression().");
            return { ok: true, expression: { kind: 'value',
                    type: given.type || TYPE.STRING,
                    lexical: given.lexical || '' } };
        }
        if (action === 'set-expression-designator') {
            log.debug("Leaving XacmlEditor.newExpression().");
            return { ok: true, expression: {
                    kind: 'designator',
                    category: given.category || model.CATEGORY.ACCESS_SUBJECT,
                    attributeId: given.attributeId || 'employeeType',
                    dataType: given.dataType || TYPE.STRING,
                    issuer: null, mustBePresent: false
                } };
        }
        if (action === 'set-expression-selector') {
            log.debug("Leaving XacmlEditor.newExpression().");
            return { ok: true, expression: {
                    kind: 'selector',
                    category: given.category || model.CATEGORY.RESOURCE,
                    // A path that selects everything, so the expression is
                    // complete and the
                    // bag it returns is whatever the request's <Content> holds.
                    // An empty
                    // Path is not legal and a selector with one would be a
                    // document that
                    // does not load.
                    path: given.path || '//*',
                    dataType: given.dataType || TYPE.STRING,
                    contextSelectorId: null, namespaces: null,
                    mustBePresent: false
                } };
        }
        if (action === 'set-expression-function') {
            const named = given.functionId || (F1 + 'string-equal');
            if (!functions.lookup(named)) {
                log.debug("Leaving XacmlEditor.newExpression().");
                return { ok: false, why: 'There is no function "' + named +
                  '".' };
            }
            log.debug("Leaving XacmlEditor.newExpression().");
            // A FUNCTION AS A VALUE, not a call: `<Function FunctionId="..."/>`
            // is
            // what the first argument of `any-of` or `map` is, and applying it
            // there
            // instead is the commonest way to write a higher-order function
            // wrongly.
            return { ok: true, expression: { kind: 'function',
              functionId: named } };
        }
        if (action === 'set-expression-variable') {
            const available = inScope || [];
            const chosen = given.variableId ||
                (available.length ? available[0].id : '');
            if (!chosen) {
                log.debug("Leaving XacmlEditor.newExpression().");
                // Cannot happen through the page's menu — `optionsAt()`
                // withdraws the option where there is nothing to name — and
                // can happen for any other caller of applyEdit().
                return { ok: false,
                    why: 'This policy defines no variables, so there is ' +
                      'nothing ' +
                        'for a VariableReference to name. Add a variable ' +
                        'definition to the policy first.' };
            }
            const known = available.filter(function (one) {
                return one.id === chosen;
            }).length > 0;
            if (!known) {
                log.debug("Leaving XacmlEditor.newExpression().");
                return { ok: false,
                    why: 'This policy defines no $' + chosen + '. A ' +
                        'VariableReference may only name a ' +
                        'VariableDefinition on the SAME policy — section ' +
                        '5.24 — and the document would not load.' };
            }
            log.debug("Leaving XacmlEditor.newExpression().");
            return { ok: true, expression: { kind: 'variableRef',
                    variableId: chosen } };
        }
        const functionId = given.functionId || (F1 + 'string-equal');
        const definition = functions.lookup(functionId);
        if (!definition) {
            log.debug("Leaving XacmlEditor.newExpression().");
            return { ok: false, why: 'There is no function "' + functionId +
              '".' };
        }
        // ARGUMENTS ARE PRE-BUILT TO THE FUNCTION'S DECLARED ARITY AND TYPES,
        // so
        // the expression typechecks the moment it exists. An `Apply` with no
        // arguments is an arity error, and an editor that produced one would
        // refuse
        // to save the document it had just told you it had updated.
        const args = (definition.args || []).map(function (parameter) {
            if (parameter.kind === 'bag') {
                return { kind: 'designator',
                    category: model.CATEGORY.ACCESS_SUBJECT,
                    attributeId: 'employeeType',
                    dataType: parameter.type || TYPE.STRING,
                    issuer: null, mustBePresent: false };
            }
            if (parameter.kind === 'function') {
                // THE SIX HIGHER-ORDER FUNCTIONS AND `map` TAKE A FUNCTION, and
                // until
                // this branch existed they were handed an <AttributeValue>
                // instead —
                // so choosing `any-of` from the menu built an expression the
                // validator
                // refuses, the store declines the write, and the editor's one
                // promise
                // (it cannot offer what the validator will refuse) was broken
                // by seven
                // of the 275 entries in its own function list.
                //
                // `map` is the one that needs a different default: its function
                // is
                // applied to ONE value and returns one, while the other six
                // take a
                // predicate of two. A default of the wrong shape is legal XACML
                // that
                // fails at evaluation, which is worse than one that fails at
                // load.
                return { kind: 'function',
                    functionId: /:map$/.test(functionId)
                        ? (F1 + 'string-normalize-to-lower-case')
                        : (F1 + 'string-equal') };
            }
            return { kind: 'value', type: parameter.type || TYPE.STRING,
                lexical: '' };
        });
        log.debug("Leaving XacmlEditor.newExpression().");
        return { ok: true, expression: { kind: 'apply', functionId: functionId,
                args: args } };
    }
    // -------------------------------------------------------------------------
    // THE TREE THE PAGE DRAWS.
    //
    // A flat list of `{ path, depth, kind, label, detail }` rather than a
    // nested
    // structure, because the page renders it as an indented list and a flat
    // list
    // is what that needs — nesting it here would mean the renderer had to walk
    // it
    // again to flatten it.
    // -------------------------------------------------------------------------
    /**
     * Flattens a policy model into the rows the editor page draws as an
     * indented list.
     * @param policy - the policy model
     * @returns `{ path, depth, kind, label, detail }` per node, in document
     * order
     */
    tree(policy) {
        const self = this;
        const { log } = this.deps;
        log.debug('Entering XacmlEditor.tree().');
        const rows = [];
        function push(path, depth, kind, label, detail) {
            log.debug("Entering push().");
            rows.push({ path: path, depth: depth, kind: kind, label: label,
                detail: detail || '' });
            log.debug("Leaving push().");
        }
        function walkExpression(expression, path, depth, label) {
            log.debug("Entering walkExpression().");
            if (!expression) {
                log.debug("Leaving walkExpression().");
                return;
            }
            if (expression.kind === 'apply') {
                push(path, depth, 'expression', label +
                  self.shortName(expression.functionId), (expression.args ||
                  []).length + ' argument(s)' +
                    (expression.description ? ' — ' +
                      expression.description : ''));
                (expression.args || []).forEach(function (argument, index) {
                    walkExpression(argument, path + '.args.' + index, depth + 1,
                      '');
                });
                log.debug("Leaving walkExpression().");
                return;
            }
            if (expression.kind === 'value') {
                push(path, depth, 'expression', label + '"' +
                  expression.lexical + '"', self.shortType(expression.type) +
                    (expression.xpathCategory
                        ? ', over ' +
                          self.categoryLabel(expression.xpathCategory)
                        : ''));
                log.debug("Leaving walkExpression().");
                return;
            }
            if (expression.kind === 'designator') {
                push(path, depth, 'expression', label + expression.attributeId,
                  self.shortType(expression.dataType) + ' from ' +
                    self.categoryLabel(expression.category) +
                    (expression.issuer ? ', issued by ' +
                      expression.issuer : '') +
                    (expression.mustBePresent ? ', must be present' : ''));
                log.debug("Leaving walkExpression().");
                return;
            }
            // AN AttributeSelector IS DRAWN AS ITS PATH, because that is what
            // it is —
            // an XPath over the <Content> of a request category rather than a
            // named
            // attribute. Until it was drawn at all, a policy holding one showed
            // a row
            // labelled `selector` with no way to see or change the path.
            if (expression.kind === 'selector') {
                const bindings = Object.keys(expression.namespaces || {})
                    .filter(function (prefix) {
                    return prefix !== '';
                });
                push(path, depth, 'expression', label + expression.path,
                  self.shortType(expression.dataType) + ' selected from ' +
                    self.categoryLabel(expression.category) +
                    (expression.contextSelectorId
                        ? ', rooted at ' + expression.contextSelectorId : '') +
                    (expression.mustBePresent ? ', must be present' : '') +
                    (bindings.length
                        ? ', ' + bindings.length +
                          ' namespace binding(s)' : ''));
                log.debug("Leaving walkExpression().");
                return;
            }
            if (expression.kind === 'variableRef') {
                push(path, depth, 'expression', label + '$' +
                  expression.variableId, '');
                log.debug("Leaving walkExpression().");
                return;
            }
            if (expression.kind === 'function') {
                push(path, depth, 'expression', label +
                  self.shortName(expression.functionId),
                  'a function used as a VALUE — not applied here');
                log.debug("Leaving walkExpression().");
                return;
            }
            push(path, depth, 'expression', label + expression.kind, '');
            log.debug("Leaving walkExpression().");
        }
        function walkTarget(target, base, depth) {
            log.debug("Entering walkTarget().");
            if (!target || !target.anyOf || !target.anyOf.length) {
                log.debug("Leaving walkTarget().");
                return;
            }
            push(base + '.target', depth, 'target', 'Target',
              target.anyOf.length + ' clause(s), all must match');
            target.anyOf.forEach(function (anyOf, i) {
                const anyPath = base + '.target.anyOf.' + i;
                push(anyPath, depth + 1, 'anyOf', 'Clause ' + (i + 1),
                  anyOf.allOf.length + ' alternative(s), any may match');
                anyOf.allOf.forEach(function (allOf, j) {
                    const allPath = anyPath + '.allOf.' + j;
                    push(allPath, depth + 2, 'allOf', 'Alternative ' + (j + 1),
                      allOf.matches.length + ' match(es), all must hold');
                    allOf.matches.forEach(function (match, k) {
                        const reference = match.reference || {};
                        push(allPath + '.matches.' + k, depth + 3, 'match',
                          self.shortName(match.matchId), '"' +
                          match.value.lexical + '" against ' +
                            (reference.kind === 'selector'
                                ? 'the path ' + reference.path
                                : reference.attributeId) +
                            ' in ' + self.categoryLabel(reference.category) +
                            (reference.mustBePresent ?
                                ', must be present' : ''));
                    });
                });
            });
            log.debug("Leaving walkTarget().");
        }
        // An obligation or an advice, and the ATTRIBUTE ASSIGNMENTS under it —
        // which were addable and invisible until this walked them.
        // `add-assignment`
        // has been in the menu since the editor shipped, and what it produced
        // could
        // not be seen, edited or removed: the only way to correct a mistyped
        // one
        // was to remove the whole obligation and build it again.
        function walkHolders(list, base, depth, what) {
            log.debug("Entering walkHolders().");
            (list || []).forEach(function (one, i) {
                const path = base + '.' +
                    (what === 'Advice' ? 'advice' : 'obligations') + '.' + i;
                push(path, depth, 'obligation', what + ' ' + one.id, 'on ' +
                  one.on + ', ' + (one.assignments || []).length +
                    ' assignment(s)');
                (one.assignments || []).forEach(function (assignment, j) {
                    const assignmentPath = path + '.assignments.' + j;
                    push(assignmentPath, depth + 1, 'assignment',
                      assignment.attributeId, (assignment.category
                        ? 'in ' + self.categoryLabel(assignment.category) + ', '
                        : '') +
                        (assignment.issuer ? 'issued by ' + assignment.issuer +
                          ', ' :
                            '') +
                        'value: ' +
                          self.describeExpression(assignment.expression));
                    walkExpression(assignment.expression, assignmentPath +
                      '.expression', depth + 2, '');
                });
            });
            log.debug("Leaving walkHolders().");
        }
        // The four combiner-parameter elements, which are SHOWN AND REMOVABLE
        // AND NOT ADDABLE — the one place in this editor where those three
        // come apart, and it is deliberate. Section C of the specification
        // says none of the twelve standard combining algorithms takes a
        // parameter, so an Add button here would be the first control on this
        // page that provably changes no decision. Drawing them is a different
        // question: a document may arrive with them through an import, and an
        // element the editor did not draw would be one the person could
        // neither see nor delete while the writer faithfully kept it.
        function walkCombinerParameters(node, base, depth) {
            log.debug("Entering walkCombinerParameters().");
            (node.combinerParameters || []).forEach(function (one, i) {
                push(base + '.combinerParameters.' + i, depth,
                  'combinerParameter', 'CombinerParameter ' + one.name,
                  self.describeExpression(one.value) +
                    ' — carried, and read by no standard algorithm');
            });
            [['ruleCombinerParameters', 'RuleCombinerParameters'],
                ['policyCombinerParameters', 'PolicyCombinerParameters'],
                ['policySetCombinerParameters', 'PolicySetCombinerParameters']]
                .forEach(function (pair) {
                (node[pair[0]] || []).forEach(function (group, i) {
                    const path = base + '.' + pair[0] + '.' + i;
                    push(path, depth, 'combinerParameterGroup', pair[1] +
                      ' for ' + group.ref, (group.parameters || []).length +
                      ' parameter(s) — carried, ' +
                        'and read by no standard algorithm');
                    (group.parameters || []).forEach(function (one, j) {
                        push(path + '.parameters.' + j, depth + 1,
                          'combinerParameter', one.name,
                          self.describeExpression(one.value));
                    });
                });
            });
            log.debug("Leaving walkCombinerParameters().");
        }
        // ONE WALK FOR A POLICY AND A POLICY SET, recursing through the
        // second's
        // children. It used to walk `policy.rules` and nothing else, so a
        // PolicySet
        // drew as a policy with no rules — an empty tree, an Add menu offering
        // a
        // Rule the writer would discard, and no way to reach a single thing
        // inside
        // the document.
        function walkPolicy(node, base, depth) {
            log.debug("Entering walkPolicy().");
            const set = self.isPolicySet(node);
            push(base, depth, set ? 'policySet' : 'policy', node.id,
              self.shortAlgorithm(node.combiningAlgId) + ', ' +
                (set ? (node.children || []).length + ' child(ren)'
                    : (node.rules || []).length + ' rule(s)') +
                ', version ' + (node.version || '1.0') +
                (node.maxDelegationDepth
                    ? ', delegation depth ' + node.maxDelegationDepth : '') +
                (node.xpathVersion ? ', XPath ' + node.xpathVersion : ''));
            walkTarget(node.target, base, depth + 1);
            if (set) {
                (node.children || []).forEach(function (child, index) {
                    const path = base + '.children.' + index;
                    if (child.kind === 'PolicyIdReference' ||
                        child.kind === 'PolicySetIdReference') {
                        push(path, depth + 1, 'reference', child.kind + ' ' +
                          child.ref, (child.version ? 'version ' + child.version
                            : 'any version') +
                            ' — resolved from the repository when a ' +
                              'decision is made, ' +
                            'not when the document is loaded');
                        return;
                    }
                    walkPolicy(child, path, depth + 1);
                });
            }
            else {
                // THE VARIABLES COME BEFORE THE RULES, which is the schema's
                // order and
                // also the reading order: a rule's condition may name one, and
                // a
                // definition drawn after its use reads backwards.
                Object.keys(node.variables || {}).forEach(function (id) {
                    const path = base + '.variables.' + id;
                    push(path, depth + 1, 'variable', '$' + id,
                      self.describeExpression(node.variables[id]) +
                        ' — visible to this policy only');
                    const definition = node.variables[id];
                    if (definition && definition.kind === 'apply') {
                        (definition.args || []).forEach(function (argument,
                          index) {
                            walkExpression(argument, path + '.args.' + index,
                              depth + 2, '');
                        });
                    }
                });
                (node.rules || []).forEach(function (rule, index) {
                    const rulePath = base + '.rules.' + index;
                    push(rulePath, depth + 1, 'rule', rule.effect + ' — ' +
                      rule.id, rule.description);
                    walkTarget(rule.target, rulePath, depth + 2);
                    if (rule.condition) {
                        walkExpression(rule.condition, rulePath + '.condition',
                          depth + 2, 'Condition: ');
                    }
                    walkHolders(rule.obligations, rulePath, depth + 2,
                      'Obligation');
                    walkHolders(rule.advice, rulePath, depth + 2, 'Advice');
                });
            }
            walkCombinerParameters(node, base, depth + 1);
            walkHolders(node.obligations, base, depth + 1, 'Obligation');
            walkHolders(node.advice, base, depth + 1, 'Advice');
            log.debug("Leaving walkPolicy().");
        }
        walkPolicy(policy, '', 0);
        log.debug('Leaving XacmlEditor.tree(). ' + rows.length + ' row(s).');
        return rows;
    }
    // -------------------------------------------------------------------------
    // THE ONE SCHEMA RULE THIS EDITOR CAN BREAK WITHOUT THE VALIDATOR NOTICING.
    //
    // Section 5.14: <XPathVersion> MUST be present when the policy contains an
    // <AttributeSelector> or an `xpathExpression` value. It is a document rule
    // rather than a typing rule, so `xacml_validate.js` says nothing about it
    // and
    // never will — that file refuses what is CERTAINLY WRONG for every request,
    // and a missing XPathVersion changes no decision this PDP makes, because
    // this
    // PDP evaluates no XPath at all, so there is no dialect to switch on a URI.
    //
    // So it is reported rather than refused, and reported where it can be
    // fixed:
    // the editor page draws it beside the field that sets it. Refusing the
    // write
    // would be the editor inventing a rule the evaluator does not have; saying
    // nothing would let somebody build a document here that this engine is
    // perfectly happy with and somebody else's schema validator rejects — which
    // is the failure mode `writeTarget()` argues about, arriving from the other
    // side.
    //
    // Returns the policies (by id) that need one and have not got one, so the
    // page can name them: in a policy set the requirement is per policy, and
    // "somewhere in this document" would send somebody looking through five of
    // them.
    // -------------------------------------------------------------------------
    /**
     * Lists the policies that use XPath (an AttributeSelector or an
     * xpathExpression value) and declare no XPathVersion, which section 5.14
     * requires; reported, not refused.
     * @param policy - the policy model
     * @returns the ids of the policies missing one
     */
    xpathVersionGaps(policy) {
        const self = this;
        const { log, model } = this.deps;
        const TYPE = model.TYPE;
        log.debug('Entering XacmlEditor.xpathVersionGaps().');
        const gaps = [];
        function usesXPath(node) {
            log.debug("Entering usesXPath().");
            let found = false;
            function walkExpression(expression) {
                log.debug("Entering walkExpression().");
                if (!expression || found) {
                    log.debug("Leaving walkExpression().");
                    return;
                }
                if (expression.kind === 'selector') {
                    found = true;
                    log.debug("Leaving walkExpression().");
                    return;
                }
                if (expression.kind === 'value' &&
                    model.canonicalType(expression.type) ===
                        TYPE.XPATH_EXPRESSION) {
                    found = true;
                    log.debug("Leaving walkExpression().");
                    return;
                }
                if (expression.kind === 'apply') {
                    (expression.args || []).forEach(walkExpression);
                }
                log.debug("Leaving walkExpression().");
            }
            function walkTarget(target) {
                log.debug("Entering walkTarget().");
                ((target || {}).anyOf || []).forEach(function (anyOf) {
                    (anyOf.allOf || []).forEach(function (allOf) {
                        (allOf.matches || []).forEach(function (match) {
                            walkExpression(match.value);
                            walkExpression(match.reference);
                        });
                    });
                });
                log.debug("Leaving walkTarget().");
            }
            function walkHolders(list) {
                log.debug("Entering walkHolders().");
                (list || []).forEach(function (one) {
                    (one.assignments || []).forEach(function (assignment) {
                        walkExpression(assignment.expression);
                    });
                });
                log.debug("Leaving walkHolders().");
            }
            walkTarget(node.target);
            Object.keys(node.variables || {}).forEach(function (id) {
                walkExpression(node.variables[id]);
            });
            (node.rules || []).forEach(function (rule) {
                walkTarget(rule.target);
                walkExpression(rule.condition);
                walkHolders(rule.obligations);
                walkHolders(rule.advice);
            });
            walkHolders(node.obligations);
            walkHolders(node.advice);
            log.debug("Leaving usesXPath().");
            return found;
        }
        function visit(node) {
            log.debug("Entering visit().");
            if (!node) {
                log.debug("Leaving visit().");
                return;
            }
            if (usesXPath(node) && !node.xpathVersion) {
                gaps.push(node.id);
            }
            if (self.isPolicySet(node)) {
                (node.children || []).forEach(function (child) {
                    if (child.kind === 'Policy' || child.kind === 'PolicySet') {
                        visit(child);
                    }
                });
            }
            log.debug("Leaving visit().");
        }
        visit(policy);
        log.debug('Leaving XacmlEditor.xpathVersionGaps(). ' + gaps.length +
            ' gap(s).');
        return gaps;
    }
    // The bare name of a combining algorithm. `shortName()` strips a FUNCTION
    // prefix and leaves an algorithm URI whole, which is why this is separate
    // rather than one regular expression asked to do both — the two families of
    // URI differ in more than their last segment.
    /**
     * Returns the bare name of a combining algorithm.
     * @param uri - a combining algorithm URI
     * @returns the name after `combining-algorithm:`, '?' when empty
     */
    shortAlgorithm(uri) {
        const { log } = this.deps;
        log.debug("Entering XacmlEditor.shortAlgorithm().");
        log.debug("Leaving XacmlEditor.shortAlgorithm().");
        return String(uri || '').replace(/^.*combining-algorithm:/, '') || '?';
    }
    /**
     * Returns a category's short label from the category menu.
     * @param uri - a category URI
     * @returns the label, the URI when it is not on the menu
     */
    categoryLabel(uri) {
        const { log } = this.deps;
        log.debug("Entering XacmlEditor.categoryLabel().");
        const found = CATEGORY_MENU.filter(function (one) {
            return one.uri === uri;
        })[0];
        log.debug("Leaving XacmlEditor.categoryLabel().");
        return found ? found.label : uri;
    }
}
/**
 * The attribute categories the editor offers, with their short labels.
 */
XacmlEditor.CATEGORY_MENU = CATEGORY_MENU;
/**
 * The rule-combining algorithms the editor offers.
 */
XacmlEditor.RULE_ALG_MENU = RULE_ALG_MENU;
/**
 * The policy-combining algorithms the editor offers.
 */
XacmlEditor.POLICY_ALG_MENU = POLICY_ALG_MENU;
/**
 * The `Add` options per kind of node: the editor's grammar.
 */
XacmlEditor.ADDITIONS = ADDITIONS;
// ---------------------------------------------------------------------------
// THE INSTANCE. The exports below forward to the one instance `xacml_slot.js`
// holds, built from `defaultDeps()` when this module loads.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot('xacml/xacml_editor',
  () => new XacmlEditor(XacmlEditor.defaultDeps()), null, helpers.log);
// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();
module.exports = {
    XacmlEditor: XacmlEditor,
    installInstance: (instance) => slot.install(instance),
    instanceOrigin: () => slot.origin(),
    nodeAt: slot.forward('nodeAt'),
    enclosingPolicy: slot.forward('enclosingPolicy'),
    isPolicySet: slot.forward('isPolicySet'),
    variablesInScope: slot.forward('variablesInScope'),
    describeExpression: slot.forward('describeExpression'),
    shortAlgorithm: slot.forward('shortAlgorithm'),
    xpathVersionGaps: slot.forward('xpathVersionGaps'),
    algorithmMenuFor: slot.forward('algorithmMenuFor'),
    kindAt: slot.forward('kindAt'),
    optionsAt: slot.forward('optionsAt'),
    applyEdit: slot.forward('applyEdit'),
    tree: slot.forward('tree'),
    matchFunctions: slot.forward('matchFunctions'),
    applyFunctions: slot.forward('applyFunctions'),
    typeMenu: slot.forward('typeMenu'),
    shortName: slot.forward('shortName'),
    shortType: slot.forward('shortType'),
    categoryLabel: slot.forward('categoryLabel'),
    CATEGORY_MENU: XacmlEditor.CATEGORY_MENU,
    RULE_ALG_MENU: XacmlEditor.RULE_ALG_MENU,
    POLICY_ALG_MENU: XacmlEditor.POLICY_ALG_MENU,
    ADDITIONS: XacmlEditor.ADDITIONS
};
