// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: xacml_alfa.ts
//
// ---------------------------------------------------------------------------
// ALFA — THE ABBREVIATED LANGUAGE FOR AUTHORIZATION — READ AND WRITTEN.
//
// The THIRD rendering of `xacml_model.js`, and the one people actually want to
// look at. A policy that is forty lines of XML is eight lines of ALFA, and the
// eight say the same thing:
//
//     policy staffAccess {
//         apply denyUnlessPermit
//         rule allowStaff {
//             permit
//             target clause employeeType == "staff" and actionId == "GET"
//         }
//     }
//
// So this file is a parser and an emitter over the same model the XML reader
// produces, and NOTHING downstream knows which one a policy came from — see
// `xacml_model.js`'s header for why that is the rule this directory is built
// on. It is also what made this phase cheap: the model, the validator and the
// writer were already there, so ALFA is a syntax and not a second policy
// system.
//
// ---------------------------------------------------------------------------
// ALFA IS A COMMITTEE SPECIFICATION DRAFT, NOT A RATIFIED STANDARD.
//
// It was Axiomatics' language, contributed to the OASIS XACML TC, and it has
// never gone to Committee Specification. There is no conformance suite for it,
// no schema, and no second implementation to disagree with — which is a very
// different footing from the rest of this directory, where 455 cases somebody
// else wrote hold the engine honest.
//
// So the contract this file offers is one it can actually keep, stated rather
// than implied:
//
//   **ANYTHING THIS EMITTER WRITES, THIS PARSER READS, AND THE POLICY DECIDES
//   IDENTICALLY EITHER WAY.**
//
// `tests/xacml_alfa.js` asserts exactly that, in both directions, over every
// policy the templates can build and over the seeded one. What this file does
// NOT claim is that it reads every ALFA document in the world: the language
// has corners — macros, `advice` at namespace scope, imports across files —
// that nothing here emits and nothing here parses, and it says so when it
// meets one rather than guessing.
//
// ---------------------------------------------------------------------------
// FOUR PLACES THIS DIALECT IS EXPLICIT WHERE ALFA IS VAGUE, AND EACH IS
// WRITTEN DOWN BECAUSE A READER WILL OTHERWISE THINK IT IS A BUG.
//
// 1. TYPED LITERALS. ALFA has native syntax for strings, integers, booleans
//    and doubles and nothing agreed for the other thirteen datatypes. This
//    dialect writes those as a cast — `date("2026-01-01")`,
//    `anyURI("https://x/y")` — and reads the same. Without it a `date` would
//    have to be emitted as a string and would come back as one, which is a
//    policy that silently stops comparing dates.
//
// 2. THE THREE LEVELS OF A TARGET MAP ONTO `clause`, `or` AND `and`, in that
//    order. A XACML Target is AnyOf* (ANDed), an AnyOf is AllOf* (ORed) and an
//    AllOf is Match* (ANDed) — so each `clause` is one AnyOf, `or` separates
//    alternatives within it, and `and` joins matches inside an alternative.
//    `and` binds tighter than `or`, which makes `A and B or C` mean
//    `(A and B) or C` and lands on exactly the shape XACML wants.
//
// 3. AN ATTRIBUTE IS DECLARED BEFORE IT IS USED. ALFA references attributes by
//    a short name and the mapping to a category, an AttributeId and a datatype
//    lives in an `attribute` declaration. The emitter writes one for every
//    designator it meets and the parser refuses a name it has not seen — which
//    is the single most useful refusal in this file, because a typo in an
//    attribute name is otherwise a policy that quietly matches nothing.
//
// 4. A BARE NAME MAY ALSO BE A FUNCTION, AND THAT IS WHAT A HIGHER-ORDER
//    FUNCTION TAKES. `anyOfAny(stringEqual, a, b)` passes the FUNCTION
//    `string-equal` as an argument — a `<Function>` element in XACML, not an
//    `<AttributeValue>` and not a designator — and the seven higher-order
//    functions this engine implements are the only place one appears. The
//    emitter has always written it as the bare short name, which is the only
//    spelling ALFA has; the parser read it as an attribute reference and
//    refused the document, so `anyOfAny` round-tripped in one direction only.
//    It was found the day the first policy here used one — the `role-issuance`
//    template, whose whole condition is an intersection test.
//
//    **A DECLARATION WINS.** A name that is BOTH declared as an attribute and
//    the short name of a function is the attribute, because the declaration is
//    something somebody wrote in this document on purpose. The emitter makes
//    sure the two can never collide from its side: `collectAttributes()` will
//    not hand a designator a short name that a function already owns, and
//    numbers it instead. Point 3's refusal is unchanged for every name that is
//    neither — it just says so about both kinds now.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `AlfaLanguage` takes the logger and the three engine modules it reads
// (`xacml_model.js`, `xacml_datatypes.js`, `xacml_functions.js`, which stay
// JavaScript because the remote PEP's image copies them by name) through its
// constructor. The name tables that come from `xacml_model.js` alone stay
// module-level constants and are static members; the index of functions by
// their ALFA name is built from the function library, so it is built by the
// constructor and is an instance member. The parser's helpers stay closures
// inside `parse()`, because they share its position in the token list.
//
// The module still exports every old name, for `xacml_admin.ts` and
// `tests/xacml_alfa.js`: each function a FACADE forwarding to the instance the
// composition root builds and installs (#50's R2), and the function index a
// getter reading that instance's. A process without the root builds a
// default when this module loads — which is also what builds the function
// index at load, as the original did.
// ---------------------------------------------------------------------------
const helpers = require("../xacml_runtime");
const InstanceSlot = require("./xacml_slot");
const model = require("./xacml_model");
const datatypes = require("./xacml_datatypes");
const functions = require("./xacml_functions");
const F1 = 'urn:oasis:names:tc:xacml:1.0:function:';
const F3 = 'urn:oasis:names:tc:xacml:3.0:function:';
const TYPE = model.TYPE;
// ---------------------------------------------------------------------------
// THE NAMES ALFA USES FOR THINGS THAT HAVE URIs IN XACML.
// ---------------------------------------------------------------------------
const CATEGORY_NAMES = {
    subjectCat: model.CATEGORY.ACCESS_SUBJECT,
    resourceCat: model.CATEGORY.RESOURCE,
    actionCat: model.CATEGORY.ACTION,
    environmentCat: model.CATEGORY.ENVIRONMENT,
    recipientSubjectCat: model.CATEGORY.RECIPIENT_SUBJECT,
    intermediarySubjectCat: model.CATEGORY.INTERMEDIARY_SUBJECT,
    codebaseCat: model.CATEGORY.CODEBASE,
    requestingMachineCat: model.CATEGORY.REQUESTING_MACHINE
};
const CATEGORY_URIS = {};
Object.keys(CATEGORY_NAMES).forEach(function (name) {
    CATEGORY_URIS[CATEGORY_NAMES[name]] = name;
});
// The combining algorithms, in ALFA's camel case. Both the 3.0 and the legacy
// 1.0 spellings map to the same ALFA name, and the emitter writes the 3.0 one
// back — which is a NORMALISATION and is worth knowing: a policy that came in
// naming the legacy algorithm and goes out through ALFA names the modern one.
// They are different functions (see `xacml_pdp.js`), so this is the one place
// a round trip through ALFA can change what a policy does, and it only does so
// for the legacy spellings.
const ALGORITHM_NAMES = {
    denyOverrides: [model.RULE_ALG.DENY_OVERRIDES,
        model.POLICY_ALG.DENY_OVERRIDES],
    permitOverrides: [model.RULE_ALG.PERMIT_OVERRIDES,
        model.POLICY_ALG.PERMIT_OVERRIDES],
    orderedDenyOverrides: [model.RULE_ALG.ORDERED_DENY_OVERRIDES,
        model.POLICY_ALG.ORDERED_DENY_OVERRIDES],
    orderedPermitOverrides: [model.RULE_ALG.ORDERED_PERMIT_OVERRIDES,
        model.POLICY_ALG.ORDERED_PERMIT_OVERRIDES],
    denyUnlessPermit: [model.RULE_ALG.DENY_UNLESS_PERMIT,
        model.POLICY_ALG.DENY_UNLESS_PERMIT],
    permitUnlessDeny: [model.RULE_ALG.PERMIT_UNLESS_DENY,
        model.POLICY_ALG.PERMIT_UNLESS_DENY],
    firstApplicable: [model.RULE_ALG.FIRST_APPLICABLE,
        model.POLICY_ALG.FIRST_APPLICABLE],
    onlyOneApplicable: [null, model.POLICY_ALG.ONLY_ONE_APPLICABLE]
};
// The comparison functions that get an operator instead of a call. Everything
// else is written as a call, which is both readable and unambiguous — the
// alternative is inventing operators the language does not have.
const OPERATORS = [
    { symbol: '==', suffix: '-equal' },
    { symbol: '>=', suffix: '-greater-than-or-equal' },
    { symbol: '<=', suffix: '-less-than-or-equal' },
    { symbol: '>', suffix: '-greater-than' },
    { symbol: '<', suffix: '-less-than' }
];
// ---------------------------------------------------------------------------
// THE TOKENIZER.
// ---------------------------------------------------------------------------
const PUNCTUATION = ['==', '!=', '>=', '<=', '&&', '||', '{', '}', '(', ')',
    ',', '=', '>', '<', '!', '$'];
/**
 * Reads and writes ALFA, the Abbreviated Language for Authorization, over
 * the same policy model the XML and JSON readers produce.
 *
 * Nothing downstream can tell which syntax a policy arrived in.
 */
class AlfaLanguage {
    /**
     * Builds the language over its dependencies and indexes the function
     * library by short name.
     *
     * @param deps - the logger, the model, the datatype table and the function
     *   library
     */
    constructor(deps) {
        this.deps = deps;
        // The inverse of `shortFunctionName()`. Built once from the library, so
        // every function this service implements is reachable by its camel-case
        // name and nothing else is.
        /**
         * Every implemented function's URI, keyed by its camel-case ALFA name;
         * where two share a name the 3.0 function wins.
         */
        this.functionByShortName = {};
        const self = this;
        deps.log.debug("Entering AlfaLanguage.constructor().");
        deps.functions.names().forEach(function (uri) {
            const name = self.shortFunctionName(uri);
            // A collision would be two functions with one ALFA name; the 3.0
            // one
            // wins, because that is the spelling a new policy should use.
            // Recorded
            // rather than silent — see `collisions()`.
            if (!self.functionByShortName[name] || uri.indexOf(':3.0:') >= 0) {
                self.functionByShortName[name] = uri;
            }
        });
        deps.log.debug("Leaving AlfaLanguage.constructor().");
    }
    // What the composition root passes, from the real modules.
    /**
     * Returns the dependencies built from the real modules, as the
     * composition root passes them.
     *
     * @returns the dependencies
     */
    static defaultDeps() {
        helpers.log.debug("Entering AlfaLanguage.defaultDeps().");
        helpers.log.debug("Leaving AlfaLanguage.defaultDeps().");
        return {
            log: helpers.log,
            model: model,
            datatypes: datatypes,
            functions: functions
        };
    }
    /**
     * Returns the ALFA name of a combining algorithm URI.
     *
     * A legacy 1.0 or 1.1 spelling maps by its suffix to the name its modern
     * counterpart shares, so writing it back names the 3.0 algorithm.
     * @param uri - the combining algorithm identifier
     * @returns the ALFA name, or null when there is none
     */
    algorithmNameOf(uri) {
        const { log } = this.deps;
        log.debug("Entering AlfaLanguage.algorithmNameOf().");
        const names = Object.keys(ALGORITHM_NAMES);
        for (let i = 0; i < names.length; i += 1) {
            if (ALGORITHM_NAMES[names[i]].indexOf(uri) >= 0) {
                log.debug("Leaving AlfaLanguage.algorithmNameOf().");
                return names[i];
            }
        }
        // A legacy 1.0 or 1.1 spelling, which shares an ALFA name with its
        // modern
        // counterpart. Mapped by SUFFIX rather than left unnamed, because an
        // unnamed algorithm would make the whole policy unrenderable.
        const suffix = String(uri).split(':').pop();
        const camel = suffix.replace(/-([a-z])/g, function (whole, letter) {
            return letter.toUpperCase();
        });
        log.debug("Leaving AlfaLanguage.algorithmNameOf().");
        return ALGORITHM_NAMES[camel] ? camel : null;
    }
    /**
     * Returns the combining algorithm URI for an ALFA name.
     *
     * @param name - the ALFA algorithm name
     * @param forPolicySet - true for the policy-combining URI, otherwise the
     *   rule-combining one
     * @returns the URI, or null when the name is unknown or has no URI of
     *   that kind
     */
    algorithmUriOf(name, forPolicySet) {
        const { log } = this.deps;
        log.debug("Entering AlfaLanguage.algorithmUriOf().");
        const pair = ALGORITHM_NAMES[name];
        if (!pair) {
            log.debug("Leaving AlfaLanguage.algorithmUriOf().");
            return null;
        }
        log.debug("Leaving AlfaLanguage.algorithmUriOf().");
        return forPolicySet ? pair[1] : pair[0];
    }
    operatorFor(functionId) {
        const { log } = this.deps;
        log.debug("Entering AlfaLanguage.operatorFor().");
        const short = String(functionId).replace(/^.*:function:/, '');
        for (let i = 0; i < OPERATORS.length; i += 1) {
            if (short.slice(-OPERATORS[i].suffix.length) ===
                OPERATORS[i].suffix) {
                log.debug("Leaving AlfaLanguage.operatorFor().");
                return OPERATORS[i].symbol;
            }
        }
        log.debug("Leaving AlfaLanguage.operatorFor().");
        return null;
    }
    // The function a `<type> <symbol> <type>` comparison means. Resolved
    // through
    // the real library, so an operator on a type that has no such function is
    // refused rather than producing a URI nothing implements.
    functionForOperator(symbol, typeUri) {
        const { log, datatypes, functions, model } = this.deps;
        const TYPE = model.TYPE;
        log.debug("Entering AlfaLanguage.functionForOperator().");
        const entry = OPERATORS.filter(function (one) {
            return one.symbol === symbol;
        })[0];
        if (!entry) {
            log.debug("Leaving AlfaLanguage.functionForOperator().");
            return null;
        }
        const row = datatypes.typeOf(typeUri);
        if (!row) {
            log.debug("Leaving AlfaLanguage.functionForOperator().");
            return null;
        }
        const duration = typeUri === TYPE.DAYTIME_DURATION ||
            typeUri === TYPE.YEARMONTH_DURATION;
        const uri = (duration && entry.suffix === '-equal' ? F3 : F1) +
            row.name + entry.suffix;
        log.debug("Leaving AlfaLanguage.functionForOperator().");
        return functions.lookup(uri) ? uri : null;
    }
    /**
     * Returns a function's camel-case ALFA name: the part after `:function:`
     * with each hyphen folded into a capital.
     *
     * @param uri - the function identifier
     * @returns the short name
     */
    shortFunctionName(uri) {
        const { log } = this.deps;
        log.debug("Entering AlfaLanguage.shortFunctionName().");
        log.debug("Leaving AlfaLanguage.shortFunctionName().");
        return String(uri).replace(/^.*:function:/, '')
            .replace(/-([a-z0-9])/g, function (whole, ch) {
            return ch.toUpperCase();
        });
    }
    // -------------------------------------------------------------------------
    // THE EMITTER.
    // -------------------------------------------------------------------------
    // Every designator in a policy gets a short name, and the same designator
    // always gets the same one. Collected in one pass BEFORE anything is
    // written,
    // because the declarations go at the top and the uses come after.
    collectAttributes(policy) {
        const self = this;
        const { log } = this.deps;
        log.debug('Entering AlfaLanguage.collectAttributes().');
        const byKey = {};
        const order = [];
        function note(designator) {
            log.debug("Entering note().");
            const key = designator.category + '|' + designator.attributeId +
              '|' +
                designator.dataType;
            if (byKey[key]) {
                log.debug("Leaving note().");
                return;
            }
            const base = self.shortNameForAttribute(designator.attributeId);
            let name = base;
            let n = 2;
            // A COLLISION IS ON THE SHORT NAME AND NOT ON THE ATTRIBUTE. Two
            // different attributes can end with the same segment —
            // `...:subject:role`
            // and `...:resource:role` — and giving both the name `role` would
            // make
            // the second declaration silently replace the first, so a policy
            // would
            // read an attribute out of the wrong category. Numbered instead.
            // AND NOT
            // A NAME A FUNCTION ALREADY OWNS. A bare word in an expression is
            // an
            // attribute reference OR a function reference (header point 4), and
            // the
            // parser resolves it by looking at the declarations first — so a
            // designator called `stringEqual` would shadow the function of that
            // name
            // for the whole document and turn a higher-order argument into a
            // bag. It
            // is vanishingly rare and costs one comparison to make impossible.
            while (order.some(function (one) { return one.name === name; }) ||
                self.functionByShortName[name]) {
                name = base + n;
                n += 1;
            }
            byKey[key] = name;
            order.push({ name: name, category: designator.category,
                attributeId: designator.attributeId,
                dataType: designator.dataType });
            log.debug("Leaving note().");
        }
        self.walkDesignators(policy, note);
        log.debug('Leaving AlfaLanguage.collectAttributes(). ' + order.length +
            ' attribute(s).');
        return { byKey: byKey, order: order };
    }
    /**
     * Derives a short ALFA name for an attribute from the last segment of its
     * identifier, in camel case.
     *
     * Returns `attr` when nothing usable is left, and prefixes `a` to a name
     * that would start with a digit.
     * @param attributeId - the attribute identifier
     * @returns the short name
     */
    shortNameForAttribute(attributeId) {
        const { log } = this.deps;
        log.debug("Entering AlfaLanguage.shortNameForAttribute().");
        const tail = String(attributeId).split(':').pop().split('/').pop();
        const camel = tail.replace(/[-_.]([a-zA-Z0-9])/g, function (whole, ch) {
            return ch.toUpperCase();
        }).replace(/[^A-Za-z0-9]/g, '');
        if (!camel) {
            log.debug("Leaving AlfaLanguage.shortNameForAttribute().");
            return 'attr';
        }
        log.debug("Leaving AlfaLanguage.shortNameForAttribute().");
        return /^[0-9]/.test(camel)
            ? 'a' + camel
            : camel.charAt(0).toLowerCase() + camel.slice(1);
    }
    walkDesignators(node, visit) {
        const { log } = this.deps;
        log.debug("Entering AlfaLanguage.walkDesignators().");
        function expression(one) {
            log.debug("Entering expression().");
            if (!one) {
                log.debug("Leaving expression().");
                return;
            }
            if (one.kind === 'designator') {
                visit(one);
                log.debug("Leaving expression().");
                return;
            }
            if (one.kind === 'apply') {
                (one.args || []).forEach(expression);
            }
            log.debug("Leaving expression().");
        }
        function target(one) {
            log.debug("Entering target().");
            if (!one || !one.anyOf) {
                log.debug("Leaving target().");
                return;
            }
            one.anyOf.forEach(function (anyOf) {
                anyOf.allOf.forEach(function (allOf) {
                    allOf.matches.forEach(function (match) {
                        expression(match.reference);
                    });
                });
            });
            log.debug("Leaving target().");
        }
        function holders(list) {
            log.debug("Entering holders().");
            (list || []).forEach(function (holder) {
                (holder.assignments || []).forEach(function (assignment) {
                    expression(assignment.expression);
                });
            });
            log.debug("Leaving holders().");
        }
        function policy(one) {
            log.debug("Entering policy().");
            target(one.target);
            holders(one.obligations);
            holders(one.advice);
            if (one.kind === 'PolicySet') {
                (one.children || []).forEach(function (child) {
                    if (child.kind === 'Policy' || child.kind === 'PolicySet') {
                        policy(child);
                    }
                });
                log.debug("Leaving policy().");
                return;
            }
            Object.keys(one.variables || {}).forEach(function (id) {
                expression(one.variables[id]);
            });
            (one.rules || []).forEach(function (rule) {
                target(rule.target);
                expression(rule.condition);
                holders(rule.obligations);
                holders(rule.advice);
            });
            log.debug("Leaving policy().");
        }
        policy(node);
        log.debug("Leaving AlfaLanguage.walkDesignators().");
    }
    // A literal. Native syntax for the four types ALFA has one for; a cast for
    // the other thirteen. See point 1 in the header.
    literalOf(expression) {
        const self = this;
        const { log, model, datatypes } = this.deps;
        const TYPE = model.TYPE;
        log.debug("Entering AlfaLanguage.literalOf().");
        const type = model.canonicalType(expression.type);
        const lexical = String(expression.lexical === undefined
            ? '' : expression.lexical);
        if (type === TYPE.STRING) {
            log.debug("Leaving AlfaLanguage.literalOf().");
            return self.quote(lexical);
        }
        if (type === TYPE.BOOLEAN) {
            log.debug("Leaving AlfaLanguage.literalOf().");
            return lexical === 'true' || lexical === '1' ? 'true' : 'false';
        }
        if (type === TYPE.INTEGER || type === TYPE.DOUBLE) {
            // Written bare only when it LOOKS like a number. A double of `INF`
            // or
            // `NaN` is a legal lexical form that is not a numeric literal in
            // any
            // language, so it takes the cast form and round-trips.
            if (/^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$/.test(lexical)) {
                log.debug("Leaving AlfaLanguage.literalOf().");
                return lexical;
            }
        }
        const row = datatypes.typeOf(type);
        log.debug("Leaving AlfaLanguage.literalOf().");
        return (row ? row.name : 'string') + '(' + self.quote(lexical) + ')';
    }
    quote(text) {
        const { log } = this.deps;
        log.debug("Entering AlfaLanguage.quote().");
        log.debug("Leaving AlfaLanguage.quote().");
        return '"' + String(text).replace(/\\/g,
          '\\\\').replace(/"/g, '\\"') + '"';
    }
    emitExpression(expression, attributes) {
        const self = this;
        const { log } = this.deps;
        log.debug("Entering AlfaLanguage.emitExpression().");
        if (!expression) {
            log.debug("Leaving AlfaLanguage.emitExpression().");
            return '';
        }
        if (expression.kind === 'value') {
            log.debug("Leaving AlfaLanguage.emitExpression().");
            return self.literalOf(expression);
        }
        if (expression.kind === 'designator') {
            const key = expression.category + '|' + expression.attributeId +
              '|' +
                expression.dataType;
            log.debug("Leaving AlfaLanguage.emitExpression().");
            return attributes.byKey[key] ||
              self.shortNameForAttribute(expression.attributeId);
        }
        if (expression.kind === 'variableRef') {
            log.debug("Leaving AlfaLanguage.emitExpression().");
            return '$' + expression.variableId;
        }
        if (expression.kind === 'function') {
            log.debug("Leaving AlfaLanguage.emitExpression().");
            return self.shortFunctionName(expression.functionId);
        }
        if (expression.kind === 'selector') {
            log.debug("Leaving AlfaLanguage.emitExpression().");
            // Nothing here evaluates an AttributeSelector, and ALFA has no
            // agreed
            // syntax for one. Emitted as a call that names it, so the document
            // is
            // readable and the parser refuses it rather than pretending.
            return 'attributeSelector(' + self.quote(expression.category) +
              ', ' +
                self.quote(expression.path) + ', ' +
                self.quote(expression.dataType) + ')';
        }
        if (expression.kind === 'apply') {
            const args = (expression.args || []).map(function (one) {
                return self.emitExpression(one, attributes);
            });
            const short = self.shortFunctionName(expression.functionId);
            if (short === 'and' || short === 'or') {
                const symbol = short === 'and' ? ' && ' : ' || ';
                log.debug("Leaving AlfaLanguage.emitExpression().");
                return args.length ? '(' + args.join(symbol) +
                  ')' : (short === 'and' ? 'true' : 'false');
            }
            if (short === 'not' && args.length === 1) {
                log.debug("Leaving AlfaLanguage.emitExpression().");
                return '!' + args[0];
            }
            const operator = self.operatorFor(expression.functionId);
            if (operator && args.length === 2) {
                log.debug("Leaving AlfaLanguage.emitExpression().");
                return '(' + args[0] + ' ' + operator + ' ' + args[1] + ')';
            }
            log.debug("Leaving AlfaLanguage.emitExpression().");
            return short + '(' + args.join(', ') + ')';
        }
        log.debug("Leaving AlfaLanguage.emitExpression().");
        return '/* unrenderable */';
    }
    emitTarget(target, attributes, indent) {
        const self = this;
        const { log } = this.deps;
        log.debug("Entering AlfaLanguage.emitTarget().");
        if (!target || !target.anyOf || !target.anyOf.length) {
            log.debug("Leaving AlfaLanguage.emitTarget().");
            return '';
        }
        log.debug("Leaving AlfaLanguage.emitTarget().");
        return target.anyOf.map(function (anyOf) {
            const alternatives = anyOf.allOf.map(function (allOf) {
                return allOf.matches.map(function (match) {
                    const left = self.emitExpression(match.reference,
                      attributes);
                    const right = self.emitExpression(match.value, attributes);
                    const operator = self.operatorFor(match.matchId);
                    if (operator) {
                        // ATTRIBUTE ON THE LEFT, VALUE ON THE RIGHT — which is
                        // the reverse
                        // of XACML, where a Match's AttributeValue comes first.
                        // ALFA reads
                        // the way a person writes a condition, and the parser
                        // swaps them
                        // back. For a NON-symmetric operator that swap matters,
                        // which is
                        // why `>` becomes `<` and not `>` when the sides are
                        // exchanged.
                        return left + ' ' + self.mirrorOperator(operator) +
                          ' ' + right;
                    }
                    return self.shortFunctionName(match.matchId) + '(' + right +
                      ', ' +
                        left + ')';
                }).join(' and ');
            }).join(' or ');
            return indent + 'target clause ' + alternatives;
        }).join('\n');
    }
    // `a > b` written with the sides exchanged is `b < a`. Only the four
    // ordering
    // operators are affected; `==` is symmetric.
    mirrorOperator(symbol) {
        const { log } = this.deps;
        log.debug("Entering AlfaLanguage.mirrorOperator().");
        if (symbol === '>') {
            log.debug("Leaving AlfaLanguage.mirrorOperator().");
            return '<';
        }
        if (symbol === '<') {
            log.debug("Leaving AlfaLanguage.mirrorOperator().");
            return '>';
        }
        if (symbol === '>=') {
            log.debug("Leaving AlfaLanguage.mirrorOperator().");
            return '<=';
        }
        if (symbol === '<=') {
            log.debug("Leaving AlfaLanguage.mirrorOperator().");
            return '>=';
        }
        log.debug("Leaving AlfaLanguage.mirrorOperator().");
        return symbol;
    }
    emitHolders(list, attributes, indent, keyword) {
        const self = this;
        const { log } = this.deps;
        log.debug("Entering AlfaLanguage.emitHolders().");
        if (!list || !list.length) {
            log.debug("Leaving AlfaLanguage.emitHolders().");
            return '';
        }
        const byEffect = { Permit: [], Deny: [] };
        list.forEach(function (holder) {
            (byEffect[holder.on] || byEffect.Permit).push(holder);
        });
        log.debug("Leaving AlfaLanguage.emitHolders().");
        return Object.keys(byEffect).filter(function (effect) {
            return byEffect[effect].length;
        }).map(function (effect) {
            const body = byEffect[effect].map(function (holder) {
                // AN ASSIGNMENT'S ATTRIBUTE IS NAMED AS WRITTEN, QUOTED WHERE
                // IT IS
                // NOT A PLAIN WORD (#62 P3). It was always written bare, which
                // read
                // back only while every assignment in every template happened
                // to be
                // one — the issuance policy's risk obligation assigns
                // `urn:sts:xacml:risk-action`, whose colons the reader took for
                // punctuation. The reader has always accepted either spelling.
                const assignments = (holder.assignments ||
                  []).map(function (one) {
                    const name =
                        /^[A-Za-z_][A-Za-z0-9_]*$/.test(String(one.attributeId))
                        ? String(one.attributeId) : self.quote(one.attributeId);
                    return indent + '        ' + name + ' = ' +
                        self.emitExpression(one.expression, attributes);
                }).join('\n');
                return indent + '    ' + keyword + ' ' + self.quote(holder.id) +
                    (assignments
                        ? ' {\n' + assignments + '\n' + indent + '    }'
                        : ' { }');
            }).join('\n');
            return indent + 'on ' + effect.toLowerCase() + ' {\n' + body +
              '\n' +
                indent + '}';
        }).join('\n');
    }
    emitRule(rule, attributes, indent) {
        const self = this;
        const { log } = this.deps;
        log.debug("Entering AlfaLanguage.emitRule().");
        const lines = [];
        lines.push(indent + 'rule ' + self.identifier(rule.id) + ' {');
        const inner = indent + '    ';
        // A DESCRIPTION IS A PROPERTY AND NOT A `//` COMMENT, and that is the
        // whole
        // of why: the tokenizer discards comments, so a description written as
        // one
        // survives being read by a person and is DELETED by the next round
        // trip.
        // The XML reader had the same defect and it cost every explanation in
        // every
        // policy that went through the editor. `description = "..."` reads
        // back.
        if (rule.description) {
            lines.push(inner + 'description = ' +
                self.quote(rule.description.replace(/\s+/g, ' ')));
        }
        lines.push(inner + rule.effect.toLowerCase());
        const target = self.emitTarget(rule.target, attributes, inner);
        if (target) {
            lines.push(target);
        }
        if (rule.condition) {
            lines.push(inner + 'condition ' +
                self.emitExpression(rule.condition, attributes));
        }
        const obligations = self.emitHolders(rule.obligations, attributes,
          inner, 'obligation');
        if (obligations) {
            lines.push(obligations);
        }
        const advice = self.emitHolders(rule.advice, attributes, inner,
          'advice');
        if (advice) {
            lines.push(advice);
        }
        lines.push(indent + '}');
        log.debug("Leaving AlfaLanguage.emitRule().");
        return lines.join('\n');
    }
    // An ALFA identifier cannot hold a colon, and every PolicyId in the world
    // is
    // a URI. So the identifier is a SLUG and the full URI is carried in an `id`
    // property beside it — which is what makes a round trip lossless. Emitting
    // only the slug would silently rename every policy that went through ALFA.
    identifier(uri) {
        const { log } = this.deps;
        log.debug("Entering AlfaLanguage.identifier().");
        const tail = String(uri).split(':').pop().split('/').pop();
        const camel = tail.replace(/[-_.]([a-zA-Z0-9])/g, function (whole, ch) {
            return ch.toUpperCase();
        }).replace(/[^A-Za-z0-9]/g, '');
        if (!camel) {
            log.debug("Leaving AlfaLanguage.identifier().");
            return 'p';
        }
        log.debug("Leaving AlfaLanguage.identifier().");
        return /^[0-9]/.test(camel) ? 'p' + camel : camel;
    }
    emitPolicyBody(policy, attributes, indent) {
        const self = this;
        const { log } = this.deps;
        log.debug("Entering AlfaLanguage.emitPolicyBody().");
        const lines = [];
        const keyword = policy.kind === 'PolicySet' ? 'policyset' : 'policy';
        lines.push(indent + keyword + ' ' + self.identifier(policy.id) + ' {');
        const inner = indent + '    ';
        lines.push(inner + 'id = ' + self.quote(policy.id));
        lines.push(inner + 'version = ' + self.quote(policy.version || '1.0'));
        // See emitRule(): a property rather than a comment, so it survives.
        if (policy.description) {
            lines.push(inner + 'description = ' +
                self.quote(policy.description.replace(/\s+/g, ' ')));
        }
        const algorithm = self.algorithmNameOf(policy.combiningAlgId);
        lines.push(inner + 'apply ' + (algorithm || 'denyUnlessPermit'));
        if (!algorithm) {
            lines.push(inner + '// The original combining algorithm was ' +
                policy.combiningAlgId + ', which has no ALFA name.');
        }
        const target = self.emitTarget(policy.target, attributes, inner);
        if (target) {
            lines.push(target);
        }
        if (policy.kind === 'PolicySet') {
            (policy.children || []).forEach(function (child) {
                if (child.kind === 'Policy' || child.kind === 'PolicySet') {
                    lines.push(self.emitPolicyBody(child, attributes, inner));
                }
                else {
                    lines.push(inner + '// ' + child.kind + ' ' + child.ref +
                        ' — a reference, which ALFA resolves by name at ' +
                          'compile ' +
                        'time and this dialect does not follow.');
                }
            });
        }
        else {
            Object.keys(policy.variables || {}).forEach(function (id) {
                lines.push(inner + '$' + id + ' = ' +
                    self.emitExpression(policy.variables[id], attributes));
            });
            (policy.rules || []).forEach(function (rule) {
                lines.push(self.emitRule(rule, attributes, inner));
            });
        }
        const obligations = self.emitHolders(policy.obligations, attributes,
          inner, 'obligation');
        if (obligations) {
            lines.push(obligations);
        }
        const advice = self.emitHolders(policy.advice, attributes, inner,
          'advice');
        if (advice) {
            lines.push(advice);
        }
        lines.push(indent + '}');
        log.debug("Leaving AlfaLanguage.emitPolicyBody().");
        return lines.join('\n');
    }
    /**
     * Renders a policy or policy set as an ALFA document.
     *
     * Every designator is declared once at the top under a short name; legacy
     * combining algorithms are written with their 3.0 names.
     * @param policy - the Policy or PolicySet
     * @param options - optional; `namespace`, the ALFA namespace (`stsMock` by
     *   default)
     * @returns the ALFA text
     */
    write(policy, options) {
        const self = this;
        const { log, datatypes } = this.deps;
        log.debug('Entering AlfaLanguage.write(). id=' + policy.id);
        const settings = options || {};
        const namespace = settings.namespace || 'stsMock';
        const attributes = self.collectAttributes(policy);
        const declarations = attributes.order.map(function (one) {
            const row = datatypes.typeOf(one.dataType);
            return '    attribute ' + one.name + ' {\n' +
                '        category = ' + (CATEGORY_URIS[one.category] ||
                self.quote(one.category)) + '\n' +
                '        id = ' + self.quote(one.attributeId) + '\n' +
                '        type = ' + (row ? row.name : 'string') + '\n' +
                '    }';
        }).join('\n');
        const body = self.emitPolicyBody(policy, attributes, '    ');
        const text = 'namespace ' + namespace + ' {\n' +
            (declarations ? declarations + '\n\n' : '') + body + '\n}\n';
        log.debug('Leaving AlfaLanguage.write(). ' + text.length + ' bytes.');
        return text;
    }
    /**
     * Splits ALFA source into tokens, ending with an `end` token.
     *
     * @param text - the source
     * @returns the tokens, each with its kind, value and line
     * @throws a syntax error on a character ALFA does not use
     */
    tokenize(text) {
        const { log, model } = this.deps;
        log.debug('Entering AlfaLanguage.tokenize().');
        const tokens = [];
        let i = 0;
        let line = 1;
        const source = String(text);
        while (i < source.length) {
            const ch = source[i];
            if (ch === '\n') {
                line += 1;
                i += 1;
                continue;
            }
            if (/\s/.test(ch)) {
                i += 1;
                continue;
            }
            if (ch === '/' && source[i + 1] === '/') {
                while (i < source.length && source[i] !== '\n') {
                    i += 1;
                }
                continue;
            }
            if (ch === '/' && source[i + 1] === '*') {
                const end = source.indexOf('*/', i + 2);
                if (end < 0) {
                    log.debug('Leaving AlfaLanguage.tokenize(). ' +
                      'Unterminated comment.');
                    throw model.syntaxError('An unterminated /* comment ' +
                      'at line ' + line +
                        '.');
                }
                line += source.slice(i, end).split('\n').length - 1;
                i = end + 2;
                continue;
            }
            if (ch === '"') {
                let value = '';
                i += 1;
                while (i < source.length && source[i] !== '"') {
                    if (source[i] === '\\') {
                        i += 1;
                        if (i >= source.length) {
                            break;
                        }
                    }
                    value += source[i];
                    i += 1;
                }
                if (i >= source.length) {
                    log.debug('Leaving AlfaLanguage.tokenize(). ' +
                      'Unterminated string.');
                    throw model.syntaxError('An unterminated string at line ' +
                      line +
                        '.');
                }
                i += 1;
                tokens.push({ kind: 'string', value: value, line: line });
                continue;
            }
            if (/[0-9]/.test(ch) ||
                (ch === '-' && /[0-9]/.test(source[i + 1] || ''))) {
                let value = ch;
                i += 1;
                while (i < source.length && /[0-9.eE+-]/.test(source[i])) {
                    // An exponent's sign belongs to the number; a bare `-`
                    // after a digit
                    // does not, and treating it as part of the number would
                    // swallow the
                    // operator in `a-1`.
                    if ((source[i] === '+' || source[i] === '-') &&
                        !/[eE]/.test(value[value.length - 1])) {
                        break;
                    }
                    value += source[i];
                    i += 1;
                }
                tokens.push({ kind: 'number', value: value, line: line });
                continue;
            }
            if (/[A-Za-z_]/.test(ch)) {
                let value = '';
                while (i < source.length && /[A-Za-z0-9_]/.test(source[i])) {
                    value += source[i];
                    i += 1;
                }
                tokens.push({ kind: 'word', value: value, line: line });
                continue;
            }
            const two = source.slice(i, i + 2);
            const punctuation = PUNCTUATION.indexOf(two) >= 0 ? two
                : (PUNCTUATION.indexOf(ch) >= 0 ? ch : null);
            if (!punctuation) {
                log.debug('Leaving AlfaLanguage.tokenize(). Unexpected ' +
                  'character.');
                throw model.syntaxError('Unexpected character "' + ch +
                  '" at line ' +
                    line + '.');
            }
            tokens.push({ kind: 'punct', value: punctuation, line: line });
            i += punctuation.length;
        }
        tokens.push({ kind: 'end', value: '', line: line });
        log.debug('Leaving AlfaLanguage.tokenize(). ' + tokens.length +
            ' token(s).');
        return tokens;
    }
    // -------------------------------------------------------------------------
    // THE PARSER.
    // -------------------------------------------------------------------------
    /**
     * Parses an ALFA document into the policy model.
     *
     * @param text - the ALFA source
     * @returns the root Policy or PolicySet
     * @throws a syntax error on anything that does not parse, or a document
     *   with no policy in it
     */
    parse(text) {
        const self = this;
        const { log, model, datatypes, functions } = this.deps;
        const TYPE = model.TYPE;
        log.debug('Entering AlfaLanguage.parse().');
        const tokens = self.tokenize(text);
        let at = 0;
        const attributes = {};
        function peek(offset) {
            log.debug("Entering peek().");
            log.debug("Leaving peek().");
            return tokens[at + (offset || 0)];
        }
        function next() {
            log.debug("Entering next().");
            const token = tokens[at];
            at += 1;
            log.debug("Leaving next().");
            return token;
        }
        function is(value, offset) {
            log.debug("Entering is().");
            const token = peek(offset);
            log.debug("Leaving is().");
            return token && token.value === value &&
                (token.kind === 'word' || token.kind === 'punct');
        }
        function expect(value) {
            log.debug("Entering expect().");
            const token = next();
            if (!token || token.value !== value) {
                throw model.syntaxError('Expected "' + value + '" at line ' +
                    (token ? token.line : '?') + ' but found "' +
                    (token ? token.value : 'the end of the document') + '".');
            }
            log.debug("Leaving expect().");
            return token;
        }
        function expectWord() {
            log.debug("Entering expectWord().");
            const token = next();
            if (!token || token.kind !== 'word') {
                throw model.syntaxError('Expected a name at line ' +
                  (token ? token.line : '?') +
                    ' but found "' + (token ? token.value : 'the end') + '".');
            }
            log.debug("Leaving expectWord().");
            return token.value;
        }
        function expectString() {
            log.debug("Entering expectString().");
            const token = next();
            if (!token || token.kind !== 'string') {
                throw model.syntaxError('Expected a quoted string at line ' +
                  (token ? token.line : '?') +
                    ' but found "' + (token ? token.value : 'the end') + '".');
            }
            log.debug("Leaving expectString().");
            return token.value;
        }
        // --- attribute declarations
        // ---------------------------------------------
        function attributeDeclaration() {
            log.debug('Entering attributeDeclaration().');
            expect('attribute');
            const name = expectWord();
            expect('{');
            const declared = { category: null, attributeId: null,
              dataType: null };
            while (!is('}')) {
                const key = expectWord();
                expect('=');
                if (key === 'category') {
                    const token = next();
                    declared.category = token.kind === 'string' ? token.value
                        : CATEGORY_NAMES[token.value];
                    if (!declared.category) {
                        throw model.syntaxError('Unknown category "' +
                          token.value + '" at line ' + token.line +
                            '. The names are: ' +
                              Object.keys(CATEGORY_NAMES).join(', ') +
                            ', or a category URI in quotes.');
                    }
                }
                else if (key === 'id') {
                    declared.attributeId = expectString();
                }
                else if (key === 'type') {
                    const token = next();
                    const wanted = token.kind === 'string' ?
                        token.value : token.value;
                    const found =
                        Object.keys(datatypes.TYPES).filter(function (uri) {
                        return datatypes.TYPES[uri].name === wanted ||
                          uri === wanted;
                    })[0];
                    if (!found) {
                        throw model.syntaxError('Unknown datatype "' + wanted +
                          '" at line ' + token.line + '.');
                    }
                    declared.dataType = found;
                }
                else {
                    throw model.syntaxError('An attribute declaration ' +
                      'takes category, id and type; "' + key +
                        '" is not one of them.');
                }
            }
            expect('}');
            if (!declared.category || !declared.attributeId ||
              !declared.dataType) {
                throw model.syntaxError('The attribute "' + name +
                  '" must declare all three of category, ' +
                    'id and type.');
            }
            attributes[name] = declared;
            log.debug('Leaving attributeDeclaration(). name=' + name);
        }
        function designatorFor(name, token) {
            log.debug("Entering designatorFor().");
            const declared = attributes[name];
            if (!declared) {
                // THE MOST USEFUL REFUSAL IN THIS FILE. See point 3 in the
                // header: a
                // typo in an attribute name is otherwise a policy that quietly
                // matches
                // nothing, and a policy that matches nothing looks exactly like
                // a
                // policy that is working correctly and denying you.
                throw model.syntaxError('The attribute "' + name +
                  '" is used at line ' +
                    (token ? token.line : '?') + ' and never declared. ALFA ' +
                    'references attributes by a short name; the category, ' +
                      'id and ' +
                    'type come from an `attribute ' + name +
                      ' { ... }` declaration. ' +
                    'It is not the name of a function this engine ' +
                      'implements either, ' +
                    'which is the OTHER thing a bare word may be — the ' +
                      'first argument ' +
                    'of a higher-order function such as `anyOfAny`.' +
                    (Object.keys(attributes).length
                        ? ' Declared here: ' +
                          Object.keys(attributes).sort().join(', ') +
                            '.'
                        : ' Nothing is declared in this document.'));
            }
            log.debug("Leaving designatorFor().");
            return { kind: 'designator', category: declared.category,
                attributeId: declared.attributeId,
                dataType: declared.dataType, issuer: null,
                mustBePresent: false };
        }
        // A BARE WORD IN AN EXPRESSION IS ONE OF TWO THINGS, and header point 4
        // argues the order they are tried in: an attribute the document
        // DECLARED,
        // or — where nothing declared it — the short name of a function, which
        // is
        // what the seven higher-order functions take as their first argument.
        // Only
        // a name that is neither reaches the refusal, which is point 3's and is
        // the
        // most useful one in this file.
        function nameReference(name, token) {
            log.debug("Entering nameReference().");
            if (attributes[name]) {
                log.debug("Leaving nameReference().");
                return designatorFor(name, token);
            }
            const uri = self.functionByShortName[name];
            if (uri) {
                log.debug('nameReference(): "' + name + '" is the function ' +
                  uri +
                    '.');
                log.debug("Leaving nameReference().");
                return { kind: 'function', functionId: uri };
            }
            log.debug("Leaving nameReference().");
            return designatorFor(name, token);
        }
        // --- expressions
        // ---------------------------------------------------------
        function primary() {
            log.debug("Entering primary().");
            const token = next();
            if (token.kind === 'string') {
                log.debug("Leaving primary().");
                return { kind: 'value', type: TYPE.STRING,
                  lexical: token.value };
            }
            if (token.kind === 'number') {
                const isDouble = /[.eE]/.test(token.value);
                log.debug("Leaving primary().");
                return { kind: 'value',
                    type: isDouble ? TYPE.DOUBLE : TYPE.INTEGER,
                    lexical: token.value };
            }
            if (token.kind === 'punct' && token.value === '(') {
                const inner = expression();
                expect(')');
                log.debug("Leaving primary().");
                return inner;
            }
            if (token.kind === 'punct' && token.value === '!') {
                log.debug("Leaving primary().");
                return { kind: 'apply', functionId: F1 + 'not',
                  args: [primary()] };
            }
            if (token.kind === 'punct' && token.value === '$') {
                log.debug("Leaving primary().");
                return { kind: 'variableRef', variableId: expectWord() };
            }
            if (token.kind === 'word') {
                if (token.value === 'true' || token.value === 'false') {
                    log.debug("Leaving primary().");
                    return { kind: 'value', type: TYPE.BOOLEAN,
                      lexical: token.value };
                }
                if (is('(')) {
                    next();
                    // A TYPED LITERAL or a FUNCTION CALL, and the name decides
                    // which. A
                    // datatype name followed by one quoted string is a cast;
                    // anything
                    // else is a call. `string("x")` is therefore a literal and
                    // not a call
                    // to a function called `string`, which does not exist.
                    const typeUri =
                        Object.keys(datatypes.TYPES).filter(function (uri) {
                        return datatypes.TYPES[uri].name === token.value;
                    })[0];
                    if (typeUri && peek().kind === 'string' && is(')', 1)) {
                        const value = expectString();
                        expect(')');
                        log.debug("Leaving primary().");
                        return { kind: 'value', type: typeUri, lexical: value };
                    }
                    const args = [];
                    if (!is(')')) {
                        args.push(expression());
                        while (is(',')) {
                            next();
                            args.push(expression());
                        }
                    }
                    expect(')');
                    const uri = self.functionByShortName[token.value];
                    if (!uri) {
                        throw model.syntaxError('There is no function called ' +
                            '"' + token.value + '" at line ' +
                            token.line + '.');
                    }
                    log.debug("Leaving primary().");
                    return { kind: 'apply', functionId: uri, args: args };
                }
                log.debug("Leaving primary().");
                return nameReference(token.value, token);
            }
            log.debug("Leaving primary().");
            throw model.syntaxError('Unexpected "' + token.value +
              '" at line ' +
                token.line + '.');
        }
        function comparison() {
            log.debug("Entering comparison().");
            const left = primary();
            const token = peek();
            const symbols = ['==', '!=', '>=', '<=', '>', '<'];
            if (token.kind === 'punct' && symbols.indexOf(token.value) >= 0) {
                next();
                const right = primary();
                log.debug("Leaving comparison().");
                return comparisonOf(left, token.value, right, token.line);
            }
            log.debug("Leaving comparison().");
            return left;
        }
        // A CHAIN OF `&&` OR `||` IS ONE n-ARY APPLY AND NOT A NEST OF
        // TWO-ARGUMENT
        // ONES, and that is worth the four extra lines. XACML's `and` and `or`
        // take
        // any number of arguments, every template here that builds one builds
        // it
        // n-ary, and the emitter writes `(a || b || c)` for all three shapes —
        // so a
        // left-associative parse read that back as `or(or(a, b), c)`, which
        // DECIDES
        // identically and re-emits as `((a || b) || c)`. The contract in this
        // file's header is that a round trip is byte-identical, not merely
        // equivalent, and an ALFA edit that silently re-bracketed every
        // condition
        // it touched would make the XML diff of a policy somebody changed one
        // word
        // in unreadable.
        function chain(operand, functionId, symbol, word) {
            log.debug("Entering chain().");
            const args = [operand()];
            while (is(symbol) || is(word)) {
                next();
                args.push(operand());
            }
            log.debug("Leaving chain().");
            return args.length === 1 ? args[0]
                : { kind: 'apply', functionId: functionId, args: args };
        }
        function conjunction() {
            log.debug("Entering conjunction().");
            log.debug("Leaving conjunction().");
            return chain(comparison, F1 + 'and', '&&', 'and');
        }
        function expression() {
            log.debug("Entering expression().");
            log.debug("Leaving expression().");
            return chain(conjunction, F1 + 'or', '||', 'or');
        }
        // The function a comparison means, chosen from the DECLARED TYPE of
        // whichever side has one. A comparison between two literals with no
        // designator is typed from the left; a comparison against a designator
        // is
        // typed from the designator, because that is the type the policy will
        // actually meet at evaluation.
        function comparisonOf(left, symbol, right, line) {
            log.debug("Entering comparisonOf().");
            const typeUri = typeOfExpression(right) || typeOfExpression(left) ||
                TYPE.STRING;
            if (symbol === '!=') {
                const equal = self.functionForOperator('==', typeUri);
                if (!equal) {
                    throw model.syntaxError('There is no equality function ' +
                        'for ' +
                        typeUri + ' (line ' + line + ').');
                }
                log.debug("Leaving comparisonOf().");
                return { kind: 'apply', functionId: F1 + 'not',
                    args: [{ kind: 'apply', functionId: equal,
                            args: [left, right] }] };
            }
            const uri = self.functionForOperator(symbol, typeUri);
            if (!uri) {
                const row = datatypes.typeOf(typeUri);
                throw model.syntaxError('The operator "' + symbol +
                  '" has no XACML function for ' +
                    (row ? row.name : typeUri) + ' at line ' + line +
                      '. Not every ' +
                    'datatype is ordered — boolean and anyURI have ' +
                      'equality and no ' +
                    'comparison.');
            }
            // XACML PUTS THE VALUE FIRST. ALFA reads attribute-first, so the
            // sides
            // are exchanged on the way in — and for an ordering operator the
            // operator
            // has to be mirrored with them or `age > 18` becomes `18 > age`.
            if (left.kind === 'designator' && right.kind === 'value') {
                const mirrored =
                    self.functionForOperator(self
                        .mirrorOperator(symbol), typeUri);
                log.debug("Leaving comparisonOf().");
                return { kind: 'apply', functionId: mirrored || uri,
                    args: [right, left] };
            }
            log.debug("Leaving comparisonOf().");
            return { kind: 'apply', functionId: uri, args: [left, right] };
        }
        function typeOfExpression(one) {
            log.debug("Entering typeOfExpression().");
            if (!one) {
                log.debug("Leaving typeOfExpression().");
                return null;
            }
            if (one.kind === 'value') {
                log.debug("Leaving typeOfExpression().");
                return model.canonicalType(one.type);
            }
            if (one.kind === 'designator') {
                log.debug("Leaving typeOfExpression().");
                return model.canonicalType(one.dataType);
            }
            if (one.kind === 'apply') {
                const definition = functions.lookup(one.functionId);
                log.debug("Leaving typeOfExpression().");
                return definition &&
                  definition.returns ? definition.returns.type
                    : null;
            }
            log.debug("Leaving typeOfExpression().");
            return null;
        }
        // --- targets
        // -------------------------------------------------------------
        //
        // `clause` is one AnyOf, `or` separates its AllOf alternatives, and
        // `and`
        // joins the Matches inside one. Parsed structurally rather than through
        // `expression()` because a Target is NOT a boolean expression — it is
        // three
        // fixed levels, and flattening it would lose the difference between `A
        // and
        // B` inside one alternative and `A` in one clause with `B` in the next,
        // which mean the same thing here and different things everywhere else.
        function targetClause() {
            log.debug("Entering targetClause().");
            expect('target');
            expect('clause');
            const alternatives = [];
            let matches = [matchTerm()];
            for (;;) {
                if (is('and') || is('&&')) {
                    next();
                    matches.push(matchTerm());
                    continue;
                }
                if (is('or') || is('||')) {
                    next();
                    alternatives.push({ matches: matches });
                    matches = [matchTerm()];
                    continue;
                }
                break;
            }
            alternatives.push({ matches: matches });
            log.debug("Leaving targetClause().");
            return { allOf: alternatives };
        }
        function matchTerm() {
            log.debug("Entering matchTerm().");
            const token = peek();
            // A CALL FORM, for the match functions that have no operator —
            // `regexpMatch("a.*", role)` and the two name-match functions.
            // XACML's
            // own argument order, value first, because that is what the
            // function
            // declares.
            if (token.kind === 'word' && is('(', 1) &&
                self.functionByShortName[token.value]) {
                const call = primary();
                if (call.kind !== 'apply' || call.args.length !== 2) {
                    throw model.syntaxError('A target clause written as a ' +
                      'call needs exactly two arguments ' +
                        '(line ' + token.line + ').');
                }
                const value = call.args[0];
                const reference = call.args[1];
                if (value.kind !== 'value' || reference.kind !== 'designator') {
                    throw model.syntaxError('A target clause call takes a ' +
                      'literal and then an attribute ' +
                        '(line ' + token.line + ').');
                }
                log.debug("Leaving matchTerm().");
                return { matchId: call.functionId, value: value,
                  reference: reference };
            }
            const left = primary();
            const operatorToken = next();
            const symbols = ['==', '>=', '<=', '>', '<'];
            if (operatorToken.kind !== 'punct' ||
                symbols.indexOf(operatorToken.value) < 0) {
                throw model.syntaxError('A target clause compares an ' +
                  'attribute with a value using one of ' +
                    symbols.join(', ') + '; found "' + operatorToken.value +
                    '" at line ' + operatorToken.line +
                      '. `!=` is not available in a ' +
                    'target — XACML has no not-equal match function — so ' +
                      'put it in a ' +
                    'condition instead.');
            }
            const right = primary();
            const applied = comparisonOf(left, operatorToken.value, right,
              operatorToken.line);
            if (applied.args.length !== 2 || applied.args[0].kind !== 'value' ||
                applied.args[1].kind !== 'designator') {
                throw model.syntaxError('A target clause compares one ' +
                  'attribute with one literal value ' +
                    '(line ' + operatorToken.line + ').');
            }
            log.debug("Leaving matchTerm().");
            return { matchId: applied.functionId, value: applied.args[0],
                reference: applied.args[1] };
        }
        // --- obligations
        // ---------------------------------------------------------
        function holderBlock(effect, into) {
            log.debug("Entering holderBlock().");
            expect('{');
            while (!is('}')) {
                const keyword = expectWord();
                if (keyword !== 'obligation' && keyword !== 'advice') {
                    throw model.syntaxError('An `on ' + effect.toLowerCase() +
                      '` block holds obligations ' +
                        'and advice; "' + keyword + '" is neither.');
                }
                const token = peek();
                const id = token.kind === 'string' ?
                    expectString() : expectWord();
                const assignments = [];
                expect('{');
                while (!is('}')) {
                    const attributeId = peek().kind === 'string' ?
                        expectString()
                        : expectWord();
                    expect('=');
                    assignments.push({ attributeId: attributeId, category: null,
                        issuer: null, expression: expression() });
                }
                expect('}');
                into[keyword === 'advice' ? 'advice' : 'obligations'].push({
                    id: id, on: effect, assignments: assignments
                });
            }
            expect('}');
            log.debug("Leaving holderBlock().");
        }
        // --- rules, policies, policy sets
        // ---------------------------------------
        function ruleBlock() {
            log.debug("Entering ruleBlock().");
            expect('rule');
            const slug = expectWord();
            expect('{');
            const rule = { id: slug, effect: null, description: '',
              target: null,
                condition: null, obligations: [], advice: [] };
            const anyOf = [];
            while (!is('}')) {
                if (is('permit') || is('deny')) {
                    rule.effect = next().value === 'permit' ?
                        model.EFFECT.PERMIT
                        : model.EFFECT.DENY;
                    continue;
                }
                if (is('id')) {
                    next();
                    expect('=');
                    rule.id = expectString();
                    continue;
                }
                if (is('description')) {
                    next();
                    expect('=');
                    rule.description = expectString();
                    continue;
                }
                if (is('target')) {
                    anyOf.push(targetClause());
                    continue;
                }
                if (is('condition')) {
                    next();
                    rule.condition = expression();
                    continue;
                }
                if (is('on')) {
                    next();
                    const effect = expectWord() === 'permit' ?
                        model.EFFECT.PERMIT
                        : model.EFFECT.DENY;
                    holderBlock(effect, rule);
                    continue;
                }
                const token = peek();
                throw model.syntaxError('Unexpected "' + token.value +
                  '" inside a rule at line ' +
                    token.line +
                      '. A rule holds permit or deny, an id, target ' +
                    'clauses, a condition, and `on permit` / `on deny` ' +
                        'blocks.');
            }
            expect('}');
            if (!rule.effect) {
                throw model.syntaxError('The rule "' + rule.id +
                  '" says neither permit nor deny. Every ' +
                    'XACML rule has an Effect and there is no default.');
            }
            if (anyOf.length) {
                rule.target = { anyOf: anyOf };
            }
            log.debug("Leaving ruleBlock().");
            return rule;
        }
        function policyBlock() {
            log.debug("Entering policyBlock().");
            const keyword = next().value;
            const isSet = keyword === 'policyset';
            const slug = expectWord();
            expect('{');
            const policy = { kind: isSet ? 'PolicySet' : 'Policy', id: slug,
                version: '1.0', description: '',
                combiningAlgId: null, target: null, variables: {},
                rules: [], children: [], obligations: [], advice: [] };
            const anyOf = [];
            while (!is('}')) {
                if (is('id')) {
                    next();
                    expect('=');
                    policy.id = expectString();
                    continue;
                }
                if (is('version')) {
                    next();
                    expect('=');
                    policy.version = expectString();
                    continue;
                }
                if (is('description')) {
                    next();
                    expect('=');
                    policy.description = expectString();
                    continue;
                }
                if (is('apply')) {
                    next();
                    const name = expectWord();
                    const uri = self.algorithmUriOf(name, isSet);
                    if (!uri) {
                        throw model.syntaxError('There is no ' +
                          (isSet ? 'policy' : 'rule') +
                            '-combining algorithm called "' + name +
                              '". The names are: ' +
                            Object.keys(ALGORITHM_NAMES).filter(function (one) {
                                return self.algorithmUriOf(one, isSet);
                            }).join(', ') + '.');
                    }
                    policy.combiningAlgId = uri;
                    continue;
                }
                if (is('target')) {
                    anyOf.push(targetClause());
                    continue;
                }
                if (is('rule')) {
                    policy.rules.push(ruleBlock());
                    continue;
                }
                if (is('policy') || is('policyset')) {
                    policy.children.push(policyBlock());
                    continue;
                }
                if (is('on')) {
                    next();
                    const effect = expectWord() === 'permit' ?
                        model.EFFECT.PERMIT
                        : model.EFFECT.DENY;
                    holderBlock(effect, policy);
                    continue;
                }
                if (is('$')) {
                    next();
                    const id = expectWord();
                    expect('=');
                    policy.variables[id] = expression();
                    continue;
                }
                const token = peek();
                throw model.syntaxError('Unexpected "' + token.value +
                  '" inside a ' + keyword +
                    ' at line ' + token.line + '.');
            }
            expect('}');
            if (!policy.combiningAlgId) {
                throw model.syntaxError('The ' + keyword + ' "' + policy.id +
                  '" has no `apply` line. A ' +
                    'combining algorithm is the single most consequential ' +
                      'line in a ' +
                    'policy and there is deliberately no default.');
            }
            if (anyOf.length) {
                policy.target = { anyOf: anyOf };
            }
            if (isSet) {
                delete policy.rules;
                delete policy.variables;
            }
            else {
                delete policy.children;
            }
            log.debug("Leaving policyBlock().");
            return policy;
        }
        // --- the document
        // --------------------------------------------------------
        expect('namespace');
        expectWord();
        expect('{');
        let root = null;
        while (!is('}')) {
            if (is('attribute')) {
                attributeDeclaration();
                continue;
            }
            if (is('import')) {
                // `import Attributes.*` is idiomatic ALFA and pulls in the
                // standard
                // attribute set from another file. There is no file system here
                // and no
                // second document, so it is SKIPPED with the attributes it
                // would have
                // brought left undeclared — which means a policy relying on it
                // fails at
                // the first use, naming the attribute. That is a better failure
                // than
                // silently inventing the standard set, because the set an
                // implementation ships is exactly what varies between them.
                next();
                while (!is('{') && peek().kind !== 'end' &&
                    !is('policy') && !is('policyset') && !is('attribute')) {
                    next();
                }
                continue;
            }
            if (is('policy') || is('policyset')) {
                const parsed = policyBlock();
                if (root) {
                    log.debug('Leaving AlfaLanguage.parse(). Two ' +
                      'top-level policies.');
                    throw model.syntaxError('This document holds more ' +
                      'than one top-level policy. A PDP ' +
                        'evaluates ONE document, so wrap them in a ' +
                          'policyset and say ' +
                        'which combining algorithm joins them.');
                }
                root = parsed;
                continue;
            }
            const token = peek();
            log.debug('Leaving AlfaLanguage.parse(). Unexpected token.');
            throw model.syntaxError('Unexpected "' + token.value +
              '" at line ' + token.line +
                ' inside the namespace.');
        }
        expect('}');
        if (!root) {
            log.debug('Leaving AlfaLanguage.parse(). No policy.');
            throw model.syntaxError('This document declares a namespace ' +
              'and no policy in it.');
        }
        log.debug('Leaving AlfaLanguage.parse(). id=' + root.id);
        return root;
    }
}
/**
 * ALFA's names for the attribute categories, mapped to their URIs.
 */
AlfaLanguage.CATEGORY_NAMES = CATEGORY_NAMES;
/**
 * ALFA's camel-case names for the combining algorithms, each mapped to its
 * rule-combining and policy-combining URIs (null where there is none).
 */
AlfaLanguage.ALGORITHM_NAMES = ALGORITHM_NAMES;
// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot('xacml/xacml_alfa',
  () => new AlfaLanguage(AlfaLanguage.defaultDeps()), null, helpers.log);
// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();
module.exports = {
    AlfaLanguage: AlfaLanguage,
    installInstance: (instance) => slot.install(instance),
    instanceOrigin: () => slot.origin(),
    write: slot.forward('write'),
    parse: slot.forward('parse'),
    tokenize: slot.forward('tokenize'),
    algorithmNameOf: slot.forward('algorithmNameOf'),
    algorithmUriOf: slot.forward('algorithmUriOf'),
    shortFunctionName: slot.forward('shortFunctionName'),
    shortNameForAttribute: slot.forward('shortNameForAttribute'),
    CATEGORY_NAMES: AlfaLanguage.CATEGORY_NAMES,
    ALGORITHM_NAMES: AlfaLanguage.ALGORITHM_NAMES,
    // Built by the instance's constructor, so read from it when asked.
    get FUNCTION_BY_SHORT_NAME() {
        helpers.log.debug("Entering FUNCTION_BY_SHORT_NAME().");
        helpers.log.debug("Leaving FUNCTION_BY_SHORT_NAME().");
        return slot.get().functionByShortName;
    }
};
