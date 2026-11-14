# XACML — the editor and the decision test

Covers `client/public/xacml.html`, `client/src/xacml.js`,
`client/src/xacml_workbench.js`, `client/src/xacml_draw.js`,
`client/src/xacml_runtime.js`, the engine under `client/src/xacml/`,
`client/public/css/xacml.css`, `tests/xacml_engine.js`,
`tests/xacml_page.js`, and the function table with its two jobs
(`tests/xacml_function_cases.js`, `tests/xacml_functions_engine.js`,
`tests/xacml_functions_page.js`).

The page is the XACML editor and the "Try a decision" tool from the
iya-sts admin console, as a debugger workflow. It was added for
issue #275.

## An independent copy

The engine was copied out of iya-sts and compiled to plain JavaScript.
It is not vendored, not a submodule, and not kept in step by a script.
The two copies evolve independently. A later change to the console
does not arrive here, and a change here does not go back. Edit the
JavaScript in this tree. There is no TypeScript source beside it.

ALFA written on this page uses the namespace `example`. The parser
still accepts a document from any namespace, so a policy pasted from
the iya-sts console imports.

An attribute's MustBePresent and Issuer are written after its short
name where it is used, in the syntax of Axiomatics' ALFA reference:
`role[mustbepresent]`, `role[issuer="https://idp.example"]`, or both,
`role[mustbepresent issuer="..."]`. They are not part of the
`attribute` declaration, because two uses of one attribute may differ.
Writing a document as ALFA and reading it back gives the same
designators; each of the 447 OASIS mandatory conformance policies that
loads decides its request identically after that round trip.

## What the page does

The repository is a list of named documents in `localStorage`, under
`xacml_repository`. Create a blank Policy or PolicySet, import XACML
XML or ALFA, or load the one-rule sample. The stored form is always
XML. ALFA on the page is a view of that document.

The editor draws the same tree the console draws, and each Add offers
only the elements that are legal at that point. An edit that does not
typecheck is refused and the stored document is left as it was. An
XPathVersion gap is reported and does not block the save. This PDP
does not evaluate XPath. A variable name may not contain a dot,
because a node is addressed by a dotted path. Combiner parameters
that are already in the document can be removed. The editor does not
add them, and it does not edit a PolicyIssuer. MustBePresent is a
yes/no select.

A blank document uses deny-unless-permit. With no rule that permits,
the decision is Deny.

Try a decision asks the local PDP. The policy is the one named in the
form, or the decision root when that list says the root. The subject,
the action, the resource and any extra attribute rows are the whole
request. A pasted XACML Request, or a JSON Profile request, replaces
those fields when the box is not empty. The result shows the decision,
the applicable policies, the obligations, the advice, the status, and
both PEP biases. Deny-biased allows only Permit. Permit-biased refuses
only Deny. An obligation other than
`urn:sts:xacml:obligation:log` turns an otherwise allowed decision
into a refusal. That is the one obligation id the copied PEP
discharges, and it is XACML section 7.2 either way: a PEP that cannot
fulfil an obligation must not grant the access.

There is no directory and no Policy Information Point. The attributes
in the request are the only ones the decision sees. The page says so.

## What this page does not include

The iya-sts LDAP policy store, its PIP, its PEP registry, its remote
PEPs, its service templates, and the OASIS conformance corpus. Those
are that service's administration. This page is the editor and the
decision test.

## The engine has no DOM

`client/src/xacml.js` is the only file that touches the page.
`xacml_workbench.js` holds the repository and calls the editor, the
writers and the PDP. `xacml_draw.js` returns HTML. The modules under
`client/src/xacml/` parse, validate and evaluate. `tests/xacml_engine.js`
drives the workbench in node for that reason. A round trip that only
went through the page would agree with itself whatever the engine did.

## The page test

`tests/xacml_page.js` drives the page in Chrome: decisions, a Match
edit, an ill-typed edit refused, a rule added and removed, the ALFA
view imported back, the decision root, a reload, and Remove.

The page redraws the editor with `innerHTML` after every edit, so an
element handle held across an edit goes stale. iya-sts's job for the
same editor fails intermittently for that kind of reason. This test
finds, fills and submits each form inside one in-page script, waits on
the status line and the decision rather than on elements, reads what
was saved from `localStorage`, and never needs a control to be
visible, so collapsed panes do not affect it. A wait that times out
reports what the page showed.

## The static sites

The page is ordinary browser JavaScript. It ships on the hosted sites.
Its landing card is not greyed out.

## Every function, against Appendix A

`tests/xacml_function_cases.js` is a table of 482 policies, one
function or datatype rule each, with the decision XACML 3.0 Appendix A
and the datatypes' lexical rules give it: Permit when the function
returned what the specification says, NotApplicable when it did not,
Indeterminate for a processing error, and Refused for a policy the
loader must not accept. The answers are read from the specification,
never from this engine's output. `xacml_functions_engine.js` runs the
table in node and writes every importable case out as ALFA and back;
`xacml_functions_page.js` runs it through the page's Import and Ask
controls. A function added to the registry with no case fails the node
job.

The table found these, all fixed on 2026-11-13:

* `integer-add`, `double-add`, `integer-multiply` and `double-multiply`
  took exactly two arguments. A.3.2 says each MUST accept two or more.
* `string-regexp-match` and the five typed variants anchored every
  pattern, as an XML Schema pattern facet does, and read `^` and `$` as
  characters. A.3.13 says they are `xf:matches`, which SEARCHES and has
  those anchors. **A policy that relied on the implicit anchoring now
  matches more widely and needs `^...$`.**
* Eight comparison functions (`yearMonthDuration-less-than` and the
  rest, for both durations) were registered under the OASIS namespace.
  A.3.6 and A.3.7 define comparisons for integer, double, string, time,
  dateTime and date only, so a policy naming them now fails to load.
* `map` took exactly one bag after its function. A.3.12 says n+1
  arguments with the one bag in any position, and a function that
  returns a primitive.
* `string-from-anyURI`, `-x500Name`, `-rfc822Name`, `-ipAddress` and
  `-dnsName` gave a canonical text. A.3.9 says the form originally
  written, and the typed regexp-match functions are defined through it.
* `ipAddress` dropped IPv6 brackets and the port range when written, and
  never read a bracketed IPv6 mask. `dnsName` accepted any text without
  whitespace. Both follow B.4 now: RFC 2396 hosts, RFC 2732 IPv6
  references, and the SocketPermission port-range syntax.
* `date` and `dateTime` accepted days that do not exist (2021-02-29),
  hours past 24:00:00 and time zones beyond plus or minus 14:00.
* The ALFA writer wrote a double spelt `2` bare, which reads back as an
  integer, wrote `+09` which does not parse, and wrote a malformed
  boolean as `false`. A literal is bare now only when the reader rebuilds
  the same type and text, and `type("...")` otherwise.

`double-equal(NaN, NaN)` is true here, which A.3.1's "according to
IEEE 754" seems to contradict. XML Schema's value space has one NaN, and
the OASIS conformance cases IIC350 and IIC358 expect Permit.
