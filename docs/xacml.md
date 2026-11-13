# XACML — the editor and the decision test

Covers `client/public/xacml.html`, `client/src/xacml.js`,
`client/src/xacml_workbench.js`, `client/src/xacml_draw.js`,
`client/src/xacml_runtime.js`, the engine under `client/src/xacml/`,
`client/public/css/xacml.css` and `tests/xacml_engine.js`.

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

## The static sites

The page is ordinary browser JavaScript. It ships on the hosted sites.
Its landing card is not greyed out.
