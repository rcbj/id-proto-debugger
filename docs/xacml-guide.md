---
title: "Using the XACML editor"
---

# Using the XACML editor

The XACML workflow is the **XACML** card on the landing page. It is one
page, `xacml.html`, headed **XACML Editor**. You keep XACML 3.0 Policies and
PolicySets there, edit them, and ask one of them for a decision.

These pages have no screenshots. The pictures in the
[OAuth2 / OIDC guide](oauth2-oidc/index.md) come from the Selenium jobs, and
those jobs were not re-run for this pass.

* TOC
{:toc}

## Before you start

From a checkout, follow [Getting started](getting-started.md). Then open
`https://localhost:3000` and pick **XACML**.

Nothing else has to be running. The page needs no identity provider, no
API call and no PDP of its own. See
[Where the decision is made](#where-the-decision-is-made).

## The layout of the page

**About this page** is a folded note at the top. Under it is a status line.
Every button reports there: a plain message when it worked, a warning when
it was refused.

The page has five panes. Click a pane's title to fold or open it. The
**Collapse all panes** switch folds every pane; its label then reads
**Expand all panes**.

| Pane | What it is for |
|---|---|
| **Repository** | Create a blank policy, load the sample, or import XML or ALFA. |
| **Upload / Download** | Add a policy from a file. Save or copy the open policy as XML. |
| **Editor** | The open policy, one row per element, each with its own form. |
| **Try a decision** | Build a request, press **Ask**, read the decision. |
| **SAML Tools** | Links to the SAML decoders, the assertion tool, Certificate Details and the PKI page. Folded when the page loads. |

**Create blank**, **Load sample** and **Upload** open the Editor pane and
fold the others. **Import** does not change the panes.

The policy is shown as an indented table, not as a diagram.

## Start a policy

All of this is in the **Repository** pane.

| Field or button | Default | What it does |
|---|---|---|
| **Name** | `policy` | The name the new policy is kept under in this browser. It is also the new PolicyId. |
| **Kind** | Policy | Or PolicySet. A Policy holds Rules. A PolicySet holds Policies and other PolicySets. |
| **Create blank** | | An empty policy of that kind and name. |
| **Load sample** | | The one-rule sample, stored as `sample`. |
| **Import as** | empty, placeholder *defaults to the policy id* | The repository name for an imported document. Empty uses its PolicyId or PolicySetId. |
| **XACML XML or ALFA** | empty | Paste a Policy or PolicySet here. |
| **Import** | | Parses the box and adds the result to the repository. |

A text that starts with `<` is read as XACML XML. Anything else is read as
ALFA. The repository always stores XML. ALFA on this page is a view of that
XML.

### A blank policy

A blank document is Version `1.0`, uses **deny-unless-permit**, and has no
rules or children. With nothing that permits, deny-unless-permit answers
**Deny**. So a blank policy denies every request until you add a rule that
permits. Its Description says so.

### The sample

**Load sample** stores a Policy called `sample` and reports *Loaded the
sample. alice is permitted; anyone else is denied.* It is a blank Policy
with one rule added:

* Rule `sample:rule:1`, Effect **Permit**.
* Its target is one Match: `string-equal`, value `alice`, against
  `urn:oasis:names:tc:xacml:1.0:subject:subject-id` in the access-subject
  category.

The Description is the blank policy's text, which still says the policy is
empty. Load sample always uses the name `sample`. If that name is taken it
is refused.

### ALFA

ALFA the page writes uses the namespace `example`. A document in any other
namespace still imports. This is the sample in ALFA, as the editor shows it:

```
namespace example {
    attribute subjectId {
        category = subjectCat
        id = "urn:oasis:names:tc:xacml:1.0:subject:subject-id"
        type = string
    }

    policy sample {
        id = "sample"
        version = "1.0"
        description = "An empty Policy. ..."
        apply denyUnlessPermit
        rule p1 {
            permit
            target clause subjectId == "alice"
        }
    }
}
```

MustBePresent and Issuer are written after the attribute where it is used:
`subjectId[mustbepresent]`, `subjectId[issuer="..."]`, or
`subjectId[mustbepresent issuer="..."]`.

### The decision root

The first policy you store becomes the **decision root**. **Try a
decision** asks the root when you do not name a policy. When you remove the
root, the first policy left becomes the root.

## Upload and download

All of this is in the **Upload / Download** pane.

| Field or button | Default | What it does |
|---|---|---|
| **File** | | A file picker for `.xml`, `.alfa` or `.txt`. |
| **Upload** | | Reads the file and adds it like **Import**. The name is **Import as**, or the file name without `.xml`, `.alfa` or `.txt`. |
| **Layout** | Formatted | Formatted is indented the way the editor writes it. Unformatted has no whitespace between elements. |
| **Download** | | Saves the policy open in the Editor as `<name>.xml`. |
| **Copy** | | Copies that XML to the clipboard. |

Download and Copy always give XACML 3.0 XML. To get ALFA, open **As ALFA**
at the bottom of the Editor pane and copy it from there.

## The Editor pane

### The controls at the top

| Control | What it does |
|---|---|
| **Open** | The policy shown below. |
| **Enabled** | See the note under this table. |
| status text | *This is the decision root.* or *This is not the decision root.* |
| **Make decision root** | Makes the open policy the root. The old root stays in the repository. |
| **Remove** | Deletes the open policy from this browser. There is no confirmation. |

The page says that only an enabled policy takes part in a decision. What
the code does is narrower. **Enabled** decides whether another policy's
PolicyIdReference or PolicySetIdReference can find this one. **Try a
decision** still asks a disabled policy when you name it, or when it is the
root.

When the open policy is the root and is enabled, a warning says so. It
appears for the sample, because the sample is the first policy stored.

### Warnings above the tree

* A list of problems the validator found in the document. The note under
  it reads *An edit that does not typecheck is not saved.*
* An XPathVersion gap. The document holds an AttributeSelector or an
  xpathExpression value and has no XPathVersion. This is reported, and the
  document is still saved. This PDP does not evaluate XPath.
* If the stored document does not parse at all, its error is shown and no
  tree is drawn.

### The tree

The tree is a table with three columns: **Element**, **Kind** and **Add /
remove**. Each element of the document is one row, indented by depth. A row
shows a label, a one-line summary, and the form that edits it.

The **Add / remove** column has a menu and an **Add** button where something
may be added, and a **Remove** button where the row may go. The menu offers
only what is legal at that point. **What can be added here** under a row
explains each choice.

| Row | Add offers |
|---|---|
| Policy | Rule, Variable definition, Obligation, Advice, Target clause |
| PolicySet | Policy, Policy set, PolicyIdReference, PolicySetIdReference, Target clause, Obligation, Advice |
| Rule | Target clause, Condition, Obligation, Advice. Condition disappears once the rule has one. |
| Target | Target clause |
| Clause | Alternative |
| Alternative | Match |
| Expression or variable | Function call, Literal value, Attribute, Attribute selector, Function reference, Variable reference. A function call also offers Argument. Variable reference appears only where the policy defines a variable. |
| Obligation or advice | Attribute assignment |

Clauses in a target are ANDed: every clause must match. Alternatives in a
clause are ORed. Every Match in an alternative must hold.

The root policy has no **Remove**. A Target has none either; remove its
last clause instead.

### What Add creates

Add takes no input. It creates a complete element with default values, and
you edit it afterwards with that row's form.

| Added | Starts as |
|---|---|
| Rule | Effect Permit, RuleId `<PolicyId>:rule:<n>`, no target. |
| Policy or Policy set inside a set | Id `<PolicySetId>:policy:<n>` or `:set:<n>`, Version 1.0, deny-unless-permit, empty. |
| PolicyIdReference / PolicySetIdReference | Points at `urn:example:policy:referenced`, any version. |
| Variable definition | `$v1`, `$v2`, ... A bag of the access-subject attribute `employeeType` (string). |
| Target clause, Alternative, Match | One Match: `string-equal`, empty value, against `subject-id` in access-subject. |
| Condition | `string-is-in("", employeeType)`. |
| Obligation / Advice | Id `urn:sts:xacml:obligation:<n>` or `urn:sts:xacml:advice:<n>`, fires on Permit. |
| Attribute assignment | AttributeId `urn:sts:xacml:assignment:<n>`, an empty string value. |
| Argument | An empty string value. |

A new obligation makes both PEPs refuse a Permit until you rename it. See
[Obligations and advice](#obligations-and-advice).

### The edit forms

Each row's form has an **Update** button (**Rename** for a variable).
Pressing it saves that element and redraws the document.

| Row | Fields |
|---|---|
| Policy / PolicySet | **PolicyId** or **PolicySetId**, the combining algorithm, **Version**, **Description**, **MaxDelegationDepth**, **XPathVersion**. |
| Rule | Effect (Permit or Deny), **RuleId**, **Description**. |
| Match | Two forms. The first: the match function and the value. The second: **against** an attribute or a selector, its **AttributeId** (or **Path**), the category, **Issuer** (or **ContextSelectorId**), and **must be present**. |
| Attribute (designator) | AttributeId, category, data type, **Issuer**, **must be present**. |
| Attribute selector | **Path**, category, data type, **ContextSelectorId**, **must be present**, and one **namespace** prefix and URI. |
| Literal value | The value and its data type. An xpathExpression value also takes a category. |
| Function call | The function and a **Description**. |
| Function reference | The function. |
| Variable reference | Which variable, from those the policy defines. |
| Variable | **VariableId $**, with **Rename**, then the form for its expression. |
| Obligation / Advice | The id and **fires on** Permit or Deny. |
| Attribute assignment | **AttributeId**, **Category** (or *(none)*), **Issuer**. |
| PolicyIdReference / PolicySetIdReference | The referenced id and **Version**. |

Things worth knowing about these forms:

* **The function decides the type of a Match.** Changing the function
  changes the type of both the value and the attribute. The line under the
  form shows the current value type.
* **must be present** is a no/yes menu. Yes turns a missing attribute into
  an Indeterminate with the status `missing-attribute`. No treats it as an
  empty bag.
* **Issuer** left empty matches any issuer.
* A value must be valid for its type. `notanint` for an integer is refused
  with *"notanint" is not a valid integer.*, and nothing is saved.
* **Version** must be dot-separated numbers, such as `1`, `1.0` or
  `2.13.7`.
* **MaxDelegationDepth** must be a non-negative integer, or empty. It is
  stored and not read by this PDP.
* A variable name may not contain a dot, because the page addresses each
  row by a dotted path. Renaming a variable rewrites every reference to it.
* A selector's namespace: a prefix with a URI adds that binding. A prefix
  with an empty URI removes it.
* Combiner parameters already in an imported document appear as rows and
  can be removed. The editor does not add them.

An edit that would leave the document invalid is refused, the status line
says why, and the stored document is left as it was.

### Combining algorithms

The menu on a Policy row lists rule-combining algorithms. The menu on a
PolicySet row lists policy-combining algorithms. The notes under the form
describe the one selected.

| Algorithm | Policy | PolicySet | What it does |
|---|---|---|---|
| deny-unless-permit | yes | yes | Anything not permitted is denied. Never NotApplicable or Indeterminate. |
| permit-unless-deny | yes | yes | Anything not denied is permitted. |
| deny-overrides | yes | yes | One Deny outranks any number of Permits. |
| permit-overrides | yes | yes | One Permit outranks any number of Denies. |
| first-applicable | yes | yes | The first rule or child that decides anything wins. Order matters. |
| only-one-applicable | no | yes | Two applicable children is Indeterminate. |
| ordered-deny-overrides | yes | yes | Identical here, because this PDP always evaluates in document order. |
| ordered-permit-overrides | yes | yes | permit-overrides with the order fixed. |

The legacy XACML 1.0 and 1.1 identifiers (for example
`urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides`) are
not in the menu. A document that uses one imports and is decided with it.
Its policy row cannot show it, though: the menu has no matching entry, so
the browser shows the first entry, deny-unless-permit. Pressing **Update**
on that row writes what the menu shows. Leave that form alone, or edit the
algorithm in the XML and import it again.

### As ALFA and As stored XML

Two folded sections close the pane. **As ALFA** is the open policy written
as ALFA. **As stored XML** is exactly what the repository holds. Both are
read-only. To change a policy through its text, edit a copy and **Import**
it under a new name.

## Ask for a decision

All of this is in the **Try a decision** pane.

| Field or button | Default | What it does |
|---|---|---|
| **Policy** | *(the root)* | The policy the request is decided against. |
| **Subject** | `alice` | `urn:oasis:names:tc:xacml:1.0:subject:subject-id`, access-subject category, string. |
| **Action** | `GET` | `urn:oasis:names:tc:xacml:1.0:action:action-id`, action category, string. Empty is sent as `GET`. |
| **Resource** | `https://example.com/a` | `urn:oasis:names:tc:xacml:1.0:resource:resource-id`, resource category, **anyURI**. |
| **Add attribute** | | Adds a row: category, AttributeId, value, data type. |
| **Request XML or JSON Profile** | empty | A whole request. When not empty it replaces every field above. |
| **Ask** | | Decides and shows the result below. |

A new attribute row starts with the access-subject category URI and the
data type `http://www.w3.org/2001/XMLSchema#string`. Both are free text.
Enter full URIs. A row with no AttributeId is ignored.

The resource goes out as an **anyURI**. A Match that compares it with
`string-equal` never matches. Use `anyURI-equal`.

If Subject and Resource are both empty, no attribute row has an
AttributeId, and the request box is empty, **Ask** clears the result and
asks nothing.

The request is the only source of attributes. There is no directory and no
Policy Information Point. The PDP adds three environment attributes from
the browser's clock, in UTC, when the request does not carry them:
`current-time`, `current-date` and `current-dateTime`.

### Pasting a request

A text that starts with `{` is read as a JSON Profile request. Anything
else is read as an XACML XML `<Request>`.

A JSON Profile request:

```json
{"Request": {"ReturnPolicyIdList": true,
  "AccessSubject": {"Attribute": [
    {"AttributeId": "urn:oasis:names:tc:xacml:1.0:subject:subject-id",
     "Value": "alice"}]}}}
```

The shorthand categories are `AccessSubject`, `RecipientSubject`,
`IntermediarySubject`, `Codebase`, `RequestingMachine`, `Resource`,
`Action` and `Environment`. Other categories go in a `Category` array with
a `CategoryId`. `DataType` may be a URI or a short name such as `integer`.
Without one, the type is taken from the JSON value. An array `Value` is a
bag.

An XML request:

```xml
<Request xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
         ReturnPolicyIdList="false" CombinedDecision="false">
  <Attributes
      Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject">
    <Attribute AttributeId="urn:oasis:names:tc:xacml:1.0:subject:subject-id"
               IncludeInResult="true">
      <AttributeValue
          DataType="http://www.w3.org/2001/XMLSchema#string"
          >bob</AttributeValue>
    </Attribute>
  </Attributes>
</Request>
```

Applicable policies are listed only when the request asks for them. The
fields above always ask. A pasted request asks only when it sets
`ReturnPolicyIdList` to true; it defaults to false in both formats.

Clear the box to go back to the fields.

### Reading the result

The result starts with the decision as a heading and the line
*Policy `name`.* Then a table:

| Row | What it shows |
|---|---|
| **PDP** | Permit, Deny, NotApplicable or Indeterminate. |
| **Deny-biased PEP** | Allowed or Refused, with the reason. Only Permit is allowed. |
| **Permit-biased PEP** | Allowed or Refused, with the reason. Only Deny is refused. |
| **Applicable policies** | The PolicyIds and PolicySetIds that applied, or *none*. |
| **Obligations** | The obligation ids returned, or *none*. |
| **Advice** | The advice ids returned, or *none*. |
| **Status** | The status code, with its message when there is one. |

Obligations and advice are listed by id. Their attribute assignments are
not shown.

The status codes are the four XACML ones:

| Code ends in | Meaning |
|---|---|
| `status:ok` | Evaluation ran normally. |
| `status:missing-attribute` | An attribute marked must be present was not in the request. The message names it. |
| `status:syntax-error` | Something in the policy or the request could not be read or evaluated. |
| `status:processing-error` | Evaluation failed, for example two applicable policies under only-one-applicable. |

A status other than `ok` can sit under a Deny or a Permit. Under
deny-unless-permit an error inside the policy still ends as Deny, and the
status row is where you see why.

### Obligations and advice

An obligation is something the PEP must do. A PEP that cannot do it must
not grant the access. Both PEPs on this page can discharge exactly one
obligation id, `urn:sts:xacml:obligation:log`. Any other obligation turns
an allowed result into **Refused**, under both biases, and the reason names
the obligation.

So a new obligation, which starts as `urn:sts:xacml:obligation:1`, makes a
Permit come out Refused. Rename it to `urn:sts:xacml:obligation:log` to see
the access allowed with the obligation attached.

Advice never changes Allowed or Refused.

### Policy references

A PolicyIdReference or PolicySetIdReference names a **PolicyId**, not a
repository name. It is resolved at decision time from the other policies
in the repository that are **Enabled**. The policy being decided is not
searched. A reference that finds nothing makes that child Indeterminate,
with the message *Cannot evaluate a node of kind "UnresolvedReference".*
Under deny-unless-permit the overall decision is still Deny.

## Where the decision is made

In the browser. The editor, the validator and the PDP are part of the
page's JavaScript. **Ask** sends nothing anywhere: the page makes no call to
the API service, to iya-sts, or to any external PDP or PEP. The two PEPs in
the result are simulated by the page from the PDP's answer.

## What the browser keeps

The repository is kept in `localStorage` under the key `xacml_repository`.
Each entry holds the name, the policy as XML, whether it is enabled, and
whether it is the decision root. It survives a reload. It is not shared
with any other browser, and clearing the site's data deletes it. Use
**Download** to keep a copy.

The request fields, the attribute rows, the request box and the result are
not stored. A reload resets them to their defaults.

There are no keys, secrets or passwords on this page.

## On the deployed sites

The page ships to the deployed static sites, and its landing card is not
greyed out. Everything on it works there, because nothing on it needs the
API.

## Common messages

| Message | What it means |
|---|---|
| *A policy needs a name.* | **Name** is empty. |
| *There is already a policy called "x".* | Names are unique. Pick another, or **Remove** the old one first. |
| *Paste a policy first.* | **Import** with an empty box. |
| *The document has no id, so it needs a name.* | Fill **Import as**. |
| *The document is not well-formed XML: ...* | The XML did not parse. Also given for a pasted request. |
| *Expected "namespace" at line 1 but found "..."* | The text did not start with `<`, so it was read as ALFA, and it is not ALFA. |
| *A policy document's root must be \<Policy\> or \<PolicySet\>; this one is \<...\>.* | You imported something else, such as a Request. |
| *A request document's root must be \<Request\>; this one is \<...\>.* | The request box holds something else, such as a policy. |
| *A JSON Profile request is an object with a "Request" member.* | The JSON has no top-level `Request`. |
| *"x" is not a valid integer.* (or another type) | A value that is not valid for its data type. Nothing was saved. |
| *That edit would leave the policy invalid, so it was not saved.* | The edit was refused. The rest of the message says why. |
| *A variable name may not contain a dot in this editor.* | See [The edit forms](#the-edit-forms). |
| *There is no policy to decide with.* | The repository is empty. |
| *There is no policy open to export.* | **Download** or **Copy** with nothing open. |
| *Choose a file to upload first.* | **Upload** with no file chosen. |
| *Open a policy first.* | **Make decision root** or **Remove** with nothing open. |
| *That part of the policy is not there any more.* | The document changed after the page was drawn. Reload and try again. |
| *The browser refused the clipboard.* | **Copy** failed. Use **Download**. |

## For developers

How the page is built, the engine under `client/src/xacml/`, and the tests
that hold it to XACML 3.0 Appendix A and Appendix C are in
[XACML — the editor and the decision test](xacml.md).
