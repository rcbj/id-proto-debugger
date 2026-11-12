---
title: "SAML Assertion Tool"
---

# SAML Assertion Tool

`/saml_tools.html` builds a SAML assertion, signs it, and encrypts it, in
the browser. It does not send anything. Open it from the **Tools** pane on
`saml_request.html` or `saml_response.html`.

The three panes follow one pipeline. **Generated Assertion** updates as you
type. After **Sign Assertion**, later edits rebuild the assertion and sign
it again. After **Encrypt Assertion**, later edits rebuild, re-sign, and
re-encrypt. **Reset** turns both of those off and restores every field.

A field marked stored below is written to `localStorage`, including the
private keys. There is no "save this key pair" checkbox on this page. The
note at the bottom of the form says the same thing: do not paste a
production key. Timestamps are the exception. They are regenerated on each
visit so a stale `IssueInstant` does not survive a reload.

This page has no screenshot. The pictures in the
[OAuth2 / OIDC guide](oauth2-oidc/index.md) come from the Selenium jobs, and
those jobs were not re-run for this pass.

* TOC
{:toc}

## 1. Compose Assertion

| Field or button | Default | Stored | What it does |
|---|---|---|---|
| **Generated Assertion** | rebuilt as you type | | The artifact so far. **Copy**, **Pretty Print**, **Download**, **Reset**, **SAML Compliance**. |
| **SAML Compliance** | | | PASS / FAIL / WARN against the selected version: identifier form, UTC instants, Issuer, Subject, audience, attributes, and, once signed, where `<ds:Signature>` sits. |
| **Pretty Print** | | | Re-indents. Re-signs if signing is engaged. |
| **Download** | | | The furthest artifact: encrypted, else signed, else plain. |
| **Reset** | | | Defaults in all three panes. Drops attributes, keys, and signed or encrypted output. |
| **Assertion Version** | SAML 2.0 | yes | Also 1.1 and 1.0. Controls that the version does not have are hidden. |
| **Issuer** | this debugger's origin plus `/issuer` | yes | `<saml:Issuer>` in 2.0. An attribute in 1.x. |
| **Assertion ID** | a generated NCName | | `ID` in 2.0, `AssertionID` in 1.x. **New ID** replaces it. |
| **Validity (minutes)** | 5 | yes | Drives `NotBefore` / `NotOnOrAfter`. |
| **Clock skew (seconds)** | 60 | yes | Subtracted from the start of the window. |
| **Refresh Times** | | | Rewrites the instants from now. |
| **IssueInstant**, **NotBefore**, **NotOnOrAfter** | now, in UTC with a `Z` | | Editable. Not stored. |
| **Subject** | on | yes | Off hides the subject block. In 1.x the subject lives inside each statement. |
| **NameID value** | empty | yes | `<saml:NameID>` in 2.0, `<saml:NameIdentifier>` in 1.x. |
| **NameID Format** | emailAddress (1.1) | yes | Also unspecified, X509SubjectName, WindowsDomainQualifiedName, and the 2.0 formats persistent, transient, entity, kerberos. |
| **NameQualifier** | empty | yes | |
| **SPNameQualifier** | empty | yes | SAML 2.0. |
| **SubjectConfirmation** | on | yes | |
| **Confirmation Method** | bearer | yes | Also holder-of-key, sender-vouches, and artifact (SAML 1.x). The URI follows the version. |
| **Recipient**, **InResponseTo**, **Address** | empty | yes | |
| **Confirmation NotOnOrAfter** | from the validity window | | Not stored. |
| **Conditions** | on | yes | The validity window. |
| **AudienceRestriction** | on | yes | `AudienceRestrictionCondition` in 1.x. |
| **Audience** | empty | yes | |
| **OneTimeUse condition** | off | yes | `DoNotCacheCondition` in 1.1. Absent from 1.0. |
| **ProxyRestriction** | off | yes | SAML 2.0. |
| **Proxy Count** | 0 | yes | |
| **Advice** | off | yes | |
| **Advice AssertionIDRef** | empty | yes | |
| **AuthnStatement** | on | yes | |
| **AuthnInstant** | now | | Not stored. |
| **AuthnContextClassRef** | PasswordProtectedTransport | yes | SAML 2.0. Also Password, X509, TLSClient, Kerberos, SmartcardPKI, MobileTwoFactorContract, unspecified. |
| **AuthenticationMethod** | password | yes | SAML 1.x. Also X509-PKI, HardwareToken, Kerberos, SSL/TLS client, unspecified. |
| **SessionIndex** | empty | yes | |
| **SessionNotOnOrAfter** | from the window | | Not stored. |
| **SubjectLocality** | off | yes | |
| **Locality Address**, **Locality DNS Name** | empty | yes | |
| **AuthzDecisionStatement** | off | yes | |
| **Authz Resource** | empty | yes | |
| **Decision** | Permit | yes | Also Deny and Indeterminate. |
| **Action** | `Read` | yes | |
| **Action Namespace** | `urn:oasis:names:tc:SAML:1.0:action:rwedc` | yes | |
| **AttributeStatement** | off | yes | Check it to add attributes. |
| **Type** | string | | Also integer, boolean, dateTime, anyURI, base64Binary, unspecified (no `xsi:type`). |
| **URI Prefix**, **name**, **value** | empty | | **Add** appends a row. **Clear Attributes** drops them. In 2.0 a prefix switches `NameFormat` to URI. In 1.x it is `AttributeNamespace`. |

## 2. Sign (XML Signature)

An enveloped signature over the assertion.

| Field | Default | What it does |
|---|---|---|
| **Signature Algorithm** | RSA-SHA256 | Also RSA-SHA1, RSA-SHA384, RSA-SHA512. After load, the post-quantum group from [Post-quantum XML Signature](xmldsig-pqc.md) is appended. |
| **Canonicalization** | Exclusive XML Canonicalization 1.0 | Or inclusive C14N 1.0. |
| **Key Size** | 2048 | Also 3072 and 4096. |
| **Generate Keys** | | RSA pair and a self-signed certificate, embedded in `KeyInfo`. |
| **Download** | | The signing pair as PEM. |
| **Private Signer Key** / **Public Signer Certificate** | empty | Both stored. |
| **Sign Assertion** | | Engages signing. The compose box then shows the signed assertion. |
| **Signed Assertion** | | The last signed document. |
| **Signed XML to Verify** | | This assertion, or any signed XML you paste. |
| **Verification Certificate** | | Empty uses the certificate in `KeyInfo`. |
| **Verify** | | Checks every reference digest and `SignatureValue`. |

Where the signature is placed:

| Version | Reference URI | Position |
|---|---|---|
| SAML 2.0 | `#ID` | Immediately after `<saml:Issuer>` |
| SAML 1.1 | `#AssertionID` | Last child of `<saml:Assertion>` |
| SAML 1.0 | `""` (the whole document) | Last child of `<saml:Assertion>` |

SAML 1.0's `AssertionID` is not an `xs:ID`, so the empty reference is the
form other verifiers accept. Clearing the private key, or **Reset**, turns
signing off.

## 3. Encrypt (XML Encryption)

Sign, then encrypt. Paste the relying party's certificate, or generate a
throwaway recipient pair.

| Field | Default | What it does |
|---|---|---|
| **Recipient Key Size** | 2048 | Also 3072 and 4096. |
| **Generate Keys** / **Download** | | Recipient certificate and private key. Both stored. |
| **Encryption Certificate** / **Recipient Private Key** | empty | The public half wraps the session key. The private half is for **Decrypt**. |
| **Encrypted Type** | Element (whole assertion) | Or Content. |
| **Canonicalization** | None (serialize as-is) | Or exclusive or inclusive C14N 1.0. |
| **Data Encryption Algorithm** | AES-256-GCM | Also AES-192-GCM, AES-128-GCM, AES-CBC at 256/192/128, Triple DES CBC. |
| **Key Transport Algorithm** | RSA-OAEP (xmlenc11) | Also RSA-OAEP-MGF1P and RSA-1_5. |
| **Key Transport Digest** | SHA-256 | Also SHA-1, SHA-384, SHA-512. |
| **MGF** | MGF1 with SHA-256 | Also SHA-1, SHA-384, SHA-512. |
| **Wrap in EncryptedAssertion** | on | SAML 2.0. SAML 1.x has no such element, so the output is a bare `EncryptedData`. |
| **Assertion to Encrypt** | follows the current artifact | Editing it by hand stops that following. |
| **Encrypt Assertion** | | Engages encryption for later edits. |
| **EncryptedAssertion to Decrypt** / **Decrypt** | | Round-trip with the recipient private key. |

The page builds an assertion, not a `<samlp:Response>`. A full sign-in is
the [SAML workflow](saml.md).
