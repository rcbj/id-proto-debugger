---
title: "SAML decoders and certificate details"
---

# SAML decoders and certificate details

Three pages read a message or a certificate you already have. None of them
sends what you paste, and none of them stores a private key. Open them from
the **Tools** pane on `saml_request.html` or `saml_response.html`.

These pages have no screenshots. The pictures in the
[OAuth2 / OIDC guide](oauth2-oidc/index.md) come from the Selenium jobs, and
those jobs were not re-run for this pass.

* TOC
{:toc}

## Request decoder

`/saml_authnrequest.html` reads an `AuthnRequest`. Paste a redirect URL, a
query string, an HTTP-POST form body, a bare `SAMLRequest` parameter, an
artifact, or the XML.

### Message

| Field or button | Default | What it does |
|---|---|---|
| **Binding** | Auto-detect | Also HTTP-Redirect (DEFLATE + base64 in the query), HTTP-POST (base64, not compressed), and HTTP-Artifact. Leave Auto-detect unless the blob is ambiguous. |
| **Message** | empty | The paste box. |
| **Decode** | | Fills the Decoded Message pane. |
| **Clear** | | Empties the page. |

### Digital Signature (optional)

**Validate the digital signature** is off. Turn it on. Paste the signer's
certificate into **Signer Certificate** when the message does not carry one
(a redirect signature has nowhere to put it; a POST signature usually
does). Click **Validate Signature**. Redirect signatures are the
query-string signature. POST signatures are the enveloped signature. The
status line reports the result. **View certificate details** opens the
certificate page for the PEM in that box.

### Decryption (optional)

**Decrypt the encrypted structure** is off. **Private Key (PKCS#8 PEM)** is
the SP key. **Certificate (optional)** says whether this is the key the
sender wrapped to. **Load SP key pair** fills both from the key pair the
SAML request page keeps in this browser, when that page is keeping one.
Nothing pasted here is stored. **Decrypt** writes the plaintext into the
decoded pane.

### Decoded Message

Tabs: **Original**, **Encrypted**, **XML**, **Details**. Each text box has
**Copy**. **Original** is what you pasted. **XML** is the inflated request.
**Details** is the issuer, the bindings, the NameID policy, and the
signature parameters.

## Response decoder

`/saml_response_decoder.html` reads a response in SAML 2.0 or SAML 1.1.
Paste a POST body, a redirect URL, a bare `SAMLResponse`, an artifact, a
bare `<saml:Assertion>`, or the XML.

The controls match the request decoder. The signature legend is the plural
**Digital Signatures (optional)**.

**Binding** defaults to Auto-detect. The listed bindings are HTTP-POST,
HTTP-Redirect, and HTTP-Artifact. POST is the ordinary browser binding for
a response.

**Validate the digital signatures** is off. **Validate Signatures** checks
every signature separately and reports each one: the response, each
assertion, and a redirect query string. One failure does not hide the
others. **Signer Certificate** is the same field as on the request decoder.

**Decrypt the encrypted structure**, **Private Key (PKCS#8 PEM)**,
**Certificate (optional)**, **Load SP key pair**, and **Decrypt** work as
on the request decoder. Nothing pasted here is stored.

Decoded tabs add **Assertions**, which lists each assertion and its
attributes beside **Original**, **Encrypted**, **XML**, and **Details**.

## Certificate details

`/saml_cert.html` parses one X.509 certificate.

| Field or button | What it does |
|---|---|
| **Certificate** | PEM or bare base64 DER. |
| **Parse** | Fills **Details**: subject, issuer, serial, validity, public key, extensions, and fingerprints. |
| **Status** | The parse result, or why the text was not a certificate. |

The SAML, WS-Trust, and JWT Tools pages link here as **View certificate
details**. They put the PEM in `localStorage` under `saml_cert_view` so this
page can show it. That is the certificate, which is public. The private key
stays on the page that generated it.
