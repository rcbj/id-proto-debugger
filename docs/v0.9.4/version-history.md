# Version history

* v0.1 - Red Hat SSO support including all OAuth2 Grants and OIDC Authorization Code Flow
* v0.2 - 3Scale + APICast support for all OAuth2 Grants and OIDC Authorization Code Flow
* v0.3 - Azure Active Directory support for OAuth2 Grans and OIDC Authorization Code Flow.  Added error reporting logic and support for optional resource parameter.  Added additional debug logging code in client.  Moved Token Endpoint interaction into server-side (Ruby/Sinatra/Docker); this was necessary because Azure Active Directory does not support CORS (making Javascript interaction from a browser impossible).  Disabled IdP server certificate validation in IdP call.
* v0.4 - Full OpenID Connect support (all variations of Implicit and Hybrid Flows).  Support for public clients (ie, no client secret).
* v0.5 - Refresh Token support. Updates to UI.
* v0.6 - Rewritten in JavaScript. Ported to AWS for idptools.io website. Numerous enhancements. See Release Notes.
* v0.7 - PKCE Support added.
* v0.8 - Added Selenium-based test suite. Token Endpoint calls can be initiated from frontend or backend. Numerous new features.
* v0.9 - SAML 2.0 and WS-Trust support (SP-initiated SSO, SAML Assertion Tool, WS-Trust 1.0–1.4), JWT / Encoding / Digital Signature tool pages, static-site deployment, and the M.N.O versioning scheme described above.
* v0.9.3 - Smart cards (ISO 7816: Yubico OTP, OATH, PIV, the OpenPGP card, YubiHSM Auth) with writes and factory resets, over WebHID or the api's PC/SC relay, which can run natively; XACML 3.0 combining algorithms held to Appendix C, fixing legacy permit-overrides granting when a policy failed to evaluate; live-site suites green against iya-sts v1.0.0; GitHub releases created by Docker Image CI.
