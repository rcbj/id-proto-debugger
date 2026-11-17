// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/main.tsp
//
// EVERY BROWSER STORAGE KEY THE CLIENT NAMES, declared once with what it is
// (lib/debugger_lib.tsp, StorageFacts). One file per client module, the
// first alphabetically to name a key; which modules name it, and through
// which call, is read from the source by tests/storage_inventory.js rather
// than declared, so it cannot go stale.
//
// Generated from it:
//
// * common/model/storage.json — every key, for tests/data_model.js, which
//   holds it to the inventory in both directions (an undeclared key fails,
//   and so does a declared key nothing names);
// * common/model/storage_classes.json — only the secret, bearer,
//   secret-member and keypair lists, which client/src/secret_storage.js and
//   the four key-pair panes enforce with.
//
// A NEW KEY IS DECLARED HERE IN THE SAME COMMIT AS THE CODE THAT WRITES IT.
// If it is a client secret, a password or a typed bearer token, its class
// is what keeps it out of storage; a key filed as `ordinary` by mistake is
// stored like any other.
//
// The first draft of these files was written by a one-time conversion from
// the inventory on 2026-11-16, with secret_storage.js's three lists and the
// four key-pair panes' lists as the classes; anything named like a token, a
// response or a history was filed as `output`, and the rest as `ordinary`.

import "./bbs2023.tsp";
import "./digital_signature.tsp";
import "./gnap.tsp";
import "./introspection.tsp";
import "./jwks.tsp";
import "./jwt_tools.tsp";
import "./kerberos_panes.tsp";
import "./oauth2_oidc_1.tsp";
import "./oauth2_oidc_2.tsp";
import "./oauth_dpop.tsp";
import "./op_metadata.tsp";
import "./pki.tsp";
import "./rfc9700.tsp";
import "./saml_authnrequest.tsp";
import "./saml_cert.tsp";
import "./saml_request.tsp";
import "./saml_response.tsp";
import "./saml_tools.tsp";
import "./scim.tsp";
import "./sd_jwt_vc.tsp";
import "./sd_jwt_vp.tsp";
import "./secret_storage.tsp";
import "./session_handoff.tsp";
import "./smartcard.tsp";
import "./spiffe.tsp";
import "./ssf_history.tsp";
import "./ssf.tsp";
import "./token_detail.tsp";
import "./token_handoff.tsp";
import "./userinfo.tsp";
import "./vc_issuance_1.tsp";
import "./webauthn_analyzer.tsp";
import "./webauthn_lab.tsp";
import "./wsfed_request.tsp";
import "./wstrust_response.tsp";
import "./wstrust_tools.tsp";
import "./xacml.tsp";
