// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/catalog/oauth.tsp
//
// THE OAUTH 2.0 / OPENID CONNECT METADATA CATALOGUES: the members of a
// discovery document the Configuration Parameters pane carries
// (client/src/op_metadata.js), and the client metadata choice members a
// registration request offers (client/src/rp_metadata_choices.js).
//
// This project's reading of OpenID Connect Discovery 1.0 section 3, RFC 8414
// section 2, RFC 9449 section 5.1, and OpenID Connect RP Metadata Choices 1.0
// sections 2 and 3. The modules keep only the code that reads these rows.

namespace IdProtoDebugger.Catalog;

/**
 * How a discovery member is shown in the Configuration Parameters pane.
 * `array` is comma-separated in the UI (values may contain spaces, e.g.
 * response_types_supported "code id_token"), `boolean` is a true/false
 * <select>, and `string` is plain text.
 */
alias DiscoveryFieldType = "array" | "boolean" | "string";

/** One member of an authorization server's discovery document. */
model DiscoveryMember {
  /** The metadata member name, which is also the input's element id. */
  name: string;

  /** How the pane shows its value. */
  type: DiscoveryFieldType;

  /**
   * The dummy default, in the same spirit as the other localhost
   * placeholders. The four booleans default to the values the
   * specification itself defines; an empty string is no default.
   */
  dflt: string;
}

/**
 * One OpenID Connect RP Metadata Choices 1.0 section 2 member: a JSON array
 * of values the client can use, and its single-valued partner, the value
 * the provider selected.
 */
model RpMetadataChoice {
  /** The array member, which is registration input. */
  choice: string;

  /** The single-valued member a registration response carries. */
  partner: string;

  /** The specification that defines the partner. */
  from: string;
}

// OpenID Provider Metadata — OpenID Connect Discovery 1.0 section 3.
//
// Every member the specification defines, so a discovery document can be
// inspected (and overridden) in full. The five the debugger drove before
// this table existed — authorization_endpoint, token_endpoint,
// userinfo_endpoint (#oidc_userinfo_endpoint), jwks_uri (#jwks_endpoint) and
// registration_endpoint — keep their original element ids and their own
// handling, and are NOT repeated here. Non-Discovery endpoints the pane also
// carries (introspection, revocation, device authorization) are likewise
// left alone.
const OP_METADATA: DiscoveryMember[] = #[
  #{ name: "issuer", type: "string", dflt: "https://localhost/oidc" },
  #{
    name: "scopes_supported",
    type: "array",
    dflt: "openid, profile, email, address, phone, offline_access",
  },
  #{
    name: "response_types_supported",
    type: "array",
    dflt: "code, id_token, id_token token, code id_token, code token, code id_token token",
  },
  #{
    name: "response_modes_supported",
    type: "array",
    dflt: "query, fragment, form_post",
  },
  #{
    name: "grant_types_supported",
    type: "array",
    dflt: "authorization_code, implicit, refresh_token, client_credentials, password, urn:ietf:params:oauth:grant-type:device_code",
  },
  #{ name: "acr_values_supported", type: "array", dflt: "0, 1" },
  #{ name: "subject_types_supported", type: "array", dflt: "public, pairwise" },
  #{
    name: "id_token_signing_alg_values_supported",
    type: "array",
    dflt: "RS256, RS384, RS512, ES256, PS256, HS256",
  },
  #{
    name: "id_token_encryption_alg_values_supported",
    type: "array",
    dflt: "RSA-OAEP, RSA-OAEP-256, ECDH-ES, A128KW",
  },
  #{
    name: "id_token_encryption_enc_values_supported",
    type: "array",
    dflt: "A128GCM, A192GCM, A256GCM, A128CBC-HS256",
  },
  #{
    name: "userinfo_signing_alg_values_supported",
    type: "array",
    dflt: "RS256, ES256, HS256",
  },
  #{
    name: "userinfo_encryption_alg_values_supported",
    type: "array",
    dflt: "RSA-OAEP, RSA-OAEP-256, ECDH-ES",
  },
  #{
    name: "userinfo_encryption_enc_values_supported",
    type: "array",
    dflt: "A128GCM, A256GCM, A128CBC-HS256",
  },
  #{
    name: "request_object_signing_alg_values_supported",
    type: "array",
    dflt: "none, RS256, ES256, PS256",
  },
  #{
    name: "request_object_encryption_alg_values_supported",
    type: "array",
    dflt: "RSA-OAEP, RSA-OAEP-256, ECDH-ES",
  },
  #{
    name: "request_object_encryption_enc_values_supported",
    type: "array",
    dflt: "A128GCM, A256GCM, A128CBC-HS256",
  },
  #{
    name: "token_endpoint_auth_methods_supported",
    type: "array",
    dflt: "client_secret_basic, client_secret_post, client_secret_jwt, private_key_jwt, none",
  },
  #{
    name: "token_endpoint_auth_signing_alg_values_supported",
    type: "array",
    dflt: "RS256, ES256, PS256, HS256",
  },
  #{
    name: "display_values_supported",
    type: "array",
    dflt: "page, popup, touch, wap",
  },
  #{
    name: "claim_types_supported",
    type: "array",
    dflt: "normal, aggregated, distributed",
  },
  #{
    name: "claims_supported",
    type: "array",
    dflt: "sub, iss, aud, exp, iat, auth_time, nonce, acr, amr, azp, name, given_name, family_name, preferred_username, email, email_verified",
  },
  #{
    name: "service_documentation",
    type: "string",
    dflt: "https://localhost/oidc/docs",
  },
  #{
    name: "claims_locales_supported",
    type: "array",
    dflt: "en-US, en-GB, fr-CA",
  },
  #{
    name: "ui_locales_supported",
    type: "array",
    dflt: "en-US, en-GB, fr-CA",
  },
  #{ name: "claims_parameter_supported", type: "boolean", dflt: "false" },
  #{ name: "request_parameter_supported", type: "boolean", dflt: "false" },
  #{ name: "request_uri_parameter_supported", type: "boolean", dflt: "true" },
  #{
    name: "require_request_uri_registration",
    type: "boolean",
    dflt: "false",
  },
  #{
    name: "op_policy_uri",
    type: "string",
    dflt: "https://localhost/oidc/policy",
  },
  #{ name: "op_tos_uri", type: "string", dflt: "https://localhost/oidc/tos" }
];

// Members RFC 8414 (OAuth 2.0 Authorization Server Metadata) section 2
// defines that OpenID Connect Discovery 1.0 does NOT, plus one RFC 9449
// registers.
//
// A separate list because that distinction is real — an OIDC Discovery
// document legitimately omits every one, and each should show the
// -->not defined<-- note when it does — but every pane that shows OpenID
// Provider metadata shows these as well, so op_metadata.js runs its
// operations over both lists.
const AS_ONLY_METADATA: DiscoveryMember[] = #[
  #{
    name: "revocation_endpoint_auth_methods_supported",
    type: "array",
    dflt: "client_secret_basic, client_secret_post, private_key_jwt",
  },
  #{
    name: "revocation_endpoint_auth_signing_alg_values_supported",
    type: "array",
    dflt: "RS256, ES256, PS256",
  },
  #{
    name: "introspection_endpoint_auth_methods_supported",
    type: "array",
    dflt: "client_secret_basic, client_secret_post, private_key_jwt",
  },
  #{
    name: "introspection_endpoint_auth_signing_alg_values_supported",
    type: "array",
    dflt: "RS256, ES256, PS256",
  },
  #{
    name: "code_challenge_methods_supported",
    type: "array",
    dflt: "S256, plain",
  },
  // RFC 9449 section 5.1, registered by that document rather than by RFC
  // 8414. It belongs in this list because its presence is the ONLY signal a
  // client has that DPoP is on offer: there is no other discovery mechanism,
  // so an authorization server that supports DPoP and omits this will never
  // be asked for it. Default empty, because absent means "has not said so"
  // and inventing a default would claim support nobody advertised.
  #{ name: "dpop_signing_alg_values_supported", type: "array", dflt: "" },
  #{ name: "signed_metadata", type: "string", dflt: "" }
];

// OpenID Connect RP Metadata Choices 1.0 section 3: these two names are
// discovery metadata, not client metadata. Section 3 uses
// token_endpoint_auth_methods_supported as the client's authentication list
// at the token, revocation, introspection and pushed authorization
// endpoints, so a registration request must not carry either.
const RP_NOT_CLIENT_CHOICES: string[] = #[
  "revocation_endpoint_auth_methods_supported",
  "introspection_endpoint_auth_methods_supported"
];

// The nineteen members in OpenID Connect RP Metadata Choices 1.0 section 2,
// in the order that section lists the families. `from` is the specification
// that defines the partner.
const RP_METADATA_CHOICES: RpMetadataChoice[] = #[
  #{
    choice: "subject_types_supported",
    partner: "subject_type",
    from: "OpenID Connect Core 1.0",
  },
  #{
    choice: "id_token_signing_alg_values_supported",
    partner: "id_token_signed_response_alg",
    from: "OpenID Connect Dynamic Client Registration 1.0",
  },
  #{
    choice: "id_token_encryption_alg_values_supported",
    partner: "id_token_encrypted_response_alg",
    from: "OpenID Connect Dynamic Client Registration 1.0",
  },
  #{
    choice: "id_token_encryption_enc_values_supported",
    partner: "id_token_encrypted_response_enc",
    from: "OpenID Connect Dynamic Client Registration 1.0",
  },
  #{
    choice: "userinfo_signing_alg_values_supported",
    partner: "userinfo_signed_response_alg",
    from: "OpenID Connect Core 1.0 section 5.3.2",
  },
  #{
    choice: "userinfo_encryption_alg_values_supported",
    partner: "userinfo_encrypted_response_alg",
    from: "OpenID Connect Core 1.0 section 5.3.2",
  },
  #{
    choice: "userinfo_encryption_enc_values_supported",
    partner: "userinfo_encrypted_response_enc",
    from: "OpenID Connect Core 1.0 section 5.3.2",
  },
  #{
    choice: "request_object_signing_alg_values_supported",
    partner: "request_object_signing_alg",
    from: "OpenID Connect Dynamic Client Registration 1.0",
  },
  #{
    choice: "request_object_encryption_alg_values_supported",
    partner: "request_object_encryption_alg",
    from: "OpenID Connect Dynamic Client Registration 1.0",
  },
  #{
    choice: "request_object_encryption_enc_values_supported",
    partner: "request_object_encryption_enc",
    from: "OpenID Connect Dynamic Client Registration 1.0",
  },
  #{
    choice: "token_endpoint_auth_methods_supported",
    partner: "token_endpoint_auth_method",
    from: "OpenID Connect Dynamic Client Registration 1.0",
  },
  #{
    choice: "token_endpoint_auth_signing_alg_values_supported",
    partner: "token_endpoint_auth_signing_alg",
    from: "OpenID Connect Dynamic Client Registration 1.0",
  },
  #{
    choice: "backchannel_authentication_request_signing_alg_values_supported",
    partner: "backchannel_authentication_request_signing_alg",
    from: "OpenID Connect Client-Initiated Backchannel Authentication",
  },
  #{
    choice: "authorization_signing_alg_values_supported",
    partner: "authorization_signed_response_alg",
    from: "JWT Secured Authorization Response Mode",
  },
  #{
    choice: "authorization_encryption_alg_values_supported",
    partner: "authorization_encrypted_response_alg",
    from: "JWT Secured Authorization Response Mode",
  },
  #{
    choice: "authorization_encryption_enc_values_supported",
    partner: "authorization_encrypted_response_enc",
    from: "JWT Secured Authorization Response Mode",
  },
  #{
    choice: "introspection_signing_alg_values_supported",
    partner: "introspection_signed_response_alg",
    from: "RFC 9701",
  },
  #{
    choice: "introspection_encryption_alg_values_supported",
    partner: "introspection_encrypted_response_alg",
    from: "RFC 9701",
  },
  #{
    choice: "introspection_encryption_enc_values_supported",
    partner: "introspection_encrypted_response_enc",
    from: "RFC 9701",
  }
];
