// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/config/client_config.tsp
//
// client/src/env/*.js. envify inlines the chosen file into every bundle, so
// this is also what a page can read. Every `...Default` is the value a field
// starts with before the user has typed anything; none is a secret, and the
// password defaults are the test stacks' published test passwords.

import "@typespec/json-schema";

using TypeSpec.JsonSchema;

namespace IdProtoDebugger.Config;

/** The client service's configuration: one of client/src/env/*.js. */
model ClientConfig {
  /** The api's origin, as the browser reaches it. */
  @minLength(1) apiUrl: string;

  /**
   * This service's own origin. May be empty when read in node: the embedded
   * file takes it from window.location, which exists only in the page.
   */
  uiUrl: string;

  https?: boolean;
  hostname?: string;
  port: Port;
  logLevel: LogLevel;

  /** False on the static sites, which have no api behind them. */
  backendAvailable: boolean;

  /** The static sites' Lambda@Edge landings (infra/CLAUDE.md). */
  samlEdgeLanding?: boolean;
  wsfedEdgeLanding?: boolean;

  // --- SAML and WS-Federation service provider ----------------------------

  spEntityId: string;
  acsUrl: string;
  sloUrl: string;
  wsfedRealm: string;
  wsfedAcsUrl: string;

  // --- Where each workflow's fields start ---------------------------------

  wsfedMetadataUrlDefault: string;
  samlMetadataUrlDefault: string;
  wstrustStsUrlDefault: string;
  oid4vciIssuerUrlDefault: string;
  oid4vpVerifierUrlDefault: string;
  oid4vciIssuerSiteUrlDefault: string;
  oid4vpVerifierSiteUrlDefault: string;
  rfc8414MetadataUrlDefault: string;
  krb5RealmDefault: string;
  krb5KdcHostDefault: string;
  krb5KdcPortDefault: string;
  krb5PrincipalDefault: string;
  krb5PasswordDefault: string;
  krb5SpnegoUrlDefault: string;
  krb5SpnegoSpnDefault: string;
  ldapUrlDefault: string;
  ldapBaseDnDefault: string;
  ldapBindDnDefault: string;
  ldapPasswordDefault: string;
  spiffeTrustDomainDefault?: string;
  spiffeWorkloadAddressDefault?: string;
  spiffeServerAddressDefault?: string;
  spiffeBundleUrlDefault?: string;
  scimBaseUrlDefault: string;
  scimSignInUrlDefault: string;
  ssfTransmitterUrlDefault: string;
}
