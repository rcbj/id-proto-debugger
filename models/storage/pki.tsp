// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/storage/pki.tsp
//
// The browser storage keys client/src/pki.js is the first module
// (alphabetically) to name. Which other modules name each one is read from
// the source by tests/storage_inventory.js. See models/storage/main.tsp.

import "../lib/debugger_lib.tsp";

using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Storage;

@storageGroup("client/src/pki.js")
model PkiKeys {
  @storageKey(#{ area: "local", class: "ordinary", prefix: true })
  pkitools_: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_aia: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_akid_issuer_serial: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_alt_key_alg: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_alt_private_key: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_alt_public_key: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_bc_ca: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_bc_critical: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_bc_pathlen: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_cdp: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_cdp_critical: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_csr: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_custom_extensions: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_dn_c: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_dn_cn: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_dn_dc: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_dn_email: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_dn_extra: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_dn_l: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_dn_o: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_dn_ou: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_dn_serialnumber: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_dn_st: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_dn_uid: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_eku_anyExtendedKeyUsage: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_eku_clientAuth: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_eku_codeSigning: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_eku_critical: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_eku_emailProtection: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_eku_extra: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_eku_ipsecEndSystem: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_eku_ipsecIKE: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_eku_ipsecTunnel: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_eku_ipsecUser: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_eku_kdcAuthentication: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_eku_msDocumentSigning: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_eku_msEncryptingFileSystem: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_eku_msSmartcardLogon: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_eku_ocspSigning: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_eku_pkinitClientAuth: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_eku_serverAuth: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_eku_timeStamping: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ext_aia: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ext_akid: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ext_bc: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ext_cdp: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ext_eku: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ext_freshest: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ext_ian: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ext_inhibit_any: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ext_ku: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ext_name_constraints: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ext_ns_cert_type: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ext_ns_comment: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ext_ocsp_nocheck: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ext_pkup: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ext_policies: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ext_policy_constraints: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ext_policy_mappings: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ext_san: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ext_sia: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ext_skid: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ext_tls_feature: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_freshest: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_gen_csr: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ian: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ian_critical: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_inhibit_any_skip: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_inhibit_policy_mapping: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_issuer: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_key_alg: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ks_format: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ks_include_chain: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ku_cRLSign: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ku_critical: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ku_dataEncipherment: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ku_decipherOnly: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ku_digitalSignature: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ku_encipherOnly: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ku_keyAgreement: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ku_keyCertSign: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ku_keyEncipherment: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ku_nonRepudiation: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_name_constraints: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_nc_critical: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_not_after: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_not_before: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ns_comment: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ns_emailCA: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ns_objectSigningCA: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ns_sslCA: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ns_sslClient: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_ns_sslServer: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_pkup_not_after: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_pkup_not_before: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_policies: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_policies_critical: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_policy_mappings: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_pq_mode: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_private_key: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_profile: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_public_key: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_require_explicit_policy: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_san: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_san_critical: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_save_keys: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_selected: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_serial: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_sia: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_sig_alg: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_tls_alpn: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_tls_ciphers: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_tls_feature: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_tls_groups: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_tls_host: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_tls_http_path: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_tls_http_probe: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_tls_max_version: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_tls_min_version: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_tls_port: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_tls_probe_mutual: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_tls_servername: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_tls_sigalgs: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_tls_system_roots: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_tls_trust_pem: unknown;

  @storageKey(#{ area: "local", class: "ordinary" })
  pkitools_pki_validity_years: unknown;
}
