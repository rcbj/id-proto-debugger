#!/bin/sh
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# Turn the installer's idp-metadata.xml into the document a SAML 1.1
# deployment publishes at /idp/shibboleth (#425). The installer writes a
# SAML 2.0-only "example" document: its SAML 1.1 endpoints are commented
# out, its locations name https://shibboleth-idp/ and :8443 (neither of
# which this side-car serves), and its validUntil is the build instant, so
# it has expired before anybody reads it. A Shibboleth administrator
# serving SAML 1.1 edits exactly these things by hand, and so does this:
#
#   * protocolSupportEnumeration names the SAML 1.1 protocol and
#     Shibboleth's own, beside SAML 2.0;
#   * the Shibboleth AuthnRequest SingleSignOnService and the SAML 1.1
#     ArtifactResolutionService are uncommented;
#   * every location is the plain-HTTP address this side-car answers on;
#   * validUntil is removed.
#
# Each edit is checked, so a different installer layout fails the build
# here rather than publishing a document the tests then misread.
set -eu
md="$1"
perl -0pi -e '
  s{<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">}
   {<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol urn:oasis:names:tc:SAML:1.1:protocol urn:mace:shibboleth:1.0">};
  s{<!--(<ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:1\.0:bindings:SOAP-binding"[^>]*/>)\s*-->}{$1};
  s{<!--(<SingleSignOnService Binding="urn:mace:shibboleth:1\.0:profiles:AuthnRequest"[^>]*/>)\s*-->}{$1};
  s{https://shibboleth-idp(?::8443)?/idp/}{http://shibboleth-idp:8080/idp/}g;
  s{\s+validUntil="[^"]*"}{};
' "$md"
grep -q 'urn:oasis:names:tc:SAML:1.1:protocol urn:mace:shibboleth:1.0' "$md"
grep -q '^\s*<ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding" Location="http://shibboleth-idp:8080/idp/profile/SAML1/SOAP/ArtifactResolution"' "$md"
grep -q '^\s*<SingleSignOnService Binding="urn:mace:shibboleth:1.0:profiles:AuthnRequest" Location="http://shibboleth-idp:8080/idp/profile/Shibboleth/SSO"' "$md"
! grep -q 'validUntil=' "$md"
! grep -q 'https://shibboleth-idp' "$md"
echo "publish-saml11-metadata: $md publishes SAML 1.1."
