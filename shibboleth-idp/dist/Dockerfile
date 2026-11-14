# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

# THE SHIBBOLETH SIDE-CAR'S TWO ARCHIVES, AS AN IMAGE.
#
# Nothing but the two files shibboleth-idp/Dockerfile installs, each fetched
# from its official location and refused unless its SHA-256 matches. It is
# built and pushed to the private mirror as shibboleth-idp-dist:<IdP version>
# by .github/scripts/mirror-builds.sh (.github/image-mirror-builds.txt), so
# the test stack's build copies the archives out of ghcr.io and never reaches
# shibboleth.net or Maven Central itself.
#
# FROM scratch: the image is a carrier, never run. ADD --checksum verifies
# before the layer is written; shibboleth-idp/Dockerfile verifies again,
# because a mirror tag can be overwritten.
#
# Shibboleth publishes the IdP's SHA-256 beside the archive (.sha256). Maven
# Central publishes only a SHA-1 for jetty-home
# (26e8e5b8bf3501798162303713463476c9db0614); the SHA-256 below is of the
# archive whose SHA-1 matched it. A version bump changes the URL, the digest,
# the tag in image-mirror-builds.txt and the FROM in shibboleth-idp/Dockerfile.
FROM scratch
ADD --checksum=sha256:815abe9c707c8741278eda8b9120be7d99f09238d2974ccc3a93b37d549cc149 \
    https://shibboleth.net/downloads/identity-provider/4.3.3/shibboleth-identity-provider-4.3.3.tar.gz \
    /shibboleth-identity-provider-4.3.3.tar.gz
ADD --checksum=sha256:e4217cc1f9e501b7a17fd9a568858785925bcf5d490c3dac8a9f97123779cd8c \
    https://repo1.maven.org/maven2/org/eclipse/jetty/jetty-home/10.0.22/jetty-home-10.0.22.tar.gz \
    /jetty-home-10.0.22.tar.gz
